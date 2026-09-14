use crate::Error;
use serde_json::Value;
use std::env;
use tracing::debug;

use lazy_static::lazy_static;

/// Ceiling on a whole broker request, connect through body.
pub(crate) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Ceiling on establishing the TCP/TLS connection to the broker.
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Build an HTTP client with explicit ceilings on both halves of a
/// request.
///
/// Factored out so no caller can get a client without them.
/// `pod_reconciler` used to build its own with `ReqwestClient::new()`,
/// which has NO timeouts at all — reqwest's default is to wait
/// forever — so its broker GET could park indefinitely and pods
/// stopped being marked dead with nothing logged. Timeouts are not a
/// per-call-site decision; they belong to the client.
fn build_http_client(
    request_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(request_timeout)
        .connect_timeout(connect_timeout)
        .build()
        .expect("Failed to create HTTP client")
}

lazy_static! {
    static ref CLIENT: reqwest::Client = build_http_client(REQUEST_TIMEOUT, CONNECT_TIMEOUT);
}

/// The Controller's one HTTP client for broker traffic.
///
/// Shared rather than per-subsystem: it carries the timeouts above, and
/// reqwest pools connections behind an `Arc`, so every caller reusing
/// this one also stops re-dialling the broker on each request.
pub(crate) fn http_client() -> &'static reqwest::Client {
    &CLIENT
}

/// Build the broker URL for a given path, robust against trailing
/// slashes in API_ENDPOINT (a natural copy-paste artefact). Pre-fix
/// `fmt!("{}/{}", "http://broker:9090/", "pod/traffic/batch")` produced
/// "http://broker:9090//pod/traffic/batch" which most servers normalize
/// but shows up in error logs and can break prefix-matched proxies.
/// Also strips a leading slash from path for the same reason.
pub(crate) fn build_url(api_endpoint: &str, path: &str) -> String {
    let endpoint = api_endpoint.trim_end_matches('/');
    let p = path.trim_start_matches('/');
    format!("{}/{}", endpoint, p)
}

/// Optional shared secret for the broker API. When `BROKER_AUTH_TOKEN`
/// is set (matching the broker's own config), the controller sends it as
/// a bearer token on every POST. Empty / whitespace-only is treated as
/// unset.
fn broker_auth_token() -> Option<String> {
    env::var("BROKER_AUTH_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) async fn api_post_call(v: Value, path: &str) -> Result<(), Error> {
    api_post_call_json(v, path).await.map(|_| ())
}

/// `api_post_call`, plus the broker's response body.
///
/// A 2xx is not by itself proof that the broker stored what was sent:
/// the seccomp denial ingest validates per row and answers
/// `200 {"accepted": n}` with `n` below the number of rows posted when
/// some were refused — including `n == 0` for a batch refused whole.
/// The caller has already cleared the kernel map by then, so those rows
/// exist nowhere else; a caller that reads only the status reports a
/// clean delivery over silent, unrecoverable loss.
///
/// The same function body as `api_post_call` deliberately, with that one
/// returning `()` from it. Two copies of the URL, auth and status
/// handling would be two places for a broker-auth or 404 change to land
/// in one and not the other.
pub(crate) async fn api_post_call_json(v: Value, path: &str) -> Result<Value, Error> {
    // main.rs trims its API_ENDPOINT read but stores the trimmed
    // value in a local variable that doesn't propagate here. Re-trim
    // at this read site for consistency — operator pastes with
    // trailing newline would otherwise create whitespace-laden URLs
    // even though build_url handles trailing slashes.
    let api_endpoint = env::var("API_ENDPOINT")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("API_ENDPOINT environment variable not set".to_string()))?;
    let url = build_url(&api_endpoint, path);

    debug!("Posting to {}", url);

    // Serialize to bytes directly without intermediate string allocation
    let json_bytes = serde_json::to_vec(&v)
        .map_err(|e| Error::Custom(format!("Failed to serialize JSON: {}", e)))?;

    let mut request = CLIENT
        .post(&url)
        .header("content-type", "application/json")
        .body(json_bytes);

    // Optional bearer auth: when the broker is deployed with
    // BROKER_AUTH_TOKEN set, the controller must present the same token
    // or its writes are rejected (401). Unset preserves the original
    // no-auth behaviour. Read per-call to match the API_ENDPOINT pattern
    // above; the value is stable for the process lifetime.
    if let Some(token) = broker_auth_token() {
        request = request.bearer_auth(token);
    }

    let res = request
        .send()
        .await
        .map_err(|e| Error::ApiError(format!("{}", e)))?;

    // Promote non-2xx broker responses to errors. Pre-fix the function
    // returned Ok regardless of status — a 500 from the broker (or
    // 503 during a restart) was silently swallowed by every caller,
    // so a misconfigured broker dropping every POST showed up as
    // "controller is happy" while the database stayed empty.
    let status = res.status();
    if !status.is_success() {
        let body = res
            .text()
            .await
            .unwrap_or_else(|e| format!("<could not read body: {}>", e));
        return Err(Error::ApiError(format!(
            "broker returned {} for POST {}: {}",
            status, url, body
        )));
    }

    debug!("Post url {} : Success", url);
    // A body that is absent or not JSON is not an error: most endpoints
    // answer 200 with nothing useful, and only callers that look for a
    // specific field care. They get `Null` and decide for themselves.
    let body = res.text().await.unwrap_or_default();
    Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn api_endpoint() -> Result<String, Error> {
    env::var("API_ENDPOINT")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("API_ENDPOINT environment variable not set".to_string()))
}

/// Send a bodiless-or-JSON request and promote a non-2xx status to an
/// error, the way `api_post_call` does. `tolerate_404` turns a 404 into
/// success for idempotent deletes.
async fn send_checked(
    request: reqwest::RequestBuilder,
    method: &str,
    url: &str,
    tolerate_404: bool,
) -> Result<(), Error> {
    let mut request = request;
    if let Some(token) = broker_auth_token() {
        request = request.bearer_auth(token);
    }
    let res = request
        .send()
        .await
        .map_err(|e| Error::ApiError(format!("{}", e)))?;
    let status = res.status();
    if status.is_success() || (tolerate_404 && status == reqwest::StatusCode::NOT_FOUND) {
        debug!("{} url {} : {}", method, url, status);
        return Ok(());
    }
    let body = res
        .text()
        .await
        .unwrap_or_else(|e| format!("<could not read body: {}>", e));
    Err(Error::ApiError(format!(
        "broker returned {} for {} {}: {}",
        status, method, url, body
    )))
}

/// Authenticated JSON PUT (idempotent upsert). Used by the seccomp CR
/// mirror; same endpoint / auth / status handling as `api_post_call`.
pub(crate) async fn api_put_call(v: Value, path: &str) -> Result<(), Error> {
    let url = build_url(&api_endpoint()?, path);
    debug!("Putting to {}", url);
    let json_bytes = serde_json::to_vec(&v)
        .map_err(|e| Error::Custom(format!("Failed to serialize JSON: {}", e)))?;
    let request = CLIENT
        .put(&url)
        .header("content-type", "application/json")
        .body(json_bytes);
    send_checked(request, "PUT", &url, false).await
}

/// Authenticated DELETE. A 404 counts as success: the row is gone either
/// way, and N nodes race to delete the same mirror row.
pub(crate) async fn api_delete_call(path: &str) -> Result<(), Error> {
    let url = build_url(&api_endpoint()?, path);
    debug!("Deleting {}", url);
    send_checked(CLIENT.delete(&url), "DELETE", &url, true).await
}

/// Authenticated, timeout-bounded GET against the broker, returning the
/// raw response body. Mirrors `api_post_call`'s endpoint / auth / status
/// handling. Used by the seccomp distributor, which needs the profile
/// JSON verbatim to write to disk.
pub(crate) async fn api_get_bytes(path: &str) -> Result<Vec<u8>, Error> {
    let api_endpoint = env::var("API_ENDPOINT")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("API_ENDPOINT environment variable not set".to_string()))?;
    let url = build_url(&api_endpoint, path);
    debug!("Getting {}", url);

    let mut request = CLIENT.get(&url);
    if let Some(token) = broker_auth_token() {
        request = request.bearer_auth(token);
    }

    let res = request
        .send()
        .await
        .map_err(|e| Error::ApiError(format!("{}", e)))?;

    let status = res.status();
    if !status.is_success() {
        let body = res
            .text()
            .await
            .unwrap_or_else(|e| format!("<could not read body: {}>", e));
        return Err(Error::ApiError(format!(
            "broker returned {} for GET {}: {}",
            status, url, body
        )));
    }

    let bytes = res
        .bytes()
        .await
        .map_err(|e| Error::ApiError(format!("reading GET {} body: {}", url, e)))?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener that accepts and never responds — a broker that has
    /// stopped serving without closing its socket. `reqwest`'s default
    /// client waits on this forever.
    fn hung_broker() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        (listener, format!("http://{addr}/pod/list/node-a"))
    }

    /// The defect, pinned: this is exactly the client `pod_reconciler`
    /// built (`ReqwestClient::new()`), and against a hung broker its
    /// GET never returns.
    #[tokio::test]
    async fn a_default_reqwest_client_waits_forever() {
        let (_listener, url) = hung_broker();
        let client = reqwest::Client::new();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(750),
            client.get(&url).send(),
        )
        .await;

        assert!(
            outcome.is_err(),
            "reqwest::Client::new() has no request timeout; if this ever resolves, reqwest              has changed its defaults"
        );
    }

    /// The fix: a client from the shared constructor gives up.
    #[tokio::test]
    async fn a_client_from_the_shared_builder_times_out() {
        let (_listener, url) = hung_broker();
        let client = build_http_client(
            std::time::Duration::from_millis(200),
            std::time::Duration::from_millis(100),
        );

        let started = tokio::time::Instant::now();
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("a hung broker must produce an error, not a response");

        assert!(err.is_timeout(), "expected a timeout, got {err}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "took {:?}",
            started.elapsed()
        );
    }

    /// The shipped ceilings, guarded.
    ///
    /// Every timeout test in this crate injects its own short ceiling so
    /// the suite stays fast (200ms here, 300ms in `container`). That
    /// proves the mechanism and leaves the production numbers asserted
    /// nowhere: mutation testing raised `REQUEST_TIMEOUT` to 24 hours
    /// with the whole suite and CI green. A bound costs nothing at
    /// runtime and makes changing these deliberate rather than silent.
    ///
    /// The bound is not arbitrary. The controller posts to the broker
    /// from subsystems that run on a clock — the syscall recorder every
    /// 10s, the network batch flush every 1s — so a broker that is
    /// wedged rather than down must not hold one of them past several
    /// of its own ticks. 30s already allows that; a minute is the point
    /// where it stops being a ceiling at all.
    #[test]
    fn the_shipped_broker_ceilings_stay_bounded() {
        assert!(
            REQUEST_TIMEOUT <= std::time::Duration::from_secs(60),
            "a {REQUEST_TIMEOUT:?} request ceiling lets a wedged broker stall a subsystem \
             across many of its own ticks; that is the #1344 hang with extra steps"
        );
        assert!(
            CONNECT_TIMEOUT < REQUEST_TIMEOUT,
            "the connect budget must be a fraction of the whole-request budget, not equal \
             to or larger than it"
        );
    }

    /// The shared client is the one built with the production
    /// ceilings, and every caller gets the same pooled instance.
    #[test]
    fn the_shared_client_is_a_single_pooled_instance() {
        assert!(
            std::ptr::eq(http_client(), http_client()),
            "callers must share one client, so connections are pooled rather than re-dialled"
        );
        assert!(CONNECT_TIMEOUT < REQUEST_TIMEOUT);
    }

    // build_url is the URL constructor for every controller → broker
    // POST. Robustness against trailing slashes prevents double-slash
    // URLs from leaking into logs (and from breaking prefix-matched
    // proxies in some deployment topologies).

    #[test]
    fn build_url_no_trailing_slash() {
        assert_eq!(
            build_url("http://broker:9090", "pod/traffic/batch"),
            "http://broker:9090/pod/traffic/batch"
        );
    }

    #[test]
    fn build_url_trailing_slash_on_endpoint() {
        // The bug case: API_ENDPOINT="http://broker:9090/" — typical
        // copy-paste artefact. No double slash in the output.
        assert_eq!(
            build_url("http://broker:9090/", "pod/traffic/batch"),
            "http://broker:9090/pod/traffic/batch"
        );
    }

    #[test]
    fn build_url_double_trailing_slash() {
        assert_eq!(
            build_url("http://broker:9090//", "pod/traffic/batch"),
            "http://broker:9090/pod/traffic/batch"
        );
    }

    #[test]
    fn build_url_leading_slash_on_path() {
        // Defensive: a future caller writes `path="/pod/traffic/batch"`
        // with a leading slash. Still produces a single slash.
        assert_eq!(
            build_url("http://broker:9090", "/pod/traffic/batch"),
            "http://broker:9090/pod/traffic/batch"
        );
    }

    #[test]
    fn build_url_preserves_path_components_on_endpoint() {
        // Operators may configure a sub-path prefix
        // (API_ENDPOINT="http://gateway/broker"). Only trailing
        // slashes are stripped.
        assert_eq!(
            build_url("http://gateway/broker", "pod/traffic"),
            "http://gateway/broker/pod/traffic"
        );
        assert_eq!(
            build_url("http://gateway/broker/", "pod/traffic"),
            "http://gateway/broker/pod/traffic"
        );
    }
}
