use crate::Error;
use serde_json::Value;
use std::env;
use tracing::debug;

use lazy_static::lazy_static;

lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client");
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
    Ok(())
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
