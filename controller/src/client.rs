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

    let res = CLIENT
        .post(&url)
        .header("content-type", "application/json")
        .body(json_bytes)
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
