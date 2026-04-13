use crate::Error;
use serde_json::Value;
use std::env;
use std::sync::LazyLock;
use tracing::debug;

// reqwest::Client::builder().timeout(...).connect_timeout(...).build() can only fail
// if the TLS backend fails to initialise. We use the default TLS backend (native-tls /
// rustls) which is compiled-in and has no runtime prerequisites, so this cannot fail in
// practice. The `expect` message is kept to surface the unlikely OS-level failure clearly.
static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client: TLS backend initialisation failed")
});

pub(crate) async fn api_post_call(v: Value, path: &str) -> Result<(), Error> {
    let api_endpoint = env::var("API_ENDPOINT")
        .map_err(|_| Error::Custom("API_ENDPOINT environment variable not set".to_string()))?;
    let url = format!("{}/{}", api_endpoint, path);

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

    debug!("Post url {} : Success", url);
    debug!("Post call response {:?}", res);
    Ok(())
}
