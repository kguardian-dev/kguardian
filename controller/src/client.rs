use crate::Error;
use serde_json::Value;
use std::env;
use tracing::debug;

use lazy_static::lazy_static;

lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::Client::new();
}

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
