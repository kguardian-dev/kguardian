use crate::Error;
use reqwest::header;
use serde_json::Value;
use std::env;
use tracing::{debug, error};

use lazy_static::lazy_static;

lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::Client::new();
}

pub(crate) async fn api_post_call(v: Value, path: &str) -> Result<(), Error> {
    let api_endpoint = env::var("API_ENDPOINT").expect("$API_ENDPOINT is not set");
    let url = format!("{}/{}", api_endpoint, path);
    let mut headers = header::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    debug!("input json {}", v.to_string());

    let res = CLIENT
        .post(&url)
        .headers(headers)
        .body(v.to_string())
        .send()
        .await
        .map_err(|e| {
            error!("Failed to send the traffic logs to API {}", url);
            error!("Msg {}", e);
            Error::CustomError(format!("API call failed: {}", e))
        })?;

    debug!("Post url {} : Success", url);
    debug!("Post call response {:?}", res);
    Ok(())
}
