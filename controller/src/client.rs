
use crate::Error;
use reqwest::header;
use serde_json::Value;
use std::env;
use tracing::{debug, error};

pub(crate) async fn api_post_call(v: Value, path: &str) -> Result<(), Error> {
    let api_endpoint = env::var("API_ENDPOINT").expect("$API_ENDPOINT is not set");
    let url = format!("{}/{}", api_endpoint, path);
    let mut headers = header::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    debug!("input json {}", v.to_string());
    // send it to db
    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .headers(headers)
        .body(v.to_string())
        .send()
        .await;
    if let Err(e) = res {
        error!("Failed to send the traffic logs to API {}", url);

        error!("Msg {}", e);
        return Ok(());
    }
    debug!("Post url {} : Success", url);
    debug!("Post call response {:?}", res.unwrap());
    Ok(())
}
