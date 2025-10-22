use crate::{api_post_call, Error, PodInspect, PodTraffic};
use chrono::Utc;
use moka::future::Cache;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use uuid::Uuid;

lazy_static::lazy_static! {
    static ref TRAFFIC_CACHE: Arc<Cache<HttpKey, ()>> = Arc::new(Cache::new(10000));
}
pub const MAX_HTTP_DATA_LEN: usize = 256;

pub mod http_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/http_probe.skel.rs"
    ));
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct HttpKey {
    pod_name: String,
    pod_ip: String,
    pod_port: String,
    traffic_in_out_ip: String,
    traffic_in_out_port: String,
    traffic_type: String,
    ip_protocol: String,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HttpEventData {
    pub inum: u64,
    pub saddr: u32,    // network byte order
    pub sport: u16,    // network byte order
    pub is_request: u8,
    _pad: u8,
    pub data_len: u32,
    pub data: [u8; MAX_HTTP_DATA_LEN],
}



pub async fn handle_http_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<HttpEventData>,
    container_map_tcp: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_tcp.lock().await;
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            process_http_event(&event).await?
        }
    }
    Ok(())
}

fn parse_http_headers(s: &str) -> Option<(String, Vec<(String, String)>, &str)> {
    // split headers and body
    let mut parts = s.splitn(2, "\r\n\r\n");
    let header_block = parts.next()?;
    let body = parts.next().unwrap_or("");

    let mut lines = header_block.split("\r\n");
    let start_line = lines.next()?.to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            // malformed header line, skip
            continue;
        }
    }
    Some((start_line, headers, body))
}

pub async fn process_http_event(evt: &HttpEventData) -> Result<(), Error> {
     let src_ip = Ipv4Addr::from(u32::from_be(evt.saddr));
    let src_port = u16::from_be(evt.sport);
    let data_len = evt.data_len as usize;
    let copy_len = std::cmp::min(data_len, MAX_HTTP_DATA_LEN);
    let raw = &evt.data[..copy_len];

    // Normalize to owned String for simple parsing (safe fallback on invalid UTF-8).
    let data_string = match str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(raw).into_owned(),
    };

    if let Some((start_line, headers, body)) = parse_http_headers(&data_string) {
          println!(
        "HTTP EVENT: net_ns={} src={}:{} path={} req/rsp={}",
        evt.inum,
        src_ip,
        src_port,
        start_line,
       if evt.is_request == 1 { "req" } else { "resp" },
    
    );

        // Print headers (or use them programmatically)
        for (k, v) in headers.iter() {
            println!("  header: {}: {}", k, v);
        }

        // If you need the body:
        if !body.is_empty() {
            println!("  body (first 200 bytes): {}", &body[..std::cmp::min(200, body.len())]);
        }
    
    } else {
         println!(
        "HTTP EVENT: net_ns={} src={}:{} type={} len={}",
        evt.inum,
        src_ip,
        src_port,
        if evt.is_request == 1 { "req" } else { "resp" },
        data_len
    );
    }
    Ok(())
}
