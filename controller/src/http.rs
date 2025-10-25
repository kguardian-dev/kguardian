use crate::models::PodHttpTraffic;
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
    traffic_type: String,
    ip_protocol: String,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HttpEventData {
    pub inum: u64,
    pub saddr: u32, // network byte order
    pub daddr: u32, // network byte order
    pub sport: u16, // network byte order
    pub dport: u16, // network byte order
    pub is_request: u8,
    _pad: u8,
    pub data_len: u32,
    pub data: [u8; MAX_HTTP_DATA_LEN],
}

// ...existing code...
pub async fn handle_http_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<HttpEventData>,
    container_map_tcp: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_tcp.lock().await;
        println!("HTTP Data: {}", event.inum);
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            // pass pod_inspect so we can POST L7 events with pod metadata
            process_http_event(&event, pod_inspect).await?
        }
    }
    Ok(())
}
// ...existing code...
fn parse_http_headers(s: &str) -> Option<(String, Vec<(String, String)>, &str)> {
    // split headers and body
    
    let mut parts = s.splitn(2, "\r\n\r\n");
    let header_block = parts.next()?;
    let body = parts.next().unwrap_or("");

    let mut lines = header_block.split("\r\n");
    let start_line = lines.next()?.to_string();

    println!("start_line: {}", start_line);

   

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

// ...existing code...
pub async fn process_http_event(evt: &HttpEventData, pod_data: &PodInspect) -> Result<(), Error> {
    let src_ip = Ipv4Addr::from(u32::from_be(evt.saddr));
    let src_port = u16::from_be(evt.sport);
    let _dst_ip = Ipv4Addr::from(u32::from_be(evt.daddr));
    let host_port  = u16::from_be(evt.dport);
    let data_len = evt.data_len as usize;
    let copy_len = std::cmp::min(data_len, MAX_HTTP_DATA_LEN);
    let raw = &evt.data[..copy_len];

    

    // Normalize to owned String for simple parsing (safe fallback on invalid UTF-8).
    let data_string = match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(raw).into_owned(),
    };

    

    // try to parse start-line / headers once so we can extract HTTP path
    let parsed = parse_http_headers(&data_string);
    let http_path_opt: Option<String> = parsed.as_ref().and_then(|(start_line, _headers, _body)| 
            start_line.split_whitespace().nth(1).map(|s| s.to_string())
    );
    
    let http_method_opt: Option<String> = parsed.as_ref().and_then(|(start_line, _headers, _body)| 
        start_line.split_whitespace().next().map(|s| s.to_string())
    );

    // Determine traffic metadata for caching / POST payload
    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned();
    let pod_ip = pod_data.status.pod_ip.to_string();
    let mut pod_port_str = String::new();
    let mut traffic_in_out_ip_str = String::new();
    let mut traffic_in_out_port_str = String::new();
    // For L7 events the "traffic_in_out_ip" is the remote/client IP


    // Determine direction: requests are INGRESS, responses are EGRESS
    let traffic_type_str = if evt.is_request == 1 { 
     traffic_in_out_ip_str = IpAddr::V4(src_ip).to_string();
    traffic_in_out_port_str = 0.to_string();
    pod_port_str = evt.dport.to_string();
        "INGRESS" 
    } else { 
    traffic_in_out_ip_str = IpAddr::V4(_dst_ip).to_string();
    traffic_in_out_port_str = host_port.to_string();
    pod_port_str = host_port.to_string();
        "EGRESS" }.to_string();
    
    let protocol_str = "TCP".to_string();

    if pod_ip.eq(&traffic_in_out_ip_str) {
        // skip localhost/pod-internal traffic
        return Ok(());
    }

    let cache_key = HttpKey {
        pod_name: pod_name.clone(),
        pod_ip: pod_ip.clone(),
        pod_port: pod_port_str.clone(),
        traffic_in_out_ip: traffic_in_out_ip_str.clone(),
        traffic_type: traffic_type_str.clone(),
        ip_protocol: protocol_str.clone(),
    };

    if !TRAFFIC_CACHE.contains_key(&cache_key) {
        let payload = json!(PodHttpTraffic {
            uuid: Uuid::new_v4().to_string(),
            pod_name,
            pod_namespace,
            pod_ip,
            pod_port: Some(pod_port_str),
            traffic_in_out_ip: Some(traffic_in_out_ip_str),
            traffic_in_out_port: Some(traffic_in_out_port_str),
            traffic_type: Some(traffic_type_str),
            ip_protocol: Some(protocol_str),
            // pass HTTP path (may be None)
            http_path: http_path_opt.clone(),
            http_method: http_method_opt.clone(),
            time_stamp: Utc::now().naive_utc(),
        });

        info!("L7 Record to be inserted {}", payload.to_string());
        if let Err(e) = api_post_call(payload, "pod/l7traffic").await {
            error!("Failed to post L7 HTTP event: {}", e);
        } else {
            TRAFFIC_CACHE.insert(cache_key.clone(), ()).await;
        }
    } else {
        debug!("Skipping duplicate L7 event for pod: {}", pod_data.status.pod_name);
    }
    Ok(())
}
// ...existing code...

