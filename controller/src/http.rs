use crate::{api_post_call, Error, PodHttpTraffic, PodInspect};
use chrono::Utc;
use dashmap::DashMap;
use moka::future::Cache;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

pub mod http_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/http.skel.rs"
    ));
}

pub const MAX_HTTP_DATA_LEN: usize = 128;

// Direction constants matching the eBPF program
const HTTP_RECV_REQUEST: u8 = 0;  // INGRESS: we received an HTTP request
const HTTP_SEND_REQUEST: u8 = 1;  // EGRESS:  we sent an HTTP request
const HTTP_RECV_RESPONSE: u8 = 2; // received a response (to our EGRESS request)
const HTTP_SEND_RESPONSE: u8 = 3; // sent a response    (to an INGRESS request)

/// Mirrors the eBPF `event_t` struct — must stay in sync with http.bpf.c.
/// Field layout (with implicit 2-byte padding before data_len):
///   u64 inum, u32 saddr, u32 daddr, u16 sport, u16 dport,
///   u8 direction, u8 _pad, [2 bytes padding], u32 data_len, u8[128] data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HttpEventData {
    pub inum: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub direction: u8,
    pub _pad: u8,
    pub _pad2: u16, // explicit padding to align data_len to 4-byte boundary
    pub data_len: u32,
    pub data: [u8; MAX_HTTP_DATA_LEN],
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct HttpTrafficKey {
    pod_name: String,
    pod_ip: String,
    pod_port: String,
    traffic_in_out_ip: String,
    traffic_in_out_port: String,
    traffic_type: String,
    http_method: String,
    http_path: String,
}

lazy_static::lazy_static! {
    static ref HTTP_TRAFFIC_CACHE: Arc<Cache<HttpTrafficKey, ()>> =
        Arc::new(Cache::new(10_000));
}

pub async fn handle_http_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<HttpEventData>,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Result<(), Error> {
    const BATCH_SIZE: usize = 50;
    const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    let mut batch: Vec<PodHttpTraffic> = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = tokio::time::Instant::now();

    loop {
        let event = tokio::time::timeout(BATCH_TIMEOUT, event_receiver.recv()).await;

        match event {
            Ok(Some(evt)) => {
                if let Some(pod_inspect) = container_map.get(&evt.inum) {
                    if let Some(traffic) = build_http_traffic_event(&evt, &pod_inspect).await {
                        batch.push(traffic);
                    }
                }
                if batch.len() >= BATCH_SIZE {
                    flush_http_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                if !batch.is_empty() {
                    flush_http_batch(&mut batch).await;
                }
                error!("HTTP event receiver closed unexpectedly");
                break;
            }
            Err(_) => {
                // timeout — flush if anything pending
                if !batch.is_empty() && last_flush.elapsed() >= BATCH_TIMEOUT {
                    flush_http_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn flush_http_batch(batch: &mut Vec<PodHttpTraffic>) {
    if batch.is_empty() {
        return;
    }
    debug!("Flushing HTTP event batch of {} events", batch.len());
    if let Err(e) = api_post_call(serde_json::json!(batch), "pod/l7traffic/batch").await {
        error!("Failed to post HTTP traffic batch: {}", e);
    }
    batch.clear();
}

async fn build_http_traffic_event(
    evt: &HttpEventData,
    pod_data: &PodInspect,
) -> Option<PodHttpTraffic> {
    let (traffic_type, pod_port, traffic_in_out_ip, traffic_in_out_port) =
        match evt.direction {
            HTTP_RECV_REQUEST => {
                // Inbound request: remote → us
                let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(evt.daddr))).to_string();
                let remote_port = u16::from_be(evt.dport).to_string();
                let local_port = evt.sport.to_string(); // sport is already host-byte-order
                ("INGRESS", local_port, remote_ip, remote_port)
            }
            HTTP_SEND_REQUEST => {
                // Outbound request: us → remote
                let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(evt.daddr))).to_string();
                let remote_port = u16::from_be(evt.dport).to_string();
                ("EGRESS", "0".to_string(), remote_ip, remote_port)
            }
            HTTP_RECV_RESPONSE => {
                // Response received for an outbound request
                let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(evt.daddr))).to_string();
                let remote_port = u16::from_be(evt.dport).to_string();
                ("EGRESS", "0".to_string(), remote_ip, remote_port)
            }
            HTTP_SEND_RESPONSE => {
                // Response sent for an inbound request
                let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(evt.daddr))).to_string();
                let remote_port = u16::from_be(evt.dport).to_string();
                let local_port = evt.sport.to_string();
                ("INGRESS", local_port, remote_ip, remote_port)
            }
            _ => {
                debug!("Unknown HTTP event direction: {}", evt.direction);
                return None;
            }
        };

    // Skip loopback / self traffic
    if pod_data.status.pod_ip == traffic_in_out_ip {
        return None;
    }

    let (http_method, http_path) =
        parse_http_data(&evt.data, evt.data_len as usize, evt.direction);

    let cache_key = HttpTrafficKey {
        pod_name: pod_data.status.pod_name.clone(),
        pod_ip: pod_data.status.pod_ip.clone(),
        pod_port: pod_port.clone(),
        traffic_in_out_ip: traffic_in_out_ip.clone(),
        traffic_in_out_port: traffic_in_out_port.clone(),
        traffic_type: traffic_type.to_string(),
        http_method: http_method.clone().unwrap_or_default(),
        http_path: http_path.clone().unwrap_or_default(),
    };

    if HTTP_TRAFFIC_CACHE.contains_key(&cache_key) {
        debug!(
            "Skipping duplicate HTTP event for pod: {}",
            pod_data.status.pod_name
        );
        return None;
    }

    let traffic = PodHttpTraffic {
        uuid: Uuid::new_v4().to_string(),
        pod_name: pod_data.status.pod_name.clone(),
        pod_namespace: pod_data.status.pod_namespace.clone(),
        pod_ip: pod_data.status.pod_ip.clone(),
        pod_port: Some(pod_port),
        ip_protocol: Some("TCP".to_string()),
        http_method,
        http_path,
        traffic_type: Some(traffic_type.to_string()),
        traffic_in_out_ip: Some(traffic_in_out_ip),
        traffic_in_out_port: Some(traffic_in_out_port),
        time_stamp: Utc::now().naive_utc(),
    };

    HTTP_TRAFFIC_CACHE.insert(cache_key, ()).await;

    Some(traffic)
}

/// Parse HTTP method+path from a request, or status code from a response.
/// Returns (http_method, http_path).
fn parse_http_data(
    data: &[u8; MAX_HTTP_DATA_LEN],
    data_len: usize,
    direction: u8,
) -> (Option<String>, Option<String>) {
    let len = data_len.min(MAX_HTTP_DATA_LEN);
    let text = match std::str::from_utf8(&data[..len]) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };

    match direction {
        HTTP_RECV_REQUEST | HTTP_SEND_REQUEST => {
            // "METHOD /path HTTP/1.1\r\n..."
            let mut parts = text.splitn(3, ' ');
            let method = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            let path = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            (method, path)
        }
        HTTP_RECV_RESPONSE | HTTP_SEND_RESPONSE => {
            // "HTTP/1.1 200 OK\r\n..."
            let status = text.splitn(3, ' ').nth(1).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            (None, status)
        }
        _ => (None, None),
    }
}
