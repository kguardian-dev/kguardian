use crate::models::PodPacketDrop;
use crate::{api_post_call, Error, PodInspect};
use chrono::Utc;
use moka::future::Cache;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Hash, Eq, PartialEq, Clone)]
struct TrafficKey {
    pod_name: String,
    pod_ip: String,
    traffic_in_out_ip: String,
    traffic_in_out_port: String,
    traffic_type: String,
    ip_protocol: String,
}

lazy_static::lazy_static! {
    static ref NETPOLICY_CACHE: Arc<Cache<TrafficKey, ()>> = Arc::new(Cache::new(10000));
}

pub mod netpolicy_drop {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/netpolicy_drop.skel.rs"
    ));
}
pub use netpolicy_drop::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PolicyDropEvent {
    pub timestamp: u64,
    pub inum: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub _pad: [u8; 1],      // Align to next field
    pub syn_retries: u32,
}

fn proto_to_string(proto: u8) -> String {
    match proto {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        1 => "ICMP".to_string(),
        58 => "ICMPv6".to_string(),
        _ => format!("UNKNOWN({})", proto),
    }
}

fn get_drop_reason(protocol: u8, syn_retries: u32) -> String {
    if syn_retries > 0 {
        format!("Network Policy (Connection Timeout - {} SYN retries)", syn_retries)
    } else {
        match protocol {
            6 => "Network Policy (TCP Drop)".to_string(),
            17 => "Network Policy (UDP Drop)".to_string(),
            1 => "Network Policy (ICMP Drop)".to_string(),
            _ => "Network Policy".to_string(),
        }
    }
}

pub async fn handle_netpolicy_drop_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<PolicyDropEvent>,
    container_map: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Result<(), Error> {
    // Batching configuration
    const BATCH_SIZE: usize = 100;
    const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = tokio::time::Instant::now();

    info!("Network policy drop event handler started");

    loop {
        // Use timeout to ensure we flush even if batch not full
        let event = tokio::time::timeout(BATCH_TIMEOUT, event_receiver.recv()).await;

        match event {
            Ok(Some(event)) => {
                let container_map_locked = container_map.lock().await;
                if let Some(pod_inspect) = container_map_locked.get(&event.inum) {
                    if let Some(drop_event) = build_netpolicy_drop_event(&event, pod_inspect).await {
                        batch.push(drop_event);
                    }
                    drop(container_map_locked); // Release lock early
                } else {
                    drop(container_map_locked);
                    debug!("No pod found for network namespace inode: {}", event.inum);
                }

                // Flush if batch is full
                if batch.len() >= BATCH_SIZE {
                    flush_netpolicy_drop_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                // Channel closed, flush remaining and exit
                if !batch.is_empty() {
                    flush_netpolicy_drop_batch(&mut batch).await;
                }
                info!("Network policy drop event receiver closed");
                break;
            }
            Err(_) => {
                // Timeout reached, flush if we have any events
                if !batch.is_empty() && last_flush.elapsed() >= BATCH_TIMEOUT {
                    flush_netpolicy_drop_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn flush_netpolicy_drop_batch(batch: &mut Vec<PodPacketDrop>) {
    if batch.is_empty() {
        return;
    }

    debug!("Flushing network policy drop event batch of {} events", batch.len());

    // Send batch to API
    if let Err(e) = api_post_call(json!(batch), "pod/packet_drop/batch").await {
        error!("Failed to post network policy drop event batch: {}", e);
    } else {
        info!("Successfully posted {} network policy drop events", batch.len());
    }

    batch.clear();
}

async fn build_netpolicy_drop_event(
    data: &PolicyDropEvent,
    pod_data: &PodInspect,
) -> Option<PodPacketDrop> {
    let s_ip = Ipv4Addr::from(u32::from_be(data.saddr));
    let d_ip = Ipv4Addr::from(u32::from_be(data.daddr));
    let s_port = data.sport;
    let d_port = data.dport;
    let protocol_str = proto_to_string(data.protocol);

    debug!(
        "Network Policy Drop: Pod: {}, Namespace: {:?}, Src: {}:{}, Dst: {}:{}, Protocol: {}, SYN Retries: {}",
        pod_data.status.pod_name,
        pod_data.status.pod_namespace,
        s_ip,
        s_port,
        d_ip,
        d_port,
        protocol_str,
        data.syn_retries
    );

    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned();
    let pod_ip = pod_data.status.pod_ip.to_string();
    let traffic_in_out_ip_str = d_ip.to_string();
    let traffic_in_out_port_str = d_port.to_string();
    let traffic_type_str = "EGRESS".to_string();

    // Skip if source and destination are the same
    if pod_ip.eq(&traffic_in_out_ip_str) {
        return None;
    }

    let cache_key = TrafficKey {
        pod_name: pod_name.clone(),
        pod_ip: pod_ip.clone(),
        traffic_in_out_ip: traffic_in_out_ip_str.clone(),
        traffic_in_out_port: traffic_in_out_port_str.clone(),
        traffic_type: traffic_type_str.clone(),
        ip_protocol: protocol_str.clone(),
    };

    // Check cache to avoid duplicates
    if !NETPOLICY_CACHE.contains_key(&cache_key) {
        let drop_reason = get_drop_reason(data.protocol, data.syn_retries);

        let drop_event = PodPacketDrop {
            uuid: Uuid::new_v4().to_string(),
            pod_name,
            pod_namespace,
            pod_ip,
            pod_port: Some(s_port.to_string()),
            traffic_in_out_ip: Some(traffic_in_out_ip_str),
            traffic_in_out_port: Some(traffic_in_out_port_str),
            traffic_type: Some(traffic_type_str),
            drop_reason: Some(drop_reason),
            ip_protocol: Some(protocol_str),
            time_stamp: Utc::now().naive_utc(),
        };

        // Insert into cache immediately to prevent duplicates in same batch
        NETPOLICY_CACHE.insert(cache_key, ()).await;

        return Some(drop_event);
    } else {
        debug!("Skipping duplicate network policy drop event for pod: {}", pod_name);
    }

    None
}
