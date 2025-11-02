use crate::models::PodPacketDrop;
use crate::{api_post_call, Error, PodInspect};
use chrono::Utc;
use dashmap::DashMap;
use moka::future::Cache;
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{debug, error};
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
    static ref TRAFFIC_CACHE: Arc<Cache<TrafficKey, ()>> = Arc::new(Cache::new(10000));
}

pub mod packet_drop {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/packet_drop.skel.rs"
    ));
}
pub use packet_drop::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketDropEvent {
    pub timestamp: u64,
    pub inum: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub drop_location: u64,
}

fn proto_to_string(proto: u8) -> String {
    match proto {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        1 => "ICMP".to_string(),
        58 => "ICMPv6".to_string(), // common IPv6 ICMP
        _ => format!("UNKNOWN({})", proto),
    }
}

pub async fn handle_packet_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<PacketDropEvent>,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Result<(), Error> {
    // Batching configuration
    const BATCH_SIZE: usize = 100;
    const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = tokio::time::Instant::now();

    loop {
        // Use timeout to ensure we flush even if batch not full
        let event = tokio::time::timeout(BATCH_TIMEOUT, event_receiver.recv()).await;

        match event {
            Ok(Some(event)) => {
                // DashMap provides lock-free reads - no need for explicit locking!
                if let Some(pod_inspect) = container_map.get(&event.inum) {
                    if let Some(drop_event) = build_packet_drop_event(&event, &pod_inspect).await {
                        batch.push(drop_event);
                    }
                }

                // Flush if batch is full
                if batch.len() >= BATCH_SIZE {
                    flush_packet_drop_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                // Channel closed, flush remaining and exit
                if !batch.is_empty() {
                    flush_packet_drop_batch(&mut batch).await;
                }
                break;
            }
            Err(_) => {
                // Timeout reached, flush if we have any events
                if !batch.is_empty() && last_flush.elapsed() >= BATCH_TIMEOUT {
                    flush_packet_drop_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn flush_packet_drop_batch(batch: &mut Vec<PodPacketDrop>) {
    if batch.is_empty() {
        return;
    }

    debug!("Flushing packet drop event batch of {} events", batch.len());

    // Send batch to API
    if let Err(e) = api_post_call(json!(batch), "pod/packet_drop/batch").await {
        error!("Failed to post packet drop event batch: {}", e);
    }

    batch.clear();
}

async fn build_packet_drop_event(
    data: &PacketDropEvent,
    pod_data: &PodInspect,
) -> Option<PodPacketDrop> {
    let s_ip = Ipv4Addr::from(u32::from_be(data.saddr));
    let d_ip = Ipv4Addr::from(u32::from_be(data.daddr));
    let s_port = data.sport;
    let d_port = data.dport;
    debug!("Packet Drop Event: Pod: {}, Namespace: {:?}, Src: {}:{}, Dst: {}:{}, Protocol: {}, Drop Location: 0x{:x}",
        pod_data.status.pod_name,
        pod_data.status.pod_namespace,
        s_ip,
        s_port,
        d_ip,
        d_port,
        data.protocol,
        data.drop_location
    );

    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned();
    let pod_ip = pod_data.status.pod_ip.to_string();
    let traffic_in_out_ip_str = d_ip.to_string();
    let traffic_in_out_port_str = d_port.to_string();
    let traffic_type_str = "EGRESS".to_string();
    let protocol_str = proto_to_string(data.protocol);

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
    if !TRAFFIC_CACHE.contains_key(&cache_key) {
        let drop_event = PodPacketDrop {
            uuid: Uuid::new_v4().to_string(),
            pod_name,
            pod_namespace,
            pod_ip,
            pod_port: Some("0".to_string()),
            traffic_in_out_ip: Some(traffic_in_out_ip_str),
            traffic_in_out_port: Some(traffic_in_out_port_str),
            traffic_type: Some(traffic_type_str),
            drop_reason: Some("Network Policy".to_string()),
            ip_protocol: Some(protocol_str),
            time_stamp: Utc::now().naive_utc(),
        };
        // Insert into cache immediately to prevent duplicates in same batch
        TRAFFIC_CACHE.insert(cache_key, ()).await;

        return Some(drop_event);
    } else {
        debug!("Skipping duplicate packet drop event for pod: {}", pod_name);
    }

    None
}
