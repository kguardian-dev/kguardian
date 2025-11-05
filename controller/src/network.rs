use crate::{api_post_call, Error, PodInspect, PodTraffic};
use chrono::Utc;
use dashmap::DashMap;
use moka::future::Cache;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

// Network event kind constants (from eBPF program)
const KIND_EGRESS_TCP: u16 = 1;
const KIND_INGRESS_TCP: u16 = 2;
const KIND_EGRESS_UDP: u16 = 3;

lazy_static::lazy_static! {
    static ref TRAFFIC_CACHE: Arc<Cache<TrafficKey, ()>> = Arc::new(Cache::new(10000));
}

pub mod network_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/network_probe.skel.rs"
    ));
}

pub mod netpolicy_drop {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/netpolicy_drop.skel.rs"
    ));
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct TrafficKey {
    pod_name: String,
    pod_ip: String,
    pod_port: String,
    traffic_in_out_ip: String,
    traffic_in_out_port: String,
    traffic_type: String,
    ip_protocol: String,
    decision: String,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEventData {
    pub inum: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    pub kind: u16,
}

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
    pub _pad: u8,
    pub syn_retries: u32,
}

pub async fn handle_network_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<NetworkEventData>,
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
                    if let Some(traffic) = build_traffic_event(&event, &pod_inspect).await {
                        batch.push(traffic);
                    }
                }

                // Flush if batch is full
                if batch.len() >= BATCH_SIZE {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                // Channel closed, flush remaining and exit
                if !batch.is_empty() {
                    flush_network_batch(&mut batch).await;
                }
                break;
            }
            Err(_) => {
                // Timeout reached, flush if we have any events
                if !batch.is_empty() && last_flush.elapsed() >= BATCH_TIMEOUT {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn flush_network_batch(batch: &mut Vec<PodTraffic>) {
    if batch.is_empty() {
        return;
    }

    debug!("Flushing network event batch of {} events", batch.len());

    // Send batch to API
    if let Err(e) = api_post_call(json!(batch), "pod/traffic/batch").await {
        error!("Failed to post network event batch: {}", e);
    }

    batch.clear();
}

async fn build_traffic_event(data: &NetworkEventData, pod_data: &PodInspect) -> Option<PodTraffic> {
    let src = u32::from_be(data.saddr);
    let dst = u32::from_be(data.daddr);
    let sport = data.sport;
    let dport = data.dport;

    // Use pattern matching for cleaner event kind handling
    let (traffic_type, protocol, pod_port, traffic_in_out_port) = match data.kind {
        KIND_INGRESS_TCP => ("INGRESS", "TCP", sport, 0),
        KIND_EGRESS_TCP => ("EGRESS", "TCP", 0, dport),
        KIND_EGRESS_UDP => ("EGRESS", "UDP", 0, dport),
        _ => {
            debug!("Unknown network event kind: {}", data.kind);
            return None;
        }
    };

    let traffic_in_out_ip = IpAddr::V4(Ipv4Addr::from(dst)).to_string();

    debug!(
        "Inum : {} src {}:{},dst {}:{}, traffic type {:?} kind {:?}",
        data.inum,
        IpAddr::V4(Ipv4Addr::from(src)),
        sport,
        IpAddr::V4(Ipv4Addr::from(dst)),
        dport,
        traffic_type,
        data.kind
    );

    // Skip if source and destination are the same (early return before allocations)
    if pod_data.status.pod_ip.eq(&traffic_in_out_ip) {
        return None;
    }

    // Build cache key with minimal allocations to check duplicates first
    let cache_key = TrafficKey {
        pod_name: pod_data.status.pod_name.to_string(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: pod_port.to_string(),
        traffic_in_out_ip: traffic_in_out_ip.clone(),
        traffic_in_out_port: traffic_in_out_port.to_string(),
        traffic_type: traffic_type.to_string(),
        ip_protocol: protocol.to_string(),
        decision: "ALLOW".to_string(),
    };

    // Check cache to avoid duplicates - return early if duplicate
    if TRAFFIC_CACHE.contains_key(&cache_key) {
        debug!(
            "Skipping duplicate network event for pod: {}",
            pod_data.status.pod_name
        );
        return None;
    }

    // Only allocate traffic struct if not in cache
    let traffic = PodTraffic {
        uuid: Uuid::new_v4().to_string(),
        pod_name: pod_data.status.pod_name.to_string(),
        pod_namespace: pod_data.status.pod_namespace.to_owned(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: Some(pod_port.to_string()),
        traffic_in_out_ip: Some(traffic_in_out_ip),
        traffic_in_out_port: Some(traffic_in_out_port.to_string()),
        traffic_type: Some(traffic_type.to_string()),
        ip_protocol: Some(protocol.to_string()),
        decision: Some("ALLOW".to_string()),
        time_stamp: Utc::now().naive_utc(),
    };

    debug!("Adding traffic event to batch: {:?}", cache_key);

    // Insert into cache immediately to prevent duplicates in same batch
    TRAFFIC_CACHE.insert(cache_key, ()).await;

    Some(traffic)
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

pub async fn handle_policy_drop_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<PolicyDropEvent>,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Result<(), Error> {
    // Batching configuration
    const BATCH_SIZE: usize = 100;
    const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = tokio::time::Instant::now();

    debug!("Network policy drop event handler started");

    loop {
        // Use timeout to ensure we flush even if batch not full
        let event = tokio::time::timeout(BATCH_TIMEOUT, event_receiver.recv()).await;

        match event {
            Ok(Some(event)) => {
                if let Some(pod_inspect) = container_map.get(&event.inum) {
                    if let Some(drop_event) = build_policy_drop_event(&event, &pod_inspect).await {
                        batch.push(drop_event);
                    }
                } else {
                    debug!("No pod found for network namespace inode: {}", event.inum);
                }

                // Flush if batch is full
                if batch.len() >= BATCH_SIZE {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                // Channel closed, flush remaining and exit
                if !batch.is_empty() {
                    flush_network_batch(&mut batch).await;
                }
                debug!("Network policy drop event receiver closed");
                break;
            }
            Err(_) => {
                // Timeout reached, flush if we have any events
                if !batch.is_empty() && last_flush.elapsed() >= BATCH_TIMEOUT {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn build_policy_drop_event(
    data: &PolicyDropEvent,
    pod_data: &PodInspect,
) -> Option<PodTraffic> {
    let s_ip = Ipv4Addr::from(u32::from_be(data.saddr));
    let d_ip = Ipv4Addr::from(u32::from_be(data.daddr));
    let s_port = 0;
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

    let d_ip_str = d_ip.to_string();

    // Skip if source and destination are the same (early return before allocations)
    if pod_data.status.pod_ip.eq(&d_ip_str) {
        return None;
    }

    // Build cache key with minimal allocations to check duplicates first
    let cache_key = TrafficKey {
        pod_name: pod_data.status.pod_name.to_string(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: s_port.to_string(),
        traffic_in_out_ip: d_ip_str.clone(),
        traffic_in_out_port: d_port.to_string(),
        traffic_type: "EGRESS".to_string(),
        ip_protocol: protocol_str.clone(),
        decision: "DROP".to_string(),
    };

    // Check cache to avoid duplicates - return early if duplicate
    if TRAFFIC_CACHE.contains_key(&cache_key) {
        debug!(
            "Skipping duplicate network policy drop event for pod: {}",
            pod_data.status.pod_name
        );
        return None;
    }

    // Only allocate drop event if not in cache
    let drop_event = PodTraffic {
        uuid: Uuid::new_v4().to_string(),
        pod_name: pod_data.status.pod_name.to_string(),
        pod_namespace: pod_data.status.pod_namespace.to_owned(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: Some(s_port.to_string()),
        traffic_in_out_ip: Some(d_ip_str),
        traffic_in_out_port: Some(d_port.to_string()),
        traffic_type: Some("EGRESS".to_string()),
        ip_protocol: Some(protocol_str),
        decision: Some("DROP".to_string()),
        time_stamp: Utc::now().naive_utc(),
    };

    // Insert into cache immediately to prevent duplicates in same batch
    TRAFFIC_CACHE.insert(cache_key, ()).await;

    Some(drop_event)
}
