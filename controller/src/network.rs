use crate::{api_post_call, Error, PodInspect, PodTraffic};
use chrono::Utc;
use dashmap::DashMap;
use moka::future::Cache;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

lazy_static::lazy_static! {
    static ref TRAFFIC_CACHE: Arc<Cache<TrafficKey, ()>> = Arc::new(Cache::new(10000));
}

pub mod network_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/network_probe.skel.rs"
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

async fn build_traffic_event(
    data: &NetworkEventData,
    pod_data: &PodInspect,
) -> Option<PodTraffic> {
    let src = u32::from_be(data.saddr);
    let dst = u32::from_be(data.daddr);
    let sport = data.sport;
    let dport = data.dport;
    let mut protocol = "";
    let mut pod_port = sport;
    let traffic_in_out_ip = IpAddr::V4(Ipv4Addr::from(dst)).to_string();
    let mut traffic_in_out_port = dport;
    let mut traffic_type = "";

    if data.kind.eq(&2) {
        traffic_type = "INGRESS";
        traffic_in_out_port = 0;
        protocol = "TCP";
    } else if data.kind.eq(&1) {
        traffic_type = "EGRESS";
        pod_port = 0;
        protocol = "TCP";
    } else if data.kind.eq(&3) {
        traffic_type = "EGRESS";
        pod_port = 0;
        traffic_in_out_port = dport;
        protocol = "UDP"
    }

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

    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned();
    let pod_ip = pod_data.status.pod_ip.to_string();
    let pod_port_str = pod_port.to_string();
    let traffic_in_out_ip_str = traffic_in_out_ip.to_string();
    let traffic_in_out_port_str = traffic_in_out_port.to_string();
    let traffic_type_str = traffic_type.to_string();
    let protocol_str = protocol.to_string();

    // Skip if source and destination are the same
    if pod_ip.eq(&traffic_in_out_ip_str) {
        return None;
    }

    let cache_key = TrafficKey {
        pod_name: pod_name.clone(),
        pod_ip: pod_ip.clone(),
        pod_port: pod_port_str.clone(),
        traffic_in_out_ip: traffic_in_out_ip_str.clone(),
        traffic_in_out_port: traffic_in_out_port_str.clone(),
        traffic_type: traffic_type_str.clone(),
        ip_protocol: protocol_str.clone(),
    };

    // Check cache to avoid duplicates
    if !TRAFFIC_CACHE.contains_key(&cache_key) {
        let traffic = PodTraffic {
            uuid: Uuid::new_v4().to_string(),
            pod_name,
            pod_namespace,
            pod_ip,
            pod_port: Some(pod_port_str),
            traffic_in_out_ip: Some(traffic_in_out_ip_str),
            traffic_in_out_port: Some(traffic_in_out_port_str),
            traffic_type: Some(traffic_type_str),
            ip_protocol: Some(protocol_str),
            time_stamp: Utc::now().naive_utc(),
        };

        debug!("Adding traffic event to batch: {:?}", cache_key);

        // Insert into cache immediately to prevent duplicates in same batch
        TRAFFIC_CACHE.insert(cache_key, ()).await;

        return Some(traffic);
    } else {
        debug!("Skipping duplicate network event for pod: {}", pod_name);
    }

    None
}
