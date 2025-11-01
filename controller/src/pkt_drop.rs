use crate::models::PodPacketDrop;
use crate::{api_post_call, Error, PodInspect};
use chrono::Utc;
use moka::future::Cache;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
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
    container_map_tcp: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_tcp.lock().await;
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            process_pkt_drop_event(&event, pod_inspect).await?
        }
    }
    Ok(())
}

pub async fn process_pkt_drop_event(
    data: &PacketDropEvent,
    pod_data: &PodInspect,
) -> Result<(), Error> {
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

    if pod_ip.eq(&traffic_in_out_ip_str) {
        return Ok(());
    }

    let cache_key = TrafficKey {
        pod_name: pod_name.clone(),
        pod_ip: pod_ip.clone(),
        traffic_in_out_ip: traffic_in_out_ip_str.clone(),
        traffic_in_out_port: traffic_in_out_port_str.clone(),
        traffic_type: traffic_type_str.clone(),
        ip_protocol: protocol_str.clone(),
    };

    if !TRAFFIC_CACHE.contains_key(&cache_key) {
        let z = json!(PodPacketDrop {
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
        });
        debug!("Record to be inserted {}", z.to_string());
        if let Err(e) = api_post_call(z, "pod/packet_drop").await {
            error!("Failed to post Network event: {}", e);
        } else {
            TRAFFIC_CACHE.insert(cache_key.clone(), ()).await;
        }
    } else {
        debug!("Skipping duplicate network event for pod: {}", pod_name);
    }

    Ok(())
}
