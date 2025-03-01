use chrono::Utc;
use moka::future::Cache;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

use crate::{api_post_call, Error, PodInspect, PodTraffic};
lazy_static::lazy_static! {
    static ref TRAFFIC_CACHE: Arc<Cache<String, (String, String, String, String, String, String)>> =
        Arc::new(Cache::new(1000));
}

pub mod network_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/network_probe.skel.rs"
    ));
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkData {
    pub inum: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    old_state: u16,
    new_state: u16,
    pub kind: u16,
}

pub async fn handle_network_event(data: &NetworkData, pod_data: &PodInspect) -> Result<(), Error> {
    let src = u32::from_be(data.saddr);
    let dst = u32::from_be(data.daddr);
    let sport = data.sport;
    let dport = data.dport;
    let mut protocol = "";
    let mut pod_port = sport;
    let traffic_in_out_ip = IpAddr::V4(Ipv4Addr::from(dst)).to_string();
    let mut traffic_in_out_port = dport;
    let mut traffic_type = "";

    if data.kind.eq(&1) {
        traffic_type = "INGRESS";
        traffic_in_out_port = 0;
        protocol = "TCP";
    } else if data.kind.eq(&2) {
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
        "Inum : {} src {}:{},dst {}:{}, old state {}. new state {} trafic type {:?}",
        data.inum,
        IpAddr::V4(Ipv4Addr::from(src)),
        sport,
        IpAddr::V4(Ipv4Addr::from(dst)),
        dport,
        data.old_state,
        data.new_state,
        traffic_type
    );

    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned();
    let pod_ip = pod_data.status.pod_ip.to_string();
    let pod_port_str = pod_port.to_string();
    let traffic_in_out_ip_str = traffic_in_out_ip.to_string();
    let traffic_in_out_port_str = traffic_in_out_port.to_string();
    let traffic_type_str = traffic_type.to_string();
    let protocol_str = protocol.to_string();

    let cache_key = pod_name.clone();
    let cache_value = (
        pod_ip.clone(),
        pod_port_str.clone(),
        traffic_in_out_ip_str.clone(),
        traffic_in_out_port_str.clone(),
        traffic_type_str.clone(),
        protocol_str.clone(),
    );

    if !TRAFFIC_CACHE.contains_key(&cache_key) {
        TRAFFIC_CACHE
            .insert(cache_key.clone(), cache_value.clone())
            .await;
        let z = json!(PodTraffic {
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
        });
        debug!("Record to be inserted {}", z.to_string());
        api_post_call(z, "pod/traffic").await?
    }
    Ok(())
}
