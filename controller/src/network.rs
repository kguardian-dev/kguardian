use chrono::Utc;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{api_post_call, Error, PodInspect, PodTraffic};

pub mod tcpprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcp_probe.skel.rs"
    ));
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpData {
    pub inum: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    old_state: u16,
    new_state: u16,
    pub kind: u16,
}

pub async fn handle_network_event(data: &TcpData, pod_data: &PodInspect) -> Result<(), Error> {
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
        "Inum: {} src {}:{},dst {}:{}, old state {}. new state {}",
        data.inum,
        IpAddr::V4(Ipv4Addr::from(src)),
        sport,
        IpAddr::V4(Ipv4Addr::from(dst)),
        dport,
        data.old_state,
        data.new_state
    );

    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned();
    let pod_ip = pod_data.status.pod_ip.to_string();
    let z = json!(PodTraffic {
        uuid: Uuid::new_v4().to_string(),
        pod_name,
        pod_namespace,
        pod_ip,
        pod_port: Some(pod_port.to_string()),
        traffic_in_out_ip: Some(traffic_in_out_ip.to_string()),
        traffic_in_out_port: Some(traffic_in_out_port.to_string()),
        traffic_type: Some(traffic_type.to_string()),
        ip_protocol: Some(protocol.to_string()),
        // example: 2007-04-05T14:30:30
        time_stamp: Utc::now().naive_utc() // .format("%Y-%m-%dT%H:%M:%S.%fZ")
                                           // .to_string(),
    });
    info!("Record to be inserted {}", z.to_string());
    api_post_call(z, "pod/traffic").await
}
