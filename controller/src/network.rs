use std::{mem::MaybeUninit, net::{IpAddr, Ipv4Addr}};

use libbpf_rs::{skel::{OpenSkel, Skel, SkelBuilder}, MapCore, PerfBufferBuilder};
use serde_json::json;
use tcpprobe::{TcpProbeSkel, TcpProbeSkelBuilder};
use anyhow::Result;
use chrono::{NaiveDateTime, Utc};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{api_post_call, PodInspect, PodTraffic};

pub mod tcpprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcp_probe.skel.rs"
    ));
}
// pub fn load_sock_set_sock_inet()-> Result<()>{
//     let mut open_object = MaybeUninit::uninit();
//     let skel_builder = TcpProbeSkelBuilder::default();
//     let tcp_probe_skel = skel_builder.open(&mut open_object)?;
//     let mut skel:TcpProbeSkel = tcp_probe_skel.load()?;

//     skel.attach()?;
//     let perf = PerfBufferBuilder::new(&skel.maps.tracept_events).sample_cb(|_cpu, data: &[u8]| {
//     let data: &TcpData = unsafe { &*(data.as_ptr() as *const TcpData) };
//         handle_event(data);
//     }).build()?;
//     loop {
//         perf.poll(std::time::Duration::from_millis(100))?;
//     }
//     Ok(())
// }



#[repr(C)]
#[derive(Clone,Copy)]
pub struct TcpData {
    pub inum: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    old_state: u16,
    new_state : u16,
    pub kind: u16,
}

pub async fn handle_event(data: &TcpData, pod_data: &PodInspect) {
    let src = u32::from_be(data.saddr);
    let dst = u32::from_be(data.daddr);
    let sport = data.sport;
    let dport = data.dport;
    let mut protocol = "";
    let mut pod_port = sport;
    let mut kind = "";
    let traffic_in_out_ip = IpAddr::V4(Ipv4Addr::from(dst)).to_string();
    let mut traffic_in_out_port = dport;
    let mut traffic_type="" ;

    if data.kind.eq(&1) {
        traffic_type = "INGRESS";
        traffic_in_out_port = 0;
        protocol = "TCP";
 
    }else if data.kind.eq(&2) {
        traffic_type = "EGRESS";
        pod_port = 0;
        protocol = "TCP";
    }else if data.kind.eq(&3){
        traffic_type = "EGRESS";
        pod_port = 0;
        traffic_in_out_port = dport;
        protocol = "UDP"

    }
 // println!("Inum: {} src ip {}, syn {}, ack {}, ingress_index {}", data.inum,ip_addr, data.syn, data.ack, data.ingress_ifindex);
    println!("Inum: {} src {}:{},dst {}:{}, kind {}, old state {}. new state {}", data.inum,IpAddr::V4(Ipv4Addr::from(src)),sport, IpAddr::V4(Ipv4Addr::from(dst)), dport, kind, data.old_state, data.new_state);

    
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
    api_post_call(z, "netpol/pods").await;

    // this should await, but we in blocking thread
    // TODO, think of doing of better way, we wont know if the post call is done or not
    

}
