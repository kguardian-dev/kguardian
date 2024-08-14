use std::{mem::MaybeUninit, net::{IpAddr, Ipv4Addr}};

use libbpf_rs::{skel::{OpenSkel, Skel, SkelBuilder}, MapCore, PerfBufferBuilder};
use tcpprobe::{TcpProbeSkel, TcpProbeSkelBuilder};
use anyhow::Result;

mod tcpprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcp_probe.skel.rs"
    ));
}
pub fn load_sock_set_sock_inet()-> Result<()>{
    let mut open_object = MaybeUninit::uninit();
    let skel_builder = TcpProbeSkelBuilder::default();
    let tcp_probe_skel = skel_builder.open(&mut open_object)?;
    let mut skel:TcpProbeSkel = tcp_probe_skel.load()?;

    skel.attach()?;
    let perf = PerfBufferBuilder::new(&skel.maps.tracept_events).sample_cb(|_cpu, data: &[u8]| {
    let data: &TcpData = unsafe { &*(data.as_ptr() as *const TcpData) };
        handle_event(data);
    }).build()?;
    loop {
        perf.poll(std::time::Duration::from_millis(100))?;
    }
    Ok(())
}



#[repr(C)]
pub struct TcpData {
    inum: u64,
    saddr: u32,
    daddr: u32,
}

pub fn handle_event(data: &TcpData) {
    let src = u32::from_be(data.saddr);
    let dst = u32::from_be(data.daddr);

    // println!("Inum: {} src ip {}, syn {}, ack {}, ingress_index {}", data.inum,ip_addr, data.syn, data.ack, data.ingress_ifindex);
    println!("Inum: {} src ip {},dst ip {}", data.inum,IpAddr::V4(Ipv4Addr::from(src)), IpAddr::V4(Ipv4Addr::from(dst)));
}
