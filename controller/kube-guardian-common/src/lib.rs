#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]

pub struct TrafficLog {
    // pub source_addr: u32, // ipv4 source IP address
    // pub dest_addr: u32,   // ipv4 destination IP address
    // pub src_port: u16,    // TCP or UDP remote port (sport for ingress)
    // pub dst_port: u16,    // TCP or UDP local port (dport for ingress)
    // pub syn: u16,
    // pub ack: u16,
    // pub traffic: u32,
    // pub if_index: u32,
    // pub local_ip4: u32,
    pub cgroup_id: u32,
    pub thread_id: u32,
}
#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for TrafficLog {}
}

unsafe impl Send for TrafficLog {}
