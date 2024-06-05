#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]

pub struct TrafficLog {
    pub saddr: u32, // source address
    pub daddr: u32, // destination address
    pub sport: u16, //src port
    pub dport: u16, // dest port
    pub syn: u16,
    pub ack: u16,
    pub inum: u32, // i node numbner
}
#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for TrafficLog {}
}

unsafe impl Send for TrafficLog {}
