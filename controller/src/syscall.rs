use std::{mem::MaybeUninit, net::{IpAddr, Ipv4Addr}};

use libbpf_rs::{skel::{OpenSkel, Skel, SkelBuilder}, MapCore, PerfBufferBuilder};
use serde_json::json;
use sycallprobe::{SyscallSkel, SyscallSkelBuilder};
use anyhow::Result;
use chrono::{NaiveDateTime, Utc};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{api_post_call, PodInspect, PodTraffic};

pub mod sycallprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}

#[repr(C)]
#[derive(Clone,Copy)]
pub struct SyscallData {
    pub inum: u64,
    pub sysnbr: u32,
}


pub async fn handle_syscall_event(data: &SyscallData, pod_data: &PodInspect) {
    println!("Syscall event: {:?} for pod {}", data.sysnbr, pod_data.status.pod_name);
    
}
