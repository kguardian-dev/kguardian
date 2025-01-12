use serde_json::json;
use chrono::Utc;
use tracing::info;
use libseccomp::{ScmpArch, ScmpSyscall};

use crate::{api_post_call, Error, PodInspect, SyscallData};

pub mod sycallprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}

#[repr(C)]
#[derive(Clone,Copy)]
pub struct SyscallTrace {
    pub inum: u64,
    pub sysnbr: u32,
}


pub async fn handle_syscall_event(data: &SyscallTrace, pod_data: &PodInspect) -> Result<(), Error> {
    let pod_name = pod_data.status.pod_name.to_string();
    let pod_namespace = pod_data.status.pod_namespace.to_owned().unwrap();
    let syscall_number = data.sysnbr;
    let syscall_name = get_syscall_name(syscall_number.try_into().unwrap()).unwrap_or_else(|| format!( "{}", syscall_number));

    let z = json!(SyscallData {
        pod_name,
        pod_namespace,
        syscalls: syscall_name,
        arch: std::env::consts::ARCH.to_string(),
        time_stamp: Utc::now().naive_utc()
    });
    info!("Record to be inserted {}", z.to_string());
    api_post_call(z, "pod/syscalls").await
    
}

fn get_syscall_name(syscall_number: i32) -> Option<String> {
    let arch = if cfg!(target_arch = "x86_64") {
        ScmpArch::X8664
    } else if cfg!(target_arch = "aarch64") {
        ScmpArch::Aarch64
    } else {
        eprintln!("Unsupported architecture");
        return None;
    };

    let syscall = ScmpSyscall::from(syscall_number);
    let name = syscall.get_name_by_arch(arch).ok()?;
    Some(name)
}
