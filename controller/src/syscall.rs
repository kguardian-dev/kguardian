use chrono::Utc;
use dashmap::DashMap;
use libseccomp::{ScmpArch, ScmpSyscall};
use moka::future::Cache;
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error};

use crate::{api_post_call, Error, PodInspect, SyscallData};

pub mod sycallprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}

type SyscallCache = Cache<String, Arc<Mutex<HashSet<String>>>>;

lazy_static::lazy_static! {
    static ref SYSCALL_CACHE: SyscallCache = Cache::new(10_000);
    static ref LAST_SENT_CACHE: SyscallCache = Cache::new(10_000);
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEventData {
    pub inum: u64,
    pub sysnbr: u32,
}

pub async fn handle_syscall_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<SyscallEventData>,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        // DashMap provides lock-free reads - no need for explicit locking!
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            process_syscall_event(&event, &pod_inspect).await?
        }
    }
    tracing::error!("Syscall event receiver exited unexpectedly!");
    Ok(())
}

pub async fn process_syscall_event(
    data: &SyscallEventData,
    pod_data: &PodInspect,
) -> Result<(), Error> {
    let pod_name = pod_data.status.pod_name.to_string();
    let syscall_number = data.sysnbr;
    let syscall_name = get_syscall_name(syscall_number.try_into().unwrap())
        .unwrap_or_else(|| format!("{}", syscall_number));

    let syscalls = SYSCALL_CACHE
        .get_with(pod_name.clone(), async {
            Arc::new(Mutex::new(HashSet::new()))
        })
        .await;

    let mut syscalls_lock = syscalls.lock().await;

    if syscalls_lock.contains(&syscall_name) {
        debug!(
            "Skipping duplicate syscall: {} for pod: {}",
            syscall_name, pod_name
        );
    } else {
        syscalls_lock.insert(syscall_name.clone());
    }

    Ok(())
}

pub async fn send_syscall_cache_periodically() -> Result<(), Error> {
    // Reduced from 60s to 10s for faster visibility of syscall data
    let interval_duration = std::time::Duration::from_secs(10);
    for _ in 0.. {
        let mut batch = Vec::new();

        for (pod_name, syscalls) in SYSCALL_CACHE.iter() {
            let syscalls_lock = syscalls.lock().await;
            let last_sent = LAST_SENT_CACHE
                .get_with(pod_name.to_string(), async {
                    Arc::new(Mutex::new(HashSet::new()))
                })
                .await;
            let mut last_sent_lock = last_sent.lock().await;

            if *syscalls_lock != *last_sent_lock {
                let syscall_names: Vec<String> = syscalls_lock.iter().cloned().collect();
                let z = json!(SyscallData {
                    pod_name: pod_name.to_string(),
                    pod_namespace: "".to_string(), // We will not store the namespace and rather read it from the pod_details table
                    syscalls: syscall_names,
                    arch: std::env::consts::ARCH.to_string(),
                    time_stamp: Utc::now().naive_utc()
                });
                batch.push(z);
                debug!("Sending batch of {} syscalls to API", batch.len());
                *last_sent_lock = syscalls_lock.clone();
            }
        }

        if !batch.is_empty() {
            if let Err(e) = api_post_call(json!(batch), "pod/syscalls").await {
                error!("Failed to post Syscall Event: {}", e);
            }
        }
        tokio::time::sleep(interval_duration).await;
    }

    Ok(())
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
