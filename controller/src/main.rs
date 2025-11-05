use anyhow::Result;
use dashmap::DashMap;
use std::{env, sync::Arc};
use tokio::sync::mpsc;

use tracing::info;

use kguardian::bpf::ebpf_handle;
use kguardian::log::init_logger;
use kguardian::network::{handle_network_events, handle_policy_drop_events, PolicyDropEvent};
use kguardian::service_watcher::watch_service;
use kguardian::syscall::{
    handle_syscall_events, send_syscall_cache_periodically, SyscallEventData,
};
use kguardian::{
    error::Error, models::PodInspect, network::NetworkEventData, pod_watcher::watch_pods,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logger();

    let node_name = env::var("CURRENT_NODE")
        .map_err(|_| Error::Custom("CURRENT_NODE environment variable not set".to_string()))?;

    let excluded_namespaces: Vec<String> = env::var("EXCLUDED_NAMESPACES")
        .unwrap_or_else(|_| "kube-system,kguardian".to_string())
        .split(',')
        .map(|s| s.to_string())
        .collect();

    let ignore_daemonset_traffic = env::var("IGNORE_DAEMONSET_TRAFFIC")
        .unwrap_or_else(|_| "true".to_string()) // Default to true, dont log the daemonset traffic
        .parse::<bool>()
        .unwrap_or(true);

    let (tx, rx) = mpsc::channel(1000); // Use tokio's mpsc channel

    let (sender_ip, recv_ip) = mpsc::channel(1000); // Use tokio's mpsc channel

    // Use DashMap for lock-free concurrent access (much faster than Mutex<BTreeMap>)
    let container_map: Arc<DashMap<u64, PodInspect>> = Arc::new(DashMap::new());
    let pod_c = Arc::clone(&container_map);
    let network_map = Arc::clone(&container_map);
    let syscall_map = Arc::clone(&container_map);

    let pods = watch_pods(
        node_name,
        tx,
        pod_c,
        &excluded_namespaces,
        sender_ip,
        ignore_daemonset_traffic,
    );
    info!("Ignoring namespaces: {:?}", excluded_namespaces);

    let service = watch_service();

    let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkEventData>(1000);
    let (syscall_event_sender, syscall_event_receiver) = mpsc::channel::<SyscallEventData>(1000);
    let (netpolicy_drop_sender, netpolicy_drop_receiver) = mpsc::channel::<PolicyDropEvent>(1000);

    let network_event_handler = handle_network_events(network_event_receiver, network_map);
    let netpolicy_drop_handler =
        handle_policy_drop_events(netpolicy_drop_receiver, Arc::clone(&container_map));
    let syscall_event_handler = handle_syscall_events(syscall_event_receiver, syscall_map);

    let ebpf_handle = ebpf_handle(
        network_event_sender,
        syscall_event_sender,
        netpolicy_drop_sender,
        rx,
        recv_ip,
        ignore_daemonset_traffic,
    );

    let syscall_recorder = send_syscall_cache_periodically();

    // Wait for all tasks to complete (they should run indefinitely)
    tokio::try_join!(
        service,
        pods,
        network_event_handler,
        syscall_event_handler,
        netpolicy_drop_handler,
        syscall_recorder,
        async { ebpf_handle.await? }
    )?;
    Ok(())
}
