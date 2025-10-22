use anyhow::Result;
use kube_guardian::http::{handle_http_events, HttpEventData};
use std::{collections::BTreeMap, env, sync::Arc};
use tokio::sync::{mpsc, Mutex};

use tracing::info;

use kube_guardian::bpf::ebpf_handle;
use kube_guardian::log::init_logger;
use kube_guardian::network::handle_network_events;
use kube_guardian::service_watcher::watch_service;
use kube_guardian::syscall::{
    handle_syscall_events, send_syscall_cache_periodically, SyscallEventData,
};
use kube_guardian::{
    error::Error, models::PodInspect, network::NetworkEventData, pod_watcher::watch_pods,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logger();

    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");

    let excluded_namespaces: Vec<String> = env::var("EXCLUDED_NAMESPACES")
        .unwrap_or_else(|_| "kube-system,kube-guardian".to_string())
        .split(',')
        .map(|s| s.to_string())
        .collect();

    let ignore_daemonset_traffic = env::var("IGNORE_DAEMONSET_TRAFFIC")
        .unwrap_or_else(|_| "true".to_string()) // Default to true, dont log the daemonset traffic
        .parse::<bool>()
        .unwrap_or(true);

    let (tx, rx) = mpsc::channel(1000); // Use tokio's mpsc channel

    let (sender_ip, recv_ip) = mpsc::channel(1000); // Use tokio's mpsc channel

    let c: Arc<Mutex<BTreeMap<u64, PodInspect>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let pod_c = Arc::clone(&c);
    let container_map = Arc::clone(&c);
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
    let (http_event_sender, http_event_receiver) = mpsc::channel::<HttpEventData>(1000);

    let network_event_handler =
        handle_network_events(network_event_receiver, Arc::clone(&container_map));
    let syscall_event_handler = handle_syscall_events(syscall_event_receiver, Arc::clone(&container_map));
    let http_event_handler = handle_http_events(http_event_receiver, container_map);

    let ebpf_handle = ebpf_handle(
        network_event_sender,
        syscall_event_sender,
        http_event_sender,
        rx,
        recv_ip,
        ignore_daemonset_traffic,
    );

    let syscall_recorder = send_syscall_cache_periodically();

    // Wait for all tasks to complete (they should run indefinitely)
    _ = tokio::try_join!(
        service,
        pods,
        network_event_handler,
        syscall_event_handler,
        http_event_handler,
        syscall_recorder,
        async { ebpf_handle.await.unwrap() }
    )
    .unwrap();
    Ok(())
}
