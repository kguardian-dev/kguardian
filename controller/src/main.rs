use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, PerfBufferBuilder};
use std::{collections::BTreeMap, env, mem::MaybeUninit, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio::{task, task::JoinHandle};

use kube_guardian::network::{handle_network_events, network_probe::NetworkProbeSkelBuilder};
use kube_guardian::service_watcher::watch_service;
use kube_guardian::syscall::{
    handle_syscall_events, send_syscall_cache_periodically, sycallprobe::SyscallSkelBuilder,
    SyscallEventData,
};
use kube_guardian::{
    error::Error, models::PodInspect, network::NetworkEventData, pod_watcher::watch_pods,
};

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let c: Arc<Mutex<BTreeMap<u64, PodInspect>>> = Arc::new(Mutex::new(BTreeMap::new()));

    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");
    let (tx, mut rx) = mpsc::channel(100); // Use tokio's mpsc channel
    let pod_c = Arc::clone(&c);

    let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkEventData>(1000);
    let (syscall_event_sender, syscall_event_receiver) = mpsc::channel::<SyscallEventData>(1000);
    let container_map = Arc::clone(&c);

    let pods = watch_pods(node_name, tx, pod_c);
    let service = watch_service();
    let network_event_handler =
        handle_network_events(network_event_receiver, Arc::clone(&container_map));
    let syscall_event_handler = handle_syscall_events(syscall_event_receiver, container_map);

    // Spawn the eBPF handling task
    let ebpf_handle: JoinHandle<Result<(), Error>> = task::spawn_blocking(move || {
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = NetworkProbeSkelBuilder::default();
        let network_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut network_sk = network_probe_skel.load().unwrap();
        network_sk.attach().unwrap();

        let mut open_object = MaybeUninit::uninit();

        let skel_builder = SyscallSkelBuilder::default();
        let syscall_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut syscall_sk = syscall_probe_skel.load().unwrap();
        syscall_sk.attach().unwrap();

        let network_perf = PerfBufferBuilder::new(&network_sk.maps.tracept_events)
            .sample_cb(move |_cpu, data: &[u8]| {
                let network_event_data: NetworkEventData =
                    unsafe { *(data.as_ptr() as *const NetworkEventData) };

                if let Err(e) = network_event_sender.blocking_send(network_event_data) {
                    // eprintln!("Failed to send TCP event: {:?}", e);
                    // TODO: If SendError, possibly the receiver is closed, restart the controller
                }
            })
            .build()
            .unwrap();

        let syscall_perf = PerfBufferBuilder::new(&syscall_sk.maps.syscall_events)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                let syscall_event_data: SyscallEventData =
                    unsafe { *(data.as_ptr() as *const SyscallEventData) };
                if let Err(e) = syscall_event_sender.blocking_send(syscall_event_data) {
                    //eprintln!("Failed to send Syscall event: {:?}", e);
                    //TODO: If SendError, possibly the receiver is closed, restart the controller
                }
            })
            .build()
            .unwrap();

        loop {
            network_perf
                .poll(std::time::Duration::from_millis(100))
                .unwrap();
            syscall_perf
                .poll(std::time::Duration::from_millis(100))
                .unwrap();

            // Process any incoming messages from the pod watcher
            if let Ok(inum) = rx.try_recv() {
                network_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
                syscall_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
            }
        }
    });

    let syscall_recorder = send_syscall_cache_periodically();

    // Wait for all tasks to complete (they should run indefinitely)
    _ = tokio::try_join!(
        service,
        pods,
        network_event_handler,
        syscall_event_handler,
        syscall_recorder,
        async { ebpf_handle.await.unwrap() }
    )
    .unwrap();
    Ok(())
}

pub fn init_logger() {
    // check the rust log
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    if std::env::var("RUST_LOG").unwrap().to_lowercase().eq("info") {
        std::env::set_var("RUST_LOG", "info,kube_client=off");
    } else {
        std::env::set_var(
            "RUST_LOG",
            "debug,kube_client=off,tower=off,hyper=off,h2=off,rustls=off,reqwest=off",
        );
    }

    let timer = time::format_description::parse(
        "[year]-[month padding:zero]-[day padding:zero] [hour]:[minute]:[second]",
    )
    .expect("Time Error");
    let time_offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(time_offset, timer);

    // Initialize the logger
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_timer(timer)
        .init();
}
