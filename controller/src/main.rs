use std::collections::BTreeMap;
use std::env;
use std::mem::MaybeUninit;
use std::sync::Arc;
use kube_guardian::network::handle_network_event;
use kube_guardian::network::tcpprobe::TcpProbeSkelBuilder;
use kube_guardian::service_watcher::watch_service;
use kube_guardian::syscall::handle_syscall_event;
use kube_guardian::syscall::sycallprobe::SyscallSkelBuilder;
use kube_guardian::syscall::SyscallTrace;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;


use kube_guardian::models::PodInspect;
use kube_guardian::network::TcpData;
use kube_guardian::pod_watcher::watch_pods;
use kube_guardian::error::Error;
use tokio::task;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;


#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let c: Arc<TokioMutex<BTreeMap<u64, PodInspect>>> = Arc::new(TokioMutex::new(BTreeMap::new()));

    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");
    let (tx, mut rx) = mpsc::channel(100); // Use tokio's mpsc channel
    let pod_c = Arc::clone(&c);

    let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkEventData>(1000);
    let (syscall_event_sender, syscall_event_receiver) = mpsc::channel::<SyscallEventData>(1000);
    let container_map = Arc::clone(&c);

    let pods = watch_pods(node_name, tx, pod_c);
    let service = watch_service();
    let network_event_handler = handle_network_events(network_event_receiver, Arc::clone(&container_map));
    let syscall_event_handler = handle_syscall_events(syscall_event_receiver, container_map);

    // Spawn the eBPF handling task
    let ebpf_handle:JoinHandle<Result<(), Error>>  = task::spawn_blocking(move || {
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = TcpProbeSkelBuilder::default();
        let tcp_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut network_sk = tcp_probe_skel.load().unwrap();
        network_sk.attach().unwrap();

        let mut open_object = MaybeUninit::uninit();

        let skel_builder = SyscallSkelBuilder::default();
        let syscall_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut syscall_sk = syscall_probe_skel.load().unwrap();
        syscall_sk.attach().unwrap();


        let network_perf = PerfBufferBuilder::new(&network_sk.maps.tracept_events)
            .sample_cb(move |_cpu, data: &[u8]| {
                let tcp_data: TcpData = unsafe { *(data.as_ptr() as *const TcpData) };
                let event_data = NetworkEventData {
                    inum: tcp_data.inum,
                    tcp_data,
                };
                if let Err(e) = network_event_sender.blocking_send(event_data) {
                    eprintln!("Failed to send TCP event: {:?}", e);
                }
            })
            .build()
            .unwrap();

            let syscall_perf = PerfBufferBuilder::new(&syscall_sk.maps.syscall_events)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                let syscall_data: SyscallTrace = unsafe { *(data.as_ptr() as *const SyscallTrace) };
                let syscall_event_data = SyscallEventData {
                    syscall_data,
                };
                if let Err(e) = syscall_event_sender.blocking_send(syscall_event_data) {
                    eprintln!("Failed to send Syscakll event: {:?}", e);
                }
            })
            .build()
            .unwrap();

 
        loop {
            network_perf.poll(std::time::Duration::from_millis(100)).unwrap();
            syscall_perf.poll(std::time::Duration::from_millis(100)).unwrap();
        

            // Process any incoming messages from the pod watcher
            if let Ok(inum) = rx.try_recv() {
                println!("Received inode number: {}", inum);
                network_sk.maps.inode_num.update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY).unwrap();
                syscall_sk.maps.inode_num.update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY).unwrap();
            }
           
        }
        
    });

    // Wait for all tasks to complete (they should run indefinitely)
    _ = tokio::try_join!(
        service,
        pods,
        network_event_handler,
        syscall_event_handler,
        async { ebpf_handle.await.unwrap() }
    ).unwrap();
    Ok(())
}

#[derive(Clone)]
struct NetworkEventData {
    inum: u64,
    tcp_data: TcpData,
}

#[derive(Clone)]
struct SyscallEventData {
    syscall_data: SyscallTrace,
}


async fn handle_network_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<NetworkEventData>,
    container_map_tcp: Arc<TokioMutex<BTreeMap<u64, PodInspect>>>,
)->Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_tcp.lock().await;
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            handle_network_event(&event.tcp_data, pod_inspect).await?
        }
    }
    Ok(())
}


async fn handle_syscall_events(
    mut event_receiver: mpsc::Receiver<SyscallEventData>,
    container_map_udp: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_udp.lock().await;
        if let Some(pod_inspect) = container_map.get(&event.syscall_data.inum ) {
            handle_syscall_event(&event.syscall_data, pod_inspect).await?
        }
    }
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

