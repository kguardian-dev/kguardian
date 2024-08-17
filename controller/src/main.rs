// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use anyhow::bail;
use anyhow::Result;
use futures::channel::mpsc::Receiver;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;

use plain::Plain;
use kube_guardian::models::PodInspect;
use kube_guardian::tcp::handle_event;
use kube_guardian::tcp::TcpData;
use kube_guardian::watcher::watch_pods;
use kube_guardian::error::Error;


use kube_guardian::watcher::tcpprobe::TcpProbeSkelBuilder;

mod syscall {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}

use syscall::*;



#[repr(C)]
pub struct UdpData {
    pub inum: u64,
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}



use tokio::task;

use tokio::sync::Mutex as TokioMutex;
use futures::StreamExt;
use tokio::task::JoinHandle;


#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let c: Arc<TokioMutex<BTreeMap<u64, PodInspect>>> = Arc::new(TokioMutex::new(BTreeMap::new()));

    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");
    let (tx, mut rx) = mpsc::channel(100); // Use tokio's mpsc channel
    let pod_c = Arc::clone(&c);

    let (event_sender, event_receiver) = mpsc::channel::<EventData>(1000);
    let container_map_tcp = Arc::clone(&c);

    // Spawn the pod watcher task
    let pods:JoinHandle<Result<(), Error>>  = tokio::spawn(async move {
        watch_pods(node_name, tx, pod_c).await
    });

    // Spawn the event handler task
    let event_handler:JoinHandle<Result<(), Error>>  = tokio::spawn(async move {
        handle_events(event_receiver, container_map_tcp).await;
        Ok(())
    });


    // Spawn the eBPF handling task
    let ebpf_handle:JoinHandle<Result<(), Error>>  = task::spawn_blocking(move || {
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = TcpProbeSkelBuilder::default();
        let tcp_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut sk = tcp_probe_skel.load().unwrap();
        sk.attach().unwrap();

        let perf = PerfBufferBuilder::new(&sk.maps.tracept_events)
            .sample_cb(move |_cpu, data: &[u8]| {
                let tcp_data: TcpData = unsafe { *(data.as_ptr() as *const TcpData) };
                let event_data = EventData {
                    inum: tcp_data.inum,
                    tcp_data,
                };
                if let Err(e) = event_sender.blocking_send(event_data) {
                    eprintln!("Failed to send TCP event: {:?}", e);
                }
            })
            .build()
            .unwrap();

 
        loop {
            perf.poll(std::time::Duration::from_millis(100)).unwrap();
            // perf_udp.poll(std::time::Duration::from_millis(100)).unwrap();

            // Process any incoming messages from the pod watcher
            if let Ok(inum) = rx.try_recv() {
                println!("Received inode number: {}", inum);
                sk.maps.inode_num.update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY).unwrap();
            }
        }
        Ok(())
    });

    // Wait for all tasks to complete (they should run indefinitely)
    _ = tokio::try_join!(
        async { pods.await.unwrap() },
        async { event_handler.await.unwrap() },
        async { ebpf_handle.await.unwrap() }
    ).unwrap();
    Ok(())
}

#[derive(Clone)]
struct EventData {
    inum: u64,
    tcp_data: TcpData,
}

async fn handle_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<EventData>,
    container_map_tcp: Arc<TokioMutex<BTreeMap<u64, PodInspect>>>,
) {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_tcp.lock().await;
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            handle_event(&event.tcp_data, pod_inspect).await;
        }
    }
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

