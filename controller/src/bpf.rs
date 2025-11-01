use crate::network::network_probe::NetworkProbeSkelBuilder;
use crate::pkt_drop::packet_drop::PacketDropSkelBuilder;
use crate::pkt_drop::PacketDropEvent;
use crate::syscall::{sycallprobe::SyscallSkelBuilder, SyscallEventData};
use crate::{error::Error, network::NetworkEventData};
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, PerfBufferBuilder};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{task, task::JoinHandle};
use tracing::info;

pub fn ebpf_handle(
    network_event_sender: Sender<NetworkEventData>,
    syscall_event_sender: Sender<SyscallEventData>,
    pktevent_sender: Sender<PacketDropEvent>,
    mut rx: Receiver<u64>,
    mut ignore_ips: Receiver<String>,
    ignore_daemonset_traffic: bool,
) -> JoinHandle<Result<(), Error>> {
    task::spawn_blocking(move || {
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = NetworkProbeSkelBuilder::default();
        let network_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut network_sk = network_probe_skel.load().unwrap();
        network_sk.attach().unwrap();

        let mut open_object = MaybeUninit::uninit();

        let skel_builder = PacketDropSkelBuilder::default();
        let packet_drop_skel = skel_builder.open(&mut open_object).unwrap();
        let mut pktdrp_sk = packet_drop_skel.load().unwrap();
        pktdrp_sk.attach().unwrap();


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


        let pktdrp_perf = PerfBufferBuilder::new(&pktdrp_sk.maps.drop_events)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                let syscall_event_data: PacketDropEvent =
                    unsafe { *(data.as_ptr() as *const PacketDropEvent) };
                if let Err(e) = pktevent_sender.blocking_send(syscall_event_data) {
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
            pktdrp_perf.poll(std::time::Duration::from_millis(100))
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
                pktdrp_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
            }
            if ignore_daemonset_traffic {
                if let Ok(ip) = ignore_ips.try_recv() {
                    let ip: Ipv4Addr = ip.parse().unwrap();
                    let ip_u32 = u32::from(ip).to_be(); // Ensure the IP is in network byte order
                    network_sk
                        .maps
                        .ignore_ips
                        .update(&ip_u32.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                        .unwrap();
                }
            }
        }
    })
}
