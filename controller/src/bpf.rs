use crate::network::netpolicy_drop::NetpolicyDropSkelBuilder;
use crate::network::network_probe::NetworkProbeSkelBuilder;
use crate::network::PolicyDropEvent;
use crate::syscall::{sycallprobe::SyscallSkelBuilder, SyscallEventData};
use crate::{error::Error, network::NetworkEventData};
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{task, task::JoinHandle};
use tracing::info;

/// Populate the syscall allowlist with security-relevant syscalls
/// This dramatically reduces overhead by filtering out noisy syscalls
fn populate_syscall_allowlist(syscall_map: &libbpf_rs::Map) -> Result<()> {
    // Security-relevant syscalls to monitor
    let security_syscalls: Vec<u32> = vec![
        // Process execution
        59,  // execve
        322, // execveat
        57,  // fork
        58,  // vfork
        56,  // clone
        231, // exit_group
        // Network operations
        41,  // socket
        42,  // connect
        43,  // accept
        288, // accept4
        49,  // bind
        50,  // listen
        46,  // sendmsg
        47,  // recvmsg
        44,  // sendto
        45,  // recvfrom
        // File operations
        2,   // open
        257, // openat
        318, // openat2
        85,  // creat
        87,  // unlink
        263, // unlinkat
        82,  // rename
        264, // renameat
        316, // renameat2
        83,  // mkdir
        84,  // rmdir
        88,  // symlink
        266, // symlinkat
        // Privilege operations
        105, // setuid
        106, // setgid
        117, // setresuid
        119, // setresgid
        114, // setregid
        113, // setreuid
        157, // prctl
        101, // ptrace
        155, // pivot_root
        165, // mount
        166, // umount2
        167, // swapon
        168, // swapoff
        // Module loading
        175, // init_module
        313, // finit_module
        176, // delete_module
        // Capabilities
        126, // capset
        // BPF operations (for security monitoring)
        321, // bpf
        // Namespace operations
        308, // setns
        272, // unshare
        // Time manipulation
        227, // clock_settime
        228, // clock_adjtime
        // Keyring operations
        248, // keyctl
        // Security-sensitive I/O
        78,  // getdents
        217, // getdents64
        0,   // read (for /proc, /sys reads)
        1,   // write (for sensitive writes)
    ];

    info!(
        "Populating syscall allowlist with {} security-relevant syscalls",
        security_syscalls.len()
    );

    for &syscall_nr in &security_syscalls {
        syscall_map.update(
            &syscall_nr.to_ne_bytes(),
            &1u32.to_ne_bytes(),
            MapFlags::ANY,
        )?;
    }

    info!("Syscall allowlist populated successfully");
    Ok(())
}

pub fn ebpf_handle(
    network_event_sender: Sender<NetworkEventData>,
    syscall_event_sender: Sender<SyscallEventData>,
    netpolicy_drop_sender: Sender<PolicyDropEvent>,
    mut rx: Receiver<u64>,
    mut ignore_ips: Receiver<String>,
    ignore_daemonset_traffic: bool,
) -> JoinHandle<Result<(), Error>> {
    task::spawn_blocking(move || {
        // Load and attach network probe
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = NetworkProbeSkelBuilder::default();
        let network_probe_skel = skel_builder
            .open(&mut open_object)
            .map_err(|e| Error::Custom(format!("Failed to open network probe eBPF: {}", e)))?;
        let mut network_sk = network_probe_skel
            .load()
            .map_err(|e| Error::Custom(format!("Failed to load network probe eBPF: {}", e)))?;
        network_sk
            .attach()
            .map_err(|e| Error::Custom(format!("Failed to attach network probe eBPF: {}", e)))?;
        info!("Network probe eBPF program loaded and attached");

        // Load and attach netpolicy drop probe
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = NetpolicyDropSkelBuilder::default();
        let netpolicy_drop_skel = skel_builder
            .open(&mut open_object)
            .map_err(|e| Error::Custom(format!("Failed to open netpolicy drop eBPF: {}", e)))?;
        let mut netpolicy_sk = netpolicy_drop_skel
            .load()
            .map_err(|e| Error::Custom(format!("Failed to load netpolicy drop eBPF: {}", e)))?;
        netpolicy_sk
            .attach()
            .map_err(|e| Error::Custom(format!("Failed to attach netpolicy drop eBPF: {}", e)))?;
        info!("Network policy drop eBPF program loaded and attached");

        // Load and attach syscall probe
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = SyscallSkelBuilder::default();
        let syscall_probe_skel = skel_builder
            .open(&mut open_object)
            .map_err(|e| Error::Custom(format!("Failed to open syscall eBPF: {}", e)))?;
        let mut syscall_sk = syscall_probe_skel
            .load()
            .map_err(|e| Error::Custom(format!("Failed to load syscall eBPF: {}", e)))?;

        // Populate syscall allowlist BEFORE attaching to reduce overhead immediately
        if let Err(e) = populate_syscall_allowlist(&syscall_sk.maps.allowed_syscalls) {
            eprintln!("Warning: Failed to populate syscall allowlist: {}", e);
            eprintln!("Continuing without allowlist (will trace all syscalls)");
        }

        syscall_sk
            .attach()
            .map_err(|e| Error::Custom(format!("Failed to attach syscall eBPF: {}", e)))?;
        info!("Syscall probe eBPF program loaded and attached");

        // Build a unified ring buffer that polls all three maps efficiently
        let mut ring_buffer_builder = RingBufferBuilder::new();

        // Add network events ring buffer
        ring_buffer_builder
            .add(&network_sk.maps.network_events, move |data: &[u8]| {
                let network_event_data: NetworkEventData =
                    unsafe { *(data.as_ptr() as *const NetworkEventData) };

                if let Err(e) = network_event_sender.blocking_send(network_event_data) {
                    eprintln!("Failed to send network event (receiver closed): {:?}", e);
                }
                0 // Return 0 for success
            })
            .map_err(|e| {
                Error::Custom(format!("Failed to add network events ring buffer: {}", e))
            })?;

        // Add syscall events ring buffer
        ring_buffer_builder
            .add(&syscall_sk.maps.syscall_events, move |data: &[u8]| {
                let syscall_event_data: SyscallEventData =
                    unsafe { *(data.as_ptr() as *const SyscallEventData) };
                if let Err(e) = syscall_event_sender.blocking_send(syscall_event_data) {
                    eprintln!("Failed to send syscall event (receiver closed): {:?}", e);
                }
                0 // Return 0 for success
            })
            .map_err(|e| {
                Error::Custom(format!("Failed to add syscall events ring buffer: {}", e))
            })?;

        // Add network policy drop events ring buffer
        ring_buffer_builder
            .add(
                &netpolicy_sk.maps.policy_drop_events,
                move |data: &[u8]| {
                    let policy_drop_event: PolicyDropEvent =
                        unsafe { *(data.as_ptr() as *const PolicyDropEvent) };
                    if let Err(e) = netpolicy_drop_sender.blocking_send(policy_drop_event) {
                        eprintln!(
                            "Failed to send network policy drop event (receiver closed): {:?}",
                            e
                        );
                    }
                    0 // Return 0 for success
                },
            )
            .map_err(|e| {
                Error::Custom(format!(
                    "Failed to add policy drop events ring buffer: {}",
                    e
                ))
            })?;

        let ring_buffer = ring_buffer_builder
            .build()
            .map_err(|e| Error::Custom(format!("Failed to build ring buffer: {}", e)))?;
        info!("Network policy drop ring buffer initialized");

        loop {
            // Poll all ring buffers with a single call (much more efficient!)
            if let Err(e) = ring_buffer.poll(std::time::Duration::from_millis(100)) {
                eprintln!("Error polling ring buffer: {}", e);
                continue;
            }

            // Process any incoming messages from the pod watcher
            if let Ok(inum) = rx.try_recv() {
                let _ = network_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .map_err(|e| eprintln!("Failed to update network inode map: {}", e));
                let _ = syscall_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .map_err(|e| eprintln!("Failed to update syscall inode map: {}", e));
                let _ = netpolicy_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .map_err(|e| eprintln!("Failed to update netpolicy inode map: {}", e));
            }
            if ignore_daemonset_traffic {
                if let Ok(ip) = ignore_ips.try_recv() {
                    if let Ok(parsed_ip) = ip.parse::<Ipv4Addr>() {
                        let ip_u32 = u32::from(parsed_ip).to_be(); // Ensure the IP is in network byte order
                        let _ = network_sk
                            .maps
                            .ignore_ips
                            .update(&ip_u32.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                            .map_err(|e| eprintln!("Failed to update ignore_ips map: {}", e));
                    } else {
                        eprintln!("Failed to parse IP address: {}", ip);
                    }
                }
            }
        }
    })
}
