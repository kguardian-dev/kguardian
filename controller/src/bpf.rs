use crate::capture_tiers::{CaptureLevel, ResolvedTiers};
use crate::models::PodRegistration;
use crate::network::netpolicy_drop::NetpolicyDropSkelBuilder;
use crate::network::network_probe::NetworkProbeSkelBuilder;
use crate::network::{ip_to_wire_addr, PolicyDropEvent};
use crate::syscall::{sycallprobe::SyscallSkelBuilder, SyscallEventData};
use crate::{error::Error, network::NetworkEventData};
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{task, task::JoinHandle};
use tracing::{info, warn};

// Each ring-buffer callback runs on the libbpf-rs poll thread, which is
// inside a `task::spawn_blocking` and therefore not cancelable by Tokio.
// If the corresponding mpsc receiver is dropped (e.g. its task in
// `try_join!` got cancelled because a sister task errored), every
// subsequent eBPF event would log a "(receiver closed)" line, flooding
// stderr at syscall frequency. Latch the first failure per channel,
// log it loudly via the structured logger, then drop subsequent events
// silently — the operator still sees the signal once and the logs stay
// readable.
static NETWORK_SEND_FAILED: AtomicBool = AtomicBool::new(false);
static SYSCALL_SEND_FAILED: AtomicBool = AtomicBool::new(false);
static POLICY_DROP_SEND_FAILED: AtomicBool = AtomicBool::new(false);

// Set when ANY receiver closes — signals the spawn_blocking poll loop
// to exit on its next iteration. Without this, the poll loop would keep
// running indefinitely after try_join! cancels its sibling tasks (the
// underlying root cause of the spam #880 patched). Exiting forces the
// JoinHandle to resolve, which in turn surfaces an error to main's
// try_join! and the kubelet restarts the pod cleanly. Self-heal
// pattern, mirrored from broker /health (#876).
static EBPF_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Trip the eBPF shutdown flag from a receiver-closed callback. Idempotent.
#[inline]
fn signal_ebpf_shutdown() {
    EBPF_SHUTDOWN.store(true, Ordering::Relaxed);
}

/// True once any send-failure handler has tripped the flag.
#[inline]
fn ebpf_shutdown_requested() -> bool {
    EBPF_SHUTDOWN.load(Ordering::Relaxed)
}

/// A persistently-failing poll (e.g. the eBPF map fds being torn down as a
/// node drains) returns immediately, so the loop backs off per error and
/// gives up after this many consecutive failures — ~5s at the 100ms
/// backoff — exiting for a clean kubelet restart rather than hot-spinning a
/// CPU (the "cactus" full-CPU syscall-log spam reported when a node went
/// down).
const MAX_CONSECUTIVE_POLL_ERRORS: u32 = 50;

/// What the poll loop should do after a ring-buffer poll error, given how
/// many have occurred back-to-back. Extracted as a pure function so the
/// warn-once + backoff + bail thresholds are unit-testable and can't
/// silently regress back into a hot spin.
#[derive(Debug, PartialEq, Eq)]
enum PollErrorAction {
    /// First failure in a streak: warn loudly (once), then back off.
    WarnAndBackoff,
    /// Subsequent failure: back off silently (warn already emitted).
    BackoffSilently,
    /// Sustained failure: stop the loop so the pod restarts cleanly.
    Bail,
}

/// Decide the action after the Nth consecutive poll error. `consecutive`
/// is the running count INCLUDING the current error (i.e. first error == 1).
fn classify_poll_error(consecutive: u32, max: u32) -> PollErrorAction {
    if consecutive >= max {
        PollErrorAction::Bail
    } else if consecutive == 1 {
        PollErrorAction::WarnAndBackoff
    } else {
        PollErrorAction::BackoffSilently
    }
}

/// Fill one tier's allowlist map with already-resolved syscall numbers.
/// Value type is `u8` to match `KG_ALLOWLIST` in syscall.bpf.c.
fn populate_allowlist(map: &libbpf_rs::Map, level: CaptureLevel, nrs: &[u32]) -> Result<()> {
    for nr in nrs {
        map.update(&nr.to_ne_bytes(), &1u8.to_ne_bytes(), MapFlags::ANY)?;
    }
    info!(
        tier = %level,
        entries = nrs.len(),
        "syscall allowlist map populated"
    );
    Ok(())
}

/// Populate every non-full tier map from the names resolved at startup
/// (see `capture_tiers`). Numbers were resolved for THIS architecture by
/// libseccomp — the previous hard-coded list was x86_64-only and selected
/// unrelated syscalls on arm64.
///
/// Failure is per map and non-fatal: the other tiers still load, and the
/// `full` tier needs no map at all. A tier whose map failed to populate
/// captures nothing, so it is logged at error rather than silently
/// falling back to unfiltered capture (which would undo the operator's
/// choice of tier).
fn populate_tier_maps(maps: &crate::syscall::sycallprobe::SyscallMaps<'_>, tiers: &ResolvedTiers) {
    let plan: [(
        &libbpf_rs::Map,
        CaptureLevel,
        &std::collections::BTreeSet<u32>,
    ); 4] = [
        (&*maps.allowlist_high, CaptureLevel::High, &tiers.high),
        (&*maps.allowlist_medium, CaptureLevel::Medium, &tiers.medium),
        (&*maps.allowlist_low, CaptureLevel::Low, &tiers.low),
        (&*maps.allowlist_custom, CaptureLevel::Custom, &tiers.custom),
    ];
    for (map, level, nrs) in plan {
        let nrs: Vec<u32> = nrs.iter().copied().collect();
        if let Err(e) = populate_allowlist(map, level, &nrs) {
            tracing::error!(
                tier = %level,
                "failed to populate syscall allowlist map: {e}; workloads at this tier will \
                 capture NO syscalls until the controller restarts"
            );
        }
    }
}

/// Where `sym` lives according to a `/proc/kallsyms` dump: `None` if
/// absent, `Some(None)` if built in, `Some(Some(module))` if exported
/// by a module (kallsyms appends the module as a bracketed 4th field).
/// `/proc/kallsyms` lists symbol names even when addresses are hidden,
/// so reading it needs no capability beyond what the controller
/// already runs with.
fn symbol_location(kallsyms: &str, sym: &str) -> Option<Option<String>> {
    kallsyms.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.nth(2)?;
        if name != sym {
            return None;
        }
        Some(
            fields
                .next()
                .map(|module| module.trim_matches(['[', ']']).to_string()),
        )
    })
}

/// True when an fentry program targeting `sym` can actually LOAD.
///
/// Used to decide whether the `fentry/udpv6_sendmsg` twins stay
/// autoloaded: an fentry program whose target cannot be resolved fails
/// the whole skeleton load, which would kill the controller on exactly
/// the nodes read_sock_addrs works to keep it alive on.
///
/// Presence in kallsyms is necessary but NOT sufficient. fentry
/// resolves its target through BTF; a built-in symbol is covered by
/// vmlinux BTF (whose absence would already fail every other fentry
/// program here), but a MODULE symbol needs that module's split BTF,
/// which kernels older than 5.11 or built with
/// CONFIG_DEBUG_INFO_BTF_MODULES=n do not ship — Debian 11's 5.10 with
/// its CONFIG_IPV6=m is the canonical case. There the symbol IS in
/// kallsyms, the load still fails, and trusting kallsyms alone would
/// crash-loop the controller. So a module symbol is only trusted when
/// /sys/kernel/btf/<module> exists.
fn kernel_can_fentry(sym: &str) -> bool {
    let kallsyms = match std::fs::read_to_string("/proc/kallsyms") {
        Ok(contents) => contents,
        Err(e) => {
            // Failing open would abort the load on kernels without the
            // symbol; failing closed only costs IPv6 UDP visibility.
            warn!("could not read /proc/kallsyms ({e}); assuming {sym} is absent");
            return false;
        }
    };
    match symbol_location(&kallsyms, sym) {
        None => false,
        Some(None) => true,
        Some(Some(module)) => {
            let btf = format!("/sys/kernel/btf/{module}");
            let present = std::path::Path::new(&btf).exists();
            if !present {
                warn!(
                    "{sym} lives in module {module} but {btf} is missing \
                     (kernel without module BTF); skipping its probes"
                );
            }
            present
        }
    }
}

pub fn ebpf_handle(
    network_event_sender: Sender<NetworkEventData>,
    syscall_event_sender: Sender<SyscallEventData>,
    netpolicy_drop_sender: Sender<PolicyDropEvent>,
    mut rx: Receiver<PodRegistration>,
    mut ignore_ips: Receiver<String>,
    ignore_daemonset_traffic: bool,
    tiers: ResolvedTiers,
) -> JoinHandle<Result<(), Error>> {
    task::spawn_blocking(move || {
        // The IPv6 UDP twins target udpv6_sendmsg; on a kernel where
        // that target cannot be fentry-attached they must be dropped
        // BEFORE load or the skeleton load fails and the controller
        // dies. See kernel_can_fentry.
        let kernel_has_udpv6 = kernel_can_fentry("udpv6_sendmsg");
        if !kernel_has_udpv6 {
            warn!(
                "no loadable udpv6_sendmsg (IPv6 disabled, module not loaded, or \
                 module BTF missing); native IPv6 UDP traffic will not be captured"
            );
        }

        // Load and attach network probe
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = NetworkProbeSkelBuilder::default();
        let mut network_probe_skel = skel_builder
            .open(&mut open_object)
            .map_err(|e| Error::Custom(format!("Failed to open network probe eBPF: {}", e)))?;
        if !kernel_has_udpv6 {
            network_probe_skel
                .progs
                .trace_udpv6_send
                .set_autoload(false);
        }
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
        let mut netpolicy_drop_skel = skel_builder
            .open(&mut open_object)
            .map_err(|e| Error::Custom(format!("Failed to open netpolicy drop eBPF: {}", e)))?;
        if !kernel_has_udpv6 {
            netpolicy_drop_skel
                .progs
                .trace_udpv6_send
                .set_autoload(false);
        }
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

        // Populate the tier allowlists BEFORE attaching so the very first
        // events are already filtered by tier.
        populate_tier_maps(&syscall_sk.maps, &tiers);

        syscall_sk
            .attach()
            .map_err(|e| Error::Custom(format!("Failed to attach syscall eBPF: {}", e)))?;
        info!("Syscall probe eBPF program loaded and attached");

        // Build a unified ring buffer that polls all three maps efficiently
        let mut ring_buffer_builder = RingBufferBuilder::new();

        // Add network events ring buffer
        ring_buffer_builder
            .add(&network_sk.maps.network_events, move |data: &[u8]| {
                if data.len() < std::mem::size_of::<NetworkEventData>() {
                    eprintln!(
                        "Network event data too small: {} < {}",
                        data.len(),
                        std::mem::size_of::<NetworkEventData>()
                    );
                    return 0;
                }
                let network_event_data: NetworkEventData =
                    unsafe { *(data.as_ptr() as *const NetworkEventData) };

                if let Err(e) = network_event_sender.blocking_send(network_event_data) {
                    if !NETWORK_SEND_FAILED.swap(true, Ordering::Relaxed) {
                        warn!(error = ?e, "network event channel closed; signalling eBPF poll loop to exit");
                    }
                    signal_ebpf_shutdown();
                }
                0 // Return 0 for success
            })
            .map_err(|e| {
                Error::Custom(format!("Failed to add network events ring buffer: {}", e))
            })?;

        // Add syscall events ring buffer
        ring_buffer_builder
            .add(&syscall_sk.maps.syscall_events, move |data: &[u8]| {
                if data.len() < std::mem::size_of::<SyscallEventData>() {
                    eprintln!(
                        "Syscall event data too small: {} < {}",
                        data.len(),
                        std::mem::size_of::<SyscallEventData>()
                    );
                    return 0;
                }
                let syscall_event_data: SyscallEventData =
                    unsafe { *(data.as_ptr() as *const SyscallEventData) };
                if let Err(e) = syscall_event_sender.blocking_send(syscall_event_data) {
                    if !SYSCALL_SEND_FAILED.swap(true, Ordering::Relaxed) {
                        warn!(error = ?e, "syscall event channel closed; signalling eBPF poll loop to exit");
                    }
                    signal_ebpf_shutdown();
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
                    if data.len() < std::mem::size_of::<PolicyDropEvent>() {
                        eprintln!(
                            "Policy drop event data too small: {} < {}",
                            data.len(),
                            std::mem::size_of::<PolicyDropEvent>()
                        );
                        return 0;
                    }
                    let policy_drop_event: PolicyDropEvent =
                        unsafe { *(data.as_ptr() as *const PolicyDropEvent) };
                    if let Err(e) = netpolicy_drop_sender.blocking_send(policy_drop_event) {
                        if !POLICY_DROP_SEND_FAILED.swap(true, Ordering::Relaxed) {
                            warn!(error = ?e, "network policy drop event channel closed; signalling eBPF poll loop to exit");
                        }
                        signal_ebpf_shutdown();
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

        let mut consecutive_poll_errors: u32 = 0;

        loop {
            // Honour the shutdown flag before polling so we exit promptly
            // (within ~100ms) when a receiver-closed handler flips it.
            // Returning Err propagates up through the JoinHandle into
            // main's try_join!, which fails the controller and prompts
            // the kubelet to restart the pod — clean recovery instead
            // of a stuck process.
            if ebpf_shutdown_requested() {
                return Err(Error::Custom(
                    "eBPF poll loop exiting: an event-channel receiver was closed (likely a sister task in try_join! errored). Pod will restart.".into(),
                ));
            }
            // Poll all ring buffers with a single call (much more efficient!)
            //
            // The 100ms timeout only throttles the SUCCESS path — libbpf's
            // poll returns *immediately* on error (e.g. epoll on a
            // torn-down map fd while a node is draining), so an
            // unbacked-off `continue` here pegs a CPU at 100% and floods
            // stderr (the old eprintln also bypassed RUST_LOG, so it could
            // not be silenced). Back off per error, warn once via tracing,
            // and bail after sustained failure so the kubelet restarts us
            // cleanly instead of leaving a hot-spinning pod.
            if let Err(e) = ring_buffer.poll(std::time::Duration::from_millis(100)) {
                consecutive_poll_errors += 1;
                match classify_poll_error(consecutive_poll_errors, MAX_CONSECUTIVE_POLL_ERRORS) {
                    PollErrorAction::Bail => {
                        return Err(Error::Custom(format!(
                            "ring buffer poll failed {} times consecutively (last: {}); exiting for restart",
                            consecutive_poll_errors, e
                        )));
                    }
                    PollErrorAction::WarnAndBackoff => {
                        warn!(error = %e, "ring buffer poll failed; backing off (repeats suppressed until it recovers)");
                    }
                    PollErrorAction::BackoffSilently => {}
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            consecutive_poll_errors = 0;

            // Drain the pod watcher's queues, don't sip from them.
            //
            // These were `if let`, taking ONE item per loop iteration. The
            // iteration rate is tied to ring_buffer.poll() returning, and poll
            // only returns once its callbacks have pushed every pending record
            // through blocking_send into bounded(1000) channels. Under event
            // load the poll thread spends most of its time parked in those
            // sends, so iterations become rare and the intake rate collapses
            // toward zero.
            //
            // Meanwhile resync_pods re-sends an inode for EVERY on-node pod
            // every 60s unconditionally, so a 234-pod node offers ~234/min
            // forever. Once intake falls below that, the bounded(1000) channel
            // fills and the pod watcher parks on `send().await`. Nothing then
            // registers a new pod again, and because the eBPF programs gate on
            // the inode_num map (syscall.bpf.c: unknown netns returns early),
            // unregistered pods emit nothing at all. On a node dominated by
            // short-lived Jobs the registered set is soon entirely dead pods
            // and telemetry decays to zero. The process stays healthy-looking
            // throughout: Running, no restarts, flat memory.
            //
            // Bounded rather than a bare `while let` on purpose: an unbounded
            // drain against a producer that can outrun us would keep us out of
            // poll() and starve the ring buffers instead, trading one
            // starvation for its mirror image. The cap is far above the real
            // arrival rate (~234/min) yet still returns us to poll() promptly.
            const MAX_DRAIN_PER_ITERATION: usize = 128;

            let mut drained = 0;
            while drained < MAX_DRAIN_PER_ITERATION {
                let Ok(reg) = rx.try_recv() else { break };
                drained += 1;
                // The same flags value goes into all three maps. The
                // network and netpolicy probes only test the key for
                // presence and POD_TRACKED is always set, so the tier
                // and generation bits are inert for them; the syscall
                // probe reads both out of its instance.
                let key = reg.netns_inode.to_ne_bytes();
                let val = reg.flags.to_ne_bytes();
                let _ = network_sk
                    .maps
                    .inode_num
                    .update(&key, &val, MapFlags::ANY)
                    .map_err(|e| eprintln!("Failed to update network inode map: {}", e));
                let _ = syscall_sk
                    .maps
                    .inode_num
                    .update(&key, &val, MapFlags::ANY)
                    .map_err(|e| eprintln!("Failed to update syscall inode map: {}", e));
                let _ = netpolicy_sk
                    .maps
                    .inode_num
                    .update(&key, &val, MapFlags::ANY)
                    .map_err(|e| eprintln!("Failed to update netpolicy inode map: {}", e));
            }
            if ignore_daemonset_traffic {
                // Same starvation, same bound: one IP per iteration meant the
                // daemonset ignore-list lagged behind the pods it describes,
                // so their traffic was recorded until the backlog caught up.
                let mut ips_drained = 0;
                while ips_drained < MAX_DRAIN_PER_ITERATION {
                    let Ok(ip) = ignore_ips.try_recv() else { break };
                    ips_drained += 1;
                    // Parsed as IpAddr, not Ipv4Addr: a dual-stack
                    // daemonset pod reports IPv6 addresses too, and the
                    // v4-only parse silently dropped them — the ignore
                    // list then only half-worked on such nodes.
                    //
                    // The key is the same 16-byte v4-mapped form the
                    // eBPF probes compare against (see read_sock_addrs
                    // in src/bpf/helper.h); ip_to_wire_addr is the one
                    // place that spelling is produced.
                    match ip.parse::<IpAddr>() {
                        Ok(parsed_ip) => {
                            let key = ip_to_wire_addr(parsed_ip);
                            let _ = network_sk
                                .maps
                                .ignore_ips
                                .update(&key, &1_u32.to_ne_bytes(), MapFlags::ANY)
                                .map_err(|e| eprintln!("Failed to update ignore_ips map: {}", e));
                        }
                        Err(_) => eprintln!("Failed to parse IP address: {}", ip),
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests mutate process-wide AtomicBool statics, so they must
    // not run concurrently. `cargo test` parallelises by default and CI
    // does NOT pass --test-threads=1 for the controller, so we serialise
    // each test body with a test-local mutex instead of relying on run
    // order. unwrap_or_else(into_inner) keeps one failing test from
    // poisoning the lock and cascading into the others.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    // ---- symbol_location: the kallsyms parse behind the udpv6 gate ----
    //
    // The distinction between "built in" and "in a module" is
    // load-bearing: a module symbol without its module BTF fails the
    // fentry load even though kallsyms lists it (Debian 11's 5.10 with
    // CONFIG_IPV6=m), so misparsing the module tag either crash-loops
    // the controller or silently disables IPv6 UDP capture.

    #[test]
    fn symbol_location_builtin() {
        let dump = "ffffffff81000000 T udp_sendmsg\n\
                    0000000000000000 T udpv6_sendmsg\n";
        assert_eq!(symbol_location(dump, "udpv6_sendmsg"), Some(None));
    }

    #[test]
    fn symbol_location_module_tag_is_extracted() {
        let dump = "ffffffff81000000 T udp_sendmsg\n\
                    ffffffffc0aa0000 t udpv6_sendmsg\t[ipv6]\n";
        assert_eq!(
            symbol_location(dump, "udpv6_sendmsg"),
            Some(Some("ipv6".to_string()))
        );
    }

    #[test]
    fn symbol_location_absent_and_no_prefix_confusion() {
        // __pfx_/prefixed neighbours must not satisfy an exact lookup.
        let dump = "ffffffff81000000 T __pfx_udpv6_sendmsg\n\
                    ffffffff81000010 T udpv6_sendmsg_prelude\n";
        assert_eq!(symbol_location(dump, "udpv6_sendmsg"), None);
    }

    fn reset_state() {
        EBPF_SHUTDOWN.store(false, Ordering::Relaxed);
        NETWORK_SEND_FAILED.store(false, Ordering::Relaxed);
        SYSCALL_SEND_FAILED.store(false, Ordering::Relaxed);
        POLICY_DROP_SEND_FAILED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn shutdown_flag_starts_clear() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_state();
        assert!(!ebpf_shutdown_requested());
    }

    #[test]
    fn signal_then_observe() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_state();
        signal_ebpf_shutdown();
        assert!(ebpf_shutdown_requested());
    }

    #[test]
    fn signal_is_idempotent() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_state();
        signal_ebpf_shutdown();
        signal_ebpf_shutdown();
        signal_ebpf_shutdown();
        assert!(ebpf_shutdown_requested());
    }

    #[test]
    fn send_failed_latches_and_warn_fires_once() {
        // The warn-once-then-suppress contract from #880 must continue
        // to hold even with the shutdown flag added — a regression that
        // dropped the latch would re-introduce the spam.
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_state();
        // Simulate the "first failure" path: swap returns the OLD value.
        // false → true ⇒ first call returns false; subsequent return true.
        assert!(!NETWORK_SEND_FAILED.swap(true, Ordering::Relaxed));
        assert!(NETWORK_SEND_FAILED.swap(true, Ordering::Relaxed));
        assert!(NETWORK_SEND_FAILED.swap(true, Ordering::Relaxed));
    }

    #[test]
    fn poll_error_warns_once_backs_off_then_bails() {
        // The "cactus" guard: a torn-down map fd makes poll() return an
        // error immediately, so the loop must (1) warn exactly once on the
        // first error, (2) back off silently while it persists, and (3)
        // bail at the threshold so the kubelet restarts the pod instead of
        // a CPU hot-spinning + flooding the syscall log. No statics here,
        // so no TEST_GUARD needed — the helper is pure.
        const MAX: u32 = 50;
        // First error → warn (and back off).
        assert_eq!(classify_poll_error(1, MAX), PollErrorAction::WarnAndBackoff);
        // Mid-streak errors → silent backoff, no repeated warns.
        assert_eq!(
            classify_poll_error(2, MAX),
            PollErrorAction::BackoffSilently
        );
        assert_eq!(
            classify_poll_error(MAX - 1, MAX),
            PollErrorAction::BackoffSilently
        );
        // At and beyond the threshold → bail for a clean restart.
        assert_eq!(classify_poll_error(MAX, MAX), PollErrorAction::Bail);
        assert_eq!(classify_poll_error(MAX + 1, MAX), PollErrorAction::Bail);
    }

    #[test]
    fn poll_error_never_silently_hot_spins() {
        // Defensive: there is no consecutive-error count below the cap that
        // resolves to "do nothing" — every error either warns, backs off,
        // or bails. (A regression making the bail branch unreachable would
        // re-create the original hang.)
        for n in 1..=MAX_CONSECUTIVE_POLL_ERRORS {
            let action = classify_poll_error(n, MAX_CONSECUTIVE_POLL_ERRORS);
            if n >= MAX_CONSECUTIVE_POLL_ERRORS {
                assert_eq!(action, PollErrorAction::Bail);
            } else {
                assert_ne!(action, PollErrorAction::Bail);
            }
        }
    }
}
