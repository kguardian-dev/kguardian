use crate::capture_tiers::{CaptureLevel, ResolvedTiers};
use crate::early_capture::CgroupEventData;
use crate::models::PodRegistration;
use crate::network::netpolicy_drop::NetpolicyDropSkelBuilder;
use crate::network::network_probe::NetworkProbeSkelBuilder;
use crate::network::{ip_to_wire_addr, PolicyDropEvent};
use crate::seccomp_denial::seccomp_denial_skel::{SeccompDenialSkel, SeccompDenialSkelBuilder};
use crate::seccomp_denial::{DenialMaps, AUDIT_SECCOMP_SYMBOL};
use crate::syscall::{sycallprobe::SyscallSkelBuilder, SyscallEventData};
use crate::{error::Error, network::NetworkEventData};
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject, RingBufferBuilder};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio::{task, task::JoinHandle};
use tracing::{info, warn};

// Each ring-buffer callback runs on the libbpf-rs poll thread, which is
// inside a `task::spawn_blocking` and therefore not cancelable by Tokio.
// If the corresponding mpsc receiver is dropped (e.g. its consumer
// task stopped, or the supervisor cancelled it on shutdown), every
// subsequent eBPF event would log a "(receiver closed)" line, flooding
// stderr at syscall frequency. Latch the first failure per channel,
// log it loudly via the structured logger, then drop subsequent events
// silently — the operator still sees the signal once and the logs stay
// readable.
static NETWORK_SEND_FAILED: AtomicBool = AtomicBool::new(false);
static SYSCALL_SEND_FAILED: AtomicBool = AtomicBool::new(false);
static POLICY_DROP_SEND_FAILED: AtomicBool = AtomicBool::new(false);
static CGROUP_SEND_FAILED: AtomicBool = AtomicBool::new(false);

// Set when ANY receiver closes, and by main on its way out — signals
// the spawn_blocking poll loop to exit on its next iteration. Without
// this, the poll loop would keep running indefinitely after the
// consumers are gone (the underlying root cause of the spam #880
// patched). Exiting forces the JoinHandle to resolve, which surfaces a
// fault to the supervisor and the kubelet restarts the pod cleanly.
// Self-heal pattern, mirrored from broker /health (#876).
static EBPF_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Trip the eBPF shutdown flag. Idempotent.
///
/// Called from the receiver-closed callbacks below, and by `main` on
/// its way out. The second caller is not optional: the poll loop runs
/// inside `spawn_blocking`, and dropping the runtime waits — with no
/// timeout — for every blocking task that has already started
/// (`BlockingPool::drop` → `shutdown(None)`). So on SIGTERM the
/// process cannot exit until this loop notices and returns. It used to
/// notice only when a `blocking_send` failed against a dropped
/// receiver, which requires an eBPF event to arrive: on an idle node
/// there might not be one for minutes, and SIGTERM turned into "wait
/// for the kubelet's SIGKILL". Telling it directly makes shutdown
/// deterministic at one poll interval (~100ms).
#[inline]
pub fn signal_ebpf_shutdown() {
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

/// Whether the syscall probe's cgroup ownership gate loaded (see
/// `credit_generation` in syscall.bpf.c). Reported in the startup-capture
/// summary log.
static OWNERSHIP_GATE: AtomicBool = AtomicBool::new(false);

pub fn ownership_gate_active() -> bool {
    OWNERSHIP_GATE.load(Ordering::Relaxed)
}

/// One way of loading the syscall object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallLoadVariant {
    /// `kg_ownership_gate` in the object's rodata.
    pub ownership_gate: bool,
    /// Load `trace_cgroup_mkdir` (startup capture).
    pub startup_capture: bool,
    /// Fail this attempt on purpose (`KGUARDIAN_INJECT_LOAD_FAILURE`),
    /// to exercise the fallback on a real node.
    pub inject_failure: bool,
}

/// The configurations to try, most capable first. The last one is the
/// behaviour before either optional feature existed.
///
/// `SYSCALL_OWNERSHIP_GATE=off` starts without the gate.
/// `KGUARDIAN_INJECT_LOAD_FAILURE=ownership` fails every gated attempt,
/// `=all` every attempt (so the controller exits, as a real total failure
/// would).
pub fn syscall_load_variants(
    ownership_env: Option<&str>,
    inject: Option<&str>,
) -> Vec<SyscallLoadVariant> {
    let gate_allowed = !ownership_env.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "false" | "0" | "no" | "disabled"
        )
    });
    let inject = inject.map(|v| v.trim().to_ascii_lowercase());
    [(true, true), (false, true), (false, false)]
        .into_iter()
        .filter(|(gate, _)| gate_allowed || !gate)
        .map(|(ownership_gate, startup_capture)| SyscallLoadVariant {
            ownership_gate,
            startup_capture,
            inject_failure: match inject.as_deref() {
                Some("ownership") => ownership_gate,
                Some("all") => true,
                _ => false,
            },
        })
        .collect()
}

/// Open and load the syscall object in `variant`'s configuration.
fn open_and_load_syscall(
    storage: &mut MaybeUninit<OpenObject>,
    variant: SyscallLoadVariant,
) -> std::result::Result<crate::syscall::sycallprobe::SyscallSkel<'_>, String> {
    let mut open = SyscallSkelBuilder::default()
        .open(storage)
        .map_err(|e| format!("open: {e}"))?;
    match open.maps.rodata_data.as_deref_mut() {
        Some(rodata) => rodata.kg_ownership_gate = variant.ownership_gate,
        // No rodata means the flag is gone from the object: only the
        // gate-less configuration is honest then.
        None if variant.ownership_gate => return Err("object has no kg_ownership_gate".into()),
        None => {}
    }
    if !variant.startup_capture {
        open.progs.trace_cgroup_mkdir.set_autoload(false);
    }
    if variant.inject_failure {
        return Err("load failure injected by KGUARDIAN_INJECT_LOAD_FAILURE".into());
    }
    open.load().map_err(|e| format!("load: {e}"))
}

/// Delete `key` from `map` only while its value is still `expected`.
/// True when something was deleted.
fn compare_and_delete(map: &libbpf_rs::Map, key: &[u8], expected: &[u8]) -> bool {
    match map.lookup(key, MapFlags::ANY) {
        Ok(Some(current)) if current.as_slice() == expected => map.delete(key).is_ok(),
        _ => false,
    }
}

/// Index of userspace's retired-marks counter in the `pending_gate` map.
/// Keep in sync with `KG_GATE_RETIRED` in syscall.bpf.c.
const PENDING_GATE_RETIRED: u32 = 1;

/// Fill `runtime_prefilter` (indexed by syscall number) with the
/// syscalls runc only makes before the container's seccomp filter exists
/// (`early_capture::RUNTIME_PREFILTER_SYSCALLS`), resolved for this arch.
/// A failure leaves the map empty, which records those syscalls as
/// before: a slightly wider profile, never a narrower one.
fn populate_runtime_prefilter(map: &libbpf_rs::Map) {
    let Some(arch) = crate::capture_tiers::native_scmp_arch() else {
        return;
    };
    let (nrs, _unknown) = crate::capture_tiers::resolve_names(
        crate::early_capture::RUNTIME_PREFILTER_SYSCALLS
            .iter()
            .copied(),
        arch,
    );
    let mut written = 0;
    for nr in nrs {
        // The map holds 1024 slots; syscall numbers on every supported
        // arch are well below that.
        if nr < 1024
            && map
                .update(&nr.to_ne_bytes(), &1u8.to_ne_bytes(), MapFlags::ANY)
                .is_ok()
        {
            written += 1;
        }
    }
    info!(
        entries = written,
        "runtime pre-filter syscall map populated (runc setup syscalls skipped)"
    );
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

/// [`symbol_location`] against the RUNNING kernel's `/proc/kallsyms`.
///
/// A file we cannot read is reported as "symbol absent", deliberately
/// indistinguishable from the real thing: every caller has a
/// skip-this-probe fallback, and skipping costs one signal whereas
/// trusting a dump we never read costs a failed load — which, for the
/// probes this gates, means a Controller that will not start.
fn kernel_symbol(sym: &str) -> Option<Option<String>> {
    let kallsyms = match std::fs::read_to_string("/proc/kallsyms") {
        Ok(contents) => contents,
        Err(e) => {
            warn!("could not read /proc/kallsyms ({e}); assuming {sym} is absent");
            return None;
        }
    };
    symbol_location(&kallsyms, sym)
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
    match kernel_symbol(sym) {
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

/// True when a kprobe can plausibly attach to `sym`.
///
/// The BTF half of [`kernel_can_fentry`] does not apply: a kprobe
/// resolves its target by symbol name through the kprobe subsystem, so a
/// symbol in a loaded module is attachable whether or not that module
/// shipped split BTF. Presence in kallsyms is the whole test.
///
/// It is still only a *plausibility* test — the symbol could be on the
/// kprobe blacklist, or in a `noinstr` section — so the caller must also
/// survive an attach that fails anyway. Both layers exist because
/// `audit_seccomp` is genuinely absent on a CONFIG_AUDITSYSCALL=n kernel
/// and that node has to keep running.
fn kernel_can_kprobe(sym: &str) -> bool {
    kernel_symbol(sym).is_some()
}

/// Open, load and attach the seccomp-denial probe and hand its map
/// handles to the drain task. `None` means this node does not get the
/// feature.
///
/// Every failure path here returns `None` with a warning, and that is
/// the most important property of this function rather than a
/// convenience. `audit_seccomp` genuinely does not exist on a kernel
/// built without CONFIG_AUDITSYSCALL; such a node is a supported node
/// and must lose seccomp denial capture, not the Controller. Nothing in
/// here may reach `ebpf_handle`'s `?` — a probe that cannot load is not
/// the same kind of event as the syscall probe failing to load, and
/// turning it into one would trade a missing signal for a
/// CrashLoopBackOff on every CONFIG_AUDITSYSCALL=n cluster.
///
/// The skeleton borrows its `OpenObject` storage for its whole life, so
/// holding it in a local of the poll loop needs a `'static` borrow; the
/// storage (one pointer-sized `MaybeUninit`) is `Box::leak`ed, exactly
/// as `contention::open_load_attach` does. It happens at most once per
/// process, and a failed attempt leaks the same 8 bytes once — the
/// object itself is still dropped and closed.
fn load_seccomp_denial_probe(
    maps_tx: oneshot::Sender<DenialMaps>,
) -> Option<SeccompDenialSkel<'static>> {
    if !kernel_can_kprobe(AUDIT_SECCOMP_SYMBOL) {
        warn!(
            "{AUDIT_SECCOMP_SYMBOL} is not in /proc/kallsyms (kernel built without \
             CONFIG_AUDITSYSCALL, or the symbol inlined away by a full-LTO build); the \
             kernel's seccomp verdicts will not be captured on this node. Every other \
             probe is unaffected."
        );
        return None;
    }

    let storage: &'static mut MaybeUninit<OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut skel = match SeccompDenialSkelBuilder::default()
        .open(storage)
        .and_then(|open| open.load())
    {
        Ok(skel) => skel,
        Err(e) => {
            warn!(
                "could not load the seccomp denial eBPF program ({e}); the kernel's seccomp \
                 verdicts will not be captured on this node"
            );
            return None;
        }
    };

    // Duplicate the map fds BEFORE attaching. If this fails there is
    // nothing that could ever drain the probe, so attaching it would
    // only count verdicts into a map no one reads — and on an LRU map
    // that is invisible rather than noisy.
    let maps = match DenialMaps::from_skel(&skel.maps) {
        Ok(maps) => maps,
        Err(e) => {
            warn!(
                "could not duplicate the seccomp denial map descriptors ({e}); skipping the \
                 probe"
            );
            return None;
        }
    };

    // The second layer of the graceful-degradation guard. kallsyms says
    // the symbol exists, which is necessary but not sufficient: it can
    // still be on the kprobe blacklist or in a section the kernel
    // refuses to instrument.
    if let Err(e) = skel.attach() {
        warn!(
            "could not attach kprobe/{AUDIT_SECCOMP_SYMBOL} ({e}); the symbol is present but \
             not instrumentable on this kernel. Seccomp verdicts will not be captured here."
        );
        return None;
    }

    if maps_tx.send(maps).is_err() {
        warn!("the seccomp denial drain task is not listening; not keeping the probe attached");
        return None;
    }

    info!("Seccomp denial eBPF program loaded and attached (kprobe/{AUDIT_SECCOMP_SYMBOL})");
    Some(skel)
}

// Ten parameters, one per thing `main` has to hand the loader. They are
// not a bag of options with a sensible grouping waiting to be found: each
// is a distinct channel end or a resolved startup value, and bundling them
// into a config struct would only move the same list one file over.
#[allow(clippy::too_many_arguments)]
pub fn ebpf_handle(
    network_event_sender: Sender<NetworkEventData>,
    syscall_event_sender: Sender<SyscallEventData>,
    netpolicy_drop_sender: Sender<PolicyDropEvent>,
    mut rx: Receiver<PodRegistration>,
    mut ignore_ips: Receiver<String>,
    ignore_daemonset_traffic: bool,
    tiers: ResolvedTiers,
    seccomp_denial_maps: Option<oneshot::Sender<DenialMaps>>,
    cgroup_event_sender: Sender<(u64, String)>,
    mut forget_pending: Receiver<u64>,
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

        // Load the syscall probe, degrading rather than dying.
        //
        // Two optional features ride in this object with the required
        // syscall tracepoint: startup capture (tp_btf/cgroup_mkdir) and
        // the cgroup ownership gate on the registered path. Either can be
        // refused by a kernel the object was not tested on — round 3 on
        // cluster-00 (6.18) refused a CO-RE relocation in the ownership
        // walk and the controller crashlooped on every node. The variants
        // are tried in order, each dropping more, down to the pre-gate
        // behaviour; only the last one failing is fatal.
        let variants = syscall_load_variants(
            std::env::var("SYSCALL_OWNERSHIP_GATE").ok().as_deref(),
            std::env::var("KGUARDIAN_INJECT_LOAD_FAILURE")
                .ok()
                .as_deref(),
        );
        let mut storages: [MaybeUninit<OpenObject>; 3] = [const { MaybeUninit::uninit() }; 3];
        let mut loaded = None;
        let mut last_error = String::new();
        for (variant, storage) in variants.iter().zip(storages.iter_mut()) {
            match open_and_load_syscall(storage, *variant) {
                Ok(sk) => {
                    loaded = Some((sk, *variant));
                    break;
                }
                Err(e) => {
                    warn!(
                        ownership_gate = variant.ownership_gate,
                        startup_capture = variant.startup_capture,
                        error = %e,
                        "syscall eBPF object failed to load in this configuration; \
                         retrying with less"
                    );
                    last_error = e;
                }
            }
        }
        let Some((syscall_sk, variant)) = loaded else {
            return Err(Error::Custom(format!(
                "Failed to load syscall eBPF in any configuration: {last_error}"
            )));
        };
        OWNERSHIP_GATE.store(variant.ownership_gate, Ordering::Relaxed);
        if !variant.ownership_gate {
            warn!(
                ownership_gate = false,
                "syscall ownership gate is OFF: syscalls are credited to a pod by network \
                 namespace alone, so host processes working inside a pod's namespace \
                 (containerd, CNI plugins) are counted in its seccomp profile, as before \
                 this gate existed"
            );
        }
        let cgroup_mkdir_loaded = variant.startup_capture;

        // Populate the tier allowlists BEFORE attaching so the very first
        // events are already filtered by tier.
        populate_tier_maps(&syscall_sk.maps, &tiers);
        populate_runtime_prefilter(&syscall_sk.maps.runtime_prefilter);
        // Userspace's half of the pending-path gate (see pending_gate in
        // syscall.bpf.c): marks this process has deleted. Only this loop
        // writes it.
        let mut pending_retired: u64 = 0;

        // Attached one program at a time rather than with skel.attach(),
        // so the startup-capture program can fail on its own. The
        // syscall tracepoint is required; without cgroup_mkdir the probe
        // simply behaves as it did before startup capture existed.
        let _syscall_link = syscall_sk
            .progs
            .trace_execve
            .attach()
            .map_err(|e| Error::Custom(format!("Failed to attach syscall eBPF: {}", e)))?;
        info!("Syscall probe eBPF program loaded and attached");
        let cgroup_mkdir_attach: Result<_, String> = if cgroup_mkdir_loaded {
            syscall_sk
                .progs
                .trace_cgroup_mkdir
                .attach()
                .map_err(|e| e.to_string())
        } else {
            Err("program not loaded (see the load warning above)".into())
        };
        let _cgroup_mkdir_link = match cgroup_mkdir_attach {
            Ok(link) => {
                info!(
                    "Startup syscall capture attached (tp_btf/cgroup_mkdir): containers are \
                     captured from cgroup creation, before their pod is registered"
                );
                Some(link)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "could not attach tp_btf/cgroup_mkdir; syscalls a container makes before \
                     its pod is registered (runtime setup, app startup) will NOT be captured, \
                     so seccomp profiles recorded from fresh pods are not startup-complete"
                );
                None
            }
        };

        // Load and attach the seccomp denial probe. `None` here means
        // SECCOMP_DENIAL_CAPTURE is off and nothing is loaded at all;
        // `None` back from the loader means this kernel cannot carry the
        // probe. Neither is an error — unlike the three above, this one
        // is never allowed to stop the Controller.
        let seccomp_denial_sk = seccomp_denial_maps.and_then(load_seccomp_denial_probe);

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

        // Cgroup creations for startup capture (see early_capture). Rare —
        // one per container, sandbox and pod-level cgroup — so a string
        // allocation per event is fine.
        ring_buffer_builder
            .add(&syscall_sk.maps.cgroup_events, move |data: &[u8]| {
                if data.len() < std::mem::size_of::<CgroupEventData>() {
                    eprintln!(
                        "Cgroup event data too small: {} < {}",
                        data.len(),
                        std::mem::size_of::<CgroupEventData>()
                    );
                    return 0;
                }
                let ev: CgroupEventData = unsafe { *(data.as_ptr() as *const CgroupEventData) };
                if let Err(e) = cgroup_event_sender.blocking_send((ev.cgroup_id, ev.path_str())) {
                    if !CGROUP_SEND_FAILED.swap(true, Ordering::Relaxed) {
                        warn!(error = ?e, "cgroup event channel closed; signalling eBPF poll loop to exit");
                    }
                    signal_ebpf_shutdown();
                }
                0
            })
            .map_err(|e| {
                Error::Custom(format!("Failed to add cgroup events ring buffer: {}", e))
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
            // (within ~100ms) when a receiver-closed handler — or main's
            // shutdown path — flips it. Returning Err propagates up
            // through the JoinHandle to the supervisor, which fails the
            // controller and prompts the kubelet to restart the pod —
            // clean recovery instead of a stuck process.
            if ebpf_shutdown_requested() {
                return Err(Error::Custom(
                    "eBPF poll loop exiting: shutdown was signalled (an event-channel receiver closed, or the Controller is terminating). Pod will restart if this was not a graceful shutdown.".into(),
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
                // The same flags value goes into every probe's map. They
                // all read the generation bits out of their own
                // instance — every per-netns key in the tree folds in
                // the generation, because the kernel recycles netns
                // inode numbers and a bare-inode key hands a dead pod's
                // state to its replacement (see KG_GEN_SHIFT in
                // src/bpf/helper.h). Only the syscall probe reads the
                // tier bits; for the network, netpolicy and seccomp
                // denial probes those stay inert.
                let key = reg.netns_inode.to_ne_bytes();
                let val = reg.flags.to_ne_bytes();
                if reg.unregister {
                    // Compare-and-delete in every instance. Registrations
                    // and unregistrations travel this one channel in the
                    // order the pod watcher sent them and are applied only
                    // here, so nothing can slip in between the lookup and
                    // the delete; the compare protects a newer pod already
                    // registered on the recycled inode.
                    let mut maps: Vec<&libbpf_rs::Map> = vec![
                        &network_sk.maps.inode_num,
                        &syscall_sk.maps.inode_num,
                        &netpolicy_sk.maps.inode_num,
                    ];
                    if let Some(sk) = seccomp_denial_sk.as_ref() {
                        maps.push(&sk.maps.inode_num);
                    }
                    let removed = maps
                        .into_iter()
                        .filter(|m| compare_and_delete(m, &key, &val))
                        .count();
                    tracing::debug!(
                        inode = reg.netns_inode,
                        flags = reg.flags,
                        removed,
                        "netns unregistered (pod finished)"
                    );
                    continue;
                }
                // Ownership side tables for the syscall probe's registered
                // path (credit_generation in syscall.bpf.c). Written before
                // inode_num so the first syscall credited under this
                // registration already sees them.
                let generation = crate::models::pod_flags::generation(reg.flags);
                if reg.alias_gen != 0 {
                    let _ = syscall_sk
                        .maps
                        .gen_alias
                        .update(
                            &reg.alias_gen.to_ne_bytes(),
                            &generation.to_ne_bytes(),
                            MapFlags::ANY,
                        )
                        .map_err(|e| eprintln!("Failed to update gen_alias: {}", e));
                }
                if reg.host_network {
                    let _ = syscall_sk
                        .maps
                        .hostnet_gens
                        .update(&generation.to_ne_bytes(), &1u8.to_ne_bytes(), MapFlags::ANY)
                        .map_err(|e| eprintln!("Failed to update hostnet_gens: {}", e));
                }
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
                // Fourth instance, present only when the seccomp denial
                // probe loaded. Its registration is the gate: the probe
                // drops anything from an unregistered netns, and stamps
                // the generation it reads here into every row it
                // records. It is a gate and not the whole attribution —
                // a hostNetwork pod's netns is the node's, so the entry
                // says only that something tracked lives there, and the
                // cgroup id the probe records alongside is what names
                // which container. The drain does NOT read this map
                // back — it derives the generation it expects from the
                // same `ContainerMap` entry it takes the pod's identity
                // from, because reading the two out of separate stores
                // is what let a dead pod's denials be written to the pod
                // that took its inode (see
                // `seccomp_denial::build_denials`).
                if let Some(sk) = seccomp_denial_sk.as_ref() {
                    let _ = sk
                        .maps
                        .inode_num
                        .update(&key, &val, MapFlags::ANY)
                        .map_err(|e| eprintln!("Failed to update seccomp denial inode map: {}", e));
                }
            }
            // Startup capture: cgroups userspace is done with (attributed,
            // expired, or never a container). Deleting the pending mark
            // stops the kernel capturing them; a miss (already evicted by
            // the LRU) is harmless.
            let mut forgotten = 0;
            let mut retired_now = 0u64;
            while forgotten < MAX_DRAIN_PER_ITERATION {
                let Ok(cgroup_id) = forget_pending.try_recv() else {
                    break;
                };
                forgotten += 1;
                // Only a delete that removed a mark counts towards the
                // gate: a repeat forget (late event re-attributed) or a
                // mark the LRU already evicted must not.
                if syscall_sk
                    .maps
                    .pending_cgroups
                    .delete(&cgroup_id.to_ne_bytes())
                    .is_ok()
                {
                    retired_now += 1;
                }
            }
            if retired_now > 0 {
                pending_retired += retired_now;
                let _ = syscall_sk
                    .maps
                    .pending_gate
                    .update(
                        &PENDING_GATE_RETIRED.to_ne_bytes(),
                        &pending_retired.to_ne_bytes(),
                        MapFlags::ANY,
                    )
                    .map_err(|e| eprintln!("Failed to update pending_gate: {}", e));
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

    /// The one thing `audit_seccomp`'s gate must never get wrong.
    ///
    /// A kernel built without CONFIG_AUDITSYSCALL has no such symbol, and
    /// on that node the probe has to be skipped. Attaching optimistically
    /// — or treating an unreadable /proc/kallsyms as "probably there" —
    /// turns a missing signal into a DaemonSet that will not start, on
    /// every cluster whose kernel was built that way.
    #[test]
    fn an_absent_symbol_is_never_attached_by_either_gate() {
        const NONSENSE: &str = "kguardian_definitely_not_a_kernel_symbol";
        assert!(!kernel_can_kprobe(NONSENSE));
        assert!(!kernel_can_fentry(NONSENSE));
    }

    /// The two gates part company on a module symbol, and only there.
    ///
    /// `kernel_can_fentry` additionally demands /sys/kernel/btf/<module>,
    /// because fentry resolves through BTF. `kernel_can_kprobe` does not,
    /// because a kprobe resolves by name through the kprobe subsystem —
    /// so a module symbol with no split BTF is attachable by one and not
    /// the other. Both read this same parse; the divergence is in what
    /// each does with `Some(Some(module))`.
    #[test]
    fn a_module_symbol_is_located_for_both_gates_to_judge() {
        let dump = "ffffffffc0aa0000 t audit_seccomp\t[somemod]\n";
        assert_eq!(
            symbol_location(dump, "audit_seccomp"),
            Some(Some("somemod".to_string()))
        );
    }

    #[test]
    fn symbol_location_absent_and_no_prefix_confusion() {
        // __pfx_/prefixed neighbours must not satisfy an exact lookup.
        let dump = "ffffffff81000000 T __pfx_udpv6_sendmsg\n\
                    ffffffff81000010 T udpv6_sendmsg_prelude\n";
        assert_eq!(symbol_location(dump, "udpv6_sendmsg"), None);
    }

    // ---- syscall object load variants (round 3 crashloop) ------------------

    fn v(gate: bool, startup: bool, inject: bool) -> SyscallLoadVariant {
        SyscallLoadVariant {
            ownership_gate: gate,
            startup_capture: startup,
            inject_failure: inject,
        }
    }

    #[test]
    fn load_variants_degrade_down_to_the_pre_gate_behaviour() {
        assert_eq!(
            syscall_load_variants(None, None),
            vec![
                v(true, true, false),
                v(false, true, false),
                v(false, false, false)
            ]
        );
        // The last resort never carries either optional feature.
        let last = *syscall_load_variants(None, None).last().unwrap();
        assert!(!last.ownership_gate && !last.startup_capture);
    }

    #[test]
    fn the_ownership_gate_can_be_switched_off() {
        for off in ["off", "false", "0", "OFF", " disabled "] {
            assert!(
                syscall_load_variants(Some(off), None)
                    .iter()
                    .all(|v| !v.ownership_gate),
                "{off:?}"
            );
        }
        assert_eq!(syscall_load_variants(Some("on"), None).len(), 3);
    }

    /// The fallback the live crash needed: a gated object that fails to
    /// load must leave a gate-less one to try, and injection lets that be
    /// proven on a real node (KGUARDIAN_INJECT_LOAD_FAILURE=ownership).
    #[test]
    fn an_injected_gate_failure_falls_back_to_the_gateless_object() {
        let variants = syscall_load_variants(None, Some("ownership"));
        let first_ok = variants.iter().find(|v| !v.inject_failure).unwrap();
        assert!(!first_ok.ownership_gate);
        assert!(
            first_ok.startup_capture,
            "startup capture survives a gate failure"
        );
        assert!(syscall_load_variants(None, Some("all"))
            .iter()
            .all(|v| v.inject_failure));
    }

    /// Loads every probe object on the RUNNING kernel, the way the
    /// controller does, and requires the full configuration to load
    /// without falling back. Needs root and a BTF kernel, so it is ignored
    /// by default; the ebpf-kernels CI job runs it inside VMs booted on
    /// several kernels (.github/workflows/controller-ebpf-kernels.yaml).
    #[test]
    #[ignore = "needs root and a BTF-enabled kernel; run by the ebpf-kernels CI job"]
    fn every_probe_object_loads_on_this_kernel() {
        use crate::network::netpolicy_drop::NetpolicyDropSkelBuilder;
        use crate::network::network_probe::NetworkProbeSkelBuilder;

        // Syscall object: every variant must load on its own. The gate-less
        // ones are the fallback guarantee (checked first, so a broken
        // gated build still proves the fallback would have saved the
        // node); the full one failing is exactly the regression to catch.
        let mut failures = Vec::new();
        let mut variants = syscall_load_variants(None, None);
        variants.reverse();
        for variant in variants {
            let mut storage = MaybeUninit::uninit();
            let outcome = open_and_load_syscall(&mut storage, variant).map(drop);
            match outcome {
                Ok(()) => eprintln!("syscall object loads: {variant:?}"),
                Err(e) => {
                    eprintln!("syscall object FAILS: {variant:?}: {e}");
                    failures.push((variant, e));
                }
            }
        }
        assert!(
            failures.iter().all(|(v, _)| v.ownership_gate),
            "a fallback (gate-less) configuration does not load: {failures:?}"
        );
        assert!(failures.is_empty(), "{failures:?}");

        let udpv6 = kernel_can_fentry("udpv6_sendmsg");
        let mut storage = MaybeUninit::uninit();
        let mut open = NetworkProbeSkelBuilder::default()
            .open(&mut storage)
            .expect("open network probe");
        if !udpv6 {
            open.progs.trace_udpv6_send.set_autoload(false);
        }
        open.load().expect("load network probe");

        let mut storage = MaybeUninit::uninit();
        let mut open = NetpolicyDropSkelBuilder::default()
            .open(&mut storage)
            .expect("open netpolicy probe");
        if !udpv6 {
            open.progs.trace_udpv6_send.set_autoload(false);
        }
        open.load().expect("load netpolicy probe");

        if kernel_can_kprobe(AUDIT_SECCOMP_SYMBOL) {
            let mut storage = MaybeUninit::uninit();
            SeccompDenialSkelBuilder::default()
                .open(&mut storage)
                .expect("open seccomp denial probe")
                .load()
                .expect("load seccomp denial probe");
        }

        let mut storage = MaybeUninit::uninit();
        crate::contention::sched_contention_skel::SchedContentionSkelBuilder::default()
            .open(&mut storage)
            .expect("open sched contention probe")
            .load()
            .expect("load sched contention probe");
    }

    /// End to end on the RUNNING kernel: the syscall probe's ownership
    /// gate must credit a task in a pod's own cgroup to that pod. The
    /// test registers its own netns under a pod generation (as the pod
    /// watcher would), runs a process in a kubepods-shaped cgroup whose
    /// pod UID hashes to that generation, and checks both what the gate
    /// cached for the cgroup and that the syscalls arrive. Startup capture
    /// is left off so the registered path, and the gate, are what run.
    /// Needs root and cgroup v2; run by the ebpf-kernels CI job.
    #[test]
    #[ignore = "needs root, cgroup v2 and a BTF-enabled kernel; run by the ebpf-kernels CI job"]
    fn syscall_ownership_gate_credits_a_pod_cgroup() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::process::CommandExt;
        use std::sync::Arc;

        const UID: &str = "0c8f5a1e-2b4d-4e0a-9f1c-0123456789ab";
        const CID: &str = "7a1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let pod_dir = format!("/sys/fs/cgroup/kubepods/besteffort/pod{UID}");
        let ctr_dir = format!("{pod_dir}/{CID}");
        std::fs::create_dir_all(&ctr_dir).expect("create a kubepods-shaped cgroup");
        let cgid = std::fs::metadata(&ctr_dir).unwrap().ino();

        let mut storage = MaybeUninit::uninit();
        let variant = SyscallLoadVariant {
            ownership_gate: true,
            startup_capture: false,
            inject_failure: false,
        };
        let sk = open_and_load_syscall(&mut storage, variant).expect("load the gated object");
        let _link = sk.progs.trace_execve.attach().expect("attach sys_enter");

        let gen = crate::models::pod_flags::generation_for_uid(Some(UID));
        let netns = std::fs::metadata("/proc/self/ns/net").unwrap().ino();
        sk.maps
            .inode_num
            .update(
                &netns.to_ne_bytes(),
                &crate::models::pod_flags::pack(CaptureLevel::Full, gen).to_ne_bytes(),
                MapFlags::ANY,
            )
            .expect("register the netns");

        let events: Arc<Mutex<Vec<SyscallEventData>>> = Arc::default();
        let sink = Arc::clone(&events);
        let mut rb = RingBufferBuilder::new();
        rb.add(&sk.maps.syscall_events, move |data: &[u8]| {
            let ev: SyscallEventData =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const SyscallEventData) };
            sink.lock().unwrap().push(ev);
            0
        })
        .unwrap();
        let rb = rb.build().unwrap();

        let procs = format!("{ctr_dir}/cgroup.procs");
        let status = unsafe {
            std::process::Command::new("/bin/sh")
                .args(["-c", "/bin/true"])
                .pre_exec(move || {
                    std::fs::write(&procs, std::process::id().to_string())?;
                    Ok(())
                })
                .status()
        }
        .expect("spawn");
        assert!(status.success());
        for _ in 0..20 {
            rb.poll(std::time::Duration::from_millis(100)).unwrap();
        }

        let cached = sk
            .maps
            .cgroup_pod_gen
            .lookup(&cgid.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .map(|v| u32::from_ne_bytes(v[..4].try_into().unwrap()));
        let credited = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.cgroup_id == cgid && e.generation == gen)
            .count();
        eprintln!(
            "gate for cgroup {cgid}: cached {cached:#x?}, expected {:#x}; \
             syscalls credited to the pod: {credited}",
            (1u32 << 31) | gen
        );
        let _ = std::fs::remove_dir(&ctr_dir);
        let _ = std::fs::remove_dir(&pod_dir);
        assert_eq!(
            cached,
            Some((1u32 << 31) | gen),
            "the gate must recognise the pod-level cgroup"
        );
        assert!(credited > 0, "the pod's syscalls must be credited to it");
    }

    fn reset_state() {
        EBPF_SHUTDOWN.store(false, Ordering::Relaxed);
        NETWORK_SEND_FAILED.store(false, Ordering::Relaxed);
        SYSCALL_SEND_FAILED.store(false, Ordering::Relaxed);
        POLICY_DROP_SEND_FAILED.store(false, Ordering::Relaxed);
        CGROUP_SEND_FAILED.store(false, Ordering::Relaxed);
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

    /// The idle-node shutdown path, pinned.
    ///
    /// The poll loop lives in a `spawn_blocking` that nothing can
    /// cancel, and dropping the runtime waits for it with no timeout
    /// (tokio 1.53.1: `BlockingPool::drop` → `shutdown(None)` →
    /// `shutdown_rx.wait(None)`). So this flag is the only thing that
    /// lets the process exit at all.
    ///
    /// Before `signal_ebpf_shutdown` was reachable from outside this
    /// module, the only thing that raised it was a `blocking_send`
    /// failing against a dropped receiver — which requires an eBPF
    /// event to arrive. Under traffic that is instant; on a node with
    /// no traffic no event fires, nothing trips, and SIGTERM hung until
    /// the kubelet's SIGKILL (30s, the default: this DaemonSet sets no
    /// terminationGracePeriodSeconds and has no probes). "SIGTERM works"
    /// was only ever true under load, which is exactly the kind of
    /// thing that regresses invisibly.
    ///
    /// What this pins is the independence: the flag goes up with no
    /// channel, no callback and no send failure anywhere.
    #[test]
    fn shutdown_can_be_requested_with_no_event_ever_arriving() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_state();

        // An idle node: nothing has been sent, so none of the
        // send-failure latches has fired.
        assert!(!ebpf_shutdown_requested());
        assert!(!NETWORK_SEND_FAILED.load(Ordering::Relaxed));
        assert!(!SYSCALL_SEND_FAILED.load(Ordering::Relaxed));
        assert!(!POLICY_DROP_SEND_FAILED.load(Ordering::Relaxed));

        signal_ebpf_shutdown();

        assert!(
            ebpf_shutdown_requested(),
            "the poll loop checks this at the top of every iteration, so raising it is what \
             bounds SIGTERM at one ~100ms poll interval on a node with no traffic"
        );
        assert!(
            !NETWORK_SEND_FAILED.load(Ordering::Relaxed)
                && !SYSCALL_SEND_FAILED.load(Ordering::Relaxed)
                && !POLICY_DROP_SEND_FAILED.load(Ordering::Relaxed),
            "shutdown must not route through the send-failure latches; depending on them is \
             precisely what made this path need traffic to work"
        );
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

    /// The shutdown *sequence*, not just the flag.
    ///
    /// `shutdown_can_be_requested_with_no_event_ever_arriving` above
    /// proves the flag CAN be raised. It does not prove anything raises
    /// it — mutation testing confirmed that deleting the call from the
    /// shutdown path left the whole suite green while restoring the
    /// idle-node hang. This drives the sequence `main` actually calls.
    ///
    /// `block_on` rather than `#[tokio::test]` so `TEST_GUARD` is never
    /// held across an await: these statics are process-global and the
    /// other tests in this module race for them.
    #[test]
    fn the_controller_shutdown_sequence_raises_the_ebpf_flag() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_state();
        assert!(!ebpf_shutdown_requested());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a test runtime");
        let recovered = rt.block_on(async {
            let mut supervisor = crate::supervisor::Supervisor::new();
            crate::supervisor::shut_down(&mut supervisor, crate::supervisor::Draining::Gracefully)
                .await
        });

        assert!(
            recovered.is_empty(),
            "nothing was running, so nothing faulted"
        );
        assert!(
            ebpf_shutdown_requested(),
            "the shutdown sequence must raise the flag: the poll loop is a spawn_blocking \
             that nothing can cancel, and dropping the runtime waits for it with no \
             timeout, so this is the only thing that lets the process exit on an idle node"
        );
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
