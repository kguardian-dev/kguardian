//! Startup syscall capture: attributing syscalls made by containers the
//! pod watcher has not registered yet.
//!
//! # Why
//!
//! A pod's netns reaches the eBPF `inode_num` map only once an app
//! container is running: the pod watcher needs a `containerID` from the
//! pod status and a pid from containerd before it can read the netns
//! inode. Until then the syscall probe dropped everything the pod did,
//! so runc's container setup and the app's first ~100 ms were never
//! recorded. A seccomp profile built from a fresh pod was therefore not
//! startup-complete, and enforcing it with `SCMP_ACT_ERRNO` crashlooped
//! the next restart (proven live on cluster-00, 2026-09-03).
//!
//! # How
//!
//! The container's cgroup exists before any of its tasks run. The
//! `tp_btf/cgroup_mkdir` program in `bpf/syscall.bpf.c` marks every new
//! kubepods cgroup *pending* in the kernel and sends its path here. The
//! syscall probe, when a task's netns is not registered, falls back to
//! the pending map by cgroup id and emits a deduplicated
//! `KG_SYSCALL_EVENT_PENDING` event. This module buffers those events by
//! cgroup id, learns each cgroup's pod UID and container id from its
//! path, and — once the pod watcher has registered that pod — hands the
//! buffered syscalls to the normal per-pod pipeline, filtered by the
//! pod's capture tier. Cgroups that are done (attributed and past the
//! linger window), that can never be attributed (not a container, not a
//! pod we track), or that expired are handed back so the eBPF loop can
//! delete their pending mark.
//!
//! # What is deliberately left out
//!
//! * The pod sandbox (pause). It has its own cgroup and seccomp profile.
//!   Its container id never appears in pod status, so once the pod is
//!   registered a cgroup no status claims for [`SANDBOX_GRACE`] is
//!   discarded, not merged. Pod status was chosen over asking containerd
//!   (`io.cri-containerd.kind=sandbox`) because it needs no RPC on this
//!   path and names the app containers positively.
//! * runc's pre-filter setup syscalls ([`RUNTIME_PREFILTER_SYSCALLS`],
//!   skipped in the kernel for `runc:[…]` tasks).
//!
//! # Knobs
//!
//! `STARTUP_CAPTURE_PENDING_TTL_SECONDS` (default 600) and
//! `STARTUP_CAPTURE_KNOWN_POD_TTL_SECONDS` (default 3600).
//!
//! Everything here is pure and clock-injected so it is unit-testable
//! without a kernel.

use crate::capture_tiers::ResolvedTiers;
use crate::models::pod_flags;
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

/// Size of the path buffer in `struct cgroup_event_t`. Keep in sync with
/// `KG_CGROUP_PATH_MAX` in `bpf/syscall.bpf.c`.
pub const CGROUP_PATH_MAX: usize = 256;

/// `data_t.kind` values. Keep in sync with `KG_SYSCALL_EVENT_*` in
/// `bpf/syscall.bpf.c`.
pub const SYSCALL_EVENT_REGISTERED: u32 = 0;
pub const SYSCALL_EVENT_PENDING: u32 = 1;

/// Default for how long a pending cgroup may wait when its pod is not
/// known to the pod watcher at all (`STARTUP_CAPTURE_PENDING_TTL_SECONDS`).
///
/// A cgroup that belongs to a pod kube-guardian never tracks (an excluded
/// namespace, a non-containerd runtime, a static pod whose mirror UID
/// differs) is dropped when this expires. A pod the watcher HAS seen gets
/// [`KNOWN_POD_TTL`] instead.
pub const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

/// Default for how long a pending cgroup may wait when the pod watcher
/// knows its pod but has not registered it yet
/// (`STARTUP_CAPTURE_KNOWN_POD_TTL_SECONDS`). Registration waits for the
/// pod to be Ready, so this has to outlast long init containers, slow
/// image pulls and slow readiness probes.
pub const KNOWN_POD_TTL: Duration = Duration::from_secs(60 * 60);

/// How long a container cgroup of a REGISTERED pod may stay unclaimed —
/// its id in none of the pod's container statuses — before it is taken
/// to be the pod sandbox (pause) and discarded. The sandbox id never
/// appears in pod status; an app container's id appears as soon as the
/// kubelet reports it started, normally within a second.
pub const SANDBOX_GRACE: Duration = Duration::from_secs(60);

/// How long a retired cgroup is remembered, so pending events that were
/// already in flight when it retired (the kernel mark is deleted a poll
/// later) are still attributed — or discarded, for a sandbox — instead of
/// starting an anonymous entry nothing can attribute.
pub const TOMBSTONE_TTL: Duration = Duration::from_secs(5 * 60);

/// Syscalls the container runtime makes only BEFORE it installs the
/// container's seccomp filter, and that the probe therefore skips for
/// tasks named `runc:[…]` (never for the app itself). Resolved to numbers
/// per arch and written into the `runtime_prefilter` map; see the comment
/// on that map in `bpf/syscall.bpf.c` for why this is a short list and
/// not "everything runc init does".
///
/// All of these run in runc's rootfs/hostname/keyring/namespace setup,
/// ahead of `syncParentReady`, whether the filter is installed early
/// (NoNewPrivileges unset) or late (NoNewPrivileges set).
pub const RUNTIME_PREFILTER_SYSCALLS: &[&str] = &[
    // namespaces (nsexec)
    "unshare",
    "setns",
    // rootfs
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "mount_setattr",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    // /dev population
    "mknod",
    "mknodat",
    "symlink",
    "symlinkat",
    // UTS + session keyring
    "sethostname",
    "setdomainname",
    "keyctl",
];

/// Durations read from the environment, with the defaults above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupCaptureConfig {
    pub pending_ttl: Duration,
    pub known_pod_ttl: Duration,
}

impl Default for StartupCaptureConfig {
    fn default() -> Self {
        Self {
            pending_ttl: PENDING_TTL,
            known_pod_ttl: KNOWN_POD_TTL,
        }
    }
}

impl StartupCaptureConfig {
    /// Parse from raw env values; a missing, unparseable or zero value
    /// keeps the default. The known-pod TTL is never shorter than the
    /// base TTL.
    pub fn from_values(pending: Option<&str>, known: Option<&str>) -> Self {
        let secs = |v: Option<&str>, d: Duration| {
            v.and_then(|s| s.trim().parse::<u64>().ok())
                .filter(|&n| n > 0)
                .map(Duration::from_secs)
                .unwrap_or(d)
        };
        let pending_ttl = secs(pending, PENDING_TTL);
        let known_pod_ttl = secs(known, KNOWN_POD_TTL).max(pending_ttl);
        Self {
            pending_ttl,
            known_pod_ttl,
        }
    }

    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var("STARTUP_CAPTURE_PENDING_TTL_SECONDS")
                .ok()
                .as_deref(),
            std::env::var("STARTUP_CAPTURE_KNOWN_POD_TTL_SECONDS")
                .ok()
                .as_deref(),
        )
    }
}

/// How long a cgroup stays pending after its pod was first found.
///
/// After registration the netns path captures the pod's tasks, but a
/// task that has not joined the pod netns yet (runc init before setns)
/// only reaches us through the pending path, so the mark is kept for a
/// short while rather than dropped at the first flush.
pub const ATTRIBUTED_LINGER: Duration = Duration::from_secs(30);

/// Upper bound on cgroups buffered in userspace. The kernel map holds
/// 8192; this only has to cover the containers starting at once on one
/// node.
pub const MAX_TRACKED_CGROUPS: usize = 4096;

/// A cgroup creation event as the kernel writes it into the
/// `cgroup_events` ring buffer. Keep in sync with `struct
/// cgroup_event_t` in `bpf/syscall.bpf.c`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupEventData {
    pub cgroup_id: u64,
    pub level: u32,
    pub _pad: u32,
    pub path: [u8; CGROUP_PATH_MAX],
}

impl CgroupEventData {
    /// The path up to its NUL terminator, lossily decoded.
    pub fn path_str(&self) -> String {
        let end = self
            .path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(CGROUP_PATH_MAX);
        String::from_utf8_lossy(&self.path[..end]).into_owned()
    }
}

/// What a kubepods cgroup path says about who lives in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupIdentity {
    /// The pod UID, normalised to the dashed form `metadata.uid` uses.
    pub pod_uid: String,
    /// The container id (the runtime prefix and `.scope` suffix
    /// stripped). `None` for the pod-level cgroup itself, which never
    /// holds a task under cgroup v2's no-internal-process rule.
    pub container_id: Option<String>,
}

/// True for the two pod UID shapes kubelet puts in cgroup paths: an
/// RFC 4122 UUID (every API-created pod) or a 32-hex config hash (static
/// pods).
fn is_pod_uid(s: &str) -> bool {
    let b = s.as_bytes();
    match b.len() {
        36 => b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        }),
        32 => b.iter().all(u8::is_ascii_hexdigit),
        _ => false,
    }
}

/// The pod UID named by one path segment, if it is a pod cgroup.
///
/// cgroupfs driver: `pod<uid>` with the UID's own dashes.
/// systemd driver: `kubepods[-<qos>]-pod<uid>.slice` with the UID's
/// dashes turned into underscores (a `-` would nest another slice), and
/// kind's `kubelet-kubepods-…-pod<uid>.slice` the same way.
fn pod_uid_from_segment(seg: &str) -> Option<String> {
    let seg = seg.strip_suffix(".slice").unwrap_or(seg);
    let candidate = if let Some(rest) = seg.strip_prefix("pod") {
        rest
    } else {
        let at = seg.rfind("-pod")?;
        &seg[at + 4..]
    };
    let uid = candidate.replace('_', "-");
    is_pod_uid(&uid).then_some(uid)
}

/// The container id named by a container cgroup segment.
///
/// systemd driver: `<runtime-prefix>-<id>.scope`
/// (`cri-containerd-<id>.scope`, `crio-<id>.scope`, `docker-<id>.scope`).
/// cgroupfs driver: the bare id.
pub(crate) fn container_id_from_segment(seg: &str) -> Option<String> {
    let id = match seg.strip_suffix(".scope") {
        Some(scope) => &scope[scope.rfind('-').map_or(0, |i| i + 1)..],
        None => seg,
    };
    (!id.is_empty() && id.bytes().all(|c| c.is_ascii_alphanumeric())).then(|| id.to_string())
}

/// Parse a cgroup v2 path (as the `cgroup_mkdir` tracepoint reports it,
/// relative to the cgroup root) into the pod and container it belongs to.
///
/// Returns `None` for anything that is not under a kubepods hierarchy or
/// has no pod segment — a systemd unit, the QoS slices, the kubepods
/// root itself. A cgroup nested *below* a container (a container that
/// manages its own sub-cgroups) resolves to that container.
pub fn parse_kubepods_cgroup_path(path: &str) -> Option<CgroupIdentity> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let kubepods_at = segs.iter().position(|s| s.contains("kubepods"))?;
    let (pod_at, pod_uid) = segs
        .iter()
        .enumerate()
        .skip(kubepods_at)
        .find_map(|(i, s)| pod_uid_from_segment(s).map(|uid| (i, uid)))?;
    let container_id = segs
        .get(pod_at + 1)
        .and_then(|s| container_id_from_segment(s));
    Some(CgroupIdentity {
        pod_uid,
        container_id,
    })
}

/// Keep only the syscalls the pod's capture tier allows. `flags` is the
/// pod's `inode_num` value (`pod_flags`). Full, and any tier index
/// userspace does not emit, is unfiltered — the same rule as
/// `tier_allows` in the probe, so a bad value can never blind capture.
pub fn filter_for_tier(flags: u32, tiers: &ResolvedTiers, syscalls: &BTreeSet<u32>) -> Vec<u32> {
    match pod_flags::level(flags).and_then(|l| tiers.for_level(l)) {
        Some(allow) => syscalls.intersection(allow).copied().collect(),
        None => syscalls.iter().copied().collect(),
    }
}

// ---- Pods the watcher knows about -----------------------------------------
//
// The pod watcher only REGISTERS a pod (ContainerMap + inode_num) once it
// is Ready, but it sees it much earlier. Startup capture needs both facts:
// "this UID is a pod we track, keep waiting" (so a long init container
// does not expire), and "these are the pod's container ids" (so the
// sandbox, whose id never appears in pod status, is not merged into the
// app containers' set). Kept here, written by the watcher, read by the
// attribution pass. A plain lock: no await is ever held across it.

/// uid -> (when last noted, the pod's container ids).
type KnownPods = HashMap<String, (Instant, BTreeSet<String>)>;

static KNOWN_PODS: std::sync::LazyLock<std::sync::RwLock<KnownPods>> =
    std::sync::LazyLock::new(Default::default);

/// Every container id a pod's status names: current and last-terminated,
/// for app, init and ephemeral containers. Bare ids (runtime prefix
/// stripped); the pod sandbox is never among them.
pub fn pod_container_ids(pod: &k8s_openapi::api::core::v1::Pod) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let Some(status) = pod.status.as_ref() else {
        return ids;
    };
    let lists = [
        status.container_statuses.as_deref(),
        status.init_container_statuses.as_deref(),
        status.ephemeral_container_statuses.as_deref(),
    ];
    for cs in lists.into_iter().flatten().flatten() {
        let last = cs
            .last_state
            .as_ref()
            .and_then(|s| s.terminated.as_ref())
            .and_then(|t| t.container_id.as_deref());
        for raw in [cs.container_id.as_deref(), last].into_iter().flatten() {
            if let Some(id) = crate::container::parse_container_id(raw) {
                ids.insert(id);
            }
        }
    }
    ids
}

/// Record (or refresh) a pod the watcher tracks on this node.
pub fn note_known_pod(pod: &k8s_openapi::api::core::v1::Pod) {
    let Some(uid) = pod.metadata.uid.as_deref().filter(|u| !u.is_empty()) else {
        return;
    };
    let ids = pod_container_ids(pod);
    if let Ok(mut known) = KNOWN_PODS.write() {
        known.insert(uid.to_string(), (Instant::now(), ids));
    }
}

/// Drop a pod that is terminal or deleted.
pub fn forget_known_pod(uid: &str) {
    if let Ok(mut known) = KNOWN_PODS.write() {
        known.remove(uid);
    }
}

/// Drop pods noted before `listed_at` that are not in `live` (the resync
/// LIST taken at `listed_at`). A pod noted after the LIST is newer than
/// its evidence and is kept; the next resync judges it.
pub fn retain_known_pods(live: &std::collections::HashSet<String>, listed_at: Instant) {
    if let Ok(mut known) = KNOWN_PODS.write() {
        known.retain(|uid, (noted, _)| live.contains(uid) || *noted >= listed_at);
    }
}

/// The container ids of a known pod, or `None` if the watcher does not
/// know the UID.
pub fn known_pod_containers(uid: &str) -> Option<BTreeSet<String>> {
    KNOWN_PODS.read().ok()?.get(uid).map(|(_, ids)| ids.clone())
}

// ---- hostNetwork pods by generation ---------------------------------------
//
// Every hostNetwork pod on a node shares the node's netns, and the
// ContainerMap (keyed by netns inode) holds only the last one registered.
// The probe credits their tasks by the generation of their own cgroup, and
// userspace resolves that generation here.

static HOST_NETWORK_PODS: std::sync::LazyLock<
    std::sync::RwLock<HashMap<u32, std::sync::Arc<crate::PodInspect>>>,
> = std::sync::LazyLock::new(Default::default);

pub fn note_host_network_pod(pod: std::sync::Arc<crate::PodInspect>) {
    let generation = pod_flags::generation(pod.capture_flags);
    if let Ok(mut pods) = HOST_NETWORK_PODS.write() {
        pods.insert(generation, pod);
    }
}

pub fn host_network_pod(generation: u32) -> Option<std::sync::Arc<crate::PodInspect>> {
    HOST_NETWORK_PODS.read().ok()?.get(&generation).cloned()
}

pub fn host_network_pods_by_uid() -> HashMap<String, std::sync::Arc<crate::PodInspect>> {
    HOST_NETWORK_PODS
        .read()
        .map(|pods| {
            pods.values()
                .map(|p| (p.info.config.metadata.uid.clone(), std::sync::Arc::clone(p)))
                .collect()
        })
        .unwrap_or_default()
}

/// Drop hostNetwork pods registered before `listed_at` whose UID is not in
/// `live` (the resync LIST taken at `listed_at`).
pub fn retain_host_network_pods(live: &std::collections::HashSet<String>, listed_at: Instant) {
    if let Ok(mut pods) = HOST_NETWORK_PODS.write() {
        pods.retain(|_, p| {
            live.contains(&p.info.config.metadata.uid)
                || p.registered_at.is_none_or(|at| at >= listed_at)
        });
    }
}

// ---- Pod-level cgroup names (mirror of bpf/pod_cgroup.h) -------------------

/// `kg_pod_gen_from_name` in `bpf/pod_cgroup.h`, in Rust: the registration
/// generation of the pod a pod-level cgroup name belongs to, or `None`.
/// Kept byte-for-byte equivalent; `the_c_pod_cgroup_parser_matches_the_rust_one`
/// compiles the C and compares them on the same names.
pub fn pod_generation_from_cgroup_name(name: &str) -> Option<u32> {
    let n = name.as_bytes();
    let scan = n.len().min(128 - 3);
    let mut at = None;
    for i in 0..scan {
        if n[i..].starts_with(b"pod") && (i == 0 || n[i - 1] == b'-') {
            at = Some(i + 3);
        }
    }
    let rest = &n[at?..];
    let len = rest
        .iter()
        .take(36)
        .position(|&c| c == b'.')
        .unwrap_or(rest.len().min(36));
    let uid: Vec<u8> = rest[..len]
        .iter()
        .map(|&c| if c == b'_' { b'-' } else { c })
        .collect();
    if let Some(&end) = rest.get(len) {
        if end != b'.' {
            return None;
        }
    }
    let dashes_ok = uid.iter().enumerate().all(|(k, &c)| match c {
        b'-' => matches!(k, 8 | 13 | 18 | 23),
        c => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
    });
    let dashes = uid.iter().filter(|&&c| c == b'-').count();
    if !dashes_ok || !((len == 36 && dashes == 4) || (len == 32 && dashes == 0)) {
        return None;
    }
    let uid = std::str::from_utf8(&uid).ok()?;
    Some(pod_flags::generation_for_uid(Some(uid)))
}

// ---- Attribution ----------------------------------------------------------

/// What the watcher knows about the pod a pending cgroup belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodState<P> {
    /// Not a pod the watcher tracks (yet, or at all).
    Unknown,
    /// Seen by the watcher, not registered yet (not Ready).
    Known,
    /// Registered. `claims` is whether the cgroup's container id is one
    /// of the pod's own containers (false for the sandbox, and briefly
    /// for an app container the status has not caught up with).
    Registered { pod: P, claims: bool },
}

#[derive(Debug)]
struct Entry {
    /// `None` until the cgroup's mkdir event has arrived. The pending
    /// syscall events travel on a different ring buffer, so they can be
    /// read first.
    identity: Option<CgroupIdentity>,
    first_seen: Instant,
    /// Whether the pod was ever seen by the watcher; extends the TTL.
    known: bool,
    attributed_at: Option<Instant>,
    /// First pass at which the pod was registered but did not claim this
    /// container.
    unclaimed_since: Option<Instant>,
    buffered: BTreeSet<u32>,
}

impl Entry {
    fn new(identity: Option<CgroupIdentity>, now: Instant) -> Self {
        Self {
            identity,
            first_seen: now,
            known: false,
            attributed_at: None,
            unclaimed_since: None,
            buffered: BTreeSet::new(),
        }
    }
}

/// Why a cgroup was retired, remembered for late events.
#[derive(Debug, Clone)]
enum Tombstone {
    /// Attributed: late events are attributed to the same identity.
    Attributed(CgroupIdentity),
    /// The pod sandbox: late events are discarded.
    Sandbox,
    /// Expired or not a container: late events are discarded.
    Unattributable,
}

/// What the watcher knows about `identity`'s pod, from the registered pods
/// by UID (`ContainerMap`, which is never pruned and may hold a dead pod's
/// entry) and the known-pods registry (which the watcher prunes when a pod
/// terminates or leaves the node).
///
/// The known-pods registry is authoritative for "is this pod alive": a
/// pod the watcher has forgotten is `Unknown` even if a stale
/// `ContainerMap` entry still carries its UID. Treating that as
/// "registered, container not claimed" classified every container of a
/// finished Job as a sandbox (seen live as `sandboxes_discarded` exceeding
/// the unattributed cgroups).
pub fn resolve_pod_state<P: Clone>(
    identity: &CgroupIdentity,
    registered_by_uid: &HashMap<String, P>,
    known_containers: Option<&BTreeSet<String>>,
) -> PodState<P> {
    let Some(ids) = known_containers else {
        return PodState::Unknown;
    };
    match registered_by_uid.get(&identity.pod_uid) {
        Some(pod) => PodState::Registered {
            pod: pod.clone(),
            claims: identity
                .container_id
                .as_deref()
                .is_some_and(|cid| ids.contains(cid)),
        },
        None => PodState::Known,
    }
}

/// One cgroup's syscalls, ready to be merged into a pod's set.
#[derive(Debug, PartialEq, Eq)]
pub struct Flush<P> {
    pub cgroup_id: u64,
    pub pod: P,
    pub identity: CgroupIdentity,
    pub syscalls: BTreeSet<u32>,
}

/// The result of one attribution pass.
#[derive(Debug, PartialEq, Eq)]
pub struct Attribution<P> {
    pub flush: Vec<Flush<P>>,
    /// Cgroup ids whose kernel pending mark should be deleted.
    pub forget: Vec<u64>,
    /// Cgroups dropped unattributed this pass (expired).
    pub expired: usize,
}

/// Counters for the periodic summary log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PendingStats {
    pub cgroups_seen: u64,
    pub cgroups_attributed: u64,
    pub cgroups_expired: u64,
    pub sandboxes_discarded: u64,
    pub syscalls_attributed: u64,
    /// Syscall events that could never be attributed: their cgroup
    /// expired with them still buffered, or they arrived for a cgroup
    /// already retired as unattributable.
    pub syscalls_unattributable: u64,
    /// Late events (after retirement) that were still attributed.
    pub late_events_attributed: u64,
    pub events_dropped_full: u64,
}

/// The userspace half of startup capture. See the module docs.
#[derive(Debug)]
pub struct PendingCapture {
    entries: HashMap<u64, Entry>,
    tombstones: HashMap<u64, (Tombstone, Instant)>,
    config: StartupCaptureConfig,
    linger: Duration,
    sandbox_grace: Duration,
    tombstone_ttl: Duration,
    max: usize,
    pub stats: PendingStats,
}

impl Default for PendingCapture {
    fn default() -> Self {
        Self::new(StartupCaptureConfig::default())
    }
}

impl PendingCapture {
    pub fn new(config: StartupCaptureConfig) -> Self {
        Self {
            entries: HashMap::new(),
            tombstones: HashMap::new(),
            config,
            linger: ATTRIBUTED_LINGER,
            sandbox_grace: SANDBOX_GRACE,
            tombstone_ttl: TOMBSTONE_TTL,
            max: MAX_TRACKED_CGROUPS,
            stats: PendingStats::default(),
        }
    }

    /// Override the capacity (tests).
    pub fn with_max(mut self, max: usize) -> Self {
        self.max = max;
        self
    }

    /// Cgroups currently buffered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a new entry may be created. Existing entries always
    /// accept more data.
    fn has_room_for(&self, cgroup_id: u64) -> bool {
        self.entries.contains_key(&cgroup_id) || self.entries.len() < self.max
    }

    fn tombstone(&mut self, cgroup_id: u64, why: Tombstone, now: Instant) {
        if self.tombstones.len() >= self.max {
            let ttl = self.tombstone_ttl;
            self.tombstones
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < ttl);
        }
        if self.tombstones.len() < self.max {
            self.tombstones.insert(cgroup_id, (why, now));
        }
    }

    /// A cgroup was created under kubepods. Returns `Some(id)` when the
    /// kernel's pending mark should be deleted straight away because
    /// nothing in this cgroup can ever be attributed to a container: it
    /// is not a pod cgroup, or it is the pod-level cgroup (which holds no
    /// tasks under cgroup v2).
    pub fn cgroup_created(&mut self, cgroup_id: u64, path: &str, now: Instant) -> Option<u64> {
        let identity = match parse_kubepods_cgroup_path(path) {
            Some(id) if id.container_id.is_some() => id,
            _ => {
                if let Some(e) = self.entries.remove(&cgroup_id) {
                    self.stats.syscalls_unattributable += e.buffered.len() as u64;
                }
                self.tombstone(cgroup_id, Tombstone::Unattributable, now);
                return Some(cgroup_id);
            }
        };
        if !self.has_room_for(cgroup_id) {
            self.stats.events_dropped_full += 1;
            return Some(cgroup_id);
        }
        self.stats.cgroups_seen += 1;
        self.entries
            .entry(cgroup_id)
            .or_insert_with(|| Entry::new(None, now))
            .identity = Some(identity);
        None
    }

    /// A syscall from a pending cgroup (already deduplicated in-kernel
    /// per cgroup and syscall).
    pub fn pending_syscall(&mut self, cgroup_id: u64, syscall: u32, now: Instant) {
        if !self.entries.contains_key(&cgroup_id) {
            // In flight when its cgroup retired: the kernel mark goes a
            // poll after the forget is queued. Use what is known.
            match self.tombstones.get(&cgroup_id).map(|(t, _)| t.clone()) {
                Some(Tombstone::Attributed(identity)) => {
                    if !self.has_room_for(cgroup_id) {
                        self.stats.events_dropped_full += 1;
                        return;
                    }
                    self.stats.late_events_attributed += 1;
                    self.tombstones.remove(&cgroup_id);
                    let mut e = Entry::new(Some(identity), now);
                    // Already attributed once: flush at the next pass and
                    // retire again after a fresh linger (or at once, if the
                    // pod has gone since).
                    e.known = true;
                    e.attributed_at = Some(now);
                    self.entries.insert(cgroup_id, e);
                }
                Some(Tombstone::Sandbox) | Some(Tombstone::Unattributable) => {
                    self.stats.syscalls_unattributable += 1;
                    return;
                }
                None => {}
            }
        }
        if !self.has_room_for(cgroup_id) {
            self.stats.events_dropped_full += 1;
            return;
        }
        self.entries
            .entry(cgroup_id)
            .or_insert_with(|| Entry::new(None, now))
            .buffered
            .insert(syscall);
    }

    /// Attribute what can be attributed, retire what is finished or
    /// expired. `resolve` says what the watcher knows about the cgroup's
    /// pod and container.
    pub fn attribute<P, F>(&mut self, now: Instant, mut resolve: F) -> Attribution<P>
    where
        F: FnMut(&CgroupIdentity) -> PodState<P>,
    {
        let mut out = Attribution {
            flush: Vec::new(),
            forget: Vec::new(),
            expired: 0,
        };
        let mut retire: Vec<(u64, Tombstone)> = Vec::new();
        let tombstone_ttl = self.tombstone_ttl;
        self.tombstones
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < tombstone_ttl);

        for (&cgroup_id, entry) in self.entries.iter_mut() {
            let state = match entry.identity.as_ref() {
                Some(identity) => resolve(identity),
                None => PodState::Unknown,
            };
            match state {
                PodState::Registered { pod, claims: true } => {
                    let identity = entry.identity.clone().expect("resolved from an identity");
                    if entry.attributed_at.is_none() {
                        self.stats.cgroups_attributed += 1;
                    }
                    let attributed_at = *entry.attributed_at.get_or_insert(now);
                    if !entry.buffered.is_empty() {
                        let syscalls = std::mem::take(&mut entry.buffered);
                        self.stats.syscalls_attributed += syscalls.len() as u64;
                        out.flush.push(Flush {
                            cgroup_id,
                            pod,
                            identity: identity.clone(),
                            syscalls,
                        });
                    }
                    if now.saturating_duration_since(attributed_at) >= self.linger {
                        retire.push((cgroup_id, Tombstone::Attributed(identity)));
                    }
                }
                PodState::Registered { claims: false, .. } => {
                    entry.known = true;
                    let since = *entry.unclaimed_since.get_or_insert(now);
                    if now.saturating_duration_since(since) >= self.sandbox_grace {
                        self.stats.sandboxes_discarded += 1;
                        retire.push((cgroup_id, Tombstone::Sandbox));
                    }
                }
                PodState::Known | PodState::Unknown => {
                    if matches!(state, PodState::Known) {
                        entry.known = true;
                    }
                    if entry.attributed_at.is_some() {
                        // Found once, gone from the map since (deleted).
                        // Nothing more will resolve; stop capturing.
                        let identity = entry.identity.clone().expect("attributed");
                        retire.push((cgroup_id, Tombstone::Attributed(identity)));
                        continue;
                    }
                    let ttl = if entry.known {
                        self.config.known_pod_ttl
                    } else {
                        self.config.pending_ttl
                    };
                    if now.saturating_duration_since(entry.first_seen) >= ttl {
                        out.expired += 1;
                        self.stats.cgroups_expired += 1;
                        retire.push((cgroup_id, Tombstone::Unattributable));
                    }
                }
            }
        }
        for (id, why) in retire {
            if let Some(e) = self.entries.remove(&id) {
                // A sandbox's syscalls are discarded on purpose; anything
                // else still buffered at retirement is a real loss.
                if !matches!(why, Tombstone::Sandbox) {
                    self.stats.syscalls_unattributable += e.buffered.len() as u64;
                }
            }
            self.tombstone(id, why, now);
            out.forget.push(id);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_tiers::CaptureLevel;

    const UID: &str = "3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab";
    const UID_US: &str = "3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab";
    const CID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn ident(cid: Option<&str>) -> Option<CgroupIdentity> {
        Some(CgroupIdentity {
            pod_uid: UID.to_string(),
            container_id: cid.map(str::to_string),
        })
    }

    // ---- parse_kubepods_cgroup_path -------------------------------------

    #[test]
    fn parses_systemd_driver_container_scope() {
        for qos in ["burstable", "besteffort"] {
            let p = format!(
                "/kubepods.slice/kubepods-{qos}.slice/kubepods-{qos}-pod{UID_US}.slice/cri-containerd-{CID}.scope"
            );
            assert_eq!(parse_kubepods_cgroup_path(&p), ident(Some(CID)), "{p}");
        }
    }

    #[test]
    fn parses_systemd_driver_guaranteed_pod_without_qos_segment() {
        let p = format!("/kubepods.slice/kubepods-pod{UID_US}.slice/cri-containerd-{CID}.scope");
        assert_eq!(parse_kubepods_cgroup_path(&p), ident(Some(CID)));
    }

    #[test]
    fn parses_cgroupfs_driver_paths() {
        let burstable = format!("/kubepods/burstable/pod{UID}/{CID}");
        let guaranteed = format!("/kubepods/pod{UID}/{CID}");
        assert_eq!(parse_kubepods_cgroup_path(&burstable), ident(Some(CID)));
        assert_eq!(parse_kubepods_cgroup_path(&guaranteed), ident(Some(CID)));
    }

    #[test]
    fn parses_kind_nested_kubelet_slice() {
        let p = format!(
            "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod{UID_US}.slice/cri-containerd-{CID}.scope"
        );
        assert_eq!(parse_kubepods_cgroup_path(&p), ident(Some(CID)));
    }

    #[test]
    fn other_runtime_prefixes_still_yield_the_id() {
        let p = format!("/kubepods.slice/kubepods-pod{UID_US}.slice/crio-{CID}.scope");
        assert_eq!(parse_kubepods_cgroup_path(&p), ident(Some(CID)));
    }

    #[test]
    fn pod_level_cgroup_has_no_container() {
        let systemd = format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_US}.slice"
        );
        let cgroupfs = format!("/kubepods/burstable/pod{UID}");
        assert_eq!(parse_kubepods_cgroup_path(&systemd), ident(None));
        assert_eq!(parse_kubepods_cgroup_path(&cgroupfs), ident(None));
    }

    #[test]
    fn a_cgroup_nested_inside_a_container_resolves_to_that_container() {
        let p = format!("/kubepods/burstable/pod{UID}/{CID}/init.scope");
        assert_eq!(parse_kubepods_cgroup_path(&p), ident(Some(CID)));
    }

    #[test]
    fn static_pod_config_hash_uid_is_accepted() {
        let hash = "8d5b2c7f1a3e4b6c9d0e1f2a3b4c5d6e";
        let p = format!("/kubepods/burstable/pod{hash}/{CID}");
        assert_eq!(
            parse_kubepods_cgroup_path(&p),
            Some(CgroupIdentity {
                pod_uid: hash.to_string(),
                container_id: Some(CID.to_string())
            })
        );
    }

    #[test]
    fn non_pod_cgroups_are_rejected() {
        for p in [
            "/kubepods.slice",
            "/kubepods.slice/kubepods-burstable.slice",
            "/kubepods/burstable",
            "/system.slice/containerd.service",
            "/user.slice/user-1000.slice/session-3.scope",
            "",
            "/",
            // A UID-shaped segment NOT under kubepods is not a pod.
            &format!("/system.slice/pod{UID}/{CID}"),
            // A malformed UID is not a pod.
            "/kubepods/burstable/podnot-a-uid/abc",
        ] {
            assert_eq!(parse_kubepods_cgroup_path(p), None, "{p}");
        }
    }

    #[test]
    fn junk_container_segments_are_not_container_ids() {
        let p = format!("/kubepods/burstable/pod{UID}/..");
        assert_eq!(parse_kubepods_cgroup_path(&p), ident(None));
    }

    #[test]
    fn cgroup_event_path_stops_at_nul() {
        let mut ev = CgroupEventData {
            cgroup_id: 7,
            level: 4,
            _pad: 0,
            path: [0u8; CGROUP_PATH_MAX],
        };
        let s = b"/kubepods/besteffort";
        ev.path[..s.len()].copy_from_slice(s);
        ev.path[s.len() + 1] = b'X'; // garbage after the NUL is ignored
        assert_eq!(ev.path_str(), "/kubepods/besteffort");
    }

    #[test]
    fn cgroup_event_layout_matches_the_kernel_struct() {
        // struct cgroup_event_t: u64 + u32 + u32 + char[256].
        assert_eq!(std::mem::size_of::<CgroupEventData>(), 8 + 4 + 4 + 256);
    }

    // ---- PendingCapture --------------------------------------------------

    fn container_path() -> String {
        format!("/kubepods/burstable/pod{UID}/{CID}")
    }

    const SANDBOX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    fn sandbox_path() -> String {
        format!("/kubepods/burstable/pod{UID}/{SANDBOX}")
    }

    /// The pod is registered and its status names CID (not the sandbox).
    fn registered(id: &CgroupIdentity) -> PodState<&'static str> {
        if id.pod_uid != UID {
            return PodState::Unknown;
        }
        PodState::Registered {
            pod: "ns/pod",
            claims: id.container_id.as_deref() == Some(CID),
        }
    }

    fn unknown(_: &CgroupIdentity) -> PodState<&'static str> {
        PodState::Unknown
    }

    fn known(_: &CgroupIdentity) -> PodState<&'static str> {
        PodState::Known
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn cfg(pending: u64, known: u64) -> StartupCaptureConfig {
        StartupCaptureConfig {
            pending_ttl: secs(pending),
            known_pod_ttl: secs(known),
        }
    }

    #[test]
    fn syscalls_buffered_before_registration_are_attributed_once_the_pod_appears() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        assert_eq!(pc.cgroup_created(42, &container_path(), t0), None);
        for nr in [59, 157, 165, 155] {
            pc.pending_syscall(42, nr, t0);
        }

        // Pod not registered yet: nothing flushes, nothing is forgotten.
        let a = pc.attribute(t0 + secs(1), known);
        assert!(a.flush.is_empty() && a.forget.is_empty());

        // Registered: everything buffered flushes to it, once.
        let a = pc.attribute(t0 + secs(2), registered);
        assert_eq!(a.flush.len(), 1);
        assert_eq!(a.flush[0].pod, "ns/pod");
        assert_eq!(a.flush[0].cgroup_id, 42);
        assert_eq!(a.flush[0].identity, ident(Some(CID)).unwrap());
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59, 155, 157, 165]));
        assert!(a.forget.is_empty(), "lingers after the first flush");

        let a = pc.attribute(t0 + secs(3), registered);
        assert!(a.flush.is_empty(), "nothing new, nothing re-sent");
    }

    #[test]
    fn syscall_events_that_beat_the_mkdir_event_are_kept() {
        // The two travel on different ring buffers; order is not given.
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.pending_syscall(42, 59, t0);
        pc.pending_syscall(42, 272, t0);
        assert_eq!(pc.cgroup_created(42, &container_path(), t0), None);
        let a = pc.attribute(t0, registered);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59, 272]));
    }

    #[test]
    fn late_syscalls_during_linger_flush_then_the_mark_is_forgotten() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.cgroup_created(42, &container_path(), t0);
        pc.pending_syscall(42, 59, t0);
        pc.attribute(t0, registered);

        pc.pending_syscall(42, 308, t0 + secs(5)); // setns, late
        let a = pc.attribute(t0 + secs(10), registered);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([308]));
        assert!(a.forget.is_empty());

        let a = pc.attribute(t0 + ATTRIBUTED_LINGER, registered);
        assert_eq!(a.forget, vec![42]);
        assert!(pc.is_empty());
    }

    /// Reviewer finding: an event already in flight when its cgroup
    /// retired (the kernel mark is deleted a poll later) used to start an
    /// anonymous entry that was never attributed and silently expired.
    #[test]
    fn events_arriving_after_retirement_are_still_attributed() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.cgroup_created(42, &container_path(), t0);
        pc.pending_syscall(42, 59, t0);
        pc.attribute(t0, registered);
        let a = pc.attribute(t0 + ATTRIBUTED_LINGER, registered);
        assert_eq!(a.forget, vec![42]);

        // In flight: arrives after the retirement.
        pc.pending_syscall(42, 231, t0 + ATTRIBUTED_LINGER + secs(1));
        let a = pc.attribute(t0 + ATTRIBUTED_LINGER + secs(2), registered);
        assert_eq!(a.flush.len(), 1, "attributed, not orphaned");
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([231]));
        assert_eq!(pc.stats.late_events_attributed, 1);
        assert_eq!(pc.stats.syscalls_unattributable, 0);

        // And it retires again (a second forget, harmless in the kernel).
        let a = pc.attribute(t0 + ATTRIBUTED_LINGER * 2 + secs(2), registered);
        assert_eq!(a.forget, vec![42]);
    }

    #[test]
    fn late_events_for_a_pod_deleted_since_retire_at_once() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.cgroup_created(42, &container_path(), t0);
        pc.attribute(t0, registered);
        pc.attribute(t0 + ATTRIBUTED_LINGER, registered);
        pc.pending_syscall(42, 231, t0 + ATTRIBUTED_LINGER + secs(1));
        let a = pc.attribute(t0 + ATTRIBUTED_LINGER + secs(2), unknown);
        assert_eq!(a.forget, vec![42], "no hour-long wait for a gone pod");
        assert_eq!(pc.stats.syscalls_unattributable, 1);
    }

    #[test]
    fn late_events_after_the_tombstone_expires_are_unattributable_after_ttl() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(cfg(60, 60));
        pc.cgroup_created(42, &container_path(), t0);
        pc.attribute(t0, registered);
        pc.attribute(t0 + ATTRIBUTED_LINGER, registered);
        let later = t0 + ATTRIBUTED_LINGER + TOMBSTONE_TTL;
        pc.attribute(later, registered); // prunes the tombstone
        pc.pending_syscall(42, 1, later);
        let a = pc.attribute(later + secs(60), registered);
        assert_eq!(a.forget, vec![42]);
        assert_eq!(pc.stats.syscalls_unattributable, 1);
    }

    #[test]
    fn a_pod_that_never_registers_expires_and_is_forgotten() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(cfg(60, 3600));
        pc.cgroup_created(42, &container_path(), t0);
        pc.pending_syscall(42, 59, t0);

        let a = pc.attribute(t0 + secs(59), unknown);
        assert!(a.forget.is_empty());
        let a = pc.attribute(t0 + secs(60), unknown);
        assert_eq!(a.forget, vec![42]);
        assert_eq!(a.expired, 1);
        assert!(a.flush.is_empty(), "never attributed to anyone");
        assert_eq!(pc.stats.cgroups_expired, 1);
        assert_eq!(pc.stats.syscalls_unattributable, 1);

        // A late event for it is counted, not buffered again.
        pc.pending_syscall(42, 60, t0 + secs(61));
        assert!(pc.is_empty());
        assert_eq!(pc.stats.syscalls_unattributable, 2);
    }

    /// Reviewer finding: an init container that runs past the base TTL
    /// lost the startup syscalls of the containers after it. A pod the
    /// watcher knows gets the long TTL.
    #[test]
    fn a_known_but_unregistered_pod_gets_the_long_ttl() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(cfg(600, 3600));
        pc.cgroup_created(42, &container_path(), t0);
        pc.pending_syscall(42, 59, t0);

        let a = pc.attribute(t0 + secs(601), known);
        assert!(a.forget.is_empty(), "known pod: still waiting at 10 min");
        let a = pc.attribute(t0 + secs(1800), registered);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59]));

        let mut pc = PendingCapture::new(cfg(600, 3600));
        pc.cgroup_created(7, &container_path(), t0);
        pc.attribute(t0 + secs(1), known);
        let a = pc.attribute(t0 + secs(3600), known);
        assert_eq!(a.forget, vec![7], "bounded even for a known pod");
    }

    #[test]
    fn syscalls_without_a_mkdir_event_expire_rather_than_guess() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(cfg(60, 3600));
        pc.pending_syscall(99, 59, t0);
        let a = pc.attribute(t0 + secs(1), registered);
        assert!(a.flush.is_empty(), "no identity, no attribution");
        let a = pc.attribute(t0 + secs(60), registered);
        assert_eq!(a.forget, vec![99]);
        assert_eq!(pc.stats.syscalls_unattributable, 1);
    }

    #[test]
    fn non_container_cgroups_are_forgotten_immediately() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        let pod_level = format!("/kubepods/burstable/pod{UID}");
        assert_eq!(pc.cgroup_created(1, &pod_level, t0), Some(1));
        assert_eq!(pc.cgroup_created(2, "/kubepods/burstable", t0), Some(2));
        assert!(pc.is_empty());
    }

    #[test]
    fn a_pod_deleted_after_attribution_retires_its_cgroup() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.cgroup_created(42, &container_path(), t0);
        pc.attribute(t0, registered);
        let a = pc.attribute(t0 + secs(1), unknown);
        assert_eq!(a.forget, vec![42]);
        assert_eq!(a.expired, 0);
    }

    /// Coordinator item 2: the pod sandbox has its own cgroup and its own
    /// seccomp; its syscalls must not join the app containers' set. Its
    /// id never appears in pod status, so a registered pod never claims
    /// it, and after the grace period it is discarded, with late events.
    #[test]
    fn the_sandbox_is_never_merged_into_the_pods_set() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.cgroup_created(1, &sandbox_path(), t0);
        pc.cgroup_created(2, &container_path(), t0);
        pc.pending_syscall(1, 34, t0); // pause()
        pc.pending_syscall(2, 59, t0);

        let a = pc.attribute(t0 + secs(1), registered);
        assert_eq!(a.flush.len(), 1);
        assert_eq!(a.flush[0].cgroup_id, 2);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59]));

        let a = pc.attribute(t0 + secs(1) + SANDBOX_GRACE, registered);
        assert!(a.flush.iter().all(|f| f.cgroup_id != 1));
        assert!(a.forget.contains(&1), "sandbox mark retired");
        assert_eq!(pc.stats.sandboxes_discarded, 1);
        assert_eq!(pc.stats.syscalls_unattributable, 0, "discarded on purpose");

        pc.pending_syscall(1, 35, t0 + secs(62)); // late, from the sandbox
        let a = pc.attribute(t0 + secs(63), registered);
        assert!(a.flush.iter().all(|f| f.cgroup_id != 1));
    }

    #[test]
    fn an_app_container_the_status_catches_up_with_is_not_mistaken_for_the_sandbox() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        pc.cgroup_created(2, &container_path(), t0);
        pc.pending_syscall(2, 59, t0);
        // Registered, but the status does not name the container yet.
        let lagging = |_: &CgroupIdentity| PodState::Registered {
            pod: "ns/pod",
            claims: false,
        };
        let a = pc.attribute(t0 + secs(1), lagging);
        assert!(a.flush.is_empty() && a.forget.is_empty());
        let a = pc.attribute(t0 + secs(5), registered);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59]));
    }

    #[test]
    fn capacity_is_bounded_and_overflow_is_counted() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default().with_max(2);
        pc.pending_syscall(1, 1, t0);
        pc.pending_syscall(2, 1, t0);
        pc.pending_syscall(3, 1, t0);
        assert_eq!(pc.len(), 2);
        // Existing entries keep accepting data at capacity.
        pc.pending_syscall(1, 2, t0);
        assert_eq!(pc.stats.events_dropped_full, 1);
        // A mkdir at capacity asks the kernel to stop capturing it.
        assert_eq!(pc.cgroup_created(4, &container_path(), t0), Some(4));
    }

    #[test]
    fn config_reads_env_values_and_keeps_known_ttl_at_least_the_base() {
        let d = StartupCaptureConfig::from_values(None, None);
        assert_eq!(d, StartupCaptureConfig::default());
        let c = StartupCaptureConfig::from_values(Some("120"), Some("7200"));
        assert_eq!(c.pending_ttl, secs(120));
        assert_eq!(c.known_pod_ttl, secs(7200));
        let c = StartupCaptureConfig::from_values(Some("9000"), Some("60"));
        assert_eq!(c.known_pod_ttl, secs(9000));
        let c = StartupCaptureConfig::from_values(Some("junk"), Some("0"));
        assert_eq!(c, StartupCaptureConfig::default());
    }

    // ---- known pods / container ids ----------------------------------------

    #[test]
    fn pod_container_ids_cover_every_status_list_and_last_state() {
        use k8s_openapi::api::core::v1::{
            ContainerState, ContainerStateTerminated, ContainerStatus, Pod, PodStatus,
        };
        let cs = |id: &str, last: Option<&str>| ContainerStatus {
            container_id: Some(format!("containerd://{id}")),
            last_state: last.map(|l| ContainerState {
                terminated: Some(ContainerStateTerminated {
                    container_id: Some(format!("containerd://{l}")),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pod = Pod {
            status: Some(PodStatus {
                container_statuses: Some(vec![cs("app2", Some("app1"))]),
                init_container_statuses: Some(vec![cs("init", None)]),
                ephemeral_container_statuses: Some(vec![cs("debug", None)]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            pod_container_ids(&pod),
            BTreeSet::from(["app1", "app2", "debug", "init"].map(String::from))
        );
    }

    #[test]
    fn known_pods_registry_round_trips() {
        use k8s_openapi::api::core::v1::{ContainerStatus, Pod, PodStatus};
        let uid = "11111111-2222-3333-4444-555555555555";
        let mut pod = Pod {
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    container_id: Some("containerd://abc".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        pod.metadata.uid = Some(uid.into());
        let t_before = Instant::now();
        note_known_pod(&pod);
        assert_eq!(
            known_pod_containers(uid),
            Some(BTreeSet::from(["abc".to_string()]))
        );
        let after_note = Instant::now();
        retain_known_pods(&std::collections::HashSet::new(), t_before);
        assert!(
            known_pod_containers(uid).is_some(),
            "noted after the LIST was taken: kept"
        );
        retain_known_pods(
            &std::collections::HashSet::from([uid.to_string()]),
            after_note,
        );
        assert!(known_pod_containers(uid).is_some(), "in the LIST: kept");
        retain_known_pods(&std::collections::HashSet::new(), after_note);
        assert_eq!(
            known_pod_containers(uid),
            None,
            "absent from a later LIST: dropped"
        );
        note_known_pod(&pod);
        forget_known_pod(uid);
        assert_eq!(known_pod_containers(uid), None);
    }

    // ---- registered-path ownership (bpf/pod_cgroup.h) ------------------------

    const OWNER_NAMES: &[&str] = &[
        // pod-level cgroups
        "pod3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab",
        "kubepods-burstable-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice",
        "kubepods-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice",
        "kubelet-kubepods-besteffort-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice",
        "pod8d5b2c7f1a3e4b6c9d0e1f2a3b4c5d6e", // static pod config hash
        // not pod cgroups
        "kubepods",
        "kubepods.slice",
        "kubepods-besteffort.slice",
        "besteffort",
        "cri-containerd-0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0.scope",
        "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "podruntime",
        "runtime",
        "containerd.service",
        "system.slice",
        "init.scope",
        "",
        // malformed
        "podnot-a-uid",
        "pod3F2A9C1E-7B4D-4E0A-9F1C-0123456789AB",
        "pod3f2a9c1e-7b4d-4e0a-9f1c-0123456789abX",
        "pod3f2a9c1e7b4d-4e0a-9f1c-0123456789ab-",
        "xpod3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab",
    ];

    #[test]
    fn pod_generation_from_cgroup_name_matches_generation_for_uid() {
        let g = pod_flags::generation_for_uid(Some(UID));
        assert_eq!(
            pod_generation_from_cgroup_name(&format!("pod{UID}")),
            Some(g)
        );
        assert_eq!(
            pod_generation_from_cgroup_name(&format!("kubepods-burstable-pod{UID_US}.slice")),
            Some(g)
        );
        for n in &OWNER_NAMES[5..] {
            assert_eq!(pod_generation_from_cgroup_name(n), None, "{n:?}");
        }
    }

    /// The probe's parser is C; this compiles bpf/pod_cgroup.h with the
    /// host compiler and checks it agrees with the Rust mirror (and so
    /// with pod_flags::generation_for_uid) on every name above. Needs a C
    /// compiler, which building the eBPF objects already requires.
    #[test]
    fn the_c_pod_cgroup_parser_matches_the_rust_one() {
        let dir = std::env::temp_dir().join(format!("kg-podcg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let header = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/pod_cgroup.h");
        let src = dir.join("harness.c");
        std::fs::write(
            &src,
            format!(
                r#"typedef unsigned int __u32;
#define __always_inline inline __attribute__((always_inline))
#include "{header}"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {{
    for (int i = 1; i < argc; i++) {{
        char buf[KG_CG_NAME_BUF];
        memset(buf, 0, sizeof buf);
        strncpy(buf, argv[i], sizeof buf - 1);
        printf("%u\n", kg_pod_gen_from_name(buf));
    }}
    return 0;
}}
"#
            ),
        )
        .unwrap();
        let bin = dir.join("harness");
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        let status = std::process::Command::new(&cc)
            .args(["-O2", "-std=c99", "-o"])
            .arg(&bin)
            .arg(&src)
            .status()
            .expect("a host C compiler");
        assert!(status.success(), "compiling pod_cgroup.h failed");
        let out = std::process::Command::new(&bin)
            .args(OWNER_NAMES)
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let c: Vec<u32> = text.lines().map(|l| l.parse().unwrap()).collect();
        assert_eq!(c.len(), OWNER_NAMES.len());
        for (name, v) in OWNER_NAMES.iter().zip(c) {
            let c_gen = (v != 0).then_some(v & 0x0fff_ffff);
            assert!(v == 0 || v & (1 << 31) != 0, "{name:?}: pod bit");
            assert_eq!(c_gen, pod_generation_from_cgroup_name(name), "{name:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Model of the probe's registered-path decision (credit_generation in
    /// syscall.bpf.c), driven by the parser above, for the three cases the
    /// live defect turned on.
    fn credit(
        netns_gen: u32,
        cgroup_names: &[&str],
        alias: &HashMap<u32, u32>,
        hostnet: &[u32],
    ) -> Option<u32> {
        let owner = cgroup_names
            .iter()
            .take(4)
            .find_map(|n| pod_generation_from_cgroup_name(n))?;
        if owner == netns_gen {
            return Some(owner);
        }
        let gen = alias.get(&owner).copied().unwrap_or(owner);
        (gen == netns_gen || hostnet.contains(&gen)).then_some(gen)
    }

    #[test]
    fn host_processes_in_a_pod_netns_are_not_credited_to_the_pod() {
        let g = pod_flags::generation_for_uid(Some(UID));
        let none = HashMap::new();
        // containerd pinning / unmounting the netns, a CNI plugin: their
        // cgroups name no pod (leaf first, then ancestors).
        for chain in [
            &["containerd.service", "system.slice"][..],
            &["runtime", "podruntime"][..],
            &["kubelet.service", "system.slice"][..],
        ] {
            assert_eq!(credit(g, chain, &none, &[]), None, "{chain:?}");
        }
    }

    #[test]
    fn the_pods_own_tasks_are_credited() {
        let g = pod_flags::generation_for_uid(Some(UID));
        let none = HashMap::new();
        let leaf = format!("cri-containerd-{CID}.scope");
        let pod = format!("kubepods-besteffort-pod{UID_US}.slice");
        let chain = [
            leaf.as_str(),
            pod.as_str(),
            "kubepods-besteffort.slice",
            "kubepods.slice",
        ];
        assert_eq!(credit(g, &chain, &none, &[]), Some(g));
        // cgroupfs, and a sub-cgroup the container manages itself.
        let pod = format!("pod{UID}");
        let chain = ["init.scope", CID, pod.as_str(), "besteffort"];
        assert_eq!(credit(g, &chain, &none, &[]), Some(g));
    }

    #[test]
    fn another_pods_task_on_a_recycled_inode_is_not_credited() {
        // inode_num still names the DEAD pod; the task is a new pod's.
        let dead = pod_flags::generation_for_uid(Some("aaaaaaaa-0000-4000-8000-000000000001"));
        let new_uid = "bbbbbbbb-0000-4000-8000-000000000002";
        let pod = format!("pod{new_uid}");
        let chain = [CID, pod.as_str(), "burstable", "kubepods"];
        assert_eq!(credit(dead, &chain, &HashMap::new(), &[]), None);
    }

    #[test]
    fn host_network_and_static_pods_are_credited_to_themselves() {
        let holder = pod_flags::generation_for_uid(Some("cccccccc-0000-4000-8000-000000000003"));
        let g = pod_flags::generation_for_uid(Some(UID));
        let pod = format!("pod{UID}");
        let chain = [CID, pod.as_str()];
        // Another hostNetwork pod holds the node netns entry.
        assert_eq!(credit(holder, &chain, &HashMap::new(), &[g]), Some(g));
        // Static pod: cgroup carries the config hash, registration the
        // mirror UID.
        let hash = "8d5b2c7f1a3e4b6c9d0e1f2a3b4c5d6e";
        let mirror = pod_flags::generation_for_uid(Some(UID));
        let alias = HashMap::from([(pod_flags::generation_for_uid(Some(hash)), mirror)]);
        let pod = format!("pod{hash}");
        let chain = [CID, pod.as_str()];
        assert_eq!(credit(mirror, &chain, &alias, &[]), Some(mirror));
    }

    #[test]
    fn the_probe_checks_cgroup_ownership_before_crediting_a_registered_syscall() {
        let src = include_str!("bpf/syscall.bpf.c");
        let handler = &src[src
            .find("SEC(\"tracepoint/raw_syscalls/sys_enter\")")
            .unwrap()..];
        let netns = handler
            .find("bpf_map_lookup_elem(&inode_num, &net_ns)")
            .unwrap();
        let owner = handler
            .find("credit_generation(KG_GEN_OF(*flags))")
            .unwrap();
        let dedup = handler.find("bpf_map_update_elem(&seen_syscalls").unwrap();
        assert!(netns < owner && owner < dedup);
        assert!(
            handler.contains(".generation = gen,"),
            "dedup keyed by the credited pod"
        );
    }

    // ---- runtime pre-filter list -------------------------------------------

    /// Coordinator item 2: runc's pre-filter setup syscalls are skipped
    /// for `runc:[` tasks. Pin that the list resolves on the supported
    /// arches and that nothing runc makes UNDER the filter is in it.
    #[test]
    fn runtime_prefilter_list_resolves_and_excludes_post_filter_syscalls() {
        use crate::capture_tiers::resolve_names;
        use libseccomp::ScmpArch;
        for arch in [ScmpArch::X8664, ScmpArch::Aarch64] {
            let (nrs, unknown) = resolve_names(RUNTIME_PREFILTER_SYSCALLS.iter().copied(), arch);
            // mknod/symlink have no arm64 syscall (only the *at forms).
            assert!(
                unknown.iter().all(|u| u == "mknod" || u == "symlink"),
                "{arch:?}: unresolved {unknown:?}"
            );
            assert!(nrs.len() >= RUNTIME_PREFILTER_SYSCALLS.len() - 2);
        }
        for under_filter in [
            "execve",
            "execveat",
            "capset",
            "prctl",
            "setgroups",
            "setresuid",
            "setresgid",
            "close",
            "close_range",
            "chdir",
            "openat",
            "write",
            "futex",
            "fcntl",
        ] {
            assert!(
                !RUNTIME_PREFILTER_SYSCALLS.contains(&under_filter),
                "{under_filter} runs under the container's seccomp filter and must be recorded"
            );
        }
    }

    /// The probe gates the skip on the comm prefix and applies it on both
    /// capture paths; pinned at source level since eBPF cannot be loaded
    /// in the unit tests.
    #[test]
    fn the_probe_skips_prefilter_syscalls_only_for_runc_tasks_on_both_paths() {
        let src = include_str!("bpf/syscall.bpf.c");
        assert!(
            src.contains("comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c'")
        );
        assert_eq!(
            src.matches("if (runtime_prefilter_skip(syscall_id))")
                .count(),
            2,
            "pending and registered paths"
        );
    }

    /// build.rs compiles the syscall object with -mcpu=v2 so the gate's
    /// __sync_fetch_and_add is the legacy XADD every supported kernel
    /// accepts. A toolchain that loses the flag fails here.
    #[test]
    fn embedded_syscall_object_uses_legacy_xadd_atomics() {
        let obj: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/syscall.bpf.o"));
        let (atomics, fetch) = crate::contention::tests::scan_bpf_atomics(obj);
        assert!(
            atomics > 0,
            "expected the pending_gate increment in the object"
        );
        assert_eq!(
            fetch, 0,
            "{fetch} BPF_ATOMIC|BPF_FETCH instruction(s) found; build.rs must pass -mcpu=v2"
        );
    }

    #[test]
    fn the_pending_path_is_gated_before_any_lookup() {
        let src = include_str!("bpf/syscall.bpf.c");
        let body = &src[src
            .find("static __always_inline bool capture_pending")
            .unwrap()..];
        let gate = body.find("*created == *retired").expect("gate present");
        let lookup = body.find("bpf_get_current_cgroup_id").unwrap();
        assert!(gate < lookup, "the gate must come before the cgroup lookup");
    }

    // ---- event-sequence harness (cluster-00 defects A and B) ---------------
    //
    // Drives PendingCapture through the same resolver the controller uses
    // (resolve_pod_state), with a registered-pods table that keeps stale
    // entries the way ContainerMap does and a known-pods table the watcher
    // prunes. The kernel routing half (pending before netns) is pinned by
    // the_probe_consults_pending_cgroups_before_the_netns_map.

    struct Node {
        pending: PendingCapture,
        /// uid -> pod label; never pruned (like ContainerMap).
        registered: HashMap<String, &'static str>,
        /// uid -> container ids; pruned on termination (like KNOWN_PODS).
        known: HashMap<String, BTreeSet<String>>,
        /// What each pod label accumulated.
        sets: HashMap<&'static str, BTreeSet<u32>>,
    }

    impl Node {
        fn new() -> Self {
            Self {
                pending: PendingCapture::default(),
                registered: HashMap::new(),
                known: HashMap::new(),
                sets: HashMap::new(),
            }
        }
        fn path(uid: &str, cid: &str) -> String {
            format!("/kubepods/besteffort/pod{uid}/{cid}")
        }
        fn start(&mut self, cgroup: u64, uid: &str, cid: &str, t: Instant) {
            self.pending
                .cgroup_created(cgroup, &Self::path(uid, cid), t);
            self.known.entry(uid.to_string()).or_default();
        }
        fn status_names(&mut self, uid: &str, cid: &str) {
            self.known
                .entry(uid.to_string())
                .or_default()
                .insert(cid.to_string());
        }
        fn register(&mut self, uid: &str, label: &'static str) {
            self.registered.insert(uid.to_string(), label);
        }
        /// Pod completes: the watcher keeps it known with its final
        /// container ids until the object is deleted.
        fn terminate(&mut self, _uid: &str) {}
        /// Pod object deleted: gone from the known registry at the next
        /// resync; ContainerMap keeps its entry.
        fn delete(&mut self, uid: &str) {
            self.known.remove(uid);
        }
        fn tick(&mut self, t: Instant) {
            let registered = self.registered.clone();
            let known = self.known.clone();
            let a = self.pending.attribute(t, |id| {
                resolve_pod_state(id, &registered, known.get(&id.pod_uid))
            });
            for f in a.flush {
                self.sets.entry(f.pod).or_default().extend(f.syscalls);
            }
        }
    }

    const UID_CURL1: &str = "c0c0c0c0-0000-4000-8000-000000000001";
    const UID_CURL2: &str = "c0c0c0c0-0000-4000-8000-000000000002";
    const UID_NGINX: &str = "e0e0e0e0-0000-4000-8000-000000000003";
    const UID_NGINX2: &str = "e0e0e0e0-0000-4000-8000-000000000004";

    /// Defect B: a pod name reused (curlcheck deleted, a new curlcheck
    /// created) next to a live nginx pod. The second curlcheck's startup
    /// syscalls must land on the second curlcheck's UID and nowhere else;
    /// nothing here is keyed by name or netns inode.
    #[test]
    fn a_reused_pod_name_never_leaks_startup_syscalls_into_another_pod() {
        let t0 = Instant::now();
        let mut n = Node::new();
        let (fork, pipe, stat, membarrier, exit) = (57, 22, 4, 324, 60);

        // First curlcheck runs, is attributed, terminates.
        n.start(10, UID_CURL1, "cc1", t0);
        n.pending.pending_syscall(10, fork, t0);
        n.status_names(UID_CURL1, "cc1");
        n.register(UID_CURL1, "curlcheck#1");
        n.tick(t0 + secs(1));
        n.terminate(UID_CURL1);
        n.delete(UID_CURL1);

        // nginx starts (sandbox + app), registers.
        n.start(20, UID_NGINX, "sbx", t0 + secs(2));
        n.start(21, UID_NGINX, "ngx", t0 + secs(2));
        n.pending.pending_syscall(20, 34, t0 + secs(2));
        n.pending.pending_syscall(21, 232, t0 + secs(2)); // epoll_wait
        n.status_names(UID_NGINX, "ngx");
        n.register(UID_NGINX, "nginx");

        // Second curlcheck (same NAME, new UID) starts while nginx lives.
        n.start(30, UID_CURL2, "cc2", t0 + secs(3));
        for nr in [fork, pipe, stat, membarrier, exit] {
            n.pending.pending_syscall(30, nr, t0 + secs(3));
        }
        n.tick(t0 + secs(4)); // curlcheck#2 known, not registered yet
        n.status_names(UID_CURL2, "cc2");
        n.register(UID_CURL2, "curlcheck#2");
        n.terminate(UID_CURL2); // ...and it may even be gone by the tick
        n.tick(t0 + secs(5));

        assert_eq!(
            n.sets["nginx"],
            BTreeSet::from([232]),
            "nginx has only its own"
        );
        assert_eq!(
            n.sets["curlcheck#2"],
            BTreeSet::from([fork, pipe, stat, membarrier, exit]),
            "a pod that completed before the tick still gets its own startup set"
        );
        assert_eq!(n.sets["curlcheck#1"], BTreeSet::from([fork]));
        for (label, set) in &n.sets {
            if *label != "curlcheck#1" && *label != "curlcheck#2" {
                assert!(
                    set.is_disjoint(&BTreeSet::from([fork, pipe, stat, membarrier, exit])),
                    "{label} got curl's syscalls"
                );
            }
        }
    }

    /// Defect A, userspace half: a pod created after others died (so its
    /// netns inode is a dead pod's, still "registered" in the kernel map)
    /// is attributed by its cgroup's UID, and the dead pod — whose stale
    /// ContainerMap entry survives — resolves to nobody.
    #[test]
    fn a_pod_starting_on_a_dead_pods_netns_inode_is_attributed_to_itself() {
        let t0 = Instant::now();
        let mut n = Node::new();
        // Dead pod: registered once, terminated; stale entry remains.
        n.register(UID_NGINX, "nginx-old");
        n.status_names(UID_NGINX, "old");
        n.terminate(UID_NGINX);
        n.delete(UID_NGINX);

        // New pod, same image, same node, after the churn.
        n.start(40, UID_NGINX2, "sbx2", t0);
        n.start(41, UID_NGINX2, "new", t0);
        for nr in [59, 4, 257, 262, 302] {
            n.pending.pending_syscall(41, nr, t0);
        }
        n.tick(t0 + secs(1));
        n.status_names(UID_NGINX2, "new");
        n.register(UID_NGINX2, "nginx-new");
        n.tick(t0 + secs(2));

        assert_eq!(n.sets["nginx-new"], BTreeSet::from([4, 59, 257, 262, 302]));
        assert!(!n.sets.contains_key("nginx-old"));
    }

    /// Live evidence: sandboxes_discarded exceeded the cgroups that were
    /// never attributed, because a terminated (Job) pod's stale
    /// ContainerMap entry made its app containers look unclaimed.
    #[test]
    fn a_terminated_pods_containers_are_not_counted_as_sandboxes() {
        let t0 = Instant::now();
        let mut n = Node::new();
        n.start(50, UID_CURL1, "job", t0);
        n.pending.pending_syscall(50, 59, t0);
        n.status_names(UID_CURL1, "job");
        n.register(UID_CURL1, "job-pod");
        // Completes before the first attribution tick.
        n.terminate(UID_CURL1);
        n.tick(t0 + secs(1));
        assert_eq!(n.sets["job-pod"], BTreeSet::from([59]));
        n.tick(t0 + secs(1) + ATTRIBUTED_LINGER);
        n.delete(UID_CURL1);
        n.tick(t0 + secs(2) + ATTRIBUTED_LINGER + SANDBOX_GRACE);
        assert_eq!(n.pending.stats.sandboxes_discarded, 0);
        assert_eq!(n.pending.stats.cgroups_attributed, 1);
        assert!(n.pending.is_empty());

        // Attributed, then the pod object deleted inside the linger
        // window: retired as attributed, not as a sandbox.
        let mut n = Node::new();
        n.start(51, UID_CURL2, "job2", t0);
        n.pending.pending_syscall(51, 59, t0);
        n.status_names(UID_CURL2, "job2");
        n.register(UID_CURL2, "job-pod-2");
        n.tick(t0 + secs(1));
        n.delete(UID_CURL2);
        n.tick(t0 + secs(2));
        n.tick(t0 + secs(3) + SANDBOX_GRACE);
        assert_eq!(n.pending.stats.sandboxes_discarded, 0);
        assert!(
            n.pending.is_empty(),
            "retired as attributed once the pod is gone"
        );
    }

    #[test]
    fn resolve_pod_state_trusts_the_known_registry_over_stale_registrations() {
        let id = ident(Some(CID)).unwrap();
        let reg = HashMap::from([(UID.to_string(), "p")]);
        let claimed = BTreeSet::from([CID.to_string()]);
        let other = BTreeSet::from(["x".to_string()]);
        assert_eq!(resolve_pod_state(&id, &reg, None), PodState::Unknown);
        assert_eq!(
            resolve_pod_state(&id, &reg, Some(&claimed)),
            PodState::Registered {
                pod: "p",
                claims: true
            }
        );
        assert_eq!(
            resolve_pod_state(&id, &reg, Some(&other)),
            PodState::Registered {
                pod: "p",
                claims: false
            }
        );
        assert_eq!(
            resolve_pod_state(&id, &HashMap::<String, &str>::new(), Some(&claimed)),
            PodState::Known
        );
    }

    /// Defects A and B (cluster-00, 2026-09-26), kernel half. A new pod
    /// usually gets a dead pod's netns inode number, and inode_num still
    /// holds the dead pod's entry. When the probe consulted inode_num
    /// first, a new pod's startup took the registered path with the dead
    /// pod's generation: deduplicated against the dead pod's set, credited
    /// to the dead pod, and never seen by the pending path. The pending
    /// (cgroup) check must come first in the sys_enter handler.
    #[test]
    fn the_probe_consults_pending_cgroups_before_the_netns_map() {
        let src = include_str!("bpf/syscall.bpf.c");
        let handler = &src[src
            .find("SEC(\"tracepoint/raw_syscalls/sys_enter\")")
            .expect("sys_enter handler")..];
        let pending = handler
            .find("if (capture_pending(net_ns, syscall_id))")
            .expect("pending check in the handler");
        let netns = handler
            .find("bpf_map_lookup_elem(&inode_num, &net_ns)")
            .expect("netns lookup in the handler");
        assert!(
            pending < netns,
            "the pending-cgroup check must run before the inode_num lookup, or a pod \
             that reuses a dead pod's netns inode is captured as the dead pod"
        );
        // And a pending hit must end the handler, not fall through to the
        // registered path (which would count the syscall twice, once under
        // the dead pod).
        assert!(handler[pending..]
            .starts_with("if (capture_pending(net_ns, syscall_id))\n        return 0;"));
    }
    // ---- filter_for_tier --------------------------------------------------

    #[test]
    fn tier_filter_applies_the_pods_allowlist() {
        let tiers = ResolvedTiers {
            low: BTreeSet::from([59, 101]),
            ..Default::default()
        };
        let seen = BTreeSet::from([0, 59, 101, 157]);

        let low = pod_flags::pack(CaptureLevel::Low, 7);
        assert_eq!(filter_for_tier(low, &tiers, &seen), vec![59, 101]);

        let full = pod_flags::pack(CaptureLevel::Full, 7);
        assert_eq!(filter_for_tier(full, &tiers, &seen), vec![0, 59, 101, 157]);

        // An index userspace never emits is unfiltered, like the probe.
        let bogus = pod_flags::POD_TRACKED | (6 << pod_flags::TIER_SHIFT);
        assert_eq!(filter_for_tier(bogus, &tiers, &seen).len(), 4);
    }
}
