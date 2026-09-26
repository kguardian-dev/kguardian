//! Runtime inventory (#1533 P1-2): the binaries each container executes
//! and the files it maps executable (shared libraries, the dynamic
//! loader), per container, posted to the broker's `runtime_executables`.
//!
//! # Sources
//!
//! - **eBPF** (`bpf/runtime_inventory.bpf.c`): `sched_process_exec` for
//!   the file a process runs, `security_mmap_file` with `PROT_EXEC` for
//!   the rest. Each (cgroup, file, kind) is reported once. The event
//!   carries the pod generation (from the pod-level cgroup's name, the
//!   same machinery that credits syscalls) and the container's cgroup
//!   name, so attribution needs no netns and survives pod churn.
//! - **Backfill** from `/proc/<pid>/exe` and `/proc/<pid>/maps`, once per
//!   container, for processes that were already running when the probe
//!   attached. It sees only what is still running and mapped at that
//!   moment.
//!
//! # Paths
//!
//! Absolute paths inside the container's filesystem, as the kernel
//! resolved them: symlinks are followed (the file actually run), and a
//! volume mounted inside the container is reported under its mount point.
//! `path_complete` is false when the kernel could not build the whole
//! path (too deep, or a name it could not read).
//!
//! # Bounds
//!
//! At most [`MAX_ENTRIES_PER_CONTAINER`] paths per container (overflow
//! is counted), a POST carries at most [`MAX_POST_ENTRIES`] entries, and
//! an entry is re-posted at most every [`REPOST`] while its container
//! runs (that is what keeps the broker's `last_seen` fresh for
//! retention). Events for pods the pod watcher never tracks are dropped
//! after [`UNKNOWN_POD_TTL`].

use crate::early_capture::{container_id_from_segment, parse_kubepods_cgroup_path};
use crate::image_inventory::parse_image_id;
use crate::models::pod_flags;
use chrono::{NaiveDateTime, Utc};
use k8s_openapi::api::core::v1::Pod;
use kube::ResourceExt;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;
use tracing::{debug, info, warn};

pub mod runtime_inventory_skel {
    include!(concat!(env!("OUT_DIR"), "/runtime_inventory.skel.rs"));
}

/// Keep in sync with `KG_RT_*` in `bpf/runtime_inventory.bpf.c`.
pub const KIND_EXEC: u32 = 1;
pub const KIND_LIB: u32 = 2;

/// Keep in sync with `bpf/runtime_inventory.bpf.c`.
pub const PATH_OFF_MAX: usize = 1024;
pub const PATH_NAME_MAX: usize = 256;
pub const PATH_BUF: usize = PATH_OFF_MAX + PATH_NAME_MAX;
pub const CONTAINER_NAME: usize = 128;

pub const MAX_ENTRIES_PER_CONTAINER: usize = 4096;
/// The broker rejects larger batches.
pub const MAX_POST_ENTRIES: usize = 2000;
pub const REPOST: Duration = Duration::from_secs(60 * 60);
pub const UNKNOWN_POD_TTL: Duration = Duration::from_secs(10 * 60);
const POST_EVERY: Duration = Duration::from_secs(10);
/// Coverage heartbeat cadence; sent with each heartbeat so the broker
/// knows how late one may be before it is a gap.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(300);
/// A container that started less than this after the probe attached is
/// treated as already running (backfilled), not captured from its start.
const START_MARGIN_SECS: i64 = 2;
const BACKFILL_EVERY: Duration = Duration::from_secs(60);
const STATS_EVERY: Duration = Duration::from_secs(300);

/// `kguardian.dev/runtime-inventory: "off"` on a pod opts it out.
pub const RUNTIME_INVENTORY_ANNOTATION: &str = "kguardian.dev/runtime-inventory";

/// What is captured (`RUNTIME_INVENTORY`, chart `runtimeInventory.mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// Executed binaries only.
    Exec,
    /// Executed binaries and executable mappings (libraries).
    Full,
}

impl Mode {
    pub fn parse(v: Option<&str>) -> Self {
        // Opt-in until its overhead is measured: unset or anything
        // unrecognised is off.
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("exec") => Mode::Exec,
            Some("full") | Some("true") | Some("on") => Mode::Full,
            _ => Mode::Off,
        }
    }

    pub fn from_env() -> Self {
        Self::parse(std::env::var("RUNTIME_INVENTORY").ok().as_deref())
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Exec => "exec",
            Mode::Full => "full",
        }
    }
}

/// One event as the probe writes it. Keep in sync with `struct
/// runtime_event`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeEventData {
    pub cgroup_id: u64,
    pub ino: u64,
    pub dev: u32,
    pub generation: u32,
    pub kind: u32,
    pub ncomp: u32,
    pub complete: u32,
    pub pid: u32,
    pub fs_magic: u32,
    pub nlink: u32,
    pub upper: u32,
    /// Bytes of `path` in use.
    pub path_len: u32,
    pub container: [u8; CONTAINER_NAME],
    pub path: [u8; PATH_BUF],
}

fn c_str(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Rebuild the path from the probe's leaf-first components. Returns the
/// path and whether it is complete.
pub fn decode_path(buf: &[u8], ncomp: u32, complete: bool) -> (String, bool) {
    let mut comps = Vec::new();
    let mut off = 0usize;
    for _ in 0..ncomp {
        if off >= buf.len() {
            return (join_components(&comps), false);
        }
        let rest = &buf[off..];
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        comps.push(String::from_utf8_lossy(&rest[..len]).into_owned());
        off += len + 1;
    }
    (join_components(&comps), complete && !comps.is_empty())
}

fn join_components(leaf_first: &[String]) -> String {
    let mut s = String::new();
    for c in leaf_first.iter().rev() {
        s.push('/');
        s.push_str(c);
    }
    if s.is_empty() {
        s.push('/');
    }
    s
}

impl RuntimeEventData {
    pub fn container_id(&self) -> Option<String> {
        container_id_from_segment(&c_str(&self.container))
    }

    pub fn kind_str(&self) -> Option<&'static str> {
        match self.kind {
            KIND_EXEC => Some("exec"),
            KIND_LIB => Some("lib"),
            _ => None,
        }
    }

    pub fn path(&self) -> (String, bool) {
        decode_path(&self.path, self.ncomp, self.complete != 0)
    }

    /// Where the file came from; see [`Origin`].
    pub fn origin(&self, path: &str) -> Origin {
        classify(self.fs_magic, self.nlink, self.upper, path)
    }
}

/// Keep in sync with `KG_OVERLAYFS_MAGIC` / `KG_UPPER_*` in the probe.
pub const OVERLAYFS_MAGIC: u32 = 0x794c_7630;
const TMPFS_MAGIC: u32 = 0x0102_1994;
const HUGETLBFS_MAGIC: u32 = 0x9584_58f6;
pub const UPPER_UNKNOWN: u32 = 0;
pub const UPPER_NO: u32 = 1;
pub const UPPER_YES: u32 = 2;

/// Where an executed or mapped file lives: the input to P2-5 drift ("a
/// binary the image did not ship"). Ordered from least to most
/// suspicious; when sightings of one path disagree the most suspicious
/// wins (a replica that ran the file from its writable layer is the
/// finding, whatever the others did).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Not determined (a `/proc` backfill, or overlayfs without its type
    /// in kernel BTF).
    Unknown,
    /// In an image layer (overlayfs lower layer, never modified).
    Image,
    /// Not on overlayfs: a volume (emptyDir, configMap, hostPath, PVC),
    /// or a root filesystem from a non-overlay snapshotter.
    OtherFs,
    /// Unlinked while in use: deleted after it was started.
    Deleted,
    /// In the container's writable upper layer: written or modified after
    /// the container started.
    WritableLayer,
    /// An anonymous memory file (`memfd_create`): never on any disk.
    Memfd,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Unknown => "unknown",
            Origin::Image => "image",
            Origin::OtherFs => "otherFs",
            Origin::Deleted => "deleted",
            Origin::WritableLayer => "writableLayer",
            Origin::Memfd => "memfd",
        }
    }
}

/// Classify from the probe's fields. `path` is the rebuilt path; a memfd
/// is `/memfd:<name>` on the kernel's internal shmem mount.
pub fn classify(fs_magic: u32, nlink: u32, upper: u32, path: &str) -> Origin {
    if nlink == 0 {
        let shmem = fs_magic == TMPFS_MAGIC || fs_magic == HUGETLBFS_MAGIC;
        return if shmem && path.starts_with("/memfd:") {
            Origin::Memfd
        } else {
            Origin::Deleted
        };
    }
    if fs_magic != OVERLAYFS_MAGIC {
        return Origin::OtherFs;
    }
    match upper {
        UPPER_YES => Origin::WritableLayer,
        UPPER_NO => Origin::Image,
        _ => Origin::Unknown,
    }
}

/// A `/proc` link or maps path: `(path, origin)`. The kernel appends
/// ` (deleted)` to an unlinked file, and a memfd reads `/memfd:<name>
/// (deleted)`; anything else is `Unknown` (the backfill cannot see
/// layers).
pub fn proc_path_origin(raw: &str) -> Option<(String, Origin)> {
    let (path, deleted) = match raw.strip_suffix(" (deleted)") {
        Some(p) => (p, true),
        None => (raw, false),
    };
    if !path.starts_with('/') {
        return None;
    }
    let origin = match (deleted, path.starts_with("/memfd:")) {
        (true, true) => Origin::Memfd,
        (true, false) => Origin::Deleted,
        _ => Origin::Unknown,
    };
    Some((path.to_string(), origin))
}

// ---- Who a (generation, container id) is ---------------------------------

// ---- Probe state, shared with the eBPF loader --------------------------

/// When the exec probe attached, and whether the library probe did too.
/// Unset while no probe is loaded (feature off, or this kernel refused
/// it): coverage is then reported as probes missing, never as covered.
static PROBE: std::sync::OnceLock<(NaiveDateTime, bool)> = std::sync::OnceLock::new();

/// Events the kernel could not queue (ring buffer full), cumulative.
/// Published by the eBPF poll loop.
pub static KERNEL_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Called by the eBPF loader once the probe is attached.
pub fn probe_attached(libs: bool) {
    let _ = PROBE.set((Utc::now().naive_utc(), libs));
}

/// One container of a pod, as the pod status names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub name: String,
    /// Image digest, or "".
    pub digest: String,
    /// When the container started (from its status), if known.
    pub started_at: Option<NaiveDateTime>,
    /// This id is the container's current, running one (not a
    /// `lastState.terminated` id).
    pub running: bool,
}

/// What the broker needs to key a container's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRuntime {
    pub uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub workload_kind: String,
    pub workload_name: String,
    /// container id -> the container
    pub containers: HashMap<String, ContainerInfo>,
}

/// Build from a pod and its resolved workload (None = the pod itself).
pub fn pod_runtime(pod: &Pod, workload: Option<(&str, &str)>) -> Option<PodRuntime> {
    let uid = pod.metadata.uid.clone().filter(|u| !u.is_empty())?;
    let namespace = pod.metadata.namespace.clone().unwrap_or_default();
    let pod_name = pod.name_any();
    let (workload_kind, workload_name) = match workload {
        Some((k, n)) => (k.to_string(), n.to_string()),
        None => ("Pod".to_string(), pod_name.clone()),
    };
    let mut containers = HashMap::new();
    if let Some(status) = pod.status.as_ref() {
        let lists = [
            status.container_statuses.as_deref(),
            status.init_container_statuses.as_deref(),
            status.ephemeral_container_statuses.as_deref(),
        ];
        for cs in lists.into_iter().flatten().flatten() {
            let digest = parse_image_id(&cs.image_id)
                .map(|p| p.digest)
                .unwrap_or_default();
            let secs = |t: &k8s_openapi::apimachinery::pkg::apis::meta::v1::Time| {
                chrono::DateTime::from_timestamp(t.0.as_second(), 0).map(|d| d.naive_utc())
            };
            let state = cs.state.as_ref();
            let running_since = state
                .and_then(|s| s.running.as_ref())
                .and_then(|r| r.started_at.as_ref())
                .and_then(secs);
            let current_started = running_since.or_else(|| {
                state
                    .and_then(|s| s.terminated.as_ref())
                    .and_then(|t| t.started_at.as_ref())
                    .and_then(secs)
            });
            let last = cs.last_state.as_ref().and_then(|s| s.terminated.as_ref());
            let entries = [
                (
                    cs.container_id.as_deref(),
                    current_started,
                    running_since.is_some(),
                ),
                (
                    last.and_then(|t| t.container_id.as_deref()),
                    last.and_then(|t| t.started_at.as_ref()).and_then(secs),
                    false,
                ),
            ];
            for (raw, started_at, running) in entries {
                let Some(id) = raw.and_then(crate::container::parse_container_id) else {
                    continue;
                };
                containers.insert(
                    id,
                    ContainerInfo {
                        name: cs.name.clone(),
                        digest: digest.clone(),
                        started_at,
                        running,
                    },
                );
            }
        }
    }
    Some(PodRuntime {
        uid,
        namespace,
        pod_name,
        workload_kind,
        workload_name,
        containers,
    })
}

/// True when the pod opted out with [`RUNTIME_INVENTORY_ANNOTATION`].
pub fn opted_out(pod: &Pod) -> bool {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(RUNTIME_INVENTORY_ANNOTATION))
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("off"))
}

#[derive(Default)]
struct Registry {
    /// generation -> pod. Static pods also under their config-hash
    /// generation (the one the cgroup path yields).
    by_gen: HashMap<u32, PodRuntime>,
    /// Generations of pods seen but not inventoried (excluded namespace,
    /// opted out): their events are dropped on arrival.
    ignored: HashMap<u32, String>,
}

static REGISTRY: std::sync::LazyLock<std::sync::RwLock<Registry>> =
    std::sync::LazyLock::new(Default::default);

fn generations(pod: &Pod, uid: &str) -> Vec<u32> {
    let mut gens = vec![pod_flags::generation_for_uid(Some(uid))];
    let alias = crate::pod_watcher::static_pod_alias_generation(pod);
    if alias != 0 {
        gens.push(alias);
    }
    gens
}

/// Record (or refresh) a pod to inventory. Called where the pod watcher
/// posts the pod with its resolved workload.
pub fn note_pod(pod: &Pod, workload: Option<(&str, &str)>) {
    let Some(rt) = pod_runtime(pod, workload) else {
        return;
    };
    let gens = generations(pod, &rt.uid);
    if let Ok(mut reg) = REGISTRY.write() {
        for g in gens {
            reg.ignored.remove(&g);
            reg.by_gen.insert(g, rt.clone());
        }
    }
}

/// Record a pod whose events must be dropped.
pub fn ignore_pod(pod: &Pod) {
    let Some(uid) = pod.metadata.uid.clone().filter(|u| !u.is_empty()) else {
        return;
    };
    let gens = generations(pod, &uid);
    if let Ok(mut reg) = REGISTRY.write() {
        for g in gens {
            reg.by_gen.remove(&g);
            reg.ignored.insert(g, uid.clone());
        }
    }
}

/// Keep only pods in `live` (a resync LIST).
pub fn retain_pods(live: &HashSet<String>) {
    if let Ok(mut reg) = REGISTRY.write() {
        reg.by_gen.retain(|_, p| live.contains(&p.uid));
        reg.ignored.retain(|_, uid| live.contains(uid));
    }
}

/// Every tracked pod once (a static pod is registered under two
/// generations; either keys it).
fn registry_pods() -> Vec<(u32, PodRuntime)> {
    let Ok(reg) = REGISTRY.read() else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out: Vec<(u32, PodRuntime)> = reg.by_gen.iter().map(|(g, p)| (*g, p.clone())).collect();
    out.sort_by_key(|(g, _)| *g);
    out.retain(|(_, p)| seen.insert(p.uid.clone()));
    out
}

enum Lookup {
    Known(PodRuntime),
    Ignored,
    Unknown,
}

fn lookup(generation: u32) -> Lookup {
    let Ok(reg) = REGISTRY.read() else {
        return Lookup::Unknown;
    };
    if let Some(p) = reg.by_gen.get(&generation) {
        return Lookup::Known(p.clone());
    }
    if reg.ignored.contains_key(&generation) {
        return Lookup::Ignored;
    }
    Lookup::Unknown
}

// ---- Store ---------------------------------------------------------------

/// Which container an entry belongs to: (pod generation, container id).
pub type ContainerKey = (u32, String);

/// An entry handed out by [`Store::due`], to mark sent after the POST.
pub type SentMark = (ContainerKey, (&'static str, String));

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    first_seen: NaiveDateTime,
    last_seen: NaiveDateTime,
    source: &'static str,
    complete: bool,
    origin: Origin,
    sent_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct ContainerEntries {
    first_event: Option<Instant>,
    /// (kind, path) -> entry
    entries: BTreeMap<(&'static str, String), Entry>,
    backfilled: bool,
}

/// One entry of a `/runtime/executables` POST.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeExecutablePost {
    pub pod_namespace: String,
    pub pod_name: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub image_digest: String,
    pub kind: String,
    pub path: String,
    pub path_complete: bool,
    pub source: String,
    pub origin: String,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub events: u64,
    pub ignored: u64,
    pub unknown_dropped: u64,
    pub overflow: u64,
    pub backfilled_containers: u64,
    pub posted: u64,
}

/// Per-container inventory waiting to be (re-)posted. Pure: identity is
/// looked up through the closure passed to [`Store::due`].
#[derive(Debug, Default)]
pub struct Store {
    containers: HashMap<ContainerKey, ContainerEntries>,
    /// Containers dropped as not attributable (the pod sandbox, a pod
    /// never tracked), with the number of sightings thrown away: later
    /// sightings, including the next backfill pass, are ignored instead of
    /// being held for another TTL. If the container turns out to be a
    /// tracked one after all, the count is reported as events dropped and
    /// capture resumes. Forgotten with the pod.
    discarded: HashMap<ContainerKey, u64>,
    /// Events lost per container and not yet reported in a heartbeat.
    drops: HashMap<ContainerKey, u64>,
    /// Containers whose inventory is known incomplete for as long as they
    /// run (the backfill could not read all their mappings).
    incomplete: HashSet<ContainerKey>,
    /// Coverage per container (see [`Store::coverage_due`]).
    coverage: HashMap<ContainerKey, Coverage>,
    /// When each container was backfilled from /proc.
    backfilled_at: HashMap<ContainerKey, NaiveDateTime>,
    /// Kernel drop count at the last heartbeat.
    drops_seen: u64,
    pub stats: Stats,
}

/// What coverage has been reported for one container.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Coverage {
    start_mode: &'static str,
    tracking_since: NaiveDateTime,
    /// The last heartbeat sent, for the final `ended` one.
    last: Option<CoveragePost>,
}

/// One entry of a `/runtime/coverage` POST: this container instance was
/// watched since `tracking_since`, as of `heartbeat_at`, and lost
/// `events_dropped` sightings since the previous heartbeat.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CoveragePost {
    pub pod_namespace: String,
    pub pod_name: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub image_digest: String,
    pub container_id: String,
    pub node_name: String,
    /// `exec` | `full`.
    pub mode: String,
    /// The exec probe is attached.
    pub exec_probe: bool,
    /// The library probe is attached (mode full, and the kernel allowed it).
    pub lib_probe: bool,
    /// `start`: captured from the container's start. `backfill`: the
    /// container was already running; capture begins at the /proc backfill.
    pub start_mode: String,
    pub tracking_since: NaiveDateTime,
    /// Sightings that may have been lost since the previous heartbeat:
    /// events the kernel could not queue (counted for every container on
    /// the node, since the kernel cannot say whose they were), paths over
    /// the per-container cap, entries the broker dropped at ingest, and
    /// sightings thrown away while the pod was not yet known.
    pub events_dropped: u64,
    /// Entries seen but not yet accepted by the broker.
    pub unsent: u64,
    /// The inventory of this container is known to be incomplete (the
    /// /proc backfill hit its maps cap): never covered while it runs.
    pub incomplete: bool,
    /// The container is gone; its last heartbeat.
    pub ended: bool,
    pub heartbeat_at: NaiveDateTime,
    pub heartbeat_secs: u32,
}

/// One observation of a file in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub kind: &'static str,
    pub path: String,
    pub complete: bool,
    pub source: &'static str,
    pub origin: Origin,
}

impl Store {
    pub fn add(&mut self, key: ContainerKey, s: Sighting, now: Instant, wall: NaiveDateTime) {
        if let Some(n) = self.discarded.get_mut(&key) {
            *n += 1;
            return;
        }
        let key_for_gap = key.clone();
        let c = self.containers.entry(key).or_default();
        c.first_event.get_or_insert(now);
        let Sighting {
            kind,
            path,
            complete,
            source,
            origin,
        } = s;
        let k = (kind, path);
        if let Some(e) = c.entries.get_mut(&k) {
            e.last_seen = e.last_seen.max(wall);
            e.complete |= complete;
            if source == "ebpf" {
                e.source = "ebpf";
            }
            if origin > e.origin {
                // Something new to tell the broker: post it again.
                e.origin = origin;
                e.sent_at = None;
            }
            return;
        }
        if c.entries.len() >= MAX_ENTRIES_PER_CONTAINER {
            self.stats.overflow += 1;
            *self.drops.entry(key_for_gap).or_default() += 1;
            return;
        }
        c.entries.insert(
            k,
            Entry {
                first_seen: wall,
                last_seen: wall,
                source,
                complete,
                origin,
                sent_at: None,
            },
        );
    }

    pub fn needs_backfill(&self, key: &ContainerKey) -> bool {
        self.containers.get(key).is_none_or(|c| !c.backfilled)
    }

    pub fn mark_backfilled(&mut self, key: ContainerKey, wall: NaiveDateTime) {
        self.backfilled_at.entry(key.clone()).or_insert(wall);
        let c = self.containers.entry(key).or_default();
        if !c.backfilled {
            c.backfilled = true;
            self.stats.backfilled_containers += 1;
        }
    }

    /// Entries due for posting (never sent, or sent more than [`REPOST`]
    /// ago while the container still runs), at most `max`, with the keys
    /// to mark sent afterwards. Containers whose pod is unknown are held
    /// for [`UNKNOWN_POD_TTL`] and then dropped; containers of pods that
    /// are gone are dropped once everything they hold was sent.
    pub fn due<F>(
        &mut self,
        now: Instant,
        wall: NaiveDateTime,
        max: usize,
        resolve: F,
    ) -> (Vec<RuntimeExecutablePost>, Vec<SentMark>)
    where
        F: Fn(u32) -> Option<PodRuntime>,
    {
        let mut posts = Vec::new();
        let mut marks = Vec::new();
        let mut drop = Vec::new();
        for (key, c) in self.containers.iter_mut() {
            let pod = resolve(key.0);
            let Some(pod) = pod else {
                if c.first_event
                    .is_some_and(|t| now.saturating_duration_since(t) >= UNKNOWN_POD_TTL)
                {
                    self.stats.unknown_dropped += c.entries.len() as u64;
                    drop.push(key.clone());
                }
                continue;
            };
            let running = pod.containers.get(&key.1).is_some_and(|c| c.running);
            let Some(ContainerInfo {
                name: container_name,
                digest,
                ..
            }) = pod.containers.get(&key.1).cloned()
            else {
                // Container id not (yet) in the pod's status: hold until
                // the status names it or the TTL runs out.
                if c.first_event
                    .is_some_and(|t| now.saturating_duration_since(t) >= UNKNOWN_POD_TTL)
                {
                    self.stats.unknown_dropped += c.entries.len() as u64;
                    drop.push(key.clone());
                }
                continue;
            };
            for ((kind, path), e) in c.entries.iter_mut() {
                if posts.len() >= max {
                    break;
                }
                let due = match e.sent_at {
                    None => true,
                    Some(at) => running && now.saturating_duration_since(at) >= REPOST,
                };
                if !due {
                    continue;
                }
                if e.sent_at.is_some() {
                    // A re-post refreshes the broker's last_seen.
                    e.last_seen = e.last_seen.max(wall);
                }
                posts.push(RuntimeExecutablePost {
                    pod_namespace: pod.namespace.clone(),
                    pod_name: pod.pod_name.clone(),
                    workload_kind: pod.workload_kind.clone(),
                    workload_name: pod.workload_name.clone(),
                    container_name: container_name.clone(),
                    image_digest: digest.clone(),
                    kind: kind.to_string(),
                    path: path.clone(),
                    path_complete: e.complete,
                    source: e.source.to_string(),
                    origin: e.origin.as_str().to_string(),
                    first_seen: e.first_seen,
                    last_seen: e.last_seen,
                });
                marks.push((key.clone(), (*kind, path.clone())));
            }
        }
        for key in drop {
            let n = self
                .containers
                .remove(&key)
                .map_or(0, |c| c.entries.len() as u64);
            self.discarded.insert(key, n);
        }
        (posts, marks)
    }

    /// The broker accepted a POST but dropped `dropped` of its entries
    /// (it cannot say which): every container in it may have lost one.
    pub fn note_ingest_dropped(&mut self, marks: &[SentMark], dropped: u64) {
        if dropped == 0 {
            return;
        }
        let keys: HashSet<&ContainerKey> = marks.iter().map(|(k, _)| k).collect();
        for k in keys {
            *self.drops.entry(k.clone()).or_default() += dropped;
        }
    }

    pub fn mark_sent(&mut self, marks: &[SentMark], now: Instant) {
        for (key, k) in marks {
            if let Some(e) = self
                .containers
                .get_mut(key)
                .and_then(|c| c.entries.get_mut(k))
            {
                e.sent_at = Some(now);
            }
        }
    }

    /// Forget containers whose pod the registry no longer has, once all
    /// their entries were sent.
    pub fn prune<F>(&mut self, resolve: F)
    where
        F: Fn(u32) -> Option<PodRuntime>,
    {
        self.containers.retain(|key, c| {
            resolve(key.0).is_some() || c.entries.values().any(|e| e.sent_at.is_none())
        });
        self.discarded.retain(|key, _| resolve(key.0).is_some());
        self.drops.retain(|key, _| resolve(key.0).is_some());
        self.incomplete.retain(|key| resolve(key.0).is_some());
        self.backfilled_at
            .retain(|key, _| resolve(key.0).is_some_and(|p| p.containers.contains_key(&key.1)));
    }

    pub fn containers(&self) -> usize {
        self.containers.len()
    }

    /// Coverage heartbeats for every running container of every tracked
    /// pod on this node, plus a final `ended` one for each container that
    /// stopped since the last call. Pure: the probe state, the kernel drop
    /// count and the pod registry are passed in.
    ///
    /// A container is `start` when it started after the probe attached
    /// (plus a small margin): the kernel saw its first exec. Otherwise it
    /// is reported only once the /proc backfill has run, as `backfill`
    /// from that moment. With no probe, containers are reported with both
    /// probes false so the broker can say why they are not covered.
    pub fn coverage_due(
        &mut self,
        pods: &[(u32, PodRuntime)],
        probe: Option<(NaiveDateTime, bool)>,
        mode: Mode,
        kernel_drops: u64,
        node: &str,
        wall: NaiveDateTime,
    ) -> Vec<CoveragePost> {
        let kernel_delta = kernel_drops.saturating_sub(self.drops_seen);
        self.drops_seen = kernel_drops;
        if kernel_delta > 0 {
            // Whose events they were is unknown: every container on the
            // node, reported or not yet, may have lost one.
            for (generation, pod) in pods {
                for (cid, info) in &pod.containers {
                    if info.running {
                        *self.drops.entry((*generation, cid.clone())).or_default() += kernel_delta;
                    }
                }
            }
            // Including containers that stopped since the last beat.
            for key in self.coverage.keys() {
                let n = self.drops.entry(key.clone()).or_default();
                *n = (*n).max(kernel_delta);
            }
        }
        let mut out = Vec::new();
        let mut live: HashSet<ContainerKey> = HashSet::new();
        for (generation, pod) in pods {
            for (cid, info) in &pod.containers {
                if !info.running {
                    continue;
                }
                let key: ContainerKey = (*generation, cid.clone());
                live.insert(key.clone());
                // Thrown away while unattributable, but it is a tracked
                // container: those were lost, and capture resumes.
                if let Some(n) = self.discarded.remove(&key) {
                    *self.drops.entry(key.clone()).or_default() += n.max(1);
                }
                let (exec_probe, lib_probe) = match probe {
                    Some((_, libs)) => (true, libs && mode == Mode::Full),
                    None => (false, false),
                };
                if !self.coverage.contains_key(&key) {
                    let start = match (probe, info.started_at) {
                        (Some((attached, _)), Some(started))
                            if started
                                > attached + chrono::Duration::seconds(START_MARGIN_SECS) =>
                        {
                            Some(("start", started))
                        }
                        _ => self.backfilled_at.get(&key).map(|t| ("backfill", *t)),
                    };
                    let Some((start_mode, tracking_since)) = start.or_else(|| {
                        // No probe: report the container anyway, so the
                        // reason is "probes missing" rather than "no data".
                        probe.is_none().then_some(("backfill", wall))
                    }) else {
                        continue;
                    };
                    self.coverage.insert(
                        key.clone(),
                        Coverage {
                            start_mode,
                            tracking_since,
                            last: None,
                        },
                    );
                }
                let events_dropped = self.drops.remove(&key).unwrap_or(0);
                let unsent = self.containers.get(&key).map_or(0, |c| {
                    c.entries.values().filter(|e| e.sent_at.is_none()).count() as u64
                });
                let cov = self.coverage.get_mut(&key).expect("inserted above");
                let post = CoveragePost {
                    pod_namespace: pod.namespace.clone(),
                    pod_name: pod.pod_name.clone(),
                    workload_kind: pod.workload_kind.clone(),
                    workload_name: pod.workload_name.clone(),
                    container_name: info.name.clone(),
                    image_digest: info.digest.clone(),
                    container_id: cid.clone(),
                    node_name: node.to_string(),
                    mode: mode.as_str().to_string(),
                    exec_probe,
                    lib_probe,
                    start_mode: cov.start_mode.to_string(),
                    tracking_since: cov.tracking_since,
                    events_dropped,
                    unsent,
                    incomplete: self.incomplete.contains(&key),
                    ended: false,
                    heartbeat_at: wall,
                    heartbeat_secs: HEARTBEAT_EVERY.as_secs() as u32,
                };
                cov.last = Some(post.clone());
                out.push(post);
            }
        }
        // Containers reported before and not running now: one last beat.
        let gone: Vec<ContainerKey> = self
            .coverage
            .keys()
            .filter(|k| !live.contains(*k))
            .cloned()
            .collect();
        for key in gone {
            let cov = self.coverage.remove(&key).expect("listed above");
            if let Some(last) = cov.last {
                out.push(CoveragePost {
                    events_dropped: self.drops.remove(&key).unwrap_or(0),
                    unsent: 0,
                    ended: true,
                    heartbeat_at: wall,
                    ..last
                });
            }
        }
        out
    }
}

// ---- Backfill from /proc -------------------------------------------------

/// The container a process runs in, from its `/proc/<pid>/cgroup` body.
/// The controller's own cgroup namespace makes the path relative
/// (`0::/../../kubepods-…/cri-containerd-<id>.scope`), but the pod and
/// container segments are still in it.
pub fn process_container(cgroup_body: &str) -> Option<(String, String)> {
    let path = cgroup_body.lines().find_map(|l| l.strip_prefix("0::"))?;
    let id = parse_kubepods_cgroup_path(path.trim())?;
    Some((id.pod_uid, id.container_id?))
}

fn backfilled(kind: &'static str, path: String, origin: Origin) -> Sighting {
    Sighting {
        kind,
        path,
        complete: true,
        source: "backfill",
        origin,
    }
}

/// Executable file mappings in a `/proc/<pid>/maps` body, excluding `exe`,
/// with the origin the path itself reveals (see [`proc_path_origin`]).
pub fn exec_mappings(maps: &str, exe: Option<&str>) -> Vec<(String, Origin)> {
    let mut out: Vec<(String, Origin)> = Vec::new();
    for line in maps.lines() {
        let mut f = line.split_whitespace();
        let (Some(_range), Some(perms), Some(_off), Some(_dev), Some(inode)) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        if !perms.contains('x') || inode == "0" {
            continue;
        }
        let raw: String = f.collect::<Vec<_>>().join(" ");
        let Some((path, origin)) = proc_path_origin(&raw) else {
            continue;
        };
        if Some(path.as_str()) == exe || out.iter().any(|(p, _)| *p == path) {
            continue;
        }
        out.push((path, origin));
    }
    out
}

/// Largest `/proc/<pid>/maps` read; a process with more mappings than
/// this has its first 4 MiB of them backfilled.
const MAX_MAPS_BYTES: u64 = 4 << 20;

/// Read at most `cap` bytes; `.1` is true when the file was longer (the
/// read was cut short).
fn read_capped(path: &Path, cap: u64) -> Option<(String, bool)> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(cap + 1)
        .read_to_end(&mut buf)
        .ok()?;
    let truncated = buf.len() as u64 > cap;
    buf.truncate(cap as usize);
    // A cut in the middle of a UTF-8 sequence, or of a line: only whole
    // lines up to the cut are used.
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if truncated {
        let end = text.rfind('\n').map_or(0, |i| i + 1);
        text.truncate(end);
    }
    Some((text, truncated))
}

/// What one /proc pass found for one container not yet backfilled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackfillFound {
    pub sightings: Vec<Sighting>,
    /// A process's maps were longer than [`MAX_MAPS_BYTES`]: executable
    /// mappings past the cut were not read, so the container's inventory
    /// is known to be incomplete for as long as it runs.
    pub truncated: bool,
}

/// What one /proc pass found, per container.
pub type BackfillScan = Vec<(ContainerKey, BackfillFound)>;

/// One pass over `proc_root`: for every container not in `done` whose pod
/// is tracked, the executable and executable mappings of each of its
/// processes. Blocking file I/O and no `Store`, so it runs off the async
/// task (see [`run`]). A process whose cgroup changed while it was read
/// (it exited and the pid was reused) is skipped.
pub fn scan_proc<F>(
    proc_root: &Path,
    done: &HashSet<ContainerKey>,
    mode: Mode,
    tracked: F,
) -> BackfillScan
where
    F: Fn(u32) -> bool,
{
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut found: HashMap<ContainerKey, BackfillFound> = HashMap::new();
    for ent in dir.flatten() {
        let name = ent.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let base = proc_root.join(pid);
        let Some((cg, _)) = read_capped(&base.join("cgroup"), 64 << 10) else {
            continue;
        };
        let Some((uid, cid)) = process_container(&cg) else {
            continue;
        };
        let generation = pod_flags::generation_for_uid(Some(&uid));
        if !tracked(generation) {
            continue;
        }
        let key = (generation, cid);
        if done.contains(&key) {
            continue;
        }
        let exe = std::fs::read_link(base.join("exe"))
            .ok()
            .and_then(|p| proc_path_origin(&p.to_string_lossy()));
        let maps = (mode == Mode::Full)
            .then(|| read_capped(&base.join("maps"), MAX_MAPS_BYTES))
            .flatten();
        // Same process throughout? A pid reused by another container's
        // process in between would credit its files to this one.
        if read_capped(&base.join("cgroup"), 64 << 10)
            .map(|(c, _)| c)
            .as_deref()
            != Some(cg.as_str())
        {
            continue;
        }
        let out = found.entry(key).or_default();
        if let Some((path, origin)) = exe.clone() {
            out.sightings.push(backfilled("exec", path, origin));
        }
        if let Some((maps, truncated)) = maps {
            out.truncated |= truncated;
            let exe_path = exe.as_ref().map(|(p, _)| p.as_str());
            for (lib, origin) in exec_mappings(&maps, exe_path) {
                out.sightings.push(backfilled("lib", lib, origin));
            }
        }
    }
    found.into_iter().collect()
}

/// Record a scan: every container in it is marked backfilled. Returns the
/// containers backfilled.
pub fn apply_backfill(
    store: &mut Store,
    scan: BackfillScan,
    now: Instant,
    wall: NaiveDateTime,
) -> usize {
    let mut n = 0;
    for (key, found) in scan {
        if !store.needs_backfill(&key) {
            continue;
        }
        if found.truncated {
            warn!(
                container = %key.1,
                max_bytes = MAX_MAPS_BYTES,
                "runtime inventory: /proc maps over the cap; this container's coverage is incomplete"
            );
            store.incomplete.insert(key.clone());
        }
        for s in found.sightings {
            store.add(key.clone(), s, now, wall);
        }
        store.mark_backfilled(key, wall);
        n += 1;
    }
    n
}

/// Containers already backfilled (the scan skips them).
impl Store {
    pub fn backfilled_keys(&self) -> HashSet<ContainerKey> {
        self.containers
            .iter()
            .filter(|(_, c)| c.backfilled)
            .map(|(k, _)| k.clone())
            .chain(self.discarded.keys().cloned())
            .collect()
    }
}

/// [`scan_proc`] then [`apply_backfill`], in one call (tests).
pub fn backfill<F>(
    proc_root: &Path,
    store: &mut Store,
    mode: Mode,
    tracked: F,
    now: Instant,
    wall: NaiveDateTime,
) -> usize
where
    F: Fn(u32) -> bool,
{
    let scan = scan_proc(proc_root, &store.backfilled_keys(), mode, tracked);
    apply_backfill(store, scan, now, wall)
}

// ---- The subsystem ---------------------------------------------------------

/// Consume probe events, backfill, and post. Returns when the event
/// channel closes (the eBPF loop is gone).
pub async fn run(mut events: Receiver<RuntimeEventData>, mode: Mode) -> Result<(), crate::Error> {
    info!(mode = mode.as_str(), "runtime inventory");
    if mode == Mode::Off {
        return Ok(());
    }
    let mut store = Store::default();
    let mut post_tick = tokio::time::interval(POST_EVERY);
    post_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_backfill: Option<Instant> = None;
    let mut last_heartbeat: Option<Instant> = None;
    let node = std::env::var("CURRENT_NODE").unwrap_or_default();
    let mut last_stats = Instant::now();
    let resolve = |g: u32| match lookup(g) {
        Lookup::Known(p) => Some(p),
        _ => None,
    };
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                store.stats.events += 1;
                if let Lookup::Ignored = lookup(ev.generation) {
                    store.stats.ignored += 1;
                    continue;
                }
                let (Some(kind), Some(cid)) = (ev.kind_str(), ev.container_id()) else {
                    continue;
                };
                if kind == "lib" && mode != Mode::Full {
                    continue;
                }
                let (path, complete) = ev.path();
                let origin = ev.origin(&path);
                let sighting = Sighting { kind, path, complete, source: "ebpf", origin };
                store.add((ev.generation, cid), sighting, Instant::now(), Utc::now().naive_utc());
            }
            _ = post_tick.tick() => {
                if last_backfill.is_none_or(|t| t.elapsed() >= BACKFILL_EVERY) {
                    last_backfill = Some(Instant::now());
                    // Blocking /proc reads off this task: the event
                    // channel keeps draining, so the eBPF poll loop (shared
                    // with the network and syscall probes) never waits on it.
                    let done = store.backfilled_keys();
                    let scan = tokio::task::spawn_blocking(move || {
                        scan_proc(Path::new("/proc"), &done, mode, |g| {
                            matches!(lookup(g), Lookup::Known(_))
                        })
                    })
                    .await
                    .unwrap_or_default();
                    let n = apply_backfill(&mut store, scan, Instant::now(), Utc::now().naive_utc());
                    if n > 0 {
                        debug!(containers = n, "runtime inventory: backfilled from /proc");
                    }
                }
                post_due(&mut store, &resolve).await;
                // Coverage heartbeat, after the backfill and the post so a
                // backfilled container is reported the pass it was read.
                if last_heartbeat.is_none_or(|t| t.elapsed() >= HEARTBEAT_EVERY) {
                    last_heartbeat = Some(Instant::now());
                    let beats = store.coverage_due(
                        &registry_pods(),
                        PROBE.get().copied(),
                        mode,
                        KERNEL_DROPS.load(std::sync::atomic::Ordering::Relaxed),
                        &node,
                        Utc::now().naive_utc(),
                    );
                    post_coverage(beats).await;
                }
                store.prune(resolve);
                if last_stats.elapsed() >= STATS_EVERY {
                    last_stats = Instant::now();
                    let s = store.stats;
                    info!(
                        events = s.events,
                        ignored = s.ignored,
                        unknown_dropped = s.unknown_dropped,
                        overflow = s.overflow,
                        backfilled_containers = s.backfilled_containers,
                        posted = s.posted,
                        containers = store.containers(),
                        "runtime inventory (cumulative)"
                    );
                }
            }
        }
    }
    warn!("runtime inventory event channel closed");
    Ok(())
}

/// Post heartbeats in chunks. A failed chunk is not retried: the next
/// heartbeat carries the same state, and the broker treats the missed
/// one as a gap only if the next is also late.
async fn post_coverage(beats: Vec<CoveragePost>) {
    for chunk in beats.chunks(MAX_POST_ENTRIES) {
        if let Err(e) = crate::api_post_call(serde_json::json!(chunk), "runtime/coverage").await {
            warn!(entries = chunk.len(), error = %e, "runtime coverage heartbeat POST failed");
            return;
        }
    }
}

async fn post_due<F>(store: &mut Store, resolve: &F)
where
    F: Fn(u32) -> Option<PodRuntime>,
{
    loop {
        let (posts, marks) = store.due(
            Instant::now(),
            Utc::now().naive_utc(),
            MAX_POST_ENTRIES,
            resolve,
        );
        if posts.is_empty() {
            return;
        }
        let n = posts.len();
        match crate::client::api_post_call_json(serde_json::json!(posts), "runtime/executables")
            .await
        {
            Ok(summary) => {
                let dropped = summary.get("dropped").and_then(|d| d.as_u64()).unwrap_or(0);
                if dropped > 0 {
                    warn!(
                        dropped,
                        "broker dropped runtime inventory entries; reported as a coverage gap"
                    );
                }
                store.note_ingest_dropped(&marks, dropped);
                store.mark_sent(&marks, Instant::now());
                store.stats.posted += n as u64;
                if n < MAX_POST_ENTRIES {
                    return;
                }
            }
            Err(e) => {
                warn!(entries = n, error = %e, "runtime inventory POST failed; retrying next pass");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &str = "3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab";
    const CID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn buf(comps_leaf_first: &[&str]) -> [u8; PATH_BUF] {
        let mut b = [0u8; PATH_BUF];
        let mut off = 0;
        for c in comps_leaf_first {
            b[off..off + c.len()].copy_from_slice(c.as_bytes());
            off += c.len() + 1;
        }
        b
    }

    #[test]
    fn event_layout_matches_the_kernel_struct() {
        assert_eq!(
            std::mem::size_of::<RuntimeEventData>(),
            8 + 8 + 10 * 4 + CONTAINER_NAME + PATH_BUF
        );
        assert_eq!(std::mem::offset_of!(RuntimeEventData, container), 56);
    }

    #[test]
    fn paths_are_rebuilt_from_leaf_first_components() {
        let b = buf(&["libssl.so.3", "x86_64-linux-gnu", "lib", "usr"]);
        assert_eq!(
            decode_path(&b, 4, true),
            ("/usr/lib/x86_64-linux-gnu/libssl.so.3".to_string(), true)
        );
        // Incomplete walks are flagged.
        assert!(!decode_path(&b, 2, false).1);
        assert_eq!(decode_path(&b, 0, true), ("/".to_string(), false));
    }

    #[test]
    fn a_volume_mount_path_joins_across_the_mount() {
        // The probe walks main.py -> (mount root) -> app -> (rootfs root).
        let b = buf(&["main.py", "app"]);
        assert_eq!(decode_path(&b, 2, true).0, "/app/main.py");
    }

    #[test]
    fn mode_parses() {
        assert_eq!(Mode::parse(None), Mode::Off, "opt-in");
        assert_eq!(Mode::parse(Some("")), Mode::Off);
        assert_eq!(Mode::parse(Some("typo")), Mode::Off);
        assert_eq!(Mode::parse(Some("exec")), Mode::Exec);
        assert_eq!(Mode::parse(Some("OFF")), Mode::Off);
        assert_eq!(Mode::parse(Some(" Full ")), Mode::Full);
    }

    #[test]
    fn process_container_reads_the_relative_cgroup_path() {
        let body = format!(
            "0::/../../kubepods-besteffort.slice/kubepods-besteffort-pod{}.slice/cri-containerd-{CID}.scope\n",
            UID.replace('-', "_")
        );
        assert_eq!(
            process_container(&body),
            Some((UID.to_string(), CID.to_string()))
        );
        assert_eq!(
            process_container("0::/system.slice/containerd.service\n"),
            None
        );
    }

    #[test]
    fn exec_mappings_keep_executable_files_and_flag_deleted_ones() {
        let maps = "\
55d0c0000000-55d0c0001000 r-xp 00000000 00:2a 123 /usr/sbin/nginx
7f00000000-7f00001000 r--p 00000000 00:2a 456 /usr/lib/x86_64-linux-gnu/libc.so.6
7f00001000-7f00002000 r-xp 00001000 00:2a 456 /usr/lib/x86_64-linux-gnu/libc.so.6
7f00002000-7f00003000 r-xp 00000000 00:00 0 [vdso]
7f00003000-7f00004000 r-xp 00000000 00:2a 789 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f00004000-7f00005000 r-xp 00000000 00:2a 999 /tmp/gone.so (deleted)
7f00005000-7f00006000 r-xp 00000000 00:2a 998 /opt/my app/lib.so
";
        assert_eq!(
            exec_mappings(maps, Some("/usr/sbin/nginx")),
            vec![
                (
                    "/usr/lib/x86_64-linux-gnu/libc.so.6".to_string(),
                    Origin::Unknown
                ),
                (
                    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".to_string(),
                    Origin::Unknown
                ),
                ("/tmp/gone.so".to_string(), Origin::Deleted),
                ("/opt/my app/lib.so".to_string(), Origin::Unknown),
            ]
        );
    }

    fn pod_rt() -> PodRuntime {
        PodRuntime {
            uid: UID.into(),
            namespace: "ns".into(),
            pod_name: "web-1".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            containers: HashMap::from([(
                CID.to_string(),
                ContainerInfo {
                    name: "nginx".to_string(),
                    digest: "sha256:ab".to_string(),
                    started_at: None,
                    running: true,
                },
            )]),
        }
    }

    fn sg(kind: &'static str, path: String, source: &'static str) -> Sighting {
        Sighting {
            kind,
            path,
            complete: true,
            source,
            origin: Origin::Image,
        }
    }

    fn wall() -> NaiveDateTime {
        Utc::now().naive_utc()
    }

    #[test]
    fn entries_post_once_then_repost_hourly_while_running() {
        let t0 = Instant::now();
        let mut s = Store::default();
        let key = (7u32, CID.to_string());
        s.add(
            key.clone(),
            sg("exec", "/usr/sbin/nginx".into(), "ebpf"),
            t0,
            wall(),
        );
        s.add(
            key.clone(),
            sg("lib", "/usr/lib/libc.so.6".into(), "ebpf"),
            t0,
            wall(),
        );
        let (posts, marks) = s.due(t0, wall(), 100, |_| Some(pod_rt()));
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].container_name, "nginx");
        assert_eq!(posts[0].workload_kind, "Deployment");
        assert_eq!(posts[0].image_digest, "sha256:ab");
        s.mark_sent(&marks, t0);
        assert!(s
            .due(
                t0 + Duration::from_secs(60),
                wall(),
                100,
                |_| Some(pod_rt())
            )
            .0
            .is_empty());
        assert_eq!(
            s.due(t0 + REPOST, wall(), 100, |_| Some(pod_rt())).0.len(),
            2
        );
    }

    #[test]
    fn posts_are_chunked() {
        let t0 = Instant::now();
        let mut s = Store::default();
        let key = (7u32, CID.to_string());
        for i in 0..25 {
            s.add(
                key.clone(),
                sg("lib", format!("/l/{i}.so"), "ebpf"),
                t0,
                wall(),
            );
        }
        let (p1, m1) = s.due(t0, wall(), 10, |_| Some(pod_rt()));
        assert_eq!(p1.len(), 10);
        s.mark_sent(&m1, t0);
        assert_eq!(s.due(t0, wall(), 100, |_| Some(pod_rt())).0.len(), 15);
    }

    #[test]
    fn unknown_pods_are_held_then_dropped() {
        let t0 = Instant::now();
        let mut s = Store::default();
        let key = (9u32, CID.to_string());
        s.add(
            key.clone(),
            sg("exec", "/bin/sh".into(), "ebpf"),
            t0,
            wall(),
        );
        assert!(s.due(t0, wall(), 10, |_| None).0.is_empty());
        assert_eq!(
            s.containers(),
            1,
            "held while the watcher may still learn the pod"
        );
        // Learned in time: posted.
        assert_eq!(
            s.due(t0 + Duration::from_secs(5), wall(), 10, |_| Some(pod_rt()))
                .0
                .len(),
            1
        );
        let mut s = Store::default();
        s.add(key, sg("exec", "/bin/sh".into(), "ebpf"), t0, wall());
        s.due(t0 + UNKNOWN_POD_TTL, wall(), 10, |_| None);
        assert_eq!(s.containers(), 0);
        assert_eq!(s.stats.unknown_dropped, 1);
    }

    #[test]
    fn a_container_id_the_status_does_not_name_is_held() {
        // The sandbox, or an app container the status has not caught up with.
        let t0 = Instant::now();
        let mut s = Store::default();
        let sandbox: ContainerKey = (7, "sandbox".into());
        s.add(
            sandbox.clone(),
            sg("exec", "/pause".into(), "ebpf"),
            t0,
            wall(),
        );
        assert!(s.due(t0, wall(), 10, |_| Some(pod_rt())).0.is_empty());
        s.due(t0 + UNKNOWN_POD_TTL, wall(), 10, |_| Some(pod_rt()));
        assert_eq!(s.containers(), 0, "the sandbox's execs never post");
        // The next backfill pass does not start the hold over again...
        s.add(
            sandbox.clone(),
            sg("exec", "/pause".into(), "backfill"),
            t0,
            wall(),
        );
        assert_eq!(s.containers(), 0);
        // ...until the pod is gone, when the tombstone goes with it.
        s.prune(|_| None);
        s.add(sandbox, sg("exec", "/pause".into(), "ebpf"), t0, wall());
        assert_eq!(s.containers(), 1);
    }

    fn at(h: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(1_800_000_000 + h * 3600, 0)
            .unwrap()
            .naive_utc()
    }

    fn pod_started(started_h: i64) -> PodRuntime {
        let mut p = pod_rt();
        p.containers.get_mut(CID).unwrap().started_at = Some(at(started_h));
        p
    }

    #[test]
    fn coverage_is_from_start_only_for_containers_started_after_the_probe() {
        let mut s = Store::default();
        let probe = Some((at(0), true));
        // Started an hour after the probe attached: captured from start.
        let beats = s.coverage_due(&[(7, pod_started(1))], probe, Mode::Full, 0, "n1", at(2));
        assert_eq!(beats.len(), 1);
        let b = &beats[0];
        assert_eq!((b.start_mode.as_str(), b.tracking_since), ("start", at(1)));
        assert!(b.exec_probe && b.lib_probe && !b.ended);
        assert_eq!((b.events_dropped, b.unsent), (0, 0));
        assert_eq!((b.container_id.as_str(), b.node_name.as_str()), (CID, "n1"));
        assert_eq!(b.heartbeat_secs, 300);

        // Already running when the probe attached: nothing until the
        // backfill has read it, then `backfill` from that moment.
        let mut s = Store::default();
        let old = [(7, pod_started(-5))];
        assert!(s
            .coverage_due(&old, probe, Mode::Full, 0, "n1", at(1))
            .is_empty());
        s.mark_backfilled((7, CID.to_string()), at(1));
        let b = &s.coverage_due(&old, probe, Mode::Full, 0, "n1", at(2))[0];
        assert_eq!(
            (b.start_mode.as_str(), b.tracking_since),
            ("backfill", at(1))
        );
        // The start of tracking never moves on later heartbeats.
        let b = &s.coverage_due(&old, probe, Mode::Full, 0, "n1", at(3))[0];
        assert_eq!(b.tracking_since, at(1));
    }

    #[test]
    fn coverage_reports_missing_probes_and_exec_only_mode() {
        let mut s = Store::default();
        let b = &s.coverage_due(&[(7, pod_started(1))], None, Mode::Full, 0, "n1", at(2))[0];
        assert!(
            !b.exec_probe && !b.lib_probe,
            "no probe loaded: said so, not silent"
        );
        let mut s = Store::default();
        let b = &s.coverage_due(
            &[(7, pod_started(1))],
            Some((at(0), true)),
            Mode::Exec,
            0,
            "n1",
            at(2),
        )[0];
        assert!(
            b.exec_probe && !b.lib_probe,
            "exec mode never vouches for libraries"
        );
        let mut s = Store::default();
        let b = &s.coverage_due(
            &[(7, pod_started(1))],
            Some((at(0), false)),
            Mode::Full,
            0,
            "n1",
            at(2),
        )[0];
        assert!(
            !b.lib_probe,
            "full mode on a kernel without the fentry probe"
        );
    }

    #[test]
    fn coverage_counts_every_kind_of_lost_event_once() {
        let mut s = Store::default();
        let pods = [(7, pod_started(1))];
        let probe = Some((at(0), true));
        let key = (7u32, CID.to_string());
        let beat = |s: &mut Store, drops: u64, h: i64| {
            s.coverage_due(&pods, probe, Mode::Full, drops, "n1", at(h))[0].clone()
        };
        assert_eq!(
            beat(&mut s, 3, 2).events_dropped,
            3,
            "drops before the first beat count"
        );
        // Kernel drops since the last beat: reported once.
        assert_eq!(beat(&mut s, 5, 3).events_dropped, 2);
        assert_eq!(beat(&mut s, 5, 4).events_dropped, 0);
        // Per-container overflow.
        for i in 0..=MAX_ENTRIES_PER_CONTAINER {
            s.add(
                key.clone(),
                sg("lib", format!("/l/{i}"), "ebpf"),
                Instant::now(),
                wall(),
            );
        }
        let b = beat(&mut s, 5, 5);
        assert_eq!(b.events_dropped, 1);
        assert_eq!(
            b.unsent, MAX_ENTRIES_PER_CONTAINER as u64,
            "entries not yet posted"
        );
        // Entries the broker dropped at ingest.
        let (_, marks) = s.due(Instant::now(), wall(), 10, |_| Some(pod_rt()));
        s.note_ingest_dropped(&marks, 2);
        assert_eq!(beat(&mut s, 5, 6).events_dropped, 2);
    }

    #[test]
    fn sightings_discarded_before_the_pod_was_known_count_as_lost_and_capture_resumes() {
        let t0 = Instant::now();
        let mut s = Store::default();
        let key = (7u32, CID.to_string());
        s.add(key.clone(), sg("exec", "/app".into(), "ebpf"), t0, wall());
        // The pod stayed unknown past the TTL: discarded.
        s.due(t0 + UNKNOWN_POD_TTL, wall(), 10, |_| None);
        s.add(key.clone(), sg("exec", "/later".into(), "ebpf"), t0, wall());
        assert_eq!(s.containers(), 0);
        // Then the watcher learns it is a tracked, running container.
        let b = &s.coverage_due(
            &[(7, pod_started(1))],
            Some((at(0), true)),
            Mode::Full,
            0,
            "n1",
            at(2),
        )[0];
        assert_eq!(b.events_dropped, 2, "both discarded sightings");
        s.add(key, sg("exec", "/after".into(), "ebpf"), t0, wall());
        assert_eq!(s.containers(), 1, "capture resumes");
    }

    #[test]
    fn a_truncated_maps_read_marks_the_container_incomplete_in_every_heartbeat() {
        let root = std::env::temp_dir().join(format!("kg-rt-trunc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let pid = root.join("4343");
        std::fs::create_dir_all(&pid).unwrap();
        std::fs::write(
            pid.join("cgroup"),
            format!("0::/../kubepods/burstable/pod{UID}/{CID}\n"),
        )
        .unwrap();
        // More executable mappings than the cap holds.
        let line =
            "7f00000000-7f00001000 r-xp 00000000 00:2a 456 /usr/lib/x86_64-linux-gnu/libfoo.so.1\n";
        let maps = line.repeat(MAX_MAPS_BYTES as usize / line.len() + 10);
        std::fs::write(pid.join("maps"), &maps).unwrap();
        std::os::unix::fs::symlink("/usr/bin/app", pid.join("exe")).unwrap();

        let gen = pod_flags::generation_for_uid(Some(UID));
        let mut s = Store::default();
        let scan = scan_proc(&root, &HashSet::new(), Mode::Full, |g| g == gen);
        assert_eq!(scan.len(), 1);
        assert!(scan[0].1.truncated, "the cut is detected");
        assert!(
            scan[0]
                .1
                .sightings
                .iter()
                .any(|x| x.path.ends_with("libfoo.so.1")),
            "whole lines before the cut are still used"
        );
        apply_backfill(&mut s, scan, Instant::now(), wall());
        let pods = [(gen, pod_started(-5))];
        let probe = Some((at(0), true));
        for h in 1..4 {
            let b = &s.coverage_due(&pods, probe, Mode::Full, 0, "n1", at(h))[0];
            assert!(b.incomplete, "heartbeat {h} carries it");
        }

        // Under the cap: complete.
        std::fs::write(pid.join("maps"), line).unwrap();
        let mut s = Store::default();
        let scan = scan_proc(&root, &HashSet::new(), Mode::Full, |g| g == gen);
        assert!(!scan[0].1.truncated);
        apply_backfill(&mut s, scan, Instant::now(), wall());
        assert!(!s.coverage_due(&pods, probe, Mode::Full, 0, "n1", at(1))[0].incomplete);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stopped_container_gets_one_last_beat() {
        let mut s = Store::default();
        let probe = Some((at(0), true));
        s.coverage_due(&[(7, pod_started(1))], probe, Mode::Full, 0, "n1", at(2));
        let mut stopped = pod_started(1);
        stopped.containers.get_mut(CID).unwrap().running = false;
        let beats = s.coverage_due(&[(7, stopped.clone())], probe, Mode::Full, 4, "n1", at(3));
        assert_eq!(beats.len(), 1);
        assert!(beats[0].ended);
        assert_eq!(
            beats[0].events_dropped, 4,
            "drops before it stopped are still reported"
        );
        assert_eq!(
            (beats[0].heartbeat_at, beats[0].tracking_since),
            (at(3), at(1))
        );
        assert!(s
            .coverage_due(&[(7, stopped)], probe, Mode::Full, 4, "n1", at(4))
            .is_empty());
    }

    #[test]
    fn origins_classify_and_the_most_suspicious_sighting_wins() {
        assert_eq!(
            classify(OVERLAYFS_MAGIC, 1, UPPER_NO, "/usr/bin/app"),
            Origin::Image
        );
        assert_eq!(
            classify(OVERLAYFS_MAGIC, 1, UPPER_YES, "/tmp/x"),
            Origin::WritableLayer
        );
        assert_eq!(
            classify(OVERLAYFS_MAGIC, 1, UPPER_UNKNOWN, "/x"),
            Origin::Unknown
        );
        assert_eq!(
            classify(0xEF53, 1, UPPER_UNKNOWN, "/data/x"),
            Origin::OtherFs
        );
        assert_eq!(classify(0x0102_1994, 0, 0, "/memfd:payload"), Origin::Memfd);
        assert_eq!(classify(0x0102_1994, 0, 0, "/tmp/x"), Origin::Deleted);
        assert_eq!(
            classify(OVERLAYFS_MAGIC, 0, UPPER_YES, "/memfd:x"),
            Origin::Deleted
        );

        assert_eq!(
            proc_path_origin("/memfd:x (deleted)"),
            Some(("/memfd:x".to_string(), Origin::Memfd))
        );
        assert_eq!(
            proc_path_origin("/tmp/dropper (deleted)"),
            Some(("/tmp/dropper".to_string(), Origin::Deleted))
        );
        assert_eq!(
            proc_path_origin("/usr/bin/app"),
            Some(("/usr/bin/app".to_string(), Origin::Unknown))
        );
        assert_eq!(proc_path_origin("[vdso]"), None);

        let t0 = Instant::now();
        let mut s = Store::default();
        let key = (7u32, CID.to_string());
        s.add(
            key.clone(),
            sg("exec", "/app/run".into(), "ebpf"),
            t0,
            wall(),
        );
        let (p, m) = s.due(t0, wall(), 10, |_| Some(pod_rt()));
        assert_eq!(p[0].origin, "image");
        s.mark_sent(&m, t0);
        // Another replica ran it after it was rewritten: re-posted at once.
        let mut w = sg("exec", "/app/run".into(), "ebpf");
        w.origin = Origin::WritableLayer;
        s.add(key.clone(), w, t0, wall());
        let (p, m) = s.due(t0, wall(), 10, |_| Some(pod_rt()));
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].origin, "writableLayer");
        s.mark_sent(&m, t0);
        // A less suspicious sighting never downgrades it.
        s.add(key, sg("exec", "/app/run".into(), "backfill"), t0, wall());
        assert!(s.due(t0, wall(), 10, |_| Some(pod_rt())).0.is_empty());
    }

    #[test]
    fn capacity_is_bounded_and_ebpf_wins_over_backfill() {
        let t0 = Instant::now();
        let mut s = Store::default();
        let key = (7u32, CID.to_string());
        for i in 0..MAX_ENTRIES_PER_CONTAINER + 5 {
            s.add(
                key.clone(),
                sg("lib", format!("/l/{i}"), "backfill"),
                t0,
                wall(),
            );
        }
        assert_eq!(s.stats.overflow, 5);
        s.add(key.clone(), sg("lib", "/l/0".into(), "ebpf"), t0, wall());
        let (posts, _) = s.due(t0, wall(), 10_000, |_| Some(pod_rt()));
        assert_eq!(
            posts.iter().find(|p| p.path == "/l/0").unwrap().source,
            "ebpf"
        );
    }

    #[test]
    fn backfill_walks_a_fake_proc() {
        let root = std::env::temp_dir().join(format!("kg-rt-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let pid = root.join("4242");
        std::fs::create_dir_all(&pid).unwrap();
        std::fs::write(
            pid.join("cgroup"),
            format!("0::/../kubepods/burstable/pod{UID}/{CID}\n"),
        )
        .unwrap();
        std::fs::write(
            pid.join("maps"),
            "1-2 r-xp 0 00:2a 1 /usr/bin/app\n3-4 r-xp 0 00:2a 2 /usr/lib/libz.so.1\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("/usr/bin/app", pid.join("exe")).unwrap();
        // A host process: ignored.
        let host = root.join("1");
        std::fs::create_dir_all(&host).unwrap();
        std::fs::write(host.join("cgroup"), "0::/init.scope\n").unwrap();

        let gen = pod_flags::generation_for_uid(Some(UID));
        let mut s = Store::default();
        let t0 = Instant::now();
        let n = backfill(&root, &mut s, Mode::Full, |g| g == gen, t0, wall());
        assert_eq!(n, 1);
        let (posts, _) = s.due(t0, wall(), 10, |_| Some(pod_rt()));
        let got: Vec<_> = posts
            .iter()
            .map(|p| (p.kind.as_str(), p.path.as_str(), p.source.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("exec", "/usr/bin/app", "backfill"),
                ("lib", "/usr/lib/libz.so.1", "backfill")
            ]
        );
        // Once per container.
        assert_eq!(
            backfill(&root, &mut s, Mode::Full, |g| g == gen, t0, wall()),
            0
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pod_runtime_maps_container_ids_to_names_and_digests() {
        use k8s_openapi::api::core::v1::{ContainerStatus, PodStatus};
        let mut pod = Pod {
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    name: "nginx".into(),
                    container_id: Some(format!("containerd://{CID}")),
                    image_id: "docker.io/library/nginx@sha256:0123456789012345678901234567890123456789012345678901234567890123".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        pod.metadata.uid = Some(UID.into());
        pod.metadata.name = Some("web-1".into());
        pod.metadata.namespace = Some("ns".into());
        let rt = pod_runtime(&pod, None).unwrap();
        assert_eq!(rt.workload_kind, "Pod");
        assert_eq!(rt.workload_name, "web-1");
        let c = &rt.containers[CID];
        assert_eq!(c.name, "nginx");
        assert!(c.digest.starts_with("sha256:0123"));
        assert!(!c.running, "no running state in this status");
    }
}
