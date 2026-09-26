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

/// What the broker needs to key a container's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRuntime {
    pub uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub workload_kind: String,
    pub workload_name: String,
    /// container id -> (container name, image digest or "")
    pub containers: HashMap<String, (String, String)>,
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
            let last = cs
                .last_state
                .as_ref()
                .and_then(|s| s.terminated.as_ref())
                .and_then(|t| t.container_id.as_deref());
            for raw in [cs.container_id.as_deref(), last].into_iter().flatten() {
                if let Some(id) = crate::container::parse_container_id(raw) {
                    containers.insert(id, (cs.name.clone(), digest.clone()));
                }
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
    /// Containers dropped as never attributable (the pod sandbox, a pod
    /// never tracked): later sightings, including the next backfill pass,
    /// are ignored instead of being held for another TTL. Forgotten with
    /// the pod.
    discarded: HashSet<ContainerKey>,
    pub stats: Stats,
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
        if self.discarded.contains(&key) {
            return;
        }
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

    pub fn mark_backfilled(&mut self, key: ContainerKey) {
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
            let running = pod.containers.contains_key(&key.1);
            let Some((container_name, digest)) = pod.containers.get(&key.1).cloned() else {
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
            self.containers.remove(&key);
            self.discarded.insert(key);
        }
        (posts, marks)
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
        self.discarded.retain(|key| resolve(key.0).is_some());
    }

    pub fn containers(&self) -> usize {
        self.containers.len()
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

/// One pass over `proc_root`: record, for every container not yet
/// backfilled whose pod is tracked, the executable and executable
/// mappings of each of its processes. Returns the containers backfilled.
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
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return 0;
    };
    let mut touched: HashSet<ContainerKey> = HashSet::new();
    for ent in dir.flatten() {
        let name = ent.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let base = proc_root.join(pid);
        let Ok(cg) = std::fs::read_to_string(base.join("cgroup")) else {
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
        if !store.needs_backfill(&key) && !touched.contains(&key) {
            continue;
        }
        let exe = std::fs::read_link(base.join("exe"))
            .ok()
            .and_then(|p| proc_path_origin(&p.to_string_lossy()));
        if let Some((path, origin)) = exe.clone() {
            store.add(key.clone(), backfilled("exec", path, origin), now, wall);
        }
        if mode == Mode::Full {
            if let Ok(maps) = std::fs::read_to_string(base.join("maps")) {
                let exe_path = exe.as_ref().map(|(p, _)| p.as_str());
                for (lib, origin) in exec_mappings(&maps, exe_path) {
                    store.add(key.clone(), backfilled("lib", lib, origin), now, wall);
                }
            }
        }
        touched.insert(key);
    }
    let n = touched.len();
    for key in touched {
        store.mark_backfilled(key);
    }
    n
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
                    let n = backfill(
                        Path::new("/proc"),
                        &mut store,
                        mode,
                        |g| resolve(g).is_some(),
                        Instant::now(),
                        Utc::now().naive_utc(),
                    );
                    if n > 0 {
                        debug!(containers = n, "runtime inventory: backfilled from /proc");
                    }
                }
                post_due(&mut store, &resolve).await;
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
        match crate::api_post_call(serde_json::json!(posts), "runtime/executables").await {
            Ok(()) => {
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
                ("nginx".to_string(), "sha256:ab".to_string()),
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
        let (name, digest) = &rt.containers[CID];
        assert_eq!(name, "nginx");
        assert!(digest.starts_with("sha256:0123"));
    }
}
