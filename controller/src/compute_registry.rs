//! Per-container identity, keyed by cgroup id: the registry behind the
//! compute sampler, the scheduler-contention probe and seccomp denial
//! attribution.
//!
//! Three readers, switched independently. `seccomp_denial` is the one
//! that is not about compute at all: a `hostNetwork` pod shares the
//! node's network namespace with every other one, so the netns inode
//! names none of them and the cgroup id is the only identifier left
//! that is 1:1 with a container. `main.rs` therefore builds this
//! registry when EITHER the gauges or denial capture is on
//! (`seccomp_denial::needs_container_registry`); only the sampler
//! subscribes to the registration events below.
//!
//! The netns `ContainerMap` (models.rs) is per pod and keyed by the
//! network-namespace inode; that is the right key for traffic and
//! syscalls and the wrong one for CPU accounting, where the scheduler
//! thinks in tasks and cgroups and limits are per container. This is the
//! parallel, per-container registry described in the design (D1): one
//! [`ContainerCompute`] per container, keyed by the 64-bit cgroup id that
//! `bpf_get_current_cgroup_id()` yields in BPF and `name_to_handle_at`
//! yields in userspace.
//!
//! Two tiers of entry:
//!
//! * **sampled** — read every tick, announced to the BPF
//!   `tracked_cgroups` map, eligible as a victim;
//! * **identity-only** — pods opted out with `kguardian.dev/compute:
//!   "off"` (design D9). Never sampled, never tracked, but blame
//!   resolution consults them before the cgroup index so an opted-out
//!   bully is still named `ns/pod/container` rather than `pod:<uid8>`.
//!
//! Locking: a single `std::sync::RwLock` around a plain map, taken only
//! for synchronous, allocation-light operations. Every read returns an
//! owned `Arc` or a `Vec` snapshot, so no guard can outlive the call and
//! nothing here can be held across an `.await` — the hazard `clippy.toml`
//! guards the DashMap-based `ContainerMap` against does not arise.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::broadcast;
use tracing::debug;

/// Requests and limits per container, captured from the pod spec at
/// registration so the broker never needs the API server to normalise a
/// gauge. `None` means unset in the spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceSpec {
    pub cpu_request_millis: Option<u64>,
    pub cpu_limit_millis: Option<u64>,
    pub memory_request_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
}

/// One container's compute identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerCompute {
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub container_name: String,
    pub container_id: String,
    pub pid: u32,
    /// Relative to the cgroup root, no leading slash.
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub resources: ResourceSpec,
    pub node: String,
}

impl ContainerCompute {
    /// `<pod_uid>/<container_name>` — the broker's primary key.
    pub fn container_uid(&self) -> String {
        format!("{}/{}", self.pod_uid, self.container_name)
    }
}

/// Registration events for the BPF `tracked_cgroups` map. Only sampled
/// container cgroups are announced; identity-only entries never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeRegistration {
    Added { cgroup_id: u64 },
    Removed { cgroup_id: u64 },
}

/// Which tier a container is registered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Sampled,
    IdentityOnly,
}

#[derive(Default)]
struct Inner {
    /// Sampled containers, keyed by cgroup id.
    containers: HashMap<u64, Arc<ContainerCompute>>,
    /// Opted-out containers, keyed by cgroup id: identity for blame only.
    identity: HashMap<u64, Arc<ContainerCompute>>,
    /// pod_uid -> its containers, for `remove_pod` and the by-name lookups.
    by_pod: HashMap<String, PodEntry>,
}

struct PodEntry {
    /// When the pod was first registered. The resync prune only retires
    /// pods registered BEFORE its LIST was taken, so a pod the watch
    /// registered during the (serial, containerd-bound) resync walk is
    /// not pruned and re-registered a minute later.
    since: Instant,
    ids: Vec<(u64, Tier)>,
}

/// Registry of every container cgroup this node knows about.
pub struct ComputeRegistry {
    inner: RwLock<Inner>,
    events: broadcast::Sender<ComputeRegistration>,
    /// Pods the watcher tried to register (eligible: on-node, ready,
    /// not excluded). Drives the sampler's startup self-check: eligible
    /// pods seen but an empty registry means resolution is broken.
    eligible_seen: AtomicU64,
    first_eligible: Mutex<Option<Instant>>,
}

pub type ComputeMap = Arc<ComputeRegistry>;

/// Capacity of the registration channel. A receiver that falls further
/// behind than this sees `Lagged` and must resync from `containers()`;
/// the sampler does exactly that.
const EVENT_CAPACITY: usize = 4096;

impl Default for ComputeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeRegistry {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            inner: RwLock::new(Inner::default()),
            events,
            eligible_seen: AtomicU64::new(0),
            first_eligible: Mutex::new(None),
        }
    }

    /// The pod watcher saw a pod it would sample (before trying to
    /// resolve its cgroups).
    pub fn note_eligible_pod(&self) {
        self.eligible_seen.fetch_add(1, Ordering::Relaxed);
        let mut first = self
            .first_eligible
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        first.get_or_insert_with(Instant::now);
    }

    pub fn eligible_pods_seen(&self) -> u64 {
        self.eligible_seen.load(Ordering::Relaxed)
    }

    pub fn first_eligible_at(&self) -> Option<Instant> {
        *self
            .first_eligible
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert (or replace) a sampled container, keyed by cgroup id.
    /// Idempotent: re-registering the same cgroup id emits no event, so
    /// the 60 s pod resync does not churn the BPF map. A container whose
    /// cgroup id changed (restart → new scope) is announced as a fresh
    /// `Added`, and its previous id is retired with `Removed`. An
    /// identity-only entry for the same container (opt-out annotation
    /// removed) is promoted.
    pub fn insert_container(&self, c: ContainerCompute) {
        self.insert(c, Tier::Sampled);
    }

    /// Insert (or replace) an identity-only container: never sampled,
    /// never tracked, but nameable as a culprit. A sampled entry for the
    /// same container (opt-out annotation added) is demoted and retired
    /// from the BPF map.
    pub fn insert_identity_only(&self, c: ContainerCompute) {
        self.insert(c, Tier::IdentityOnly);
    }

    fn insert(&self, c: ContainerCompute, tier: Tier) {
        let mut events = Vec::new();
        {
            let mut g = self.write();
            // Retire every other entry for the same container name (a
            // restart, or a tier change).
            let stale: Vec<(u64, Tier)> = g
                .by_pod
                .get(&c.pod_uid)
                .map(|entry| {
                    entry
                        .ids
                        .iter()
                        .copied()
                        .filter(|(id, t)| {
                            let same_name = match t {
                                Tier::Sampled => g.containers.get(id),
                                Tier::IdentityOnly => g.identity.get(id),
                            }
                            .is_some_and(|old| old.container_name == c.container_name);
                            same_name && (*id != c.cgroup_id || *t != tier)
                        })
                        .collect()
                })
                .unwrap_or_default();
            for (id, t) in &stale {
                match t {
                    Tier::Sampled => {
                        g.containers.remove(id);
                        events.push(ComputeRegistration::Removed { cgroup_id: *id });
                    }
                    Tier::IdentityOnly => {
                        g.identity.remove(id);
                    }
                }
            }
            let ids = &mut g
                .by_pod
                .entry(c.pod_uid.clone())
                .or_insert_with(|| PodEntry {
                    since: Instant::now(),
                    ids: Vec::new(),
                })
                .ids;
            ids.retain(|x| !stale.contains(x));
            if !ids.contains(&(c.cgroup_id, tier)) {
                ids.push((c.cgroup_id, tier));
                if tier == Tier::Sampled {
                    events.push(ComputeRegistration::Added {
                        cgroup_id: c.cgroup_id,
                    });
                }
            }
            let entry = Arc::new(c);
            match tier {
                Tier::Sampled => g.containers.insert(entry.cgroup_id, entry),
                Tier::IdentityOnly => g.identity.insert(entry.cgroup_id, entry),
            };
        }
        for e in events {
            let _ = self.events.send(e);
        }
    }

    /// Remove a pod and every container registered under it, in either
    /// tier.
    pub fn remove_pod(&self, pod_uid: &str) {
        let removed: Vec<(u64, Tier)> = {
            let mut g = self.write();
            let ids = g.by_pod.remove(pod_uid).map(|e| e.ids).unwrap_or_default();
            for (id, t) in &ids {
                match t {
                    Tier::Sampled => g.containers.remove(id),
                    Tier::IdentityOnly => g.identity.remove(id),
                };
            }
            ids
        };
        for (id, t) in removed {
            if t == Tier::Sampled {
                let _ = self
                    .events
                    .send(ComputeRegistration::Removed { cgroup_id: id });
            }
        }
    }

    /// Snapshot of every SAMPLED container; no guard is held on return.
    /// Identity-only entries are excluded by construction.
    pub fn containers(&self) -> Vec<Arc<ContainerCompute>> {
        self.read().containers.values().map(Arc::clone).collect()
    }

    /// Every registered pod uid, both tiers — used by the resync pass to
    /// retire pods that are gone from the API server without a watch
    /// event.
    pub fn pod_uids(&self) -> Vec<String> {
        self.read().by_pod.keys().cloned().collect()
    }

    /// Pod uids first registered before `t` — the only ones a resync
    /// prune based on a LIST taken at `t` may retire.
    pub fn pod_uids_registered_before(&self, t: Instant) -> Vec<String> {
        self.read()
            .by_pod
            .iter()
            .filter(|(_, e)| e.since < t)
            .map(|(uid, _)| uid.clone())
            .collect()
    }

    /// Containers registered in EITHER tier. An opted-out pod resolved
    /// into the identity tier is a success of the resolution path, so
    /// the startup self-check counts it.
    pub fn resolved_containers(&self) -> usize {
        let g = self.read();
        g.containers.len() + g.identity.len()
    }

    /// A sampled container by cgroup id.
    pub fn lookup_cgroup(&self, cgroup_id: u64) -> Option<Arc<ContainerCompute>> {
        self.read().containers.get(&cgroup_id).map(Arc::clone)
    }

    /// An identity-only (opted-out) container by cgroup id, for blame.
    pub fn lookup_identity(&self, cgroup_id: u64) -> Option<Arc<ContainerCompute>> {
        self.read().identity.get(&cgroup_id).map(Arc::clone)
    }

    /// The registered entry for a container by pod uid and name, in
    /// either tier, so the pod watcher can skip the containerd lookup
    /// for a container it has already resolved.
    pub fn container_for(
        &self,
        pod_uid: &str,
        container_name: &str,
    ) -> Option<(Arc<ContainerCompute>, Tier)> {
        let g = self.read();
        g.by_pod.get(pod_uid)?.ids.iter().find_map(|(id, t)| {
            let entry = match t {
                Tier::Sampled => g.containers.get(id),
                Tier::IdentityOnly => g.identity.get(id),
            }?;
            (entry.container_name == container_name).then(|| (Arc::clone(entry), *t))
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ComputeRegistration> {
        self.events.subscribe()
    }
}

/// Resolve the 64-bit cgroup id of `<root>/<rel_path>` with
/// `name_to_handle_at(2)`.
///
/// On cgroup v2 the file handle kernfs hands back is the node's 64-bit
/// id (`FILEID_KERNFS`, 8 bytes, native endian — little-endian on every
/// architecture this controller builds for), which is the same value
/// `bpf_get_current_cgroup_id()` returns in BPF and `bpftool cgroup
/// tree` prints. bpftrace's `cgroupid()` and systemd read it the same
/// way.
pub fn cgroup_id_for_path(root: &Path, rel_path: &str) -> io::Result<u64> {
    let full = root.join(rel_path.trim_start_matches('/'));
    cgroup_id_for_full_path(&full)
}

/// Same as [`cgroup_id_for_path`] for an absolute path.
pub fn cgroup_id_for_full_path(full: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(full.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;

    // struct file_handle { u32 handle_bytes; i32 handle_type; u8 f_handle[]; }
    // 8 bytes of header + up to MAX_HANDLE_SZ (128) of payload. The
    // kernfs handle is 8 bytes; over-allocating costs nothing and
    // avoids the EOVERFLOW round trip. Backed by `u64`s so the buffer
    // is at least as aligned as `file_handle` (4) and as the id (8).
    const MAX_HANDLE_SZ: usize = 128;
    let mut words = [0u64; (8 + MAX_HANDLE_SZ) / 8];
    // SAFETY: the buffer is at least the size of the header plus the
    // advertised payload and is 8-byte aligned; `handle_bytes` is
    // written before the call so the kernel knows how much payload
    // space follows, and the kernel writes at most that many bytes
    // after the 8-byte header.
    let rc = unsafe {
        let handle = words.as_mut_ptr() as *mut libc::file_handle;
        (*handle).handle_bytes = MAX_HANDLE_SZ as u32;
        let mut mount_id: libc::c_int = 0;
        libc::name_to_handle_at(libc::AT_FDCWD, c_path.as_ptr(), handle, &mut mount_id, 0)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `words` is a plain-old-data array; viewing it as bytes is
    // always valid.
    let buf: &[u8] = unsafe {
        std::slice::from_raw_parts(words.as_ptr() as *const u8, std::mem::size_of_val(&words))
    };
    let handle_bytes = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if handle_bytes < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file handle is {handle_bytes} bytes, expected at least 8"),
        ));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&buf[8..16]);
    Ok(u64::from_le_bytes(id))
}

/// The cgroup v2 path of `pid`, relative to the cgroup root with no
/// leading slash, from the `0::/...` line of `<host_proc>/<pid>/cgroup`.
pub fn cgroup_path_for_pid(host_proc: &Path, pid: u32) -> io::Result<String> {
    let raw = std::fs::read_to_string(host_proc.join(pid.to_string()).join("cgroup"))?;
    parse_proc_cgroup_v2(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no cgroup v2 (0::) entry for pid {pid}"),
        )
    })
}

/// Pure half of [`cgroup_path_for_pid`]: pick the unified-hierarchy line
/// out of a `/proc/<pid>/cgroup` body. On a hybrid (v1 + v2) host the
/// file has one line per v1 controller and a single `0::` line; on pure
/// v2 it is the only line.
pub fn parse_proc_cgroup_v2(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim().trim_start_matches('/').to_string())
}

/// Convert an OCI `linux.cgroupsPath` (what containerd's `Containers.Get`
/// spec carries) into a path relative to the cgroupfs root.
///
/// Two forms exist:
///
/// * systemd driver: `<slice>:<prefix>:<name>`, e.g.
///   `kubepods-burstable-pod<uid>.slice:cri-containerd:<cid>`. systemd
///   nests a slice under every `-`-separated prefix, so that becomes
///   `kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<cid>.scope`
///   (guaranteed pods have no QoS segment: `kubepods-pod<uid>.slice`).
/// * cgroupfs driver: a plain path, `/kubepods/burstable/pod<uid>/<cid>`,
///   used as-is.
///
/// This is deterministic and needs no filesystem access, which is what
/// makes it the preferred route: it is independent of the cgroup
/// namespace the controller happens to run in.
pub fn cgroups_path_to_cgroupfs(spec: &str) -> Option<String> {
    let s = spec.trim();
    if s.is_empty() {
        return None;
    }
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        [slice, prefix, name] => {
            let slice = slice.strip_suffix(".slice").unwrap_or(slice);
            if slice.is_empty() || name.is_empty() || slice.contains('/') {
                return None;
            }
            let mut dirs = Vec::new();
            let mut acc = String::new();
            for seg in slice.split('-') {
                if !acc.is_empty() {
                    acc.push('-');
                }
                acc.push_str(seg);
                dirs.push(format!("{acc}.slice"));
            }
            dirs.push(if prefix.is_empty() {
                format!("{name}.scope")
            } else {
                format!("{prefix}-{name}.scope")
            });
            Some(dirs.join("/"))
        }
        [path] => {
            let p = path.trim_matches('/');
            (!p.is_empty() && !p.contains("..")).then(|| p.to_string())
        }
        _ => None,
    }
}

/// Pull `linux.cgroupsPath` out of an OCI runtime spec (JSON).
pub fn parse_oci_cgroups_path(json: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(json)
        .ok()?
        .get("linux")?
        .get("cgroupsPath")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Resolve a container's host pid AND its OCI `linux.cgroupsPath` over
/// ONE containerd channel: `Tasks.Get` (the netns path's own
/// `PodInspect::get_pid`, same RPC ceiling) followed by
/// `Containers.Get` on the same connection, so a wedged daemon costs
/// one connect ceiling per container, not two. `None` pid means the
/// container is skipped; a `None` cgroups path falls through to the
/// filesystem search.
pub async fn resolve_pid_and_cgroups_path(container_id: &str) -> Option<(u32, Option<String>)> {
    use containerd_client::services::v1::{
        containers_client::ContainersClient, GetContainerRequest,
    };
    use containerd_client::tonic::Request;
    use containerd_client::with_namespace;

    let channel = crate::container::connect_containerd(
        &crate::container::containerd_sock(),
        crate::container::CONNECT_TIMEOUT,
    )
    .await?;
    let inspect = crate::PodInspect {
        container_id: Some(container_id.to_string()),
        ..Default::default()
    }
    .get_pid(channel.clone())
    .await;
    let pid = inspect.pid?;

    let mut client = ContainersClient::new(channel);
    let req = GetContainerRequest {
        id: container_id.to_string(),
    };
    let req = with_namespace!(req, "k8s.io");
    let spec = match tokio::time::timeout(crate::container::RPC_TIMEOUT, client.get(req)).await {
        Ok(Ok(r)) => r.into_inner().container.and_then(|c| c.spec),
        Ok(Err(e)) => {
            debug!(container_id, error = %e, "containerd Containers.Get failed");
            None
        }
        Err(_) => {
            debug!(container_id, "containerd Containers.Get timed out");
            None
        }
    };
    Some((pid, spec.and_then(|a| parse_oci_cgroups_path(&a.value))))
}

/// Bounded search under `<root>/kubepods*` for a cgroup directory whose
/// name contains `cid` (`cri-containerd-<cid>.scope`, `crio-<cid>.scope`
/// or a bare `<cid>` under the cgroupfs driver). Returns the path
/// relative to `root`.
pub fn search_cgroup_by_cid(
    root: &Path,
    cid: &str,
    max_depth: usize,
    limit: usize,
) -> Option<String> {
    if cid.is_empty() {
        return None;
    }
    let roots = std::fs::read_dir(root).ok()?;
    let mut stack: Vec<(std::path::PathBuf, usize)> = roots
        .flatten()
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("kubepods")
                && e.file_type().map(|t| t.is_dir()).unwrap_or(false)
        })
        .map(|e| (e.path(), 1))
        .collect();
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if visited >= limit {
            break;
        }
        visited += 1;
        if dir
            .file_name()
            .map(|n| n.to_string_lossy().contains(cid))
            .unwrap_or(false)
        {
            return dir
                .strip_prefix(root)
                .ok()
                .map(|p| p.to_string_lossy().to_string());
        }
        if depth >= max_depth {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    None
}

/// Depth bound for [`search_cgroup_by_cid`]: `kubepods.slice/<qos>.slice/<pod>.slice/<scope>` is 4.
pub const CGROUP_SEARCH_MAX_DEPTH: usize = 6;
/// Directory bound for one [`search_cgroup_by_cid`] call.
pub const CGROUP_SEARCH_LIMIT: usize = 20_000;

/// How a container's cgroup path was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupResolution {
    /// Relative to the cgroup root; verified to exist.
    pub path: String,
    /// `spec` (containerd OCI spec), `search` (cgroupfs walk) or `proc`
    /// (`/proc/<pid>/cgroup`).
    pub via: &'static str,
}

/// Every route failed. Carries what each one saw so the log line says
/// why, not just that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupResolveFailure {
    pub spec: String,
    pub search: String,
    pub proc: String,
}

impl fmt::Display for CgroupResolveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spec: {}; search: {}; proc: {}",
            self.spec, self.search, self.proc
        )
    }
}

/// Resolve a container's cgroup path in a way that does not depend on
/// the controller's own cgroup namespace.
///
/// The controller runs in a private cgroupns (containerd and CRI-O add
/// one unconditionally on cgroup v2), so `/proc/<pid>/cgroup` for any
/// OTHER pod's pid renders relative to the controller's cgroup —
/// `0::/../../../kubepods-burstable.slice/…` — which does not exist
/// under the host cgroupfs mount. Order of preference:
///
/// 1. the OCI spec's `linux.cgroupsPath` from containerd, converted
///    deterministically ([`cgroups_path_to_cgroupfs`]);
/// 2. a bounded search under `<root>/kubepods*` for the container id;
/// 3. `/proc/<pid>/cgroup`, only when it contains no `..`.
///
/// Whatever route wins, the directory must exist before an id is taken
/// from it.
pub fn resolve_container_cgroup(
    root: &Path,
    host_proc: &Path,
    pid: u32,
    cid: &str,
    spec_path: Option<&str>,
) -> Result<CgroupResolution, CgroupResolveFailure> {
    let exists = |rel: &str| root.join(rel).join("cpu.stat").exists() || root.join(rel).is_dir();

    let spec = match spec_path {
        None => "unavailable".to_string(),
        Some(raw) => match cgroups_path_to_cgroupfs(raw) {
            None => format!("unparseable cgroupsPath {raw:?}"),
            Some(rel) if exists(&rel) => {
                return Ok(CgroupResolution {
                    path: rel,
                    via: "spec",
                })
            }
            Some(rel) => format!("{rel} does not exist under {}", root.display()),
        },
    };

    let search = match search_cgroup_by_cid(root, cid, CGROUP_SEARCH_MAX_DEPTH, CGROUP_SEARCH_LIMIT)
    {
        Some(rel) if exists(&rel) => {
            return Ok(CgroupResolution {
                path: rel,
                via: "search",
            })
        }
        Some(rel) => format!("found {rel} but it vanished"),
        None => format!(
            "no directory containing {cid:?} under {}/kubepods*",
            root.display()
        ),
    };

    let proc_ = match cgroup_path_for_pid(host_proc, pid) {
        Err(e) => format!(
            "{}: {e}",
            host_proc.join(pid.to_string()).join("cgroup").display()
        ),
        Ok(rel) if rel.contains("..") => {
            format!("{rel:?} is relative to another cgroup namespace (contains ..)")
        }
        Ok(rel) if exists(&rel) => {
            return Ok(CgroupResolution {
                path: rel,
                via: "proc",
            })
        }
        Ok(rel) => format!("{rel:?} does not exist under {}", root.display()),
    };

    Err(CgroupResolveFailure {
        spec,
        search,
        proc: proc_,
    })
}

/// Parse a Kubernetes CPU quantity into millicores: `100m` → 100,
/// `1` → 1000, `2.5` → 2500, `0.5` → 500. Rejects anything else.
pub fn parse_cpu_millis(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    if let Some(m) = q.strip_suffix('m') {
        return m.parse::<u64>().ok();
    }
    // Whole or decimal cores.
    let (int_part, frac_part) = match q.split_once('.') {
        Some((i, f)) => (i, f),
        None => (q, ""),
    };
    if !int_part.chars().all(|c| c.is_ascii_digit()) || int_part.is_empty() && frac_part.is_empty()
    {
        return None;
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    // Up to three fractional digits are exact in millis; beyond that we
    // truncate, which is what the kubelet does when it rounds up to a
    // millicore for scheduling anyway.
    let mut millis = 0u64;
    let mut scale = 100u64;
    for c in frac_part.chars().take(3) {
        millis += u64::from(c.to_digit(10).unwrap_or(0)) * scale;
        scale /= 10;
    }
    whole.checked_mul(1000)?.checked_add(millis)
}

/// Parse a Kubernetes memory quantity into bytes: binary suffixes
/// (`Ki`/`Mi`/`Gi`/`Ti`/`Pi`/`Ei`), decimal suffixes (`k`/`M`/`G`/`T`/`P`/`E`),
/// exponent form (`1e6`) and plain integers. Decimal mantissas are
/// accepted (`1.5Gi`). Rejects anything else.
pub fn parse_memory_bytes(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    let split = q
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(q.len());
    let (num, suffix) = q.split_at(split);
    if num.is_empty() {
        return None;
    }
    let multiplier: f64 = match suffix {
        "" => 1.0,
        "Ki" => 1024.0,
        "Mi" => 1024.0 * 1024.0,
        "Gi" => 1024.0 * 1024.0 * 1024.0,
        "Ti" => 1024.0_f64.powi(4),
        "Pi" => 1024.0_f64.powi(5),
        "Ei" => 1024.0_f64.powi(6),
        "k" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "P" => 1e15,
        "E" => 1e18,
        "m" => 1e-3, // milli-bytes exist in the API; round down below.
        s if s.starts_with('e') || s.starts_with('E') => {
            let exp: i32 = s[1..].parse().ok()?;
            10f64.powi(exp)
        }
        _ => return None,
    };
    if num.matches('.').count() > 1 {
        return None;
    }
    // Exact path for the overwhelmingly common integer + binary suffix
    // case, so `128Mi` does not go through f64 at all.
    if !num.contains('.') && multiplier.fract() == 0.0 && multiplier >= 1.0 {
        let n: u64 = num.parse().ok()?;
        return n.checked_mul(multiplier as u64);
    }
    let n: f64 = num.parse().ok()?;
    let bytes = n * multiplier;
    if !bytes.is_finite() || bytes < 0.0 {
        return None;
    }
    Some(bytes.floor() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(uid: &str, name: &str, id: u64) -> ContainerCompute {
        ContainerCompute {
            pod_uid: uid.into(),
            namespace: "ns".into(),
            pod_name: "pod".into(),
            container_name: name.into(),
            container_id: format!("cid-{id}"),
            pid: 1,
            cgroup_path: format!("kubepods.slice/pod{uid}.slice/cri-containerd-{id}.scope"),
            cgroup_id: id,
            resources: ResourceSpec::default(),
            node: "n".into(),
        }
    }

    fn drain(rx: &mut broadcast::Receiver<ComputeRegistration>) -> Vec<ComputeRegistration> {
        let mut seen = Vec::new();
        while let Ok(e) = rx.try_recv() {
            seen.push(e);
        }
        seen
    }

    #[test]
    fn insert_lookup_remove_round_trip() {
        let r = ComputeRegistry::new();
        let mut rx = r.subscribe();
        r.insert_container(container("u1", "api", 10));
        r.insert_container(container("u1", "sidecar", 11));
        r.insert_container(container("u2", "web", 20));
        assert_eq!(r.lookup_cgroup(11).unwrap().container_name, "sidecar");
        assert_eq!(r.containers().len(), 3);
        let (c, tier) = r.container_for("u1", "sidecar").unwrap();
        assert_eq!((c.cgroup_id, tier), (11, Tier::Sampled));
        assert!(r.container_for("u1", "nope").is_none());
        let mut uids = r.pod_uids();
        uids.sort();
        assert_eq!(uids, vec!["u1", "u2"]);

        r.remove_pod("u1");
        assert!(r.lookup_cgroup(10).is_none());
        assert!(r.lookup_cgroup(11).is_none());
        assert!(r.lookup_cgroup(20).is_some());
        assert_eq!(r.pod_uids(), vec!["u2"]);

        assert_eq!(
            drain(&mut rx),
            vec![
                ComputeRegistration::Added { cgroup_id: 10 },
                ComputeRegistration::Added { cgroup_id: 11 },
                ComputeRegistration::Added { cgroup_id: 20 },
                ComputeRegistration::Removed { cgroup_id: 10 },
                ComputeRegistration::Removed { cgroup_id: 11 },
            ]
        );
    }

    #[test]
    fn reinsert_is_idempotent_and_restart_retires_old_id() {
        // The 60 s resync re-registers every pod; that must not churn
        // the BPF tracked_cgroups map.
        let r = ComputeRegistry::new();
        let mut rx = r.subscribe();
        r.insert_container(container("u1", "api", 10));
        r.insert_container(container("u1", "api", 10));
        assert_eq!(
            drain(&mut rx),
            vec![ComputeRegistration::Added { cgroup_id: 10 }]
        );
        // Container restarted: same name, new scope, new id.
        r.insert_container(container("u1", "api", 12));
        assert_eq!(
            drain(&mut rx),
            vec![
                ComputeRegistration::Removed { cgroup_id: 10 },
                ComputeRegistration::Added { cgroup_id: 12 },
            ]
        );
        assert!(r.lookup_cgroup(10).is_none());
        assert_eq!(r.containers().len(), 1);
    }

    #[test]
    fn identity_only_entries_are_nameable_but_never_sampled_or_tracked() {
        // Design D9: an opted-out pod is not sampled and not in
        // tracked_cgroups, yet it can still be named as a culprit with
        // its full identity.
        let r = ComputeRegistry::new();
        let mut rx = r.subscribe();
        r.insert_identity_only(container("bully", "worker", 200));
        r.insert_identity_only(container("bully", "worker", 200));
        assert!(r.containers().is_empty(), "not sampled");
        assert!(drain(&mut rx).is_empty(), "not tracked");
        assert!(r.lookup_cgroup(200).is_none());
        let id = r.lookup_identity(200).unwrap();
        assert_eq!(id.container_uid(), "bully/worker");
        assert_eq!(
            r.resolved_containers(),
            1,
            "identity entries count as resolved"
        );
        assert_eq!(
            r.container_for("bully", "worker").map(|(_, t)| t),
            Some(Tier::IdentityOnly)
        );
        assert_eq!(r.pod_uids(), vec!["bully"]);

        // Removal clears it, silently.
        r.remove_pod("bully");
        assert!(r.lookup_identity(200).is_none());
        assert!(r.pod_uids().is_empty());
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn toggling_the_opt_out_moves_a_container_between_tiers() {
        let r = ComputeRegistry::new();
        let mut rx = r.subscribe();
        r.insert_container(container("u1", "api", 10));
        assert_eq!(
            drain(&mut rx),
            vec![ComputeRegistration::Added { cgroup_id: 10 }]
        );
        // Annotation added: demoted, retired from the BPF map.
        r.insert_identity_only(container("u1", "api", 10));
        assert_eq!(
            drain(&mut rx),
            vec![ComputeRegistration::Removed { cgroup_id: 10 }]
        );
        assert!(r.lookup_cgroup(10).is_none());
        assert!(r.lookup_identity(10).is_some());
        assert_eq!(r.containers().len(), 0);
        // Annotation removed: promoted, tracked again.
        r.insert_container(container("u1", "api", 10));
        assert_eq!(
            drain(&mut rx),
            vec![ComputeRegistration::Added { cgroup_id: 10 }]
        );
        assert!(r.lookup_identity(10).is_none());
        assert_eq!(r.containers().len(), 1);
    }

    #[test]
    fn registration_time_gates_the_resync_prune() {
        let r = ComputeRegistry::new();
        r.insert_container(container("old", "c", 1));
        let listed_at = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        r.insert_container(container("new", "c", 2));
        // Re-inserting keeps the ORIGINAL registration time.
        r.insert_container(container("old", "c", 1));
        assert_eq!(r.pod_uids_registered_before(listed_at), vec!["old"]);
    }

    #[test]
    fn eligible_pod_counter_and_first_seen() {
        let r = ComputeRegistry::new();
        assert_eq!(r.eligible_pods_seen(), 0);
        assert!(r.first_eligible_at().is_none());
        r.note_eligible_pod();
        r.note_eligible_pod();
        assert_eq!(r.eligible_pods_seen(), 2);
        assert!(r.first_eligible_at().is_some());
    }

    #[test]
    fn systemd_cgroups_path_expands_for_every_qos_class() {
        assert_eq!(
            cgroups_path_to_cgroupfs(
                "kubepods-burstable-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice:cri-containerd:abc123"
            )
            .as_deref(),
            Some(
                "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice/cri-containerd-abc123.scope"
            )
        );
        assert_eq!(
            cgroups_path_to_cgroupfs(
                "kubepods-besteffort-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice:cri-containerd:abc123"
            )
            .as_deref(),
            Some(
                "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice/cri-containerd-abc123.scope"
            )
        );
        // Guaranteed: no QoS segment.
        assert_eq!(
            cgroups_path_to_cgroupfs(
                "kubepods-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice:cri-containerd:abc123"
            )
            .as_deref(),
            Some(
                "kubepods.slice/kubepods-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice/cri-containerd-abc123.scope"
            )
        );
        // CRI-O prefix.
        assert_eq!(
            cgroups_path_to_cgroupfs("kubepods-burstable-podx.slice:crio:abc").as_deref(),
            Some("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podx.slice/crio-abc.scope")
        );
        // cgroupfs driver: as-is, no leading slash.
        assert_eq!(
            cgroups_path_to_cgroupfs(
                "/kubepods/burstable/pod3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab/abc123"
            )
            .as_deref(),
            Some("kubepods/burstable/pod3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab/abc123")
        );
        assert_eq!(cgroups_path_to_cgroupfs(""), None);
        assert_eq!(cgroups_path_to_cgroupfs("a:b"), None);
        assert_eq!(cgroups_path_to_cgroupfs("/../escape"), None);
        assert_eq!(
            parse_oci_cgroups_path(br#"{"ociVersion":"1.1.0","linux":{"cgroupsPath":"kubepods-podx.slice:cri-containerd:c1","resources":{}}}"#)
                .as_deref(),
            Some("kubepods-podx.slice:cri-containerd:c1")
        );
        assert_eq!(parse_oci_cgroups_path(b"{}"), None);
        assert_eq!(parse_oci_cgroups_path(b"not json"), None);
    }

    /// A fixture tree with a cgroupfs mount and a `/proc/<pid>/cgroup`
    /// rendered from inside another cgroup namespace (the `..` form).
    fn cgroupns_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, String) {
        let base = std::env::temp_dir().join(format!("kg-cgroupns-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("cgroup");
        let proc_ = base.join("proc");
        let scope = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope";
        std::fs::create_dir_all(root.join(scope)).unwrap();
        std::fs::write(root.join(scope).join("cpu.stat"), "usage_usec 1\n").unwrap();
        std::fs::create_dir_all(proc_.join("4242")).unwrap();
        std::fs::write(
            proc_.join("4242/cgroup"),
            "0::/../../../kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope\n",
        )
        .unwrap();
        (root, proc_, scope.to_string())
    }

    #[test]
    fn resolution_prefers_the_spec_then_the_search_and_rejects_dotdot_proc() {
        let (root, proc_, scope) = cgroupns_fixture("ok");
        // 1. spec wins when it converts to an existing directory.
        let r = resolve_container_cgroup(
            &root,
            &proc_,
            4242,
            "deadbeef",
            Some("kubepods-burstable-podabc.slice:cri-containerd:deadbeef"),
        )
        .unwrap();
        assert_eq!((r.path.as_str(), r.via), (scope.as_str(), "spec"));
        // 2. no spec: the search finds the scope by container id even
        //    though /proc renders the `..` form.
        let r = resolve_container_cgroup(&root, &proc_, 4242, "deadbeef", None).unwrap();
        assert_eq!((r.path.as_str(), r.via), (scope.as_str(), "search"));
        // 2b. a spec that does not exist on disk falls through to search.
        let r = resolve_container_cgroup(
            &root,
            &proc_,
            4242,
            "deadbeef",
            Some("kubepods-podabc.slice:cri-containerd:deadbeef"),
        )
        .unwrap();
        assert_eq!(r.via, "search");
        // 3. unknown cid and a `..` proc path: every route fails, and
        //    the failure names all three attempts.
        let e = resolve_container_cgroup(&root, &proc_, 4242, "nope", None).unwrap_err();
        assert_eq!(e.spec, "unavailable");
        assert!(e.search.contains("nope"), "{e}");
        assert!(e.proc.contains(".."), "{e}");
        // 3b. proc is accepted only when it has no `..` and exists.
        std::fs::write(proc_.join("4242/cgroup"), format!("0::/{scope}\n")).unwrap();
        let r = resolve_container_cgroup(&root, &proc_, 4242, "nope", None).unwrap();
        assert_eq!(r.via, "proc");
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn search_is_bounded_by_depth_and_scoped_to_kubepods() {
        let base = std::env::temp_dir().join(format!("kg-cgsearch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("system.slice/cri-containerd-abc.scope")).unwrap();
        std::fs::create_dir_all(base.join("kubepods.slice/a/b/c/d/e/f/cri-containerd-deep.scope"))
            .unwrap();
        std::fs::create_dir_all(base.join("kubepods/besteffort/podx/abc")).unwrap();
        // Not under kubepods*: never found.
        assert_eq!(
            search_cgroup_by_cid(&base, "abc", 6, 1000).as_deref(),
            Some("kubepods/besteffort/podx/abc")
        );
        assert_eq!(
            search_cgroup_by_cid(&base, "deep", 6, 1000),
            None,
            "beyond the depth bound"
        );
        assert_eq!(
            search_cgroup_by_cid(&base, "deep", 8, 1000).as_deref(),
            Some("kubepods.slice/a/b/c/d/e/f/cri-containerd-deep.scope")
        );
        assert_eq!(search_cgroup_by_cid(&base, "", 6, 1000), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn proc_cgroup_v2_line_is_picked_out_of_hybrid_and_pure_files() {
        let pure = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope\n";
        assert_eq!(
            parse_proc_cgroup_v2(pure).as_deref(),
            Some("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope")
        );
        let hybrid = "12:cpu,cpuacct:/kubepods/burstable/podabc/deadbeef\n\
                      3:memory:/kubepods/burstable/podabc/deadbeef\n\
                      0::/kubepods/burstable/podabc/deadbeef\n";
        assert_eq!(
            parse_proc_cgroup_v2(hybrid).as_deref(),
            Some("kubepods/burstable/podabc/deadbeef")
        );
        assert_eq!(parse_proc_cgroup_v2("12:cpu:/foo\n"), None);
        // Root cgroup.
        assert_eq!(parse_proc_cgroup_v2("0::/\n").as_deref(), Some(""));
    }

    #[test]
    fn cpu_quantities_parse_to_millis() {
        assert_eq!(parse_cpu_millis("100m"), Some(100));
        assert_eq!(parse_cpu_millis("1"), Some(1000));
        assert_eq!(parse_cpu_millis("2.5"), Some(2500));
        assert_eq!(parse_cpu_millis("0.5"), Some(500));
        assert_eq!(parse_cpu_millis(".25"), Some(250));
        assert_eq!(parse_cpu_millis("1.2345"), Some(1234));
        assert_eq!(parse_cpu_millis(" 250m "), Some(250));
        assert_eq!(parse_cpu_millis(""), None);
        assert_eq!(parse_cpu_millis("abc"), None);
        assert_eq!(parse_cpu_millis("1Gi"), None);
    }

    #[test]
    fn memory_quantities_parse_to_bytes() {
        assert_eq!(parse_memory_bytes("128Mi"), Some(128 * 1024 * 1024));
        assert_eq!(parse_memory_bytes("1Gi"), Some(1 << 30));
        assert_eq!(parse_memory_bytes("1G"), Some(1_000_000_000));
        assert_eq!(parse_memory_bytes("1000000"), Some(1_000_000));
        assert_eq!(parse_memory_bytes("512Ki"), Some(512 * 1024));
        assert_eq!(parse_memory_bytes("1.5Gi"), Some(3 * (1 << 29)));
        assert_eq!(parse_memory_bytes("1e6"), Some(1_000_000));
        assert_eq!(parse_memory_bytes("2Ti"), Some(2 << 40));
        assert_eq!(parse_memory_bytes(""), None);
        assert_eq!(parse_memory_bytes("Mi"), None);
        assert_eq!(parse_memory_bytes("1Xi"), None);
        assert_eq!(parse_memory_bytes("1.2.3"), None);
    }

    /// Verifies the `name_to_handle_at` id against `stat` on the cgroup
    /// root itself. kernfs ids carry the inode number in their low 32
    /// bits (with a generation above on 32-bit `ino_t`, and the whole id
    /// as the inode on 64-bit), so the low bits must agree either way.
    /// Skipped, not failed, on a host without cgroup v2.
    #[test]
    fn cgroup_id_matches_stat_inode_low_bits_on_cgroup_v2() {
        use std::os::unix::fs::MetadataExt;
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.controllers").exists() {
            eprintln!("skipping: /sys/fs/cgroup is not cgroup v2 here");
            return;
        }
        let id = match cgroup_id_for_path(root, "") {
            Ok(id) => id,
            Err(e)
                if e.raw_os_error() == Some(libc::EPERM)
                    || e.raw_os_error() == Some(libc::EACCES) =>
            {
                eprintln!("skipping: name_to_handle_at not permitted here ({e})");
                return;
            }
            Err(e) => panic!("name_to_handle_at on cgroup root: {e}"),
        };
        let ino = std::fs::metadata(root).unwrap().ino();
        assert_ne!(id, 0, "cgroup root id must not be 0");
        assert_eq!(
            id & 0xffff_ffff,
            ino & 0xffff_ffff,
            "handle id {id:#x} vs stat ino {ino:#x}"
        );
        // And a child, when one exists, gets a different id.
        if let Some(child) = std::fs::read_dir(root)
            .unwrap()
            .flatten()
            .find(|e| e.path().is_dir())
        {
            let rel = child.file_name().to_string_lossy().to_string();
            let cid = cgroup_id_for_path(root, &rel).unwrap();
            let cino = std::fs::metadata(child.path()).unwrap().ino();
            assert_ne!(cid, id);
            assert_eq!(cid & 0xffff_ffff, cino & 0xffff_ffff);
        }
    }

    #[test]
    fn cgroup_id_for_missing_path_is_an_error() {
        assert!(cgroup_id_for_path(Path::new("/nonexistent-kg"), "x").is_err());
    }
}
