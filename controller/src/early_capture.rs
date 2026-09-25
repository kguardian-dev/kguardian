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

/// How long a pending cgroup may wait for its pod to be registered.
///
/// The sandbox (pause) cgroup is created before the image pull, so this
/// has to outlast a slow pull; the app container's own cgroup is created
/// right before it starts and is normally attributed within one resync.
/// A cgroup that belongs to a pod kube-guardian never registers (an
/// excluded namespace, a non-containerd runtime, a static pod whose
/// mirror UID differs) is dropped when this expires.
pub const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

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
fn container_id_from_segment(seg: &str) -> Option<String> {
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

#[derive(Debug)]
struct Entry {
    /// `None` until the cgroup's mkdir event has arrived. The pending
    /// syscall events travel on a different ring buffer, so they can be
    /// read first.
    identity: Option<CgroupIdentity>,
    first_seen: Instant,
    attributed_at: Option<Instant>,
    buffered: BTreeSet<u32>,
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
    pub syscalls_attributed: u64,
    pub events_dropped_full: u64,
}

/// The userspace half of startup capture. See the module docs.
#[derive(Debug)]
pub struct PendingCapture {
    entries: HashMap<u64, Entry>,
    ttl: Duration,
    linger: Duration,
    max: usize,
    pub stats: PendingStats,
}

impl Default for PendingCapture {
    fn default() -> Self {
        Self::new(PENDING_TTL, ATTRIBUTED_LINGER, MAX_TRACKED_CGROUPS)
    }
}

impl PendingCapture {
    pub fn new(ttl: Duration, linger: Duration, max: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            linger,
            max,
            stats: PendingStats::default(),
        }
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

    /// A cgroup was created under kubepods. Returns `Some(id)` when the
    /// kernel's pending mark should be deleted straight away because
    /// nothing in this cgroup can ever be attributed to a container: it
    /// is not a pod cgroup, or it is the pod-level cgroup (which holds no
    /// tasks under cgroup v2).
    pub fn cgroup_created(&mut self, cgroup_id: u64, path: &str, now: Instant) -> Option<u64> {
        let identity = match parse_kubepods_cgroup_path(path) {
            Some(id) if id.container_id.is_some() => id,
            _ => {
                self.entries.remove(&cgroup_id);
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
            .or_insert_with(|| Entry {
                identity: None,
                first_seen: now,
                attributed_at: None,
                buffered: BTreeSet::new(),
            })
            .identity = Some(identity);
        None
    }

    /// A syscall from a pending cgroup (already deduplicated in-kernel
    /// per cgroup and syscall).
    pub fn pending_syscall(&mut self, cgroup_id: u64, syscall: u32, now: Instant) {
        if !self.has_room_for(cgroup_id) {
            self.stats.events_dropped_full += 1;
            return;
        }
        self.entries
            .entry(cgroup_id)
            .or_insert_with(|| Entry {
                identity: None,
                first_seen: now,
                attributed_at: None,
                buffered: BTreeSet::new(),
            })
            .buffered
            .insert(syscall);
    }

    /// Attribute what can be attributed, retire what is finished or
    /// expired. `resolve` maps a pod UID to the registered pod, or `None`
    /// while the pod watcher has not registered it (or never will).
    pub fn attribute<P, F>(&mut self, now: Instant, mut resolve: F) -> Attribution<P>
    where
        F: FnMut(&str) -> Option<P>,
    {
        let mut out = Attribution {
            flush: Vec::new(),
            forget: Vec::new(),
            expired: 0,
        };
        let mut retire = Vec::new();
        for (&cgroup_id, entry) in self.entries.iter_mut() {
            let pod = entry
                .identity
                .as_ref()
                .and_then(|identity| resolve(&identity.pod_uid));
            match (pod, entry.identity.as_ref()) {
                (Some(pod), Some(identity)) => {
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
                        retire.push(cgroup_id);
                    }
                }
                _ => {
                    if entry.attributed_at.is_none()
                        && now.saturating_duration_since(entry.first_seen) >= self.ttl
                    {
                        out.expired += 1;
                        self.stats.cgroups_expired += 1;
                        retire.push(cgroup_id);
                    } else if entry.attributed_at.is_some() {
                        // The pod was found once and has since left the
                        // container map (deleted). Nothing more will
                        // resolve; stop capturing.
                        retire.push(cgroup_id);
                    }
                }
            }
        }
        for id in retire {
            self.entries.remove(&id);
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

    fn resolver(uid: &str) -> Option<&'static str> {
        (uid == UID).then_some("ns/pod")
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
        let a = pc.attribute(t0 + Duration::from_secs(1), |_| None::<&str>);
        assert!(a.flush.is_empty() && a.forget.is_empty());

        // Registered: everything buffered flushes to it, once.
        let a = pc.attribute(t0 + Duration::from_secs(2), resolver);
        assert_eq!(a.flush.len(), 1);
        assert_eq!(a.flush[0].pod, "ns/pod");
        assert_eq!(a.flush[0].cgroup_id, 42);
        assert_eq!(a.flush[0].identity, ident(Some(CID)).unwrap());
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59, 155, 157, 165]),);
        assert!(a.forget.is_empty(), "lingers after the first flush");

        let a = pc.attribute(t0 + Duration::from_secs(3), resolver);
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
        let a = pc.attribute(t0, resolver);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([59, 272]));
    }

    #[test]
    fn late_syscalls_during_linger_flush_then_the_mark_is_forgotten() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(PENDING_TTL, Duration::from_secs(30), 16);
        pc.cgroup_created(42, &container_path(), t0);
        pc.pending_syscall(42, 59, t0);
        pc.attribute(t0, resolver);

        pc.pending_syscall(42, 308, t0 + Duration::from_secs(5)); // setns, late
        let a = pc.attribute(t0 + Duration::from_secs(10), resolver);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([308]));
        assert!(a.forget.is_empty());

        let a = pc.attribute(t0 + Duration::from_secs(30), resolver);
        assert_eq!(a.forget, vec![42]);
        assert!(pc.is_empty());
    }

    #[test]
    fn a_pod_that_never_registers_expires_and_is_forgotten() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(Duration::from_secs(60), ATTRIBUTED_LINGER, 16);
        pc.cgroup_created(42, &container_path(), t0);
        pc.pending_syscall(42, 59, t0);

        let a = pc.attribute(t0 + Duration::from_secs(59), |_| None::<&str>);
        assert!(a.forget.is_empty());
        let a = pc.attribute(t0 + Duration::from_secs(60), |_| None::<&str>);
        assert_eq!(a.forget, vec![42]);
        assert_eq!(a.expired, 1);
        assert!(a.flush.is_empty(), "never attributed to anyone");
        assert_eq!(pc.stats.cgroups_expired, 1);
    }

    #[test]
    fn syscalls_without_a_mkdir_event_expire_rather_than_guess() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(Duration::from_secs(60), ATTRIBUTED_LINGER, 16);
        pc.pending_syscall(99, 59, t0);
        let a = pc.attribute(t0 + Duration::from_secs(1), resolver);
        assert!(a.flush.is_empty(), "no identity, no attribution");
        let a = pc.attribute(t0 + Duration::from_secs(60), resolver);
        assert_eq!(a.forget, vec![99]);
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
        pc.attribute(t0, resolver);
        let a = pc.attribute(t0 + Duration::from_secs(1), |_| None::<&str>);
        assert_eq!(a.forget, vec![42]);
        assert_eq!(a.expired, 0);
    }

    #[test]
    fn two_containers_of_one_pod_attribute_separately() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::default();
        let sandbox = format!("/kubepods/burstable/pod{UID}/{}", "a".repeat(64));
        pc.cgroup_created(1, &sandbox, t0);
        pc.cgroup_created(2, &container_path(), t0);
        pc.pending_syscall(1, 34, t0); // pause
        pc.pending_syscall(2, 59, t0);
        let mut a = pc.attribute(t0, resolver);
        a.flush.sort_by_key(|f| f.cgroup_id);
        assert_eq!(a.flush.len(), 2);
        assert_eq!(a.flush[0].syscalls, BTreeSet::from([34]));
        assert_eq!(a.flush[1].syscalls, BTreeSet::from([59]));
        assert_eq!(a.flush[1].identity.container_id.as_deref(), Some(CID));
    }

    #[test]
    fn capacity_is_bounded_and_overflow_is_counted() {
        let t0 = Instant::now();
        let mut pc = PendingCapture::new(PENDING_TTL, ATTRIBUTED_LINGER, 2);
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
