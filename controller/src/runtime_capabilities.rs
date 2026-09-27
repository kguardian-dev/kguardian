//! Capability use per container (#1533 P2-7), posted to the broker's
//! `runtime_capabilities`.
//!
//! The probe (`trace_runtime_capable` in `bpf/runtime_inventory.bpf.c`)
//! counts every capability check a container's tasks make, per (cgroup,
//! capability, flags: granted, probed), in the kernel map `cap_seen`, and sends an event
//! for the first one of each so userspace learns which container the
//! cgroup is. The eBPF poll loop snapshots the map's counts periodically
//! ([`CapMsg::Counts`]); this module turns snapshots into per-container
//! deltas (a count that went down means the LRU evicted and re-created
//! the entry, and the new count is all new), and posts the deltas.
//!
//! `CAP_OPT_NOAUDIT` checks (the kernel asking whether a task would be
//! privileged, not the task needing it) and runc's own setup are not
//! counted; see the probe.

use crate::runtime_inventory::{ContainerKey, PodRuntime, CONTAINER_NAME};
use chrono::NaiveDateTime;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One first sighting as the probe writes it. Keep in sync with `struct
/// cap_event`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapEventData {
    pub cgroup_id: u64,
    pub generation: u32,
    pub cap: u32,
    /// [`FLAG_GRANTED`] | [`FLAG_PROBED`].
    pub flags: u32,
    pub pid: u32,
    pub container: [u8; CONTAINER_NAME],
}

impl CapEventData {
    pub fn container_id(&self) -> Option<String> {
        let end = self
            .container
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.container.len());
        crate::early_capture::container_id_from_segment(&String::from_utf8_lossy(
            &self.container[..end],
        ))
    }
}

/// Keep in sync with `KG_CAP_*` in the probe.
pub const FLAG_GRANTED: u32 = 1;
/// A `CAP_OPT_NOAUDIT` check ("probed"): see the probe.
pub const FLAG_PROBED: u32 = 2;

/// `(cgroup id, capability, flags)`, the kernel map's key.
pub type CapMapKey = (u64, u32, u32);

/// What the eBPF poll loop sends.
#[derive(Clone)]
pub enum CapMsg {
    /// A first sighting (who the cgroup is).
    Event(CapEventData),
    /// Every entry of the kernel map and its cumulative count.
    Counts(Vec<(CapMapKey, u64)>),
}

/// How often the poll loop snapshots the counts.
pub const COUNTS_EVERY: Duration = Duration::from_secs(30);
/// An entry is re-posted at most this often while its container runs,
/// even with no new use: the broker keeps a capability while it is
/// reported, so one used once at startup is never pruned from a running
/// workload.
pub const CAP_REPOST: Duration = Duration::from_secs(60 * 60);

/// Capability names, by number (include/uapi/linux/capability.h).
const CAP_NAMES: [&str; 41] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

/// The name Kubernetes uses in `securityContext.capabilities` (no `CAP_`
/// prefix). A number this list does not know yet is `CAP_<n>`.
pub fn cap_name(cap: u32) -> String {
    CAP_NAMES
        .get(cap as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("CAP_{cap}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapEntry {
    first_seen: NaiveDateTime,
    last_seen: NaiveDateTime,
    /// Uses not yet posted.
    unsent: u64,
    sent_at: Option<Instant>,
}

/// One entry of a `/runtime/capabilities` POST.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapPost {
    pub pod_namespace: String,
    pub pod_name: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub image_digest: String,
    pub capability: String,
    pub granted: bool,
    /// A `CAP_OPT_NOAUDIT` check: the kernel asked whether the task was
    /// privileged. Kept apart from ordinary uses.
    pub probed: bool,
    /// Checks since the previous post of this entry.
    pub count: u64,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

/// Per-container capability use waiting to be posted.
#[derive(Debug, Default)]
pub struct CapStore {
    /// Which container a cgroup is, from first-sighting events.
    cgroups: HashMap<u64, ContainerKey>,
    /// The kernel count last applied, per map key.
    applied: HashMap<CapMapKey, u64>,
    entries: HashMap<(ContainerKey, u32, u32), CapEntry>,
}

/// A mark to apply after a successful POST: the key and how many uses it
/// carried.
pub type CapMark = ((ContainerKey, u32, u32), u64);

impl CapStore {
    /// A first sighting: learn the cgroup, open the entry. Its count comes
    /// with the next snapshot.
    pub fn event(
        &mut self,
        cgroup_id: u64,
        key: ContainerKey,
        cap: u32,
        flags: u32,
        wall: NaiveDateTime,
    ) {
        self.cgroups.insert(cgroup_id, key.clone());
        self.entries.entry((key, cap, flags)).or_insert(CapEntry {
            first_seen: wall,
            last_seen: wall,
            unsent: 0,
            sent_at: None,
        });
    }

    /// Apply a snapshot of the kernel counts. Entries whose cgroup is not
    /// known yet are left for the next snapshot (their count is applied
    /// in full then).
    pub fn counts(&mut self, snapshot: &[(CapMapKey, u64)], wall: NaiveDateTime) {
        for (mk, count) in snapshot {
            let Some(ck) = self.cgroups.get(&mk.0).cloned() else {
                continue;
            };
            let last = self.applied.get(mk).copied().unwrap_or(0);
            // Lower than last time: evicted and re-created, all new.
            let delta = if *count >= last { count - last } else { *count };
            self.applied.insert(*mk, *count);
            if delta == 0 {
                continue;
            }
            let e = self.entries.entry((ck, mk.1, mk.2)).or_insert(CapEntry {
                first_seen: wall,
                last_seen: wall,
                unsent: 0,
                sent_at: None,
            });
            e.unsent += delta;
            e.last_seen = e.last_seen.max(wall);
        }
    }

    /// Entries to post: new uses, never posted, or not posted for
    /// [`CAP_REPOST`] while the container still runs. Entries whose pod
    /// or container is not (yet) known are held.
    pub fn due<F>(&self, now: Instant, max: usize, resolve: F) -> (Vec<CapPost>, Vec<CapMark>)
    where
        F: Fn(u32) -> Option<PodRuntime>,
    {
        let mut posts = Vec::new();
        let mut marks = Vec::new();
        for (k, e) in &self.entries {
            if posts.len() >= max {
                break;
            }
            let ((generation, cid), cap, flags) = k;
            let Some(pod) = resolve(*generation) else {
                continue;
            };
            let Some(info) = pod.containers.get(cid) else {
                continue;
            };
            let due = e.unsent > 0
                || e.sent_at.is_none()
                || (info.running
                    && e.sent_at
                        .is_some_and(|t| now.saturating_duration_since(t) >= CAP_REPOST));
            if !due {
                continue;
            }
            posts.push(CapPost {
                pod_namespace: pod.namespace.clone(),
                pod_name: pod.pod_name.clone(),
                workload_kind: pod.workload_kind.clone(),
                workload_name: pod.workload_name.clone(),
                container_name: info.name.clone(),
                image_digest: info.digest.clone(),
                capability: cap_name(*cap),
                granted: flags & FLAG_GRANTED != 0,
                probed: flags & FLAG_PROBED != 0,
                count: e.unsent,
                first_seen: e.first_seen,
                last_seen: e.last_seen,
            });
            marks.push((k.clone(), e.unsent));
        }
        (posts, marks)
    }

    /// The broker accepted a POST: those uses are sent.
    pub fn mark_sent(&mut self, marks: &[CapMark], now: Instant) {
        for (k, n) in marks {
            if let Some(e) = self.entries.get_mut(k) {
                e.unsent = e.unsent.saturating_sub(*n);
                e.sent_at = Some(now);
            }
        }
    }

    /// Forget containers whose pod is gone once everything was sent.
    pub fn prune<F>(&mut self, resolve: F)
    where
        F: Fn(u32) -> Option<PodRuntime>,
    {
        self.entries
            .retain(|((g, _), _, _), e| resolve(*g).is_some() || e.unsent > 0);
        let live: std::collections::HashSet<ContainerKey> =
            self.entries.keys().map(|(k, _, _)| k.clone()).collect();
        self.cgroups
            .retain(|_, k| live.contains(k) || resolve(k.0).is_some());
        let cgroups = &self.cgroups;
        self.applied.retain(|mk, _| cgroups.contains_key(&mk.0));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_inventory::ContainerInfo;

    const CID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn wall(h: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(1_800_000_000 + h * 3600, 0)
            .unwrap()
            .naive_utc()
    }

    fn pod(running: bool) -> PodRuntime {
        PodRuntime {
            uid: "u".into(),
            namespace: "ns".into(),
            pod_name: "web-1".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            containers: HashMap::from([(
                CID.to_string(),
                ContainerInfo {
                    name: "app".into(),
                    digest: "sha256:ab".into(),
                    started_at: None,
                    running,
                },
            )]),
        }
    }

    #[test]
    fn names_follow_the_kernel_numbering() {
        assert_eq!(cap_name(0), "CHOWN");
        assert_eq!(cap_name(10), "NET_BIND_SERVICE");
        assert_eq!(cap_name(21), "SYS_ADMIN");
        assert_eq!(cap_name(40), "CHECKPOINT_RESTORE");
        assert_eq!(cap_name(41), "CAP_41");
    }

    #[test]
    fn event_layout_matches_the_kernel_struct() {
        assert_eq!(
            std::mem::size_of::<CapEventData>(),
            8 + 4 * 4 + CONTAINER_NAME
        );
        assert_eq!(std::mem::offset_of!(CapEventData, container), 24);
    }

    #[test]
    fn counts_become_deltas_and_survive_eviction() {
        let key: ContainerKey = (7, CID.to_string());
        let mut s = CapStore::default();
        // A snapshot before the event is held (cgroup unknown).
        s.counts(&[((99, 10, FLAG_GRANTED), 3)], wall(0));
        assert!(s.is_empty());
        s.event(99, key.clone(), 10, FLAG_GRANTED, wall(0));
        s.counts(&[((99, 10, FLAG_GRANTED), 3)], wall(1));
        let t0 = Instant::now();
        let (p, m) = s.due(t0, 100, |_| Some(pod(true)));
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].capability.as_str(), p[0].granted, p[0].count),
            ("NET_BIND_SERVICE", true, 3),
            "the whole count once the cgroup is known"
        );
        s.mark_sent(&m, t0);
        // 3 -> 5: two new uses.
        s.counts(&[((99, 10, FLAG_GRANTED), 5)], wall(2));
        let (p, m) = s.due(t0, 100, |_| Some(pod(true)));
        assert_eq!(p[0].count, 2);
        assert_eq!(p[0].last_seen, wall(2));
        s.mark_sent(&m, t0);
        // Evicted and re-created at 1: one new use, not a negative one.
        s.counts(&[((99, 10, FLAG_GRANTED), 1)], wall(3));
        assert_eq!(s.due(t0, 100, |_| Some(pod(true))).0[0].count, 1);
    }

    #[test]
    fn unchanged_entries_are_reposted_hourly_while_running_only() {
        let key: ContainerKey = (7, CID.to_string());
        let mut s = CapStore::default();
        s.event(99, key, 21, 0, wall(0));
        let t0 = Instant::now();
        let (p, m) = s.due(t0, 100, |_| Some(pod(true)));
        assert_eq!((p.len(), p[0].count, p[0].granted), (1, 0, false));
        s.mark_sent(&m, t0);
        assert!(s
            .due(t0 + Duration::from_secs(60), 100, |_| Some(pod(true)))
            .0
            .is_empty());
        assert_eq!(s.due(t0 + CAP_REPOST, 100, |_| Some(pod(true))).0.len(), 1);
        assert!(
            s.due(t0 + CAP_REPOST, 100, |_| Some(pod(false)))
                .0
                .is_empty(),
            "a stopped container is not kept alive"
        );
    }

    #[test]
    fn unknown_pods_are_held_and_a_failed_post_keeps_the_uses() {
        let key: ContainerKey = (7, CID.to_string());
        let mut s = CapStore::default();
        s.event(99, key, 12, FLAG_GRANTED, wall(0));
        s.counts(&[((99, 12, FLAG_GRANTED), 4)], wall(0));
        let t0 = Instant::now();
        assert!(s.due(t0, 100, |_| None).0.is_empty(), "held");
        // Due, but the POST fails: nothing marked, the 4 uses are posted
        // next time.
        let (p, _) = s.due(t0, 100, |_| Some(pod(true)));
        assert_eq!(p[0].count, 4);
        assert_eq!(s.due(t0, 100, |_| Some(pod(true))).0[0].count, 4);
    }
}
