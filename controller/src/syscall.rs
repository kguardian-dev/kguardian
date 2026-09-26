use crate::capture_tiers::{native_scmp_arch, ResolvedTiers};
use crate::early_capture::{
    filter_for_tier, known_pod_containers, resolve_pod_state, PendingCapture, StartupCaptureConfig,
    SYSCALL_EVENT_PENDING,
};
use crate::models::{lookup_pod, ContainerMap};
use chrono::Utc;
use libseccomp::ScmpSyscall;
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info};

use crate::{api_post_call, Error, PodInspect, SyscallData};

pub mod sycallprobe {
    include!(concat!(env!("OUT_DIR"), "/syscall.skel.rs"));
}

/// Upper bound on pods whose syscall sets are held in memory, matching the
/// capacity of the caches this replaced.
const MAX_POD_SETS: usize = 10_000;

/// One pod incarnation's syscall set and what was last posted for it.
#[derive(Debug, Default)]
struct PodSet {
    name: String,
    syscalls: HashSet<String>,
    last_sent: HashSet<String>,
    touched: u64,
}

/// Syscall sets per pod INCARNATION (pod UID), posted under the pod name.
///
/// These used to be keyed by pod name, so a pod deleted and recreated
/// under the same name (bare pods, StatefulSets) shared one set with its
/// predecessor: anything credited to the old pod after the new one
/// existed — the old containers' teardown, or host processes in a
/// recycled netns that still resolved to the old pod's stale entry —
/// was merged into the new pod's profile. The broker row is keyed by name
/// only, so the name has exactly one CURRENT incarnation: the newest one
/// seen (by creation time; a first-seen UID wins a tie). An older
/// incarnation's events are dropped once a newer one exists, and its set
/// is discarded, so the row carries the current pod's own set.
#[derive(Debug, Default)]
pub struct SyscallSets {
    pods: HashMap<String, PodSet>,
    /// name -> (uid, created_unix) of the current incarnation.
    current: HashMap<String, (String, i64)>,
    /// UIDs superseded by a newer same-name pod; never current again.
    superseded: HashSet<String>,
    clock: u64,
}

/// What `SyscallSets::record` did with a syscall.
#[derive(Debug, PartialEq, Eq)]
pub enum Recorded {
    New,
    Duplicate,
    /// From an incarnation a newer same-name pod has superseded.
    Superseded,
}

impl SyscallSets {
    pub fn record(&mut self, uid: &str, name: &str, created_unix: i64, syscall: &str) -> Recorded {
        if self.superseded.contains(uid) {
            return Recorded::Superseded;
        }
        match self.current.get(name).cloned() {
            Some((cur, _)) if cur == uid => {}
            Some((cur, cur_created)) => {
                if created_unix < cur_created {
                    // Older than the current holder of the name.
                    self.superseded.insert(uid.to_string());
                    self.pods.remove(uid);
                    return Recorded::Superseded;
                }
                self.superseded.insert(cur.clone());
                self.pods.remove(&cur);
                self.current
                    .insert(name.to_string(), (uid.to_string(), created_unix));
            }
            None => {
                self.current
                    .insert(name.to_string(), (uid.to_string(), created_unix));
            }
        }
        self.clock += 1;
        let clock = self.clock;
        let set = self.pods.entry(uid.to_string()).or_insert_with(|| PodSet {
            name: name.to_string(),
            ..Default::default()
        });
        set.touched = clock;
        let new = set.syscalls.insert(syscall.to_string());
        self.evict_if_full();
        if new {
            Recorded::New
        } else {
            Recorded::Duplicate
        }
    }

    fn evict_if_full(&mut self) {
        if self.pods.len() <= MAX_POD_SETS {
            return;
        }
        if let Some(oldest) = self
            .pods
            .iter()
            .min_by_key(|(_, s)| s.touched)
            .map(|(uid, _)| uid.clone())
        {
            if let Some(set) = self.pods.remove(&oldest) {
                if self
                    .current
                    .get(&set.name)
                    .is_some_and(|(u, _)| *u == oldest)
                {
                    self.current.remove(&set.name);
                }
            }
        }
        if self.superseded.len() > MAX_POD_SETS {
            self.superseded.clear();
        }
    }

    /// (uid, name, snapshot) for every set that changed since it was last
    /// posted successfully.
    pub fn changed(&self) -> Vec<(String, String, HashSet<String>)> {
        self.pods
            .iter()
            .filter(|(_, s)| s.syscalls != s.last_sent)
            .map(|(uid, s)| (uid.clone(), s.name.clone(), s.syscalls.clone()))
            .collect()
    }

    /// Record a successful post. A set superseded meanwhile is gone and
    /// stays gone.
    pub fn mark_sent(&mut self, uid: &str, snapshot: HashSet<String>) {
        if let Some(s) = self.pods.get_mut(uid) {
            s.last_sent = snapshot;
        }
    }

    #[cfg(test)]
    fn set_of(&self, uid: &str) -> Option<&HashSet<String>> {
        self.pods.get(uid).map(|s| &s.syscalls)
    }
}

static SYSCALL_SETS: std::sync::LazyLock<std::sync::Mutex<SyscallSets>> =
    std::sync::LazyLock::new(Default::default);

fn with_sets<T>(f: impl FnOnce(&mut SyscallSets) -> T) -> T {
    // A poisoned lock only means a panic elsewhere mid-update; the sets
    // are still usable.
    let mut guard = SYSCALL_SETS.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut guard)
}

/// One syscall event as the probe writes it. Keep in sync with `struct
/// data_t` in `bpf/syscall.bpf.c`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallEventData {
    pub inum: u64,
    pub sysnbr: u32,
    /// `early_capture::SYSCALL_EVENT_REGISTERED` or `_PENDING`.
    pub kind: u32,
    /// The calling task's cgroup v2 id — the container, where `inum`
    /// names only the pod.
    pub cgroup_id: u64,
    /// Registered path: generation of the pod owning the task's cgroup
    /// (`task_pod_generation` in the probe). 0 on the pending path.
    pub generation: u32,
    pub _pad: u32,
}

/// The pod a registered-path event belongs to: the netns's pod when the
/// task's cgroup is that pod's, otherwise a hostNetwork pod with the
/// task's generation (they all share the node's netns, whose entry names
/// only one of them). The probe already dropped every other case.
fn registered_event_pod(
    container_map: &ContainerMap,
    event: &SyscallEventData,
) -> Option<Arc<PodInspect>> {
    let pod = lookup_pod(container_map, event.inum)?;
    if crate::models::pod_flags::generation(pod.capture_flags) == event.generation {
        return Some(pod);
    }
    crate::early_capture::host_network_pod(event.generation)
}

/// How often buffered startup syscalls are checked against the pods the
/// watcher has registered.
const ATTRIBUTION_TICK: Duration = Duration::from_secs(1);

/// How often the startup-capture counters are logged.
const STATS_EVERY: Duration = Duration::from_secs(300);

/// Everything startup capture needs besides the syscall stream itself.
/// See `early_capture`.
pub struct StartupCapture {
    /// Cgroup creations from the `cgroup_events` ring buffer: id, path.
    pub cgroup_events: Receiver<(u64, String)>,
    /// Cgroup ids whose kernel pending mark the eBPF loop should delete.
    pub forget: Sender<u64>,
    /// The tier allowlists, to apply a pod's tier to syscalls the kernel
    /// captured before it knew the pod.
    pub tiers: ResolvedTiers,
    /// TTLs (`STARTUP_CAPTURE_*` env).
    pub config: StartupCaptureConfig,
}

/// Cap on forgets waiting for room in the channel to the eBPF loop.
/// Only reachable if that loop stops draining; beyond it the oldest are
/// dropped (their kernel marks then age out of the LRU).
const MAX_QUEUED_FORGETS: usize = 16_384;

/// Forgets not yet handed to the eBPF loop. Retried every tick instead
/// of being dropped on a full channel: a mark that is never deleted
/// keeps the kernel capturing that cgroup and holds the hot-path gate
/// open.
#[derive(Default)]
struct ForgetQueue {
    queued: VecDeque<u64>,
    dropped: u64,
}

impl ForgetQueue {
    fn push(&mut self, id: u64) {
        if self.queued.len() >= MAX_QUEUED_FORGETS {
            self.queued.pop_front();
            self.dropped += 1;
        }
        self.queued.push_back(id);
    }

    /// Hand over as many as the channel takes; keep the rest.
    fn flush(&mut self, forget: &Sender<u64>) {
        while let Some(&id) = self.queued.front() {
            match forget.try_send(id) {
                Ok(()) => {
                    self.queued.pop_front();
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => break,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // The eBPF loop is gone; the controller is going down.
                    self.queued.clear();
                    break;
                }
            }
        }
    }
}

pub async fn handle_syscall_events(
    mut event_receiver: Receiver<SyscallEventData>,
    container_map: ContainerMap,
    startup: StartupCapture,
) -> Result<(), Error> {
    let StartupCapture {
        mut cgroup_events,
        forget,
        tiers,
        config,
    } = startup;
    info!(
        pending_ttl_secs = config.pending_ttl.as_secs(),
        known_pod_ttl_secs = config.known_pod_ttl.as_secs(),
        "startup syscall capture TTLs"
    );
    let mut pending = PendingCapture::new(config);
    let mut forgets = ForgetQueue::default();
    let mut cgroup_events_open = true;
    let mut tick = tokio::time::interval(ATTRIBUTION_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_stats = Instant::now();

    loop {
        tokio::select! {
            event = event_receiver.recv() => {
                let Some(event) = event else { break };
                if event.kind == SYSCALL_EVENT_PENDING {
                    pending.pending_syscall(event.cgroup_id, event.sysnbr, Instant::now());
                    continue;
                }
                // Resolve before awaiting. This was the worst of the three
                // sites: the inline `get()` held the shard's read guard
                // across process_syscall_event, which itself awaits a tokio
                // Mutex shared with the periodic sender — so the guard could
                // be held for as long as that lock was contended. See
                // ContainerMap in models.rs.
                match registered_event_pod(&container_map, &event) {
                    Some(pod_inspect) => process_syscall_event(&event, &pod_inspect).await?,
                    None => debug!(
                        inum = event.inum,
                        generation = event.generation,
                        "syscall from a registered netns names no registered pod; dropped"
                    ),
                }
            }
            created = cgroup_events.recv(), if cgroup_events_open => {
                match created {
                    Some((id, path)) => {
                        if let Some(id) = pending.cgroup_created(id, &path, Instant::now()) {
                            forgets.push(id);
                            forgets.flush(&forget);
                        }
                    }
                    // The eBPF loop is going away; the syscall channel
                    // closes with it and ends this loop.
                    None => cgroup_events_open = false,
                }
            }
            _ = tick.tick() => {
                if !pending.is_empty() {
                    attribute_pending(&mut pending, &container_map, &tiers, &mut forgets).await?;
                }
                forgets.flush(&forget);
                if last_stats.elapsed() >= STATS_EVERY {
                    last_stats = Instant::now();
                    let s = pending.stats;
                    if s.cgroups_seen > 0 {
                        info!(
                            ownership_gate = crate::bpf::ownership_gate_active(),
                            cgroups_seen = s.cgroups_seen,
                            cgroups_attributed = s.cgroups_attributed,
                            cgroups_expired = s.cgroups_expired,
                            sandboxes_discarded = s.sandboxes_discarded,
                            syscalls_attributed = s.syscalls_attributed,
                            late_events_attributed = s.late_events_attributed,
                            syscalls_unattributable = s.syscalls_unattributable,
                            dropped_at_capacity = s.events_dropped_full,
                            forgets_queued = forgets.queued.len(),
                            forgets_dropped = forgets.dropped,
                            buffered_now = pending.len(),
                            "startup syscall capture (cumulative)"
                        );
                    }
                }
            }
        }
    }
    tracing::error!("Syscall event receiver exited unexpectedly!");
    Ok(())
}

/// One attribution pass: resolve buffered cgroups to pods by UID, merge
/// the syscalls of the pod's own containers (at the pod's tier) into its
/// set, and retire finished, expired or sandbox cgroups in the kernel.
async fn attribute_pending(
    pending: &mut PendingCapture,
    container_map: &ContainerMap,
    tiers: &ResolvedTiers,
    forgets: &mut ForgetQueue,
) -> Result<(), Error> {
    // Snapshot uid -> pod without holding any shard guard past this
    // statement (see ContainerMap). A few hundred entries, once a second,
    // and only while something is pending.
    // Finished pods' entries stay in the map (marked unregistered), so a
    // Job that completed before its startup syscalls were attributed
    // still resolves by UID.
    // hostNetwork pods first: they share one ContainerMap key (the node's
    // netns), so all but the last registered are only in their own registry.
    let mut by_uid: HashMap<String, Arc<PodInspect>> =
        crate::early_capture::host_network_pods_by_uid();
    by_uid.extend(
        container_map
            .iter()
            .filter(|e| !e.value().info.config.metadata.uid.is_empty())
            .map(|e| {
                (
                    e.value().info.config.metadata.uid.clone(),
                    Arc::clone(e.value()),
                )
            }),
    );

    let result = pending.attribute(Instant::now(), |identity| {
        let containers = known_pod_containers(&identity.pod_uid);
        resolve_pod_state(identity, &by_uid, containers.as_ref())
    });
    for id in result.forget {
        forgets.push(id);
    }
    for flush in result.flush {
        let pod = flush.pod;
        let allowed = filter_for_tier(pod.capture_flags, tiers, &flush.syscalls);
        debug!(
            pod = %pod.status.pod_name,
            namespace = %pod.info.config.metadata.namespace,
            container_id = flush.identity.container_id.as_deref().unwrap_or(""),
            cgroup_id = flush.cgroup_id,
            captured = flush.syscalls.len(),
            kept_by_tier = allowed.len(),
            "startup capture: attributing syscalls captured before the pod was registered"
        );
        for nr in allowed {
            let event = SyscallEventData {
                inum: pod.inode_num.unwrap_or_default(),
                sysnbr: nr,
                kind: SYSCALL_EVENT_PENDING,
                cgroup_id: flush.cgroup_id,
                ..Default::default()
            };
            process_syscall_event(&event, &pod).await?;
        }
    }
    Ok(())
}

pub async fn process_syscall_event(
    data: &SyscallEventData,
    pod_data: &PodInspect,
) -> Result<(), Error> {
    let pod_name = pod_data.status.pod_name.as_str();
    let uid = match pod_data.info.config.metadata.uid.as_str() {
        "" => pod_name,
        uid => uid,
    };
    let syscall_number = data.sysnbr;
    // u32 → i32 truncation. Real syscall numbers fit in 16 bits (the
    // highest defined Linux syscall is well under 1000). The previous
    // .try_into().unwrap() would panic if a hostile or buggy kernel
    // ever emitted u32::MAX; fall back to the numeric form via
    // get_syscall_name's None branch instead.
    let syscall_name = i32::try_from(syscall_number)
        .ok()
        .and_then(get_syscall_name)
        .unwrap_or_else(|| format!("{}", syscall_number));

    let outcome = with_sets(|s| s.record(uid, pod_name, pod_data.created_unix, &syscall_name));
    if outcome != Recorded::New {
        debug!(
            pod = pod_name,
            uid,
            syscall = %syscall_name,
            ?outcome,
            "syscall not added"
        );
    }
    Ok(())
}

pub async fn send_syscall_cache_periodically() -> Result<(), Error> {
    // Reduced from 60s to 10s for faster visibility of syscall data
    let interval_duration = std::time::Duration::from_secs(10);
    loop {
        // Snapshot under the lock, post without it. Only a successful
        // POST marks a snapshot sent: a transient broker failure must
        // retry next pass rather than lose the batch.
        let changed = with_sets(|s| s.changed());
        if !changed.is_empty() {
            let batch: Vec<_> = changed
                .iter()
                .map(|(_, name, snapshot)| {
                    json!(SyscallData {
                        pod_name: name.clone(),
                        pod_namespace: "".to_string(), // We will not store the namespace and rather read it from the pod_details table
                        syscalls: snapshot.iter().cloned().collect(),
                        arch: std::env::consts::ARCH.to_string(),
                        time_stamp: Utc::now().naive_utc()
                    })
                })
                .collect();
            debug!("Sending batch of {} syscalls to API", batch.len());
            match api_post_call(json!(batch), "pod/syscalls").await {
                Ok(()) => with_sets(|s| {
                    for (uid, _, snapshot) in changed {
                        s.mark_sent(&uid, snapshot);
                    }
                }),
                Err(e) => {
                    error!(
                        "Failed to post Syscall Event: {}; {} pod batches will retry next pass",
                        e,
                        changed.len()
                    );
                }
            }
        }
        tokio::time::sleep(interval_duration).await;
    }
}

fn get_syscall_name(syscall_number: i32) -> Option<String> {
    // Same arch selection the tier allowlists use at startup
    // (capture_tiers::native_scmp_arch), so a number the probe filtered
    // by name resolves back to that same name here.
    let Some(arch) = native_scmp_arch() else {
        eprintln!("Unsupported architecture");
        return None;
    };

    let syscall = ScmpSyscall::from(syscall_number);
    let name = syscall.get_name_by_arch(arch).ok()?;
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// cluster-00 round 2: bare pod ng-5 deleted and recreated under the
    /// same name. Anything still credited to the OLD incarnation after the
    /// new one exists (its teardown, or host processes in a recycled netns
    /// resolving to its stale entry, such as a `mount`) must not reach the
    /// new pod's set, and the row must carry the new pod's own set.
    #[test]
    fn a_recreated_same_name_pod_never_inherits_its_predecessors_syscalls() {
        let mut s = SyscallSets::default();
        for sc in ["read", "epoll_wait", "exit_group"] {
            s.record("uid-old", "ng-5", 100, sc);
        }
        s.mark_sent("uid-old", names(&["read", "epoll_wait", "exit_group"]));

        // New incarnation starts.
        assert_eq!(s.record("uid-new", "ng-5", 200, "execve"), Recorded::New);
        assert_eq!(s.record("uid-new", "ng-5", 200, "read"), Recorded::New);

        // Late events for the old one (teardown, stale-netns credit).
        assert_eq!(
            s.record("uid-old", "ng-5", 100, "mount"),
            Recorded::Superseded
        );
        assert_eq!(
            s.record("uid-old", "ng-5", 100, "tgkill"),
            Recorded::Superseded
        );

        assert_eq!(s.set_of("uid-new"), Some(&names(&["execve", "read"])));
        assert!(s.set_of("uid-old").is_none(), "old set discarded");
        let changed = s.changed();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0, "uid-new");
        assert_eq!(changed[0].1, "ng-5");
        assert!(!changed[0].2.contains("mount"));
    }

    #[test]
    fn an_older_incarnation_seen_after_the_newer_one_is_dropped() {
        let mut s = SyscallSets::default();
        s.record("uid-new", "ng-5", 200, "execve");
        assert_eq!(
            s.record("uid-old", "ng-5", 100, "mount"),
            Recorded::Superseded
        );
        assert_eq!(s.set_of("uid-new"), Some(&names(&["execve"])));
        assert!(s.set_of("uid-old").is_none());
    }

    #[test]
    fn a_same_second_recreate_goes_to_the_newcomer_and_never_flips_back() {
        let mut s = SyscallSets::default();
        s.record("uid-a", "ng-5", 100, "read");
        s.record("uid-b", "ng-5", 100, "execve"); // same second: newcomer wins
        assert_eq!(
            s.record("uid-a", "ng-5", 100, "mount"),
            Recorded::Superseded
        );
        assert_eq!(s.record("uid-b", "ng-5", 100, "write"), Recorded::New);
        assert_eq!(s.set_of("uid-b"), Some(&names(&["execve", "write"])));
    }

    #[test]
    fn distinct_names_are_independent_and_sends_retry_until_marked() {
        let mut s = SyscallSets::default();
        s.record("u1", "a", 1, "read");
        s.record("u2", "b", 1, "write");
        assert_eq!(s.changed().len(), 2);
        s.mark_sent("u1", names(&["read"]));
        let changed = s.changed();
        assert_eq!(changed.len(), 1, "b not marked sent: retried");
        assert_eq!(changed[0].1, "b");
        assert_eq!(s.record("u1", "a", 1, "read"), Recorded::Duplicate);
    }

    #[test]
    fn event_layout_matches_the_kernel_struct() {
        // struct data_t in bpf/syscall.bpf.c: u64 inum, u32 sysnbr,
        // u32 kind, u64 cgroup_id. The ring-buffer callback casts the raw
        // bytes to this type, so a size or order mismatch silently reads
        // garbage rather than failing.
        assert_eq!(std::mem::size_of::<SyscallEventData>(), 32);
        assert_eq!(std::mem::offset_of!(SyscallEventData, generation), 24);
        assert_eq!(std::mem::offset_of!(SyscallEventData, sysnbr), 8);
        assert_eq!(std::mem::offset_of!(SyscallEventData, kind), 12);
        assert_eq!(std::mem::offset_of!(SyscallEventData, cgroup_id), 16);
    }
}
