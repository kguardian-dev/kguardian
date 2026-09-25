use crate::capture_tiers::{native_scmp_arch, ResolvedTiers};
use crate::early_capture::{
    filter_for_tier, known_pod_containers, resolve_pod_state, PendingCapture, StartupCaptureConfig,
    SYSCALL_EVENT_PENDING,
};
use crate::models::{lookup_pod, ContainerMap};
use chrono::Utc;
use libseccomp::ScmpSyscall;
use moka::future::Cache;
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::{api_post_call, Error, PodInspect, SyscallData};

pub mod sycallprobe {
    include!(concat!(env!("OUT_DIR"), "/syscall.skel.rs"));
}

type SyscallCache = Cache<String, Arc<Mutex<HashSet<String>>>>;

lazy_static::lazy_static! {
    static ref SYSCALL_CACHE: SyscallCache = Cache::new(10_000);
    static ref LAST_SENT_CACHE: SyscallCache = Cache::new(10_000);
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
                if let Some(pod_inspect) = lookup_pod(&container_map, event.inum) {
                    process_syscall_event(&event, &pod_inspect).await?
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
    let by_uid: HashMap<String, Arc<PodInspect>> = container_map
        .iter()
        .filter(|e| !e.value().info.config.metadata.uid.is_empty())
        .map(|e| {
            (
                e.value().info.config.metadata.uid.clone(),
                Arc::clone(e.value()),
            )
        })
        .collect();

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
    let pod_name = pod_data.status.pod_name.to_string();
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

    let syscalls = SYSCALL_CACHE
        .get_with(pod_name.clone(), async {
            Arc::new(Mutex::new(HashSet::new()))
        })
        .await;

    let mut syscalls_lock = syscalls.lock().await;

    if syscalls_lock.contains(&syscall_name) {
        debug!(
            "Skipping duplicate syscall: {} for pod: {}",
            syscall_name, pod_name
        );
    } else {
        syscalls_lock.insert(syscall_name.clone());
    }

    Ok(())
}

pub async fn send_syscall_cache_periodically() -> Result<(), Error> {
    // Reduced from 60s to 10s for faster visibility of syscall data
    let interval_duration = std::time::Duration::from_secs(10);
    loop {
        let mut batch = Vec::new();
        // Track which (pod, snapshot) pairs to mark as last_sent
        // AFTER the POST succeeds. The pre-fix code eagerly updated
        // last_sent inside the loop, before the POST — so a
        // transient broker failure permanently dropped the batch:
        // next iteration the diff `syscalls_lock != last_sent_lock`
        // was false (we'd just made them equal), no retry, broker
        // never got those syscalls. Stable-state pods (no new
        // syscalls between iterations) lost data.
        let mut pending_updates: Vec<(String, HashSet<String>)> = Vec::new();

        for (pod_name, syscalls) in SYSCALL_CACHE.iter() {
            let syscalls_lock = syscalls.lock().await;
            let last_sent = LAST_SENT_CACHE
                .get_with(pod_name.to_string(), async {
                    Arc::new(Mutex::new(HashSet::new()))
                })
                .await;
            let last_sent_lock = last_sent.lock().await;

            if *syscalls_lock != *last_sent_lock {
                let snapshot = syscalls_lock.clone();
                let syscall_names: Vec<String> = snapshot.iter().cloned().collect();
                let z = json!(SyscallData {
                    pod_name: pod_name.to_string(),
                    pod_namespace: "".to_string(), // We will not store the namespace and rather read it from the pod_details table
                    syscalls: syscall_names,
                    arch: std::env::consts::ARCH.to_string(),
                    time_stamp: Utc::now().naive_utc()
                });
                batch.push(z);
                pending_updates.push((pod_name.to_string(), snapshot));
            }
        }

        if !batch.is_empty() {
            debug!("Sending batch of {} syscalls to API", batch.len());
            match api_post_call(json!(batch), "pod/syscalls").await {
                Ok(()) => {
                    // POST succeeded — persist the snapshots as
                    // last_sent so we don't re-send them next pass.
                    // No race: this loop is the only writer of
                    // LAST_SENT_CACHE entries. If new syscalls
                    // arrived between POST and update, the next
                    // iteration's diff catches them.
                    for (pod_name, snapshot) in pending_updates {
                        let last_sent = LAST_SENT_CACHE
                            .get_with(pod_name, async { Arc::new(Mutex::new(HashSet::new())) })
                            .await;
                        *last_sent.lock().await = snapshot;
                    }
                }
                Err(e) => {
                    // Don't touch last_sent. Next iteration will see
                    // the same diff and retry.
                    error!(
                        "Failed to post Syscall Event: {}; {} pod batches will retry next pass",
                        e,
                        pending_updates.len()
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

    #[test]
    fn event_layout_matches_the_kernel_struct() {
        // struct data_t in bpf/syscall.bpf.c: u64 inum, u32 sysnbr,
        // u32 kind, u64 cgroup_id. The ring-buffer callback casts the raw
        // bytes to this type, so a size or order mismatch silently reads
        // garbage rather than failing.
        assert_eq!(std::mem::size_of::<SyscallEventData>(), 24);
        assert_eq!(std::mem::offset_of!(SyscallEventData, sysnbr), 8);
        assert_eq!(std::mem::offset_of!(SyscallEventData, kind), 12);
        assert_eq!(std::mem::offset_of!(SyscallEventData, cgroup_id), 16);
    }
}
