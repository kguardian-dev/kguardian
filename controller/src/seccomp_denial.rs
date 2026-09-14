//! Userspace side of the seccomp-denial probe
//! (`src/bpf/seccomp_denial.bpf.c`).
//!
//! A `SeccompProfile` with `defaultAction: SCMP_ACT_LOG` makes the kernel
//! record every would-be denial. Until now kguardian never read that back,
//! so the audit output of the sandbox it generated was invisible to it —
//! the only denial-adjacent signal was `Drift`, inferred from eBPF syscall
//! observation, which says a profile is incomplete but never that the
//! kernel actually acted on one. This module closes that: the kernel's own
//! verdict, attributed to a pod, counted, and shipped to the Broker.
//!
//! The kernel side aggregates; this side drains. Every
//! [`DEFAULT_INTERVAL_SECS`] the map is read-and-cleared, each row is
//! attributed to a pod, the syscall number and the raw `SECCOMP_RET_*`
//! action are resolved to the `SCMP_*` spellings the rest of the tree
//! uses, and the result is POSTed to `POST /seccomp/denials`.
//!
//! Attribution takes two routes, because no one identifier names a
//! workload on every pod. A pod with a network namespace of its own is
//! named by its netns inode, the way everything else in this tree names
//! it. A `hostNetwork: true` pod has no such namespace — its inode is
//! the node's, shared with kubelet and with every other hostNetwork pod
//! — so it is named by the cgroup id the probe records alongside,
//! resolved through the per-container registry in
//! [`crate::compute_registry`]. See [`build_denials`].
//!
//! Nothing in here is allowed to take the Controller down. The probe is
//! skipped on a kernel without `audit_seccomp` (see
//! `bpf::kernel_can_kprobe`), a Broker that does not know the endpoint is
//! a warning, and a failed POST carries its rows into the next tick
//! rather than dropping them.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use libbpf_rs::{ErrorKind as BpfErrorKind, MapCore, MapFlags, MapHandle};
use libseccomp::ScmpSyscall;
use serde::Serialize;
use serde_json::json;
use tokio::sync::{broadcast, oneshot};
use tracing::{debug, info, warn};

use crate::capture_tiers::native_scmp_arch;
use crate::client::api_post_call_json;
use crate::compute_config::ComputeConfig;
use crate::compute_registry::{ComputeMap, ComputeRegistration, ComputeRegistry, ContainerCompute};
use crate::models::{lookup_pod, pod_flags, ContainerMap};
use crate::Error;

pub mod seccomp_denial_skel {
    include!(concat!(env!("OUT_DIR"), "/seccomp_denial.skel.rs"));
}

/// The kernel symbol the probe attaches to. Absent on a kernel built
/// without `CONFIG_AUDITSYSCALL`, which is a supported node — see the
/// header comment of `src/bpf/seccomp_denial.bpf.c`.
pub const AUDIT_SECCOMP_SYMBOL: &str = "audit_seccomp";

/// Broker path for the ingest POST.
pub const DENIALS_PATH: &str = "seccomp/denials";

/// `SECCOMP_DENIAL_CAPTURE` — master switch, default on.
pub const CAPTURE_ENV: &str = "SECCOMP_DENIAL_CAPTURE";
/// `SECCOMP_DENIAL_INTERVAL_SECONDS` — drain cadence.
pub const INTERVAL_ENV: &str = "SECCOMP_DENIAL_INTERVAL_SECONDS";

/// Drain cadence, matching the syscall recorder's 10s
/// (`syscall::send_syscall_cache_periodically`).
pub const DEFAULT_INTERVAL_SECS: u64 = 10;

/// Rows per POST.
///
/// The Broker's ingest route accepts a 4 MiB body (`DENIAL_JSON_LIMIT_BYTES`),
/// which at the ~200-400 B a denial serialises to is roughly 10 000-20 000
/// rows. A drain is NOT bounded by that: the kernel map holds 65 536 rows and
/// a decoder hammering a blocked syscall can fill it, which is precisely the
/// scenario this feature exists for. An unchunked drain would therefore be
/// rejected wholesale exactly when the signal matters most.
///
/// 5 000 rows is ~1-2 MB — comfortably inside the limit with room for long
/// pod names — and turns a full 65 536-row map into 14 sequential POSTs
/// rather than one 413.
const MAX_DENIALS_PER_POST: usize = 5_000;

/// Ceiling on rows carried forward across a FAILED post.
///
/// This bounds the retry backlog only. It is deliberately not applied to a
/// batch on its way out: capping there would silently discard the bulk of a
/// denial storm instead of chunking it, which is the failure this whole path
/// is built to survive. Rows the Broker refused accumulate here, and past
/// this many the memory matters more than the tail of the backlog — the
/// oldest are dropped and the loss is logged rather than growing without
/// bound behind an unreachable Broker.
const MAX_PENDING_DENIALS: usize = 20_000;

// Compile-time rather than a test, because these are the two numbers a
// future edit is most likely to get wrong and a build failure is a better
// place to find out than a node under a denial storm.
const _: () = assert!(
    MAX_DENIALS_PER_POST <= 5_000,
    "a body above the Broker's stated chunk ceiling risks a 413 on exactly the drain that \
     mattered"
);
const _: () = assert!(
    MAX_PENDING_DENIALS >= MAX_DENIALS_PER_POST,
    "the retry backlog must hold at least one whole body, or a failed chunk could never be \
     retried in full"
);

/// Occupancy above this fraction of the map means LRU eviction is
/// probably discarding rows before a drain sees them, so the counts have
/// become a floor rather than a total. Worth saying out loud once per
/// tick, because "few denials" and "denials we could not keep up with"
/// look identical on a dashboard otherwise.
const OCCUPANCY_WARN_RATIO: f64 = 0.9;

// Raw `SECCOMP_RET_*` action values (include/uapi/linux/seccomp.h),
// as `seccomp_log()` passes them after masking with
// SECCOMP_RET_ACTION_FULL.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// The mask the kernel applies before dispatching on an action. Mirrors
/// `KG_SECCOMP_RET_ACTION_FULL` in the probe.
const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;

/// Startup configuration, from the `SECCOMP_DENIAL_*` environment the
/// chart renders.
///
/// Same shape as [`crate::compute_config::ComputeConfig`]: a pure
/// `from_values` over the raw strings and a thin `from_env` on top. Every
/// value has a default and an unparseable one warns and falls back —
/// this is a default-on feature and must never refuse to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompDenialConfig {
    /// `SECCOMP_DENIAL_CAPTURE`. Off means the probe is never loaded and
    /// no drain task runs.
    pub enabled: bool,
    /// `SECCOMP_DENIAL_INTERVAL_SECONDS`, clamped to at least 1s.
    pub interval: Duration,
}

impl Default for SeccompDenialConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECS),
        }
    }
}

impl SeccompDenialConfig {
    /// Pure parser over the raw env values.
    pub fn from_values(enabled: Option<&str>, interval_seconds: Option<&str>) -> Self {
        let secs = match interval_seconds.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_INTERVAL_SECS,
            Some(s) => match s.parse::<u64>() {
                Ok(0) => {
                    warn!("{INTERVAL_ENV}=0 is not a cadence; using 1s");
                    1
                }
                Ok(v) => v,
                Err(_) => {
                    warn!(
                        env = INTERVAL_ENV,
                        value = s,
                        default = DEFAULT_INTERVAL_SECS,
                        "not an unsigned integer; using default"
                    );
                    DEFAULT_INTERVAL_SECS
                }
            },
        };
        Self {
            enabled: crate::pod_watcher::parse_lenient_bool(enabled.unwrap_or_default(), true),
            interval: Duration::from_secs(secs),
        }
    }

    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(CAPTURE_ENV).ok().as_deref(),
            std::env::var(INTERVAL_ENV).ok().as_deref(),
        )
    }
}

/// One denial row as it goes over the wire.
///
/// Field names are the `POST /seccomp/denials` contract; `camelCase` is
/// applied wholesale rather than per field so a rename cannot silently
/// drift from the Broker's `serde` model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompDenial {
    /// Pod UID, the stable half of the Broker's storage key — a pod name
    /// can be reused by a replacement pod of the same workload, a UID
    /// cannot. Empty only for a pod that reached the `ContainerMap`
    /// without one, which the Broker rejects; see [`pod_attribution`].
    pub pod_uid: String,
    pub pod_name: String,
    pub pod_namespace: String,
    /// Resolved name, or `syscall_<nr>` when libseccomp does not know the
    /// number on this arch. Never dropped: a denial on a syscall we
    /// cannot name is still a denial.
    pub syscall: String,
    /// Signed, because a Linux syscall number is an `int` and a process
    /// can genuinely present a negative one — `syscall(-1)` reaches
    /// seccomp with `this_syscall == -1`, is denied, and is logged like
    /// any other. Reporting that as the u32 it is stored as would send
    /// 4294967295 to a Broker column that is `INTEGER`, and serde would
    /// reject the whole batch — letting any unprivileged workload under
    /// an `SCMP_ACT_LOG` profile poison every denial on its node with
    /// one call.
    pub syscall_nr: i32,
    /// `SCMP_ACT_*` spelling, or `SCMP_ACT_UNKNOWN`.
    pub action: &'static str,
    /// The raw `SECCOMP_RET_*` value, kept even when `action` is
    /// `SCMP_ACT_UNKNOWN` so an unrecognised verdict is still diagnosable.
    pub action_raw: u32,
    /// `SCMP_ARCH_*` token for the node's architecture, omitted on an
    /// architecture libseccomp has no token for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<&'static str>,
    pub count: u64,
    #[serde(serialize_with = "rfc3339_seconds")]
    pub first_seen: DateTime<Utc>,
    #[serde(serialize_with = "rfc3339_seconds")]
    pub last_seen: DateTime<Utc>,
}

/// The POST body.
///
/// Sent on EVERY drain interval, including one that drained nothing. An
/// empty batch is not a wasted request: it is this node's capture
/// heartbeat, and it is the only thing that lets the Broker tell "nothing
/// was denied" from "nothing was watching". Without it, a fresh install
/// has no denial rows anywhere, so every workload sits at
/// `DenialsObserved: Unknown` — and `Unknown` blocks promotion, which is
/// the workflow this feature exists to unblock.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DenialBatch<'a> {
    node: &'a str,
    /// Whether the probe is actually attached on this node.
    ///
    /// A node that degraded gracefully — no `audit_seccomp` symbol, or an
    /// attach the kernel refused — still reports in, and must report in
    /// as `false`. Reporting its silence as a clean bill of health would
    /// turn graceful degradation into a false all-clear, which is a worse
    /// outcome than the crash the degradation exists to avoid.
    capturing: bool,
    /// This node's drain cadence in seconds — the interval between the
    /// heartbeats above, declared by the node that sends them.
    ///
    /// The Broker has to decide when a node's last report is too old to
    /// believe, and it cannot know that from a constant: the cadence is
    /// `SECCOMP_DENIAL_INTERVAL_SECONDS`, an operator-set Helm value with
    /// no upper bound, so any window the Broker hard-codes is wrong for
    /// some supported configuration — and wrong in the direction that
    /// makes a healthy cluster read as stale, which is `Unknown`, which
    /// blocks promotion. Coupling the two settings would only move the
    /// problem into the chart; the node declaring its own cadence needs
    /// no agreement at all. The Broker computes
    /// `max(300, intervalSeconds * 3)` from this and treats absent or
    /// zero as 300, so an older Controller stays exactly as it was.
    interval_seconds: u64,
    denials: &'a [SeccompDenial],
}

/// The POST body for one chunk, as JSON.
///
/// One place builds it, and the tests exercise that place, so
/// `intervalSeconds` cannot end up on the denial-carrying report and
/// missing from the empty heartbeat — which is the report a stalled node
/// sends, and therefore the one the Broker's staleness window is FOR.
fn denial_batch_body(
    node: &str,
    capturing: bool,
    interval: Duration,
    denials: &[SeccompDenial],
) -> serde_json::Value {
    json!(DenialBatch {
        node,
        capturing,
        interval_seconds: interval.as_secs(),
        denials,
    })
}

/// RFC3339 at second precision (`2026-09-14T04:05:06Z`), which is the
/// spelling in the wire contract. Sub-second precision would be noise:
/// these are the first and last verdict within a drain interval measured
/// in seconds, and the timestamp is reconstructed from a monotonic clock
/// anchor whose own error is larger than a millisecond.
fn rfc3339_seconds<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// One row exactly as the kernel keeps it, before any attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawDenial {
    netns: u64,
    /// The cgroup the calling task was in — 1:1 with a container, and
    /// the only identifier in the key that survives `hostNetwork: true`.
    cgroup_id: u64,
    generation: u32,
    syscall_nr: u32,
    action: u32,
    count: u64,
    first_seen_ns: u64,
    last_seen_ns: u64,
}

/// What one drain produced, plus the health numbers that go with it.
///
/// `Default` is the "there was no probe to drain" case: a node reporting in
/// with `capturing: false` still ticks, and still has to reach the POST.
#[derive(Debug, Default)]
struct DrainOutcome {
    rows: Vec<RawDenial>,
    /// Rows present in the map when the drain started.
    occupancy: usize,
    /// Cumulative in-kernel record failures since load. Any increase
    /// means verdicts were seen and not counted.
    update_failures: u64,
    /// Rows the drain could not read back. Counted rather than fatal —
    /// see [`drain`].
    read_errors: usize,
}

/// The map file descriptors the drain needs, handed over by the eBPF
/// loader once the probe is attached.
///
/// Handles rather than the skeleton itself: the skeleton has to stay
/// alive on `bpf::ebpf_handle`'s `spawn_blocking` thread for the programs
/// to stay attached, and a `MapHandle` is an owned dup of the map's fd,
/// so this side can read the maps from a Tokio task without sharing the
/// skeleton across threads.
#[derive(Debug)]
pub struct DenialMaps {
    denials: MapHandle,
    stats: MapHandle,
    /// False once the kernel has refused `BPF_MAP_LOOKUP_AND_DELETE_ELEM`
    /// on this map — support for hash maps only arrived in Linux 5.14 —
    /// after which the drain uses a separate lookup and delete.
    atomic_take: AtomicBool,
}

impl DenialMaps {
    /// Duplicate the fds of the maps the drain reads.
    pub fn from_skel(
        maps: &seccomp_denial_skel::SeccompDenialMaps<'_>,
    ) -> Result<Self, libbpf_rs::Error> {
        Ok(Self {
            denials: MapHandle::try_from(&maps.seccomp_denials)?,
            stats: MapHandle::try_from(&maps.denial_stats)?,
            atomic_take: AtomicBool::new(true),
        })
    }

    /// Read a row and remove it in the same step where the kernel allows
    /// it, so a verdict recorded between the read and the delete is not
    /// lost.
    ///
    /// `BPF_MAP_LOOKUP_AND_DELETE_ELEM` only covers hash maps from Linux
    /// 5.14; older kernels reject it. The first refusal — whatever its
    /// errno, because the kernel has spelled "unsupported" as several
    /// over the years — permanently drops this instance to the
    /// lookup-then-delete path. That path is correct everywhere and costs
    /// only atomicity, so treating an unrelated error as a refusal
    /// degrades the drain rather than breaking it.
    fn take(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if self.atomic_take.load(Ordering::Relaxed) {
            match self.denials.lookup_and_delete(key) {
                Ok(value) => return Ok(value),
                Err(e) => {
                    warn!(
                        error = %e,
                        "atomic lookup-and-delete on seccomp_denials failed (hash-map \
                         support for it starts at Linux 5.14); using a separate lookup \
                         and delete for the life of this process"
                    );
                    self.atomic_take.store(false, Ordering::Relaxed);
                }
            }
        }

        let value = self
            .denials
            .lookup(key, MapFlags::ANY)
            .map_err(|e| Error::Custom(format!("seccomp_denials lookup: {e}")))?;
        match self.denials.delete(key) {
            Ok(()) => {}
            // Already gone: the row was evicted between the two calls.
            // Nothing to do, and nothing lost that this drain could have
            // reported.
            Err(e) if e.kind() == BpfErrorKind::NotFound => {}
            Err(e) => return Err(Error::Custom(format!("seccomp_denials delete: {e}"))),
        }
        Ok(value)
    }

    fn stat(&self, index: u32) -> u64 {
        self.stats
            .lookup(&index.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .as_deref()
            .and_then(u64_from_bytes)
            .unwrap_or(0)
    }
}

/// Index of the in-kernel record-failure counter. Mirrors
/// `KG_STAT_DENIAL_UPDATE_FAILURES` in the probe.
const STAT_UPDATE_FAILURES: u32 = 0;

/// Wall-clock reading paired with the monotonic clock the probe stamps
/// its rows from.
///
/// `bpf_ktime_get_ns()` is CLOCK_MONOTONIC — nanoseconds since boot —
/// and the wire format wants RFC3339, so the two have to be tied
/// together. Read AFTER the drain, never before: that makes
/// `mono_ns >= every row's timestamp` true by construction, so
/// [`mono_to_utc`] never has to invent a time in the future.
#[derive(Debug, Clone, Copy)]
struct ClockAnchor {
    wall: DateTime<Utc>,
    mono_ns: u64,
}

impl ClockAnchor {
    fn now() -> Self {
        Self {
            wall: Utc::now(),
            mono_ns: monotonic_ns(),
        }
    }
}

/// CLOCK_MONOTONIC in nanoseconds — the same clock `bpf_ktime_get_ns()`
/// reads. Returns 0 if the call fails, which makes every conversion
/// against this anchor collapse to "now": wrong by at most the node's
/// uptime in the pathological case, and `clock_gettime(CLOCK_MONOTONIC)`
/// does not fail on a Linux the Controller can run on.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live, correctly typed `timespec` for the duration
    // of the call and CLOCK_MONOTONIC is always a valid clock id.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// Turn one of the probe's monotonic timestamps into wall-clock time.
///
/// `saturating_sub` covers the case the anchor ordering is supposed to
/// make impossible (a row stamped after the anchor was read): such a row
/// is reported as "now" rather than as a time in the future, which would
/// make `first_seen > last_seen` and confuse the Broker's `LEAST`/
/// `GREATEST` upsert.
fn mono_to_utc(anchor: &ClockAnchor, event_mono_ns: u64) -> DateTime<Utc> {
    let age_ns = anchor.mono_ns.saturating_sub(event_mono_ns);
    let age = TimeDelta::nanoseconds(i64::try_from(age_ns).unwrap_or(i64::MAX));
    anchor.wall.checked_sub_signed(age).unwrap_or(anchor.wall)
}

/// `SCMP_ACT_*` name for a raw `SECCOMP_RET_*` value.
///
/// Matched on the action bits only: the kernel already masks before
/// calling `audit_seccomp`, and the probe masks again, but a name lookup
/// that ignores the data field is correct either way and cannot be broken
/// by a filter that returns an errno.
///
/// `SCMP_ACT_ALLOW` is in the table even though `seccomp_log()` returns
/// early for it and it can therefore never arrive. It is a real spelling
/// the rest of the tree uses, and reporting it as `SCMP_ACT_UNKNOWN`
/// would send an operator looking for a kernel bug that is really just
/// this table being short.
fn action_name(raw: u32) -> &'static str {
    match raw & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_KILL_PROCESS => "SCMP_ACT_KILL_PROCESS",
        SECCOMP_RET_KILL_THREAD => "SCMP_ACT_KILL",
        SECCOMP_RET_TRAP => "SCMP_ACT_TRAP",
        SECCOMP_RET_ERRNO => "SCMP_ACT_ERRNO",
        SECCOMP_RET_USER_NOTIF => "SCMP_ACT_NOTIFY",
        SECCOMP_RET_TRACE => "SCMP_ACT_TRACE",
        SECCOMP_RET_LOG => "SCMP_ACT_LOG",
        SECCOMP_RET_ALLOW => "SCMP_ACT_ALLOW",
        _ => "SCMP_ACT_UNKNOWN",
    }
}

/// `SCMP_ARCH_*` token for this binary's target architecture.
///
/// Deliberately the same mapping as `arch_token` in `broker/src/seccomp.rs`
/// — note that aarch64 is spelled `SCMP_ARCH_ARM64` there, not
/// `SCMP_ARCH_AARCH64`, and the two must agree or a denial row's arch
/// will not match the arch on the profile it belongs to.
fn scmp_arch_token() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("SCMP_ARCH_X86_64"),
        "aarch64" => Some("SCMP_ARCH_ARM64"),
        _ => None,
    }
}

/// Resolve a syscall number to its name, falling back to `syscall_<nr>`.
///
/// Same libseccomp path `syscall.rs` uses, and the same architecture
/// selection (`capture_tiers::native_scmp_arch`), so a number resolves to
/// the name the generated profile would list. The fallback spelling
/// differs from `syscall.rs`'s bare number on purpose: this one reaches a
/// UI and a Prometheus label, where a lone `423` reads as a mistake.
fn syscall_display_name(nr: i32) -> String {
    let resolved = native_scmp_arch()
        .and_then(|arch| ScmpSyscall::from(nr).get_name_by_arch(arch).ok())
        // libseccomp names its multiplexed pseudo-syscalls with negative
        // numbers, so a name could come back for one of those. It would
        // be a name nothing else in kguardian uses; the numeric form is
        // less misleading than a token no profile can contain.
        .filter(|_| nr >= 0);
    resolved.unwrap_or_else(|| format!("syscall_{nr}"))
}

/// Everything a drained row needs about the pod on its netns, taken from
/// one `ContainerMap` entry.
///
/// One struct rather than a tuple plus a separate generation lookup
/// because the two must describe the same pod: see [`build_denials`] for
/// the misattribution that follows from reading them out of two stores.
#[derive(Debug)]
struct PodAttribution {
    /// The generation this pod's registration put in every probe's
    /// `inode_num` value, recomputed from `uid` rather than read back
    /// from the kernel.
    generation: u32,
    /// The pod does not have a netns of its own, so the inode this entry
    /// is filed under is the node's and names no single pod. Such a row
    /// is attributed by its cgroup id instead; see [`build_denials`].
    host_network: bool,
    uid: String,
    name: String,
    namespace: String,
}

/// Pod identity, and the generation it registered with, for a denial
/// row's netns — `None` when that netns belongs to no pod this node
/// currently knows.
///
/// The UID comes from `info.config.metadata`, which
/// `pod_watcher::pod_identity_metadata` fills when it registers the
/// netns. That is load-bearing rather than incidental: the Broker's
/// storage key is `(pod_uid, syscall, action)` and it rejects a row whose
/// UID is empty rather than collapse every pod on the cluster into one
/// row per syscall/action pair. Registration used to fill `status` only,
/// and the whole feature stored nothing while looking healthy from both
/// ends. An empty UID reaching here is now the hand-built-pod case only,
/// and it is counted (`AttributionLosses::missing_uid`) so it can never
/// be silent again.
fn pod_attribution(container_map: &ContainerMap, netns: u64) -> Option<PodAttribution> {
    let pod = lookup_pod(container_map, netns)?;
    let uid = pod.info.config.metadata.uid.clone();
    Some(PodAttribution {
        generation: registration_generation(&uid),
        host_network: pod.host_network,
        uid,
        name: pod.status.pod_name.clone(),
        namespace: pod.status.pod_namespace.clone().unwrap_or_default(),
    })
}

/// The generation `pod_watcher::pod_registration_flags` derived for a pod
/// with this UID — the value the probe stamps into every row it records
/// for that pod's netns.
///
/// The empty string has to map to `None` and not to `Some("")`. The two
/// spellings are the same pod to `pod_watcher` — `pod_identity_metadata`
/// stores a missing `metadata.uid` as `""` while
/// `pod_registration_flags` hashes the `Option` — but they are different
/// numbers to `generation_for_uid`: `None` is 0, and `Some("")` is FNV's
/// offset basis, which is not. Getting this backwards would drop every
/// denial from exactly the UID-less pods the registration path goes out
/// of its way to keep tracked, and drop them as a generation mismatch
/// that never happened on the node.
fn registration_generation(pod_uid: &str) -> u32 {
    pod_flags::generation_for_uid(Some(pod_uid).filter(|uid| !uid.is_empty()))
}

/// Why a drained row did not make it onto the wire. Counted rather than
/// logged per row: under a denial storm the per-row log IS the storm.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct AttributionLosses {
    /// Neither route named a pod: nothing is registered on the row's
    /// netns any more, AND its cgroup is not a container this node
    /// knows.
    unknown_pod: usize,
    /// The row's netns is the NODE's — every hostNetwork pod and every
    /// host process shares it — and its cgroup resolved to no container
    /// on this node, so the row names nothing. Most of these are the
    /// node's own processes under a `SystemCallFilter=` unit, which is
    /// the correct answer; a workload's rows landing here is not, and
    /// nothing in the key tells them apart. See [`build_denials`].
    unresolved_cgroup: usize,
    /// One cgroup id counted above, so the warning points at something
    /// an operator can resolve (`bpftool cgroup tree` prints these).
    /// One example, not a list: under a storm every host process on the
    /// node qualifies and naming them all would be its own noise.
    unresolved_cgroup_example: Option<u64>,
    /// The row needed the cgroup route and there is no container
    /// registry to take it. Counted separately from a cgroup that
    /// simply did not resolve, because this one is a misconfiguration
    /// with a fix rather than a fact about the workload. See
    /// [`build_denials`].
    no_container_registry: usize,
    /// The row's netns names one pod and the row's cgroup names a
    /// container of a DIFFERENT one. Two independent identifiers
    /// disagree; nothing in the row says which is stale, so it is
    /// refused. The reachable cause is `EXCLUDED_NAMESPACES` — see
    /// [`build_denials`].
    netns_cgroup_mismatch: usize,
    /// The row's generation is not the one the pod now on its netns
    /// registered with. Either the inode was recycled and the row is the
    /// dead pod's, or the row is the LIVE pod's own and was recorded
    /// before `bpf.rs` published its new generation — the two cannot be
    /// told apart, so both are dropped. See the check in
    /// [`build_denials`] and `KG_GEN_SHIFT` in `src/bpf/helper.h`.
    stale_generation: usize,
    /// Rows whose pod has no UID in the `ContainerMap`. Not dropped
    /// here — the row is still a real denial and the Broker may yet
    /// learn to resolve it — but counted so the condition is loud
    /// rather than a table that stays mysteriously empty. See
    /// [`pod_attribution`].
    missing_uid: usize,
}

/// Whether the Controller builds the per-container cgroup registry.
///
/// The registry was the compute sampler's, and for a while it was built
/// only when `COMPUTE_ENABLED` was on. Denial attribution now depends on
/// it: a `hostNetwork` pod's verdicts have no other identifier, so with
/// no registry they are counted and dropped, and a workload nothing can
/// attribute reports no denials — which the Broker reads as no denials.
/// Switching off an unrelated observability feature would therefore have
/// silently un-monitored every hostNetwork workload on the node, in the
/// direction that reads as clean.
///
/// One function, called from `main.rs`, so the coupling has one
/// definition and a test can pin it. The chart mounts the host cgroupfs
/// under the matching condition
/// (`charts/kguardian/templates/controller/daemonset.yaml`); without the
/// mount there is nothing to resolve a container's cgroup against, so
/// the two must be changed together.
pub fn needs_container_registry(compute_enabled: bool, denial_capture_enabled: bool) -> bool {
    compute_enabled || denial_capture_enabled
}

/// The cgroup registry handle denial attribution resolves `hostNetwork`
/// pods through.
///
/// A newtype with a private field, and the only thing that can build one
/// is [`wire_registry`]. That is the whole point of it: while this was a
/// plain `Option<ComputeMap>` threaded through `main.rs`, one word at
/// the call site —
///
/// ```text
/// let seccomp_denial_cgroups: Option<ComputeMap> = None;
/// ```
///
/// — switched denial reporting off for every hostNetwork workload on the
/// node, and no test anywhere could see it, because `main.rs` is a
/// binary with no tests and the decision lived only there. It was spelt
/// exactly that way in a scratch tree during review and the suite stayed
/// green at 331 passing. The failure it produces is silence: those
/// workloads keep reporting nothing, and the Broker reads nothing as
/// `DenialsObserved: False, observed: 0` — checked, and clean.
///
/// `main.rs` now has no decision left to get wrong; it destructures what
/// `wire_registry` returns, and `wire_registry` is pinned by a test.
pub struct DenialRegistry(Option<ComputeMap>);

impl DenialRegistry {
    /// The registry, if denial capture is on. Borrowed, so a caller
    /// cannot detach it from the wiring it came out of.
    pub fn registry(&self) -> Option<&ComputeMap> {
        self.0.as_ref()
    }
}

/// Who gets the per-container cgroup registry, decided once.
///
/// Returned as owned handles rather than the booleans behind them,
/// because the booleans were what went wrong: see [`DenialRegistry`].
pub struct RegistryWiring {
    /// The registry itself, for the pod watcher to fill. `None` only
    /// when nothing on this node reads it.
    pub registry: Option<ComputeMap>,
    /// Registration events for the compute sampler. Subscribed ONLY when
    /// the gauges are on: a receiver with nothing draining it makes the
    /// broadcast channel back up to capacity for no reason.
    pub compute_events: Option<broadcast::Receiver<ComputeRegistration>>,
    /// The handle seccomp denial attribution resolves cgroups through.
    pub denial_cgroups: DenialRegistry,
}

/// Wire the container registry to its readers from the two switches that
/// decide it.
///
/// Takes the config structs, not two `bool`s, so the arguments cannot be
/// transposed or both filled from the same switch — the other sabotage
/// that survived the suite was `want_container_registry =
/// compute_config.enabled`, re-coupling the registry to the gauges,
/// which is the exact bug [`needs_container_registry`] exists to close.
///
/// One registry, shared: the sampler and the denial drain must resolve
/// the same cgroup ids, and handing them two would reintroduce the split
/// store this feature already had to remove once.
pub fn wire_registry(compute: &ComputeConfig, denial: &SeccompDenialConfig) -> RegistryWiring {
    let registry: Option<ComputeMap> = needs_container_registry(compute.enabled, denial.enabled)
        .then(|| Arc::new(ComputeRegistry::new()));
    RegistryWiring {
        compute_events: registry
            .as_ref()
            .filter(|_| compute.enabled)
            .map(|m| m.subscribe()),
        denial_cgroups: DenialRegistry(
            registry.as_ref().filter(|_| denial.enabled).map(Arc::clone),
        ),
        registry,
    }
}

/// The pod identity one attributed row carries, borrowed from whichever
/// of the two stores named it.
struct Named<'a> {
    uid: &'a str,
    name: &'a str,
    namespace: &'a str,
}

/// The container a cgroup id belongs to, in EITHER tier of the compute
/// registry.
///
/// `kguardian.dev/compute: "off"` files a pod in the identity-only tier
/// so it is never CPU-sampled. That annotation is about the cost of
/// gauges; it says nothing about whether the kernel is denying the
/// workload syscalls. Consulting `lookup_cgroup` alone would make
/// opting out of compute sampling quietly opt a workload out of denial
/// reporting too — a false all-clear bought with an unrelated
/// annotation, and exactly the kind of coupling this route exists to
/// remove rather than reintroduce.
fn container_for_cgroup(registry: &ComputeMap, cgroup_id: u64) -> Option<Arc<ContainerCompute>> {
    registry
        .lookup_cgroup(cgroup_id)
        .or_else(|| registry.lookup_identity(cgroup_id))
}

/// Attribute drained rows to pods and render them for the wire.
///
/// Pure over its inputs (the clock anchor is passed in) so the
/// attribution rules are testable without a kernel.
///
/// # The cost of getting this wrong
///
/// A denial credited to the wrong workload flips that workload's
/// `DenialsObserved` to `True` and blocks a promotion that should have
/// gone ahead, while the denials that were real disappear into it. An
/// unreported denial is a gap an operator can see; a misreported one is
/// an accusation against a workload that did nothing. So every rule
/// below refuses rather than guesses, and every refusal is counted into
/// [`AttributionLosses`] so the gap is a number and not a silence.
///
/// Two distinct ways an inode fails to name one pod, and neither
/// subsumes the other:
///
/// **The netns was reused.** The kernel hands netns inode numbers out of
/// an IDA, so a dead pod's number is handed to the next pod on the node.
/// The generation in the row's key settles it — but only because
/// identity and the generation it is checked against come from the SAME
/// `ContainerMap` entry, which is why this takes no kernel map. The
/// probe's `inode_num` map holds the same generation and is written
/// LATER: `pod_watcher` inserts the `ContainerMap` entry, then sends the
/// registration over an mpsc channel that `bpf.rs` only drains between
/// ring-buffer polls — at least the 100ms poll behind, and seconds
/// behind under load. Taking the generation from there while taking
/// identity from here left a window in which a just-recycled inode
/// resolved to its NEW pod while the kernel still held the OLD pod's
/// generation: the check passed, and the dead pod's denials were written
/// to the live pod. One entry carries one pod's UID, so deriving the
/// expected generation from it leaves nothing to interleave.
///
/// **The netns was never the pod's.** A `hostNetwork: true` pod has no
/// network namespace of its own: its inode is the NODE's, shared with
/// every other hostNetwork pod and with every host process — kubelet,
/// the containerd shims, a systemd unit with `SystemCallFilter=`. The
/// generation check is blind to this, because there is no mismatch to
/// find: whichever such pod registered last owns both the `ContainerMap`
/// entry and the kernel `inode_num` value, so the two agree with each
/// other and both name the wrong workload.
///
/// The netns cannot settle that, so a second identifier does. The probe
/// records `bpf_get_current_cgroup_id()` in every row, and a container's
/// cgroup is its own whether or not it shares the node's network
/// namespace. It is the TASK's cgroup: a workload that nests its own
/// (an image running systemd with cgroup delegation) reports a child of
/// the container scope, which the registry does not hold, so its rows
/// are refused and counted rather than misattributed. `cgroups` is the registry `pod_watcher` fills as it walks
/// each pod's containers — keyed on exactly that number, because
/// `name_to_handle_at` on the cgroup v2 directory yields what BPF
/// yields. So a hostNetwork pod's denials are attributed to it, its
/// neighbour's to the neighbour, and kubelet's to nobody: a host
/// process is in no container's cgroup, resolves to nothing, and is
/// refused. Only kubelet's row is refused now; the blanket refusal that
/// preceded this took the two workloads' rows with it.
///
/// Refusing is not neutral, and this is the second half of why the
/// cgroup route exists at all. A workload that produces no denial rows
/// is not reported as unmonitored — the Broker has nothing to report it
/// from, so it reads `DenialsObserved: False` with `observed: 0`,
/// "checked, and clean". Every refusal here is therefore a potential
/// false all-clear, which is why they are counted into
/// [`AttributionLosses`] and warned about rather than merely dropped.
///
/// Order matters: netns first for a pod that owns one. That path is
/// generation-checked against the same `ContainerMap` entry it takes
/// identity from, it needs nothing from containerd, and it is the path
/// every other probe in this tree uses. The cgroup route is what the
/// netns cannot do, not a replacement for it.
///
/// **The generation is not enough on its own**, because only a TRACKED
/// pod ever writes one. `EXCLUDED_NAMESPACES` switches off the netns
/// registration and nothing else, and no entry is ever removed from
/// either store, so an excluded pod handed a dead tracked pod's recycled
/// inode registers nothing: the stale `ContainerMap` entry and the stale
/// kernel generation survive together and agree with each other. The
/// check above passes on a row that belongs to neither pod. So when the
/// row's cgroup resolves to a container of a DIFFERENT pod — the one
/// identifier the exclusion list does not touch, because the registry is
/// filled for every pod on the node — the row is refused and counted
/// (`netns_cgroup_mismatch`). A cgroup the registry does not hold
/// contradicts nothing and costs a legitimate row nothing.
fn build_denials(
    rows: &[RawDenial],
    container_map: &ContainerMap,
    cgroups: Option<&ComputeMap>,
    anchor: &ClockAnchor,
) -> (Vec<SeccompDenial>, AttributionLosses) {
    let arch = scmp_arch_token();
    let mut losses = AttributionLosses::default();
    let mut names: HashMap<u32, String> = HashMap::new();
    // Both lookups are memoised across rows: under a storm one pod
    // contributes hundreds of rows, and neither the netns registration
    // nor a syscall's name changes within a single drain. Memoising the
    // pod is also what keeps one drain self-consistent — a registration
    // landing mid-drain cannot split one netns's rows between two pods.
    let mut pods: HashMap<u64, Option<PodAttribution>> = HashMap::new();
    // The cgroup route is memoised for the same reasons, and one more:
    // a container registered or retired mid-drain would otherwise split
    // one cgroup's rows between two answers.
    let mut containers: HashMap<u64, Option<Arc<ContainerCompute>>> = HashMap::new();
    let mut out = Vec::with_capacity(rows.len());

    for row in rows {
        let netns_pod = pods
            .entry(row.netns)
            .or_insert_with(|| pod_attribution(container_map, row.netns))
            .as_ref();

        let named = match netns_pod {
            // One inode, one pod: the netns route, generation-checked.
            Some(pod) if !pod.host_network => {
                // The check that stops a replacement pod being handed
                // its predecessor's denials.
                //
                // A mismatch does NOT prove the row belongs to a pod
                // that is gone, and this comment used to say it did.
                // Two rows are indistinguishable here, both carrying
                // the OLD generation: the dead pod's leftovers, and the
                // LIVE pod's own verdicts recorded during the
                // registration window, while `bpf.rs` had not yet
                // written the new flags to `inode_num`. Nothing in the
                // key separates them — that is what makes the window a
                // window.
                //
                // Attributing the pair to the live pod is what the
                // older code did, and it credited a dead workload's
                // denials to whatever took its inode. Dropping the pair
                // loses some of the live pod's own denials for as long
                // as the window lasts (a 100ms ring-buffer poll, longer
                // under load). That is the deliberate trade: the first
                // is a wrong answer about a workload that made no such
                // call, the second is a gap in a signal that is already
                // a floor rather than a total. Counted, not silent.
                if pod.generation != row.generation {
                    losses.stale_generation += 1;
                    continue;
                }
                // The generation is not on its own enough, because it is
                // only ever written by a pod the node TRACKS.
                //
                // `EXCLUDED_NAMESPACES` switches off the netns
                // registration (`pod_watcher::registration_plan`), and
                // nothing ever removes a `ContainerMap` entry or an
                // `inode_num` value — the generation is what handles
                // recycling. So when a tracked pod dies and an
                // EXCLUDED-namespace pod is handed its netns inode, the
                // successor never registers: the stale entry and the
                // stale kernel generation survive together and AGREE
                // with each other. The check above passes, and the new
                // pod's denials are credited, permanently, to a dead
                // workload in another namespace. A tracked successor
                // cannot do this — its own registration overwrites both
                // — so the exclusion list is the whole difference
                // between a gap and an accusation.
                //
                // The row carries a second, independent identifier that
                // the exclusion list does not touch: the cgroup id of
                // the task that made the call. The cgroup registry is
                // filled for every pod on the node, excluded namespaces
                // included, so when it names a container the answer owes
                // nothing to whether the namespace is tracked. If it
                // names a container of a DIFFERENT pod, one of the two
                // identifiers is stale and the row says nothing about
                // which — so it is refused, like every other
                // disagreement in this function.
                //
                // It cannot fire on a legitimate row. A cgroup id it
                // does not hold — a nested cgroup, an init or ephemeral
                // container, the pause container, a host process —
                // resolves to `None` and contradicts nothing; only two
                // positive answers that name different pods count.
                let contradicted = match cgroups {
                    None => false,
                    Some(registry) => containers
                        .entry(row.cgroup_id)
                        .or_insert_with(|| container_for_cgroup(registry, row.cgroup_id))
                        .as_deref()
                        .is_some_and(|c| c.pod_uid != pod.uid),
                };
                if contradicted {
                    losses.netns_cgroup_mismatch += 1;
                    continue;
                }
                Named {
                    uid: &pod.uid,
                    name: &pod.name,
                    namespace: &pod.namespace,
                }
            }
            // The inode names no single pod: either it is the node's
            // (hostNetwork) or nothing is registered on it any more.
            // The cgroup does name one.
            shared => {
                let Some(registry) = cgroups else {
                    // Explicit, and counted on its own. The registry is
                    // built whenever denial capture is on, so its
                    // absence is a wiring fault rather than a property
                    // of the row — and treating it as "unresolvable"
                    // would file a fixable misconfiguration under the
                    // same number as kubelet's own syscalls.
                    losses.no_container_registry += 1;
                    continue;
                };
                let resolved = containers
                    .entry(row.cgroup_id)
                    .or_insert_with(|| container_for_cgroup(registry, row.cgroup_id));
                match resolved.as_deref() {
                    Some(c) => Named {
                        uid: &c.pod_uid,
                        name: &c.pod_name,
                        namespace: &c.namespace,
                    },
                    None => {
                        if shared.is_some() {
                            losses.unresolved_cgroup += 1;
                            losses
                                .unresolved_cgroup_example
                                .get_or_insert(row.cgroup_id);
                        } else {
                            losses.unknown_pod += 1;
                        }
                        continue;
                    }
                }
            }
        };

        if named.uid.is_empty() {
            losses.missing_uid += 1;
        }

        // The map stores the number as the u32 the probe cast it to;
        // reinterpret those bits as the `int` the kernel actually passed.
        let syscall_nr = row.syscall_nr as i32;
        let syscall = names
            .entry(row.syscall_nr)
            .or_insert_with(|| syscall_display_name(syscall_nr))
            .clone();

        out.push(SeccompDenial {
            pod_uid: named.uid.to_string(),
            pod_name: named.name.to_string(),
            pod_namespace: named.namespace.to_string(),
            syscall,
            syscall_nr,
            action: action_name(row.action),
            action_raw: row.action,
            arch,
            count: row.count,
            first_seen: mono_to_utc(anchor, row.first_seen_ns),
            last_seen: mono_to_utc(anchor, row.last_seen_ns),
        });
    }

    (out, losses)
}

/// Collapse rows that share the Broker's identity for a denial.
///
/// Not an optimisation. The ingest upserts on the denial's identity, and
/// PostgreSQL refuses an `ON CONFLICT DO UPDATE` whose statement touches
/// the same row twice ("cannot affect row a second time") — so a payload
/// containing two rows with the same identity does not merely
/// double-count, it fails the whole batch. Two rows can genuinely arrive
/// with the same identity: a pod that made the same denied call under two
/// netns generations, and — until `pod_uid` is populated at all — any two
/// pods at once.
///
/// Counts add, `first_seen` takes the earliest and `last_seen` the
/// latest, which is exactly what the Broker's own upsert would have done
/// across ticks. `BTreeMap` so the output order is stable for a test to
/// assert on.
fn merge_denials(rows: Vec<SeccompDenial>) -> Vec<SeccompDenial> {
    type Identity = (String, String, String, String, &'static str);
    let mut merged: BTreeMap<Identity, SeccompDenial> = BTreeMap::new();

    for row in rows {
        let identity = (
            row.pod_uid.clone(),
            row.pod_namespace.clone(),
            row.pod_name.clone(),
            row.syscall.clone(),
            row.action,
        );
        merged
            .entry(identity)
            .and_modify(|existing| {
                existing.count = existing.count.saturating_add(row.count);
                existing.first_seen = existing.first_seen.min(row.first_seen);
                existing.last_seen = existing.last_seen.max(row.last_seen);
            })
            .or_insert(row);
    }

    merged.into_values().collect()
}

/// Split one tick's rows into the bodies it will be POSTed as.
///
/// Two invariants, both of which have a way of quietly going wrong:
///
///  * **Nothing is dropped.** Every row lands in exactly one chunk. A
///    drain can exceed the Broker's 4 MiB body limit — the kernel map
///    holds 65 536 rows and a decoder in a tight loop on a blocked
///    syscall will fill it — and the tempting fix, truncating the batch,
///    throws away most of the storm this feature exists to report.
///  * **An empty batch still produces one body.** That request is the
///    node's capture heartbeat. Returning no chunks for it would make a
///    cluster where nothing has been denied look exactly like a cluster
///    where nothing is watching.
fn post_chunks(batch: &[SeccompDenial]) -> Vec<&[SeccompDenial]> {
    if batch.is_empty() {
        vec![&[]]
    } else {
        batch.chunks(MAX_DENIALS_PER_POST).collect()
    }
}

/// How many rows the Broker says it stored, from its ingest response.
///
/// `None` when the field is absent or not a number — an older Broker, or
/// a proxy that rewrote the body. That is NOT a shortfall: treating an
/// unreadable response as rows refused would turn every POST to an older
/// Broker into a data-loss warning, which is the same false alarm in the
/// other direction.
fn accepted_rows(response: &serde_json::Value) -> Option<u64> {
    response.get("accepted")?.as_u64()
}

/// How many of the `sent` rows the Broker did not store, or `None` when
/// it stored them all or did not say.
///
/// `stored > sent` returns `None` rather than a negative: a Broker
/// counting higher than it was offered is a Broker-side bug, and the
/// Controller has nothing useful to say about it from here.
fn refused_rows_in(sent: usize, response: &serde_json::Value) -> Option<u64> {
    let stored = accepted_rows(response)?;
    // `checked_sub`, not `(stored < sent).then_some(sent - stored)`:
    // `then_some` takes its argument by value and so evaluates the
    // subtraction whatever the condition says, which underflows on the
    // `stored > sent` case — a panic in debug and a wrapped u64
    // reported as "refused 18446744073709551615" in release.
    (sent as u64).checked_sub(stored).filter(|&r| r > 0)
}

/// True when the error the POST returned is a 404 from the Broker.
///
/// `client::api_post_call_json` flattens every non-2xx into `Error::ApiError` with a
/// formatted message, so the status has to be recovered from that text.
/// The coupling is pinned by `a_404_body_is_recognised_as_a_missing_endpoint`
/// below; if `client.rs` ever grows a typed status this should use it
/// instead.
fn broker_lacks_endpoint(error: &Error) -> bool {
    matches!(error, Error::ApiError(message) if message.contains("broker returned 404"))
}

/// Read-and-clear the kernel's aggregate.
///
/// Every key is collected BEFORE any row is removed.
/// `bpf_map_get_next_key()` on a hash map restarts from the first key
/// when handed a key that no longer exists, so walking the iterator while
/// deleting the row it just yielded can loop or repeat indefinitely.
/// Snapshotting the key list sidesteps the interaction entirely; a row
/// created after the snapshot is simply drained on the next tick.
///
/// Infallible on purpose. A row that cannot be read is counted and
/// skipped rather than aborting the drain, because by the time one fails
/// the rows before it have ALREADY been removed from the map — giving up
/// would throw away real, unreportable-any-other-way counts to report an
/// error about one row.
fn drain(maps: &DenialMaps) -> DrainOutcome {
    let keys: Vec<Vec<u8>> = maps.denials.keys().collect();
    let occupancy = keys.len();
    let mut rows = Vec::with_capacity(occupancy);
    let mut read_errors = 0usize;

    for key in keys {
        let value = match maps.take(&key) {
            Ok(Some(value)) => value,
            // Evicted between the key snapshot and the read. Its counts
            // are gone either way; nothing to report.
            Ok(None) => continue,
            Err(e) => {
                if read_errors == 0 {
                    warn!(error = %e, "could not drain a seccomp denial row; skipping it");
                }
                read_errors += 1;
                continue;
            }
        };
        let (Some(k), Some(v)) = (denial_key_from_bytes(&key), denial_value_from_bytes(&value))
        else {
            // A short key or value means this build's layout and the
            // loaded object's disagree, which is a build-time mistake
            // rather than a runtime condition. Skip the row rather than
            // reading past it.
            read_errors += 1;
            continue;
        };
        rows.push(RawDenial {
            netns: k.0,
            cgroup_id: k.1,
            generation: k.2,
            syscall_nr: k.3,
            action: k.4,
            count: v.0,
            first_seen_ns: v.1,
            last_seen_ns: v.2,
        });
    }

    DrainOutcome {
        rows,
        occupancy,
        update_failures: maps.stat(STAT_UPDATE_FAILURES),
        read_errors,
    }
}

/// Drain the probe's aggregate on a timer and ship it to the Broker.
///
/// Returns `Ok(())` — never an error — only when the feature is switched
/// off; otherwise it runs for the life of the process, INCLUDING on a node
/// whose kernel could not carry the probe. There it drains nothing and
/// posts an empty `capturing: false` heartbeat every interval, which is
/// how the Broker learns the difference between a node that saw no denials
/// and a node that was never watching.
///
/// Runs as the `seccomp-denials` subsystem (`Disposition::MayRetire`),
/// so the switched-off `Ok(())` is an allowed exit while an `Err` or a
/// panic is a fault that ends the Controller. See its spawn site in
/// `main.rs` for why supervision matters here even though this function
/// has no fallible path today.
pub async fn run(
    config: SeccompDenialConfig,
    node_name: String,
    container_map: ContainerMap,
    cgroups: DenialRegistry,
    maps: oneshot::Receiver<DenialMaps>,
) -> Result<(), Error> {
    if !config.enabled {
        info!("{CAPTURE_ENV} is off; kernel seccomp verdicts will not be captured");
        return Ok(());
    }

    // Said at startup, not only once a denial has been lost to it.
    //
    // `wire_registry` cannot hand this task an absent registry while the
    // feature is on — `needs_container_registry` builds one for either
    // switch, and `DenialRegistry`'s field is private, so no caller can
    // substitute `None`. This is therefore unreachable today and is kept
    // for the day a second construction route appears: the failure it
    // would announce is silence, and silence is what this whole module
    // is arranged to make loud. hostNetwork workloads would keep
    // reporting nothing, and nothing reporting reads as nothing denied.
    let cgroups: Option<ComputeMap> = cgroups.registry().map(Arc::clone);
    if cgroups.is_none() {
        warn!(
            "no per-container cgroup registry was handed to seccomp denial capture. \
             hostNetwork pods share the node's network namespace, so their denials can \
             only be attributed by cgroup id; without the registry they will be counted \
             and dropped, and those workloads will appear never to have been denied \
             anything. This is a wiring fault in the Controller, not a property of the \
             node."
        );
    }

    // The sender is dropped without a value when the eBPF loader skipped
    // the probe — no `audit_seccomp` symbol, or a load/attach failure it
    // decided to survive. That is NOT a reason to stop: this task keeps
    // running and keeps reporting in with `capturing: false`, because a
    // node that is alive but not capturing and a node that is simply
    // quiet are the two things the Broker most needs to tell apart.
    // Retiring here would make a CONFIG_AUDITSYSCALL=n node
    // indistinguishable from one that has seen no denials.
    let maps: Option<Arc<DenialMaps>> = match maps.await {
        Ok(maps) => Some(Arc::new(maps)),
        Err(_) => {
            warn!(
                "seccomp denial probe is not loaded on this node (see the earlier warning \
                 for why); reporting capturing=false to the Broker every interval so it \
                 does not read this node's silence as a clean bill of health"
            );
            None
        }
    };
    let capturing = maps.is_some();
    let map_capacity = maps
        .as_ref()
        .map(|m| m.denials.max_entries() as usize)
        .unwrap_or(0);
    info!(
        interval_secs = config.interval.as_secs(),
        capturing, map_capacity, "seccomp denial capture running"
    );

    let mut ticker = tokio::time::interval(config.interval);
    // A slow Broker must not be repaid with a burst of catch-up ticks;
    // each drain should cover the time since the last one actually ran.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Rows a failed POST could not deliver, merged into the next tick's
    // batch. Without this a single Broker blip would silently erase a
    // whole interval's denials — the map has already been cleared by the
    // time the POST is attempted, so there is nothing to re-read.
    let mut pending: Vec<SeccompDenial> = Vec::new();
    let mut endpoint_missing = false;
    let mut last_update_failures = 0u64;
    let mut warned_missing_uid = false;
    let mut warned_unresolved_cgroup = false;
    let mut warned_no_registry = false;
    let mut warned_netns_cgroup_mismatch = false;
    // Rows the Broker accepted the request for but refused to store,
    // accumulated for the life of the process.
    //
    // Counted, NOT retried, and that is a deliberate choice rather than
    // the easy one. Every rejection the ingest can return is a fixed
    // property of the row — an empty or oversized `podUid`, `podName`,
    // `podNamespace`, `syscall`, `action` or `arch`, or a `count` that
    // is zero, negative or past its ceiling (`reject_reason` in
    // `broker/src/seccomp_denial.rs`). None of them can come good on a
    // later attempt, so a retry is guaranteed to be refused again.
    //
    // Retrying them would make things worse in two concrete ways. The
    // rows would sit in `pending` being re-POSTed every interval until
    // they reached `MAX_PENDING_DENIALS` and started evicting VALID
    // rows — trading one node's bad rows for every other pod's good
    // ones. And each retry re-sends the whole chunk, including the rows
    // that WERE stored: the Broker accumulates counts as deltas
    // (`count = count + excluded`), so replaying an accepted row
    // inflates a real workload's denial total. A retry loop here would
    // manufacture denials that never happened in the signal an operator
    // promotes a profile on.
    //
    // So the rows are lost, loudly. The fix for a refusal is in
    // whatever built the row, and the warning says so.
    let mut refused_rows = 0u64;

    loop {
        ticker.tick().await;

        // With no probe there is nothing to drain, but the tick still has
        // to reach the POST below — that empty report is the heartbeat.
        let drained = match maps.as_ref() {
            None => DrainOutcome::default(),
            Some(maps) => {
                // The drain is tens of thousands of `bpf()` syscalls in the
                // worst case (a map that filled under a storm), which is
                // long enough to matter on a Tokio worker. Off to the
                // blocking pool, the same rule the rest of this Controller
                // follows.
                let drain_maps = Arc::clone(maps);
                match tokio::task::spawn_blocking(move || drain(&drain_maps)).await {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        warn!(error = %e, "the seccomp denial drain task did not complete; retrying next tick");
                        continue;
                    }
                }
            }
        };

        // Anchor AFTER the drain so no row can be stamped later than it.
        let anchor = ClockAnchor::now();

        if drained.read_errors > 0 {
            warn!(
                rows = drained.read_errors,
                "seccomp denial rows were removed from the kernel map but could not be read \
                 back; their counts are lost"
            );
        }
        if drained.update_failures > last_update_failures {
            warn!(
                lost = drained.update_failures - last_update_failures,
                "the kernel saw seccomp verdicts it could not record; reported counts are a \
                 floor, not a total"
            );
            last_update_failures = drained.update_failures;
        }
        if map_capacity > 0
            && (drained.occupancy as f64) >= (map_capacity as f64) * OCCUPANCY_WARN_RATIO
        {
            warn!(
                occupancy = drained.occupancy,
                capacity = map_capacity,
                "the seccomp denial map is near capacity; LRU eviction is likely discarding \
                 rows between drains, so counts are a floor"
            );
        }

        let (fresh, losses) =
            build_denials(&drained.rows, &container_map, cgroups.as_ref(), &anchor);
        if losses.unknown_pod > 0
            || losses.stale_generation > 0
            || losses.unresolved_cgroup > 0
            || losses.no_container_registry > 0
        {
            // Per tick, so the ongoing rate is countable. The warnings
            // below fire once each and would otherwise be the only
            // trace of a loss that is still happening every interval.
            debug!(
                unknown_pod = losses.unknown_pod,
                stale_generation = losses.stale_generation,
                unresolved_cgroup = losses.unresolved_cgroup,
                no_container_registry = losses.no_container_registry,
                "seccomp denial rows dropped: their pod is gone and their cgroup is not a \
                 container on this node; or the generation does not match the pod on that \
                 inode, which is a recycled netns or a pod registered too recently for the \
                 kernel to be stamping its new generation yet; or the netns is the node's \
                 and the cgroup resolved to nothing, which is what a host process looks like"
            );
        }
        // Once, loudly. The Broker requires a non-empty podUid and
        // rejects rows without one, so this is the difference between
        // "this node observed no denials" and "some denials this node
        // observed were thrown away". It must not be something an
        // operator has to infer from a table that is short.
        if losses.missing_uid > 0 && !warned_missing_uid {
            warn!(
                rows = losses.missing_uid,
                "seccomp denials are being reported with an empty podUid, so the Broker will \
                 reject them. Their pod reached the netns map without a metadata.uid — see \
                 the pod-watcher warning naming it."
            );
            warned_missing_uid = true;
        }
        // Also once, loudly, and for the same reason. Most rows here
        // are the node's own processes — kubelet, a containerd shim, a
        // systemd unit with `SystemCallFilter=` — which belong to no
        // container and are correctly credited to nobody. But a
        // CONTAINER whose cgroup never resolves lands in the same
        // number, and that case is a workload reporting no denials
        // because nothing could attribute them, which the Broker cannot
        // tell from a workload that was never denied anything. The
        // pod-watcher logs a warning naming any container whose cgroup
        // it could not resolve; that is where to look if this count
        // does not match the node's own noise.
        if losses.unresolved_cgroup > 0 && !warned_unresolved_cgroup {
            warn!(
                rows = losses.unresolved_cgroup,
                example_cgroup_id = losses.unresolved_cgroup_example.unwrap_or(0),
                "seccomp denials from the node's own network namespace resolved to no \
                 container on this node and were dropped rather than credited to whichever \
                 hostNetwork pod registered that namespace last. Expected for the node's \
                 own processes; for a container it means its cgroup is not registered, and \
                 that workload will look as though it has never been denied anything. \
                 `bpftool cgroup tree` resolves the id above."
            );
            warned_unresolved_cgroup = true;
        }
        // The wiring fault, once. Distinct from the above because it
        // has a fix, and because it takes out every hostNetwork pod on
        // the node at once rather than one whose cgroup went missing.
        if losses.no_container_registry > 0 && !warned_no_registry {
            warn!(
                rows = losses.no_container_registry,
                "seccomp denials that need cgroup attribution are being dropped because no \
                 container registry was handed to this task. See the startup warning."
            );
            warned_no_registry = true;
        }
        // Once, and loudly: unlike the counts above this one is never
        // expected on a healthy node. It means a netns inode that still
        // resolves to one pod carried denials from a container of
        // another, which is a stale `ContainerMap` entry whose successor
        // never registered. `EXCLUDED_NAMESPACES` is the way that
        // happens: an excluded pod inherits a tracked pod's recycled
        // inode and registers nothing, so the dead pod's entry and the
        // kernel's generation agree with each other and name the wrong
        // workload. The rows are refused rather than credited; naming
        // the namespace list is what lets an operator act on it.
        if losses.netns_cgroup_mismatch > 0 && !warned_netns_cgroup_mismatch {
            warn!(
                rows = losses.netns_cgroup_mismatch,
                "seccomp denials arrived on a network namespace registered to one pod while \
                 their cgroup belongs to a container of another, and were dropped rather \
                 than credited to either. The usual cause is a pod in an EXCLUDED_NAMESPACES \
                 namespace inheriting a recycled netns inode from a tracked pod: it registers \
                 nothing, so the dead pod's registration survives and looks current. Narrowing \
                 EXCLUDED_NAMESPACES removes it."
            );
            warned_netns_cgroup_mismatch = true;
        }

        let mut batch = std::mem::take(&mut pending);
        batch.extend(fresh);
        let mut batch = merge_denials(batch);
        // Oldest first, so the backlog cap after the POSTs drops the
        // stalest rows rather than whichever the merge ordered last.
        batch.sort_by_key(|d| d.last_seen);

        let chunks = post_chunks(&batch);

        let mut undelivered: Vec<SeccompDenial> = Vec::new();
        let mut delivered = 0usize;
        // Latched for this tick only: once the Broker has 404'd the
        // route, offering it the remaining chunks is more round trips to
        // the same answer.
        let mut route_missing_this_tick = false;
        for chunk in chunks {
            if route_missing_this_tick {
                undelivered.extend_from_slice(chunk);
                continue;
            }
            let body = denial_batch_body(&node_name, capturing, config.interval, chunk);
            match api_post_call_json(body, DENIALS_PATH).await {
                Ok(response) => {
                    delivered += chunk.len();
                    // A 2xx is not proof the rows were stored. The
                    // Broker validates per row and answers
                    // `200 {"accepted": n}`, so a batch it refused whole
                    // still comes back as success — and the kernel map
                    // was cleared before this POST, so a refused row
                    // exists nowhere else on the node. Left unchecked
                    // this is unrecoverable loss behind a green
                    // `capturing: true` heartbeat, which reads as a
                    // clean bill of health.
                    if let Some(refused) = refused_rows_in(chunk.len(), &response) {
                        refused_rows = refused_rows.saturating_add(refused);
                        warn!(
                            sent = chunk.len(),
                            refused,
                            refused_since_start = refused_rows,
                            "the Broker did not store every seccomp denial it was sent. Those \
                             rows are gone: the kernel map is cleared before the POST, so there \
                             is no copy to resend, and they are not retried because every \
                             rejection the ingest can return would reject them again. The \
                             Broker's ingest log names the field it refused them on — this is a \
                             row the Controller built wrong, not a transport failure."
                        );
                    }
                    if endpoint_missing {
                        info!("Broker now accepts {DENIALS_PATH}; denial reporting resumed");
                        endpoint_missing = false;
                    }
                }
                Err(e) if broker_lacks_endpoint(&e) => {
                    if !endpoint_missing {
                        warn!(
                            "Broker does not serve POST /{DENIALS_PATH} (404); it predates \
                             seccomp denial capture. Denials will be held and retried, and \
                             the Controller continues normally."
                        );
                        endpoint_missing = true;
                    }
                    route_missing_this_tick = true;
                    undelivered.extend_from_slice(chunk);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        rows = chunk.len(),
                        "posting seccomp denials failed; they will be merged into the next batch"
                    );
                    undelivered.extend_from_slice(chunk);
                }
            }
        }

        if delivered > 0 {
            debug!(rows = delivered, "seccomp denials reported");
        }

        // The backlog cap applies HERE, to what the Broker refused —
        // never to a batch on its way out. Capping before the POST would
        // discard most of a denial storm rather than chunking it, which
        // is the one failure this path exists to survive.
        if undelivered.len() > MAX_PENDING_DENIALS {
            let dropped = undelivered.len() - MAX_PENDING_DENIALS;
            warn!(
                dropped,
                kept = MAX_PENDING_DENIALS,
                "more undelivered seccomp denials than the Controller will hold; dropping \
                 the oldest. The Broker has been unreachable or rejecting this endpoint."
            );
            undelivered.drain(..dropped);
        }
        pending = undelivered;
    }
}

// ---- wire decoding -------------------------------------------------
//
// These mirror `struct seccomp_denial_key` / `struct seccomp_denial_value`
// in src/bpf/seccomp_denial.bpf.c, whose sizes are pinned there by
// _Static_assert. Native endianness, because both sides are the same
// machine.

/// `(netns, cgroup_id, generation, syscall_nr, action)`.
type DenialKey = (u64, u64, u32, u32, u32);
/// `(count, first_seen_ns, last_seen_ns)`.
type DenialValue = (u64, u64, u64);

/// `sizeof(struct seccomp_denial_key)`, pinned by `_Static_assert` in
/// the probe.
const DENIAL_KEY_BYTES: usize = 32;
/// `sizeof(struct seccomp_denial_value)`, likewise.
const DENIAL_VALUE_BYTES: usize = 24;

/// Exact length, not a minimum.
///
/// A minimum was the wrong test the moment the key grew. `libbpf` hands
/// back exactly `key_size` bytes, so a length that is not the expected
/// one means this build's layout and the loaded object's disagree — and
/// decoding the first 20 or 28 bytes of a longer key anyway reads
/// `generation`, `syscall_nr` and `action` out of whatever now sits at
/// those offsets. That is not a partial read, it is counts attributed to
/// the wrong pod against the wrong syscall, which is the one outcome
/// this whole module refuses everywhere else. Rejecting the row instead
/// counts it into `DrainOutcome::read_errors`, which warns.
fn denial_key_from_bytes(b: &[u8]) -> Option<DenialKey> {
    if b.len() != DENIAL_KEY_BYTES {
        return None;
    }
    Some((
        u64_from_bytes(&b[..8])?,
        u64_from_bytes(&b[8..16])?,
        u32_from_bytes(&b[16..20])?,
        u32_from_bytes(&b[20..24])?,
        u32_from_bytes(&b[24..28])?,
    ))
}

fn denial_value_from_bytes(b: &[u8]) -> Option<DenialValue> {
    if b.len() != DENIAL_VALUE_BYTES {
        return None;
    }
    Some((
        u64_from_bytes(&b[..8])?,
        u64_from_bytes(&b[8..16])?,
        u64_from_bytes(&b[16..24])?,
    ))
}

fn u64_from_bytes(b: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(..8)?.try_into().ok()?))
}

fn u32_from_bytes(b: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    fn anchor_at(wall: DateTime<Utc>, mono_ns: u64) -> ClockAnchor {
        ClockAnchor { wall, mono_ns }
    }

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("test timestamp parses")
            .with_timezone(&Utc)
    }

    /// A `ContainerMap` shaped the way `pod_watcher::register_netns`
    /// builds one: `status` AND `info.config.metadata`, uid included.
    ///
    /// A row this pod should be credited with must carry
    /// `gen_of(its uid)` — that is the generation the same registration
    /// packed into the kernel map, and therefore the one the probe
    /// stamps on its rows.
    fn pod_at(netns: u64, name: &str, namespace: &str) -> ContainerMap {
        pod_at_with_uid(netns, name, namespace, "3f2b-uid")
    }

    fn pod_at_with_uid(netns: u64, name: &str, namespace: &str, uid: &str) -> ContainerMap {
        let map = DashMap::new();
        map.insert(netns, Arc::new(pod_entry(name, namespace, uid, false)));
        Arc::new(map)
    }

    /// One `ContainerMap` value, built the way
    /// `pod_watcher::netns_registration` builds one — including
    /// `host_network`, which is what says whether the inode it is filed
    /// under belongs to this pod or to the node.
    fn pod_entry(name: &str, namespace: &str, uid: &str, host_network: bool) -> crate::PodInspect {
        crate::PodInspect {
            status: crate::models::PodInfo {
                pod_name: name.to_string(),
                pod_namespace: Some(namespace.to_string()),
                pod_ip: String::new(),
            },
            info: crate::models::Info {
                config: crate::models::Config {
                    metadata: crate::models::Metadata {
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        uid: uid.to_string(),
                    },
                },
            },
            host_network,
            ..Default::default()
        }
    }

    /// The generation the probe will stamp on a row for a pod with this
    /// UID.
    ///
    /// Runs the REAL registration path to get it —
    /// `pod_watcher::pod_registration_flags`, the same call whose result
    /// `bpf.rs` writes into `inode_num` — rather than restating its
    /// derivation. A fixture that re-derived it would keep agreeing with
    /// itself after that function changed, so every test below would
    /// stay green while the probe stamped a number the drain no longer
    /// expects and the node dropped every denial as `stale_generation`.
    fn gen_of(uid: &str) -> u32 {
        let mut pod = k8s_openapi::api::core::v1::Pod::default();
        pod.metadata.uid = Some(uid.to_string());
        pod.metadata.name = Some("fixture".to_string());
        pod.metadata.namespace = Some("media".to_string());
        pod_flags::generation(crate::pod_watcher::pod_registration_flags(
            &pod,
            crate::capture_tiers::CaptureLevel::Medium,
        ))
    }

    /// The cgroup id a task in the ROOT cgroup carries.
    ///
    /// `bpf_get_current_cgroup_id()` has no "no cgroup" sentinel — it is
    /// `task_dfl_cgroup(current)->kn->id` and `task_dfl_cgroup()` is
    /// never NULL, so a host with no cgroup v2 in use still yields the
    /// root's kernfs id rather than 0. Measured on a live kernel: 1 for
    /// kernel threads on a normally booted host, and 0 never observed
    /// for any task. On a node whose cgroups are managed on the v1
    /// hierarchy this is what EVERY row carries.
    ///
    /// It is in no container's registry entry, because a container's
    /// cgroup is a strict descendant of the root and
    /// `compute_registry::resolve_container_cgroup` refuses to register
    /// one under the root itself. That — not the value — is what makes a
    /// row carrying it unattributable.
    const ROOT_CGROUP_ID: u64 = 1;

    /// A row from a task in the root cgroup: a real id that resolves to
    /// no container. Every pod-network case uses it, which is the point:
    /// those rows must be attributed by the netns alone, without the
    /// cgroup route having anything to offer.
    fn raw(netns: u64, generation: u32, syscall_nr: u32, action: u32, count: u64) -> RawDenial {
        raw_cg(netns, ROOT_CGROUP_ID, generation, syscall_nr, action, count)
    }

    /// The same row with a cgroup id: the container that made the call.
    fn raw_cg(
        netns: u64,
        cgroup_id: u64,
        generation: u32,
        syscall_nr: u32,
        action: u32,
        count: u64,
    ) -> RawDenial {
        RawDenial {
            netns,
            cgroup_id,
            generation,
            syscall_nr,
            action,
            count,
            first_seen_ns: 1_000,
            last_seen_ns: 2_000,
        }
    }

    /// One container in the cgroup registry, built the way
    /// `pod_watcher::register_compute` builds one.
    fn container(
        pod_uid: &str,
        namespace: &str,
        pod_name: &str,
        container_name: &str,
        cgroup_id: u64,
    ) -> ContainerCompute {
        ContainerCompute {
            pod_uid: pod_uid.to_string(),
            namespace: namespace.to_string(),
            pod_name: pod_name.to_string(),
            container_name: container_name.to_string(),
            container_id: format!("containerd://{cgroup_id:x}"),
            pid: 4242,
            cgroup_path: format!("kubepods.slice/cri-containerd-{cgroup_id:x}.scope"),
            cgroup_id,
            resources: Default::default(),
            node: "ip-10-0-1-23.ec2.internal".to_string(),
        }
    }

    fn registry(containers: &[ContainerCompute]) -> ComputeMap {
        let r = Arc::new(crate::compute_registry::ComputeRegistry::new());
        for c in containers {
            r.insert_container(c.clone());
        }
        r
    }

    fn denial(pod: &str, syscall: &str, count: u64, first: &str, last: &str) -> SeccompDenial {
        SeccompDenial {
            // Distinct per pod, as a real UID is: the merge key leads
            // with it, so a fixture that shared one everywhere would let
            // a merge keyed on nothing else still look correct.
            pod_uid: format!("{pod}-uid"),
            pod_name: pod.to_string(),
            pod_namespace: "media".to_string(),
            syscall: syscall.to_string(),
            syscall_nr: 101,
            action: "SCMP_ACT_LOG",
            action_raw: SECCOMP_RET_LOG,
            arch: Some("SCMP_ARCH_X86_64"),
            count,
            first_seen: utc(first),
            last_seen: utc(last),
        }
    }

    // ---- action mapping ----
    //
    // The action is what turns "the kernel logged something" into "the
    // kernel KILLED this workload". Mapping one to the other's spelling
    // would misreport an outage as an audit note, so every raw value the
    // kernel can pass is pinned.

    /// The raw values themselves, against the kernel's numbers.
    ///
    /// Every other test in this section feeds `action_name` a
    /// `SECCOMP_RET_*` constant from this module and checks the name it
    /// returns. That pins the mapping but not the constants: mistype one
    /// and both sides of those assertions move together, so they stay
    /// green while the kernel sends a number the table no longer has and
    /// every denial from that action reports as `SCMP_ACT_UNKNOWN`.
    /// These are the literals from `include/uapi/linux/seccomp.h`, which
    /// is the only thing this file cannot re-derive.
    #[test]
    fn the_raw_action_values_are_the_kernels() {
        assert_eq!(SECCOMP_RET_KILL_PROCESS, 0x8000_0000);
        assert_eq!(SECCOMP_RET_KILL_THREAD, 0x0000_0000);
        assert_eq!(SECCOMP_RET_TRAP, 0x0003_0000);
        assert_eq!(SECCOMP_RET_ERRNO, 0x0005_0000);
        assert_eq!(SECCOMP_RET_USER_NOTIF, 0x7fc0_0000);
        assert_eq!(SECCOMP_RET_TRACE, 0x7ff0_0000);
        assert_eq!(SECCOMP_RET_LOG, 0x7ffc_0000);
        assert_eq!(SECCOMP_RET_ALLOW, 0x7fff_0000);
        // Mirrors KG_SECCOMP_RET_ACTION_FULL in the probe; the two mask
        // the same bits or the key the kernel writes and the value
        // userspace names disagree.
        assert_eq!(SECCOMP_RET_ACTION_FULL, 0xffff_0000);
    }

    #[test]
    fn every_loggable_seccomp_action_maps_to_its_scmp_spelling() {
        assert_eq!(action_name(SECCOMP_RET_LOG), "SCMP_ACT_LOG");
        assert_eq!(action_name(SECCOMP_RET_ERRNO), "SCMP_ACT_ERRNO");
        assert_eq!(action_name(SECCOMP_RET_TRAP), "SCMP_ACT_TRAP");
        assert_eq!(action_name(SECCOMP_RET_TRACE), "SCMP_ACT_TRACE");
        assert_eq!(action_name(SECCOMP_RET_USER_NOTIF), "SCMP_ACT_NOTIFY");
        assert_eq!(action_name(SECCOMP_RET_KILL_THREAD), "SCMP_ACT_KILL");
        assert_eq!(
            action_name(SECCOMP_RET_KILL_PROCESS),
            "SCMP_ACT_KILL_PROCESS"
        );
        assert_eq!(action_name(SECCOMP_RET_ALLOW), "SCMP_ACT_ALLOW");
    }

    #[test]
    fn an_errno_in_the_data_field_does_not_hide_the_action() {
        // SECCOMP_RET_ERRNO carries the errno in its low 16 bits. The
        // kernel masks before calling audit_seccomp and the probe masks
        // again, but if either ever stopped, matching on the full 32-bit
        // value would report EPERM-returning filters as
        // SCMP_ACT_UNKNOWN — a real denial rendered as a kernel
        // mystery.
        assert_eq!(action_name(SECCOMP_RET_ERRNO | 1), "SCMP_ACT_ERRNO");
        assert_eq!(action_name(SECCOMP_RET_ERRNO | 13), "SCMP_ACT_ERRNO");
    }

    #[test]
    fn an_unknown_action_is_named_unknown_and_never_guessed() {
        assert_eq!(action_name(0x0001_0000), "SCMP_ACT_UNKNOWN");
        assert_eq!(action_name(0x1234_0000), "SCMP_ACT_UNKNOWN");
    }

    // ---- syscall naming ----

    #[test]
    fn an_unresolvable_syscall_number_is_still_reported() {
        // Dropping the row would turn "denied a syscall we cannot name"
        // into "no denials", which is the one answer that must never be
        // wrong. 60000 is far outside any arch's table.
        assert_eq!(syscall_display_name(60_000), "syscall_60000");
    }

    /// `syscall(-1)` is a call any unprivileged process can make. Under
    /// an `SCMP_ACT_LOG` profile the kernel evaluates it, denies it, and
    /// logs it with `this_syscall == -1`. The row has to survive all the
    /// way to the Broker as `-1`: sent as the u32 it is stored as, it
    /// would be 4294967295 against an `INTEGER` column, and serde would
    /// reject the entire batch — one call from one container erasing
    /// every denial on the node.
    #[test]
    fn a_negative_syscall_number_survives_as_a_negative_number() {
        let map = pod_at(42, "hostile", "media");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, _) = build_denials(
            &[raw(42, gen_of("3f2b-uid"), u32::MAX, SECCOMP_RET_LOG, 1)],
            &map,
            None,
            &anchor,
        );

        assert_eq!(rows[0].syscall_nr, -1);
        assert_eq!(rows[0].syscall, "syscall_-1");
        assert!(
            serde_json::to_value(&rows[0]).expect("serialises")["syscallNr"]
                .as_i64()
                .is_some_and(|n| n == -1),
            "the Broker deserialises syscallNr into an Option<i32>"
        );
    }

    // ---- monotonic to wall clock ----

    #[test]
    fn a_row_stamped_earlier_than_the_anchor_reads_back_as_that_much_earlier() {
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 900_000_000_000);
        // 8 seconds before the anchor was read.
        let ts = mono_to_utc(&anchor, 900_000_000_000 - 8_000_000_000);
        assert_eq!(ts, utc("2026-09-14T04:05:06Z"));
    }

    #[test]
    fn a_row_stamped_after_the_anchor_never_reads_back_in_the_future() {
        // The anchor is read after the drain, so this cannot happen —
        // but a timestamp in the future would make first_seen > last_seen
        // and break the Broker's LEAST/GREATEST upsert, so the clamp is
        // not optional.
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 1_000);
        assert_eq!(mono_to_utc(&anchor, 9_999_999), anchor.wall);
    }

    // ---- attribution ----

    #[test]
    fn a_row_is_attributed_to_the_pod_on_its_netns() {
        let map = pod_at(42, "media-transform-7d9c8-abc12", "media");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw(42, gen_of("3f2b-uid"), 101, SECCOMP_RET_LOG, 17)],
            &map,
            None,
            &anchor,
        );

        assert_eq!(losses, AttributionLosses::default());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_name, "media-transform-7d9c8-abc12");
        assert_eq!(rows[0].pod_namespace, "media");
        assert_eq!(rows[0].count, 17);
        assert_eq!(rows[0].action, "SCMP_ACT_LOG");
    }

    /// The UID reaches the wire.
    ///
    /// This is the invariant behind a defect that made the whole feature
    /// store nothing. `pod_watcher::register_netns` used to build the
    /// `ContainerMap` entry from `create_pod_info` alone, which fills
    /// `status` and leaves `info.config.metadata` at `Default` — so every
    /// denial row carried `podUid: ""`. The broker's storage key is
    /// `(pod_uid, syscall, action)`, and it rejects an empty UID rather
    /// than collapse every pod on the cluster into one row per
    /// syscall/action pair. Correct of it, and invisible from both ends:
    /// the table simply stayed empty.
    ///
    /// `pod_watcher::pod_identity_metadata` now fills all three fields;
    /// this pins the other end of that wire, so a regression there fails
    /// here rather than in a cluster.
    #[test]
    fn the_pod_uid_reaches_the_wire() {
        let map = pod_at_with_uid(42, "media-transform-7d9c8-abc12", "media", "3f2b-uid");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw(42, gen_of("3f2b-uid"), 101, SECCOMP_RET_LOG, 1)],
            &map,
            None,
            &anchor,
        );

        assert_eq!(rows[0].pod_uid, "3f2b-uid");
        assert_eq!(
            losses.missing_uid, 0,
            "a populated UID must not be counted as the gap it replaced"
        );
    }

    /// The defensive counter still works when the UID really is absent.
    ///
    /// `pod_identity_metadata` keeps a UID-less pod registered rather
    /// than blinding every probe for it, so this row can still reach
    /// here. The broker will reject it — which is the safe failure — and
    /// counting it is what stops that being silent.
    ///
    /// The row's generation is 0 because that is what such a pod's
    /// registration packs: `pod_registration_flags` hashes
    /// `metadata.uid` as an `Option`, and a pod without one hashes
    /// `None`. `registration_generation` has to reach the same 0 from
    /// the `""` the `ContainerMap` stores, or this pod loses every
    /// denial it makes to a generation mismatch — see that function.
    #[test]
    fn a_row_whose_pod_has_no_uid_is_counted_rather_than_passed_off_as_fine() {
        let map = pod_at_with_uid(42, "hand-built", "media", "");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) =
            build_denials(&[raw(42, 0, 101, SECCOMP_RET_LOG, 1)], &map, None, &anchor);

        assert_eq!(rows.len(), 1, "the row is still reported, not dropped here");
        assert_eq!(rows[0].pod_uid, "");
        assert_eq!(losses.missing_uid, 1);
        assert_eq!(
            losses.stale_generation, 0,
            "a UID-less pod's own denials must not read as another pod's"
        );
    }

    /// The empty-UID conversion, pinned on its own.
    ///
    /// `generation_for_uid` distinguishes `None` (0) from `Some("")`
    /// (FNV's offset basis, nonzero), and the two stores spell a missing
    /// UID differently: `pod_registration_flags` passes the `Option`
    /// straight through while `pod_identity_metadata` flattens it to
    /// `""`. Reading the `ContainerMap`'s `""` back as `Some("")` would
    /// therefore expect a generation no kernel row can carry, and drop
    /// every denial from exactly the pods the registration path goes out
    /// of its way to keep tracked.
    #[test]
    fn a_missing_uid_expects_the_generation_a_missing_uid_registers_with() {
        assert_eq!(registration_generation(""), 0);
        assert_eq!(
            registration_generation(""),
            pod_flags::generation_for_uid(None)
        );
        assert_ne!(
            pod_flags::generation_for_uid(Some("")),
            0,
            "the empty string is not the absent UID; this test is only meaningful while they \
             hash differently"
        );
    }

    /// The expected generation is the one the registration actually
    /// packs — checked by running both real derivations over one pod.
    ///
    /// `build_denials` no longer reads the generation back out of the
    /// kernel, so this is the only thing tying its expectation to what
    /// `pod_watcher::pod_registration_flags` put there. The two paths
    /// start from the same `Pod` and must arrive at the same number:
    ///
    ///   * `pod_registration_flags(pod)` → `bpf.rs` → `inode_num` → the
    ///     generation the probe stamps on the row.
    ///   * `pod_identity_metadata(pod)` → the `ContainerMap` entry →
    ///     `registration_generation` → the generation the drain expects.
    ///
    /// This test previously re-declared the first path inline as
    /// `pack(level, generation_for_uid(uid))` and compared that to the
    /// second. Both sides then derived from `generation_for_uid`, so it
    /// agreed with itself no matter what `pod_registration_flags` did:
    /// changing that function's derivation (and mirroring the change in
    /// `pod_watcher`'s own test, as anyone making it would) left the
    /// suite fully green while the two halves disagreed and every denial
    /// on the node dropped as `stale_generation`. Calling the real
    /// functions is the whole point — restating either body here puts
    /// the hole straight back.
    #[test]
    fn the_expected_generation_is_the_one_the_registration_packs() {
        let mut pod = k8s_openapi::api::core::v1::Pod::default();
        pod.metadata.uid = Some("3f2b-uid".into());
        pod.metadata.name = Some("media-transform-7d9c8-abc12".into());
        pod.metadata.namespace = Some("media".into());

        // What the probe will stamp, via the function bpf.rs calls.
        let stamped = pod_flags::generation(crate::pod_watcher::pod_registration_flags(
            &pod,
            crate::capture_tiers::CaptureLevel::Medium,
        ));
        // What the drain will expect, via the entry pod_watcher stores.
        let expected =
            registration_generation(&crate::pod_watcher::pod_identity_metadata(&pod).uid);

        assert_eq!(
            stamped, expected,
            "the generation the registration packs and the one the drain derives have to be \
             the same number; when they diverge the node reports no denials at all and says \
             nothing about why"
        );

        // And for the UID-less pod, where the two paths spell a missing
        // UID differently (`None` vs `""`) and still have to agree.
        let bare = k8s_openapi::api::core::v1::Pod::default();
        assert_eq!(
            pod_flags::generation(crate::pod_watcher::pod_registration_flags(
                &bare,
                crate::capture_tiers::CaptureLevel::Medium,
            )),
            registration_generation(&crate::pod_watcher::pod_identity_metadata(&bare).uid),
        );
    }

    /// The `KG_GEN_SHIFT` failure mode, at this layer.
    ///
    /// The kernel hands out netns inode numbers from an IDA, so a pod
    /// that dies frees its number for the next pod on the node. Without
    /// the generation check, the dead pod's denials — recorded before it
    /// went — would be attributed to whatever took its inode, and an
    /// operator would see a workload being denied calls it never made.
    /// The row is dropped instead: unattributable is better than wrong.
    #[test]
    fn a_recycled_netns_does_not_hand_its_denials_to_the_replacement_pod() {
        let map = pod_at(42, "replacement-pod", "media");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        // The netns now belongs to a pod with a different UID, so the
        // row's generation is one no pod on this inode can claim.
        let (rows, losses) = build_denials(
            &[raw(42, gen_of("dead-pod-uid"), 101, SECCOMP_RET_LOG, 17)],
            &map,
            None,
            &anchor,
        );

        assert!(rows.is_empty(), "a stale row must not reach the Broker");
        assert_eq!(losses.stale_generation, 1);
        assert_eq!(losses.unknown_pod, 0);
    }

    /// The netns that is not the pod's, and the whole reason the key
    /// carries a cgroup id.
    ///
    /// Both pods here are `hostNetwork: true`, so `/proc/<pid>/ns/net`
    /// resolves to the SAME node netns for both and the `ContainerMap`
    /// — one entry per inode — can only hold the pod that registered
    /// last. Registering the winner evicts the loser, and the winner's
    /// generation is also what the kernel's `inode_num` map holds, so
    /// both stores agree with each other and both name the wrong
    /// workload. There is no mismatch for the generation check to find:
    /// it is not a timing window, and no ordering fixes it.
    ///
    /// The denial below is the LOSER's — the pod the netns route cannot
    /// even see. It has to be credited to the loser. Two ways this can
    /// go wrong and both have been shipped: crediting the winner is an
    /// accusation against a workload that made no such call, and
    /// refusing the row leaves the loser with no denial rows at all,
    /// which the Broker reports as `DenialsObserved: False` with
    /// `observed: 0` — "checked, and clean" — for a workload nothing was
    /// watching.
    #[test]
    fn a_host_network_pods_denial_is_credited_to_it_and_not_to_its_neighbour() {
        const NODE_NETNS: u64 = 4_026_531_992;
        const LOSER_CGROUP: u64 = 0xa1a1_0000_0000_0001;
        const WINNER_CGROUP: u64 = 0xb2b2_0000_0000_0002;
        let map = DashMap::new();
        // Two hostNetwork pods on one node. The second insert evicting
        // the first is not the test being lazy — it is precisely what
        // registration does, and the reason the loser is unreachable
        // through this map.
        map.insert(
            NODE_NETNS,
            Arc::new(pod_entry(
                "node-exporter-4k2wq",
                "monitoring",
                "loser-uid",
                true,
            )),
        );
        map.insert(
            NODE_NETNS,
            Arc::new(pod_entry("cilium-9xr7b", "kube-system", "winner-uid", true)),
        );
        let map: ContainerMap = Arc::new(map);
        // The cgroup registry sees both, because a cgroup is per
        // container and owes nothing to the network namespace.
        let cgroups = registry(&[
            container(
                "loser-uid",
                "monitoring",
                "node-exporter-4k2wq",
                "node-exporter",
                LOSER_CGROUP,
            ),
            container(
                "winner-uid",
                "kube-system",
                "cilium-9xr7b",
                "cilium-agent",
                WINNER_CGROUP,
            ),
        ]);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        // The generation the probe stamps is the winner's: it is the
        // value the winner's registration wrote to `inode_num`, and the
        // loser's verdicts are recorded against it because they share
        // the namespace the probe gates on. The cgroup is the loser's.
        let (rows, losses) = build_denials(
            &[raw_cg(
                NODE_NETNS,
                LOSER_CGROUP,
                gen_of("winner-uid"),
                101,
                SECCOMP_RET_LOG,
                9,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );

        assert_eq!(
            rows.len(),
            1,
            "a hostNetwork pod's denial was dropped; that workload now reports no denials \
             at all, which the Broker cannot tell from a workload that was never denied \
             anything"
        );
        assert_eq!(rows[0].pod_uid, "loser-uid");
        assert_eq!(rows[0].pod_name, "node-exporter-4k2wq");
        assert_eq!(rows[0].pod_namespace, "monitoring");
        assert_eq!(rows[0].count, 9);
        assert_eq!(
            losses,
            AttributionLosses::default(),
            "nothing was refused: the cgroup named the pod outright"
        );

        // And the winner's own denial is the winner's, from the same
        // netns and the same generation — the two are told apart by the
        // only field that differs.
        let (rows, _) = build_denials(
            &[raw_cg(
                NODE_NETNS,
                WINNER_CGROUP,
                gen_of("winner-uid"),
                101,
                SECCOMP_RET_LOG,
                4,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );
        assert_eq!(rows[0].pod_uid, "winner-uid");
        assert_eq!(rows[0].pod_name, "cilium-9xr7b");
    }

    /// The refusal that survives, and must.
    ///
    /// kubelet, the containerd shims and any systemd unit with
    /// `SystemCallFilter=` all run in the node's netns. Once one
    /// hostNetwork pod is registered on it, their verdicts pass the
    /// probe's gate and reach the drain. They are in no container's
    /// cgroup, so they resolve to nothing and are refused — which is the
    /// right answer, and the one the netns alone could never give:
    /// before the cgroup id was in the key, a node process's verdict and
    /// a hostNetwork pod's were the same row.
    #[test]
    fn a_denial_from_a_node_process_is_credited_to_nobody() {
        const NODE_NETNS: u64 = 4_026_531_992;
        const CILIUM_CGROUP: u64 = 0xb2b2_0000_0000_0002;
        // systemd puts its units under system.slice, which is not under
        // kubepods and is therefore in no container registry.
        const KUBELET_CGROUP: u64 = 0x5151_0000_0000_0009;
        let map = DashMap::new();
        map.insert(
            NODE_NETNS,
            Arc::new(pod_entry("cilium-9xr7b", "kube-system", "cilium-uid", true)),
        );
        let map: ContainerMap = Arc::new(map);
        let cgroups = registry(&[container(
            "cilium-uid",
            "kube-system",
            "cilium-9xr7b",
            "cilium-agent",
            CILIUM_CGROUP,
        )]);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(
                NODE_NETNS,
                KUBELET_CGROUP,
                gen_of("cilium-uid"),
                101,
                SECCOMP_RET_LOG,
                3,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );

        assert!(
            rows.is_empty(),
            "the node's own syscall was credited to the hostNetwork pod that happens to be \
             registered on its namespace"
        );
        assert_eq!(losses.unresolved_cgroup, 1);
        assert_eq!(
            losses.unresolved_cgroup_example,
            Some(KUBELET_CGROUP),
            "the warning has to name something an operator can resolve"
        );
        assert_eq!(
            losses.stale_generation, 0,
            "the generations agree here — reporting this as a stale row would describe a \
             netns recycle that did not happen and hide the real cause"
        );
    }

    /// Opting out of CPU gauges must not opt a workload out of having
    /// its kernel denials reported.
    ///
    /// `kguardian.dev/compute: "off"` files a container in the
    /// registry's identity-only tier. That annotation is about the cost
    /// of sampling; it says nothing about seccomp. Resolving only the
    /// sampled tier would make an unrelated annotation silently
    /// un-monitor a hostNetwork workload — a false all-clear bought for
    /// free, and the exact shape of coupling this route exists to
    /// remove.
    #[test]
    fn a_compute_opted_out_container_still_has_its_denials_attributed() {
        const NODE_NETNS: u64 = 4_026_531_992;
        const CGROUP: u64 = 0xc3c3_0000_0000_0003;
        let map = DashMap::new();
        map.insert(
            NODE_NETNS,
            Arc::new(pod_entry("batch-9xr7b", "batch", "batch-uid", true)),
        );
        let map: ContainerMap = Arc::new(map);
        let cgroups: ComputeMap = Arc::new(crate::compute_registry::ComputeRegistry::new());
        cgroups.insert_identity_only(container(
            "batch-uid",
            "batch",
            "batch-9xr7b",
            "worker",
            CGROUP,
        ));
        assert!(
            cgroups.lookup_cgroup(CGROUP).is_none(),
            "this fixture is only meaningful while the sampled tier does NOT hold it"
        );
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(
                NODE_NETNS,
                CGROUP,
                gen_of("batch-uid"),
                101,
                SECCOMP_RET_LOG,
                2,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_uid, "batch-uid");
        assert_eq!(losses.unresolved_cgroup, 0);
    }

    /// A row whose netns and cgroup name different pods is refused, not
    /// credited to the netns.
    ///
    /// `EXCLUDED_NAMESPACES` turns off the netns registration and
    /// nothing else. Nothing ever removes a `ContainerMap` entry or an
    /// `inode_num` value — the generation is what handles a recycled
    /// inode — so when an excluded-namespace pod inherits a tracked
    /// pod's netns inode it registers nothing, and the dead pod's entry
    /// and the kernel's generation survive together and AGREE. The
    /// generation check passes, and without this rule the new pod's
    /// denials are credited, permanently, to a dead workload in another
    /// namespace. That is an accusation, not a gap, and the exclusion
    /// list is the only reason a tracked successor could not have
    /// overwritten both stores.
    #[test]
    fn a_netns_whose_cgroup_names_another_pod_is_refused_rather_than_misattributed() {
        // The tracked pod that owned inode 42 and is now gone. Its
        // entry, and the generation the kernel still stamps, are its.
        const RECYCLED_NETNS: u64 = 42;
        const KUBE_PROXY_CGROUP: u64 = 0x5ca1_ab1e;
        const PLEX_CGROUP: u64 = 0x0bad_cafe;
        let map = DashMap::new();
        map.insert(
            RECYCLED_NETNS,
            Arc::new(pod_entry("plex-0", "media", "plex-uid", false)),
        );
        let map: ContainerMap = Arc::new(map);
        // The cgroup registry is filled for every pod on the node,
        // excluded namespaces included — which is what makes it the
        // identifier the exclusion list cannot corrupt.
        let cgroups = registry(&[
            container(
                "kube-proxy-uid",
                "kube-system",
                "kube-proxy-t4r9v",
                "kube-proxy",
                KUBE_PROXY_CGROUP,
            ),
            container("plex-uid", "media", "plex-0", "plex", PLEX_CGROUP),
        ]);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(
                RECYCLED_NETNS,
                KUBE_PROXY_CGROUP,
                gen_of("plex-uid"),
                101,
                SECCOMP_RET_LOG,
                7,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );
        assert!(
            rows.is_empty(),
            "kube-proxy's denials were credited to media/plex-0: an accusation against a              workload that made no such call, and it blocks that workload's promotion              while the denials that were real disappear into it. Got {rows:?}"
        );
        assert_eq!(
            losses.netns_cgroup_mismatch, 1,
            "and the refusal has to be counted: an uncounted one is the silence this              module exists to remove"
        );
        assert_eq!(
            losses.stale_generation, 0,
            "the generation MATCHED — that is the point"
        );

        // The same netns and the same generation, with the pod's OWN
        // container's cgroup: attributed, nothing refused. Without this
        // half the rule above could be a blanket refusal and look right.
        let (rows, losses) = build_denials(
            &[raw_cg(
                RECYCLED_NETNS,
                PLEX_CGROUP,
                gen_of("plex-uid"),
                101,
                SECCOMP_RET_LOG,
                7,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_uid, "plex-uid");
        assert_eq!(losses, AttributionLosses::default());

        // And a cgroup the registry does not hold contradicts nothing:
        // a nested cgroup, an init or ephemeral container, the pause
        // container. The netns answer stands.
        let (rows, losses) = build_denials(
            &[raw(
                RECYCLED_NETNS,
                gen_of("plex-uid"),
                101,
                SECCOMP_RET_LOG,
                7,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );
        assert_eq!(
            rows.len(),
            1,
            "an unresolvable cgroup must not cost a pod-network pod its denials; only two              positive answers naming different pods are a contradiction"
        );
        assert_eq!(rows[0].pod_uid, "plex-uid");
        assert_eq!(losses, AttributionLosses::default());
    }

    /// A task in the ROOT cgroup is credited to nobody, and the reason
    /// is the registry, not the value.
    ///
    /// `bpf_get_current_cgroup_id()` has no "no cgroup" sentinel: a task
    /// in the root cgroup carries the root's own kernfs id (measured: 1
    /// for kernel threads on a normally booted host; 0 never observed).
    /// On a node whose cgroups are managed on the v1 hierarchy that is
    /// what EVERY row carries. What refuses it is that no container is
    /// ever registered under the root —
    /// `compute_registry::resolve_container_cgroup` will not accept the
    /// root as a container's cgroup — so the id resolves to nothing.
    #[test]
    fn a_root_cgroup_row_on_the_node_netns_is_refused_and_counted() {
        const NODE_NETNS: u64 = 4_026_531_992;
        let map = DashMap::new();
        map.insert(
            NODE_NETNS,
            Arc::new(pod_entry("cilium-9xr7b", "kube-system", "cilium-uid", true)),
        );
        let map: ContainerMap = Arc::new(map);
        let cgroups = registry(&[container(
            "cilium-uid",
            "kube-system",
            "cilium-9xr7b",
            "cilium-agent",
            0x0c17_0000,
        )]);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(
                NODE_NETNS,
                ROOT_CGROUP_ID,
                gen_of("cilium-uid"),
                101,
                SECCOMP_RET_LOG,
                3,
            )],
            &map,
            Some(&cgroups),
            &anchor,
        );
        assert!(
            rows.is_empty(),
            "kubelet's own denied syscalls were credited to whichever hostNetwork pod              registered the node's namespace last. Got {rows:?}"
        );
        assert_eq!(losses.unresolved_cgroup, 1);
        assert_eq!(losses.unresolved_cgroup_example, Some(ROOT_CGROUP_ID));
    }

    /// The absence of the registry is counted on its own, never
    /// mistaken for a clean node.
    ///
    /// `main.rs` builds the registry whenever denial capture is on, so
    /// `None` here is a wiring fault. It has to be countable as one:
    /// filing it under `unresolved_cgroup` would bury a fixable
    /// misconfiguration in the same number as the node's own expected
    /// noise, and silently attributing the row to the netns winner
    /// would be the misattribution the whole module refuses.
    #[test]
    fn without_a_cgroup_registry_a_shared_netns_row_is_refused_and_counted_as_such() {
        const NODE_NETNS: u64 = 4_026_531_992;
        let map = DashMap::new();
        map.insert(
            NODE_NETNS,
            Arc::new(pod_entry("cilium-9xr7b", "kube-system", "cilium-uid", true)),
        );
        let map: ContainerMap = Arc::new(map);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(
                NODE_NETNS,
                0xdead_beef,
                gen_of("cilium-uid"),
                101,
                SECCOMP_RET_LOG,
                3,
            )],
            &map,
            None,
            &anchor,
        );

        assert!(rows.is_empty());
        assert_eq!(losses.no_container_registry, 1);
        assert_eq!(losses.unresolved_cgroup, 0);
        assert_eq!(losses.unknown_pod, 0);
    }

    /// A pod-network pod is still attributed by its netns, and without
    /// the cgroup route being reachable at all.
    ///
    /// One pod to one inode, generation-checked. The cgroup registry is
    /// deliberately empty here: if this path ever started consulting it,
    /// denial reporting for ordinary pods would acquire a dependency on
    /// containerd cgroup resolution that it does not have and does not
    /// need.
    #[test]
    fn a_pod_with_its_own_netns_is_still_attributed_without_consulting_a_cgroup() {
        let map = DashMap::new();
        map.insert(
            42,
            Arc::new(pod_entry(
                "media-transform-7d9c8-abc12",
                "media",
                "3f2b-uid",
                false,
            )),
        );
        let map: ContainerMap = Arc::new(map);
        let empty = registry(&[]);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(42, 0, gen_of("3f2b-uid"), 101, SECCOMP_RET_LOG, 5)],
            &map,
            Some(&empty),
            &anchor,
        );

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_name, "media-transform-7d9c8-abc12");
        assert_eq!(losses, AttributionLosses::default());
    }

    /// Nothing on the netns and nothing on the cgroup: both routes
    /// tried, both empty, and the row is dropped as unattributable.
    ///
    /// The cgroup route is offered a real (empty) registry rather than
    /// `None`, so this counts the row's own condition and not the
    /// Controller's. The two are different reports with different fixes
    /// and must not share a number.
    #[test]
    fn a_row_neither_route_can_name_is_dropped_and_counted() {
        // A pod on some other netns: nothing at all is registered on 42.
        let map = pod_at(7, "elsewhere", "media");
        let empty = registry(&[]);
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw_cg(
                42,
                0xfeed_face,
                gen_of("3f2b-uid"),
                101,
                SECCOMP_RET_LOG,
                1,
            )],
            &map,
            Some(&empty),
            &anchor,
        );

        assert!(rows.is_empty());
        assert_eq!(losses.unknown_pod, 1);
        assert_eq!(
            losses.unresolved_cgroup, 0,
            "an unregistered netns is not the node's shared one; conflating them would \
             point an operator at hostNetwork when the pod has simply gone"
        );
        assert_eq!(losses.no_container_registry, 0);
    }

    /// The same row with no registry at all is the Controller's fault,
    /// not the row's, and says so.
    #[test]
    fn a_row_that_needs_the_cgroup_route_with_no_registry_names_the_wiring_fault() {
        let map = pod_at(7, "elsewhere", "media");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[raw(42, gen_of("3f2b-uid"), 101, SECCOMP_RET_LOG, 1)],
            &map,
            None,
            &anchor,
        );

        assert!(rows.is_empty());
        assert_eq!(losses.no_container_registry, 1);
        assert_eq!(losses.unknown_pod, 0);
    }

    /// The interleaving between the two stores that used to misattribute.
    ///
    /// `pod_watcher` inserts the `ContainerMap` entry for a pod and only
    /// then sends its registration to `bpf.rs`, which writes the kernel
    /// `inode_num` map between ring-buffer polls — 100ms later at best,
    /// seconds under load. This is that window: netns 42 has already
    /// been recycled to a new pod here, while the kernel still holds the
    /// dead pod's generation, which is the generation its rows carry.
    ///
    /// The dead pod's row must be dropped rather than written to the
    /// new pod. Netns inode numbers are node-global, so the new pod is
    /// routinely an unrelated workload in another namespace: crediting
    /// it flips its `DenialsObserved` to `True` and blocks a promotion
    /// that should have gone ahead, and the denials that were real
    /// vanish into it. The new pod's own rows — which the probe stamps
    /// as soon as `bpf.rs` catches up, within the same drain — still
    /// have to land.
    #[test]
    fn a_row_is_dropped_when_the_container_map_has_moved_on_but_the_kernel_map_has_not() {
        let map = pod_at_with_uid(42, "unrelated-workload", "payments", "new-pod-uid");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        let (rows, losses) = build_denials(
            &[
                raw(42, gen_of("dead-pod-uid"), 101, SECCOMP_RET_LOG, 17),
                raw(42, gen_of("new-pod-uid"), 102, SECCOMP_RET_LOG, 3),
            ],
            &map,
            None,
            &anchor,
        );

        assert_eq!(losses.stale_generation, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].syscall_nr, 102,
            "the dead pod's denials were written to the pod that took its netns inode"
        );
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[0].pod_uid, "new-pod-uid");
    }

    /// The cost side of the generation check, pinned so it stays a
    /// deliberate trade rather than an accident.
    ///
    /// Same registration window as the test above, but this row is the
    /// NEW pod's own verdict, not the dead pod's: the pod is live, it
    /// made the call itself, and the row still carries the old
    /// generation because `bpf.rs` had not yet published the new one
    /// when the probe fired. The older code — which read the expected
    /// generation out of the kernel map — attributed this row
    /// correctly, and the current code drops it.
    ///
    /// That is not a regression to fix by reverting: the two rows in
    /// this window are byte-identical in every field attribution can
    /// see, so any rule that keeps this one also credits the dead pod's
    /// leftovers to this pod. The loss is bounded by how long `bpf.rs`
    /// takes to drain its registration channel, and it is counted. It
    /// is asserted here so that a future change which silently widens
    /// the window, or which "fixes" this by reintroducing the
    /// misattribution, has to come through this test and say so.
    #[test]
    fn a_live_pods_own_denials_are_dropped_while_its_registration_is_in_flight() {
        let map = pod_at_with_uid(42, "media-transform-7d9c8-abc12", "media", "new-pod-uid");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);

        // The pod is registered in the ContainerMap, but the kernel's
        // `inode_num` still holds the previous occupant's flags, so its
        // own verdict is stamped with the OLD generation.
        let (rows, losses) = build_denials(
            &[raw(42, gen_of("dead-pod-uid"), 101, SECCOMP_RET_LOG, 4)],
            &map,
            None,
            &anchor,
        );

        assert!(
            rows.is_empty(),
            "this row is indistinguishable from the dead pod's leftovers; reporting it means \
             reporting those too, against a workload that made no such call"
        );
        assert_eq!(
            losses.stale_generation, 1,
            "the loss has to be counted — an uncounted one is the silence the whole feature \
             exists to remove"
        );
    }

    // ---- the registry the cgroup route needs ----

    /// The gate that used to be `COMPUTE_ENABLED` alone.
    ///
    /// `compute.enabled: false` is a supported install — it is one
    /// Helm value, and the gauges are unrelated to seccomp. Before this,
    /// setting it took the cgroup registry away, and with it every
    /// hostNetwork workload's denials on the node; those workloads then
    /// reported nothing, which the Broker cannot tell from having been
    /// checked and found clean.
    #[test]
    fn denial_capture_alone_is_enough_to_build_the_container_registry() {
        assert!(
            needs_container_registry(false, true),
            "with the gauges off and denial capture on there is still a registry to \
             resolve a hostNetwork pod's cgroup against; without one those workloads \
             report no denials and read as clean"
        );
        assert!(
            needs_container_registry(true, false),
            "the gauges still need it"
        );
        assert!(needs_container_registry(true, true));
        // Both off is the only case that builds nothing: no reader.
        assert!(!needs_container_registry(false, false));
    }

    /// The predicate above is two tokens; what broke was its CALL SITE.
    ///
    /// `main.rs` is a binary with no tests, and while the wiring lived
    /// there two separate one-line reversals each left the whole suite
    /// green at 331 passing:
    ///
    ///   * `want_container_registry = compute_config.enabled` — the
    ///     re-coupling `needs_container_registry` exists to prevent;
    ///   * `let seccomp_denial_cgroups: Option<ComputeMap> = None;` —
    ///     the drain handed no registry at all, which this module's own
    ///     startup warning calls a wiring fault.
    ///
    /// Both spell the same outcome: hostNetwork workloads lose cgroup
    /// attribution, their denials are counted and dropped, and the
    /// Broker reads the silence as `DenialsObserved: False, observed: 0`.
    /// So the decision moved to `wire_registry`, and this is the test it
    /// could not have. Sabotaging either line inside `wire_registry`
    /// fails it.
    #[test]
    fn wiring_gives_denial_capture_the_registry_whether_or_not_the_gauges_are_on() {
        let cfg = |compute_on: bool, denial_on: bool| {
            (
                ComputeConfig {
                    enabled: compute_on,
                    ..Default::default()
                },
                SeccompDenialConfig {
                    enabled: denial_on,
                    ..Default::default()
                },
            )
        };

        // The install that used to lose hostNetwork attribution: one
        // Helm value, `compute.enabled: false`, and the gauges are the
        // only thing it is meant to switch off.
        let (c, d) = cfg(false, true);
        let w = wire_registry(&c, &d);
        let registry = w
            .registry
            .as_ref()
            .expect("denial capture alone must build the registry");
        let denial = w
            .denial_cgroups
            .registry()
            .expect("with the gauges off the drain still needs a registry: a hostNetwork                      pod's cgroup is the only identifier it has, and without one its                      workloads report nothing, which reads as clean");
        assert!(
            Arc::ptr_eq(registry, denial),
            "the drain must resolve against the registry the pod watcher FILLS, not a              second one; two stores that drift is a bug class this tree has already paid              for once"
        );
        assert!(
            w.compute_events.is_none(),
            "nothing drains registrations with the sampler off; a held receiver backs the              broadcast channel up to capacity"
        );

        // Gauges only: registry built, and the drain is handed nothing
        // because there is no drain.
        let (c, d) = cfg(true, false);
        let w = wire_registry(&c, &d);
        assert!(w.registry.is_some(), "the gauges still need it");
        assert!(w.compute_events.is_some());
        assert!(w.denial_cgroups.registry().is_none());

        // Both on: one registry, and both readers hold that same one.
        let (c, d) = cfg(true, true);
        let w = wire_registry(&c, &d);
        let registry = w.registry.as_ref().expect("both readers are on");
        assert!(w.compute_events.is_some());
        assert!(Arc::ptr_eq(
            registry,
            w.denial_cgroups.registry().expect("denial capture is on")
        ));

        // Both off is the only case that builds nothing.
        let (c, d) = cfg(false, false);
        let w = wire_registry(&c, &d);
        assert!(w.registry.is_none());
        assert!(w.compute_events.is_none());
        assert!(w.denial_cgroups.registry().is_none());
    }

    // ---- merging ----

    /// Not a tidiness rule: the Broker upserts, and PostgreSQL rejects an
    /// `ON CONFLICT DO UPDATE` whose statement would touch the same row
    /// twice. A payload with two rows sharing an identity fails the whole
    /// batch, so this has to happen before the POST, not after.
    #[test]
    fn rows_sharing_a_broker_identity_are_collapsed_into_one() {
        let merged = merge_denials(vec![
            denial(
                "web-1",
                "ptrace",
                3,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:08Z",
            ),
            denial(
                "web-1",
                "ptrace",
                4,
                "2026-09-14T04:05:04Z",
                "2026-09-14T04:05:14Z",
            ),
        ]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].count, 7);
        assert_eq!(merged[0].first_seen, utc("2026-09-14T04:05:04Z"));
        assert_eq!(merged[0].last_seen, utc("2026-09-14T04:05:14Z"));
    }

    #[test]
    fn different_pods_and_different_syscalls_stay_separate() {
        let merged = merge_denials(vec![
            denial(
                "web-1",
                "ptrace",
                1,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:06Z",
            ),
            denial(
                "web-2",
                "ptrace",
                1,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:06Z",
            ),
            denial(
                "web-1",
                "mount",
                1,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:06Z",
            ),
        ]);
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn the_same_syscall_under_two_actions_is_two_rows() {
        // A workload denied `mount` by SCMP_ACT_ERRNO and merely logged
        // for `ptrace` are different facts; collapsing them would hide
        // the enforcing one behind the audit one.
        let mut errno = denial(
            "web-1",
            "mount",
            2,
            "2026-09-14T04:05:06Z",
            "2026-09-14T04:05:06Z",
        );
        errno.action = "SCMP_ACT_ERRNO";
        errno.action_raw = SECCOMP_RET_ERRNO;
        let merged = merge_denials(vec![
            denial(
                "web-1",
                "mount",
                2,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:06Z",
            ),
            errno,
        ]);
        assert_eq!(merged.len(), 2);
    }

    // ---- wire format ----

    #[test]
    fn a_denial_serialises_to_the_broker_contract() {
        let body = denial_batch_body(
            "ip-10-0-1-23.ec2.internal",
            true,
            Duration::from_secs(10),
            &[denial(
                "media-transform-7d9c8-abc12",
                "ptrace",
                17,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:14Z",
            )],
        );

        assert_eq!(body["node"], "ip-10-0-1-23.ec2.internal");
        assert_eq!(body["capturing"], serde_json::json!(true));
        let row = &body["denials"][0];
        assert_eq!(row["podName"], "media-transform-7d9c8-abc12");
        assert_eq!(row["podNamespace"], "media");
        assert_eq!(row["syscall"], "ptrace");
        assert_eq!(row["syscallNr"], 101);
        assert_eq!(row["action"], "SCMP_ACT_LOG");
        assert_eq!(row["actionRaw"], SECCOMP_RET_LOG);
        assert_eq!(row["arch"], "SCMP_ARCH_X86_64");
        assert_eq!(row["count"], 17);
        // Second precision, no fractional part: the contract's spelling.
        assert_eq!(row["firstSeen"], "2026-09-14T04:05:06Z");
        assert_eq!(row["lastSeen"], "2026-09-14T04:05:14Z");
    }

    // ---- heartbeat and chunking ----

    /// The empty POST that keeps a fresh install promotable.
    ///
    /// With no denial rows anywhere, "this workload was never denied" and
    /// "nothing on this cluster is capturing" are the same database state,
    /// so the Broker cannot report a clean bill of health it has no
    /// evidence for and every workload sits at `DenialsObserved: Unknown`
    /// — which blocks promotion, which is the whole workflow. The empty
    /// body carrying `node` and `capturing` is the evidence.
    #[test]
    fn an_empty_drain_still_produces_one_body_to_post() {
        let chunks = post_chunks(&[]);
        assert_eq!(chunks.len(), 1, "the heartbeat must still go out");
        assert!(chunks[0].is_empty());

        let body = denial_batch_body(
            "ip-10-0-1-23.ec2.internal",
            true,
            Duration::from_secs(10),
            chunks[0],
        );
        assert_eq!(body["node"], "ip-10-0-1-23.ec2.internal");
        assert_eq!(body["capturing"], serde_json::json!(true));
        assert_eq!(body["denials"], serde_json::json!([]));
    }

    /// The node declares its own cadence, on every report.
    ///
    /// The Broker decides whether a node's last report is too old to
    /// believe, and `Unknown` — which is what a stale node produces —
    /// blocks promotion. It cannot get the answer from a constant:
    /// `SECCOMP_DENIAL_INTERVAL_SECONDS` is an operator-set Helm value
    /// with no upper bound, so a hard-coded window makes a perfectly
    /// healthy cluster read as stale forever at any interval above a
    /// third of it. The Broker computes `max(300, intervalSeconds * 3)`
    /// per node from this field.
    ///
    /// It has to be on the EMPTY report above all. A node that is
    /// capturing and seeing nothing sends only heartbeats — that is
    /// exactly the node whose freshness is being judged, and a field
    /// present only on denial-carrying bodies would leave it falling
    /// back to the 300s default the contract exists to replace.
    #[test]
    fn every_report_declares_the_nodes_drain_interval() {
        let interval = Duration::from_secs(900);

        let heartbeat = denial_batch_body("ip-10-0-1-23.ec2.internal", true, interval, &[]);
        assert_eq!(
            heartbeat["intervalSeconds"],
            serde_json::json!(900),
            "an empty heartbeat is the report a quiet node sends, and the one the staleness \
             window is for"
        );

        let with_rows = denial_batch_body(
            "ip-10-0-1-23.ec2.internal",
            true,
            interval,
            &[denial(
                "web-1",
                "ptrace",
                1,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:06Z",
            )],
        );
        assert_eq!(with_rows["intervalSeconds"], serde_json::json!(900));

        // camelCase on the wire, like every other field in the contract.
        assert!(
            heartbeat.get("interval_seconds").is_none(),
            "the Broker deserialises intervalSeconds; the snake_case spelling would be \
             dropped as an unknown field and silently fall back to 300s"
        );

        // The configured interval, not a constant. `from_values` clamps
        // 0 to 1s, so the value on the wire is never the zero the
        // Broker reads as "absent".
        let configured = SeccompDenialConfig::from_values(None, Some("45"));
        let body = denial_batch_body("n", true, configured.interval, &[]);
        assert_eq!(body["intervalSeconds"], serde_json::json!(45));
        let clamped = SeccompDenialConfig::from_values(None, Some("0"));
        let body = denial_batch_body("n", true, clamped.interval, &[]);
        assert_eq!(body["intervalSeconds"], serde_json::json!(1));
    }

    /// A node that degraded gracefully still reports in, and must report
    /// `capturing: false`. Silence from such a node read as "no denials"
    /// is a false all-clear — a worse outcome than the crash the graceful
    /// degradation exists to avoid.
    #[test]
    fn a_node_without_the_probe_reports_in_as_not_capturing() {
        let body = denial_batch_body(
            "ip-10-0-1-23.ec2.internal",
            false,
            Duration::from_secs(10),
            &[],
        );
        assert_eq!(body["capturing"], serde_json::json!(false));
    }

    /// The storm case, pinned: chunk, never truncate.
    ///
    /// An earlier version of this loop capped the outgoing batch at the
    /// backlog ceiling, which silently discarded the bulk of exactly the
    /// event this feature was built to report. Every row must survive
    /// into some chunk.
    #[test]
    fn a_drain_larger_than_one_body_is_split_and_nothing_is_dropped() {
        let rows: Vec<SeccompDenial> = (0..12_345)
            .map(|i| {
                denial(
                    &format!("web-{i}"),
                    "ptrace",
                    1,
                    "2026-09-14T04:05:06Z",
                    "2026-09-14T04:05:06Z",
                )
            })
            .collect();

        let chunks = post_chunks(&rows);
        assert!(
            chunks.iter().all(|c| c.len() <= MAX_DENIALS_PER_POST),
            "a chunk over the limit is a 413 at the worst possible moment"
        );
        assert_eq!(
            chunks.iter().map(|c| c.len()).sum::<usize>(),
            rows.len(),
            "chunking must lose nothing; truncating a denial storm reports the opposite of \
             what happened"
        );
    }

    /// `SCMP_ARCH_ARM64` and not `SCMP_ARCH_AARCH64`: `broker/src/seccomp.rs`
    /// `arch_token` renders aarch64 that way into every exported profile's
    /// `architectures` list, and a denial row that spelled it differently
    /// would not line up with the profile it belongs to.
    #[test]
    fn the_arch_token_matches_the_brokers_spelling() {
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(scmp_arch_token(), Some("SCMP_ARCH_X86_64")),
            "aarch64" => assert_eq!(scmp_arch_token(), Some("SCMP_ARCH_ARM64")),
            _ => assert_eq!(scmp_arch_token(), None),
        }
    }

    // ---- what the Broker actually stored ----

    /// A 200 is not proof the rows landed.
    ///
    /// The ingest validates per row and answers `200 {"accepted": n}`.
    /// The Controller cleared the kernel map before the POST, so a row
    /// the Broker refused exists nowhere else on the node — and a
    /// wholly-refused batch still returns success alongside a
    /// `capturing: true` heartbeat, which reads downstream as a clean
    /// bill of health. Comparing what was sent against what was stored
    /// is the only thing standing between that and silent,
    /// unrecoverable loss.
    #[test]
    fn a_batch_the_broker_refused_is_detected_rather_than_read_as_delivered() {
        // The case that matters most: every row refused, 200 OK.
        assert_eq!(
            refused_rows_in(37, &serde_json::json!({ "accepted": 0 })),
            Some(37),
            "a wholly-refused batch returns 200; read as delivered, 37 denials vanish with an \
             all-clear behind them"
        );
        // Partial refusal — e.g. one row over the count ceiling.
        assert_eq!(
            refused_rows_in(10, &serde_json::json!({ "accepted": 9 })),
            Some(1)
        );
        // Everything stored: nothing to say.
        assert_eq!(
            refused_rows_in(10, &serde_json::json!({ "accepted": 10 })),
            None
        );
        // The heartbeat: no rows sent, none stored, not a shortfall.
        assert_eq!(
            refused_rows_in(0, &serde_json::json!({ "accepted": 0 })),
            None,
            "an empty heartbeat must not be reported as lost data every interval"
        );
    }

    /// An older Broker must not be turned into a permanent data-loss
    /// alarm.
    ///
    /// It answers without the field, or with a body that is not JSON at
    /// all. That is "cannot say", not "refused everything" — reporting
    /// it as loss would be the same false alarm pointing the other way,
    /// and would train an operator to ignore the warning that matters.
    #[test]
    fn a_broker_that_does_not_report_a_count_is_not_read_as_refusal() {
        assert_eq!(refused_rows_in(10, &serde_json::json!({})), None);
        assert_eq!(refused_rows_in(10, &serde_json::Value::Null), None);
        assert_eq!(
            refused_rows_in(10, &serde_json::json!({ "accepted": "9" })),
            None,
            "a string is not a count; guessing at its meaning is how a wrong number gets \
             reported as a real one"
        );
        // A Broker counting higher than it was offered is its own bug,
        // and not one the Controller can describe from here.
        assert_eq!(
            refused_rows_in(10, &serde_json::json!({ "accepted": 11 })),
            None
        );
    }

    // ---- forward compatibility ----

    /// An older Broker 404s this endpoint, and that must be a warning
    /// rather than anything that stops the Controller. The match is on
    /// the exact text `client::api_post_call_json` formats; this pins the
    /// coupling so a reword there fails here instead of silently turning
    /// every 404 into a generic error.
    #[test]
    fn a_404_body_is_recognised_as_a_missing_endpoint() {
        let e = Error::ApiError(
            "broker returned 404 Not Found for POST http://broker:9090/seccomp/denials: "
                .to_string(),
        );
        assert!(broker_lacks_endpoint(&e));
    }

    #[test]
    fn other_broker_failures_are_not_mistaken_for_a_missing_endpoint() {
        // A 500 or a 503 means the endpoint exists and the Broker is
        // unwell — those rows should be retried, not written off as
        // "this Broker is too old".
        for message in [
            "broker returned 500 Internal Server Error for POST http://broker:9090/seccomp/denials: ",
            "broker returned 503 Service Unavailable for POST http://broker:9090/seccomp/denials: ",
        ] {
            assert!(!broker_lacks_endpoint(&Error::ApiError(message.to_string())));
        }
        assert!(!broker_lacks_endpoint(&Error::Custom("404".to_string())));
    }

    // ---- configuration ----

    #[test]
    fn capture_is_on_by_default_and_switchable() {
        assert!(SeccompDenialConfig::from_values(None, None).enabled);
        assert!(!SeccompDenialConfig::from_values(Some("false"), None).enabled);
        // parse_lenient_bool's variants, so "False" does not silently
        // flip back to the default the way bool::from_str would.
        assert!(!SeccompDenialConfig::from_values(Some(" FALSE\n"), None).enabled);
    }

    #[test]
    fn the_default_interval_matches_the_syscall_recorder() {
        assert_eq!(
            SeccompDenialConfig::from_values(None, None).interval,
            Duration::from_secs(10),
            "the drain cadence is deliberately the syscall recorder's 10s; changing it here \
             alone would make the two halves of a profile's evidence arrive on different clocks"
        );
    }

    #[test]
    fn an_unparseable_or_zero_interval_falls_back_rather_than_refusing_to_start() {
        assert_eq!(
            SeccompDenialConfig::from_values(None, Some("soon")).interval,
            Duration::from_secs(DEFAULT_INTERVAL_SECS)
        );
        // A zero interval is a busy loop, not a cadence.
        assert_eq!(
            SeccompDenialConfig::from_values(None, Some("0")).interval,
            Duration::from_secs(1)
        );
        assert_eq!(
            SeccompDenialConfig::from_values(None, Some(" 30 ")).interval,
            Duration::from_secs(30)
        );
    }

    // ---- map layout ----
    //
    // These decoders read raw kernel bytes at fixed offsets. A mismatch
    // with the C struct is invisible at compile time and shows up as
    // nonsense counts against the wrong pod.

    #[test]
    fn a_key_decodes_at_the_offsets_the_c_struct_implies() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4_026_532_000u64.to_ne_bytes()); // netns
        bytes.extend_from_slice(&0xa1a1_0000_0000_0001u64.to_ne_bytes()); // cgroup_id
        bytes.extend_from_slice(&7u32.to_ne_bytes()); // generation
        bytes.extend_from_slice(&101u32.to_ne_bytes()); // syscall_nr
        bytes.extend_from_slice(&SECCOMP_RET_LOG.to_ne_bytes()); // action
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // pad
        assert_eq!(
            bytes.len(),
            DENIAL_KEY_BYTES,
            "the C struct is pinned at this size by _Static_assert"
        );
        assert_eq!(
            denial_key_from_bytes(&bytes),
            Some((
                4_026_532_000,
                0xa1a1_0000_0000_0001,
                7,
                101,
                SECCOMP_RET_LOG
            ))
        );
    }

    #[test]
    fn a_value_decodes_at_the_offsets_the_c_struct_implies() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&17u64.to_ne_bytes());
        bytes.extend_from_slice(&1_000u64.to_ne_bytes());
        bytes.extend_from_slice(&9_000u64.to_ne_bytes());
        assert_eq!(denial_value_from_bytes(&bytes), Some((17, 1_000, 9_000)));
    }

    /// Any length but the exact one is refused, long as well as short.
    ///
    /// A minimum-length test was the wrong test the moment the key grew
    /// by eight bytes: the old decoder would happily have read
    /// `generation`, `syscall_nr` and `action` out of the new key's
    /// `cgroup_id` and `generation`, producing confident counts against
    /// the wrong pod and the wrong syscall — the failure this module
    /// refuses everywhere else. A rejected row is counted into
    /// `DrainOutcome::read_errors`, which warns.
    #[test]
    fn a_key_or_value_of_any_other_length_is_rejected_rather_than_reinterpreted() {
        assert_eq!(denial_key_from_bytes(&[0u8; 19]), None);
        assert_eq!(denial_key_from_bytes(&[0u8; DENIAL_KEY_BYTES - 8]), None);
        assert_eq!(denial_key_from_bytes(&[0u8; DENIAL_KEY_BYTES + 8]), None);
        assert_eq!(denial_value_from_bytes(&[0u8; 23]), None);
        assert_eq!(
            denial_value_from_bytes(&[0u8; DENIAL_VALUE_BYTES + 8]),
            None
        );
    }

    // ---- toolchain guard for build.rs's -mcpu=v2 ----

    /// The flag that decides whether this probe LOADS on an old kernel.
    ///
    /// `record_denial` counts with `__sync_fetch_and_add`. Recent clang
    /// defaults the BPF target to cpu v3 and lowers that to
    /// `BPF_ATOMIC|BPF_FETCH`, which the verifier rejects before 5.12 and
    /// the arm64 JIT before 5.18. On v2 it lowers to the legacy
    /// `BPF_XADD` every supported kernel accepts. Losing the flag would
    /// therefore break exactly the old-kernel nodes this probe's whole
    /// degrade-gracefully design exists to keep serving — and it would
    /// break them silently at load time, on their nodes, not here.
    ///
    /// `contention::tests` carries a twin of this test and of
    /// `scan_bpf_atomics`. Lifting the scanner into one shared test
    /// helper would mean editing `contention.rs`, which this change does
    /// not own; it is a worthwhile follow-up.
    #[test]
    fn embedded_object_uses_legacy_xadd_atomics() {
        let obj: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_denial.bpf.o"));
        let (atomics, fetch) = scan_bpf_atomics(obj);
        assert!(
            atomics > 0,
            "expected the __sync_fetch_and_add sites in record_denial/stat_inc to be in the \
             object; finding none means the counting was refactored away, not that the \
             encoding is safe"
        );
        assert_eq!(
            fetch, 0,
            "{fetch} BPF_ATOMIC|BPF_FETCH instruction(s) found; build.rs must pass -mcpu=v2"
        );
    }

    /// Minimal ELF64-LE walk: returns (atomic insns, atomic insns with
    /// BPF_FETCH) over all SHF_EXECINSTR sections.
    fn scan_bpf_atomics(elf: &[u8]) -> (usize, usize) {
        let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap());
        assert_eq!(&elf[..4], b"\x7fELF", "not an ELF object");
        assert_eq!(elf[4], 2, "expected ELF64");
        assert_eq!(elf[5], 1, "scanner handles little-endian BPF objects only");

        let shoff = u64_at(0x28) as usize;
        let shentsize = u16_at(0x3a) as usize;
        let shnum = u16_at(0x3c) as usize;
        const SHF_EXECINSTR: u64 = 0x4;
        const BPF_LD_IMM64: u8 = 0x18;
        const BPF_ATOMIC_DW: u8 = 0xdb;
        const BPF_ATOMIC_W: u8 = 0xc3;
        const BPF_FETCH: u32 = 0x01;

        let (mut atomics, mut fetch) = (0usize, 0usize);
        for i in 0..shnum {
            let sh = shoff + i * shentsize;
            let flags = u64_at(sh + 8);
            if flags & SHF_EXECINSTR == 0 {
                continue;
            }
            let off = u64_at(sh + 24) as usize;
            let size = u64_at(sh + 32) as usize;
            let code = &elf[off..off + size];
            let mut pc = 0;
            while pc + 8 <= code.len() {
                let op = code[pc];
                if op == BPF_ATOMIC_DW || op == BPF_ATOMIC_W {
                    atomics += 1;
                    let imm = u32::from_le_bytes(code[pc + 4..pc + 8].try_into().unwrap());
                    if imm & BPF_FETCH != 0 {
                        fetch += 1;
                    }
                }
                pc += if op == BPF_LD_IMM64 { 16 } else { 8 };
            }
        }
        (atomics, fetch)
    }
}
