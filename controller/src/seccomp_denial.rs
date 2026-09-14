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
//! attributed to the pod that owns its netns, the syscall number and the
//! raw `SECCOMP_RET_*` action are resolved to the `SCMP_*` spellings the
//! rest of the tree uses, and the result is POSTed to
//! `POST /seccomp/denials`.
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
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::capture_tiers::native_scmp_arch;
use crate::client::api_post_call;
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
    /// without one, which the Broker rejects; see [`pod_identity`].
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
    denials: &'a [SeccompDenial],
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
    /// The probe's own instance of the tracked-pod map. Read (never
    /// written) here, to check that the pod on a netns is still the pod
    /// whose generation a row carries.
    tracked: MapHandle,
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
            tracked: MapHandle::try_from(&maps.inode_num)?,
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

    /// The registration generation currently recorded for `netns`, or
    /// `None` when nothing is registered on it.
    fn generation_for(&self, netns: u64) -> Option<u32> {
        let raw = self
            .tracked
            .lookup(&netns.to_ne_bytes(), MapFlags::ANY)
            .ok()??;
        Some(pod_flags::generation(u32_from_bytes(&raw)?))
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

/// Pod identity for a denial row, or `None` when the netns belongs to no
/// pod this node currently knows.
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
fn pod_identity(container_map: &ContainerMap, netns: u64) -> Option<(String, String, String)> {
    let pod = lookup_pod(container_map, netns)?;
    Some((
        pod.info.config.metadata.uid.clone(),
        pod.status.pod_name.clone(),
        pod.status.pod_namespace.clone().unwrap_or_default(),
    ))
}

/// Why a drained row did not make it onto the wire. Counted rather than
/// logged per row: under a denial storm the per-row log IS the storm.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct AttributionLosses {
    /// No pod registered on the row's netns any more.
    unknown_pod: usize,
    /// A pod IS registered, but not the one the row was recorded for —
    /// the netns inode was recycled between the verdict and the drain.
    /// See `KG_GEN_SHIFT` in `src/bpf/helper.h`.
    stale_generation: usize,
    /// Rows whose pod has no UID in the `ContainerMap`. Not dropped
    /// here — the row is still a real denial and the Broker may yet
    /// learn to resolve it — but counted so the condition is loud
    /// rather than a table that stays mysteriously empty. See
    /// [`pod_identity`].
    missing_uid: usize,
}

/// Attribute drained rows to pods and render them for the wire.
///
/// Pure over its inputs (the clock anchor is passed in) so the
/// attribution rules — especially the generation check — are testable
/// without a kernel.
fn build_denials(
    rows: &[RawDenial],
    container_map: &ContainerMap,
    generation_for: &dyn Fn(u64) -> Option<u32>,
    anchor: &ClockAnchor,
) -> (Vec<SeccompDenial>, AttributionLosses) {
    let arch = scmp_arch_token();
    let mut losses = AttributionLosses::default();
    let mut names: HashMap<u32, String> = HashMap::new();
    // Both lookups are memoised across rows: under a storm one pod
    // contributes hundreds of rows, and neither the netns registration
    // nor a syscall's name changes within a single drain.
    let mut generations: HashMap<u64, Option<u32>> = HashMap::new();
    let mut out = Vec::with_capacity(rows.len());

    for row in rows {
        // Generation first: it is a map lookup against the probe's own
        // tracked-pod map, and it is the check that stops a replacement
        // pod being handed its predecessor's denials. A row whose netns
        // now carries a different generation describes a pod that is
        // gone; there is nothing left to attribute it to.
        let current = *generations
            .entry(row.netns)
            .or_insert_with(|| generation_for(row.netns));
        match current {
            Some(current) if current == row.generation => {}
            Some(_) => {
                losses.stale_generation += 1;
                continue;
            }
            None => {
                losses.unknown_pod += 1;
                continue;
            }
        }

        let Some((pod_uid, pod_name, pod_namespace)) = pod_identity(container_map, row.netns)
        else {
            losses.unknown_pod += 1;
            continue;
        };
        if pod_uid.is_empty() {
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
            pod_uid,
            pod_name,
            pod_namespace,
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

/// True when the error `api_post_call` returned is a 404 from the Broker.
///
/// `api_post_call` flattens every non-2xx into `Error::ApiError` with a
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
            generation: k.1,
            syscall_nr: k.2,
            action: k.3,
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
    maps: oneshot::Receiver<DenialMaps>,
) -> Result<(), Error> {
    if !config.enabled {
        info!("{CAPTURE_ENV} is off; kernel seccomp verdicts will not be captured");
        return Ok(());
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

        let generation_for = |netns: u64| -> Option<u32> { maps.as_ref()?.generation_for(netns) };
        let (fresh, losses) =
            build_denials(&drained.rows, &container_map, &generation_for, &anchor);
        if losses.unknown_pod > 0 || losses.stale_generation > 0 {
            debug!(
                unknown_pod = losses.unknown_pod,
                stale_generation = losses.stale_generation,
                "seccomp denial rows dropped: their pod is gone, or its netns inode has \
                 already been reused by another pod"
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
            let body = json!(DenialBatch {
                node: &node_name,
                capturing,
                denials: chunk,
            });
            match api_post_call(body, DENIALS_PATH).await {
                Ok(()) => {
                    delivered += chunk.len();
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

/// `(netns, generation, syscall_nr, action)`.
type DenialKey = (u64, u32, u32, u32);
/// `(count, first_seen_ns, last_seen_ns)`.
type DenialValue = (u64, u64, u64);

fn denial_key_from_bytes(b: &[u8]) -> Option<DenialKey> {
    if b.len() < 20 {
        return None;
    }
    Some((
        u64_from_bytes(&b[..8])?,
        u32_from_bytes(&b[8..12])?,
        u32_from_bytes(&b[12..16])?,
        u32_from_bytes(&b[16..20])?,
    ))
}

fn denial_value_from_bytes(b: &[u8]) -> Option<DenialValue> {
    if b.len() < 24 {
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
    fn pod_at(netns: u64, name: &str, namespace: &str) -> ContainerMap {
        pod_at_with_uid(netns, name, namespace, "3f2b-uid")
    }

    fn pod_at_with_uid(netns: u64, name: &str, namespace: &str, uid: &str) -> ContainerMap {
        let map = DashMap::new();
        let inspect = crate::PodInspect {
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
            ..Default::default()
        };
        map.insert(netns, Arc::new(inspect));
        Arc::new(map)
    }

    fn raw(netns: u64, generation: u32, syscall_nr: u32, action: u32, count: u64) -> RawDenial {
        RawDenial {
            netns,
            generation,
            syscall_nr,
            action,
            count,
            first_seen_ns: 1_000,
            last_seen_ns: 2_000,
        }
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
        let generation_for = |_netns: u64| Some(7u32);

        let (rows, _) = build_denials(
            &[raw(42, 7, u32::MAX, SECCOMP_RET_LOG, 1)],
            &map,
            &generation_for,
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
        let generation_for = |_netns: u64| Some(7u32);

        let (rows, losses) = build_denials(
            &[raw(42, 7, 101, SECCOMP_RET_LOG, 17)],
            &map,
            &generation_for,
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
        let generation_for = |_netns: u64| Some(7u32);

        let (rows, losses) = build_denials(
            &[raw(42, 7, 101, SECCOMP_RET_LOG, 1)],
            &map,
            &generation_for,
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
    #[test]
    fn a_row_whose_pod_has_no_uid_is_counted_rather_than_passed_off_as_fine() {
        let map = pod_at_with_uid(42, "hand-built", "media", "");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);
        let generation_for = |_netns: u64| Some(7u32);

        let (rows, losses) = build_denials(
            &[raw(42, 7, 101, SECCOMP_RET_LOG, 1)],
            &map,
            &generation_for,
            &anchor,
        );

        assert_eq!(rows.len(), 1, "the row is still reported, not dropped here");
        assert_eq!(rows[0].pod_uid, "");
        assert_eq!(losses.missing_uid, 1);
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
        // The netns now carries generation 9; the row was recorded under 7.
        let generation_for = |_netns: u64| Some(9u32);

        let (rows, losses) = build_denials(
            &[raw(42, 7, 101, SECCOMP_RET_LOG, 17)],
            &map,
            &generation_for,
            &anchor,
        );

        assert!(rows.is_empty(), "a stale row must not reach the Broker");
        assert_eq!(losses.stale_generation, 1);
        assert_eq!(losses.unknown_pod, 0);
    }

    #[test]
    fn a_row_whose_netns_is_no_longer_registered_is_dropped() {
        let map = pod_at(42, "gone", "media");
        let anchor = anchor_at(utc("2026-09-14T04:05:14Z"), 10_000);
        let generation_for = |_netns: u64| None;

        let (rows, losses) = build_denials(
            &[raw(42, 7, 101, SECCOMP_RET_LOG, 1)],
            &map,
            &generation_for,
            &anchor,
        );

        assert!(rows.is_empty());
        assert_eq!(losses.unknown_pod, 1);
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
        let body = serde_json::to_value(DenialBatch {
            node: "ip-10-0-1-23.ec2.internal",
            capturing: true,
            denials: &[denial(
                "media-transform-7d9c8-abc12",
                "ptrace",
                17,
                "2026-09-14T04:05:06Z",
                "2026-09-14T04:05:14Z",
            )],
        })
        .expect("a batch serialises");

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

        let body = serde_json::to_value(DenialBatch {
            node: "ip-10-0-1-23.ec2.internal",
            capturing: true,
            denials: chunks[0],
        })
        .expect("a heartbeat serialises");
        assert_eq!(body["node"], "ip-10-0-1-23.ec2.internal");
        assert_eq!(body["capturing"], serde_json::json!(true));
        assert_eq!(body["denials"], serde_json::json!([]));
    }

    /// A node that degraded gracefully still reports in, and must report
    /// `capturing: false`. Silence from such a node read as "no denials"
    /// is a false all-clear — a worse outcome than the crash the graceful
    /// degradation exists to avoid.
    #[test]
    fn a_node_without_the_probe_reports_in_as_not_capturing() {
        let body = serde_json::to_value(DenialBatch {
            node: "ip-10-0-1-23.ec2.internal",
            capturing: false,
            denials: &[],
        })
        .expect("a heartbeat serialises");
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

    // ---- forward compatibility ----

    /// An older Broker 404s this endpoint, and that must be a warning
    /// rather than anything that stops the Controller. The match is on
    /// the exact text `client::api_post_call` formats; this pins the
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
        bytes.extend_from_slice(&7u32.to_ne_bytes()); // generation
        bytes.extend_from_slice(&101u32.to_ne_bytes()); // syscall_nr
        bytes.extend_from_slice(&SECCOMP_RET_LOG.to_ne_bytes()); // action
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // pad
        assert_eq!(bytes.len(), 24, "the C struct is 24 bytes");
        assert_eq!(
            denial_key_from_bytes(&bytes),
            Some((4_026_532_000, 7, 101, SECCOMP_RET_LOG))
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

    #[test]
    fn a_short_key_or_value_is_rejected_rather_than_read_past() {
        assert_eq!(denial_key_from_bytes(&[0u8; 19]), None);
        assert_eq!(denial_value_from_bytes(&[0u8; 23]), None);
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
