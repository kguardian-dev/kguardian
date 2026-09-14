//! Kernel seccomp verdicts: ingest, query, per-workload rollup, metrics.
//!
//! # What this signal is, and why it is not drift
//!
//! `seccomp.rs` reports **drift**: the set difference between the syscalls
//! the eBPF observer saw a workload make and the set a `SeccompProfile` CR
//! allows. Drift is an inference — it says a profile *looks* incomplete. It
//! is computed entirely from kguardian's own observations and would report
//! the same thing whether or not the profile was ever loaded into a kernel.
//!
//! What arrives here is the opposite: the kernel's own verdict. The
//! controller hooks `audit_seccomp`, which the kernel calls from
//! `seccomp_log()` at the moment seccomp has decided an action is loggable,
//! and ships counts. A row in `seccomp_denials` means the filter kguardian
//! generated was consulted and acted — under `SCMP_ACT_LOG` it would have
//! blocked, under `SCMP_ACT_ERRNO` it did.
//!
//! That distinction is what the whole feature exists for. Drift can be
//! stale, wrong, or absent (no CR mirrored, names never fetched). A denial
//! cannot: it already happened.
//!
//! # Counts, not events
//!
//! The controller drains a BPF LRU hash every 10 s rather than streaming one
//! ringbuffer event per denial, and this table matches that shape: one row
//! per `(pod_uid, syscall, action)`, `count` accumulated by the ingest
//! upsert across every drain, `first_seen`/`last_seen` bracketing the whole
//! accumulation. A misbehaving or compromised process can trip seccomp at
//! kernel rates; an event-per-row table would make the broker the amplifier
//! for exactly the workload an operator is trying to contain.
//!
//! # Attribution
//!
//! Resolved broker-side at ingest by joining the pod to `pod_details`, which
//! is where the controller already stamps top-level ownerReference
//! resolution (ReplicaSet -> Deployment, Job -> CronJob). This is the SAME
//! attribution `seccomp.rs` reads for its per-workload rollups — there is
//! deliberately only one path from a pod to its owning workload in the
//! broker. The result is denormalised onto the row rather than joined at
//! read time, because `pod_details` rows are pruned on their own (shorter)
//! schedule and a denial that lost its attribution would silently vanish
//! from the per-workload rollup the CR status is built from.
//!
//! # Metrics
//!
//! `/metrics` must never query Postgres (see the 100 ms pool timeout in
//! `main.rs::metrics`), so the Prometheus aggregate is maintained here as a
//! cached snapshot refreshed on its own timer and read lock-free-ish by the
//! scrape handler. See [`SeccompDenialMetrics`].

use crate::read_budget::{cost_kib, ReadBudget, AUDIT_ROW_COST_BYTES};
use crate::schema;
use actix_web::{web, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tracing::{debug, info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// `(namespace, workload_kind, workload_name)` — the same workload identity
/// `seccomp.rs` groups on. Kept structurally identical on purpose: the
/// denial rollup is looked up with a key built there.
type WorkloadKey = (String, String, String);

/// One pod's `(namespace, workload_kind, workload_name)` as `pod_details`
/// holds it. Every field is nullable there: the namespace on legacy rows,
/// the workload pair until the controller resolves ownerReferences.
type PodAttribution = (Option<String>, Option<String>, Option<String>);

/// Pod name -> its attribution, for the pods named in one ingest batch.
type AttributionIndex = HashMap<String, PodAttribution>;

/// `(namespace, kind, name, syscall, action, count, last_seen)` — one
/// attributed denial, as `DenialIndex::with_rows` folds it. Test-only: the
/// production loader reads totals and names on separate axes, and folding
/// them back into one row is a convenience the tests want and the bounded
/// read cannot offer.
#[cfg(test)]
type DenialRollupRow = (String, String, String, String, String, i64, DateTime<Utc>);

/// `(pod_name, namespace, workload_kind, workload_name)` as selected from
/// `pod_details` for the attribution lookup.
type PodAttributionRow = (String, Option<String>, Option<String>, Option<String>);

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Rows per INSERT statement. Same value `compute_api.rs` uses for its
/// hot-path upsert, for the same reason: one round trip per chunk keeps the
/// 10 s drain from becoming N round trips per node.
const INSERT_CHUNK: usize = 500;

/// JSON body limit for `POST /seccomp/denials`.
///
/// actix's default is 256 KiB, which at the ~200 B a denial serialises to
/// caps a batch around 1 300 rows — below what one node can legitimately
/// produce, and a 413 there would silently drop kernel verdicts. 4 MiB is
/// ~20 000 rows, comfortably above any real 10 s drain while staying well
/// under the 16 MiB the compute ingest path already reserves.
///
/// It is NOT the BPF map's full 65 536 entries. A node that genuinely fills
/// the map in one interval is under attack or misconfigured, and the
/// controller must chunk its drain rather than rely on this ceiling.
pub const DENIAL_JSON_LIMIT_BYTES: usize = 4 << 20;

/// Longest syscall-name list carried in one workload's `denials` block.
///
/// This value ends up in a `SeccompProfile` CR's `.status`, so it is an
/// etcd object, not just a JSON response. A workload denied on a handful of
/// syscalls is the expected shape — a denial is by definition the exception
/// — but a profile applied to the wrong workload can deny hundreds, and that
/// is precisely when the status must stay writable.
const MAX_DENIAL_SYSCALLS: usize = 50;

/// Longest action list in one workload's `denials` block. There are seven
/// `SCMP_ACT_*` spellings plus `SCMP_ACT_UNKNOWN`, so this is a formality;
/// it exists so the block cannot be unbounded on either axis.
const MAX_DENIAL_ACTIONS: usize = 16;

/// Ceiling on `count` — both the value one report may carry and the total
/// the upsert is allowed to accumulate to.
///
/// Without it a single wire value near `i64::MAX` permanently kills a node's
/// ingest. `count` lands in a `BIGINT` that the upsert adds to, Postgres
/// RAISES on bigint overflow rather than saturating, and every chunk of a
/// drain shares one transaction — so the POST 500s. The Controller clears
/// its BPF map only on a successful POST, so it replays the same batch every
/// interval, forever, and every subsequent denial from that node is lost.
/// The heartbeat commits in an earlier, separate transaction and keeps
/// succeeding, so the cluster still reads "capturing" while capture is in
/// fact dead. `BROKER_AUTH_TOKEN` is optional, so on a default deploy this
/// needs no credentials.
///
/// A trillion is roughly 40x the most extreme physical bound on one 10 s
/// drain. A 256-core node cannot retire more than ~2.5e9 syscalls/s in
/// total, and a DENIED syscall costs far more than an ordinary one because
/// it goes through `seccomp_log()` and the audit subsystem, so ~2.5e10 is
/// already unreachable. No real node arrives here.
///
/// It is also what keeps `SUM(count)` inside `BIGINT` in the rollup query,
/// which casts the sum back to `BIGINT` and would raise the same way. A
/// group there is one workload's one `(syscall, action)` pair across its
/// pods, so the sum is bounded by `pods x MAX_DENIAL_COUNT`; reaching
/// `i64::MAX` would need 9.2 million pods in one workload.
const MAX_DENIAL_COUNT: i64 = 1_000_000_000_000;

/// Distinct `(syscall, action)` pairs the rollup reads per workload.
///
/// [`DenialIndex::block_for`] keeps at most [`MAX_DENIAL_SYSCALLS`] syscalls
/// and [`MAX_DENIAL_ACTIONS`] actions, and the SQL orders pairs the same way
/// the `BTreeSet`s behind those lists do, so on real input every pair past
/// this product is one the block would have dropped anyway — the cap bounds
/// the read without changing a single visible block.
///
/// "On real input" is load-bearing. `action` is length-checked at ingest but
/// not enumerated against the `SCMP_ACT_*` set, so a caller can fabricate
/// more than [`MAX_DENIAL_ACTIONS`] distinct action strings for one syscall
/// and crowd out later syscalls within this cap. The block is then shorter
/// than it would have been. That is the deliberate trade: a shorter list on
/// fabricated input, against an unbounded read on it.
const MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD: i64 = (MAX_DENIAL_SYSCALLS * MAX_DENIAL_ACTIONS) as i64;

/// Overall cap on the name rows one cluster-wide rollup reads.
///
/// The per-workload cap alone still multiplies by the workload count, and
/// `GET /seccomp/profiles` is the endpoint that OOMKilled the Broker in
/// #1514 for exactly this shape of mistake. 10 000 pairs is far above any
/// real cluster — a denial is by definition the exception, so a cluster
/// where a hundred workloads each trip ten syscalls is 1 000 rows — and it
/// is what the read budget is charged for, so it is a reservation as much as
/// a limit.
///
/// Truncating here can only shorten a `syscalls`/`actions` list, never a
/// `total`: the totals are a separate query that is not capped, for exactly
/// that reason. A workload whose pairs fall past this cap keeps its true
/// total and loses its name list, which reads as "denied, names not shown"
/// rather than as an all-clear.
const MAX_DENIAL_ROLLUP_NAME_ROWS: i64 = 10_000;

/// Cap on the namespaces one rollup will enumerate as unattributable.
///
/// An unattributed denial withholds the all-clear from every workload in its
/// namespace — see [`UnattributedNamespaces`] — so this read is the third
/// thing `GET /seccomp/profiles` does on a 15 s poll and it needs a bound
/// like the other two. `pod_namespace` comes straight off the wire on an
/// unattributed row, so the bound must not assume the caller is a real
/// Controller with a real cluster's worth of namespaces.
///
/// Unlike the name-row ceiling, hitting this one is NOT a truncation: a
/// truncated list here would silently hand the all-clear back to the
/// namespaces that fell past the cap, which is the failure this whole read
/// exists to prevent. Past the cap the index stops enumerating and withholds
/// from everything — see [`UnattributedNamespaces::TooMany`]. A thousand is
/// far above any cluster where the answer is meaningful; reaching it means
/// attribution is broken cluster-wide or someone is feeding the endpoint,
/// and `Unknown` is the right answer to both.
const MAX_UNATTRIBUTED_NAMESPACES: usize = 1_000;

/// Peak in-flight bytes per unattributed-namespace row.
///
/// One string, but the ingest bound on it is [`MAX_DNS_NAME_LEN`] rather than
/// the length a real namespace has, and the value arrives off the wire on
/// exactly the rows this read returns. Budgeted at the bound plus `String`
/// and libpq overhead rather than at what a cluster would really send.
/// Estimated from the row shape, not measured.
const UNATTRIBUTED_NAMESPACE_ROW_COST_BYTES: u64 = 768;

/// Peak in-flight bytes per rollup name row.
///
/// Five short strings — namespace, kind, workload, syscall, action — so
/// ~60 B of text, 120 B of `String` headers, and libpq's own copy of the
/// whole result set before diesel decodes it. 512 B is roughly 1.5x that,
/// the same order of allowance [`crate::read_budget::AUDIT_ROW_COST_BYTES`]
/// makes for a wider row. Estimated from the row shape, not measured.
const DENIAL_ROLLUP_NAME_ROW_COST_BYTES: u64 = 512;

/// Series cap for `kguardian_seccomp_denials_total`.
///
/// The metric is deliberately not labelled by syscall (that would multiply
/// cardinality by ~300), so the realistic bound is workloads x actions —
/// hundreds on a large cluster. This cap is the pathological-case valve, not
/// an expected limit.
///
/// It is a MEMORY bound as much as a Prometheus one, which is why the map is
/// capped rather than only the rendered output: the counter behind that
/// metric is held for the life of the process and retention cannot reclaim
/// it. An attributed denial's labels can only be values that already exist
/// in `pod_details`, but an UNATTRIBUTED one carries the namespace straight
/// off the wire, so the map needs a ceiling that does not depend on the
/// ingest caller behaving.
///
/// Set well above real cardinality (workloads x actions — hundreds, since
/// the labels exclude syscall) so it is unambiguously a pathology valve and
/// never truncates a real cluster. At ~150 bytes per entry this is a couple
/// of MiB at full stretch.
///
/// At capacity a new label set is refused rather than evicting an existing
/// one — see [`SeccompDenialMetrics::record_batch`] for why eviction would
/// be the worse failure.
const MAX_DENIAL_SERIES: usize = 10_000;

/// Floor on how long a node's capture heartbeat stays trustworthy.
///
/// The window itself is PER NODE, computed from the cadence the node declares
/// on every report — see [`CAPTURE_REPORT_STALE_INTERVALS`]. It has to be:
/// the Controller's drain interval is an operator-set Helm value, so any
/// fixed window shorter than it makes a fleet that is capturing perfectly
/// read `Unknown` between every pair of reports, forever. Coupling the Broker
/// to the Controller's chart value would be the obvious fix and the wrong one
/// — the Broker cannot see that chart. The node declares its own cadence and
/// the Broker trusts it, up to [`CAPTURE_REPORT_STALE_CEILING_SECS`].
///
/// This floor is what a node that declares nothing gets. At the 10 s default
/// drain it is 30 consecutive missed reports — generous enough that a node
/// under load, a rolling Controller restart or a brief network partition
/// never flips the cluster to "not capturing", short enough that a genuinely
/// dead capture path is noticed in minutes rather than at the next retention
/// pass.
///
/// Deliberately shorter than `pod_compute_latest`'s 600 s staleness: that one
/// decides whether to delete a row, this one decides whether kguardian is
/// willing to tell an operator a workload is clean.
const CAPTURE_REPORT_STALE_FLOOR_SECS: i64 = 300;

/// Consecutive reports a node may miss before its heartbeat stops counting.
///
/// Three, so the window is `max(300 s, declared interval x 3)`. Two drains
/// can be lost to a Controller restart rolling over that node without the
/// cluster flipping to Unknown, and a node that has genuinely gone quiet is
/// noticed within three of its OWN intervals rather than at a wall-clock
/// figure that has nothing to do with how often it speaks.
const CAPTURE_REPORT_STALE_INTERVALS: i64 = 3;

/// Hard ceiling on the staleness window, whatever cadence a node declares.
///
/// The per-node window exists so a large drain interval cannot make a
/// capturing fleet read `Unknown`. It was given no ceiling, and that is the
/// same mistake pointing the other way: this window IS the all-clear gate, so
/// widening it does not widen "a timeout", it widens how long kguardian keeps
/// telling an operator a workload is clean on the strength of one old report.
/// Against the previous 86 400 s interval bound the window reached three
/// days, and a single report — a node departing on a spot reclaim, or one
/// unauthenticated POST, since `BROKER_AUTH_TOKEN` is optional — bought the
/// whole cluster 72 hours of `total: 0`.
///
/// Thirty minutes is the longest this file will vouch for a node it has not
/// heard from. It is chosen against what the all-clear is FOR — promoting a
/// profile from audit to enforcing, a decision an operator takes over minutes
/// — rather than against how slowly a Controller might be configured to
/// drain. Six times the floor still leaves the per-node mechanism real range:
/// a node draining every 10 minutes is trusted for 30, where the fixed window
/// this replaced called it stale at 5.
///
/// The two directions are not symmetric, which is why the ceiling is tight
/// where the floor is generous. Too short a window costs `Unknown`: visible,
/// self-correcting on the next report, and the answer an operator would want
/// anyway. Too long a window costs a false all-clear: invisible, and acted
/// on.
const CAPTURE_REPORT_STALE_CEILING_SECS: i64 = 1_800;

/// Ceiling on the drain interval a node may declare.
///
/// Derived from the window ceiling rather than chosen separately, because
/// widening the window is the only thing a declared interval does: a cadence
/// the window cannot cover is a cadence this file cannot honour. It lands at
/// ten minutes — 60x the 10 s default, and so 60x fewer POSTs, which is the
/// entire reason the chart offers the knob.
///
/// Past it the honest answer is `Unknown` rather than a wider all-clear. A
/// node draining every hour is heard from once an hour, and no amount of
/// trust turns a 59-minute-old silence into evidence that anything is
/// watching. The chart refuses such a value at install time and ingest warns
/// about one that arrives anyway, so that state is diagnosable rather than
/// silent.
///
/// Clamped at ingest rather than rejected, unlike [`MAX_DENIAL_COUNT`]: the
/// interval rides on the heartbeat, and refusing the report over it would
/// throw away the capture evidence the report exists to carry.
/// `seccomp_denial_nodes.interval_seconds` carries the same bound as a CHECK
/// constraint, and [`capture_live_sql`] clamps the window a second time in
/// SQL — so neither a row written by some other path nor one left behind by
/// the wider bound this replaced can buy a window this file would not grant.
const MAX_REPORT_INTERVAL_SECS: i64 =
    CAPTURE_REPORT_STALE_CEILING_SECS / CAPTURE_REPORT_STALE_INTERVALS;

/// Default refresh cadence for the one denial metric that needs a query. See
/// [`metrics_interval`] for why this is 15 s and why it must not be folded
/// into the retention loop's hourly cadence.
const DEFAULT_METRICS_INTERVAL_SECS: u64 = 15;

/// Floor for the refresh cadence, so a typo'd `1` cannot turn the gauge into
/// a per-second aggregate.
const MIN_METRICS_INTERVAL_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One drained BPF map entry, as the controller ships it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialInput {
    pod_uid: String,
    pod_name: String,
    pod_namespace: String,
    /// Resolved name, or `syscall_<nr>` when libseccomp could not resolve
    /// the number. The controller never drops an unresolvable row, so this
    /// is always populated.
    syscall: String,
    #[serde(default)]
    syscall_nr: Option<i32>,
    /// `SCMP_ACT_*`, or `SCMP_ACT_UNKNOWN` for a raw value the controller
    /// does not map.
    action: String,
    /// The raw `SECCOMP_RET_*` value. Exceeds `i32` (`SCMP_ACT_LOG` is
    /// 0x7fff0000 and `SCMP_ACT_ALLOW` is 0x7fff0000-adjacent, while
    /// `SCMP_ACT_KILL_PROCESS` is 0x80000000), hence `i64`.
    #[serde(default)]
    action_raw: Option<i64>,
    #[serde(default)]
    arch: Option<String>,
    count: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// Body of `POST /seccomp/denials`.
///
/// Sent on EVERY drain, including one that drained nothing. An empty batch
/// is not a no-op here: it is the node's heartbeat, and it is what lets the
/// Broker distinguish "nothing was denied" from "nothing was watching".
///
/// `camelCase` is load-bearing, not decoration: the Controller serialises
/// this struct with `rename_all = "camelCase"`, so it sends `intervalSeconds`.
/// Without the matching attribute here every multi-word field silently
/// deserialises to its `#[serde(default)]` — the staleness window would fall
/// back to the floor on every report while both halves looked implemented.
/// `node`, `capturing` and `denials` are single words and cannot expose it,
/// which is why it survived review. See
/// `wire_field_names_match_what_the_controller_sends`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialBatch {
    node: String,
    /// Whether the denial probe is actually attached on this node.
    ///
    /// Absent means the report did not say, which is NOT the same as `false`
    /// and is not treated as capture either: see [`DenialBatch::validate`].
    #[serde(default)]
    capturing: Option<bool>,
    /// The node's configured drain cadence in seconds — how long the
    /// Controller sleeps between drains, sent on every report including an
    /// empty one.
    ///
    /// It is the node's own declaration, because the Broker has no way to
    /// read the Controller's configuration and a fixed staleness window
    /// shorter than a supported drain interval makes a healthy cluster read
    /// `Unknown` forever. Absent or zero falls back to
    /// [`CAPTURE_REPORT_STALE_FLOOR_SECS`]; see [`declared_interval_seconds`].
    #[serde(default)]
    interval_seconds: Option<u64>,
    #[serde(default)]
    denials: Vec<DenialInput>,
}

/// One report, validated: everything the ingest path is allowed to act on.
struct ValidatedReport {
    /// See [`FoldedBatch::rows`].
    rows: Vec<DenialInput>,
    /// See [`FoldedBatch::rejected`].
    rejected: BTreeMap<&'static str, usize>,
    /// See [`FoldedBatch::from_the_future`].
    from_the_future: usize,
    /// Whether this report is evidence that the node is capturing.
    capturing: bool,
    /// The cadence the node declared, normalised for storage.
    interval_seconds: Option<i64>,
    /// Whether that cadence was above [`MAX_REPORT_INTERVAL_SECS`] and had to
    /// be cut down to it.
    interval_clamped: bool,
}

impl DenialBatch {
    /// Validate and fold the report, and decide from the RESULT whether the
    /// node is capturing.
    ///
    /// The two are one function because the order between them is the whole
    /// correctness argument, and a comment asking the caller to keep it was
    /// not enough: this consumes the batch, so there is no raw vector left
    /// for a later caller to count.
    ///
    /// Counted before validation, a report whose every row was rejected — a
    /// Controller shipping empty drains, or one unauthenticated POST of one
    /// garbage row, since `BROKER_AUTH_TOKEN` is optional — still recorded
    /// the node as capturing. That is the false all-clear arriving through
    /// the one field that exists to withhold it.
    ///
    /// What survives validation still outranks the flag in both directions.
    /// Rows the kernel produced prove the probe fired whatever the flag says,
    /// so a node reporting `capturing: false` while shipping real denials is
    /// believed on the evidence rather than on its own self-assessment.
    /// Absent the flag AND absent accepted rows, the honest answer is "not
    /// known to be capturing".
    fn validate(self, now: DateTime<Utc>) -> ValidatedReport {
        let (interval_seconds, interval_clamped) = declared_interval_seconds(self.interval_seconds);
        let FoldedBatch {
            rows,
            rejected,
            from_the_future,
        } = fold_batch(self.denials, now);
        let capturing = self.capturing.unwrap_or(false) || !rows.is_empty();
        ValidatedReport {
            rows,
            rejected,
            from_the_future,
            capturing,
            interval_seconds,
            interval_clamped,
        }
    }
}

/// The staleness cadence a report declares, normalised for storage, and
/// whether it had to be cut down to get there.
///
/// `None` for absent or zero — the contract's fallback, which
/// [`capture_live_sql`] reads as the [`CAPTURE_REPORT_STALE_FLOOR_SECS`]
/// floor. Anything above [`MAX_REPORT_INTERVAL_SECS`] is clamped to it rather
/// than rejected, so a cadence this file cannot honour costs a timeout bound
/// and never the heartbeat riding with it.
///
/// The clamp is returned rather than applied silently because it has a
/// consequence an operator has to be able to find: a node draining slower
/// than the ceiling is heard from less often than it is trusted for, so it
/// reads stale between its own reports and its workloads sit at `Unknown`.
/// That is the correct answer — see [`CAPTURE_REPORT_STALE_CEILING_SECS`] —
/// but discovering it by watching a condition flap is not. See
/// [`post_seccomp_denials`], which warns.
fn declared_interval_seconds(raw: Option<u64>) -> (Option<i64>, bool) {
    match raw.unwrap_or(0) {
        0 => (None, false),
        declared => {
            let declared = i64::try_from(declared).unwrap_or(i64::MAX);
            (
                Some(declared.min(MAX_REPORT_INTERVAL_SECS)),
                declared > MAX_REPORT_INTERVAL_SECS,
            )
        }
    }
}

/// A `seccomp_denials` row ready to insert.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::seccomp_denials)]
struct NewDenial {
    pod_uid: String,
    pod_name: String,
    pod_namespace: String,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    node_name: Option<String>,
    syscall: String,
    syscall_nr: Option<i32>,
    action: String,
    action_raw: Option<i64>,
    arch: Option<String>,
    count: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// One stored denial, as `GET /seccomp/denials` returns it.
#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = schema::seccomp_denials)]
#[serde(rename_all = "camelCase")]
pub struct DenialRow {
    pub id: i64,
    pub pod_uid: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub workload_kind: Option<String>,
    pub workload_name: Option<String>,
    pub node_name: Option<String>,
    pub syscall: String,
    pub syscall_nr: Option<i32>,
    pub action: String,
    pub action_raw: Option<i64>,
    pub arch: Option<String>,
    pub count: i64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Validation and folding
// ---------------------------------------------------------------------------

/// Field ceilings. A pod uid is a UUID, names and namespaces are DNS
/// subdomains, syscall names are kernel identifiers and actions are a fixed
/// enum. These are not tight bounds — they are the "this is not a syscall
/// name, it is someone probing the ingest endpoint" line.
const MAX_UID_LEN: usize = 128;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_SYSCALL_LEN: usize = 128;
const MAX_ACTION_LEN: usize = 64;
const MAX_ARCH_LEN: usize = 64;

/// Reject a batch entry that cannot identify what it is about. Returns the
/// reason so the caller can log which field failed rather than a bare count.
///
/// Pure, and the only place ingest decides a row is unusable.
fn reject_reason(d: &DenialInput) -> Option<&'static str> {
    // An empty `podUid` is REFUSED, not tolerated, and this is the one
    // rejection here that must never be softened into a fallback.
    //
    // The storage key is `(pod_uid, syscall, action)`. An empty uid accepted
    // at face value is a perfectly valid key, so every pod on the cluster
    // would collapse into ONE row per (syscall, action) — counts from
    // unrelated workloads summed together, attribution resolved from
    // whichever pod name happened to arrive last, and a `denials` block
    // naming the wrong workload. That is silent data corruption that looks
    // exactly like working ingest, in a signal an operator promotes a
    // profile to enforcing on.
    //
    // Falling back to `(namespace, name)` is the same trap one step along: a
    // pod name is reused by the next pod of the same workload, so the row
    // would then merge distinct pods over time rather than all at once.
    //
    // A Controller that cannot populate the uid should hit this wall loudly
    // and leave the table empty. An empty table plus a `warn!` naming
    // `podUid` is a diagnosable bug; a full table of merged rows is not.
    if d.pod_uid.trim().is_empty() || d.pod_uid.len() > MAX_UID_LEN {
        return Some("podUid");
    }
    if d.pod_name.trim().is_empty() || d.pod_name.len() > MAX_DNS_NAME_LEN {
        return Some("podName");
    }
    if d.pod_namespace.trim().is_empty() || d.pod_namespace.len() > MAX_DNS_NAME_LEN {
        return Some("podNamespace");
    }
    if d.syscall.trim().is_empty() || d.syscall.len() > MAX_SYSCALL_LEN {
        return Some("syscall");
    }
    if d.action.trim().is_empty() || d.action.len() > MAX_ACTION_LEN {
        return Some("action");
    }
    if d.arch.as_ref().is_some_and(|a| a.len() > MAX_ARCH_LEN) {
        return Some("arch");
    }
    // A zero or negative count is not a denial. Accepting one would add a
    // row — and therefore a workload — to the rollup that the kernel never
    // actually acted on, which is the one thing this signal must not do.
    //
    // A count above `MAX_DENIAL_COUNT` is not a measurement either, and it
    // is the far more dangerous half: unbounded, it overflows the `BIGINT`
    // the upsert accumulates into and takes the node's whole ingest down
    // with it. See [`MAX_DENIAL_COUNT`].
    //
    // Rejected rather than clamped, deliberately. Clamping would store a
    // number nobody measured, indistinguishable from a real one from that
    // point on, in the signal an operator promotes a profile to enforcing
    // on. Rejecting loses one row and says so: the per-field reject counter
    // puts `count` in the ingest `warn!`, which is a diagnosable Controller
    // bug rather than silent fiction.
    if d.count <= 0 || d.count > MAX_DENIAL_COUNT {
        return Some("count");
    }
    None
}

/// Fold a batch onto the storage key, summing counts and bracketing the
/// timestamps.
///
/// Summing is load-bearing rather than tidying. The BPF map is keyed on
/// `(netns, generation, syscall_nr, action)` — `generation` is part of the
/// KERNEL key but not of ours, so a pod whose container restarted inside one
/// drain interval yields two entries for the same `(pod, syscall, action)`
/// in a single batch. Last-one-wins would discard the earlier generation's
/// count outright, and Postgres rejects an `ON CONFLICT DO UPDATE` that
/// touches the same row twice in one statement, so the alternative to
/// folding here is an error, not a duplicate.
///
/// `first_seen`/`last_seen` are min/max rather than taken from either entry
/// for the same reason, and that also normalises an inverted pair from a
/// node whose clock stepped between the two reads.
///
/// # Why a future timestamp is clamped when a nonsense `count` is rejected
///
/// [`reject_reason`] validates seven fields and neither timestamp, and a
/// `last_seen` ahead of the Broker's clock is the one bad value that never
/// goes away: the prune is `last_seen < NOW() - interval`, so a row stamped a
/// year ahead outlives every retention window that will run in that year, and
/// `GET /seccomp/denials` orders `last_seen DESC`, so it also pins the top of
/// the list for the same year. One node with a skewed clock reaches it by
/// accident; a single POST reaches it on purpose, since `BROKER_AUTH_TOKEN`
/// is optional.
///
/// Clamping rather than rejecting, which is the opposite of what
/// [`MAX_DENIAL_COUNT`] gets, and for two reasons that do not apply to a
/// count:
///
/// - the count ceiling is ~40x the most extreme physical bound on one drain,
///   so no real node ever meets it and rejecting costs nothing real. A clock
///   a few seconds ahead of the Broker's is ordinary NTP drift on a healthy
///   node, so rejecting here would throw away real kernel verdicts over an
///   environmental condition — in the signal whose entire claim is that it
///   already happened.
/// - a clamped count would be a number nobody counted, indistinguishable from
///   a measurement from that point on. A timestamp clamped to the moment the
///   report was read is not invented: the kernel acted before the node
///   drained it and the node drained it before the Broker read it, so `now`
///   is a bound that is true by construction. The `count` on the row — the
///   quantity an operator acts on — is untouched either way.
///
/// `now` is passed in rather than read here so one report clamps every row
/// against one ceiling, and so the rule is testable without a clock.
///
/// Returns the folded rows, the per-field reject counts and how many entries
/// were ahead of the clock.
fn fold_batch(denials: Vec<DenialInput>, now: DateTime<Utc>) -> FoldedBatch {
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut from_the_future = 0usize;
    let mut folded: BTreeMap<(String, String, String), DenialInput> = BTreeMap::new();
    for mut d in denials {
        if let Some(field) = reject_reason(&d) {
            *rejected.entry(field).or_insert(0) += 1;
            continue;
        }
        // Before the fold, so no future value can reach the min/max below or
        // the upsert's LEAST/GREATEST. Both ends take the same ceiling, so a
        // clamped pair stays ordered.
        if d.first_seen > now || d.last_seen > now {
            from_the_future += 1;
            d.first_seen = d.first_seen.min(now);
            d.last_seen = d.last_seen.min(now);
        }
        let key = (d.pod_uid.clone(), d.syscall.clone(), d.action.clone());
        match folded.get_mut(&key) {
            Some(existing) => {
                // Clamped, not just saturated at `i64::MAX`: the ceiling
                // is an invariant on what this file ever stores, and a
                // fresh insert takes this value without passing through
                // the upsert's own clamp.
                existing.count = existing.count.saturating_add(d.count).min(MAX_DENIAL_COUNT);
                existing.first_seen = existing.first_seen.min(d.first_seen).min(d.last_seen);
                existing.last_seen = existing.last_seen.max(d.last_seen).max(d.first_seen);
                // Keep whichever entry could resolve the optional fields; a
                // later entry that could not must not blank them.
                existing.syscall_nr = existing.syscall_nr.or(d.syscall_nr);
                existing.action_raw = existing.action_raw.or(d.action_raw);
                existing.arch = existing.arch.take().or(d.arch);
            }
            None => {
                let mut d = d;
                // Same normalisation for a singleton, so a swapped pair is
                // never stored inverted just because it arrived alone.
                let (lo, hi) = if d.first_seen <= d.last_seen {
                    (d.first_seen, d.last_seen)
                } else {
                    (d.last_seen, d.first_seen)
                };
                d.first_seen = lo;
                d.last_seen = hi;
                folded.insert(key, d);
            }
        }
    }
    FoldedBatch {
        rows: folded.into_values().collect(),
        rejected,
        from_the_future,
    }
}

/// What one batch amounted to after validation and folding.
struct FoldedBatch {
    /// The rows that survived, folded onto the storage key.
    rows: Vec<DenialInput>,
    /// Per-field reject counts, so the ingest log can name the field that
    /// failed rather than report a bare total.
    rejected: BTreeMap<&'static str, usize>,
    /// Entries whose timestamps were ahead of the Broker's clock and were
    /// pulled back to it. A skewed node clock, not a rejected row — but an
    /// operator-visible condition either way.
    from_the_future: usize,
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

/// Pod -> owning workload, for the pods named in one batch.
///
/// Keyed on pod name because that is `pod_details`' primary key, but the
/// namespace is verified before the attribution is used: see
/// [`attribute`].
fn attribution_index(
    conn: &mut PgConnection,
    pod_names: &BTreeSet<String>,
) -> Result<AttributionIndex, DbError> {
    use schema::pod_details::dsl as pd;
    if pod_names.is_empty() {
        return Ok(HashMap::new());
    }
    let names: Vec<&String> = pod_names.iter().collect();
    let rows: Vec<PodAttributionRow> = pd::pod_details
        .filter(pd::pod_name.eq_any(names))
        .select((
            pd::pod_name,
            pd::pod_namespace,
            pd::workload_kind,
            pd::workload_name,
        ))
        .load(conn)?;
    Ok(rows
        .into_iter()
        .map(|(name, ns, kind, workload)| (name, (ns, kind, workload)))
        .collect())
}

/// The workload a denial belongs to, or `(None, None)` when it cannot be
/// resolved.
///
/// The namespace check is not defensive tidiness. `pod_details`' key is the
/// pod name alone, so two pods with the same name in different namespaces
/// collapse to one row, and attributing a denial by name alone would then
/// name ANOTHER TEAM'S workload as the one the kernel acted on — in a
/// `SeccompProfile` status, on a dashboard, and in an alert. Refusing to
/// attribute is the correct answer there.
///
/// # Refusing is not free, and it used to be treated as if it were
///
/// The obvious reading — "the denial is still stored and still queryable by
/// pod, it simply does not claim a workload it cannot prove" — is wrong, and
/// it was this function's doc comment until it cost a false all-clear. The
/// rollup filters unattributed rows out and [`DenialIndex::block_for`]
/// answers a workload with no rows with `total: 0`, so a refusal here does
/// not leave the workload's status silent: it fills it in with the clean
/// answer. The workload's block is what the promotion gate reads, and nothing
/// sends an operator to `GET /seccomp/denials` first.
///
/// So the refusal is still right — a wrong workload name is worse than none —
/// but it is a fact the read path has to carry rather than absorb. It does:
/// see [`UnattributedNamespaces`], which withholds the all-clear from the
/// whole namespace the unattributable row is in, and
/// [`crate::retention::BACKFILL_DENIAL_ATTRIBUTION_SQL`], which re-runs this
/// rule against `pod_details` later for rows that failed it only because the
/// pod was not known yet.
///
/// # A pod with no controller is its own workload
///
/// The pod watcher records a bare pod — `kubectl run`, a debug pod, a
/// static control-plane pod — with NULL `workload_kind` / `workload_name`,
/// and nothing ever fills that in. Treating such a row as "not resolvable
/// yet" would put it in [`UnattributedNamespaces`] forever, withholding the
/// all-clear from every CR in its namespace, and it would sit at the head
/// of the backfill's candidate list on every pass. A pod the watcher HAS
/// seen, in the right namespace, with no owner, is attributed to itself as
/// `("Pod", pod_name)`: a real key the rollup can group on and the metrics
/// can label, that no `workloadRef` will ever match.
///
/// Pure so the refusal has a test rather than a comment.
fn attribute(
    denial_namespace: &str,
    pod_name: &str,
    pod_details: Option<&PodAttribution>,
) -> (Option<String>, Option<String>) {
    let Some((ns, kind, workload)) = pod_details else {
        return (None, None);
    };
    // A pod_details row with no namespace recorded cannot be disproved, and
    // predates nothing in this schema that would make it common; treat it as
    // a match rather than throwing away attribution the controller did
    // resolve.
    if ns.as_deref().is_some_and(|n| n != denial_namespace) {
        return (None, None);
    }
    match (kind, workload) {
        (Some(k), Some(w)) => (Some(k.clone()), Some(w.clone())),
        (None, None) => (Some(BARE_POD_KIND.to_string()), Some(pod_name.to_string())),
        // Partial attribution is no attribution: the rollup key needs both,
        // and half a key would group unrelated workloads together.
        _ => (None, None),
    }
}

/// `workload_kind` for a pod with no controller owner: the pod is the
/// workload. Mirrors what the backfill writes in
/// [`crate::retention::BACKFILL_DENIAL_ATTRIBUTION_SQL`].
pub(crate) const BARE_POD_KIND: &str = "Pod";

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// `POST /seccomp/denials` — the controller's 10 s drain of the BPF denial
/// map for one node.
pub async fn post_seccomp_denials(
    pool: web::Data<DbPool>,
    metrics: web::Data<SeccompDenialMetrics>,
    body: web::Json<DenialBatch>,
) -> actix_web::Result<impl Responder> {
    let batch = body.into_inner();
    let node = batch.node.trim().to_string();
    if node.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("node is required"));
    }
    if node.len() > MAX_DNS_NAME_LEN {
        return Err(actix_web::error::ErrorBadRequest("node too long"));
    }

    // Read off before `validate` consumes the batch, so the warning below can
    // name the value the operator actually set rather than the clamped one.
    let batch_interval = batch.interval_seconds;
    // One clock reading for the whole report: every row is clamped against
    // the same ceiling, so the fold is a function of the batch rather than of
    // how long it took to walk it.
    let ValidatedReport {
        rows,
        rejected,
        from_the_future,
        capturing,
        interval_seconds,
        interval_clamped,
    } = batch.validate(Utc::now());
    if interval_clamped {
        // Not a rejection either — the heartbeat is kept. But a node that
        // drains slower than the Broker will vouch for it reads stale between
        // its own reports, so its workloads sit at `DenialsObserved: Unknown`
        // and an operator needs to be told why rather than left to infer it
        // from a flapping condition.
        warn!(
            %node,
            declared = ?batch_interval,
            ceiling = MAX_REPORT_INTERVAL_SECS,
            "seccomp denial report declared a drain interval above the ceiling \
             the broker will trust; it was clamped to the ceiling, so the node \
             reads as stale if its reports arrive more than 1800 s apart. Lower \
             seccomp.denials.intervalSeconds."
        );
    }
    if !rejected.is_empty() {
        // Per-field, not a bare total: "12 rejected" tells an operator
        // nothing, "12 rejected on count" says the controller is shipping
        // empty drains and "12 rejected on podUid" says attribution broke on
        // the node.
        warn!(%node, ?rejected, "seccomp denial batch had unusable entries");
    }
    if from_the_future > 0 {
        // Not a rejection, so it does not belong in the map above — but a
        // node whose clock runs ahead of the Broker's is an operator-fixable
        // fault, and the clamp would otherwise be silent.
        warn!(
            %node,
            entries = from_the_future,
            "seccomp denial batch carried timestamps ahead of the broker's clock; \
             they were clamped to the ingest time, check the node's clock"
        );
    }

    // The heartbeat, recorded on EVERY report including an empty one — and
    // before the early return below, because the empty report is the one
    // that matters most. An empty drain from a healthy node is what tells
    // the Broker that "no denials" means "nothing was denied" rather than
    // "nothing was watching", and it is the only thing that lets a fresh
    // install ever reach a real all-clear instead of sitting at Unknown
    // forever.
    // The heartbeat is stamped only once the rows are stored, never before:
    // it is what `capture_is_live` reads, and a node whose denials keep
    // failing to land must not keep vouching for the cluster's all-clear.
    // The controller replays a batch the broker 500s on, so nothing is lost
    // by answering 500 without a heartbeat.
    let heartbeat_pool = pool.clone();
    let heartbeat_node = node.clone();
    let heartbeat = move || -> Result<(), DbError> {
        let mut conn = heartbeat_pool.get()?;
        upsert_node_report(&mut conn, &heartbeat_node, capturing, interval_seconds)
    };

    if rows.is_empty() {
        web::block(heartbeat)
            .await?
            .map_err(actix_web::error::ErrorInternalServerError)?;
        debug!(%node, capturing, "seccomp denial heartbeat (no denials drained)");
        return Ok(HttpResponse::Ok().json(crate::Accepted { accepted: 0 }));
    }

    let pod_names: BTreeSet<String> = rows.iter().map(|d| d.pod_name.clone()).collect();
    let accepted = rows.len();
    let node_for_rows = node.clone();

    let (unattributed, increments) = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        let out = store_batch(&mut conn, &node_for_rows, &pod_names, rows)?;
        heartbeat()?;
        Ok(out)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    // AFTER the transaction commits, never before: the controller clears its
    // BPF map only on a successful POST, so a batch the broker 500s on is
    // replayed. Counting it here and again on the replay would inflate the
    // counter by exactly the amount an operator is alerting on.
    metrics.record_batch(increments, accepted);
    info!(
        %node,
        rows = accepted,
        unattributed,
        "seccomp denials ingested"
    );
    Ok(HttpResponse::Ok().json(crate::Accepted { accepted }))
}

/// Resolve attribution for one validated drain and store it.
///
/// Extracted from [`post_seccomp_denials`] rather than inlined so the live
/// tests can run the real path — attribution, the refusal, and the upsert —
/// against a real `pod_details`. A test that rebuilt this loop would be
/// asserting its own copy of the rule it is meant to be checking, which is a
/// failure mode this feature has already shipped once.
///
/// Returns how many rows named no workload and the Prometheus increments,
/// which are built here because this is where attribution is resolved: the
/// series is labelled by the workload, so the label set does not exist until
/// this loop runs.
fn store_batch(
    conn: &mut PgConnection,
    node: &str,
    pod_names: &BTreeSet<String>,
    rows: Vec<DenialInput>,
) -> Result<(usize, Vec<(DenialLabels, i64)>), DbError> {
    let index = attribution_index(conn, pod_names)?;
    let mut unattributed = 0usize;
    let mut inserts: Vec<NewDenial> = Vec::with_capacity(rows.len());
    let mut increments: Vec<(DenialLabels, i64)> = Vec::with_capacity(rows.len());
    for d in rows {
        let (workload_kind, workload_name) =
            attribute(&d.pod_namespace, &d.pod_name, index.get(&d.pod_name));
        if workload_kind.is_none() {
            unattributed += 1;
        }
        increments.push((
            DenialLabels {
                namespace: d.pod_namespace.clone(),
                // Unattributed denials keep their namespace and action and
                // carry empty workload labels rather than being dropped from
                // the counter: "something was denied and we could not say
                // whose" is a signal, not a non-event.
                workload_kind: workload_kind.clone().unwrap_or_default(),
                workload: workload_name.clone().unwrap_or_default(),
                action: d.action.clone(),
            },
            d.count,
        ));
        inserts.push(NewDenial {
            pod_uid: d.pod_uid,
            pod_name: d.pod_name,
            pod_namespace: d.pod_namespace,
            workload_kind,
            workload_name,
            node_name: Some(node.to_string()),
            syscall: d.syscall,
            syscall_nr: d.syscall_nr,
            action: d.action,
            action_raw: d.action_raw,
            arch: d.arch,
            count: d.count,
            first_seen: d.first_seen,
            last_seen: d.last_seen,
        });
    }
    // One transaction for the whole batch: a partially applied drain would be
    // double-counted by the next one, because the controller clears its BPF
    // map on a successful POST and has no way to replay only the half that
    // landed.
    conn.transaction::<_, DbError, _>(|conn| {
        for chunk in inserts.chunks(INSERT_CHUNK) {
            upsert_denials(conn, chunk)?;
        }
        Ok(())
    })?;
    Ok((unattributed, increments))
}

/// `INSERT ... ON CONFLICT (pod_uid, syscall, action) DO UPDATE`, the
/// accumulation the whole table shape depends on.
///
/// Built here rather than inline in [`upsert_denials`] so a test can render
/// the real statement. Every rule below is a raw SQL fragment the type
/// system cannot check, and a test that re-declares them proves nothing
/// about what production sends.
///
/// Four things here are not interchangeable with the obvious alternative:
///
/// - `count` is `existing + EXCLUDED`, not `EXCLUDED`. The controller ships
///   the delta since its last drain and clears the map, so overwriting would
///   turn a cumulative count into "whatever the last 10 seconds held" and
///   make the Prometheus counter non-monotonic.
/// - the sum is computed in `NUMERIC` and clamped by `LEAST` before it is
///   cast back. `BIGINT + BIGINT` raises on overflow, and it raises BEFORE
///   an enclosing `LEAST` could clamp it, so the cast has to be the last
///   step. `MAX_DENIAL_COUNT` bounds each report, but nothing bounds how
///   many reports land on one row — the ceiling on the running total is
///   what actually stops a 500 that would replay forever. The clamp cannot
///   lower a stored value: every write here is capped at the same ceiling,
///   so `LEAST(existing + delta, CEILING) >= existing` holds for anything
///   this code path put there.
/// - `first_seen`/`last_seen` are `LEAST`/`GREATEST`, not `EXCLUDED`. Drains
///   from a node whose clock stepped, or two nodes' reports for a pod seen
///   across a migration, must widen the bracket rather than move it.
/// - every nullable column is `COALESCE(EXCLUDED.x, existing.x)`, not
///   `EXCLUDED.x`. A later report that could not resolve the workload (the
///   pod's `pod_details` row was pruned) must not erase attribution an
///   earlier one did resolve — that would silently drop the row out of the
///   per-workload rollup the CR status is built from, which reads as "the
///   denials stopped".
///
/// `pod_name` and `pod_namespace` are absent from the SET list entirely,
/// which is the one rule here that is about what is NOT written. They are
/// `NOT NULL`, so the `COALESCE` guard the nullable columns get would be a
/// no-op on them — `EXCLUDED.x` is never NULL, so the existing value could
/// never be reached. Leaving them unwritten is the guard that actually
/// holds. A pod uid's name and namespace are fixed for the life of the uid,
/// so a conflicting report disagreeing about them is a lie or a bug either
/// way; and the rollup groups on `(pod_namespace, workload_kind,
/// workload_name)`, so honouring the new namespace would move an existing
/// row into a DIFFERENT workload's rollup — counts appearing under a
/// namespace that never made the syscall, and disappearing from the one
/// that did.
fn denial_upsert(
    rows: &[NewDenial],
) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
       + diesel::query_builder::QueryId
       + diesel::query_dsl::methods::ExecuteDsl<PgConnection>
       + diesel::RunQueryDsl<PgConnection>
       + '_ {
    use schema::seccomp_denials::dsl as sd;
    diesel::insert_into(sd::seccomp_denials)
        .values(rows)
        .on_conflict((sd::pod_uid, sd::syscall, sd::action))
        .do_update()
        .set((
            sd::node_name.eq(diesel::dsl::sql::<Nullable<Text>>(
                "COALESCE(EXCLUDED.node_name, seccomp_denials.node_name)",
            )),
            sd::workload_kind.eq(diesel::dsl::sql::<Nullable<Text>>(
                "COALESCE(EXCLUDED.workload_kind, seccomp_denials.workload_kind)",
            )),
            sd::workload_name.eq(diesel::dsl::sql::<Nullable<Text>>(
                "COALESCE(EXCLUDED.workload_name, seccomp_denials.workload_name)",
            )),
            sd::syscall_nr.eq(diesel::dsl::sql::<Nullable<diesel::sql_types::Integer>>(
                "COALESCE(EXCLUDED.syscall_nr, seccomp_denials.syscall_nr)",
            )),
            sd::action_raw.eq(diesel::dsl::sql::<Nullable<BigInt>>(
                "COALESCE(EXCLUDED.action_raw, seccomp_denials.action_raw)",
            )),
            sd::arch.eq(diesel::dsl::sql::<Nullable<Text>>(
                "COALESCE(EXCLUDED.arch, seccomp_denials.arch)",
            )),
            // Interpolated from the constant rather than written out, so the
            // ceiling cannot drift from the one ingest validates against.
            sd::count.eq(diesel::dsl::sql::<BigInt>(&format!(
                "LEAST(seccomp_denials.count::NUMERIC + EXCLUDED.count, \
                 {MAX_DENIAL_COUNT})::BIGINT"
            ))),
            sd::first_seen.eq(diesel::dsl::sql::<Timestamptz>(
                "LEAST(seccomp_denials.first_seen, EXCLUDED.first_seen)",
            )),
            sd::last_seen.eq(diesel::dsl::sql::<Timestamptz>(
                "GREATEST(seccomp_denials.last_seen, EXCLUDED.last_seen)",
            )),
        ))
}

/// Apply one chunk of the drain. See [`denial_upsert`] for the rules.
fn upsert_denials(conn: &mut PgConnection, rows: &[NewDenial]) -> Result<(), DbError> {
    if rows.is_empty() {
        return Ok(());
    }
    denial_upsert(rows).execute(conn)?;
    Ok(())
}

/// Record one node's capture heartbeat. Replaces the node's row wholesale —
/// it is a liveness snapshot, not history.
///
/// `interval_seconds` is overwritten on every report, `None` included, for
/// exactly that reason: it is the cadence the node is running NOW, and a node
/// that stops declaring one must fall back to the floor rather than keep a
/// wide window some earlier configuration justified. That direction fails
/// safe — too short a window reads Unknown, too long a window reads
/// all-clear.
fn upsert_node_report(
    conn: &mut PgConnection,
    node: &str,
    capturing: bool,
    interval_seconds: Option<i64>,
) -> Result<(), DbError> {
    use schema::seccomp_denial_nodes::dsl as sdn;
    let now = Utc::now();
    diesel::insert_into(sdn::seccomp_denial_nodes)
        .values((
            sdn::node_name.eq(node),
            sdn::capturing.eq(capturing),
            sdn::updated_at.eq(now),
            sdn::interval_seconds.eq(interval_seconds),
        ))
        .on_conflict(sdn::node_name)
        .do_update()
        .set((
            sdn::capturing.eq(capturing),
            sdn::updated_at.eq(now),
            sdn::interval_seconds.eq(interval_seconds),
        ))
        .execute(conn)?;
    Ok(())
}

/// The liveness question, as one statement: has any node reported
/// `capturing = true` inside ITS OWN staleness window.
///
/// Rendered from the constants rather than written out so the window cannot
/// drift from what ingest clamps the declared interval to, and built here
/// rather than inline so a test can read the statement production sends.
///
/// `$1` is the Broker's clock, bound rather than taken as `NOW()`: the
/// `updated_at` it is compared against was stamped by [`upsert_node_report`]
/// from the same clock, and mixing in the database's would make the answer
/// depend on the skew between two machines.
///
/// `LIMIT 1` rather than a COUNT — the question is existence, and one row is
/// the whole answer.
///
/// The `LEAST` is the ceiling, and it is applied here rather than only at
/// ingest on purpose. Ingest clamps what it writes and the column's CHECK
/// clamps what anything else writes, but a row written under the wider bound
/// this replaced survives both — it was legal when it was stored. Bounding
/// the window where the window is computed means no stored value, from any
/// path or any past version, can buy more trust than
/// [`CAPTURE_REPORT_STALE_CEILING_SECS`].
fn capture_live_sql() -> String {
    format!(
        "SELECT node_name FROM seccomp_denial_nodes \
         WHERE capturing AND updated_at >= $1 - make_interval(secs => LEAST(\
         GREATEST({CAPTURE_REPORT_STALE_FLOOR_SECS}, \
         COALESCE(interval_seconds, 0) * {CAPTURE_REPORT_STALE_INTERVALS}), \
         {CAPTURE_REPORT_STALE_CEILING_SECS})) \
         LIMIT 1"
    )
}

/// Whether kguardian can currently see seccomp verdicts anywhere on this
/// cluster — the fact that decides whether a `denials` block of `total: 0`
/// is an all-clear or a lie.
///
/// One question, one answer: **a node reported `capturing = true` recently
/// enough to be believed**. Nothing else counts, and in particular the
/// existence of a denial row does not.
///
/// # Why a stored row is not an answer
///
/// It used to be one, as a fallback for a Controller too old to send the
/// heartbeat. No such Controller exists: `seccomp_denials` and
/// `seccomp_denial_nodes` were added in the same commit and the feature has
/// never shipped, so the arm defended a case that cannot occur — and cost two
/// false all-clears to keep. A denial row from a capture path that has since
/// been switched off kept the whole cluster reading "live" for as long as the
/// row survived retention, and a database restored into a cluster that never
/// enabled capture read "live" off someone else's history. Both are gone with
/// the arm, and so is every future route through row existence, because the
/// question is now about what is watching rather than about what is stored.
///
/// What is left is the honest set of states. A node reporting with the probe
/// attached is live. Disabling capture, scaling the DaemonSet to zero,
/// rebuilding nodes with `CONFIG_AUDIT=n` and a Controller that died all land
/// on not-live, and all of them should read as Unknown rather than as clean.
///
/// # Staleness is per node
///
/// The window is `min(CAPTURE_REPORT_STALE_CEILING_SECS,
/// max(CAPTURE_REPORT_STALE_FLOOR_SECS, declared interval x
/// CAPTURE_REPORT_STALE_INTERVALS))`, evaluated per row from the cadence that
/// node declared. A fixed window cannot work: the drain interval is an
/// operator-set value, so one supported Helm value made every node on a
/// capturing fleet look stale between reports and pinned the entire cluster
/// at Unknown. Nor can an unbounded one: the window is the all-clear gate, so
/// the cadence that widens it is also the cadence that decides how long a
/// departed node keeps the cluster reading clean. Hence a floor AND a
/// ceiling.
///
/// # Known limit
///
/// No signal here is per-workload. On a fleet where some nodes capture and
/// some do not, a workload whose pods only ever ran on non-capturing nodes
/// still gets a `total: 0`. Fixing that needs the workload's pods resolved
/// to their nodes; see [`load_denial_index`].
fn capture_is_live(conn: &mut PgConnection) -> Result<bool, DbError> {
    // The name is never read — the row's existence IS the answer — but
    // `sql_query` needs somewhere to decode a column into.
    #[derive(diesel::QueryableByName)]
    struct LiveNode {
        #[diesel(sql_type = Text)]
        #[allow(dead_code)]
        node_name: String,
    }

    let live: Option<LiveNode> = diesel::sql_query(capture_live_sql())
        .bind::<Timestamptz, _>(Utc::now())
        .get_result(conn)
        .optional()?;
    Ok(live.is_some())
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DenialQuery {
    pub namespace: Option<String>,
    pub kind: Option<String>,
    pub workload: Option<String>,
    /// RFC3339. Rows whose `last_seen` is at or after this instant.
    pub since: Option<String>,
    pub limit: Option<i64>,
}

/// Clamp the caller-supplied row limit into `[1, 500]`, default 100 — the
/// same window `clamp_audit_limit` applies, because these rows are the same
/// shape and order of size as an audit verdict.
pub(crate) fn clamp_denial_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(100).clamp(1, 500)
}

/// Empty string -> absent, so `?namespace=` from a blank form field means
/// "no filter", the convention `get.rs` and `compute_api.rs` share.
///
/// Note the asymmetry with `/audit/verdicts`, where an empty namespace IS a
/// filter (cluster-scoped policies are stored with `policy_namespace = ''`).
/// A pod always has a namespace, so there is no such value here.
fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Parse the `since` parameter. RFC3339 because `last_seen` is a
/// `TIMESTAMPTZ` produced on a node — a zone-less instant would have to
/// assume the caller meant UTC, and callers in other zones would silently
/// get the wrong window.
pub(crate) fn parse_since(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|d| Some(d.with_timezone(&Utc)))
        .map_err(|e| format!("invalid since={raw:?}; expected RFC3339 ({e})"))
}

/// `GET /seccomp/denials` — stored verdicts, newest `last_seen` first.
pub async fn get_seccomp_denials(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<DenialQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let limit = clamp_denial_limit(q.limit);
    let namespace = non_empty(q.namespace);
    let kind = non_empty(q.kind);
    let workload = non_empty(q.workload);
    // Rejected before the permit: refusing bad input must not first wait on
    // a memory budget. Same ordering `get_audit_verdicts` uses.
    let since = match parse_since(q.since.as_deref()) {
        Ok(s) => s,
        Err(msg) => return Ok(HttpResponse::BadRequest().body(msg)),
    };

    let _permit = match budget.acquire(cost_kib(limit, AUDIT_ROW_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };

    let rows = web::block(move || -> Result<Vec<DenialRow>, DbError> {
        let mut conn = pool.get()?;
        Ok(denials_query(
            &mut conn, namespace, kind, workload, since, limit,
        )?)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(rows))
}

/// The `GET /seccomp/denials` SELECT, built but not run.
///
/// Split out so a test can render the statement production actually issues.
/// The ordering below is the only thing that makes the visible top-N stable,
/// and it is invisible to any test that re-declares the query itself.
fn denials_query_statement<'a>(
    by_namespace: Option<String>,
    by_kind: Option<String>,
    by_workload: Option<String>,
    since: Option<DateTime<Utc>>,
    row_limit: i64,
) -> impl diesel::query_dsl::LoadQuery<'a, PgConnection, DenialRow>
       + diesel::query_builder::QueryFragment<diesel::pg::Pg> {
    use schema::seccomp_denials::dsl as sd;
    let mut q = sd::seccomp_denials.into_boxed();
    if let Some(ns) = by_namespace {
        q = q.filter(sd::pod_namespace.eq(ns));
    }
    if let Some(k) = by_kind {
        q = q.filter(sd::workload_kind.eq(k));
    }
    if let Some(w) = by_workload {
        q = q.filter(sd::workload_name.eq(w));
    }
    if let Some(s) = since {
        q = q.filter(sd::last_seen.ge(s));
    }
    // Tie-break on id DESC for the same reason `/audit/verdicts` does: the
    // node-supplied `last_seen` is only as granular as the drain, so a whole
    // batch routinely shares one value and an untied ORDER BY reshuffles the
    // visible top-N on every identical request.
    q.order((sd::last_seen.desc(), sd::id.desc()))
        .limit(row_limit)
        .select(DenialRow::as_select())
}

pub(crate) fn denials_query(
    conn: &mut PgConnection,
    by_namespace: Option<String>,
    by_kind: Option<String>,
    by_workload: Option<String>,
    since: Option<DateTime<Utc>>,
    row_limit: i64,
) -> Result<Vec<DenialRow>, diesel::result::Error> {
    denials_query_statement(by_namespace, by_kind, by_workload, since, row_limit).load(conn)
}

// ---------------------------------------------------------------------------
// Per-workload rollup (the `denials` block on GET /seccomp/profiles)
// ---------------------------------------------------------------------------

/// The `denials` block of a profile summary.
///
/// The controller's seccomp distributor reads this to set the CR's
/// `DenialsObserved` condition, so the shape is a contract: `total`,
/// `syscalls`, `actions`, `lastSeen`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct DenialBlock {
    pub total: i64,
    pub syscalls: Vec<String>,
    pub actions: Vec<String>,
    #[serde(rename = "lastSeen")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// One workload's denials, as the index holds them before capping.
#[derive(Debug, Clone, Default)]
pub(crate) struct DenialRollup {
    total: i64,
    syscalls: BTreeSet<String>,
    actions: BTreeSet<String>,
    last_seen: Option<DateTime<Utc>>,
}

/// The namespaces holding at least one denial that no workload could be
/// proved for.
///
/// A denial the Broker cannot attribute is not a neutral gap. The rollup
/// filters `workload_kind IS NULL` away and [`DenialIndex::block_for`]
/// answers a missing key with `total: 0`, so refusing to attribute MANUFACTURES
/// the clean answer for whichever workload the row belonged to — and that
/// workload's block is what the promotion gate reads. Storing the row and
/// leaving it visible on `GET /seccomp/denials` does not undo that, because
/// nothing makes an operator look there before promoting a profile whose
/// status says zero.
///
/// The namespace is the whole of what is known about such a row: `attribute`
/// failed precisely because the owning workload could not be proved, so there
/// is no narrower set to withhold from. It is also not a guess — it is the
/// namespace the node reported the pod in, `NOT NULL` and length-checked at
/// ingest, and it is the value that made attribution refuse in the collision
/// case (a `pod_details` row for another namespace's pod of the same name).
///
/// So the all-clear is withheld from that namespace and from nowhere else:
/// every workload in it reads `Unknown`, every other namespace is unaffected.
/// That is the honest answer, because at least one workload in that namespace
/// WAS denied and the Broker cannot say which.
#[derive(Debug, Clone)]
pub(crate) enum UnattributedNamespaces {
    /// The namespaces are known and listed. An empty set is the healthy
    /// state: every stored denial names a workload.
    Listed(BTreeSet<String>),
    /// More namespaces than [`MAX_UNATTRIBUTED_NAMESPACES`] hold an
    /// unattributed denial, so the set was not enumerated.
    ///
    /// Withholds from EVERYTHING. The alternative — keep the first thousand
    /// and let the rest through — hands a clean bill of health to exactly the
    /// namespaces the read ran out of room to warn about, which is the bug
    /// this type exists for, arriving through its own fix.
    TooMany,
}

impl UnattributedNamespaces {
    /// Whether this namespace has a denial nobody could attribute, and so
    /// cannot be told it is clean.
    fn withholds(&self, namespace: &str) -> bool {
        match self {
            UnattributedNamespaces::Listed(set) => set.contains(namespace),
            UnattributedNamespaces::TooMany => true,
        }
    }
}

/// Per-workload denial rollups plus the one fact that decides whether a
/// `denials` block can be emitted at all.
pub(crate) struct DenialIndex {
    by_workload: HashMap<WorkloadKey, DenialRollup>,
    /// Whether anything on this cluster is known to be watching — the
    /// answer [`capture_is_live`] gives, not "does a denial row exist".
    ///
    /// This is the whole reason the block is an `Option`. With nothing
    /// watching, "this workload was never denied" and "nothing on this
    /// cluster is capturing denials" produce identical database state —
    /// denial capture needs `CONFIG_AUDIT` on the node, can be switched off
    /// by the operator, and is skipped outright on a kernel without the
    /// `audit_seccomp` symbol. Emitting `total: 0` in that state would put
    /// an all-clear in the CR status for a workload nobody is watching.
    ///
    /// When it is true, a workload with no rows genuinely has no denials and
    /// its `0` is a real all-clear — for every workload whose pods ran on a
    /// node that is capturing. [`capture_is_live`] carries the one case left
    /// where that is not quite so: the answer is cluster-wide, so a mixed
    /// fleet can still hand a `0` to a workload that only ever ran on nodes
    /// nobody was watching.
    observed: bool,
    /// Namespaces with a denial that named no workload. See
    /// [`UnattributedNamespaces`].
    unattributed: UnattributedNamespaces,
}

impl DenialIndex {
    /// An index for a broker that has no denial observations. Every
    /// `block_for` returns `None`.
    pub(crate) fn empty() -> Self {
        DenialIndex {
            by_workload: HashMap::new(),
            observed: false,
            unattributed: UnattributedNamespaces::Listed(BTreeSet::new()),
        }
    }

    /// The `denials` block for one workload, or `None` when no block can
    /// honestly be computed.
    ///
    /// This follows the same rule as the `cr` block above it in
    /// `seccomp.rs`: when the data needed to compute a block is missing,
    /// emit NO block rather than an empty one that reads as "all clear".
    ///
    /// The decisive argument, as with drift, is what the controller does
    /// with each. With the block absent the distributor takes its `None`
    /// arm and writes `DenialsObserved` "Unknown" — a state it already
    /// models, and the right one for "could not determine". With a
    /// `total: 0` block it writes "False", which an operator reads as "the
    /// kernel has not acted on this profile", on a cluster where nothing was
    /// ever looking.
    ///
    /// Two facts can withhold the block, and they are different questions.
    /// `observed` asks whether anything on the cluster is watching at all.
    /// [`UnattributedNamespaces`] asks whether this namespace holds a denial
    /// the Broker could not pin on a workload — because such a row is not
    /// absent from the rollup neutrally, it is absent in a way that reads as
    /// `total: 0` for whichever workload it belonged to.
    pub(crate) fn block_for(&self, key: &WorkloadKey) -> Option<DenialBlock> {
        if !self.observed {
            return None;
        }
        if self.unattributed.withholds(&key.0) {
            return None;
        }
        let rollup = self.by_workload.get(key).cloned().unwrap_or_default();
        Some(DenialBlock {
            total: rollup.total,
            syscalls: rollup
                .syscalls
                .into_iter()
                .take(MAX_DENIAL_SYSCALLS)
                .collect(),
            actions: rollup
                .actions
                .into_iter()
                .take(MAX_DENIAL_ACTIONS)
                .collect(),
            last_seen: rollup.last_seen,
        })
    }

    /// Test-only constructor for an index with observations, so
    /// `seccomp.rs` can pin the summary-level behaviour of the block
    /// without a database.
    #[cfg(test)]
    pub(crate) fn with_rows(rows: Vec<DenialRollupRow>) -> Self {
        let mut index = DenialIndex {
            by_workload: HashMap::new(),
            observed: true,
            unattributed: UnattributedNamespaces::Listed(BTreeSet::new()),
        };
        for (ns, kind, name, syscall, action, count, last_seen) in rows {
            let key = (ns, kind, name);
            index.add_total(&key, count, last_seen);
            index.add_names(&key, syscall, action);
        }
        index
    }

    /// Fold one workload's `(total, last_seen)` into the index.
    fn add_total(&mut self, key: &WorkloadKey, count: i64, last_seen: DateTime<Utc>) {
        let e = self.by_workload.entry(key.clone()).or_default();
        e.total = e.total.saturating_add(count);
        e.last_seen = Some(match e.last_seen {
            Some(prev) => prev.max(last_seen),
            None => last_seen,
        });
    }

    /// Attach one `(syscall, action)` pair to a workload the totals pass
    /// already produced.
    ///
    /// A pair for an unknown workload is DROPPED rather than creating an
    /// entry. The two queries read the same rows under the same filter, so a
    /// name with no total means a row landed between them — and an entry
    /// created from a name alone would carry `total: 0`, which is the false
    /// all-clear this whole file exists to avoid. A pair arriving one poll
    /// early is not worth manufacturing one.
    fn add_names(&mut self, key: &WorkloadKey, syscall: String, action: String) {
        if let Some(e) = self.by_workload.get_mut(key) {
            e.syscalls.insert(syscall);
            e.actions.insert(action);
        }
    }
}

/// KiB to reserve before a cluster-wide [`denial_index`] call.
///
/// Charged from the cap rather than from a `COUNT(*)`: the count would be a
/// scan of the largest table in this feature, run on the hot path of the
/// endpoint the UI polls every 15 s, to bill a read that is almost always
/// tiny. The neighbouring reservations make the same trade wherever the real
/// count is not already in hand — see
/// [`crate::read_budget::SECCOMP_DETAIL_ROWS_CHARGED`]. The cost is a flat
/// over-charge on a cluster with few denials.
pub(crate) fn denial_index_charge_kib() -> u32 {
    cost_kib(
        MAX_DENIAL_ROLLUP_NAME_ROWS,
        DENIAL_ROLLUP_NAME_ROW_COST_BYTES,
    )
    .saturating_add(cost_kib(
        // The read stops one row past the cap, and that row is read before
        // it is counted.
        MAX_UNATTRIBUTED_NAMESPACES as i64 + 1,
        UNATTRIBUTED_NAMESPACE_ROW_COST_BYTES,
    ))
}

/// KiB to reserve before a single-workload [`denial_index_for`] call.
///
/// The scoped unattributed read is one row by construction — it asks about a
/// single namespace — so it is inside the rounding on this reservation rather
/// than a term of its own.
pub(crate) fn denial_index_for_charge_kib() -> u32 {
    cost_kib(
        MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD,
        DENIAL_ROLLUP_NAME_ROW_COST_BYTES,
    )
}

/// The denial rollup for every workload — the list endpoint's index.
pub(crate) fn denial_index(conn: &mut PgConnection) -> Result<DenialIndex, DbError> {
    load_denial_index(conn, None)
}

/// The denial rollup for one workload — the detail endpoint's index.
pub(crate) fn denial_index_for(
    conn: &mut PgConnection,
    key: &WorkloadKey,
) -> Result<DenialIndex, DbError> {
    load_denial_index(conn, Some(key))
}

/// Only attributed rows can be rolled up per workload, because a rollup key
/// needs a workload and an unattributed row has none. That NOT NULL filter is
/// also what lets the rollup row types declare the two workload columns
/// non-nullable.
///
/// What the filter removes does NOT stop mattering here. A row it drops still
/// belonged to some workload in its namespace, and dropping it silently is
/// how an unattributable denial became a `total: 0` all-clear. The rows this
/// filter excludes are counted on their own axis by
/// [`unattributed_namespaces_sql`] and withhold the block for their
/// namespace; `GET /seccomp/denials` remains the endpoint that can show them
/// individually, without having to claim a workload for them.
const ROLLUP_ATTRIBUTED: &str =
    " FROM seccomp_denials WHERE workload_kind IS NOT NULL AND workload_name IS NOT NULL";

/// The single-workload narrowing, bound as `$1/$2/$3` by both rollup reads.
const ROLLUP_ONLY: &str = " AND pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3";

/// One row per workload: the `total` and `lastSeen` half of a `denials`
/// block. Deliberately uncapped — see [`load_denial_index`].
///
/// `SUM(count)` is cast because Postgres widens a sum of BIGINT to NUMERIC,
/// which diesel would reject at runtime rather than at compile time. The
/// cast is safe because [`MAX_DENIAL_COUNT`] bounds every stored count;
/// without that ceiling this cast is itself an overflow waiting for a large
/// enough workload.
fn rollup_totals_sql(scoped: bool) -> String {
    format!(
        "SELECT pod_namespace, workload_kind, workload_name, \
         SUM(count)::BIGINT AS total, MAX(last_seen) AS last_seen{ROLLUP_ATTRIBUTED}{} \
         GROUP BY pod_namespace, workload_kind, workload_name",
        if scoped { ROLLUP_ONLY } else { "" },
    )
}

/// The `(syscall, action)` pairs behind a block's name lists, bounded per
/// workload.
///
/// `ROW_NUMBER()` caps each workload at
/// [`MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD`] so one workload denied on
/// hundreds of syscalls cannot crowd out the rest. That is the bound that
/// matters; the outer LIMIT of [`MAX_DENIAL_ROLLUP_NAME_ROWS`] — the figure
/// [`denial_index_charge_kib`] reserves against the read budget — is the
/// cluster-wide ceiling behind it. A scoped read cannot need more than one
/// workload's own cap, so that is its LIMIT.
///
/// # Byte order, not the database's
///
/// Every `ORDER BY` here is `COLLATE "C"`, and that is not decoration. The
/// ranks decide WHICH pairs survive the cap and
/// [`DenialIndex::block_for`] then truncates the survivors through a
/// `BTreeSet`, which orders by UTF-8 bytes. Unqualified, the SQL orders by
/// the DATABASE's collation, and on a glibc Postgres — RDS, Cloud SQL, the
/// official non-alpine image — `en_US.UTF-8` ignores punctuation at the
/// primary level and inverts case, so it disagrees with byte order on
/// exactly the shape syscall names have: it sorts `ioctl` before
/// `io_uring_enter` where bytes sort `io_uring_enter` first. The two
/// truncations then keep different sets, and an operator building an
/// allow-list from `status.denials.syscalls` gets a syscall the kernel never
/// denied in place of one it did. `COLLATE "C"` is memcmp, which is what
/// `BTreeSet<String>` does, so the two orderings become one ordering. (musl's
/// `en_US.UTF-8` IS byte order, which is why a Postgres on alpine cannot see
/// any of this.)
///
/// # The cluster-wide ceiling truncates evenly
///
/// The outer `ORDER BY` leads with `rn`, so the LIMIT takes every workload's
/// first pair before it takes any workload's second. That is the difference
/// between a ceiling that shortens lists and one that erases them. Ordered by
/// workload first, the workloads that sorted last lost their whole name list
/// while keeping a non-zero `total` — which the distributor renders as "280
/// denials on 0 syscalls" — and which workload fell past the cap depended on
/// OTHER namespaces' pair counts, so a workload at the boundary flipped
/// between a populated list and an empty one and made every node rewrite the
/// CR on every flip. Leading with `rn` bounds the read by the same number of
/// rows while guaranteeing each workload a share of it. It is still a total
/// order, so truncation is deterministic across identical polls instead of
/// reshuffling every 15 s.
///
/// DISTINCT before the window: the same pair repeats once per pod, and
/// ranking without collapsing that first would spend a 500-replica
/// Deployment's whole per-workload budget on one syscall.
fn rollup_names_sql(scoped: bool) -> String {
    let limit = if scoped {
        MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD
    } else {
        MAX_DENIAL_ROLLUP_NAME_ROWS
    };
    format!(
        "SELECT pod_namespace, workload_kind, workload_name, syscall, action FROM ( \
         SELECT pod_namespace, workload_kind, workload_name, syscall, action, \
         ROW_NUMBER() OVER ( \
         PARTITION BY pod_namespace, workload_kind, workload_name \
         ORDER BY syscall COLLATE \"C\", action COLLATE \"C\") AS rn FROM ( \
         SELECT DISTINCT pod_namespace, workload_kind, workload_name, syscall, action\
         {ROLLUP_ATTRIBUTED}{}) pairs) ranked \
         WHERE rn <= {MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD} \
         ORDER BY rn, pod_namespace COLLATE \"C\", workload_kind COLLATE \"C\", \
         workload_name COLLATE \"C\", syscall COLLATE \"C\", action COLLATE \"C\" \
         LIMIT {limit}",
        if scoped { ROLLUP_ONLY } else { "" },
    )
}

/// The namespaces holding a denial that named no workload.
///
/// The complement of [`ROLLUP_ATTRIBUTED`], on its own axis: the rollup reads
/// the rows that HAVE a workload, this reads which namespaces have rows that
/// do not. `DISTINCT` because the answer is a set of namespaces and the row
/// count behind each is irrelevant — one unattributable denial withholds the
/// namespace's all-clear exactly as firmly as a thousand.
///
/// `LIMIT MAX_UNATTRIBUTED_NAMESPACES + 1` so the caller can tell "this is
/// the whole set" from "there are more", which are different answers and must
/// not be confused: see [`UnattributedNamespaces::TooMany`]. The scoped form
/// is the detail endpoint's, narrowed to the one namespace it is asked about,
/// and cannot return more than one row.
///
/// Either workload column being NULL is enough. `attribute` returns both or
/// neither, so a half-filled pair should not exist — but the rollup's filter
/// requires both, so a row with one of them set would otherwise be dropped
/// from the rollup AND missed here, which is precisely the hole this closes.
fn unattributed_namespaces_sql(scoped: bool) -> String {
    let limit = if scoped {
        1
    } else {
        MAX_UNATTRIBUTED_NAMESPACES + 1
    };
    format!(
        "SELECT DISTINCT pod_namespace FROM seccomp_denials \
         WHERE (workload_kind IS NULL OR workload_name IS NULL){} \
         LIMIT {limit}",
        if scoped {
            " AND pod_namespace = $1"
        } else {
            ""
        },
    )
}

/// Read [`unattributed_namespaces_sql`] into the set `block_for` consults.
fn unattributed_namespaces(
    conn: &mut PgConnection,
    only: Option<&WorkloadKey>,
) -> Result<UnattributedNamespaces, DbError> {
    #[derive(diesel::QueryableByName)]
    struct NamespaceRow {
        #[diesel(sql_type = Text)]
        pod_namespace: String,
    }

    let sql = unattributed_namespaces_sql(only.is_some());
    let rows: Vec<NamespaceRow> = match only {
        Some((ns, _, _)) => diesel::sql_query(sql).bind::<Text, _>(ns).load(conn)?,
        None => diesel::sql_query(sql).load(conn)?,
    };
    if rows.len() > MAX_UNATTRIBUTED_NAMESPACES {
        warn!(
            cap = MAX_UNATTRIBUTED_NAMESPACES,
            "more namespaces hold an unattributable seccomp denial than the rollup \
             will enumerate; no workload will be reported as clean until attribution \
             recovers"
        );
        return Ok(UnattributedNamespaces::TooMany);
    }
    let set: BTreeSet<String> = rows.into_iter().map(|r| r.pod_namespace).collect();
    // Only from the cluster-wide read. The scoped one is a narrowing of the
    // same question asked once per workload on the detail endpoint, so
    // logging there would repeat what the list endpoint already says, per
    // workload, for as long as the condition lasts.
    if !set.is_empty() && only.is_none() {
        // Named, not counted: the operator's next move is to look at
        // `GET /seccomp/denials?namespace=<ns>` for the pod behind it, and a
        // bare total does not tell them where to look. These namespaces are
        // reporting `DenialsObserved: Unknown` until it is resolved, which is
        // a state worth explaining rather than leaving to be inferred.
        warn!(
            namespaces = ?set,
            "seccomp denials in these namespaces name no workload, so no workload \
             in them can be reported clean; the pod was not in pod_details when the \
             denial arrived, or two namespaces share a pod name"
        );
    }
    Ok(UnattributedNamespaces::Listed(set))
}

/// Load the denial rollup. `only` narrows both reads to a single workload.
///
/// `observed` is deliberately NOT narrowed by `only`: scoped to one
/// workload it would be exactly `total > 0`, which collapses the
/// "unknown" and "zero" cases back together and defeats the whole point of
/// the flag. It is always a question about the cluster.
///
/// # Two queries, and why it is not one
///
/// A `denials` block needs a `total` and a `lastSeen`, which are per
/// WORKLOAD, and a `syscalls`/`actions` list, which is per `(syscall,
/// action)`. Folding both out of one grouped query is what made this read
/// unbounded, and capping THAT query is what would make it wrong: drop a row
/// and the total it contributed goes with it, silently, in the number an
/// operator promotes a profile to enforcing on. Worse, dropping a
/// workload's last row removes it from the index entirely, and
/// [`DenialIndex::block_for`] answers for a missing workload with
/// `total: 0` — a capped single query manufactures all-clears.
///
/// So the totals are read on their own axis and never capped, and the names
/// are read on theirs and capped twice. The totals query returns one row per
/// workload, which is the axis `GET /seccomp/profiles` already materialises
/// and already charges for; and that axis is bounded by the cluster, not by
/// the caller, because a row only reaches it once `attribute` has matched
/// the pod against `pod_details`.
fn load_denial_index(
    conn: &mut PgConnection,
    only: Option<&WorkloadKey>,
) -> Result<DenialIndex, DbError> {
    // Not "does a denial row exist" — "is anything watching". The two were
    // the same check until the capture heartbeat existed, and conflating
    // them is what made a quiet healthy cluster indistinguishable from one
    // where the probe never loaded.
    //
    // KNOWN GAP, and it is the one to fix next in this file: this answer is
    // CLUSTER-WIDE, so it is the same for every workload in the index. On a
    // fleet where some nodes capture and some do not — the normal state
    // mid kernel-upgrade — a workload whose pods only ever ran on
    // non-capturing nodes still gets a block saying `total: 0`, because some
    // OTHER node is capturing. That is a narrower version of exactly the
    // false all-clear the heartbeat was added to remove, and `total: 0` is
    // what promotes a profile from audit to enforcing.
    //
    // Fixing it means resolving each workload's pods to their nodes
    // (`pod_details.node_name`) and emitting a block only when every node
    // that workload ran on is capturing and fresh. Deliberately deferred
    // rather than overlooked: it changes the shape of the signal, and the
    // cluster-wide version is already strictly better than the "any row
    // exists" proxy it replaced. Documented for operators as a warning on
    // the `denials` block in docs/api-reference/endpoints/seccomp.mdx.
    let observed = capture_is_live(conn)?;
    if !observed {
        return Ok(DenialIndex::empty());
    }

    // The second thing that can withhold a block, and a different question
    // from the first: not "is anything watching" but "did something get
    // watched and land nowhere". Read before the rollup because it decides
    // which of the rollup's answers may be emitted at all.
    let unattributed = unattributed_namespaces(conn, only)?;

    // ---- totals ---------------------------------------------------------
    //
    // Aggregated in Postgres, not in Rust, and that is the difference
    // between this read being bounded and being unbounded. The stored row is
    // per POD per syscall per action, and every replica of a workload trips
    // the same syscalls, so those are pure multiplication for a block that
    // carries neither: a 500-replica Deployment tripping 20 syscalls is
    // 10 000 rows read to produce one `{total, lastSeen}`. Grouping them
    // away in SQL leaves one row per workload crossing libpq.
    //
    // Not separately charged against the read budget. One row per workload
    // is ~200 B against the 4 KiB per workload `list_seccomp_profiles`
    // already reserves (`SECCOMP_WORKLOAD_COST_BYTES`), which has twenty
    // times the margin this needs; the detail endpoint reads a single row.
    // The NAMES query below is the one that scales on another axis, and it
    // is charged for.
    //
    #[derive(diesel::QueryableByName)]
    struct TotalRow {
        #[diesel(sql_type = Text)]
        pod_namespace: String,
        #[diesel(sql_type = Text)]
        workload_kind: String,
        #[diesel(sql_type = Text)]
        workload_name: String,
        #[diesel(sql_type = BigInt)]
        total: i64,
        #[diesel(sql_type = Timestamptz)]
        last_seen: DateTime<Utc>,
    }

    let totals_sql = rollup_totals_sql(only.is_some());

    // ---- names: see `rollup_names_sql` for both caps ---------------------
    #[derive(diesel::QueryableByName)]
    struct NameRow {
        #[diesel(sql_type = Text)]
        pod_namespace: String,
        #[diesel(sql_type = Text)]
        workload_kind: String,
        #[diesel(sql_type = Text)]
        workload_name: String,
        #[diesel(sql_type = Text)]
        syscall: String,
        #[diesel(sql_type = Text)]
        action: String,
    }

    let names_sql = rollup_names_sql(only.is_some());

    let (totals, names): (Vec<TotalRow>, Vec<NameRow>) = match only {
        Some((ns, kind, name)) => (
            diesel::sql_query(totals_sql)
                .bind::<Text, _>(ns)
                .bind::<Text, _>(kind)
                .bind::<Text, _>(name)
                .load(conn)?,
            diesel::sql_query(names_sql)
                .bind::<Text, _>(ns)
                .bind::<Text, _>(kind)
                .bind::<Text, _>(name)
                .load(conn)?,
        ),
        None => (
            diesel::sql_query(totals_sql).load(conn)?,
            diesel::sql_query(names_sql).load(conn)?,
        ),
    };

    // Hitting the cluster-wide ceiling is reported, not swallowed. Every
    // workload still keeps a share of the read — see `rollup_names_sql` — so
    // no block silently loses its whole list, but the lists ARE shorter than
    // the data supports, and an operator reading `syscalls` to build an
    // allow-list needs to know that. The totals are never affected.
    let names_cap = if only.is_some() {
        MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD
    } else {
        MAX_DENIAL_ROLLUP_NAME_ROWS
    };
    if names.len() as i64 >= names_cap {
        warn!(
            rows = names.len(),
            cap = names_cap,
            "seccomp denial rollup hit its name-row ceiling; syscall and action \
             lists are truncated for every workload (totals are not)"
        );
    }

    let mut index = DenialIndex {
        by_workload: HashMap::new(),
        observed,
        unattributed,
    };
    for r in totals {
        index.add_total(
            &(r.pod_namespace, r.workload_kind, r.workload_name),
            r.total,
            r.last_seen,
        );
    }
    for r in names {
        index.add_names(
            &(r.pod_namespace, r.workload_kind, r.workload_name),
            r.syscall,
            r.action,
        );
    }
    Ok(index)
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// The label set of one `kguardian_seccomp_denials_total` series.
///
/// Labelled by workload_namespace / workload_kind / workload / action and
/// NOT by syscall. That is a deliberate cardinality choice, and it is now
/// load-bearing twice over: a syscall label would multiply the series count
/// by ~300 for information that is one `GET /seccomp/denials` away and does
/// not belong in an alerting rule, AND this key is the map key of a counter
/// held in the broker's memory for the life of the process, so its
/// cardinality is a memory bound rather than only a Prometheus bill.
///
/// # The field is `namespace`, the emitted label is `workload_namespace`
///
/// That asymmetry is deliberate on BOTH sides, and neither half is safe to
/// "tidy" into agreement with the other.
///
/// The label cannot be `namespace`: prometheus-operator relabels
/// `__meta_kubernetes_namespace` onto a `namespace` target label for every
/// ServiceMonitor-generated job, and with `honor_labels` false (the default,
/// and forceable by `overrideHonorLabels` on the Prometheus CR) ours would
/// be renamed to `exported_namespace` and replaced by whichever namespace
/// kguardian is installed in — every alert naming the wrong namespace, and
/// `sum by (workload_namespace, ...)` grouping on a constant that folds
/// `payments/worker` and `media/worker` together. See
/// `main.rs::render_denial_series`, which owns the rendering and the full
/// argument.
///
/// The field stays `namespace` because it is not a label name here: it is
/// the pod's namespace as ingest resolved it, matching `DenialInput`,
/// `NewDenial`, `DenialRow` and the `?namespace=` query parameter on
/// `GET /seccomp/denials`. Renaming it would rename an API the runbooks
/// pair with this metric on purpose. The one place the two spellings meet
/// is the renderer.
///
/// Empty `workload_kind` / `workload` mean the denial could not be
/// attributed. Prometheus treats an empty label value as absent, so those
/// fold into one per-namespace series rather than disappearing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DenialLabels {
    pub namespace: String,
    pub workload_kind: String,
    pub workload: String,
    pub action: String,
}

/// One rendered `kguardian_seccomp_denials_total` series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompDenialSeries {
    pub namespace: String,
    pub workload_kind: String,
    pub workload: String,
    pub action: String,
    pub total: u64,
}

/// Denial metrics state shared by the ingest handler, the refresh task and
/// the `/metrics` scrape.
///
/// `/metrics` runs with a 100 ms pool timeout precisely so a saturated pool
/// cannot block a Prometheus scrape, which means the scrape path must not
/// touch Postgres at all. Two of the three series never need it; the third
/// is refreshed on a timer and read from here.
#[derive(Debug)]
pub struct SeccompDenialMetrics {
    /// `kguardian_seccomp_denials_total`, accumulated at INGEST.
    ///
    /// # Why this is not `SELECT sum(count) FROM seccomp_denials`
    ///
    /// Because that number is not monotonic, and a Prometheus counter must
    /// be. `seccomp_denials.count` is the live state of a table the
    /// retention loop deletes from, so a table-derived counter DROPS at
    /// every retention pass. Prometheus reads any decrease in a counter as a
    /// process restart and compensates by adding the post-reset value on top
    /// of the pre-reset one — so each prune injects a phantom step into
    /// `rate()` and `increase()`.
    ///
    /// Both alerts that ship with the chart sit directly on those functions
    /// (`KguardianSeccompDenialRateAbnormal` on `rate(...) > 10`, and
    /// `KguardianSeccompEnforcingProfileDenials`, a critical page, on
    /// `increase(...[5m]) > 0`). A table-derived counter would page at every
    /// retention boundary, and the false page would be indistinguishable
    /// from the compromised-workload signal the alert exists to catch.
    ///
    /// So the counter is accumulated from the deltas the controller ships —
    /// it drains and clears its BPF map each interval, so each `count` on
    /// the wire is an increment, never a level — and retention never touches
    /// it. A broker restart zeroes it, which is a real counter reset and the
    /// one case Prometheus handles correctly by design.
    ///
    /// Do NOT "simplify" this into a query against the table it sits next
    /// to. The table holds the same numbers; it does not hold them
    /// monotonically.
    counters: RwLock<BTreeMap<DenialLabels, u64>>,
    /// Increments dropped because `counters` was at [`MAX_DENIAL_SERIES`].
    /// Surfaced in the refresh task's log rather than as a fourth metric,
    /// which the contract does not define.
    overflow_series: AtomicU64,
    /// `kguardian_seccomp_denial_rows_total`. Also ingest-driven, and a
    /// process counter for the same monotonicity reason.
    rows_total: AtomicU64,
    /// `kguardian_seccomp_denial_workloads`. A GAUGE, and the one value here
    /// that is genuinely table-derived — "distinct workloads with a denial
    /// inside the retention window" is a question about current table state,
    /// so pruning SHOULD move it down. It cannot be derived from `counters`:
    /// that map is cumulative since process start, so it still holds
    /// workloads whose rows retention has since removed, and it is empty
    /// after a restart that left the table full.
    workloads: AtomicU64,
}

impl Default for SeccompDenialMetrics {
    fn default() -> Self {
        SeccompDenialMetrics {
            counters: RwLock::new(BTreeMap::new()),
            overflow_series: AtomicU64::new(0),
            rows_total: AtomicU64::new(0),
            workloads: AtomicU64::new(0),
        }
    }
}

impl SeccompDenialMetrics {
    /// Apply one accepted batch: add each denial's count to its series and
    /// the row count to `rows_total`.
    ///
    /// Called only after the ingest transaction COMMITS. Incrementing before
    /// the write would over-count a batch the broker then rejected with a
    /// 500, and the controller replays those — it clears its BPF map only on
    /// a successful POST.
    ///
    /// Poison is tolerated rather than propagated: a panic in an unrelated
    /// writer must not make every subsequent ingest 500.
    fn record_batch(&self, increments: Vec<(DenialLabels, i64)>, rows: usize) {
        self.rows_total.fetch_add(rows as u64, Ordering::Relaxed);
        let mut map = self.counters.write().unwrap_or_else(|p| p.into_inner());
        let mut overflow = 0u64;
        for (labels, count) in increments {
            // Negative counts are rejected at validation, so this is belt
            // and braces — but a counter is the one place a stray negative
            // must never reach, because it would decrement and read as a
            // reset.
            let count = count.max(0) as u64;
            let has_room = map.len() < MAX_DENIAL_SERIES;
            match map.get_mut(&labels) {
                Some(v) => *v = v.saturating_add(count),
                None if has_room => {
                    map.insert(labels, count);
                }
                // At capacity with a new label set. Refused rather than
                // evicting an existing series: evicting would make that
                // series restart from zero on its next increment, which is
                // the non-monotonicity this whole design exists to avoid.
                // The denial is still stored, still queryable, and still
                // counted by `kguardian_seccomp_denial_rows_total`.
                None => overflow += 1,
            }
        }
        if overflow > 0 {
            self.overflow_series.fetch_add(overflow, Ordering::Relaxed);
        }
    }

    /// The series to render, highest count first with the label set as a
    /// deterministic tie-break.
    ///
    /// The read lock is held only long enough to copy the map; sorting
    /// happens after it is released, so a scrape never blocks ingest for
    /// longer than a clone of at most [`MAX_DENIAL_SERIES`] entries.
    pub fn series(&self) -> Vec<SeccompDenialSeries> {
        let mut out: Vec<SeccompDenialSeries> = {
            let map = self.counters.read().unwrap_or_else(|p| p.into_inner());
            map.iter()
                .map(|(k, total)| SeccompDenialSeries {
                    namespace: k.namespace.clone(),
                    workload_kind: k.workload_kind.clone(),
                    workload: k.workload.clone(),
                    action: k.action.clone(),
                    total: *total,
                })
                .collect()
        };
        out.sort_by(|a, b| {
            b.total.cmp(&a.total).then_with(|| {
                (&a.namespace, &a.workload_kind, &a.workload, &a.action).cmp(&(
                    &b.namespace,
                    &b.workload_kind,
                    &b.workload,
                    &b.action,
                ))
            })
        });
        out
    }

    /// Rows ingested since broker start. A process counter, not a database
    /// one: it resets on restart, which is what Prometheus expects of a
    /// `_total` and what makes it a useful "is ingest alive" signal
    /// independent of retention.
    pub fn rows_total(&self) -> u64 {
        self.rows_total.load(Ordering::Relaxed)
    }

    /// Distinct workloads with at least one denial in the retention window.
    pub fn workloads(&self) -> u64 {
        self.workloads.load(Ordering::Relaxed)
    }

    /// Increments refused for lack of series capacity, cumulative.
    pub fn overflow_series(&self) -> u64 {
        self.overflow_series.load(Ordering::Relaxed)
    }

    fn set_workloads(&self, n: u64) {
        self.workloads.store(n, Ordering::Relaxed);
    }
}

/// Refresh cadence for the workload gauge — the ONLY denial metric that
/// queries the database.
///
/// It does not feed the denial alerts. Those read
/// `kguardian_seccomp_denials_total`, which is accumulated at ingest
/// precisely so no timer sits between a denial and the counter an operator
/// pages on. What this cadence governs is dashboard freshness for a gauge.
///
/// Still deliberately NOT the retention loop's cadence, which defaults to an
/// hour: "how many workloads are currently being denied" is the number an
/// operator watches during a rollout, and an hour-stale answer to that is
/// not an answer. 15 s sits under a typical 30 s scrape, so the scrape is
/// never the stale part, and the query is a single `COUNT(DISTINCT …)`.
///
/// Do not merge this timer into the retention loop to save a task: the two
/// cadences differ by two orders of magnitude on purpose.
fn metrics_interval() -> Duration {
    let secs = std::env::var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS")
        .ok()
        // Same trim defense every env reader in the broker applies: a
        // pasted "15\n" must not fall back to the default.
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_METRICS_INTERVAL_SECS);
    Duration::from_secs(secs.max(MIN_METRICS_INTERVAL_SECS))
}

/// Distinct attributed workloads holding at least one denial, on one
/// connection. Kept synchronous so the caller runs it inside
/// `spawn_blocking`, and split from the pool so the live-database test
/// exercises the real query.
///
/// This is the ONLY thing the metrics path asks Postgres for. The two
/// counters are accumulated at ingest (see [`SeccompDenialMetrics`]), so the
/// per-workload `GROUP BY` this function used to carry is gone with them —
/// what is left is one aggregate returning a single row.
fn workload_count_from(conn: &mut PgConnection) -> Result<u64, DbError> {
    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        n: i64,
    }
    // Unattributed denials are not workloads, so they are excluded here even
    // though they DO appear in the counter series (with empty workload
    // labels). The two metrics answer different questions.
    let row: CountRow = diesel::sql_query(
        "SELECT COUNT(*) AS n FROM ( \
             SELECT DISTINCT pod_namespace, workload_kind, workload_name \
             FROM seccomp_denials \
             WHERE workload_kind IS NOT NULL AND workload_name IS NOT NULL \
         ) t",
    )
    .get_result(conn)?;
    Ok(row.n.max(0) as u64)
}

/// Pool wrapper for [`workload_count_from`].
fn load_workload_count(pool: &DbPool) -> Result<u64, DbError> {
    let mut conn = pool.get()?;
    workload_count_from(&mut conn)
}

/// Spawn the workload-gauge refresh loop. Returns immediately; the task
/// lives for the broker's lifetime.
///
/// Errors are logged and the loop continues, matching `retention.rs`: a
/// transient database outage must leave the last good value in place rather
/// than zero the gauge, which would read to an operator as "the denials
/// stopped" at exactly the moment the broker lost its database.
pub fn spawn_metrics_refresh(pool: DbPool, metrics: web::Data<SeccompDenialMetrics>) {
    let interval = metrics_interval();
    info!(
        interval_secs = interval.as_secs(),
        "seccomp denial workload gauge scheduled"
    );
    actix_web::rt::spawn(async move {
        loop {
            let pool = pool.clone();
            match tokio::task::spawn_blocking(move || load_workload_count(&pool)).await {
                Ok(Ok(n)) => {
                    metrics.set_workloads(n);
                    let overflow = metrics.overflow_series();
                    if overflow > 0 {
                        warn!(
                            dropped_increments = overflow,
                            cap = MAX_DENIAL_SERIES,
                            "seccomp denial series hit the cardinality cap; those denials are \
                             stored and queryable but absent from kguardian_seccomp_denials_total"
                        );
                    }
                    debug!(workloads = n, "seccomp denial workload gauge refreshed");
                }
                Ok(Err(e)) => warn!(error = %e, "seccomp denial workload gauge refresh failed"),
                Err(e) => warn!(error = %e, "seccomp denial workload gauge task panicked"),
            }
            tokio::time::sleep(interval).await;
        }
    });
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// `/seccomp/denials` — both verbs on one resource so the raised JSON body
/// limit ([`DENIAL_JSON_LIMIT_BYTES`]) is scoped to exactly this path
/// instead of being applied app-wide.
pub fn seccomp_denials_resource() -> actix_web::Resource {
    web::resource("/seccomp/denials")
        .app_data(web::JsonConfig::default().limit(DENIAL_JSON_LIMIT_BYTES))
        .route(web::get().to(get_seccomp_denials))
        .route(web::post().to(post_seccomp_denials))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// The Broker's clock, as the pure fold tests see it: after every
    /// timestamp [`input`] produces, so the clamp is inert unless a test
    /// deliberately reaches past it.
    fn ingest_now() -> DateTime<Utc> {
        ts("2026-09-14T09:00:00Z")
    }

    fn input(pod: &str, syscall: &str, action: &str, count: i64) -> DenialInput {
        DenialInput {
            pod_uid: format!("uid-{pod}"),
            pod_name: pod.to_string(),
            pod_namespace: "media".to_string(),
            syscall: syscall.to_string(),
            syscall_nr: Some(101),
            action: action.to_string(),
            action_raw: Some(2_147_483_648),
            arch: Some("SCMP_ARCH_X86_64".to_string()),
            count,
            first_seen: ts("2026-09-14T04:05:06Z"),
            last_seen: ts("2026-09-14T04:05:14Z"),
        }
    }

    // ---- folding -------------------------------------------------------

    /// The BPF map's key carries a `generation` that ours does not, so one
    /// drain can legitimately contain two entries for the same storage key.
    /// Summing is not tidying: last-one-wins silently loses a restarted
    /// container's denials, and Postgres rejects an ON CONFLICT DO UPDATE
    /// that touches one row twice, so not folding is an error rather than a
    /// duplicate row.
    /// The wire, spelled the way the Controller spells it.
    ///
    /// Deserialised from a JSON literal rather than from a `DenialBatch`
    /// built in Rust, because a round-trip through the struct passes whether
    /// or not the field names agree — it would serialise and deserialise
    /// under the same rename, and prove nothing about what crosses the wire.
    /// This body is the Controller's `rename_all = "camelCase"` output.
    ///
    /// The failure this pins is silent: drop the attribute on `DenialBatch`
    /// and `intervalSeconds` no longer matches `interval_seconds`, so
    /// `#[serde(default)]` yields `None`, every node falls back to the
    /// staleness floor, and both halves of the feature still look
    /// implemented. `node`, `capturing` and `denials` are single words and
    /// cannot catch it.
    #[test]
    fn wire_field_names_match_what_the_controller_sends() {
        let body = r#"{
            "node": "ip-10-0-1-23",
            "capturing": true,
            "intervalSeconds": 120,
            "denials": []
        }"#;
        let batch: DenialBatch = serde_json::from_str(body).expect("controller body must parse");
        assert_eq!(
            batch.interval_seconds,
            Some(120),
            "intervalSeconds did not reach the field; the struct is missing \
             rename_all = \"camelCase\" and staleness silently uses the floor"
        );
        assert_eq!(batch.node, "ip-10-0-1-23");
        assert_eq!(batch.capturing, Some(true));

        // And the declared cadence survives into the validated report, so
        // the assertion above cannot pass while the value is dropped later.
        //
        // 120 s is deliberately inside `MAX_REPORT_INTERVAL_SECS`, so this
        // stays a test about the field's NAME. A value above the ceiling is
        // clamped, which would make this assertion fail for a reason that has
        // nothing to do with the wire spelling — it did exactly that when the
        // ceiling was tightened. The clamp has its own test in
        // `a_declared_interval_falls_back_and_is_clamped`.
        let report = batch.validate(ingest_now());
        assert_eq!(report.interval_seconds, Some(120));
    }

    #[test]
    fn folding_sums_counts_for_one_storage_key() {
        let mut a = input("web-1", "ptrace", "SCMP_ACT_LOG", 17);
        a.first_seen = ts("2026-09-14T04:00:00Z");
        a.last_seen = ts("2026-09-14T04:05:00Z");
        let mut b = input("web-1", "ptrace", "SCMP_ACT_LOG", 5);
        b.first_seen = ts("2026-09-14T04:06:00Z");
        b.last_seen = ts("2026-09-14T04:09:00Z");

        let FoldedBatch { rows, rejected, .. } = fold_batch(vec![a, b], ingest_now());
        assert!(rejected.is_empty());
        assert_eq!(rows.len(), 1, "one storage key must produce one row");
        assert_eq!(rows[0].count, 22, "counts accumulate, they do not replace");
        assert_eq!(
            rows[0].first_seen,
            ts("2026-09-14T04:00:00Z"),
            "the bracket widens to the earliest observation"
        );
        assert_eq!(
            rows[0].last_seen,
            ts("2026-09-14T04:09:00Z"),
            "and to the latest"
        );
    }

    #[test]
    fn folding_keeps_distinct_syscalls_and_actions_apart() {
        let rows = fold_batch(
            vec![
                input("web-1", "ptrace", "SCMP_ACT_LOG", 1),
                input("web-1", "mount", "SCMP_ACT_LOG", 2),
                input("web-1", "ptrace", "SCMP_ACT_ERRNO", 3),
            ],
            ingest_now(),
        )
        .rows;
        assert_eq!(rows.len(), 3, "the key is (pod, syscall, action)");
    }

    /// An inverted pair means the node's clock stepped between the two reads
    /// of the BPF value. Storing it inverted would make `last_seen` order
    /// the query endpoint wrongly and break the retention scan's assumption
    /// that `last_seen` is the newest fact about a row.
    #[test]
    fn folding_normalises_an_inverted_timestamp_pair() {
        let mut d = input("web-1", "ptrace", "SCMP_ACT_LOG", 1);
        d.first_seen = ts("2026-09-14T05:00:00Z");
        d.last_seen = ts("2026-09-14T04:00:00Z");
        let rows = fold_batch(vec![d], ingest_now()).rows;
        assert_eq!(rows[0].first_seen, ts("2026-09-14T04:00:00Z"));
        assert_eq!(rows[0].last_seen, ts("2026-09-14T05:00:00Z"));
    }

    /// A timestamp the Broker's clock has not reached yet is the one bad
    /// value that never goes away on its own: the prune matches
    /// `last_seen < NOW() - interval`, so a row stamped a year ahead outlives
    /// every retention pass that runs in that year, and `GET /seccomp/denials`
    /// orders `last_seen DESC`, so it holds the top of the list for just as
    /// long. One skewed node clock reaches it by accident and a single POST
    /// reaches it on purpose.
    #[test]
    fn folding_clamps_a_timestamp_the_broker_has_not_reached_yet() {
        let now = ingest_now();
        let mut d = input("web-1", "ptrace", "SCMP_ACT_LOG", 7);
        d.first_seen = now + chrono::Duration::days(365);
        d.last_seen = now + chrono::Duration::days(366);

        let folded = fold_batch(vec![d], now);
        assert_eq!(
            folded.rows.len(),
            1,
            "clamped, not rejected: a clock a few seconds ahead is ordinary \
             NTP drift, and refusing the row would throw away a kernel \
             verdict that demonstrably happened"
        );
        assert_eq!(folded.rows[0].last_seen, now);
        assert_eq!(folded.rows[0].first_seen, now);
        assert_eq!(
            folded.rows[0].count, 7,
            "the count is the measurement, and clamping a timestamp must not \
             touch it — which is exactly why `count` itself is rejected \
             rather than clamped"
        );
        assert_eq!(
            folded.from_the_future, 1,
            "and the clamp is reported, so a skewed node clock is a fact an \
             operator can act on rather than a silent rewrite"
        );
    }

    /// The ordinary case must not pay for the clamp: a report that is merely
    /// recent is stored exactly as it arrived.
    #[test]
    fn folding_leaves_a_timestamp_at_or_before_now_alone() {
        let now = ingest_now();
        let mut d = input("web-1", "ptrace", "SCMP_ACT_LOG", 1);
        d.first_seen = now - chrono::Duration::seconds(10);
        d.last_seen = now;
        let folded = fold_batch(vec![d], now);
        assert_eq!(
            folded.rows[0].first_seen,
            now - chrono::Duration::seconds(10)
        );
        assert_eq!(folded.rows[0].last_seen, now);
        assert_eq!(folded.from_the_future, 0);
    }

    /// A zero-count row would add a workload to the rollup — and therefore
    /// flip a CR's `DenialsObserved` to True — for a denial the kernel never
    /// made.
    #[test]
    fn folding_rejects_non_positive_counts() {
        let FoldedBatch { rows, rejected, .. } = fold_batch(
            vec![
                input("web-1", "ptrace", "SCMP_ACT_LOG", 0),
                input("web-2", "ptrace", "SCMP_ACT_LOG", -3),
                input("web-3", "ptrace", "SCMP_ACT_LOG", 1),
            ],
            ingest_now(),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rejected.get("count").copied(), Some(2));
    }

    /// One stored row, as both the SQL-shape tests and the live tests build
    /// it. Shared so the statement the tests render is built from the same
    /// struct the live tests actually store.
    fn new_denial() -> NewDenial {
        NewDenial {
            pod_uid: "uid-web-1".into(),
            pod_name: "web-1".into(),
            pod_namespace: "media".into(),
            workload_kind: Some("Deployment".into()),
            workload_name: Some("web".into()),
            node_name: Some("node-a".into()),
            syscall: "ptrace".into(),
            syscall_nr: Some(101),
            action: "SCMP_ACT_LOG".into(),
            action_raw: Some(2_147_483_648),
            arch: Some("SCMP_ARCH_X86_64".into()),
            count: 17,
            first_seen: ts("2026-09-14T04:05:06Z"),
            last_seen: ts("2026-09-14T04:05:14Z"),
        }
    }

    /// The count arriving off the wire is added to a BIGINT that Postgres
    /// RAISES on rather than saturating, inside the one transaction the
    /// whole drain shares. An unbounded value there does not corrupt a
    /// number — it 500s the POST, and the Controller clears its BPF map only
    /// on a successful POST, so it replays the same batch every interval
    /// forever and every later denial from that node is lost.
    #[test]
    fn folding_rejects_a_count_no_kernel_could_have_produced() {
        let FoldedBatch { rows, rejected, .. } = fold_batch(
            vec![
                input("web-1", "ptrace", "SCMP_ACT_LOG", i64::MAX),
                input("web-2", "ptrace", "SCMP_ACT_LOG", MAX_DENIAL_COUNT + 1),
                input("web-3", "ptrace", "SCMP_ACT_LOG", MAX_DENIAL_COUNT),
            ],
            ingest_now(),
        );
        assert_eq!(
            rejected.get("count"),
            Some(&2),
            "both out-of-range counts are rejected on `count`, so the warn! \
             names the field an operator has to go and look at"
        );
        assert_eq!(
            rows.len(),
            1,
            "the ceiling is generous enough that the boundary value itself \
             is still accepted: {rows:?}"
        );
        assert_eq!(rows[0].count, MAX_DENIAL_COUNT);
    }

    /// The ceiling is an invariant on what this file ever STORES, and a
    /// fresh insert takes the folded value without passing through the
    /// upsert's clamp — so the fold has to hold it too.
    #[test]
    fn folding_clamps_a_summed_count_to_the_ceiling() {
        let FoldedBatch { rows, rejected, .. } = fold_batch(
            vec![
                input("web-1", "ptrace", "SCMP_ACT_LOG", MAX_DENIAL_COUNT),
                input("web-1", "ptrace", "SCMP_ACT_LOG", MAX_DENIAL_COUNT),
            ],
            ingest_now(),
        );
        assert!(rejected.is_empty(), "each entry is individually in range");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, MAX_DENIAL_COUNT);
    }

    #[test]
    fn folding_rejects_rows_that_cannot_identify_themselves() {
        let mut no_uid = input("web-1", "ptrace", "SCMP_ACT_LOG", 1);
        no_uid.pod_uid = "  ".into();
        let mut no_syscall = input("web-2", "ptrace", "SCMP_ACT_LOG", 1);
        no_syscall.syscall = String::new();
        let mut no_action = input("web-3", "ptrace", "SCMP_ACT_LOG", 1);
        no_action.action = String::new();
        let mut long_syscall = input("web-4", "ptrace", "SCMP_ACT_LOG", 1);
        long_syscall.syscall = "x".repeat(MAX_SYSCALL_LEN + 1);

        let FoldedBatch { rows, rejected, .. } = fold_batch(
            vec![no_uid, no_syscall, no_action, long_syscall],
            ingest_now(),
        );
        assert!(rows.is_empty());
        assert_eq!(rejected.get("podUid").copied(), Some(1));
        assert_eq!(
            rejected.get("syscall").copied(),
            Some(2),
            "empty and oversized both"
        );
        assert_eq!(rejected.get("action").copied(), Some(1));
    }

    /// An unresolvable field in a later drain must not blank what an earlier
    /// one resolved — the same COALESCE rule the upsert applies, applied to
    /// the in-memory fold so the two halves agree.
    #[test]
    fn folding_keeps_optional_fields_that_any_entry_resolved() {
        let a = input("web-1", "syscall_462", "SCMP_ACT_LOG", 1);
        let mut b = input("web-1", "syscall_462", "SCMP_ACT_LOG", 1);
        b.syscall_nr = None;
        b.arch = None;
        b.action_raw = None;

        let rows = fold_batch(vec![a, b], ingest_now()).rows;
        assert_eq!(rows[0].syscall_nr, Some(101));
        assert_eq!(rows[0].arch.as_deref(), Some("SCMP_ARCH_X86_64"));
        assert_eq!(rows[0].action_raw, Some(2_147_483_648));
    }

    // ---- capture heartbeat ---------------------------------------------

    fn batch(capturing: Option<bool>, denials: Vec<DenialInput>) -> DenialBatch {
        DenialBatch {
            node: "n1".into(),
            capturing,
            interval_seconds: None,
            denials,
        }
    }

    /// The flag is the normal signal: an empty drain from a node whose probe
    /// is attached is exactly the report that lets a quiet cluster reach a
    /// real all-clear instead of sitting at Unknown forever.
    #[test]
    fn an_empty_report_from_a_capturing_node_still_proves_capture() {
        assert!(batch(Some(true), vec![]).validate(ingest_now()).capturing);
    }

    /// The case the whole `capturing` field exists for. A node on a
    /// CONFIG_AUDIT=n kernel degrades gracefully: the Controller keeps
    /// running and keeps reporting, so it is demonstrably alive — and it is
    /// watching nothing. Reading "we heard from it" as "it is capturing"
    /// would turn graceful degradation into a false all-clear, which is the
    /// worst outcome available here: it is what promotes a profile from
    /// audit to enforcing.
    #[test]
    fn a_reporting_but_non_capturing_node_does_not_prove_capture() {
        assert!(!batch(Some(false), vec![]).validate(ingest_now()).capturing);
    }

    /// Denials in hand outrank the flag in both directions.
    #[test]
    fn denials_prove_capture_whatever_the_flag_says() {
        // A report carrying rows the kernel produced proves the probe fired,
        // whatever the flag says or fails to say.
        assert!(
            batch(None, vec![input("web-1", "ptrace", "SCMP_ACT_LOG", 1)])
                .validate(ingest_now())
                .capturing
        );
        // And a node that reports `false` while shipping denials is believed
        // on the evidence rather than on its own self-assessment.
        assert!(
            batch(
                Some(false),
                vec![input("web-1", "ptrace", "SCMP_ACT_LOG", 1)]
            )
            .validate(ingest_now())
            .capturing
        );
    }

    /// Absent the flag AND absent denials there is no evidence either way,
    /// and the honest answer is "not known to be capturing". Claiming
    /// capture from a silent report is the one error that produces a false
    /// all-clear.
    #[test]
    fn a_silent_report_with_no_flag_proves_nothing() {
        assert!(!batch(None, vec![]).validate(ingest_now()).capturing);
    }

    /// The evidence is what SURVIVED validation, not what arrived.
    ///
    /// Counted off the wire vector, every batch below is non-empty and every
    /// one of them recorded the node as capturing — a Controller shipping
    /// empty drains, a node whose attribution broke, or one unauthenticated
    /// POST of a single garbage row, since `BROKER_AUTH_TOKEN` is optional on
    /// a default deploy. None of them is evidence that anything is watching,
    /// and all of them produced the all-clear the flag exists to withhold.
    #[test]
    fn a_report_whose_every_row_was_rejected_proves_nothing() {
        let unusable = || {
            vec![
                // Not a denial: the kernel acted zero times.
                input("web-1", "ptrace", "SCMP_ACT_LOG", 0),
                // Cannot identify itself.
                DenialInput {
                    pod_uid: "  ".into(),
                    ..input("web-2", "ptrace", "SCMP_ACT_LOG", 1)
                },
                // Not a measurement any kernel could have produced.
                DenialInput {
                    count: i64::MAX,
                    ..input("web-3", "ptrace", "SCMP_ACT_LOG", 1)
                },
            ]
        };
        assert_eq!(unusable().len(), 3, "the wire vector is not empty");

        let report = batch(None, unusable()).validate(ingest_now());
        assert!(report.rows.is_empty(), "and nothing survived validation");
        assert!(
            !report.capturing,
            "a report that carried no usable row is not evidence that the \
             probe fired, and recording it as capture is what turns a broken \
             node into a cluster-wide all-clear"
        );
        assert!(
            !batch(Some(false), unusable())
                .validate(ingest_now())
                .capturing,
            "and it cannot overrule the node's own `capturing: false` either"
        );
        // The flag is still believed on its own: this rule subtracts
        // evidence, it does not add a way to lose a real heartbeat.
        assert!(
            batch(Some(true), unusable())
                .validate(ingest_now())
                .capturing
        );
    }

    /// The cadence a node declares decides its own staleness window, so it
    /// is the one field on the batch that can widen the all-clear gate.
    /// Absent or zero falls back to the floor; a value past the ceiling is
    /// clamped rather than rejected, because rejecting would throw away the
    /// heartbeat riding with it — and the clamp is reported, because it has a
    /// consequence the operator has to be able to find.
    #[test]
    fn a_declared_interval_falls_back_and_is_clamped() {
        assert_eq!(declared_interval_seconds(None), (None, false));
        assert_eq!(declared_interval_seconds(Some(0)), (None, false));
        assert_eq!(declared_interval_seconds(Some(10)), (Some(10), false));
        assert_eq!(
            declared_interval_seconds(Some(MAX_REPORT_INTERVAL_SECS as u64)),
            (Some(MAX_REPORT_INTERVAL_SECS), false)
        );
        assert_eq!(
            declared_interval_seconds(Some(MAX_REPORT_INTERVAL_SECS as u64 + 1)),
            (Some(MAX_REPORT_INTERVAL_SECS), true),
            "a node cannot buy itself a wider window than the broker grants"
        );
        assert_eq!(
            declared_interval_seconds(Some(u64::MAX)),
            (Some(MAX_REPORT_INTERVAL_SECS), true),
            "including one that does not fit the column it lands in"
        );
        assert_eq!(
            batch(Some(true), vec![])
                .validate(ingest_now())
                .interval_seconds,
            None,
            "and a report that declares nothing stores nothing, so the \
             liveness query falls back to the floor"
        );
    }

    /// The window has a CEILING as well as a floor, and the ceiling is the
    /// half that guards the all-clear.
    ///
    /// The floor stops a fast node flipping to Unknown between drains. The
    /// ceiling stops a slow one — or a fabricated one — claiming its single
    /// report is still evidence days later. Without it the bound was
    /// `MAX_REPORT_INTERVAL_SECS * 3`, and at the 86 400 s interval bound
    /// that was 259 200 s: exactly three days of cluster-wide `total: 0`
    /// bought by one POST.
    #[test]
    fn the_staleness_window_is_bounded_at_both_ends() {
        assert_eq!(
            MAX_REPORT_INTERVAL_SECS * CAPTURE_REPORT_STALE_INTERVALS,
            CAPTURE_REPORT_STALE_CEILING_SECS,
            "the interval bound is derived from the window ceiling, so a \
             declared cadence at the bound uses the whole window and no \
             cadence can ask for more"
        );
        // `const` blocks: both are compile-time facts about the constants,
        // so they fail the build rather than a test run — and clippy refuses
        // a runtime assertion whose value is constant anyway.
        const {
            assert!(
                CAPTURE_REPORT_STALE_CEILING_SECS > CAPTURE_REPORT_STALE_FLOOR_SECS,
                "a ceiling below the floor would make the floor unreachable \
                 and every node permanently stale"
            )
        };
        const {
            assert!(
                CAPTURE_REPORT_STALE_CEILING_SECS <= 3_600,
                "the window is how long kguardian will tell an operator a \
                 workload is clean on the strength of one old report; an hour \
                 is already past what that claim can carry"
            )
        };
        let sql = capture_live_sql();
        assert!(
            sql.contains("LEAST(")
                && sql.contains(&format!("), {CAPTURE_REPORT_STALE_CEILING_SECS})")),
            "and the ceiling is applied in the query, so a row stored under \
             the wider bound this replaced cannot outlive it: {sql}"
        );
    }

    /// Liveness is answered by the heartbeat and by nothing else.
    ///
    /// The row-existence fallback this used to carry defended a Controller
    /// too old to send heartbeats — and none can exist, because both denial
    /// migrations landed in one commit and the feature has never shipped. It
    /// cost two false all-clears to keep: a denial row from a capture path
    /// since switched off kept the cluster reading live until retention
    /// removed the row, and a restored database read live off history that
    /// was never this cluster's. Asking the question about what is watching
    /// rather than about what is stored closes both, and every other route
    /// through row existence with them.
    ///
    /// This pins the statement; `live_database_never_reads_liveness_off_a_\
    /// stored_denial` pins the behaviour against a real database.
    #[test]
    fn liveness_reads_the_heartbeat_table_and_never_the_denial_table() {
        let sql = capture_live_sql();
        assert!(
            sql.contains("FROM seccomp_denial_nodes"),
            "the heartbeat is the whole answer: {sql}"
        );
        assert!(
            !sql.contains("seccomp_denials"),
            "a stored denial proves capture WORKED, never that anything is \
             watching now, and treating it as liveness is how a switched-off \
             capture path keeps handing out all-clears: {sql}"
        );
        assert!(sql.contains("WHERE capturing"), "{sql}");
    }

    /// The staleness window is per node, computed from the cadence that node
    /// declared. A fixed one cannot work: the Controller's drain interval is
    /// an operator-set value, so a supported Helm value made every node on a
    /// capturing fleet look stale between its own reports and pinned the
    /// cluster at Unknown forever.
    #[test]
    fn liveness_trusts_each_nodes_own_cadence_above_a_floor() {
        let sql = capture_live_sql();
        assert!(
            sql.contains(&format!("GREATEST({CAPTURE_REPORT_STALE_FLOOR_SECS}")),
            "a node that declares nothing still gets the floor: {sql}"
        );
        assert!(
            sql.contains(&format!(
                "COALESCE(interval_seconds, 0) * {CAPTURE_REPORT_STALE_INTERVALS}"
            )),
            "and one that declares a cadence is believed for that many of \
             its own intervals: {sql}"
        );
        assert!(
            MAX_REPORT_INTERVAL_SECS.saturating_mul(CAPTURE_REPORT_STALE_INTERVALS) < i64::MAX,
            "ingest clamps the declared interval, and the column carries the \
             same bound as a CHECK, so this multiplication cannot overflow \
             inside the query"
        );
    }

    // ---- attribution ---------------------------------------------------

    #[test]
    fn attribution_uses_the_pods_resolved_workload() {
        let pd = (
            Some("media".to_string()),
            Some("Deployment".to_string()),
            Some("media-transform".to_string()),
        );
        assert_eq!(
            attribute("media", "media-transform-abc", Some(&pd)),
            (
                Some("Deployment".to_string()),
                Some("media-transform".to_string())
            )
        );
    }

    /// `pod_details` is keyed on pod name alone, so a name reused in another
    /// namespace resolves to the wrong row. Attributing on that would name
    /// another team's workload as the one the kernel acted on — in a CR
    /// status, on a dashboard and in an alert. The denial is still stored
    /// and still queryable by pod; it just does not claim a workload it
    /// cannot prove.
    #[test]
    fn attribution_refuses_a_namespace_mismatch() {
        let pd = (
            Some("payments".to_string()),
            Some("Deployment".to_string()),
            Some("ledger".to_string()),
        );
        assert_eq!(attribute("media", "ledger-0", Some(&pd)), (None, None));
    }

    #[test]
    fn attribution_is_none_for_an_unknown_pod_or_a_half_resolved_one() {
        assert_eq!(attribute("media", "web-7", None), (None, None));
        let half = (
            Some("media".to_string()),
            Some("Deployment".to_string()),
            None,
        );
        assert_eq!(
            attribute("media", "web-7", Some(&half)),
            (None, None),
            "half a workload key would group unrelated workloads together"
        );
    }

    /// A bare pod is recorded with no workload at all and never gains one.
    /// Refusing it would withhold the all-clear from its whole namespace
    /// for as long as its rows live; it is its own workload instead.
    #[test]
    fn attribution_makes_a_known_bare_pod_its_own_workload() {
        let pd = (Some("kube-system".to_string()), None, None);
        assert_eq!(
            attribute("kube-system", "kube-apiserver-node-a", Some(&pd)),
            (
                Some("Pod".to_string()),
                Some("kube-apiserver-node-a".to_string())
            )
        );
        assert_eq!(
            attribute("shop", "kube-apiserver-node-a", Some(&pd)),
            (None, None),
            "the namespace guard applies to bare pods too"
        );
    }

    #[test]
    fn attribution_tolerates_a_pod_row_with_no_namespace() {
        let pd = (
            None,
            Some("DaemonSet".to_string()),
            Some("node-exporter".to_string()),
        );
        assert_eq!(
            attribute("kube-system", "node-exporter-x", Some(&pd)),
            (
                Some("DaemonSet".to_string()),
                Some("node-exporter".to_string())
            ),
            "a missing namespace cannot disprove the match; throwing away \
             attribution the controller resolved is the worse failure"
        );
    }

    // ---- the denials block ---------------------------------------------

    fn key() -> WorkloadKey {
        (
            "media".to_string(),
            "Deployment".to_string(),
            "media-transform".to_string(),
        )
    }

    fn rollup_rows() -> Vec<DenialRollupRow> {
        vec![
            (
                "media".into(),
                "Deployment".into(),
                "media-transform".into(),
                "ptrace".into(),
                "SCMP_ACT_LOG".into(),
                17,
                ts("2026-09-14T04:05:14Z"),
            ),
            (
                "media".into(),
                "Deployment".into(),
                "media-transform".into(),
                "mount".into(),
                "SCMP_ACT_LOG".into(),
                3,
                ts("2026-09-14T03:00:00Z"),
            ),
        ]
    }

    #[test]
    fn denial_block_matches_the_runtime_contract() {
        let index = DenialIndex::with_rows(rollup_rows());
        let v = serde_json::to_value(index.block_for(&key()).unwrap()).unwrap();
        assert_eq!(v["total"], 20, "counts sum across the workload's rows");
        assert_eq!(
            v["syscalls"],
            serde_json::json!(["mount", "ptrace"]),
            "sorted, so the CR status does not churn on ordering"
        );
        assert_eq!(v["actions"], serde_json::json!(["SCMP_ACT_LOG"]));
        assert_eq!(
            v["lastSeen"], "2026-09-14T04:05:14Z",
            "the newest observation across the workload, not the last row read"
        );
    }

    /// The counterpart to `a_cr_without_names_emits_no_drift_rather_than_an_
    /// empty_one` in seccomp.rs, for the same reason.
    ///
    /// With no denial rows anywhere, "this workload was never denied" and
    /// "nothing on this cluster is capturing denials" are the same database
    /// state — capture needs CONFIG_AUDIT, can be disabled, and is skipped
    /// on a kernel without the probe target. A `total: 0` block would put an
    /// all-clear into a CR status for a workload nobody is watching, which
    /// is exactly the empty-block-reads-as-all-clear failure.
    #[test]
    fn no_denial_observations_emit_no_block_rather_than_an_empty_one() {
        let index = DenialIndex::empty();
        assert!(
            index.block_for(&key()).is_none(),
            "nothing observed anywhere means the answer is unknown, not zero"
        );
    }

    /// The other half of the same rule: once capture is known to be live,
    /// a workload with no rows really does have zero denials and its
    /// all-clear is real.
    #[test]
    fn a_quiet_workload_gets_a_real_zero_once_capture_is_proven() {
        let index = DenialIndex::with_rows(rollup_rows());
        let other = (
            "media".to_string(),
            "Deployment".to_string(),
            "thumbnailer".to_string(),
        );
        let block = index
            .block_for(&other)
            .expect("capture is proven, so zero is a real answer");
        assert_eq!(block.total, 0);
        assert!(block.syscalls.is_empty());
        assert!(block.actions.is_empty());
        assert!(
            block.last_seen.is_none(),
            "no denial means no lastSeen, not a zero timestamp"
        );
    }

    /// This list lands in a `SeccompProfile` CR's `.status`, so it is an
    /// etcd object. A profile applied to the wrong workload denies hundreds
    /// of syscalls, and that is exactly when the status must stay writable.
    #[test]
    fn the_syscall_list_is_capped() {
        let rows: Vec<_> = (0..MAX_DENIAL_SYSCALLS + 20)
            .map(|i| {
                (
                    "media".to_string(),
                    "Deployment".to_string(),
                    "media-transform".to_string(),
                    format!("syscall_{i:03}"),
                    "SCMP_ACT_LOG".to_string(),
                    1i64,
                    ts("2026-09-14T04:05:14Z"),
                )
            })
            .collect();
        let block = DenialIndex::with_rows(rows).block_for(&key()).unwrap();
        assert_eq!(block.syscalls.len(), MAX_DENIAL_SYSCALLS);
        assert_eq!(
            block.total,
            (MAX_DENIAL_SYSCALLS + 20) as i64,
            "the total counts every denial even though the names are capped"
        );
    }

    // ---- metrics counters ----------------------------------------------

    fn labels(ns: &str, kind: &str, workload: &str, action: &str) -> DenialLabels {
        DenialLabels {
            namespace: ns.into(),
            workload_kind: kind.into(),
            workload: workload.into(),
            action: action.into(),
        }
    }

    #[test]
    fn counters_sum_per_label_set_and_sort_loudest_first() {
        let m = SeccompDenialMetrics::default();
        m.record_batch(
            vec![
                (
                    labels("media", "Deployment", "media-transform", "SCMP_ACT_LOG"),
                    17,
                ),
                // Same label set, different syscall on the wire — folds
                // together, because the series is deliberately not labelled
                // by syscall.
                (
                    labels("media", "Deployment", "media-transform", "SCMP_ACT_LOG"),
                    3,
                ),
                (
                    labels("media", "Deployment", "media-transform", "SCMP_ACT_ERRNO"),
                    1,
                ),
                (
                    labels("payments", "StatefulSet", "ledger", "SCMP_ACT_LOG"),
                    2,
                ),
            ],
            4,
        );
        let series = m.series();
        assert_eq!(series.len(), 3, "one series per label set");
        assert_eq!(series[0].total, 20, "highest count first");
        assert_eq!(series[0].action, "SCMP_ACT_LOG");
        assert_eq!(m.rows_total(), 4);
        assert_eq!(m.overflow_series(), 0);
    }

    /// The regression guard for the bug this counter's design exists to
    /// avoid.
    ///
    /// `kguardian_seccomp_denials_total` must never decrease while the
    /// process lives. If it were derived from `SELECT sum(count)` over
    /// `seccomp_denials`, every retention pass would drop it — and
    /// Prometheus reads a counter decrease as a process restart, adding the
    /// post-reset value on top of the pre-reset one. That injects a phantom
    /// step into `rate()` and `increase()`, which is what the chart's denial
    /// alerts are written on, so a prune would page with a spike
    /// indistinguishable from the compromised workload the alert exists to
    /// catch.
    ///
    /// The counter lives in memory and retention cannot reach it. This test
    /// pins that by doing what retention does — removing every row — and
    /// asserting the exposed value is unchanged.
    #[test]
    fn the_counter_is_monotonic_across_a_retention_pass() {
        let m = SeccompDenialMetrics::default();
        let key = labels("media", "Deployment", "media-transform", "SCMP_ACT_LOG");
        m.record_batch(vec![(key.clone(), 17)], 1);
        m.record_batch(vec![(key.clone(), 5)], 1);
        let before = m.series();
        assert_eq!(before[0].total, 22);

        // Retention deletes rows. It holds no reference to this object and
        // has no method on it to call — which is the point. Simulate the
        // only thing that COULD follow a prune: more denials arriving for
        // the same series afterwards.
        m.record_batch(vec![(key.clone(), 1)], 1);

        let after = m.series();
        assert_eq!(
            after[0].total, 23,
            "the counter keeps climbing across a prune; it never restates \
             the table's current sum"
        );
        assert!(
            after[0].total >= before[0].total,
            "a counter that decreases is read by Prometheus as a reset"
        );
        assert_eq!(m.rows_total(), 3);
    }

    /// An unattributed denial must still be counted. Prometheus reads an
    /// empty label value as absent, so these fold into one per-namespace
    /// series rather than vanishing from the counter.
    #[test]
    fn counters_keep_unattributed_denials_with_empty_workload_labels() {
        let m = SeccompDenialMetrics::default();
        m.record_batch(vec![(labels("media", "", "", "SCMP_ACT_LOG"), 5)], 1);
        let series = m.series();
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].workload_kind, "");
        assert_eq!(series[0].workload, "");
        assert_eq!(series[0].total, 5);
        assert_eq!(
            m.workloads(),
            0,
            "the workload gauge is table-derived and set by the refresh \
             task; ingest never moves it"
        );
    }

    /// The cap is a memory bound, not only a Prometheus one: an
    /// unattributed denial's namespace comes straight off the wire, so the
    /// map needs a ceiling that does not depend on the caller behaving.
    #[test]
    fn counters_cap_series_and_never_evict_an_existing_one() {
        let m = SeccompDenialMetrics::default();
        let first = labels("ns-00000", "Deployment", "web", "SCMP_ACT_LOG");
        m.record_batch(
            (0..MAX_DENIAL_SERIES)
                .map(|i| {
                    (
                        labels(&format!("ns-{i:05}"), "Deployment", "web", "SCMP_ACT_LOG"),
                        1,
                    )
                })
                .collect(),
            MAX_DENIAL_SERIES,
        );
        assert_eq!(m.series().len(), MAX_DENIAL_SERIES);
        assert_eq!(m.overflow_series(), 0);

        // Five NEW label sets against a full map, plus another increment for
        // one already tracked.
        m.record_batch(
            (0..5)
                .map(|i| {
                    (
                        labels(&format!("new-{i}"), "Deployment", "web", "SCMP_ACT_LOG"),
                        9,
                    )
                })
                .chain(std::iter::once((first.clone(), 4)))
                .collect(),
            6,
        );
        assert_eq!(m.series().len(), MAX_DENIAL_SERIES, "the cap holds");
        assert_eq!(m.overflow_series(), 5, "and the refusals are counted");
        let kept = m
            .series()
            .into_iter()
            .find(|s| s.namespace == "ns-00000")
            .expect("an existing series is never evicted to make room");
        assert_eq!(
            kept.total, 5,
            "evicting it would restart it from zero on its next increment, \
             which is the non-monotonicity this design exists to avoid"
        );
        assert_eq!(
            m.rows_total(),
            (MAX_DENIAL_SERIES + 6) as u64,
            "rows_total counts every ingested row, so an operator can see \
             that denials arrived even when their series did not fit"
        );
    }

    // ---- query params --------------------------------------------------

    #[test]
    fn limit_clamps_like_the_other_list_endpoints() {
        assert_eq!(clamp_denial_limit(None), 100);
        assert_eq!(clamp_denial_limit(Some(42)), 42);
        assert_eq!(clamp_denial_limit(Some(0)), 1);
        assert_eq!(clamp_denial_limit(Some(-5)), 1);
        assert_eq!(clamp_denial_limit(Some(i64::MAX)), 500);
        assert_eq!(clamp_denial_limit(Some(i64::MIN)), 1);
    }

    #[test]
    fn since_requires_an_explicit_zone() {
        assert_eq!(parse_since(None).unwrap(), None);
        assert_eq!(parse_since(Some("  ")).unwrap(), None);
        assert_eq!(
            parse_since(Some("2026-09-14T04:05:14Z")).unwrap(),
            Some(ts("2026-09-14T04:05:14Z"))
        );
        // An offset is honoured rather than assumed to be UTC.
        assert_eq!(
            parse_since(Some("2026-09-14T06:05:14+02:00")).unwrap(),
            Some(ts("2026-09-14T04:05:14Z"))
        );
        // A zone-less instant is refused rather than silently read as UTC:
        // `last_seen` is a TIMESTAMPTZ produced on a node, so guessing the
        // caller's zone would hand them the wrong window with no error.
        assert!(parse_since(Some("2026-09-14 04:05:14")).is_err());
        assert!(parse_since(Some("yesterday")).is_err());
    }

    #[test]
    fn empty_filters_mean_no_filter() {
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(Some("  ".into())), None);
        assert_eq!(non_empty(Some(" media ".into())), Some("media".into()));
        assert_eq!(non_empty(None), None);
    }

    // ---- generated SQL -------------------------------------------------
    //
    // These assert on the SQL the PRODUCTION builders emit, never on SQL the
    // test declares. The previous versions of the two tests below built
    // their own statement inline and asserted diesel rendered what the test
    // had just supplied: they called nothing in this file, and an auditor
    // changed the upsert to `count = EXCLUDED.count` with the whole suite
    // still green. A test that cannot fail when production changes is not a
    // test. The live tests further down prove Postgres then DOES what the
    // fragments say; these prove the fragments are the ones being sent.

    #[test]
    fn the_query_orders_newest_first_with_a_deterministic_tie_break() {
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&denials_query_statement(
            None, None, None, None, 100,
        ))
        .to_string();
        assert!(
            sql.contains(
                r#"ORDER BY "seccomp_denials"."last_seen" DESC, "seccomp_denials"."id" DESC"#
            ),
            "a whole drain shares one last_seen; without the id tie-break the \
             visible top-N reshuffles on every identical request: {sql}"
        );
    }

    #[test]
    fn the_query_applies_every_filter_it_is_given() {
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&denials_query_statement(
            Some("media".into()),
            Some("Deployment".into()),
            Some("web".into()),
            Some(ts("2026-09-14T04:00:00Z")),
            7,
        ))
        .to_string();
        for column in [
            "pod_namespace",
            "workload_kind",
            "workload_name",
            "last_seen",
        ] {
            assert!(
                sql.contains(&format!(r#""seccomp_denials"."{column}" ="#))
                    || sql.contains(&format!(r#""seccomp_denials"."{column}" >="#)),
                "a filter the caller supplied must reach the WHERE clause, or \
                 the endpoint quietly returns another namespace's denials: {sql}"
            );
        }
        assert!(
            sql.contains("LIMIT $5"),
            "the clamped limit must bind: {sql}"
        );
    }

    /// The upsert is where every accumulation rule actually lives, and all
    /// of them are raw SQL fragments the type system cannot check. Pin the
    /// statement production builds so a refactor cannot quietly turn
    /// accumulation into replacement — which would look fine in every test
    /// that inserts one batch, and be wrong from the second drain onwards.
    #[test]
    fn the_upsert_accumulates_rather_than_replaces() {
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&denial_upsert(std::slice::from_ref(
            &new_denial(),
        )))
        .to_string();

        assert!(
            sql.contains(r#"ON CONFLICT ("pod_uid", "syscall", "action") DO UPDATE"#),
            "the accumulation key must be the table's unique constraint: {sql}"
        );
        assert!(
            sql.contains("seccomp_denials.count::NUMERIC + EXCLUDED.count"),
            "the controller ships a delta and clears its map; replacing the \
             count would make the Prometheus counter non-monotonic: {sql}"
        );
        assert!(
            sql.contains("LEAST(seccomp_denials.first_seen, EXCLUDED.first_seen)")
                && sql.contains("GREATEST(seccomp_denials.last_seen, EXCLUDED.last_seen)"),
            "the observation bracket must widen, never move: {sql}"
        );
        for column in [
            "workload_kind",
            "workload_name",
            "node_name",
            "arch",
            "syscall_nr",
            "action_raw",
        ] {
            assert!(
                sql.contains(&format!(
                    "COALESCE(EXCLUDED.{column}, seccomp_denials.{column})"
                )),
                "a later report that could not resolve {column} must not \
                 erase what an earlier one did: {sql}"
            );
        }
    }

    #[test]
    fn the_upsert_clamps_the_running_total_to_the_ingest_ceiling() {
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&denial_upsert(std::slice::from_ref(
            &new_denial(),
        )))
        .to_string();
        assert!(
            sql.contains(&format!(
                "LEAST(seccomp_denials.count::NUMERIC + EXCLUDED.count, {MAX_DENIAL_COUNT})::BIGINT"
            )),
            "the sum must be computed in NUMERIC and clamped before it is \
             cast back: BIGINT + BIGINT raises on overflow, and it raises \
             before an enclosing LEAST could clamp it — which 500s the POST, \
             and the Controller replays a failed POST forever: {sql}"
        );
    }

    /// `pod_uid` is the key and a pod's name and namespace are fixed for the
    /// life of that uid, so a conflicting report disagreeing about them is a
    /// lie or a bug either way. The rollup groups on `(pod_namespace,
    /// workload_kind, workload_name)`, so honouring a new namespace moves an
    /// existing row into a DIFFERENT workload's rollup.
    ///
    /// A `COALESCE` guard would not help: both columns are NOT NULL, so
    /// `COALESCE(EXCLUDED.x, ...)` can never reach the existing value. Not
    /// assigning them is the only guard that holds.
    #[test]
    fn the_upsert_never_moves_a_row_to_another_pods_identity() {
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&denial_upsert(std::slice::from_ref(
            &new_denial(),
        )))
        .to_string();
        let set_clause = sql
            .split("DO UPDATE SET")
            .nth(1)
            .expect("the statement is an upsert");
        for column in ["pod_name", "pod_namespace"] {
            assert!(
                !set_clause.contains(&format!(r#""{column}" ="#)),
                "{column} is immutable for a pod uid, and rewriting \
                 pod_namespace would move the row into another workload's \
                 rollup: {sql}"
            );
        }
    }

    // ---- rollup query shape --------------------------------------------

    #[test]
    fn the_rollup_name_read_is_bounded_on_both_axes() {
        for scoped in [false, true] {
            let sql = rollup_names_sql(scoped);
            assert!(
                sql.contains(&format!(
                    "WHERE rn <= {MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD}"
                )),
                "without the per-workload cap one workload denied on \
                 hundreds of syscalls crowds out every other: {sql}"
            );
            assert!(sql.contains("SELECT DISTINCT"), "{sql}");
            assert!(
                sql.contains("ORDER BY rn, pod_namespace COLLATE"),
                "the cluster-wide LIMIT must take every workload's first \
                 pair before any workload's second, or the workloads that \
                 sort last lose their whole name list while keeping a \
                 non-zero total: {sql}"
            );
            assert!(
                sql.contains("action COLLATE \"C\" LIMIT"),
                "and it must still be a TOTAL ordering, or the truncated set \
                 reshuffles between two identical polls: {sql}"
            );
        }
        assert!(
            rollup_names_sql(false).ends_with(&format!("LIMIT {MAX_DENIAL_ROLLUP_NAME_ROWS}")),
            "the cluster-wide read is the one that OOMKilled the Broker in \
             #1514, and it is what the permit reserves for"
        );
        assert!(
            rollup_names_sql(true)
                .ends_with(&format!("LIMIT {MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD}")),
            "one workload cannot need more than its own per-workload cap"
        );
    }

    /// SQL and Rust have to truncate in ONE order, and the doc comment used
    /// to assert they did while the SQL was ordering by the DATABASE's
    /// collation.
    ///
    /// [`DenialIndex::block_for`] keeps the first names out of a `BTreeSet`,
    /// which is UTF-8 byte order. The SQL decides which pairs ever reach it.
    /// Unqualified, glibc's `en_US.UTF-8` — RDS, Cloud SQL, the official
    /// non-alpine image — folds punctuation and case, so it disagrees with
    /// bytes on exactly the shape a syscall name has. `COLLATE "C"` is
    /// memcmp, so the two become one order on every database.
    #[test]
    fn the_rollup_names_are_ordered_the_way_rust_truncates_them() {
        for scoped in [false, true] {
            let sql = rollup_names_sql(scoped);
            assert!(
                sql.contains("ORDER BY syscall COLLATE \"C\", action COLLATE \"C\") AS rn"),
                "the RANKS decide which pairs survive the per-workload cap, \
                 so this is the ordering that has to match Rust's: {sql}"
            );
            assert!(
                !sql.contains("ORDER BY syscall, action"),
                "an unqualified ORDER BY is the database's collation, not \
                 byte order: {sql}"
            );
            assert!(
                sql.contains("syscall COLLATE \"C\", action COLLATE \"C\" LIMIT"),
                "the outer ordering decides which pairs survive the \
                 cluster-wide cap, so it needs the same treatment: {sql}"
            );
        }

        // The disagreement this defends against, spelled out: Rust sorts
        // these one way and glibc sorts them the other, and `io_uring_enter`
        // is a syscall the kernel really does deny. Under the database's
        // collation the rollup dropped it and offered `ioctl` in its place,
        // so an operator building an allow-list from `status.denials.syscalls`
        // allowed a syscall nothing had asked for and left the denied one
        // blocked.
        let mut rust_order = vec![
            "ioctl".to_string(),
            "io_uring_enter".to_string(),
            "sched_yield".to_string(),
            "schedctl".to_string(),
        ];
        rust_order.sort();
        assert_eq!(
            rust_order,
            vec!["io_uring_enter", "ioctl", "sched_yield", "schedctl"],
            "byte order puts `_` (0x5F) before any lowercase letter; glibc \
             ignores it at the primary level and orders on what follows"
        );
    }

    /// The totals are the half that must NOT be capped. Cap them and a
    /// truncated row takes its count with it — or takes the whole workload
    /// out of the index, at which point `block_for` answers `total: 0` for a
    /// workload that was denied. A bounded read that invents all-clears is
    /// worse than the unbounded one it replaced.
    /// The unattributed read must be able to say "there are more than I will
    /// list", because truncating it silently would hand the all-clear back to
    /// exactly the namespaces it ran out of room to warn about.
    #[test]
    fn the_unattributed_read_is_bounded_and_can_tell_it_was_bounded() {
        let sql = unattributed_namespaces_sql(false);
        assert!(
            sql.contains("workload_kind IS NULL OR workload_name IS NULL"),
            "either column missing means the rollup dropped the row: {sql}"
        );
        assert!(
            sql.contains(&format!("LIMIT {}", MAX_UNATTRIBUTED_NAMESPACES + 1)),
            "one row past the cap, so the caller can distinguish a full set \
             from a truncated one: {sql}"
        );
        let scoped = unattributed_namespaces_sql(true);
        assert!(
            scoped.contains("AND pod_namespace = $1") && scoped.contains("LIMIT 1"),
            "the detail endpoint asks about one namespace and one row settles \
             it: {scoped}"
        );
        assert!(
            UnattributedNamespaces::TooMany.withholds("anything"),
            "past the cap nothing may be reported clean"
        );
        let listed = UnattributedNamespaces::Listed(BTreeSet::from(["payments".to_string()]));
        assert!(listed.withholds("payments"));
        assert!(
            !listed.withholds("media"),
            "and the blast radius is the namespace the row was in, not the \
             cluster"
        );
    }

    #[test]
    fn the_rollup_total_read_is_not_capped_and_groups_only_by_workload() {
        for scoped in [false, true] {
            let sql = rollup_totals_sql(scoped);
            assert!(!sql.contains("LIMIT"), "totals must never truncate: {sql}");
            assert!(
                sql.ends_with("GROUP BY pod_namespace, workload_kind, workload_name"),
                "grouping by syscall or action here would make this read \
                 workloads x syscalls x actions again: {sql}"
            );
        }
        assert!(rollup_totals_sql(true).contains("pod_namespace = $1"));
        assert!(!rollup_totals_sql(false).contains('$'));
    }

    #[test]
    fn the_rollup_reservation_covers_what_the_rollup_can_read() {
        assert!(
            denial_index_charge_kib()
                >= cost_kib(
                    MAX_DENIAL_ROLLUP_NAME_ROWS,
                    DENIAL_ROLLUP_NAME_ROW_COST_BYTES
                ),
            "a reservation smaller than the LIMIT is a guardrail that fails \
             open on exactly the read it exists to bound"
        );
        assert!(
            denial_index_charge_kib() > denial_index_for_charge_kib(),
            "the cluster-wide read is the larger of the two"
        );
        // The pair cap is derived from the two caps `block_for` applies, so
        // widening either of those without widening the SQL cap would start
        // truncating lists the block would have shown.
        assert_eq!(
            MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD as usize,
            MAX_DENIAL_SYSCALLS * MAX_DENIAL_ACTIONS
        );
    }

    // ---- live database -------------------------------------------------
    //
    // Everything above is pure, which is where this module's logic mostly
    // lives — but not all of it. The accumulation rules are raw SQL
    // fragments inside the upsert (`count + EXCLUDED.count`, LEAST/GREATEST,
    // COALESCE), and `the_upsert_accumulates_rather_than_replaces` can only
    // prove those fragments are PRESENT, not that Postgres does what they
    // say. This test runs them.
    //
    // Ignored by default and gated on an explicit URL, following
    // `version_check`'s "requires network egress" precedent. Run with:
    //
    //   KG_TEST_DATABASE_URL=postgres://postgres:pw@localhost:5432/kg \
    //     cargo test --lib -- --ignored live_database
    //
    // It applies the REAL migrations — the same embedded set `main` runs —
    // rather than its own DDL, so the schema it exercises cannot drift from
    // the one shipped.

    /// A connection with the shipped schema applied and every table these
    /// tests touch emptied. Every live test starts from the same state; they
    /// share one database and must run with `--test-threads=1`.
    ///
    /// The whole embedded migration set runs, not just the denial ones.
    /// `pod_details` is part of what this feature reads — attribution
    /// resolves against it and the backfill repairs against it — so a test
    /// that hand-rolled a stand-in for it would be testing a table nothing
    /// ships. `run_pending_migrations` is a no-op after the first test.
    /// The same directory `main.rs` embeds and runs at startup. Declared
    /// again here because that one lives in the binary and this module is in
    /// the library, so the test cannot reach it — but it is the same path, so
    /// it cannot be a different schema.
    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel::connection::SimpleConnection;
        use diesel_migrations::MigrationHarness;

        let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
            panic!("set KG_TEST_DATABASE_URL to run this test");
        };
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("apply the shipped migrations");
        // TRUNCATE rather than drop-and-recreate: the migrations own the
        // schema now, so a test that dropped a table would leave diesel
        // believing it still existed.
        conn.batch_execute(
            "TRUNCATE seccomp_denials, seccomp_denial_nodes, pod_details RESTART IDENTITY",
        )
        .expect("reset the tables these tests use");
        conn
    }

    /// Register a pod the way the pod watcher does, for the columns
    /// attribution and its backfill read.
    fn seed_pod(
        conn: &mut PgConnection,
        pod_name: &str,
        namespace: &str,
        workload: Option<(&str, &str)>,
    ) {
        use schema::pod_details::dsl as pd;
        let (kind, name) = match workload {
            Some((k, n)) => (Some(k.to_string()), Some(n.to_string())),
            None => (None, None),
        };
        diesel::insert_into(pd::pod_details)
            .values((
                pd::pod_name.eq(pod_name),
                pd::pod_ip.eq("10.0.0.1"),
                pd::pod_namespace.eq(namespace),
                pd::time_stamp.eq(Utc::now().naive_utc()),
                pd::node_name.eq("n1"),
                pd::is_dead.eq(false),
                pd::workload_kind.eq(kind),
                pd::workload_name.eq(name),
            ))
            .on_conflict(pd::pod_name)
            .do_nothing()
            .execute(conn)
            .expect("seed pod_details");
    }

    /// Push one node's heartbeat `secs` into the past, the way a Controller
    /// that stopped reporting would.
    fn age_heartbeat(conn: &mut PgConnection, node: &str, secs: i64) {
        use diesel::connection::SimpleConnection;
        conn.batch_execute(&format!(
            "UPDATE seccomp_denial_nodes SET updated_at = NOW() - INTERVAL '{secs} seconds' \
             WHERE node_name = '{node}'"
        ))
        .expect("age the heartbeat");
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_accumulates_queries_and_prunes() {
        use diesel::connection::SimpleConnection;

        let mut conn = live_conn();

        // Capture liveness, before any denial exists. This is the state a
        // fresh install is in, and getting it wrong is what left every
        // workload at Unknown forever.
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "no node has reported and no denial exists: nothing is known to \
             be watching"
        );
        upsert_node_report(&mut conn, "n1", false, None).expect("degraded heartbeat");
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "a node reporting in with the probe NOT attached (CONFIG_AUDIT=n) \
             is alive and watching nothing; treating that as capture is how \
             graceful degradation becomes a false all-clear"
        );
        upsert_node_report(&mut conn, "n2", true, None).expect("capturing heartbeat");
        assert!(
            capture_is_live(&mut conn).expect("liveness"),
            "one fresh capturing node proves the path works end to end, with \
             no denial required"
        );
        // Age both heartbeats past the staleness window: nothing is
        // reporting any more, so the answer goes back to "not known".
        conn.batch_execute(&format!(
            "UPDATE seccomp_denial_nodes SET updated_at = NOW() - INTERVAL '{} seconds'",
            CAPTURE_REPORT_STALE_FLOOR_SECS + 60
        ))
        .expect("age heartbeats");
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "a stale heartbeat is not evidence; a node whose Controller died \
             stops reporting rather than reporting false"
        );

        let base = new_denial();
        upsert_denials(&mut conn, std::slice::from_ref(&base)).expect("first drain");

        // Second drain for the same key: a smaller count, an EARLIER
        // first_seen, a LATER last_seen, and attribution the broker could no
        // longer resolve.
        let second = NewDenial {
            workload_kind: None,
            workload_name: None,
            arch: None,
            syscall_nr: None,
            action_raw: None,
            count: 5,
            first_seen: ts("2026-09-14T03:00:00Z"),
            last_seen: ts("2026-09-14T05:00:00Z"),
            ..base.clone()
        };
        upsert_denials(&mut conn, &[second]).expect("second drain");

        let rows = denials_query(&mut conn, None, None, None, None, 100).expect("query");
        assert_eq!(rows.len(), 1, "the unique constraint collapses both drains");
        let r = &rows[0];
        assert_eq!(r.count, 22, "counts accumulate across drains");
        assert_eq!(r.first_seen, ts("2026-09-14T03:00:00Z"));
        assert_eq!(r.last_seen, ts("2026-09-14T05:00:00Z"));
        assert_eq!(
            r.workload_kind.as_deref(),
            Some("Deployment"),
            "a later drain that could not resolve attribution must not erase it"
        );
        assert_eq!(r.arch.as_deref(), Some("SCMP_ARCH_X86_64"));
        assert_eq!(r.syscall_nr, Some(101));
        assert_eq!(
            r.action_raw,
            Some(2_147_483_648),
            "SECCOMP_RET values above i32::MAX must survive the round trip"
        );

        // Filters.
        assert_eq!(
            denials_query(
                &mut conn,
                Some("media".into()),
                Some("Deployment".into()),
                Some("web".into()),
                None,
                100
            )
            .unwrap()
            .len(),
            1
        );
        assert!(
            denials_query(&mut conn, Some("other".into()), None, None, None, 100)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            denials_query(
                &mut conn,
                None,
                None,
                None,
                Some(ts("2026-09-14T04:00:00Z")),
                100
            )
            .unwrap()
            .len(),
            1,
            "`since` matches on last_seen, which is inside the window"
        );
        assert!(denials_query(
            &mut conn,
            None,
            None,
            None,
            Some(ts("2026-09-14T06:00:00Z")),
            100
        )
        .unwrap()
        .is_empty());

        // Rollup. Needs a live capturing node, not just a stored row: the
        // heartbeats above are still stale, and a stale fleet with old rows
        // is the state that used to produce a false all-clear.
        let key: WorkloadKey = ("media".into(), "Deployment".into(), "web".into());
        assert!(
            denial_index_for(&mut conn, &key)
                .unwrap()
                .block_for(&key)
                .is_none(),
            "rows exist but every node stopped reporting, so nothing is \
             known to be watching NOW and no block can honestly be emitted"
        );
        upsert_node_report(&mut conn, "n2", true, None).expect("capturing heartbeat");
        let block = denial_index_for(&mut conn, &key)
            .unwrap()
            .block_for(&key)
            .expect("a fresh capturing node proves capture");
        assert_eq!(block.total, 22);
        assert_eq!(block.syscalls, vec!["ptrace".to_string()]);
        assert_eq!(block.last_seen, Some(ts("2026-09-14T05:00:00Z")));

        // The one metric that genuinely queries the table.
        assert_eq!(
            workload_count_from(&mut conn).expect("workload count"),
            1,
            "one distinct attributed workload holds denials"
        );

        // Retention, running the exact statement the prune loop issues.
        //
        // The age is set relative to the SERVER's NOW() rather than to the
        // fixed literals above, because the prune compares against NOW() and
        // a test pinned to wall-clock dates would start passing or failing
        // on the calendar rather than on the code. Ageing the row 60 days
        // makes both directions of the window unambiguous.
        conn.batch_execute("UPDATE seccomp_denials SET last_seen = NOW() - INTERVAL '60 days'")
            .expect("age the row");
        let pruned = diesel::sql_query(crate::retention::SECCOMP_DENIAL_PRUNE_SQL)
            .bind::<diesel::sql_types::Text, _>("90 days")
            .bind::<diesel::sql_types::BigInt, _>(5000)
            .execute(&mut conn)
            .expect("wide-window prune");
        assert_eq!(pruned, 0, "a window wider than the row's age keeps it");
        let pruned = diesel::sql_query(crate::retention::SECCOMP_DENIAL_PRUNE_SQL)
            .bind::<diesel::sql_types::Text, _>("30 days")
            .bind::<diesel::sql_types::BigInt, _>(5000)
            .execute(&mut conn)
            .expect("narrow-window prune");
        assert_eq!(pruned, 1, "and a narrower one removes it");

        // With the table empty again and every heartbeat stale, the block
        // goes back to absent rather than reporting a zero.
        conn.batch_execute(&format!(
            "UPDATE seccomp_denial_nodes SET updated_at = NOW() - INTERVAL '{} seconds'",
            CAPTURE_REPORT_STALE_FLOOR_SECS + 60
        ))
        .expect("age heartbeats");
        assert!(
            denial_index_for(&mut conn, &key)
                .unwrap()
                .block_for(&key)
                .is_none(),
            "nothing stored and nothing reporting means unknown again"
        );

        // But a live capturing node is enough on its own: with the table
        // empty, a fresh heartbeat turns that same Unknown into a real
        // all-clear. This is the bootstrap case — a new install where
        // nothing has ever been denied — and it is the whole reason the
        // heartbeat exists.
        upsert_node_report(&mut conn, "n2", true, None).expect("fresh heartbeat");
        let block = denial_index_for(&mut conn, &key)
            .unwrap()
            .block_for(&key)
            .expect("a capturing node makes zero a real answer");
        assert_eq!(block.total, 0);
        assert!(block.last_seen.is_none());
    }

    /// The Critical one. `count` arrives off the wire, lands in a `BIGINT`,
    /// and the upsert adds to it. Postgres RAISES on bigint overflow rather
    /// than saturating, every chunk of a drain shares one transaction, and
    /// the Controller clears its BPF map only on a successful POST — so one
    /// row carrying a count near `i64::MAX` makes that node's ingest 500 on
    /// the same replayed batch forever. The heartbeat commits earlier, in
    /// its own transaction, and keeps succeeding, so the cluster reads
    /// healthy the whole time.
    ///
    /// This runs the handler's own sequence: heartbeat first, then the one
    /// transaction the chunks share. It does not go through actix, so it
    /// does not cover the `map_err(ErrorInternalServerError)` that turns the
    /// `Err` below into the 500 — that line is the only gap.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_bounds_the_count_so_one_report_cannot_kill_ingest() {
        use diesel::connection::SimpleConnection;

        let mut conn = live_conn();

        // A node that has been capturing for a while, with a real row.
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");
        upsert_denials(&mut conn, std::slice::from_ref(&new_denial())).expect("first drain");

        // The hostile (or broken) report. It never becomes a row, because
        // ingest refuses the count before the insert is built.
        let FoldedBatch { rows, rejected, .. } = fold_batch(
            vec![DenialInput {
                count: i64::MAX,
                ..input("web-1", "ptrace", "SCMP_ACT_LOG", 1)
            }],
            Utc::now(),
        );
        assert_eq!(rejected.get("count"), Some(&1));
        assert!(
            rows.is_empty(),
            "nothing reaches the transaction, so the drain that carried it \
             still commits and the Controller still clears its map"
        );

        // And if such a value were already stored — this branch is what the
        // ceiling cannot reach back in time to prevent — the next drain must
        // still commit rather than raise forever.
        conn.batch_execute("UPDATE seccomp_denials SET count = 9223372036854775807")
            .expect("plant a pre-ceiling value");
        let heartbeat = upsert_node_report(&mut conn, "n1", true, None);
        let drain = conn.transaction::<_, DbError, _>(|conn| {
            upsert_denials(conn, std::slice::from_ref(&new_denial()))
        });
        assert!(
            heartbeat.is_ok(),
            "the heartbeat commits in its own earlier transaction — which is \
             why a dead ingest still reads as a healthy cluster"
        );
        assert!(
            drain.is_ok(),
            "the accumulation must clamp instead of raising; a raise here is \
             a 500, and the Controller replays a 500 every interval forever, \
             losing every denial from the node: {drain:?}"
        );

        let stored = denials_query(&mut conn, None, None, None, None, 100).expect("query");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].count, MAX_DENIAL_COUNT,
            "clamped to the ceiling rather than raising"
        );

        // Normal accumulation is untouched by the clamp.
        conn.batch_execute("UPDATE seccomp_denials SET count = 17")
            .expect("reset");
        upsert_denials(&mut conn, std::slice::from_ref(&new_denial())).expect("second drain");
        assert_eq!(
            denials_query(&mut conn, None, None, None, None, 100).unwrap()[0].count,
            34,
            "a count nowhere near the ceiling still accumulates exactly"
        );
    }

    /// A pod uid's name and namespace are fixed for the life of that uid, so
    /// a conflicting report disagreeing about them is a lie or a bug. The
    /// rollup groups on `(pod_namespace, workload_kind, workload_name)`, so
    /// honouring a new namespace moves the row into a DIFFERENT workload's
    /// rollup — counts appearing under a namespace that never made the
    /// syscall, and vanishing from the one that did.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_keeps_a_denial_in_its_own_workloads_rollup() {
        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");

        let base = new_denial();
        upsert_denials(&mut conn, std::slice::from_ref(&base)).expect("first drain");

        // Same storage key, a different claimed identity.
        let moved = NewDenial {
            pod_name: "attacker-1".into(),
            pod_namespace: "attacker".into(),
            workload_kind: Some("Deployment".into()),
            workload_name: Some("web".into()),
            ..base.clone()
        };
        upsert_denials(&mut conn, &[moved]).expect("second drain");

        let stored = denials_query(&mut conn, None, None, None, None, 100).expect("query");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].pod_namespace, "media");
        assert_eq!(stored[0].pod_name, "web-1");

        let key: WorkloadKey = ("media".into(), "Deployment".into(), "web".into());
        let elsewhere: WorkloadKey = ("attacker".into(), "Deployment".into(), "web".into());
        let index = denial_index(&mut conn).unwrap();
        assert_eq!(
            index.block_for(&key).expect("still its own workload").total,
            34
        );
        assert_eq!(
            index
                .block_for(&elsewhere)
                .expect("capture is live, so this workload gets a real zero")
                .total,
            0,
            "the row must not appear under a namespace that never made the \
             syscall"
        );
    }

    /// `GET /seccomp/profiles` is the endpoint that OOMKilled the Broker in
    /// #1514 and the UI polls it every 15 s. The rollup behind its `denials`
    /// block is per `(workload, syscall, action)`, so it must be bounded in
    /// SQL — but the TOTALS must not be, because a truncated total is a
    /// silent undercount and a truncated workload becomes a `total: 0`
    /// all-clear.
    /// The noisy workload's syscall names, chosen so the DATABASE's collation
    /// and Rust's byte order disagree ACROSS the per-workload cap.
    ///
    /// This test used to seed `syscall_00001`-style zero-padded names, which
    /// sort identically under every collation — so it could not fail whatever
    /// the SQL ordered by, and CI's Postgres is alpine, where musl makes
    /// `en_US.UTF-8` byte order anyway. These names discriminate:
    ///
    /// - glibc ignores `_` at the primary level, so `sched_yield` sorts after
    ///   every `schedctl_NNN` there and before all of them in bytes. That is
    ///   the same shape as the `io_uring_enter` / `ioctl` pair an auditor
    ///   reproduced, stretched across the whole filler run so it crosses the
    ///   cap rather than swapping two adjacent names.
    /// - glibc folds case, so `Zsync_file_range` sorts last there and FIRST
    ///   in bytes, where `Z` (0x5A) precedes every lowercase letter.
    ///
    /// Both are inside the block's visible 50 names under byte order and past
    /// the 800-pair cap under glibc, so ranking by the database's collation
    /// drops them and offers two `schedctl_NNN` the kernel never denied in
    /// their place.
    fn discriminating_syscalls() -> Vec<String> {
        let filler = (MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD + 200) as usize - 4;
        let mut names: Vec<String> = (0..filler).map(|i| format!("schedctl_{i:03}")).collect();
        names.push("sched_yield".into());
        names.push("io_uring_enter".into());
        names.push("ioctl".into());
        names.push("Zsync_file_range".into());
        names
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_caps_the_rollup_lists_without_capping_the_totals() {
        use diesel::connection::SimpleConnection;

        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");

        // One workload far past both caps: more distinct pairs than
        // `MAX_DENIAL_ROLLUP_PAIRS_PER_WORKLOAD`, every pair repeated on
        // three pods so the DISTINCT has something to collapse and the
        // per-pod multiplication is exercised.
        const PODS: i64 = 3;
        const PER_ROW: i64 = 3;
        let names = discriminating_syscalls();
        let pairs = names.len() as i64;
        let mut values = Vec::with_capacity(names.len() * PODS as usize);
        for name in &names {
            for pod in 0..PODS {
                values.push(format!(
                    "('uid-{pod}', 'noisy-{pod}', 'media', 'Deployment', 'noisy', 'n1', \
                     '{name}', NULL, 'SCMP_ACT_LOG', NULL, NULL, {PER_ROW}, NOW(), NOW())"
                ));
            }
        }
        conn.batch_execute(&format!(
            "INSERT INTO seccomp_denials (pod_uid, pod_name, pod_namespace, workload_kind, \
             workload_name, node_name, syscall, syscall_nr, action, action_raw, arch, count, \
             first_seen, last_seen) VALUES {}",
            values.join(", ")
        ))
        .expect("seed the noisy workload");
        // A second workload that must still be visible: the per-workload cap
        // is what stops the noisy one from consuming the whole read.
        conn.batch_execute(
            "INSERT INTO seccomp_denials (pod_uid, pod_name, pod_namespace, workload_kind, \
             workload_name, node_name, syscall, syscall_nr, action, action_raw, arch, count, \
             first_seen, last_seen) VALUES \
             ('uid-q', 'quiet-1', 'media', 'Deployment', 'quiet', 'n1', 'ptrace', NULL, \
             'SCMP_ACT_ERRNO', NULL, NULL, 9, NOW(), NOW())",
        )
        .expect("seed the quiet workload");

        let index = denial_index(&mut conn).expect("rollup");
        let noisy: WorkloadKey = ("media".into(), "Deployment".into(), "noisy".into());
        let quiet: WorkloadKey = ("media".into(), "Deployment".into(), "quiet".into());

        // What the block must show: the first names in RUST's order, because
        // that is the order `block_for` truncates in. Anything else means the
        // SQL kept a different 800 pairs than the `BTreeSet` would have, and
        // the difference is a syscall the kernel denied going missing from
        // the list an operator builds an allow-list out of.
        let mut expected = names.clone();
        expected.sort();
        expected.truncate(MAX_DENIAL_SYSCALLS);

        let noisy_block = index.block_for(&noisy).expect("denied, so a block");
        assert_eq!(
            noisy_block.total,
            pairs * PODS * PER_ROW,
            "the total is summed in SQL over EVERY row, capped or not — an \
             undercount here is the number an operator promotes a profile to \
             enforcing on"
        );
        assert_eq!(
            noisy_block.syscalls.len(),
            MAX_DENIAL_SYSCALLS,
            "the visible list is capped, and the SQL cap sits above the Rust \
             one so it never shortens a block the Rust cap would have filled"
        );
        assert_eq!(
            noisy_block.syscalls, expected,
            "SQL and Rust must truncate in ONE order. Ranked by the \
             database's collation, a glibc Postgres drops `sched_yield` and \
             `Zsync_file_range` past the cap and substitutes names the \
             kernel never denied"
        );

        let quiet_block = index.block_for(&quiet).expect("denied, so a block");
        assert_eq!(quiet_block.total, 9);
        assert_eq!(
            quiet_block.syscalls,
            vec!["ptrace".to_string()],
            "a loud workload must not crowd a quiet one out of the read"
        );

        // The scoped read answers the same way, down to the same names.
        let scoped = denial_index_for(&mut conn, &noisy).expect("scoped rollup");
        assert_eq!(
            scoped.block_for(&noisy).unwrap().total,
            pairs * PODS * PER_ROW
        );
        assert_eq!(scoped.block_for(&noisy).unwrap().syscalls, expected);
    }

    /// The cluster-wide ceiling must shorten every workload's list, never
    /// erase one.
    ///
    /// Ordered by workload before the LIMIT, the workloads that sorted last
    /// got their correct `total` and an EMPTY `syscalls` list — which the
    /// distributor renders as "280 seccomp denial(s) on 0 syscall(s): ",
    /// because a non-zero total misses its zero branch. Worse, which
    /// workloads fell past the cap depended on other namespaces' pair counts,
    /// so a workload at the boundary flipped between a populated list and an
    /// empty one and made every node rewrite the CR on every flip.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_gives_every_workload_a_share_of_the_name_ceiling() {
        use diesel::connection::SimpleConnection;

        const WORKLOADS: i64 = 300;
        const PAIRS: i64 = 40;
        const PER_ROW: i64 = 7;
        // The seed has to exceed the cluster-wide ceiling or this test
        // proves nothing, and no workload may be capped by the Rust side, so
        // that a short list can only have come from the SQL.
        const { assert!(WORKLOADS * PAIRS > MAX_DENIAL_ROLLUP_NAME_ROWS) };
        const { assert!(PAIRS < MAX_DENIAL_SYSCALLS as i64) };

        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");
        conn.batch_execute(&format!(
            "INSERT INTO seccomp_denials (pod_uid, pod_name, pod_namespace, workload_kind, \
             workload_name, node_name, syscall, syscall_nr, action, action_raw, arch, count, \
             first_seen, last_seen) \
             SELECT 'uid-' || w || '-' || s, 'pod-' || w, 'ns-' || LPAD(w::TEXT, 3, '0'), \
             'Deployment', 'app', 'n1', 'syscall_' || LPAD(s::TEXT, 3, '0'), NULL, \
             'SCMP_ACT_LOG', NULL, NULL, {PER_ROW}, NOW(), NOW() \
             FROM generate_series(1, {WORKLOADS}) AS w, generate_series(1, {PAIRS}) AS s"
        ))
        .expect("seed a cluster past the ceiling");

        let index = denial_index(&mut conn).expect("rollup");
        let mut blank: Vec<String> = Vec::new();
        let mut shortest = usize::MAX;
        for w in 1..=WORKLOADS {
            let key: WorkloadKey = (format!("ns-{w:03}"), "Deployment".into(), "app".into());
            let block = index.block_for(&key).expect("denied, so a block");
            assert_eq!(
                block.total,
                PAIRS * PER_ROW,
                "totals are read on their own uncapped axis: {}",
                key.0
            );
            if block.syscalls.is_empty() {
                blank.push(key.0.clone());
            }
            shortest = shortest.min(block.syscalls.len());
        }
        assert!(
            blank.is_empty(),
            "{} of {WORKLOADS} workloads were denied and got an empty syscall \
             list, which reads as \"N denials on 0 syscalls\": {:?}",
            blank.len(),
            &blank[..blank.len().min(5)]
        );
        assert!(
            shortest < PAIRS as usize,
            "the ceiling has to actually bite here, or the seed is too small \
             to prove anything: shortest list was {shortest}"
        );
    }

    /// A stored denial is evidence that capture WORKED, never that anything
    /// is watching now — and the difference is a false all-clear.
    ///
    /// The row-existence fallback this replaces was there for a Controller
    /// too old to send heartbeats. No such Controller exists: both denial
    /// migrations landed in one commit and the feature has never shipped.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_never_reads_liveness_off_a_stored_denial() {
        let mut conn = live_conn();
        // A denial from a capture path that has since been switched off: the
        // DaemonSet scaled to zero, the feature disabled, the nodes rebuilt
        // with CONFIG_AUDIT=n. Or a database restored into a cluster that
        // never enabled capture at all — same state, same wrong answer.
        upsert_denials(&mut conn, std::slice::from_ref(&new_denial())).expect("an old denial");

        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "a row is not a heartbeat; nothing here has reported in, so \
             nothing is known to be watching"
        );
        let key: WorkloadKey = ("media".into(), "Deployment".into(), "web".into());
        let other: WorkloadKey = ("media".into(), "Deployment".into(), "quiet".into());
        assert!(
            denial_index(&mut conn).unwrap().block_for(&other).is_none(),
            "and no other workload may be handed a `total: 0` computed off \
             that row's existence"
        );

        // A node reporting in with the probe NOT attached does not rescue it.
        upsert_node_report(&mut conn, "n1", false, None).expect("degraded heartbeat");
        assert!(!capture_is_live(&mut conn).expect("liveness"));

        // Only a node that is actually capturing does.
        upsert_node_report(&mut conn, "n1", true, None).expect("capturing heartbeat");
        assert!(capture_is_live(&mut conn).expect("liveness"));
        assert_eq!(
            denial_index(&mut conn)
                .unwrap()
                .block_for(&key)
                .expect("capture is live")
                .total,
            17
        );
    }

    /// Staleness is measured against the cadence each node declares.
    ///
    /// The window was a hard-coded 300 s while the Controller's drain
    /// interval is an operator-set Helm value with no upper bound, so any
    /// configured interval above 100 s — a supported value — left every node
    /// looking stale between its own reports and pinned a perfectly healthy
    /// cluster at Unknown forever.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_measures_staleness_against_each_nodes_declared_cadence() {
        let mut conn = live_conn();

        // A node draining every 10 minutes.
        const SLOW: i64 = 600;
        upsert_node_report(&mut conn, "slow", true, Some(SLOW)).expect("heartbeat");
        age_heartbeat(&mut conn, "slow", 900);
        assert!(
            capture_is_live(&mut conn).expect("liveness"),
            "900 s is past the 300 s floor and well inside this node's own \
             3 x 600 s window; calling it stale is how a supported Helm value \
             turns a capturing fleet into Unknown"
        );
        age_heartbeat(
            &mut conn,
            "slow",
            SLOW * CAPTURE_REPORT_STALE_INTERVALS + 600,
        );
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "and past three of its own intervals it is stale like any other"
        );

        // A node that declares nothing gets the floor, not the slow node's
        // window.
        upsert_node_report(&mut conn, "quiet", true, None).expect("heartbeat");
        age_heartbeat(&mut conn, "quiet", 30);
        assert!(capture_is_live(&mut conn).expect("liveness"));
        age_heartbeat(&mut conn, "quiet", CAPTURE_REPORT_STALE_FLOOR_SECS + 600);
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "the fallback is the floor, not forever"
        );

        // And a cadence below the floor cannot NARROW the window: three 10 s
        // intervals is 30 s, which would flip the cluster to Unknown on one
        // slow reconcile.
        upsert_node_report(&mut conn, "fast", true, Some(10)).expect("heartbeat");
        age_heartbeat(&mut conn, "fast", 200);
        assert!(
            capture_is_live(&mut conn).expect("liveness"),
            "max(floor, interval x 3) — the floor wins for a fast node"
        );
    }

    /// One heartbeat must not buy days of cluster-wide all-clear.
    ///
    /// The window is `max(floor, declared x 3)`, and the declared cadence had
    /// no ceiling worth the name: clamped at a day, three days of window. Two
    /// ways to reach it. Routine — the chart recommends raising
    /// `intervalSeconds` on large clusters, and when the last capturing node
    /// goes away (spot reclaim, autoscaler, a `CONFIG_AUDIT=n` rebuild) every
    /// workload reads `total: 0` for the rest of the window. Adversarial —
    /// `BROKER_AUTH_TOKEN` is optional and `node` is checked against no known
    /// node, so one POST of a fabricated node pins the whole cluster.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_caps_how_long_one_heartbeat_buys_an_all_clear() {
        use diesel::connection::SimpleConnection;

        let mut conn = live_conn();

        // The handler's own sequence, so the clamp under test is the one
        // ingest applies rather than one the test performs.
        let report = DenialBatch {
            node: "ghost".into(),
            capturing: Some(true),
            interval_seconds: Some(86_400),
            denials: vec![],
        }
        .validate(Utc::now());
        assert!(
            report.interval_clamped,
            "the report declared a day; ingest has to notice it cut it down, \
             because the node will now read stale between its own reports"
        );
        upsert_node_report(
            &mut conn,
            "ghost",
            report.capturing,
            report.interval_seconds,
        )
        .expect("heartbeat");

        // Inside the ceiling the heartbeat still counts: the bound is a
        // ceiling on trust, not a refusal to trust.
        age_heartbeat(&mut conn, "ghost", CAPTURE_REPORT_STALE_CEILING_SECS - 60);
        assert!(
            capture_is_live(&mut conn).expect("liveness"),
            "a node inside the window is still watching"
        );

        age_heartbeat(&mut conn, "ghost", CAPTURE_REPORT_STALE_CEILING_SECS + 60);
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "past the ceiling one report is not evidence any more. Unbounded, \
             this row bought {} seconds — three days in which every workload \
             on the cluster reads a clean bill of health with nothing watching",
            86_400 * CAPTURE_REPORT_STALE_INTERVALS
        );
        let key: WorkloadKey = ("media".into(), "Deployment".into(), "web".into());
        assert!(
            denial_index(&mut conn).unwrap().block_for(&key).is_none(),
            "and no workload may be handed a block off it"
        );

        // A row stored under the wider bound this replaced — an upgrade that
        // ran the new binary against rows the old one wrote — must not
        // outlive the ceiling either. The CHECK now refuses such a value, so
        // reproducing it means standing the old constraint back up.
        //
        // Inside a transaction that is always rolled back, because Postgres
        // makes DDL transactional: the constraint comes back whether this
        // block passes, fails an assertion, or panics — a failing test must
        // not leave the next one running against a schema it did not ask
        // for. (On a panic the rollback is the server's, when the connection
        // closes.)
        let rolled_back = conn.transaction::<(), diesel::result::Error, _>(|conn| {
            conn.batch_execute(
                "ALTER TABLE seccomp_denial_nodes \
                 DROP CONSTRAINT seccomp_denial_nodes_interval_seconds_check; \
                 UPDATE seccomp_denial_nodes SET interval_seconds = 86400 \
                 WHERE node_name = 'ghost'",
            )?;
            assert!(
                !capture_is_live(conn).expect("liveness"),
                "the window is clamped where it is computed, so a legacy \
                 value buys nothing the ceiling does not grant"
            );
            Err(diesel::result::Error::RollbackTransaction)
        });
        assert!(matches!(
            rolled_back,
            Err(diesel::result::Error::RollbackTransaction)
        ));
    }

    /// A denial nobody could attribute must not become an all-clear for the
    /// workload it belonged to.
    ///
    /// `pod_details`' primary key is `pod_name` ALONE, so `payments/redis-0`
    /// and `media/redis-0` collapse to one row. Attribution refuses on the
    /// namespace mismatch — correctly, since naming the other team's workload
    /// would be worse — but the rollup filters unattributed rows out and
    /// `block_for` answers a workload with no rows with `total: 0`. Thousands
    /// of `SCMP_ACT_ERRNO` denials then read as a clean bill of health for
    /// the workload that made them.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_withholds_the_all_clear_from_an_unattributable_namespace() {
        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");

        // Only one `redis-0` row can exist, and it is media's.
        seed_pod(
            &mut conn,
            "redis-0",
            "media",
            Some(("StatefulSet", "redis")),
        );
        seed_pod(&mut conn, "web-1", "shop", Some(("Deployment", "web")));

        let rows = vec![
            DenialInput {
                pod_uid: "uid-payments".into(),
                pod_namespace: "payments".into(),
                count: 4_200,
                ..input("redis-0", "ptrace", "SCMP_ACT_ERRNO", 4_200)
            },
            DenialInput {
                pod_uid: "uid-shop".into(),
                pod_namespace: "shop".into(),
                ..input("web-1", "ptrace", "SCMP_ACT_LOG", 3)
            },
        ];
        let names: BTreeSet<String> = rows.iter().map(|d| d.pod_name.clone()).collect();
        let (unattributed, _) = store_batch(&mut conn, "n1", &names, rows).expect("ingest");
        assert_eq!(
            unattributed, 1,
            "the payments row names a pod whose only pod_details row is \
             another namespace's"
        );

        let index = denial_index(&mut conn).expect("rollup");
        let payments: WorkloadKey = ("payments".into(), "StatefulSet".into(), "redis".into());
        assert!(
            index.block_for(&payments).is_none(),
            "4 200 denials the broker could not attribute must not read as \
             `total: 0` for the workload that made them — `observed: 0` has \
             to mean \"we checked and found none\", never \"we could not tell\""
        );

        // And the withholding is namespace-scoped, not a cluster-wide
        // blackout: a namespace whose denials all resolved still reports.
        let shop: WorkloadKey = ("shop".into(), "Deployment".into(), "web".into());
        assert_eq!(
            index
                .block_for(&shop)
                .expect("attributed, so a block")
                .total,
            3
        );
        // Including a quiet workload in that namespace, which is the real
        // all-clear this feature exists to be able to give.
        let quiet: WorkloadKey = ("shop".into(), "Deployment".into(), "quiet".into());
        assert_eq!(index.block_for(&quiet).expect("a real zero").total, 0);

        // The detail endpoint answers the same way, on its own narrowed read.
        assert!(denial_index_for(&mut conn, &payments)
            .expect("scoped rollup")
            .block_for(&payments)
            .is_none());
        assert_eq!(
            denial_index_for(&mut conn, &shop)
                .expect("scoped rollup")
                .block_for(&shop)
                .expect("attributed, so a block")
                .total,
            3
        );
    }

    /// A pod that trips a syscall before its `pod_details` row lands is
    /// unattributed forever, because the ingest upsert only re-resolves a row
    /// when the same `(syscall, action)` is reported again — and a one-shot
    /// startup denial is exactly that shape. The backfill is what makes that
    /// state transient rather than a 30-day reporting outage for the
    /// namespace.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_backfills_attribution_once_the_pod_is_known() {
        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");

        // The race: the denial arrives first. And the collision, which the
        // backfill must NOT resolve.
        seed_pod(
            &mut conn,
            "redis-0",
            "media",
            Some(("StatefulSet", "redis")),
        );
        let rows = vec![
            DenialInput {
                pod_uid: "uid-race".into(),
                pod_namespace: "shop".into(),
                ..input("web-7", "ptrace", "SCMP_ACT_LOG", 11)
            },
            DenialInput {
                pod_uid: "uid-collision".into(),
                pod_namespace: "payments".into(),
                ..input("redis-0", "ptrace", "SCMP_ACT_ERRNO", 9)
            },
            // A bare pod that races the watcher the same way.
            DenialInput {
                pod_uid: "uid-bare".into(),
                pod_namespace: "shop".into(),
                ..input("debug-1", "mount", "SCMP_ACT_LOG", 3)
            },
        ];
        let names: BTreeSet<String> = rows.iter().map(|d| d.pod_name.clone()).collect();
        store_batch(&mut conn, "n1", &names, rows).expect("ingest");

        let web: WorkloadKey = ("shop".into(), "Deployment".into(), "web".into());
        let payments: WorkloadKey = ("payments".into(), "StatefulSet".into(), "redis".into());
        let index = denial_index(&mut conn).expect("rollup");
        assert!(
            index.block_for(&web).is_none(),
            "withheld before the pod is known"
        );
        assert!(index.block_for(&payments).is_none());

        // The pod watcher catches up: one owned pod, one with no owner.
        seed_pod(&mut conn, "web-7", "shop", Some(("Deployment", "web")));
        seed_pod(&mut conn, "debug-1", "shop", None);
        let resolved = diesel::sql_query(crate::retention::BACKFILL_DENIAL_ATTRIBUTION_SQL)
            .bind::<BigInt, _>(5_000)
            .execute(&mut conn)
            .expect("backfill");
        assert_eq!(
            resolved, 2,
            "the race resolves (the owned pod to its Deployment, the bare pod \
             to itself) and the collision does not: a backfill that \
             attributed by pod name alone would name media's StatefulSet as \
             the owner of payments' denials"
        );
        let bare: WorkloadKey = ("shop".into(), "Pod".into(), "debug-1".into());
        assert_eq!(
            index_after_backfill(&mut conn)
                .block_for(&bare)
                .expect("attributed")
                .total,
            3,
            "a bare pod is its own workload once the watcher has seen it"
        );

        let index = denial_index(&mut conn).expect("rollup");
        assert_eq!(
            index.block_for(&web).expect("attributed, so a block").total,
            11,
            "and the workload gets its real count, not merely its namespace \
             back"
        );
        assert!(
            index.block_for(&payments).is_none(),
            "the collision is not resolvable by this rule and must stay \
             Unknown rather than be guessed at"
        );
    }

    fn index_after_backfill(conn: &mut PgConnection) -> DenialIndex {
        denial_index(conn).expect("rollup")
    }

    /// A pod with no controller — `kubectl run`, a debug pod, a static
    /// control-plane pod — never gains a workload in `pod_details`. If ingest
    /// refused it, one such pod tripping a profile would withhold the
    /// all-clear from every CR in its namespace for as long as its rows
    /// lived. It is attributed to itself instead, and its namespace stays
    /// answerable.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_attributes_a_known_bare_pod_to_itself() {
        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");
        seed_pod(&mut conn, "aspmchk", "kube-system", None);
        seed_pod(
            &mut conn,
            "coredns-1",
            "kube-system",
            Some(("Deployment", "coredns")),
        );
        let rows = vec![DenialInput {
            pod_uid: "uid-bare".into(),
            pod_namespace: "kube-system".into(),
            ..input("aspmchk", "mount", "SCMP_ACT_LOG", 4)
        }];
        let names: BTreeSet<String> = rows.iter().map(|d| d.pod_name.clone()).collect();
        let (unattributed, _) = store_batch(&mut conn, "n1", &names, rows).expect("ingest");
        assert_eq!(unattributed, 0, "a known bare pod is not unattributed");

        let index = denial_index(&mut conn).expect("rollup");
        let bare: WorkloadKey = ("kube-system".into(), "Pod".into(), "aspmchk".into());
        assert_eq!(index.block_for(&bare).expect("its own block").total, 4);
        let coredns: WorkloadKey = ("kube-system".into(), "Deployment".into(), "coredns".into());
        assert_eq!(
            index
                .block_for(&coredns)
                .expect("the namespace is not withheld")
                .total,
            0,
            "the Deployment sharing the namespace still gets its real all-clear"
        );
    }

    /// A `last_seen` the Broker's clock has not reached yet is a row no
    /// retention window can ever match, so it lives forever and holds the top
    /// of `GET /seccomp/denials` — ordered `last_seen DESC` — for just as
    /// long. One node with a skewed clock produces it by accident; a single
    /// POST produces it on purpose, since `BROKER_AUTH_TOKEN` is optional.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_can_prune_a_row_that_arrived_from_the_future() {
        let mut conn = live_conn();
        upsert_node_report(&mut conn, "n1", true, None).expect("heartbeat");

        // The handler's own sequence: validate and fold against one clock
        // reading, then store what came out.
        let now = Utc::now();
        let skewed = DenialInput {
            first_seen: now + chrono::Duration::days(3650),
            last_seen: now + chrono::Duration::days(3650),
            ..input("web-1", "ptrace", "SCMP_ACT_LOG", 4)
        };
        let folded = fold_batch(vec![skewed], now);
        let row = &folded.rows[0];
        upsert_denials(
            &mut conn,
            &[NewDenial {
                count: row.count,
                first_seen: row.first_seen,
                last_seen: row.last_seen,
                ..new_denial()
            }],
        )
        .expect("drain");

        let stored = denials_query(&mut conn, None, None, None, None, 100).expect("query");
        assert_eq!(stored.len(), 1);
        assert!(
            stored[0].last_seen <= Utc::now(),
            "stored ahead of the clock, it pins the top of the list until the \
             clock catches up: {}",
            stored[0].last_seen
        );
        assert_eq!(
            stored[0].count, 4,
            "and the measurement itself is untouched"
        );

        // The prune is `last_seen < NOW() - interval`, so the question is
        // whether ANY window can reach this row. A zero-day window is the
        // fastest way to ask it; the retention loop never uses one, and
        // `live_database_accumulates_queries_and_prunes` covers the real
        // window on both sides.
        let pruned = diesel::sql_query(crate::retention::SECCOMP_DENIAL_PRUNE_SQL)
            .bind::<diesel::sql_types::Text, _>("0 days")
            .bind::<diesel::sql_types::BigInt, _>(5000)
            .execute(&mut conn)
            .expect("prune");
        assert_eq!(
            pruned, 1,
            "a row stamped in the future is one retention can never match, \
             so it outlives every pass that runs before the clock gets there"
        );
        assert_eq!(
            folded.from_the_future, 1,
            "and the skew is counted, so the ingest log names a node whose \
             clock an operator has to go and fix"
        );
    }

    /// A whole drain shares one `last_seen`, so without the `id` tie-break
    /// the visible top-N reshuffles between two identical polls.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_breaks_a_shared_last_seen_tie_by_id() {
        let mut conn = live_conn();
        let base = new_denial();
        for syscall in ["a_open", "b_read", "c_write"] {
            upsert_denials(
                &mut conn,
                &[NewDenial {
                    syscall: syscall.into(),
                    ..base.clone()
                }],
            )
            .expect("drain");
        }
        let rows = denials_query(&mut conn, None, None, None, None, 100).expect("query");
        assert_eq!(rows.len(), 3);
        assert!(
            rows[0].id > rows[1].id && rows[1].id > rows[2].id,
            "every row shares one last_seen, so the id tie-break is the only \
             thing ordering them: {:?}",
            rows.iter().map(|r| (r.id, &r.syscall)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_metrics_state_starts_empty() {
        let m = SeccompDenialMetrics::default();
        assert_eq!(m.rows_total(), 0);
        assert_eq!(m.workloads(), 0);
        assert_eq!(m.overflow_series(), 0);
        assert!(m.series().is_empty());
    }

    #[test]
    fn metrics_interval_has_a_floor_and_trims() {
        let _guard = crate::test_support::env_lock();
        let prev = std::env::var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS").ok();
        // SAFETY-equivalent discipline to the other env tests in this crate:
        // the crate-wide lock is held for the whole mutate/read/restore
        // window, so no concurrent test observes these values.
        std::env::set_var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS", "  120\n");
        assert_eq!(metrics_interval(), Duration::from_secs(120));
        // A typo'd `1` would turn the gauge into a per-second aggregate —
        // worse for the database than a slower refresh.
        std::env::set_var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS", "1");
        assert_eq!(
            metrics_interval(),
            Duration::from_secs(MIN_METRICS_INTERVAL_SECS)
        );
        std::env::set_var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS", "garbage");
        assert_eq!(
            metrics_interval(),
            Duration::from_secs(DEFAULT_METRICS_INTERVAL_SECS)
        );
        // The unset default, pinned through the real reader. The
        // enforcing-denial alert is a critical page on a 5-minute
        // `increase()`, so this cadence must stay far below the retention
        // loop's hourly one rather than being folded into it to save a task.
        std::env::remove_var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS");
        let unset = metrics_interval();
        assert_eq!(unset, Duration::from_secs(15));
        assert!(
            unset < Duration::from_secs(30),
            "a refresh slower than a typical Prometheus scrape would make \
             the scrape the fresh part and this the stale part"
        );
        match prev {
            Some(v) => std::env::set_var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS", v),
            None => std::env::remove_var("SECCOMP_DENIAL_METRICS_INTERVAL_SECS"),
        }
    }
}
