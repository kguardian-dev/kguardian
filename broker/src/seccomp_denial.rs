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
use diesel::upsert::excluded;
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
/// attributed denial, as the rollup index folds it.
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

/// How long a node's capture heartbeat stays trustworthy.
///
/// The Controller reports every `SECCOMP_DENIAL_INTERVAL_SECONDS` (10 s by
/// default), so this is 30 consecutive missed reports — generous enough that
/// a node under load, a rolling Controller restart or a brief network
/// partition never flips the cluster to "not capturing", short enough that a
/// genuinely dead capture path is noticed in minutes rather than at the next
/// retention pass.
///
/// Deliberately shorter than `pod_compute_latest`'s 600 s staleness: that one
/// decides whether to delete a row, this one decides whether kguardian is
/// willing to tell an operator a workload is clean.
const CAPTURE_REPORT_STALE_SECS: i64 = 300;

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
#[derive(Debug, Deserialize)]
pub struct DenialBatch {
    node: String,
    /// Whether the denial probe is actually attached on this node.
    ///
    /// `None` from a Controller that predates the heartbeat. That is not
    /// treated as `false`: such a Controller only POSTs when it HAS denials,
    /// so a batch carrying rows is itself proof of capture. See
    /// [`DenialBatch::is_capturing`].
    #[serde(default)]
    capturing: Option<bool>,
    #[serde(default)]
    denials: Vec<DenialInput>,
}

impl DenialBatch {
    /// Whether this report is evidence that the node is capturing.
    ///
    /// Denials in hand outrank the flag in both directions. A batch carrying
    /// rows proves the probe fired, whatever the flag says or fails to say —
    /// so an older Controller with no flag is still recognised, and a node
    /// that reports `capturing: false` while shipping denials is believed on
    /// the evidence rather than on its own self-assessment.
    ///
    /// Absent the flag AND absent denials, the honest answer is "not known to
    /// be capturing", which this returns as `false`. Claiming capture from a
    /// silent report is the one error that produces a false all-clear.
    fn is_capturing(&self) -> bool {
        self.capturing.unwrap_or(false) || !self.denials.is_empty()
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
    if d.count <= 0 {
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
/// Returns the folded rows and the per-field reject counts.
fn fold_batch(denials: Vec<DenialInput>) -> (Vec<DenialInput>, BTreeMap<&'static str, usize>) {
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut folded: BTreeMap<(String, String, String), DenialInput> = BTreeMap::new();
    for d in denials {
        if let Some(field) = reject_reason(&d) {
            *rejected.entry(field).or_insert(0) += 1;
            continue;
        }
        let key = (d.pod_uid.clone(), d.syscall.clone(), d.action.clone());
        match folded.get_mut(&key) {
            Some(existing) => {
                existing.count = existing.count.saturating_add(d.count);
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
    (folded.into_values().collect(), rejected)
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
/// attribute is the correct answer there: the denial is still stored and
/// still queryable by pod, it simply does not claim a workload it cannot
/// prove.
///
/// Pure so the refusal has a test rather than a comment.
fn attribute(
    denial_namespace: &str,
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
        // Partial attribution is no attribution: the rollup key needs both,
        // and half a key would group unrelated workloads together.
        _ => (None, None),
    }
}

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

    // Read BEFORE the batch is consumed by fold_batch, which takes the
    // denials by value.
    let capturing = batch.is_capturing();

    let (rows, rejected) = fold_batch(batch.denials);
    if !rejected.is_empty() {
        // Per-field, not a bare total: "12 rejected" tells an operator
        // nothing, "12 rejected on count" says the controller is shipping
        // empty drains and "12 rejected on podUid" says attribution broke on
        // the node.
        warn!(%node, ?rejected, "seccomp denial batch had unusable entries");
    }

    // The heartbeat, recorded on EVERY report including an empty one — and
    // before the early return below, because the empty report is the one
    // that matters most. An empty drain from a healthy node is what tells
    // the Broker that "no denials" means "nothing was denied" rather than
    // "nothing was watching", and it is the only thing that lets a fresh
    // install ever reach a real all-clear instead of sitting at Unknown
    // forever.
    let heartbeat_pool = pool.clone();
    let heartbeat_node = node.clone();
    web::block(move || -> Result<(), DbError> {
        let mut conn = heartbeat_pool.get()?;
        upsert_node_report(&mut conn, &heartbeat_node, capturing)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    if rows.is_empty() {
        debug!(%node, capturing, "seccomp denial heartbeat (no denials drained)");
        return Ok(HttpResponse::Ok().json(crate::Accepted { accepted: 0 }));
    }

    let pod_names: BTreeSet<String> = rows.iter().map(|d| d.pod_name.clone()).collect();
    let accepted = rows.len();
    let node_for_rows = node.clone();

    let (unattributed, increments) = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        let index = attribution_index(&mut conn, &pod_names)?;
        let mut unattributed = 0usize;
        let mut inserts: Vec<NewDenial> = Vec::with_capacity(rows.len());
        // The Prometheus counter's increments, built here because this is
        // where attribution is resolved: the series is labelled by the
        // workload, so the label set does not exist until this loop runs.
        let mut increments: Vec<(DenialLabels, i64)> = Vec::with_capacity(rows.len());
        for d in rows {
            let (workload_kind, workload_name) =
                attribute(&d.pod_namespace, index.get(&d.pod_name));
            if workload_kind.is_none() {
                unattributed += 1;
            }
            increments.push((
                DenialLabels {
                    namespace: d.pod_namespace.clone(),
                    // Unattributed denials keep their namespace and action
                    // and carry empty workload labels rather than being
                    // dropped from the counter: "something was denied and we
                    // could not say whose" is a signal, not a non-event.
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
                node_name: Some(node_for_rows.clone()),
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
        // One transaction for the whole batch: a partially applied drain
        // would be double-counted by the next one, because the controller
        // clears its BPF map on a successful POST and has no way to replay
        // only the half that landed.
        conn.transaction::<_, DbError, _>(|conn| {
            for chunk in inserts.chunks(INSERT_CHUNK) {
                upsert_denials(conn, chunk)?;
            }
            Ok(())
        })?;
        Ok((unattributed, increments))
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

/// `INSERT ... ON CONFLICT (pod_uid, syscall, action) DO UPDATE`, the
/// accumulation the whole table shape depends on.
///
/// Three things here are not interchangeable with the obvious alternative:
///
/// - `count` is `existing + EXCLUDED`, not `EXCLUDED`. The controller ships
///   the delta since its last drain and clears the map, so overwriting would
///   turn a cumulative count into "whatever the last 10 seconds held" and
///   make the Prometheus counter non-monotonic.
/// - `first_seen`/`last_seen` are `LEAST`/`GREATEST`, not `EXCLUDED`. Drains
///   from a node whose clock stepped, or two nodes' reports for a pod seen
///   across a migration, must widen the bracket rather than move it.
/// - every nullable column is `COALESCE(EXCLUDED.x, existing.x)`, not
///   `EXCLUDED.x`. A later report that could not resolve the workload (the
///   pod's `pod_details` row was pruned) must not erase attribution an
///   earlier one did resolve — that would silently drop the row out of the
///   per-workload rollup the CR status is built from, which reads as "the
///   denials stopped".
fn upsert_denials(conn: &mut PgConnection, rows: &[NewDenial]) -> Result<(), DbError> {
    use schema::seccomp_denials::dsl as sd;
    if rows.is_empty() {
        return Ok(());
    }
    diesel::insert_into(sd::seccomp_denials)
        .values(rows)
        .on_conflict((sd::pod_uid, sd::syscall, sd::action))
        .do_update()
        .set((
            sd::pod_name.eq(excluded(sd::pod_name)),
            sd::pod_namespace.eq(excluded(sd::pod_namespace)),
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
            sd::count.eq(diesel::dsl::sql::<BigInt>(
                "seccomp_denials.count + EXCLUDED.count",
            )),
            sd::first_seen.eq(diesel::dsl::sql::<Timestamptz>(
                "LEAST(seccomp_denials.first_seen, EXCLUDED.first_seen)",
            )),
            sd::last_seen.eq(diesel::dsl::sql::<Timestamptz>(
                "GREATEST(seccomp_denials.last_seen, EXCLUDED.last_seen)",
            )),
        ))
        .execute(conn)?;
    Ok(())
}

/// Record one node's capture heartbeat. Replaces the node's row wholesale —
/// it is a liveness snapshot, not history.
fn upsert_node_report(conn: &mut PgConnection, node: &str, capturing: bool) -> Result<(), DbError> {
    use schema::seccomp_denial_nodes::dsl as sdn;
    let now = Utc::now();
    diesel::insert_into(sdn::seccomp_denial_nodes)
        .values((
            sdn::node_name.eq(node),
            sdn::capturing.eq(capturing),
            sdn::updated_at.eq(now),
        ))
        .on_conflict(sdn::node_name)
        .do_update()
        .set((sdn::capturing.eq(capturing), sdn::updated_at.eq(now)))
        .execute(conn)?;
    Ok(())
}

/// Whether kguardian can currently see seccomp verdicts anywhere on this
/// cluster — the fact that decides whether a `denials` block of `total: 0`
/// is an all-clear or a lie.
///
/// Two signals, in order:
///
/// 1. **A fresh node reporting `capturing = true`.** The real answer. A node
///    that reported within [`CAPTURE_REPORT_STALE_SECS`] with the probe
///    attached proves the whole path works — probe loaded, drain running,
///    POST reaching the Broker — independently of whether anything has
///    actually been denied.
/// 2. **Any denial row at all.** The fallback, and the reason this is not
///    just the first check. A Controller that predates the heartbeat never
///    sends an empty batch, so a cluster running one would have an empty
///    node table forever; but if it has ever shipped a denial, capture
///    demonstrably worked. Without this, upgrading the Broker ahead of the
///    Controller — the supported order — would blank every `denials` block.
///
/// Neither signal is per-workload, which is the known limit of this design:
/// on a fleet where some nodes capture and some do not, a workload whose
/// pods only ever ran on non-capturing nodes still gets a `total: 0`. Fixing
/// that needs the workload's pods resolved to their nodes; see the report.
fn capture_is_live(conn: &mut PgConnection) -> Result<bool, DbError> {
    use schema::seccomp_denial_nodes::dsl as sdn;
    use schema::seccomp_denials::dsl as sd;

    let cutoff = Utc::now() - chrono::Duration::seconds(CAPTURE_REPORT_STALE_SECS);
    let fresh_capturing: Option<String> = sdn::seccomp_denial_nodes
        .filter(sdn::capturing.eq(true))
        .filter(sdn::updated_at.ge(cutoff))
        .select(sdn::node_name)
        .first(conn)
        .optional()?;
    if fresh_capturing.is_some() {
        return Ok(true);
    }

    // `LIMIT 1` rather than a COUNT: the question is existence, and on a
    // table with millions of rows a count would be the most expensive part
    // of serving a profile list that mostly wants to say "nothing here".
    Ok(sd::seccomp_denials
        .select(sd::id)
        .first::<i64>(conn)
        .optional()?
        .is_some())
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

pub(crate) fn denials_query(
    conn: &mut PgConnection,
    by_namespace: Option<String>,
    by_kind: Option<String>,
    by_workload: Option<String>,
    since: Option<DateTime<Utc>>,
    row_limit: i64,
) -> Result<Vec<DenialRow>, diesel::result::Error> {
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
        .load(conn)
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

/// Per-workload denial rollups plus the one fact that decides whether a
/// `denials` block can be emitted at all.
pub(crate) struct DenialIndex {
    by_workload: HashMap<WorkloadKey, DenialRollup>,
    /// Whether the broker holds ANY denial row, attributed or not.
    ///
    /// This is the whole reason the block is an `Option`. With no denial
    /// data at all, "this workload was never denied" and "nothing on this
    /// cluster is capturing denials" produce identical database state —
    /// denial capture needs `CONFIG_AUDIT` on the node, can be switched off
    /// by the operator, and is skipped outright on a kernel without the
    /// `audit_seccomp` symbol. Emitting `total: 0` in that state would put
    /// an all-clear in the CR status for a workload nobody is watching.
    ///
    /// A single row anywhere proves the pipeline works end to end — probe
    /// attached, drain running, POST reaching the broker — and from that
    /// point a workload with no rows genuinely has no denials, so its `0` is
    /// a real all-clear.
    observed: bool,
}

impl DenialIndex {
    /// An index for a broker that has no denial observations. Every
    /// `block_for` returns `None`.
    pub(crate) fn empty() -> Self {
        DenialIndex {
            by_workload: HashMap::new(),
            observed: false,
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
    pub(crate) fn block_for(&self, key: &WorkloadKey) -> Option<DenialBlock> {
        if !self.observed {
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
        Self::from_rows(rows, true)
    }

    /// Fold `(namespace, kind, name, syscall, action, count, last_seen)`
    /// rows into the index. Pure; the DB side is [`load_denial_index`].
    fn from_rows<I>(rows: I, observed: bool) -> Self
    where
        I: IntoIterator<Item = DenialRollupRow>,
    {
        let mut by_workload: HashMap<WorkloadKey, DenialRollup> = HashMap::new();
        for (ns, kind, name, syscall, action, count, last_seen) in rows {
            let e = by_workload.entry((ns, kind, name)).or_default();
            e.total = e.total.saturating_add(count);
            e.syscalls.insert(syscall);
            e.actions.insert(action);
            e.last_seen = Some(match e.last_seen {
                Some(prev) => prev.max(last_seen),
                None => last_seen,
            });
        }
        DenialIndex {
            by_workload,
            observed,
        }
    }
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

/// Load the denial rollup. `only` narrows the per-workload scan to a single
/// workload.
///
/// `observed` is deliberately NOT narrowed by `only`: scoped to one
/// workload it would be exactly `total > 0`, which collapses the
/// "unknown" and "zero" cases back together and defeats the whole point of
/// the flag. It is always a question about the cluster.
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

    // Aggregated in Postgres, not in Rust, and that is the difference
    // between this read being bounded and being unbounded.
    //
    // The stored row is per POD per syscall per action. Every replica of a
    // workload trips the same syscalls, so the pod dimension is pure
    // multiplication for a block that does not carry pods at all: a
    // 500-replica Deployment tripping 20 syscalls is 10 000 rows read to
    // produce one `{total, syscalls, actions, lastSeen}`. Grouping the pod
    // dimension away in SQL leaves workloads x syscalls x actions crossing
    // libpq.
    //
    // That bound matters because of where this runs. `GET /seccomp/profiles`
    // is the endpoint that OOMKilled the broker in #1514, for exactly this
    // shape of mistake — selecting per-row data to compute a per-workload
    // summary — and the UI polls it every 15 s.
    //
    // Still row-per-syscall rather than an `array_agg`: the names ARE part
    // of the block, so they have to arrive either way, and the per-workload
    // cap belongs in `block_for` where the CR status size is decided rather
    // than in SQL where it could not be tested without a database.
    #[derive(diesel::QueryableByName)]
    struct RollupRow {
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
        #[diesel(sql_type = BigInt)]
        total: i64,
        #[diesel(sql_type = Timestamptz)]
        last_seen: DateTime<Utc>,
    }

    // Only attributed rows can be rolled up per workload; an unattributed
    // denial is still visible through GET /seccomp/denials, which is the
    // endpoint that can show it without having to claim a workload. That
    // NOT NULL filter is also what lets the row type above declare the two
    // workload columns non-nullable.
    //
    // `SUM(count)` is cast because Postgres widens a sum of BIGINT to
    // NUMERIC, which diesel would reject at runtime rather than at compile
    // time.
    const SELECT: &str = "SELECT pod_namespace, workload_kind, workload_name, syscall, action, \
         SUM(count)::BIGINT AS total, MAX(last_seen) AS last_seen \
         FROM seccomp_denials \
         WHERE workload_kind IS NOT NULL AND workload_name IS NOT NULL";
    const GROUP: &str = " GROUP BY pod_namespace, workload_kind, workload_name, syscall, action";

    let rows: Vec<RollupRow> = match only {
        Some((ns, kind, name)) => diesel::sql_query(format!(
            "{SELECT} AND pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3{GROUP}"
        ))
        .bind::<Text, _>(ns)
        .bind::<Text, _>(kind)
        .bind::<Text, _>(name)
        .load(conn)?,
        None => diesel::sql_query(format!("{SELECT}{GROUP}")).load(conn)?,
    };

    Ok(DenialIndex::from_rows(
        rows.into_iter().map(|r| {
            (
                r.pod_namespace,
                r.workload_kind,
                r.workload_name,
                r.syscall,
                r.action,
                r.total,
                r.last_seen,
            )
        }),
        observed,
    ))
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// The label set of one `kguardian_seccomp_denials_total` series.
///
/// Labelled by namespace / workload_kind / workload / action and NOT by
/// syscall. That is a deliberate cardinality choice, and it is now
/// load-bearing twice over: a syscall label would multiply the series count
/// by ~300 for information that is one `GET /seccomp/denials` away and does
/// not belong in an alerting rule, AND this key is the map key of a counter
/// held in the broker's memory for the life of the process, so its
/// cardinality is a memory bound rather than only a Prometheus bill.
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
    #[test]
    fn folding_sums_counts_for_one_storage_key() {
        let mut a = input("web-1", "ptrace", "SCMP_ACT_LOG", 17);
        a.first_seen = ts("2026-09-14T04:00:00Z");
        a.last_seen = ts("2026-09-14T04:05:00Z");
        let mut b = input("web-1", "ptrace", "SCMP_ACT_LOG", 5);
        b.first_seen = ts("2026-09-14T04:06:00Z");
        b.last_seen = ts("2026-09-14T04:09:00Z");

        let (rows, rejected) = fold_batch(vec![a, b]);
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
        let (rows, _) = fold_batch(vec![
            input("web-1", "ptrace", "SCMP_ACT_LOG", 1),
            input("web-1", "mount", "SCMP_ACT_LOG", 2),
            input("web-1", "ptrace", "SCMP_ACT_ERRNO", 3),
        ]);
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
        let (rows, _) = fold_batch(vec![d]);
        assert_eq!(rows[0].first_seen, ts("2026-09-14T04:00:00Z"));
        assert_eq!(rows[0].last_seen, ts("2026-09-14T05:00:00Z"));
    }

    /// A zero-count row would add a workload to the rollup — and therefore
    /// flip a CR's `DenialsObserved` to True — for a denial the kernel never
    /// made.
    #[test]
    fn folding_rejects_non_positive_counts() {
        let (rows, rejected) = fold_batch(vec![
            input("web-1", "ptrace", "SCMP_ACT_LOG", 0),
            input("web-2", "ptrace", "SCMP_ACT_LOG", -3),
            input("web-3", "ptrace", "SCMP_ACT_LOG", 1),
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rejected.get("count").copied(), Some(2));
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

        let (rows, rejected) = fold_batch(vec![no_uid, no_syscall, no_action, long_syscall]);
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

        let (rows, _) = fold_batch(vec![a, b]);
        assert_eq!(rows[0].syscall_nr, Some(101));
        assert_eq!(rows[0].arch.as_deref(), Some("SCMP_ARCH_X86_64"));
        assert_eq!(rows[0].action_raw, Some(2_147_483_648));
    }

    // ---- capture heartbeat ---------------------------------------------

    fn batch(capturing: Option<bool>, denials: Vec<DenialInput>) -> DenialBatch {
        DenialBatch {
            node: "n1".into(),
            capturing,
            denials,
        }
    }

    /// The flag is the normal signal: an empty drain from a node whose probe
    /// is attached is exactly the report that lets a quiet cluster reach a
    /// real all-clear instead of sitting at Unknown forever.
    #[test]
    fn an_empty_report_from_a_capturing_node_still_proves_capture() {
        assert!(batch(Some(true), vec![]).is_capturing());
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
        assert!(!batch(Some(false), vec![]).is_capturing());
    }

    /// Denials in hand outrank the flag in both directions.
    #[test]
    fn denials_prove_capture_whatever_the_flag_says() {
        // An older Controller sends no flag at all, and only POSTs when it
        // has denials. Treating a missing flag as `false` would blank every
        // block on a cluster running one — i.e. on the supported upgrade
        // order, Broker first.
        assert!(batch(None, vec![input("web-1", "ptrace", "SCMP_ACT_LOG", 1)]).is_capturing());
        // And a node that reports `false` while shipping denials is believed
        // on the evidence rather than on its own self-assessment.
        assert!(batch(
            Some(false),
            vec![input("web-1", "ptrace", "SCMP_ACT_LOG", 1)]
        )
        .is_capturing());
    }

    /// Absent the flag AND absent denials there is no evidence either way,
    /// and the honest answer is "not known to be capturing". Claiming
    /// capture from a silent report is the one error that produces a false
    /// all-clear.
    #[test]
    fn a_silent_report_with_no_flag_proves_nothing() {
        assert!(!batch(None, vec![]).is_capturing());
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
            attribute("media", Some(&pd)),
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
        assert_eq!(attribute("media", Some(&pd)), (None, None));
    }

    #[test]
    fn attribution_is_none_for_an_unknown_pod_or_a_half_resolved_one() {
        assert_eq!(attribute("media", None), (None, None));
        let half = (
            Some("media".to_string()),
            Some("Deployment".to_string()),
            None,
        );
        assert_eq!(
            attribute("media", Some(&half)),
            (None, None),
            "half a workload key would group unrelated workloads together"
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
            attribute("kube-system", Some(&pd)),
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
        let index = DenialIndex::from_rows(rollup_rows(), true);
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

    /// The other half of the same rule: once ANY denial has been ingested,
    /// the pipeline is proven end to end, so a workload with no rows really
    /// does have zero denials and its all-clear is real.
    #[test]
    fn a_quiet_workload_gets_a_real_zero_once_capture_is_proven() {
        let index = DenialIndex::from_rows(rollup_rows(), true);
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
        let block = DenialIndex::from_rows(rows, true)
            .block_for(&key())
            .unwrap();
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
    // There is no database in this test suite, so the query shape is pinned
    // by asserting on the SQL diesel generates — the same technique
    // `get.rs` uses for the by-IP lookups.

    #[test]
    fn the_query_orders_newest_first_with_a_deterministic_tie_break() {
        use schema::seccomp_denials::dsl as sd;
        let q = sd::seccomp_denials
            .into_boxed()
            .order((sd::last_seen.desc(), sd::id.desc()))
            .limit(100)
            .select(DenialRow::as_select());
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&q).to_string();
        assert!(
            sql.contains(
                r#"ORDER BY "seccomp_denials"."last_seen" DESC, "seccomp_denials"."id" DESC"#
            ),
            "a whole drain shares one last_seen; without the id tie-break the \
             visible top-N reshuffles on every identical request: {sql}"
        );
    }

    /// The upsert is where every accumulation rule actually lives, and all
    /// of them are raw SQL fragments that the type system cannot check. Pin
    /// the generated statement so a refactor cannot quietly turn
    /// accumulation into replacement — which would look fine in every test
    /// that inserts one batch, and be wrong from the second drain onwards.
    #[test]
    fn the_upsert_accumulates_rather_than_replaces() {
        use schema::seccomp_denials::dsl as sd;
        let row = NewDenial {
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
        };
        let stmt = diesel::insert_into(sd::seccomp_denials)
            .values(vec![row])
            .on_conflict((sd::pod_uid, sd::syscall, sd::action))
            .do_update()
            .set((
                sd::count.eq(diesel::dsl::sql::<BigInt>(
                    "seccomp_denials.count + EXCLUDED.count",
                )),
                sd::first_seen.eq(diesel::dsl::sql::<Timestamptz>(
                    "LEAST(seccomp_denials.first_seen, EXCLUDED.first_seen)",
                )),
                sd::last_seen.eq(diesel::dsl::sql::<Timestamptz>(
                    "GREATEST(seccomp_denials.last_seen, EXCLUDED.last_seen)",
                )),
                sd::workload_kind.eq(diesel::dsl::sql::<Nullable<Text>>(
                    "COALESCE(EXCLUDED.workload_kind, seccomp_denials.workload_kind)",
                )),
            ));
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&stmt).to_string();

        assert!(
            sql.contains(r#"ON CONFLICT ("pod_uid", "syscall", "action") DO UPDATE"#),
            "the accumulation key must be the table's unique constraint: {sql}"
        );
        assert!(
            sql.contains("seccomp_denials.count + EXCLUDED.count"),
            "the controller ships a delta and clears its map; replacing the \
             count would make the Prometheus counter non-monotonic: {sql}"
        );
        assert!(
            sql.contains("LEAST(seccomp_denials.first_seen, EXCLUDED.first_seen)")
                && sql.contains("GREATEST(seccomp_denials.last_seen, EXCLUDED.last_seen)"),
            "the observation bracket must widen, never move: {sql}"
        );
        assert!(
            sql.contains("COALESCE(EXCLUDED.workload_kind, seccomp_denials.workload_kind)"),
            "a later report that could not resolve attribution must not \
             erase what an earlier one did: {sql}"
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
    // It applies the REAL migration via include_str! rather than its own
    // DDL, so the schema it exercises cannot drift from the one shipped.

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_accumulates_queries_and_prunes() {
        use diesel::connection::SimpleConnection;

        let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
            panic!("set KG_TEST_DATABASE_URL to run this test");
        };
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.batch_execute(include_str!(
            "../db/migrations/2026-09-14-100000_seccomp_denials/down.sql"
        ))
        .expect("down");
        conn.batch_execute(include_str!(
            "../db/migrations/2026-09-14-100001_seccomp_denial_nodes/down.sql"
        ))
        .expect("nodes down");
        conn.batch_execute(include_str!(
            "../db/migrations/2026-09-14-100000_seccomp_denials/up.sql"
        ))
        .expect("up");
        conn.batch_execute(include_str!(
            "../db/migrations/2026-09-14-100001_seccomp_denial_nodes/up.sql"
        ))
        .expect("nodes up");

        // Capture liveness, before any denial exists. This is the state a
        // fresh install is in, and getting it wrong is what left every
        // workload at Unknown forever.
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "no node has reported and no denial exists: nothing is known to \
             be watching"
        );
        upsert_node_report(&mut conn, "n1", false).expect("degraded heartbeat");
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "a node reporting in with the probe NOT attached (CONFIG_AUDIT=n) \
             is alive and watching nothing; treating that as capture is how \
             graceful degradation becomes a false all-clear"
        );
        upsert_node_report(&mut conn, "n2", true).expect("capturing heartbeat");
        assert!(
            capture_is_live(&mut conn).expect("liveness"),
            "one fresh capturing node proves the path works end to end, with \
             no denial required"
        );
        // Age both heartbeats past the staleness window: nothing is
        // reporting any more, so the answer goes back to "not known".
        conn.batch_execute(&format!(
            "UPDATE seccomp_denial_nodes SET updated_at = NOW() - INTERVAL '{} seconds'",
            CAPTURE_REPORT_STALE_SECS + 60
        ))
        .expect("age heartbeats");
        assert!(
            !capture_is_live(&mut conn).expect("liveness"),
            "a stale heartbeat is not evidence; a node whose Controller died \
             stops reporting rather than reporting false"
        );

        let base = NewDenial {
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
        };
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

        // Rollup.
        let key: WorkloadKey = ("media".into(), "Deployment".into(), "web".into());
        let block = denial_index_for(&mut conn, &key)
            .unwrap()
            .block_for(&key)
            .expect("a row exists, so capture is proven");
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
        upsert_node_report(&mut conn, "n2", true).expect("fresh heartbeat");
        let block = denial_index_for(&mut conn, &key)
            .unwrap()
            .block_for(&key)
            .expect("a capturing node makes zero a real answer");
        assert_eq!(block.total, 0);
        assert!(block.last_seen.is_none());

        conn.batch_execute(include_str!(
            "../db/migrations/2026-09-14-100001_seccomp_denial_nodes/down.sql"
        ))
        .expect("nodes cleanup");

        conn.batch_execute(include_str!(
            "../db/migrations/2026-09-14-100000_seccomp_denials/down.sql"
        ))
        .expect("cleanup");
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
