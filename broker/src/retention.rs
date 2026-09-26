//! Periodic cleanup of old audit_verdicts rows.
//!
//! The audit_verdicts table grows monotonically with the volume of
//! "would deny" flow events. Without a retention policy, indexes
//! degrade and disk usage climbs indefinitely on busy clusters.
//!
//! This module spawns a tokio task on broker startup that wakes every
//! `RETENTION_INTERVAL` and prunes expired rows in batches:
//!
//! ```text
//! WITH expired AS (
//!     SELECT id FROM audit_verdicts
//!     WHERE observed_at < timezone('UTC', NOW()) - INTERVAL '<N> days'
//!     ORDER BY id LIMIT <batch_size>
//! )
//! DELETE FROM audit_verdicts WHERE id IN (SELECT id FROM expired);
//! ```
//!
//! Batching keeps each transaction's lock hold and WAL chunk bounded,
//! so a one-time large prune (e.g. operator drops retention from 365
//! days to 7) doesn't block concurrent INSERTs from the broker's
//! ingest path or balloon WAL. Each batch is its own
//! `spawn_blocking` call so the broker's blocking pool stays
//! responsive between iterations.
//!
//! Configuration:
//!
//! - `AUDIT_VERDICTS_RETENTION_DAYS` (default 30) — anything older than
//!   N days is eligible for deletion. Setting to 0 disables retention.
//! - `AUDIT_VERDICTS_RETENTION_INTERVAL_SECS` (default 3600 = 1h) — how
//!   often the cleanup task runs.
//! - `AUDIT_VERDICTS_RETENTION_BATCH_SIZE` (default 5_000, clamped to
//!   [100, 100_000]) — rows deleted per batch.
//!
//! Errors are logged and the task continues; a transient DB outage
//! never crashes the broker.
//!
//! # Compute history (design D5)
//!
//! A second loop, on its own cadence (`COMPUTE_RETENTION_INTERVAL_SECS`,
//! default 600), keeps the compute tables bounded:
//!
//! 1. **Downsample**: minute rows (`resolution_secs = 60`) older than
//!    `COMPUTE_HISTORY_MINUTE_HOURS` (default 24) are folded per
//!    `(container_uid, 5-minute bucket)` into one `resolution_secs = 300`
//!    row — avg of avgs, max of maxes, last-by-ts of lasts, summed
//!    counters, element-wise summed `runq_hist` — and the minute rows
//!    deleted in the SAME transaction, one bounded range of whole
//!    buckets per batch (see `downsample_range`).
//! 2. **Prune**: `pod_compute_history` and `pod_contention_history` rows
//!    older than `COMPUTE_HISTORY_RETENTION_DAYS` (default 7; 0 disables
//!    history entirely, ingest included) — same batched CTE DELETE.
//! 3. **Dead containers and departed nodes**: `pod_compute_latest` rows
//!    not refreshed for 10 minutes (the container is gone, or its node's
//!    controller is) and `node_compute_latest` rows not refreshed for an
//!    hour (the node left the cluster; `NODE_COMPUTE_LATEST_STALE_SECS`
//!    says why the two windows differ). Runs regardless of the history
//!    setting.
//!
//! # Seccomp denials
//!
//! A third loop does two things to `seccomp_denials`. It **backfills
//! attribution** — resolving rows whose pod was not yet in `pod_details` when
//! the denial arrived — and it prunes by `last_seen`, on the same batched CTE
//! pattern. The backfill runs whatever the retention window is set to,
//! because it is not retention: an unattributed row withholds the all-clear
//! from its whole namespace, so leaving one unresolved is a reporting outage
//! rather than a housekeeping backlog. Settings:
//!
//! - `SECCOMP_DENIALS_RETENTION_DAYS` (default 30; 0 disables pruning)
//! - `SECCOMP_DENIALS_RETENTION_INTERVAL_SECS` (default 3600)
//! - `SECCOMP_DENIALS_RETENTION_BATCH_SIZE` (default 5 000, clamped to
//!   [100, 100 000])
//!
//! The window is not cosmetic here the way it is for verdicts. The retention
//! window IS the window `kguardian_seccomp_denial_workloads` and the
//! `denials` block on `GET /seccomp/profiles` report over — neither applies
//! a date filter of its own, precisely so there is one place the window is
//! defined. Widening this setting widens what a CR's `DenialsObserved`
//! condition considers current.
//!
//! # Pod traffic
//!
//! A fourth loop prunes `pod_traffic`, the flow table every generated
//! NetworkPolicy is built from. Same batched CTE DELETE, with two
//! differences that come from how the table is filled:
//!
//! - **Rows of a live pod are never pruned, however old.** A row is
//!   written once per flow class and `time_stamp` is when that class was
//!   FIRST seen: the controller suppresses repeats in-kernel (an LRU with
//!   no TTL, keyed per network namespace) and the broker dedups what does
//!   arrive. A pod holding a flow it established a month ago will not
//!   report it again, so deleting its row by age would silently drop that
//!   rule from the next policy generated for the pod. Eligible rows are
//!   the ones whose pod is dead, gone from `pod_details`, or a previous
//!   incarnation of a reused name (a StatefulSet pod): a replacement pod
//!   has a fresh network namespace and re-reports what it actually does.
//! - **...unless a newer row carries the same rule.** An expired row of a
//!   live pod IS deleted when a newer row of that pod has the same
//!   direction, protocol, ports, decision and in-cluster peer identity
//!   (peer workload, or peer name when it has none). That bounds the rows
//!   a live pod gains as its callers change IP, e.g. one per CronJob run.
//!   See [`POD_TRAFFIC_PRUNE_SQL`].
//! - **An opt-in per-pod cap for peers with no identity.** Rows whose peer
//!   is external or unresolved cannot be superseded. With
//!   `POD_TRAFFIC_MAX_ROWS_PER_POD` set, a pod over the cap loses its
//!   oldest such rows, never a row naming an in-cluster peer, and the
//!   broker warns naming the pod. See [`run_pod_traffic_cap`].
//! - **A keyset cursor instead of "delete until nothing matches".** Live
//!   pods' old rows stay, so they pile up at the head of the `time_stamp`
//!   order. Each batch examines the next `batch_size` expired rows after
//!   the cursor, deletes the ones whose pod is gone and moves the cursor
//!   past everything it examined; a pass that hits the per-pass cap hands
//!   its cursor to the next one. `batch_size` therefore bounds rows
//!   examined per statement, and rows deleted along with it.
//!
//! Settings:
//!
//! - `POD_TRAFFIC_RETENTION_DAYS` (default 14; 0 disables pruning)
//! - `POD_TRAFFIC_RETENTION_INTERVAL_SECS` (default 3600)
//! - `POD_TRAFFIC_RETENTION_BATCH_SIZE` (default 5 000, clamped to
//!   [100, 100 000])
//! - `POD_TRAFFIC_MAX_ROWS_PER_POD` (default 0 = no cap)

use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use std::time::Duration;
use tracing::{debug, info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

const DEFAULT_RETENTION_DAYS: u32 = 30;
const DEFAULT_INTERVAL_SECS: u64 = 3600;
/// Rows deleted per batch. A single unbounded DELETE on a busy
/// cluster — millions of expired rows after a long retention.days
/// bump or a recovery from a backup — would hold an exclusive lock on
/// every page touched, bloat WAL into multi-GB chunks, and block
/// concurrent INSERTs from the broker's ingest path. Batching keeps
/// each transaction short and pool-friendly.
const DEFAULT_BATCH_SIZE: i64 = 5_000;
/// Lower bound for the batch size; values below this defeat the
/// purpose (too many round-trips for trivial work) and are typically
/// a typo (`50`, `5`, `0`).
const MIN_BATCH_SIZE: i64 = 100;
/// Upper bound for the batch size. Above ~100k rows, each individual
/// DELETE starts behaving like the unbatched form — long lock hold
/// and big WAL chunks. The cap saves operators from misconfiguration
/// (10x typos `50000` → `500000`).
const MAX_BATCH_SIZE: i64 = 100_000;
/// Maximum number of batches per pass. With DEFAULT_BATCH_SIZE this
/// caps a single pass at ~5M rows / hour at the default cadence — far
/// more than any healthy cluster generates. The cap prevents a
/// pathological one-time deletion (operator drops retention from 365
/// days to 7) from monopolising the broker's blocking pool for an
/// hour; the next interval picks up where this one left off.
const MAX_BATCHES_PER_PASS: u32 = 200;

/// Default window for pruning dead pods from pod_details when audit
/// retention is disabled. pod_details bloats with pod churn regardless of
/// audit retention (and /pod/info returns the whole table), so dead-pod
/// pruning must NOT be coupled to AUDIT_VERDICTS_RETENTION_DAYS=0.
const DEFAULT_DEAD_POD_RETENTION_DAYS: u32 = 7;

/// Resolve the dead-pod pruning window from the audit retention setting.
/// Pure + testable so the decoupling can't silently regress: audit_days==0
/// (audit pruning disabled) must still yield a non-zero dead-pod window,
/// or pod_details bloats unbounded and /pod/info slows to a crawl.
fn dead_pod_retention_window(audit_days: u32) -> u32 {
    if audit_days > 0 {
        audit_days
    } else {
        DEFAULT_DEAD_POD_RETENTION_DAYS
    }
}

/// Spawn a background task that periodically prunes audit_verdicts and
/// dead pods. Returns immediately; the task lives for the broker's lifetime.
///
/// `AUDIT_VERDICTS_RETENTION_DAYS=0` disables ONLY audit_verdicts pruning.
/// Dead-pod pruning of pod_details always runs (with its own default
/// window) — it must not be coupled to the audit setting.
pub fn spawn(pool: DbPool) {
    let audit_days = retention_days();
    // Dead-pod pruning runs independently: use the audit window when set,
    // otherwise a standalone default. Setting audit retention to 0 only
    // disables audit_verdicts pruning, not pod_details cleanup.
    let dead_pod_days = dead_pod_retention_window(audit_days);
    let interval = retention_interval();
    info!(
        audit_days,
        dead_pod_days,
        interval_secs = interval.as_secs(),
        "retention loop scheduled (audit_days=0 means audit pruning off; dead-pod pruning still runs)"
    );

    let compute_pool = pool.clone();
    let denial_pool = pool.clone();
    let traffic_pool = pool.clone();
    spawn_image_inventory(pool.clone());
    spawn_workload_profiles(pool.clone());
    spawn_supplychain(pool.clone());
    actix_web::rt::spawn(async move {
        // First pass after a short warmup so the broker doesn't hammer
        // a cold pool the second it starts.
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            // Audit pruning only when enabled; dead-pod pruning always.
            if audit_days > 0 {
                run_pass(&pool, audit_days).await;
            }
            run_dead_pod_pass(&pool, dead_pod_days).await;
            tokio::time::sleep(interval).await;
        }
    });
    spawn_compute(compute_pool);
    spawn_seccomp_denials(denial_pool);
    spawn_pod_traffic(traffic_pool);
}

/// The compute-history loop (module docs, "Compute history"). Separate
/// task and cadence from the audit loop: the downsample is a heavier,
/// more frequent pass, and one loop's failure mode must not delay the
/// other's.
fn spawn_compute(pool: DbPool) {
    let days = compute_history_retention_days();
    let minute_hours = compute_minute_hours();
    let interval = compute_retention_interval();
    info!(
        days,
        minute_hours,
        interval_secs = interval.as_secs(),
        "compute retention loop scheduled (days=0 means history off; stale-latest pruning still runs)"
    );
    actix_web::rt::spawn(async move {
        tokio::time::sleep(Duration::from_secs(90)).await;
        loop {
            run_compute_pass(&pool, days, minute_hours).await;
            tokio::time::sleep(interval).await;
        }
    });
}

// ---------------------------------------------------------------------
// Seccomp denials
// ---------------------------------------------------------------------

const DEFAULT_SECCOMP_DENIAL_RETENTION_DAYS: u32 = 30;
const DEFAULT_SECCOMP_DENIAL_INTERVAL_SECS: u64 = 3600;

/// `SECCOMP_DENIALS_RETENTION_DAYS` (default 30). 0 disables pruning.
///
/// Unlike the audit window this one is read by more than the pruner: it is
/// the window the denial metrics and the `denials` block on
/// `GET /seccomp/profiles` implicitly report over, because neither filters
/// by date — the table is the window. That is deliberate (one definition,
/// not three), and it is why this setting deserves its own env var rather
/// than being folded into the audit one.
fn seccomp_denial_retention_days() -> u32 {
    std::env::var("SECCOMP_DENIALS_RETENTION_DAYS")
        .ok()
        // Same trim defense as every other env reader here.
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_SECCOMP_DENIAL_RETENTION_DAYS)
}

fn seccomp_denial_retention_interval() -> Duration {
    let secs = std::env::var("SECCOMP_DENIALS_RETENTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_SECCOMP_DENIAL_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}

/// Rows deleted per batch, clamped to the same [MIN_BATCH_SIZE,
/// MAX_BATCH_SIZE] window and for the same reasons as
/// [`retention_batch_size`].
fn seccomp_denial_batch_size() -> i64 {
    std::env::var("SECCOMP_DENIALS_RETENTION_BATCH_SIZE")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE))
        .unwrap_or(DEFAULT_BATCH_SIZE)
}

/// The seccomp-denial prune loop. Its own task and cadence, matching the
/// compute loop's separation: one loop's failure mode must not delay
/// another's.
fn spawn_seccomp_denials(pool: DbPool) {
    let days = seccomp_denial_retention_days();
    let interval = seccomp_denial_retention_interval();
    info!(
        days,
        interval_secs = interval.as_secs(),
        "seccomp denial retention loop scheduled (days=0 means pruning off; \
         attribution backfill still runs)"
    );
    actix_web::rt::spawn(async move {
        // Staggered against the other two loops' 60 s and 90 s warmups so
        // three full-table prunes do not land on a cold pool together.
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            // Denial pruning only when enabled; attribution backfill always,
            // the same split the audit loop makes for dead pods. The backfill
            // is not housekeeping — an unattributed row is why a namespace
            // reads `DenialsObserved: Unknown` — so switching pruning off
            // must not switch it off too.
            //
            // Before the prune, so a row on the edge of the window is
            // attributed for whatever poll it has left rather than being
            // repaired and deleted in the same pass.
            backfill_denial_attribution(&pool).await;
            if days > 0 {
                run_seccomp_denial_pass(&pool, days).await;
                // Once per pass, after the denial prune: the node table is
                // one row per node, so it needs no batching and no cadence of
                // its own.
                prune_stale_denial_nodes(&pool, days).await;
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// One pass pruning denials older than the window. Same batched-DELETE
/// discipline as the verdict prune — see [`run_pass`].
async fn run_seccomp_denial_pass(pool: &DbPool, days: u32) {
    let batch_size = seccomp_denial_batch_size();
    let mut total_deleted: usize = 0;
    for batch_idx in 0..MAX_BATCHES_PER_PASS {
        let pool = pool.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
            run_seccomp_denial_batch(&pool, days, batch_size)
        })
        .await;
        match result {
            Ok(Ok(0)) => {
                if total_deleted == 0 {
                    debug!("seccomp_denials retention: 0 rows pruned");
                } else {
                    info!(
                        rows = total_deleted,
                        batches = batch_idx,
                        "seccomp_denials retention pruned old rows",
                    );
                }
                return;
            }
            Ok(Ok(n)) => total_deleted += n,
            Ok(Err(RetentionError::Pool(e))) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "seccomp_denials retention: could not get db conn");
                return;
            }
            Ok(Err(RetentionError::Diesel(e))) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "seccomp_denials retention: DELETE failed");
                return;
            }
            Err(e) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "seccomp_denials retention task panicked");
                return;
            }
        }
    }
    info!(
        rows = total_deleted,
        cap = MAX_BATCHES_PER_PASS,
        "seccomp_denials retention hit per-pass batch cap; remaining rows will be pruned on next interval",
    );
}

/// Re-run attribution against `pod_details` for denials that had none.
///
/// # Why a denial arrives unattributed, and why leaving it there is not free
///
/// Ingest resolves the owning workload from `pod_details` at the moment the
/// report lands. A pod that trips a syscall in its first seconds can beat its
/// own `pod_details` row to the Broker, and the ingest upsert only re-resolves
/// a row when the same `(pod_uid, syscall, action)` is reported again — so a
/// one-shot startup denial, which is exactly the shape that race produces,
/// stays unattributed for the life of the row.
///
/// That is not a cosmetic gap. An unattributed row is filtered out of the
/// per-workload rollup, and `DenialIndex::block_for` withholds the whole
/// namespace's `denials` block because of it, so one unrepaired row sits a
/// namespace at `DenialsObserved: Unknown` until it is pruned — 30 days at
/// the default. This pass is what makes that state transient.
///
/// # The rule is `seccomp_denial::attribute`'s, in SQL
///
/// Both workload columns or neither, and the pod's namespace must match the
/// denial's (a `pod_details` row with no namespace recorded cannot be
/// disproved and is taken as a match). That equivalence is the point: a
/// backfill that attributed more loosely than ingest would resolve exactly
/// the rows ingest refused, which are the ones where `pod_details`' pod-name
/// primary key has collapsed two namespaces' pods — and would then name the
/// wrong team's workload in a `SeccompProfile` status. The collision case
/// stays unattributed here on purpose, and its namespace keeps reading
/// Unknown, which is the honest answer for it.
///
/// # Bounded, and it fails in the safe direction
///
/// One batch per pass, the same size the prune uses. Anything left is retried
/// on the next pass, and a row left unattributed keeps its namespace at
/// Unknown — so running out of budget here costs a delayed all-clear, never a
/// false one.
async fn backfill_denial_attribution(pool: &DbPool) {
    let batch_size = seccomp_denial_batch_size();
    let pool = pool.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
        let mut conn = pool.get().map_err(RetentionError::Pool)?;
        sql_query(BACKFILL_DENIAL_ATTRIBUTION_SQL)
            .bind::<diesel::sql_types::BigInt, _>(batch_size)
            .execute(&mut conn)
            .map_err(RetentionError::Diesel)
    })
    .await;
    match result {
        Ok(Ok(0)) => debug!("seccomp denial attribution backfill: 0 rows resolved"),
        Ok(Ok(n)) => info!(
            rows = n,
            "seccomp denial attribution backfill resolved rows whose pod was not \
             known when the denial arrived"
        ),
        Ok(Err(e)) => warn!(error = %e, "seccomp denial attribution backfill failed"),
        Err(e) => warn!(error = %e, "seccomp denial attribution backfill task panicked"),
    }
}

/// The backfill statement, as a constant so the live-database test runs the
/// SAME SQL this loop issues rather than a hand-copied approximation.
///
/// `$1` bounds the candidate rows. A candidate is an unattributed row whose
/// pod `pod_details` now knows, in the right namespace, so every candidate
/// resolves on the pass that picks it — either to the pod's owning workload
/// or, for a pod with no owner, to the pod itself (`Pod`/pod name, the same
/// rule ingest applies). Rows whose pod is still unknown are not candidates
/// and cost nothing until it appears; without that guard they sat at the
/// head of the id order on every pass and, past `$1` of them, starved every
/// resolvable row behind them.
pub(crate) const BACKFILL_DENIAL_ATTRIBUTION_SQL: &str = "WITH candidates AS (\
         SELECT d.id FROM seccomp_denials d \
         WHERE (d.workload_kind IS NULL OR d.workload_name IS NULL) \
           AND EXISTS (\
             SELECT 1 FROM pod_details p \
             WHERE p.pod_name = d.pod_name \
               AND (p.pod_namespace IS NULL OR p.pod_namespace = d.pod_namespace) \
               AND (p.workload_kind IS NULL) = (p.workload_name IS NULL)\
           ) \
         ORDER BY d.id \
         LIMIT $1 \
     ) \
     UPDATE seccomp_denials d \
     SET workload_kind = COALESCE(p.workload_kind, 'Pod'), \
         workload_name = COALESCE(p.workload_name, d.pod_name) \
     FROM pod_details p \
     WHERE d.id IN (SELECT id FROM candidates) \
       AND p.pod_name = d.pod_name \
       AND (p.pod_namespace IS NULL OR p.pod_namespace = d.pod_namespace) \
       AND (p.workload_kind IS NULL) = (p.workload_name IS NULL)";

/// Drop heartbeat rows for nodes that stopped reporting a whole retention
/// window ago — the node is gone, not merely quiet.
///
/// Not batched, and not on its own cadence: the table holds one row per
/// node, so a single unbounded DELETE here is bounded by cluster size rather
/// than by ingest volume.
///
/// The window is deliberately the full retention window rather than the much
/// shorter staleness window that `capture_is_live` uses. Those answer
/// different questions: staleness decides whether to TRUST a node's report
/// (minutes, or a few multiples of that node's own declared drain interval),
/// this decides whether the node still exists (days). Pruning on the
/// staleness window would delete a node's row during a long Controller
/// outage and then recreate it on recovery, which loses nothing but churns
/// the table for no reason.
///
/// The widest staleness window a node can buy itself is half an hour (see
/// `CAPTURE_REPORT_STALE_CEILING_SECS`), so with a retention window measured
/// in days the two cannot cross at all unless pruning is disabled entirely —
/// and if they somehow did, the crossing fails safe: the row goes, so the
/// cluster reads Unknown rather than clean.
async fn prune_stale_denial_nodes(pool: &DbPool, days: u32) {
    let pool = pool.clone();
    let interval = format!("{} days", days);
    let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
        let mut conn = pool.get().map_err(RetentionError::Pool)?;
        sql_query("DELETE FROM seccomp_denial_nodes WHERE updated_at < NOW() - $1::interval")
            .bind::<diesel::sql_types::Text, _>(interval)
            .execute(&mut conn)
            .map_err(RetentionError::Diesel)
    })
    .await;
    match result {
        Ok(Ok(0)) => debug!("seccomp_denial_nodes retention: 0 stale nodes pruned"),
        Ok(Ok(n)) => info!(
            rows = n,
            "seccomp_denial_nodes retention pruned departed nodes"
        ),
        Ok(Err(e)) => warn!(error = %e, "seccomp_denial_nodes retention failed"),
        Err(e) => warn!(error = %e, "seccomp_denial_nodes retention task panicked"),
    }
}

/// Batched DELETE of denials whose newest observation is outside the
/// window.
///
/// `last_seen`, not `first_seen`: a row accumulates across drains, so a pod
/// that has been tripping the same syscall for two months has a `first_seen`
/// well outside a 30-day window while still being an active denial. Pruning
/// on `first_seen` would delete exactly the longest-running problems.
///
/// The comparison is bare `NOW()`, unlike every other prune in this file.
/// `last_seen` is TIMESTAMPTZ (produced on a node, so it carries its zone),
/// and Postgres compares a timestamptz against `NOW()` in absolute time
/// regardless of the session timezone. The `timezone('UTC', NOW())` wrapper
/// the other prunes need exists to build a UTC-NAIVE right-hand side for
/// their naive columns; applying it here would strip the zone off `NOW()`
/// and reintroduce exactly the session-timezone dependency it was added to
/// remove.
fn run_seccomp_denial_batch(
    pool: &DbPool,
    days: u32,
    batch_size: i64,
) -> Result<usize, RetentionError> {
    let mut conn = pool.get().map_err(RetentionError::Pool)?;
    let interval = format!("{} days", days);
    let deleted = sql_query(SECCOMP_DENIAL_PRUNE_SQL)
        .bind::<diesel::sql_types::Text, _>(interval)
        .bind::<diesel::sql_types::BigInt, _>(batch_size)
        .execute(&mut conn)
        .map_err(RetentionError::Diesel)?;
    Ok(deleted)
}

/// The prune statement itself, as a constant so the live-database test in
/// `seccomp_denial.rs` runs the SAME SQL this loop issues rather than a
/// hand-copied approximation that can silently drift from it.
pub(crate) const SECCOMP_DENIAL_PRUNE_SQL: &str = "WITH expired AS (\
         SELECT id FROM seccomp_denials \
         WHERE last_seen < NOW() - $1::interval \
         ORDER BY id \
         LIMIT $2 \
     ) \
     DELETE FROM seccomp_denials WHERE id IN (SELECT id FROM expired)";

// ---------------------------------------------------------------------
// Pod traffic
// ---------------------------------------------------------------------

/// 14 days: twice the period of a weekly CronJob, so a job that runs once a
/// week always has its last run's flows on record when a policy is
/// generated for it. Longer-lived workloads are unaffected by the window
/// (see [`POD_TRAFFIC_PRUNE_SQL`]), so what it bounds is the history of
/// pods that no longer exist — the part of the table that grows with churn.
const DEFAULT_POD_TRAFFIC_RETENTION_DAYS: u32 = 14;
const DEFAULT_POD_TRAFFIC_INTERVAL_SECS: u64 = 3600;

/// `POD_TRAFFIC_RETENTION_DAYS` (default 14). 0 disables pruning.
fn pod_traffic_retention_days() -> u32 {
    std::env::var("POD_TRAFFIC_RETENTION_DAYS")
        .ok()
        // Same trim defense as every other env reader here.
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_POD_TRAFFIC_RETENTION_DAYS)
}

fn pod_traffic_retention_interval() -> Duration {
    let secs = std::env::var("POD_TRAFFIC_RETENTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_POD_TRAFFIC_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}

/// Rows deleted per batch, clamped to the same [MIN_BATCH_SIZE,
/// MAX_BATCH_SIZE] window and for the same reasons as
/// [`retention_batch_size`].
fn pod_traffic_batch_size() -> i64 {
    std::env::var("POD_TRAFFIC_RETENTION_BATCH_SIZE")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE))
        .unwrap_or(DEFAULT_BATCH_SIZE)
}

/// The pod_traffic prune loop. Its own task and cadence, like the others.
/// Unlike them it has nothing to do when pruning is off, so `days == 0`
/// starts no task at all.
fn spawn_pod_traffic(pool: DbPool) {
    let days = pod_traffic_retention_days();
    let max_rows = pod_traffic_max_rows_per_pod();
    let interval = pod_traffic_retention_interval();
    if days == 0 && max_rows == 0 {
        info!(
            "pod_traffic retention disabled (POD_TRAFFIC_RETENTION_DAYS=0, no per-pod cap); \
             table grows unbounded"
        );
        return;
    }
    info!(
        days,
        max_rows_per_pod = max_rows,
        interval_secs = interval.as_secs(),
        "pod_traffic retention loop scheduled (days=0 means age pruning off; \
         max_rows_per_pod=0 means no per-pod cap)"
    );
    actix_web::rt::spawn(async move {
        // Staggered after the 60 / 90 / 120 s warmups of the other loops.
        tokio::time::sleep(Duration::from_secs(150)).await;
        let mut cursor = None;
        loop {
            if days > 0 {
                cursor = run_pod_traffic_pass(&pool, days, cursor).await;
            }
            // After the age pass, so the cap only counts rows that age and
            // supersede pruning have already left.
            if max_rows > 0 {
                run_pod_traffic_cap(&pool, max_rows).await;
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// `POD_TRAFFIC_MAX_ROWS_PER_POD` (default 0 = no cap). Garbage falls back
/// to 0 rather than to some cap: this setting deletes rows regardless of
/// age, so it only ever runs when an operator set it on purpose.
fn pod_traffic_max_rows_per_pod() -> i64 {
    std::env::var("POD_TRAFFIC_MAX_ROWS_PER_POD")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(i64::from)
        .unwrap_or(0)
}

/// Most over-cap pods handled per pass; the rest wait for the next one.
const MAX_CAPPED_PODS_PER_PASS: i64 = 100;

#[derive(Debug, QueryableByName)]
struct OverCapName {
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    pod_name: String,
}

#[derive(Debug, QueryableByName)]
struct OverCapPod {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    pod_namespace: Option<String>,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows: i64,
}

/// Pod names holding more than `$1` rows, largest first, at most `$2`.
///
/// Grouped by name alone so it can be answered from
/// `idx_pod_traffic_pod_name` without touching `pod_namespace`; the
/// per-namespace count follows in [`POD_TRAFFIC_OVER_CAP_PODS_SQL`], so a
/// name shared across namespaces (`postgres-0` in three of them) is never
/// capped on the sum of its namespaces. This is the one statement in the
/// loop that reads the whole table (or its pod_name index) rather than a
/// bounded range, which is part of why the cap is opt-in.
pub(crate) const POD_TRAFFIC_OVER_CAP_NAMES_SQL: &str = "SELECT pod_name \
     FROM pod_traffic \
     WHERE pod_name IS NOT NULL \
     GROUP BY pod_name \
     HAVING count(*) > $1 \
     ORDER BY count(*) DESC \
     LIMIT $2";

/// Per-namespace row counts for one over-cap name, over-cap only.
pub(crate) const POD_TRAFFIC_OVER_CAP_PODS_SQL: &str = "SELECT pod_namespace, count(*) AS rows \
     FROM pod_traffic \
     WHERE pod_name = $1 \
     GROUP BY pod_namespace \
     HAVING count(*) > $2";

/// Delete up to `$3` of one pod's oldest rows with NO stored peer identity
/// (`peer_kind IS NULL`: external, never resolved, or written before
/// #1447). A row naming an in-cluster peer is never touched here, however
/// far over the cap the pod is: it may be the only record of a rule, and
/// dropping it would break the next generated policy.
pub(crate) const POD_TRAFFIC_CAP_PRUNE_SQL: &str = "WITH victims AS (\
         SELECT uuid FROM pod_traffic \
         WHERE pod_name = $1 \
           AND pod_namespace IS NOT DISTINCT FROM $2 \
           AND peer_kind IS NULL \
         ORDER BY time_stamp, uuid \
         LIMIT $3 \
     ) \
     DELETE FROM pod_traffic WHERE uuid IN (SELECT uuid FROM victims)";

/// Summary of capping one pod: rows before, rows pruned.
#[derive(Debug, PartialEq, Eq)]
struct CapOutcome {
    pod_name: String,
    pod_namespace: Option<String>,
    rows_before: i64,
    pruned: i64,
}

/// The opt-in per-pod cap. For every pod over `max_rows`, delete its oldest
/// rows with no stored peer identity, in batches, until it is at the cap or
/// has none of those left, and warn with the pod and the count. The age
/// pass cannot bound a live pod whose peers are external (an IP-preserving
/// ingress sees a row per client IP; a scanned pod collects a DROP row per
/// scanner), because those rows have no identity to supersede on.
async fn run_pod_traffic_cap(pool: &DbPool, max_rows: i64) {
    let batch_size = pod_traffic_batch_size();
    let pool = pool.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<CapOutcome>, RetentionError> {
        let mut conn = pool.get().map_err(RetentionError::Pool)?;
        cap_pod_traffic(&mut conn, max_rows, batch_size, MAX_BATCHES_PER_PASS)
    })
    .await;
    match result {
        Ok(Ok(outcomes)) if outcomes.is_empty() => {
            debug!(max_rows, "pod_traffic per-pod cap: no pod over the cap");
        }
        Ok(Ok(outcomes)) => {
            for o in outcomes {
                let remaining = o.rows_before - o.pruned;
                warn!(
                    pod = %o.pod_name,
                    namespace = o.pod_namespace.as_deref().unwrap_or(""),
                    rows_before = o.rows_before,
                    pruned = o.pruned,
                    rows_after = remaining,
                    max_rows,
                    still_over_cap = remaining > max_rows,
                    "pod_traffic per-pod cap exceeded; pruned oldest rows with no in-cluster peer \
                     identity (rows naming an in-cluster peer are never pruned by the cap)",
                );
            }
        }
        Ok(Err(e)) => warn!(error = %e, "pod_traffic per-pod cap failed"),
        Err(e) => warn!(error = %e, "pod_traffic per-pod cap task panicked"),
    }
}

/// The cap itself, synchronous so the live test can drive it directly.
/// `batch_budget` bounds the DELETE statements issued across all pods in
/// one call; a pod left over the cap is picked up on the next pass.
fn cap_pod_traffic(
    conn: &mut PgConnection,
    max_rows: i64,
    batch_size: i64,
    batch_budget: u32,
) -> Result<Vec<CapOutcome>, RetentionError> {
    let names: Vec<OverCapName> = sql_query(POD_TRAFFIC_OVER_CAP_NAMES_SQL)
        .bind::<diesel::sql_types::BigInt, _>(max_rows)
        .bind::<diesel::sql_types::BigInt, _>(MAX_CAPPED_PODS_PER_PASS)
        .load(conn)?;
    let mut budget = batch_budget;
    let mut outcomes = Vec::new();
    for name in names {
        let pods: Vec<OverCapPod> = sql_query(POD_TRAFFIC_OVER_CAP_PODS_SQL)
            .bind::<diesel::sql_types::Varchar, _>(&name.pod_name)
            .bind::<diesel::sql_types::BigInt, _>(max_rows)
            .load(conn)?;
        for pod in pods {
            let mut excess = pod.rows - max_rows;
            let mut pruned = 0i64;
            while excess > 0 && budget > 0 {
                budget -= 1;
                let n = sql_query(POD_TRAFFIC_CAP_PRUNE_SQL)
                    .bind::<diesel::sql_types::Varchar, _>(&name.pod_name)
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Varchar>, _>(
                        pod.pod_namespace.as_deref(),
                    )
                    .bind::<diesel::sql_types::BigInt, _>(excess.min(batch_size))
                    .execute(conn)? as i64;
                if n == 0 {
                    // Only rows naming an in-cluster peer are left.
                    break;
                }
                pruned += n;
                excess -= n;
            }
            outcomes.push(CapOutcome {
                pod_name: name.pod_name.clone(),
                pod_namespace: pod.pod_namespace,
                rows_before: pod.rows,
                pruned,
            });
        }
    }
    Ok(outcomes)
}

/// Where the scan resumes: the `(time_stamp, uuid)` of the last row a batch
/// examined, whether it deleted that row or kept it.
type TrafficCursor = (NaiveDateTime, String);

/// One pass over expired traffic, `batch_size` rows examined per batch,
/// same bounded discipline as the verdict prune (see [`run_pass`]).
///
/// Returns where the next pass should start. `None` means this pass reached
/// the end of the window, so the next one rescans from the oldest row and
/// picks up pods that have died since. `Some` means it stopped early, at the
/// per-pass cap or on an error, and the next pass resumes there instead of
/// re-walking the live pods' rows it has already passed over.
async fn run_pod_traffic_pass(
    pool: &DbPool,
    days: u32,
    mut cursor: Option<TrafficCursor>,
) -> Option<TrafficCursor> {
    let batch_size = pod_traffic_batch_size();
    let mut total_deleted: usize = 0;
    let mut total_examined: usize = 0;
    for batch_idx in 0..MAX_BATCHES_PER_PASS {
        let pool = pool.clone();
        let after = cursor.clone();
        let result =
            tokio::task::spawn_blocking(move || -> Result<Option<TrafficBatch>, RetentionError> {
                let mut conn = pool.get().map_err(RetentionError::Pool)?;
                run_pod_traffic_batch(&mut conn, days, batch_size, after.as_ref())
            })
            .await;
        match result {
            Ok(Ok(None)) => {
                if total_deleted == 0 {
                    debug!(
                        examined = total_examined,
                        "pod_traffic retention: 0 rows pruned"
                    );
                } else {
                    info!(
                        rows = total_deleted,
                        examined = total_examined,
                        batches = batch_idx,
                        "pod_traffic retention pruned old rows of pods that no longer exist",
                    );
                }
                return None;
            }
            Ok(Ok(Some(batch))) => {
                total_deleted += usize::try_from(batch.deleted).unwrap_or(0);
                total_examined += usize::try_from(batch.examined).unwrap_or(0);
                cursor = Some((batch.time_stamp, batch.uuid));
            }
            Ok(Err(RetentionError::Pool(e))) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "pod_traffic retention: could not get db conn");
                return cursor;
            }
            Ok(Err(RetentionError::Diesel(e))) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "pod_traffic retention: DELETE failed");
                return cursor;
            }
            Err(e) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "pod_traffic retention task panicked");
                return cursor;
            }
        }
    }
    info!(
        rows = total_deleted,
        examined = total_examined,
        cap = MAX_BATCHES_PER_PASS,
        "pod_traffic retention hit per-pass batch cap; the next interval resumes where this one stopped",
    );
    cursor
}

/// What one batch did: the last row it examined (the next cursor), how
/// many rows it examined and how many of those it deleted.
#[derive(Debug, QueryableByName)]
struct TrafficBatch {
    #[diesel(sql_type = diesel::sql_types::Timestamp)]
    time_stamp: NaiveDateTime,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    uuid: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    examined: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    deleted: i64,
}

/// One batch: examine the next `batch_size` expired rows after `after` and
/// delete those whose pod is gone. `None` when there was nothing left to
/// examine, i.e. the scan has reached the end of the window.
fn run_pod_traffic_batch(
    conn: &mut PgConnection,
    days: u32,
    batch_size: i64,
    after: Option<&TrafficCursor>,
) -> Result<Option<TrafficBatch>, RetentionError> {
    let interval = format!("{} days", days);
    let rows: Vec<TrafficBatch> = match after {
        None => sql_query(POD_TRAFFIC_PRUNE_SQL)
            .bind::<diesel::sql_types::Text, _>(interval)
            .bind::<diesel::sql_types::BigInt, _>(batch_size)
            .load(conn),
        Some((ts, uuid)) => sql_query(POD_TRAFFIC_PRUNE_AFTER_SQL)
            .bind::<diesel::sql_types::Text, _>(interval)
            .bind::<diesel::sql_types::BigInt, _>(batch_size)
            .bind::<diesel::sql_types::Timestamp, _>(*ts)
            .bind::<diesel::sql_types::Varchar, _>(uuid.as_str())
            .load(conn),
    }
    .map_err(RetentionError::Diesel)?;
    Ok(rows.into_iter().next())
}

/// Both prune statements, differing only in the cursor predicate (`$3`,
/// `$4`), built from one text so they cannot drift apart.
///
/// - `candidates` is a plain range scan of `idx_pod_traffic_time_stamp`
///   (`time_stamp DESC, uuid DESC`, walked backwards) that stops at
///   `LIMIT`: oldest rows first, and no new index needed. The liveness test
///   is deliberately NOT in that scan. With it inside, Postgres planned a
///   sequential scan, an anti-join and a sort of every expired row, once
///   per batch; applied to the bounded candidate set instead, a 5 000-row
///   batch over a 2 M-row table measured ~22 ms.
/// - The cursor therefore advances over rows the batch KEPT as well as
///   rows it deleted, which is why the statement returns the last
///   candidate rather than the last deletion. Resuming after the last
///   deletion would re-read every kept row behind it, and a batch of only
///   live pods' rows would look like the end of the window.
/// - `time_stamp` is TIMESTAMP carrying UTC, so the cutoff is built with
///   `timezone('UTC', NOW())`, as for the verdict prune.
/// - A row is kept while `pod_details` holds a live pod of that name in
///   that namespace that was already running when the row was written
///   (module docs). A namespace or start time `pod_details` does not know
///   cannot disprove the match, so it keeps the row: the failure this
///   guards against is a lost policy rule, and keeping a row too long is
///   the cheap direction. The hour of slack on `started_at` absorbs clock
///   skew between the API server, which sets it, and the broker, which
///   stamps rows — a live pod's first rows are exactly the ones it will
///   never report again.
/// - A live pod's row is also deleted once it is SUPERSEDED: a newer row
///   of the same pod has the same direction, protocol, ports and decision
///   and the same in-cluster peer identity, stamped at ingest (#1447) —
///   same `peer_kind`, `peer_namespace` and owning workload, or the peer's
///   own name when it has no owner (a bare pod, a Service). Whatever rule
///   the old row contributes to a generated policy, the newer row still
///   contributes. That is what bounds a live pod whose peers change IP:
///   each run of a CronJob caller arrives from a new pod and a new IP and
///   writes a new row, and without this they piled up forever. Only
///   `pod` and `service` peers qualify. A `node` peer renders as an
///   `ipBlock` for that node's IP, so another node's row does not carry
///   its rule, and a row with no stored identity (external, unresolved,
///   pre-#1447) has nothing to match on — those are what the opt-in
///   per-pod cap ([`run_pod_traffic_cap`]) is for. The newest row of each
///   group has nothing newer than itself, so a group never loses its last
///   row. The lookup is served by `idx_pod_traffic_supersede`
///   (2026-09-26-100000), a partial index over exactly those peer kinds.
macro_rules! pod_traffic_prune_sql {
    ($cursor:literal) => {
        concat!(
            "WITH candidates AS (\
                 SELECT t.uuid, t.time_stamp, t.pod_name, t.pod_namespace, \
                        t.traffic_type, t.ip_protocol, t.pod_port, \
                        t.traffic_in_out_port, t.decision, t.peer_kind, \
                        t.peer_namespace, t.peer_name, t.peer_workload_kind, \
                        t.peer_workload_name \
                 FROM pod_traffic t \
                 WHERE t.time_stamp < timezone('UTC', NOW()) - $1::interval ",
            $cursor,
            "ORDER BY t.time_stamp, t.uuid \
                 LIMIT $2 \
             ), \
             deleted AS (\
                 DELETE FROM pod_traffic d \
                 USING candidates c \
                 WHERE d.uuid = c.uuid \
                   AND (NOT EXISTS (\
                     SELECT 1 FROM pod_details p \
                     WHERE p.pod_name = c.pod_name \
                       AND p.is_dead = false \
                       AND (p.pod_namespace IS NULL OR c.pod_namespace IS NULL \
                            OR p.pod_namespace = c.pod_namespace) \
                       AND (p.started_at IS NULL \
                            OR c.time_stamp >= p.started_at - INTERVAL '1 hour')\
                   ) \
                   OR (c.peer_kind IN ('pod', 'service') \
                     AND EXISTS (\
                     SELECT 1 FROM pod_traffic n \
                     WHERE n.peer_kind IN ('pod', 'service') \
                       AND n.pod_name = c.pod_name \
                       AND n.peer_namespace = c.peer_namespace \
                       AND COALESCE(n.peer_workload_name, n.peer_name) \
                           = COALESCE(c.peer_workload_name, c.peer_name) \
                       AND n.time_stamp >= c.time_stamp \
                       AND (n.time_stamp, n.uuid) > (c.time_stamp, c.uuid) \
                       AND n.peer_kind = c.peer_kind \
                       AND COALESCE(n.peer_workload_kind, '') \
                           = COALESCE(c.peer_workload_kind, '') \
                       AND n.pod_namespace IS NOT DISTINCT FROM c.pod_namespace \
                       AND n.traffic_type IS NOT DISTINCT FROM c.traffic_type \
                       AND n.ip_protocol IS NOT DISTINCT FROM c.ip_protocol \
                       AND n.pod_port IS NOT DISTINCT FROM c.pod_port \
                       AND n.traffic_in_out_port IS NOT DISTINCT FROM c.traffic_in_out_port \
                       AND n.decision IS NOT DISTINCT FROM c.decision\
                   ))) \
                 RETURNING d.uuid \
             ) \
             SELECT c.time_stamp, c.uuid, \
                    (SELECT count(*) FROM candidates) AS examined, \
                    (SELECT count(*) FROM deleted) AS deleted \
             FROM candidates c \
             ORDER BY c.time_stamp DESC, c.uuid DESC \
             LIMIT 1"
        )
    };
}

/// First batch of a scan. A constant so the live-database test runs the
/// SAME SQL the loop issues.
pub(crate) const POD_TRAFFIC_PRUNE_SQL: &str = pod_traffic_prune_sql!("");

/// Every later batch: resumes strictly after the cursor `($3, $4)`.
pub(crate) const POD_TRAFFIC_PRUNE_AFTER_SQL: &str =
    pod_traffic_prune_sql!("AND (t.time_stamp, t.uuid) > ($3, $4) ");

/// One pass pruning pods that have been dead longer than the retention
/// window. `pod_details` keeps a row per pod ever seen and dead pods are
/// otherwise never removed, so it grows unbounded with pod churn — and
/// `/pod/info` returns the whole table including each pod's full manifest
/// JSON, so the bloat directly degrades both the broker (large serialise +
/// memory spike) and the frontend. Reuses the same window, batch size and
/// batched-DELETE discipline as the verdict prune.
async fn run_dead_pod_pass(pool: &DbPool, days: u32) {
    let batch_size = retention_batch_size();
    let mut total_deleted: usize = 0;
    for batch_idx in 0..MAX_BATCHES_PER_PASS {
        let pool = pool.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
            run_dead_pod_batch(&pool, days, batch_size)
        })
        .await;
        match result {
            Ok(Ok(0)) => {
                if total_deleted == 0 {
                    debug!("pod_details retention: 0 dead pods pruned");
                } else {
                    info!(
                        rows = total_deleted,
                        batches = batch_idx,
                        "pod_details retention pruned dead pods",
                    );
                }
                return;
            }
            Ok(Ok(n)) => total_deleted += n,
            Ok(Err(RetentionError::Pool(e))) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "pod_details retention: could not get db conn");
                return;
            }
            Ok(Err(RetentionError::Diesel(e))) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "pod_details retention: DELETE failed");
                return;
            }
            Err(e) => {
                warn!(error = %e, pruned_before_failure = total_deleted, "pod_details retention task panicked");
                return;
            }
        }
    }
    info!(
        rows = total_deleted,
        cap = MAX_BATCHES_PER_PASS,
        "pod_details retention hit per-pass batch cap; remaining dead pods will be pruned on next interval",
    );
}

/// Batched DELETE of dead pods older than the window. pod_details' PK is
/// pod_name, so the CTE selects and deletes by pod_name.
fn run_dead_pod_batch(pool: &DbPool, days: u32, batch_size: i64) -> Result<usize, RetentionError> {
    let mut conn = pool.get().map_err(RetentionError::Pool)?;
    let interval = format!("{} days", days);
    let deleted = sql_query(
        "WITH expired AS (\
             SELECT pod_name FROM pod_details \
             WHERE is_dead = true AND time_stamp < timezone('UTC', NOW()) - $1::interval \
             ORDER BY pod_name \
             LIMIT $2 \
         ) \
         DELETE FROM pod_details WHERE pod_name IN (SELECT pod_name FROM expired)",
    )
    .bind::<diesel::sql_types::Text, _>(interval)
    .bind::<diesel::sql_types::BigInt, _>(batch_size)
    .execute(&mut conn)
    .map_err(RetentionError::Diesel)?;
    Ok(deleted)
}

/// One cleanup pass — issues batched DELETEs in a loop until the
/// window is empty, the per-pass cap is hit, or an error occurs.
/// Each batch runs in its own `spawn_blocking` task so the broker's
/// blocking pool stays responsive to other work between iterations.
/// Logs the cumulative result and never propagates errors.
async fn run_pass(pool: &DbPool, days: u32) {
    let batch_size = retention_batch_size();
    let mut total_deleted: usize = 0;
    for batch_idx in 0..MAX_BATCHES_PER_PASS {
        let pool = pool.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
            run_batch(&pool, days, batch_size)
        })
        .await;
        match result {
            Ok(Ok(0)) => {
                if total_deleted == 0 {
                    debug!("audit_verdicts retention: 0 rows pruned");
                } else {
                    info!(
                        rows = total_deleted,
                        batches = batch_idx,
                        "audit_verdicts retention pruned old rows",
                    );
                }
                return;
            }
            Ok(Ok(n)) => total_deleted += n,
            Ok(Err(RetentionError::Pool(e))) => {
                warn!(
                    error = %e,
                    pruned_before_failure = total_deleted,
                    "audit_verdicts retention: could not get db conn",
                );
                return;
            }
            Ok(Err(RetentionError::Diesel(e))) => {
                warn!(
                    error = %e,
                    pruned_before_failure = total_deleted,
                    "audit_verdicts retention: DELETE failed",
                );
                return;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    pruned_before_failure = total_deleted,
                    "audit_verdicts retention task panicked",
                );
                return;
            }
        }
    }
    // Hit the per-pass cap with rows still expired. Not a problem —
    // the next interval picks up where this one left off — but worth
    // surfacing so operators notice if every pass keeps hitting the
    // cap (indicates a sustained backlog that the default cadence
    // can't keep up with; bump retention.intervalSeconds DOWN or
    // batch size up).
    info!(
        rows = total_deleted,
        cap = MAX_BATCHES_PER_PASS,
        "audit_verdicts retention hit per-pass batch cap; remaining rows will be pruned on next interval",
    );
}

/// Execute a single batched DELETE. Returns the number of rows
/// actually removed (0 means the window is empty). Kept synchronous
/// so the caller can run it inside `spawn_blocking`.
fn run_batch(pool: &DbPool, days: u32, batch_size: i64) -> Result<usize, RetentionError> {
    let mut conn = pool.get().map_err(RetentionError::Pool)?;
    let interval = format!("{} days", days);
    // Postgres doesn't allow LIMIT directly on DELETE. The CTE
    // pattern selects up to N expired rows by primary key, then
    // deletes only those — bounded lock hold + bounded WAL chunk per
    // batch.
    //
    // The interval value is server-side computed using a
    // parameterised bind. We construct the literal in code and bind
    // as text — the server casts to interval. That avoids any
    // SQL-injection surface even if `days` were ever sourced from
    // user input (it isn't, but defensible).
    // observed_at is stored as TIMESTAMP (no timezone) carrying UTC
    // values (audit.rs sets it via Utc::now().naive_utc()). Use
    // `timezone('UTC', NOW())` so the right-hand side is a UTC-naive
    // timestamp regardless of the postgres session timezone. The
    // previous `NOW() - interval` form relied on the session TZ being
    // UTC; a misconfigured operator running postgres with a non-UTC
    // default would compute the wrong retention window (typically off
    // by single-digit hours on a multi-day boundary — small but real
    // correctness drift).
    let deleted = sql_query(
        "WITH expired AS (\
             SELECT id FROM audit_verdicts \
             WHERE observed_at < timezone('UTC', NOW()) - $1::interval \
             ORDER BY id \
             LIMIT $2 \
         ) \
         DELETE FROM audit_verdicts WHERE id IN (SELECT id FROM expired)",
    )
    .bind::<diesel::sql_types::Text, _>(interval)
    .bind::<diesel::sql_types::BigInt, _>(batch_size)
    .execute(&mut conn)
    .map_err(RetentionError::Diesel)?;
    Ok(deleted)
}

// ---------------------------------------------------------------------
// Compute history (design D5)
// ---------------------------------------------------------------------

const DEFAULT_COMPUTE_RETENTION_DAYS: u32 = 7;
const DEFAULT_COMPUTE_MINUTE_HOURS: u32 = 24;
const DEFAULT_COMPUTE_INTERVAL_SECS: u64 = 600;
/// A `pod_compute_latest` row not refreshed for this long is a dead
/// container (the controller upserts every 5 s; 10 minutes is two
/// orders of magnitude of slack for a slow node).
const COMPUTE_LATEST_STALE_SECS: i64 = 600;
/// A `node_compute_latest` row not refreshed for this long belongs to a
/// node that left the cluster.
///
/// The table is upserted in place, one row per node, so it never grew
/// with cadence — but nothing removed a row when its node went away, so
/// it grew with node churn instead. On a 44-node cluster under an
/// autoscaler that replaces nodes daily it held 1 232 rows after eleven
/// days, and `GET /compute/nodes`, which serves the whole table to every
/// open UI on every ~5 s poll, shipped half a megabyte of nodes that no
/// longer existed.
///
/// An hour rather than the 10 minutes `pod_compute_latest` gets, because
/// the node row is refreshed on two very different cadences. A Controller
/// with the gauges on posts it every sample (`compute.sampleInterval`,
/// 5 s); one with the gauges OFF posts only a node-only heartbeat every
/// five minutes (`HEARTBEAT_INTERVAL` in the controller's
/// `compute_sampler.rs`), and that heartbeat is the only thing that lets
/// the UI say a node's pods are `off` rather than `pending`. At the pod
/// window, two missed heartbeats — a Controller rollout pulling a fresh
/// image plus one slow tick — would drop the row and tell an operator who
/// switched the feature off on purpose that their pods are "not yet
/// sampled". Twelve missed heartbeats, or 720 missed samples, is a node
/// that is gone. The pod rows go first, so between the two windows the
/// UI keeps explaining WHY a silent node's pods have no gauge before it
/// collapses to `pending`.
///
/// Not days, the way `seccomp_denial_nodes` is pruned, because that table
/// is consulted one row at a time by a liveness check whereas this one is
/// served whole: every departed node costs every viewer bandwidth until it
/// is pruned. And there is no churn to avoid by keeping the row through a
/// long Controller outage — the first sample after recovery recreates it
/// in the same upsert that would have refreshed it. Cordoned nodes keep
/// running the DaemonSet, so they keep posting and are never at risk; a
/// node rebooting for a kernel upgrade is back well inside the hour.
///
/// A pruned row reads as `pending` in the UI (`nodeComputeState`), the
/// right answer for a node that no longer exists. The findings engine
/// reads a missing node row as zero node pressure, so at worst it withholds
/// a `memory-pressure` finding on a node that has posted nothing for an
/// hour; it cannot invent one. The table's migration
/// (`2026-09-10-100004_node_compute_latest`) still says "Stale rows are
/// left in place": that comment predates this prune, and shipped
/// migrations are not edited.
pub(crate) const NODE_COMPUTE_LATEST_STALE_SECS: i64 = 3_600;
/// Width of a downsampled row.
pub(crate) const DOWNSAMPLE_BUCKET_SECS: i64 = 300;
/// Whole buckets folded per transaction. Two buckets = 10 minutes of
/// minute rows = 10 x (containers on the cluster) rows read, 2 x that
/// written: ~30 000 rows deleted per batch on a 3 000-container
/// cluster, the same order as `MAX_BATCH_SIZE` for the audit prune.
pub(crate) const DOWNSAMPLE_BUCKETS_PER_BATCH: i64 = 2;
/// Batches per pass: 60 x 10 minutes = 10 hours of backlog per pass,
/// so a broker that was down for a day catches up in three passes
/// without monopolising the blocking pool for one.
const MAX_DOWNSAMPLE_BATCHES_PER_PASS: u32 = 60;

/// `COMPUTE_HISTORY_RETENTION_DAYS` (default 7). 0 disables history:
/// the ingest handler drops minute batches and this loop skips the
/// downsample and prune. Shared with `compute_api.rs`.
pub(crate) fn compute_history_retention_days() -> u32 {
    std::env::var("COMPUTE_HISTORY_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_COMPUTE_RETENTION_DAYS)
}

/// `COMPUTE_HISTORY_MINUTE_HOURS` (default 24): how long minute rows
/// are kept before being folded into 5-minute rows. Floored at 1 so the
/// engine's 5-minute window always sees minute rows.
fn compute_minute_hours() -> u32 {
    std::env::var("COMPUTE_HISTORY_MINUTE_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|h| h.max(1))
        .unwrap_or(DEFAULT_COMPUTE_MINUTE_HOURS)
}

fn compute_retention_interval() -> Duration {
    let secs = std::env::var("COMPUTE_RETENTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_COMPUTE_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}

/// Floor a timestamp to the start of its 5-minute bucket (UTC-naive,
/// same epoch arithmetic the SQL uses).
pub(crate) fn floor_to_bucket(ts: NaiveDateTime) -> NaiveDateTime {
    let epoch = ts.and_utc().timestamp();
    let floored = epoch.div_euclid(DOWNSAMPLE_BUCKET_SECS) * DOWNSAMPLE_BUCKET_SECS;
    chrono::DateTime::from_timestamp(floored, 0)
        .map(|d| d.naive_utc())
        .unwrap_or(ts)
}

/// The `[start, end)` range of WHOLE buckets one downsample batch folds,
/// given the oldest remaining minute row and the cutoff below which
/// minute rows are eligible. `None` when nothing can be folded yet.
///
/// Two invariants keep the fold idempotent and duplicate-free:
/// - it starts at the oldest row's bucket, so buckets are folded oldest
///   first and a batch never skips one;
/// - it never reaches into the bucket that contains the cutoff. That
///   bucket may still be receiving minute rows on its far side; folding
///   half of it now and the other half later would produce two 300 s
///   rows for the same (container, bucket).
pub(crate) fn downsample_range(
    oldest_minute_row: NaiveDateTime,
    cutoff: NaiveDateTime,
    buckets: i64,
) -> Option<(NaiveDateTime, NaiveDateTime)> {
    let start = floor_to_bucket(oldest_minute_row);
    let end_limit = floor_to_bucket(cutoff);
    if start >= end_limit {
        return None;
    }
    let span = chrono::Duration::seconds(DOWNSAMPLE_BUCKET_SECS * buckets.max(1));
    let end = (start + span).min(end_limit);
    Some((start, end))
}

/// One compute retention pass: downsample, prune, drop stale latest
/// rows (containers, then nodes). Each step is independent — a failure
/// in one is logged and the next still runs — and each batch is its own
/// `spawn_blocking`.
async fn run_compute_pass(pool: &DbPool, days: u32, minute_hours: u32) {
    if days > 0 {
        run_downsample(pool, minute_hours).await;
        run_compute_prune(pool, "pod_compute_history", days).await;
        run_compute_prune(pool, "pod_contention_history", days).await;
    }
    run_stale_latest(pool).await;
    run_stale_node_latest(pool).await;
}

async fn run_downsample(pool: &DbPool, minute_hours: u32) {
    let mut folded_total = 0usize;
    let mut written_total = 0usize;
    for batch_idx in 0..MAX_DOWNSAMPLE_BATCHES_PER_PASS {
        let pool = pool.clone();
        let result =
            tokio::task::spawn_blocking(move || run_downsample_batch(&pool, minute_hours)).await;
        match result {
            Ok(Ok(None)) => {
                if folded_total == 0 {
                    debug!("compute downsample: nothing to fold");
                } else {
                    info!(
                        minute_rows_folded = folded_total,
                        five_minute_rows = written_total,
                        batches = batch_idx,
                        "compute downsample folded minute rows",
                    );
                }
                return;
            }
            Ok(Ok(Some((written, folded)))) => {
                written_total += written;
                folded_total += folded;
            }
            Ok(Err(e)) => {
                warn!(error = %e, folded_before_failure = folded_total, "compute downsample failed");
                return;
            }
            Err(e) => {
                warn!(error = %e, folded_before_failure = folded_total, "compute downsample task panicked");
                return;
            }
        }
    }
    info!(
        minute_rows_folded = folded_total,
        cap = MAX_DOWNSAMPLE_BATCHES_PER_PASS,
        "compute downsample hit per-pass batch cap; remaining buckets fold on next interval",
    );
}

#[derive(diesel::QueryableByName)]
struct OldestRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamp>)]
    ts: Option<chrono::NaiveDateTime>,
}

/// Fold one bucket range. Returns `(five_minute_rows_written,
/// minute_rows_deleted)`, or `None` when no eligible bucket remains.
///
/// The INSERT ... SELECT and the DELETE share one transaction and one
/// predicate (`resolution_secs = 60 AND ts >= $1 AND ts < $2`), so a
/// crash between them cannot leave a bucket both folded and unfolded.
/// The histogram is summed element-wise through `unnest ... WITH
/// ORDINALITY` in a LATERAL subquery because Postgres has no array
/// aggregate that adds arrays. Quantile columns take the max over the
/// bucket (a p99 of five p99s is not a p99, but the max is a safe upper
/// bound, and the summed `runq_hist` is there to re-derive an exact
/// one). Written with epoch arithmetic rather than `date_bin` so it runs
/// on any Postgres an operator may bring.
fn run_downsample_batch(
    pool: &DbPool,
    minute_hours: u32,
) -> Result<Option<(usize, usize)>, RetentionError> {
    use diesel::sql_types::Timestamp;
    let mut conn = pool.get().map_err(RetentionError::Pool)?;
    let now = chrono::Utc::now().naive_utc();
    let cutoff = now - chrono::Duration::hours(i64::from(minute_hours));
    let oldest = sql_query(
        "SELECT min(ts) AS ts FROM pod_compute_history WHERE resolution_secs = 60 AND ts < $1",
    )
    .bind::<Timestamp, _>(cutoff)
    .get_result::<OldestRow>(&mut conn)
    .map_err(RetentionError::Diesel)?
    .ts;
    let Some(oldest) = oldest else {
        return Ok(None);
    };
    let Some((start, end)) = downsample_range(oldest, cutoff, DOWNSAMPLE_BUCKETS_PER_BATCH) else {
        return Ok(None);
    };
    conn.transaction::<_, RetentionError, _>(|conn| {
        let written = sql_query(DOWNSAMPLE_INSERT_SQL)
            .bind::<Timestamp, _>(start)
            .bind::<Timestamp, _>(end)
            .execute(conn)
            .map_err(RetentionError::Diesel)?;
        let deleted = sql_query(
            "DELETE FROM pod_compute_history \
             WHERE resolution_secs = 60 AND ts >= $1 AND ts < $2",
        )
        .bind::<Timestamp, _>(start)
        .bind::<Timestamp, _>(end)
        .execute(conn)
        .map_err(RetentionError::Diesel)?;
        debug!(
            %start,
            %end,
            written,
            deleted,
            "compute downsample batch"
        );
        Ok(Some((written, deleted)))
    })
}

const DOWNSAMPLE_INSERT_SQL: &str = "\
INSERT INTO pod_compute_history (\
    container_uid, pod_uid, namespace, pod_name, container, node, ts, resolution_secs, \
    cpu_usage_millis_avg, cpu_usage_millis_max, cpu_usage_millis_last, \
    cpu_quota_usec, cpu_period_usec, cpu_request_millis, cpu_limit_millis, \
    cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec, \
    cpu_psi_some10_avg, cpu_psi_some10_max, cpu_psi_full10_avg, cpu_psi_full10_max, \
    mem_current_avg, mem_current_max, mem_current_last, \
    mem_working_set_avg, mem_working_set_max, mem_working_set_last, \
    mem_limit, mem_request, \
    mem_psi_some10_avg, mem_psi_some10_max, mem_psi_full10_avg, mem_psi_full10_max, \
    mem_events_high, mem_events_max, mem_oom_kill, mem_refault, mem_pgmajfault, \
    runq_count, runq_p50_us, runq_p95_us, runq_p99_us, runq_max_us, runq_overflow, runq_hist) \
SELECT g.container_uid, g.pod_uid, g.namespace, g.pod_name, g.container, g.node, g.bucket, 300, \
    g.cpu_usage_millis_avg, g.cpu_usage_millis_max, g.cpu_usage_millis_last, \
    g.cpu_quota_usec, g.cpu_period_usec, g.cpu_request_millis, g.cpu_limit_millis, \
    g.cpu_nr_periods, g.cpu_nr_throttled, g.cpu_throttled_usec, \
    g.cpu_psi_some10_avg, g.cpu_psi_some10_max, g.cpu_psi_full10_avg, g.cpu_psi_full10_max, \
    g.mem_current_avg, g.mem_current_max, g.mem_current_last, \
    g.mem_working_set_avg, g.mem_working_set_max, g.mem_working_set_last, \
    g.mem_limit, g.mem_request, \
    g.mem_psi_some10_avg, g.mem_psi_some10_max, g.mem_psi_full10_avg, g.mem_psi_full10_max, \
    g.mem_events_high, g.mem_events_max, g.mem_oom_kill, g.mem_refault, g.mem_pgmajfault, \
    g.runq_count, g.runq_p50_us, g.runq_p95_us, g.runq_p99_us, g.runq_max_us, g.runq_overflow, h.hist \
FROM ( \
    SELECT container_uid, \
        min(pod_uid) AS pod_uid, min(namespace) AS namespace, min(pod_name) AS pod_name, \
        min(container) AS container, min(node) AS node, \
        (to_timestamp(floor(extract(epoch FROM ts) / 300) * 300) AT TIME ZONE 'UTC') AS bucket, \
        avg(cpu_usage_millis_avg) AS cpu_usage_millis_avg, \
        max(cpu_usage_millis_max) AS cpu_usage_millis_max, \
        (array_agg(cpu_usage_millis_last ORDER BY ts DESC))[1] AS cpu_usage_millis_last, \
        (array_agg(cpu_quota_usec ORDER BY ts DESC))[1] AS cpu_quota_usec, \
        (array_agg(cpu_period_usec ORDER BY ts DESC))[1] AS cpu_period_usec, \
        (array_agg(cpu_request_millis ORDER BY ts DESC))[1] AS cpu_request_millis, \
        (array_agg(cpu_limit_millis ORDER BY ts DESC))[1] AS cpu_limit_millis, \
        sum(cpu_nr_periods)::bigint AS cpu_nr_periods, \
        sum(cpu_nr_throttled)::bigint AS cpu_nr_throttled, \
        sum(cpu_throttled_usec)::bigint AS cpu_throttled_usec, \
        avg(cpu_psi_some10_avg) AS cpu_psi_some10_avg, max(cpu_psi_some10_max) AS cpu_psi_some10_max, \
        avg(cpu_psi_full10_avg) AS cpu_psi_full10_avg, max(cpu_psi_full10_max) AS cpu_psi_full10_max, \
        avg(mem_current_avg)::bigint AS mem_current_avg, max(mem_current_max) AS mem_current_max, \
        (array_agg(mem_current_last ORDER BY ts DESC))[1] AS mem_current_last, \
        avg(mem_working_set_avg)::bigint AS mem_working_set_avg, \
        max(mem_working_set_max) AS mem_working_set_max, \
        (array_agg(mem_working_set_last ORDER BY ts DESC))[1] AS mem_working_set_last, \
        (array_agg(mem_limit ORDER BY ts DESC))[1] AS mem_limit, \
        (array_agg(mem_request ORDER BY ts DESC))[1] AS mem_request, \
        avg(mem_psi_some10_avg) AS mem_psi_some10_avg, max(mem_psi_some10_max) AS mem_psi_some10_max, \
        avg(mem_psi_full10_avg) AS mem_psi_full10_avg, max(mem_psi_full10_max) AS mem_psi_full10_max, \
        sum(mem_events_high)::bigint AS mem_events_high, sum(mem_events_max)::bigint AS mem_events_max, \
        sum(mem_oom_kill)::bigint AS mem_oom_kill, sum(mem_refault)::bigint AS mem_refault, \
        sum(mem_pgmajfault)::bigint AS mem_pgmajfault, \
        sum(runq_count)::bigint AS runq_count, max(runq_p50_us) AS runq_p50_us, \
        max(runq_p95_us) AS runq_p95_us, max(runq_p99_us) AS runq_p99_us, \
        max(runq_max_us) AS runq_max_us, sum(runq_overflow)::bigint AS runq_overflow \
    FROM pod_compute_history \
    WHERE resolution_secs = 60 AND ts >= $1 AND ts < $2 \
    GROUP BY container_uid, bucket \
) g \
LEFT JOIN LATERAL ( \
    SELECT array_agg(x.s ORDER BY x.i) AS hist \
    FROM ( \
        SELECT u.i, sum(u.v)::bigint AS s \
        FROM pod_compute_history p, unnest(p.runq_hist) WITH ORDINALITY AS u(v, i) \
        WHERE p.container_uid = g.container_uid AND p.resolution_secs = 60 \
          AND p.ts >= g.bucket AND p.ts < g.bucket + interval '5 minutes' \
        GROUP BY u.i \
    ) x \
) h ON true";

/// Batched prune of one compute history table by `ts`. The table name
/// is a `&'static str` chosen by the caller from two literals, never
/// user input; the interval is bound.
async fn run_compute_prune(pool: &DbPool, table: &'static str, days: u32) {
    let batch_size = retention_batch_size();
    let mut total_deleted = 0usize;
    for batch_idx in 0..MAX_BATCHES_PER_PASS {
        let pool = pool.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
            let mut conn = pool.get().map_err(RetentionError::Pool)?;
            let interval = format!("{} days", days);
            let sql = format!(
                "WITH expired AS (\
                     SELECT id FROM {table} \
                     WHERE ts < timezone('UTC', NOW()) - $1::interval \
                     ORDER BY ts \
                     LIMIT $2 \
                 ) \
                 DELETE FROM {table} WHERE id IN (SELECT id FROM expired)"
            );
            sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(interval)
                .bind::<diesel::sql_types::BigInt, _>(batch_size)
                .execute(&mut conn)
                .map_err(RetentionError::Diesel)
        })
        .await;
        match result {
            Ok(Ok(0)) => {
                if total_deleted == 0 {
                    debug!(table, "compute retention: 0 rows pruned");
                } else {
                    info!(
                        table,
                        rows = total_deleted,
                        batches = batch_idx,
                        "compute retention pruned old rows"
                    );
                }
                return;
            }
            Ok(Ok(n)) => total_deleted += n,
            Ok(Err(e)) => {
                warn!(table, error = %e, pruned_before_failure = total_deleted, "compute retention: DELETE failed");
                return;
            }
            Err(e) => {
                warn!(table, error = %e, pruned_before_failure = total_deleted, "compute retention task panicked");
                return;
            }
        }
    }
    info!(
        table,
        rows = total_deleted,
        cap = MAX_BATCHES_PER_PASS,
        "compute retention hit per-pass batch cap; remaining rows will be pruned on next interval"
    );
}

/// Drop `pod_compute_latest` rows the controller stopped refreshing.
/// The table is bounded by live-container count, so one bounded DELETE
/// (still LIMITed through the CTE, for the pathological case of a whole
/// cluster's controllers going away at once) is enough.
async fn run_stale_latest(pool: &DbPool) {
    let pool = pool.clone();
    let batch_size = retention_batch_size();
    let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
        let mut conn = pool.get().map_err(RetentionError::Pool)?;
        sql_query(
            "WITH stale AS (\
                 SELECT container_uid FROM pod_compute_latest \
                 WHERE updated_at < timezone('UTC', NOW()) - $1::interval \
                 ORDER BY updated_at \
                 LIMIT $2 \
             ) \
             DELETE FROM pod_compute_latest \
             WHERE container_uid IN (SELECT container_uid FROM stale)",
        )
        .bind::<diesel::sql_types::Text, _>(format!("{} seconds", COMPUTE_LATEST_STALE_SECS))
        .bind::<diesel::sql_types::BigInt, _>(batch_size)
        .execute(&mut conn)
        .map_err(RetentionError::Diesel)
    })
    .await;
    match result {
        Ok(Ok(0)) => debug!("pod_compute_latest: no stale containers"),
        Ok(Ok(n)) => info!(rows = n, "pod_compute_latest: pruned stale containers"),
        Ok(Err(e)) => warn!(error = %e, "pod_compute_latest stale prune failed"),
        Err(e) => warn!(error = %e, "pod_compute_latest stale prune task panicked"),
    }
}

/// The statement `run_stale_node_latest` issues, as a constant so the live
/// test runs the SAME SQL rather than a copy that can drift from it. Same
/// shape as the pod prune above: the CTE bounds the DELETE through
/// `LIMIT`, and `ORDER BY updated_at` hands it the longest-departed nodes
/// first, so a pass that hits the cap still retires the oldest debt.
///
/// The staleness predicate appears twice on purpose. The CTE alone is a
/// race: a node whose Controller comes back mid-pass upserts its row in
/// the same instant the DELETE reaches it, the DELETE waits on the row
/// lock, and under READ COMMITTED Postgres then re-evaluates only the
/// outer `WHERE` against the refreshed row — `node IN (stale)` is still
/// true, because the CTE was materialised from the pass's snapshot, so the
/// row that was just refreshed is deleted anyway (verified on Postgres
/// 18). Repeating the window on the outer DELETE makes that recheck see
/// the new `updated_at` and skip the row. The pod prune above has the
/// same shape and the same gap; it is left for a follow-up. `$1` is bound
/// once and referenced twice, which Postgres allows.
///
/// No index on `updated_at`: the table is node-count sized once this
/// prune has run, and even the one-off backlog on a cluster upgrading to
/// it (every node that churned since the feature shipped) is a few
/// thousand rows — a sequential scan and sort that finishes in
/// milliseconds, nowhere near the pool's 30 s statement timeout.
const NODE_COMPUTE_STALE_PRUNE_SQL: &str = "WITH stale AS (\
         SELECT node FROM node_compute_latest \
         WHERE updated_at < timezone('UTC', NOW()) - $1::interval \
         ORDER BY updated_at \
         LIMIT $2 \
     ) \
     DELETE FROM node_compute_latest \
     WHERE node IN (SELECT node FROM stale) \
       AND updated_at < timezone('UTC', NOW()) - $1::interval";

/// Drop `node_compute_latest` rows for nodes that left the cluster (see
/// `NODE_COMPUTE_LATEST_STALE_SECS`). One bounded DELETE per pass, like
/// the pod prune: the live table is node-count sized, so a pass whose
/// batch cap is hit — only ever the upgrade backlog — simply finishes on
/// the next interval.
async fn run_stale_node_latest(pool: &DbPool) {
    let pool = pool.clone();
    let batch_size = retention_batch_size();
    let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
        let mut conn = pool.get().map_err(RetentionError::Pool)?;
        prune_stale_node_latest(&mut conn, batch_size)
    })
    .await;
    match result {
        Ok(Ok(0)) => debug!("node_compute_latest: no departed nodes"),
        Ok(Ok(n)) => info!(rows = n, "node_compute_latest: pruned departed nodes"),
        Ok(Err(e)) => warn!(error = %e, "node_compute_latest stale prune failed"),
        Err(e) => warn!(error = %e, "node_compute_latest stale prune task panicked"),
    }
}

/// The blocking half of `run_stale_node_latest`, on a bare connection so
/// the live test can drive the exact statement and window the loop uses
/// against the shipped schema.
fn prune_stale_node_latest(
    conn: &mut PgConnection,
    batch_size: i64,
) -> Result<usize, RetentionError> {
    sql_query(NODE_COMPUTE_STALE_PRUNE_SQL)
        .bind::<diesel::sql_types::Text, _>(format!("{} seconds", NODE_COMPUTE_LATEST_STALE_SECS))
        .bind::<diesel::sql_types::BigInt, _>(batch_size)
        .execute(conn)
        .map_err(RetentionError::Diesel)
}

#[derive(Debug, thiserror::Error)]
enum RetentionError {
    #[error("connection pool: {0}")]
    Pool(#[from] diesel::r2d2::PoolError),
    #[error("delete: {0}")]
    Diesel(#[from] diesel::result::Error),
}

fn retention_days() -> u32 {
    std::env::var("AUDIT_VERDICTS_RETENTION_DAYS")
        .ok()
        // Trim before parse — consistent with the env-var
        // whitespace-defense applied across all 5 services and the
        // audit semaphore's AUDIT_INFLIGHT_PERMITS env. Without
        // trim, "30\n" (the typical copy-paste artefact) falls back
        // to the safe default — same operator-confusion class.
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

fn retention_interval() -> Duration {
    let secs = std::env::var("AUDIT_VERDICTS_RETENTION_INTERVAL_SECS")
        .ok()
        // Same trim defense — see retention_days.
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}

/// Rows deleted per batch. Clamped to [MIN_BATCH_SIZE, MAX_BATCH_SIZE]
/// so a typo can't either hammer the DB (n=1 → MAX_BATCHES_PER_PASS
/// round-trips for nothing) or lock the table (n=10M → unbatched
/// behavior). Configurable via AUDIT_VERDICTS_RETENTION_BATCH_SIZE.
fn retention_batch_size() -> i64 {
    std::env::var("AUDIT_VERDICTS_RETENTION_BATCH_SIZE")
        .ok()
        // Same trim defense — see retention_days.
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE))
        .unwrap_or(DEFAULT_BATCH_SIZE)
}

// ---------------------------------------------------------------------
// Image inventory (#1533)
// ---------------------------------------------------------------------
//
// `workload_containers` rows are keyed per digest and refreshed (at most
// every image_inventory::REFRESH_SECS) by every /pod/spec post of a live
// pod running that digest, so a row not refreshed for the window is a
// digest no running pod has reported: a finished rollout's old image, a
// deleted workload, a renamed container. It is pruned even while its
// workload keeps running other digests. `images` rows are
// pruned once they are both stale and referenced by no
// `workload_containers` row — in that order, so one pass can retire a
// deleted workload's container rows and then the digests they held.
//
// - `IMAGE_INVENTORY_RETENTION_DAYS` (default 30; 0 disables)
// - `IMAGE_INVENTORY_RETENTION_INTERVAL_SECS` (default 3600, floor 60)
// - `IMAGE_INVENTORY_RETENTION_BATCH_SIZE` (default 5 000, clamped to
//   [100, 100 000])

const DEFAULT_IMAGE_INVENTORY_RETENTION_DAYS: u32 = 30;
const DEFAULT_IMAGE_INVENTORY_INTERVAL_SECS: u64 = 3600;

fn image_inventory_retention_days() -> u32 {
    std::env::var("IMAGE_INVENTORY_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_IMAGE_INVENTORY_RETENTION_DAYS)
}

fn image_inventory_retention_interval() -> Duration {
    let secs = std::env::var("IMAGE_INVENTORY_RETENTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_IMAGE_INVENTORY_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}

fn image_inventory_batch_size() -> i64 {
    std::env::var("IMAGE_INVENTORY_RETENTION_BATCH_SIZE")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE))
        .unwrap_or(DEFAULT_BATCH_SIZE)
}

/// Batched prune of (workload, container, digest) rows no running pod has
/// refreshed within the window. Deletes by primary key; oldest first.
/// `ref_seen_at` (a pod stuck pulling the same ref) keeps the most recent
/// digest for that ref too, so a long ImagePullBackOff does not erase the
/// last known image of the workload.
pub(crate) const WORKLOAD_CONTAINERS_PRUNE_SQL: &str = "WITH expired AS (\
         SELECT cluster_id, pod_namespace, workload_kind, workload_name, container_name, \
                image_digest \
         FROM workload_containers \
         WHERE last_seen < timezone('UTC', NOW()) - $1::interval \
           AND (ref_seen_at IS NULL OR ref_seen_at < timezone('UTC', NOW()) - $1::interval) \
         ORDER BY last_seen \
         LIMIT $2 \
     ) \
     DELETE FROM workload_containers wc USING expired e \
     WHERE wc.cluster_id = e.cluster_id AND wc.pod_namespace = e.pod_namespace \
       AND wc.workload_kind = e.workload_kind AND wc.workload_name = e.workload_name \
       AND wc.container_name = e.container_name AND wc.image_digest = e.image_digest";

/// Batched prune of images last seen before the window that no container
/// row still references. A digest still referenced is kept however old
/// its `last_seen` — the reference is the evidence it runs.
pub(crate) const IMAGES_PRUNE_SQL: &str = "WITH expired AS (\
         SELECT i.digest FROM images i \
         WHERE i.last_seen < timezone('UTC', NOW()) - $1::interval \
           AND NOT EXISTS (SELECT 1 FROM workload_containers wc WHERE wc.image_digest = i.digest) \
         ORDER BY i.last_seen \
         LIMIT $2 \
     ) \
     DELETE FROM images WHERE digest IN (SELECT digest FROM expired)";

fn spawn_image_inventory(pool: DbPool) {
    let days = image_inventory_retention_days();
    let interval = image_inventory_retention_interval();
    info!(
        days,
        interval_secs = interval.as_secs(),
        "image inventory retention loop scheduled (days=0 means pruning off)"
    );
    if days == 0 {
        return;
    }
    actix_web::rt::spawn(async move {
        // Staggered after the other loops' 60/90/120 s warmups.
        tokio::time::sleep(Duration::from_secs(150)).await;
        loop {
            run_image_inventory_pass(&pool, days).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn run_image_inventory_pass(pool: &DbPool, days: u32) {
    let batch = image_inventory_batch_size();
    run_batched_prune(
        pool,
        "workload_containers",
        WORKLOAD_CONTAINERS_PRUNE_SQL,
        days,
        batch,
    )
    .await;
    run_batched_prune(pool, "images", IMAGES_PRUNE_SQL, days, batch).await;
}

/// One statement's prune, as bounded batches — same discipline and caps
/// as [`run_pass`].
async fn run_batched_prune(
    pool: &DbPool,
    table: &'static str,
    sql: &'static str,
    days: u32,
    batch_size: i64,
) {
    let mut total: usize = 0;
    for batch_idx in 0..MAX_BATCHES_PER_PASS {
        let pool = pool.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
            let mut conn = pool.get().map_err(RetentionError::Pool)?;
            prune_batch(&mut conn, sql, days, batch_size)
        })
        .await;
        match result {
            Ok(Ok(0)) => {
                if total == 0 {
                    debug!(table, "retention: 0 rows pruned");
                } else {
                    info!(
                        table,
                        rows = total,
                        batches = batch_idx,
                        "retention pruned rows"
                    );
                }
                return;
            }
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => {
                warn!(table, error = %e, pruned_before_failure = total, "retention failed");
                return;
            }
            Err(e) => {
                warn!(table, error = %e, pruned_before_failure = total, "retention task panicked");
                return;
            }
        }
    }
    info!(
        table,
        rows = total,
        cap = MAX_BATCHES_PER_PASS,
        "retention hit per-pass batch cap; the rest is pruned next interval"
    );
}

fn prune_batch(
    conn: &mut PgConnection,
    sql: &str,
    days: u32,
    batch_size: i64,
) -> Result<usize, RetentionError> {
    sql_query(sql)
        .bind::<diesel::sql_types::Text, _>(format!("{days} days"))
        .bind::<diesel::sql_types::BigInt, _>(batch_size)
        .execute(conn)
        .map_err(RetentionError::Diesel)
}

// ---------------------------------------------------------------------
// Workload security profiles (#1533)
// ---------------------------------------------------------------------
//
// `workload_profile_latest` is refreshed by the snapshotter on every visit
// of a workload that still has source data, so a row not recomputed
// within the window belongs to a workload that is gone. Versions older
// than the window are pruned too, except each live workload's newest
// (the anchor a diff points at); a gone workload's versions all age out.
// The per-workload count cap (PROFILE_VERSIONS_MAX_PER_WORKLOAD) is
// enforced by the snapshotter at write time, not here.
//
// - `PROFILE_VERSIONS_RETENTION_DAYS` (default 90; 0 disables)
// - `PROFILE_VERSIONS_RETENTION_INTERVAL_SECS` (default 3600, floor 60)
// - batch size shared with IMAGE_INVENTORY_RETENTION_BATCH_SIZE

const DEFAULT_PROFILE_VERSIONS_RETENTION_DAYS: u32 = 90;

fn profile_versions_retention_days() -> u32 {
    std::env::var("PROFILE_VERSIONS_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_PROFILE_VERSIONS_RETENTION_DAYS)
}

fn profile_versions_retention_interval() -> Duration {
    let secs = std::env::var("PROFILE_VERSIONS_RETENTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}

/// Read-model rows of workloads not recomputed within the window.
pub(crate) const PROFILE_LATEST_PRUNE_SQL: &str = "WITH expired AS (\
         SELECT cluster_id, pod_namespace, workload_kind, workload_name \
         FROM workload_profile_latest \
         WHERE computed_at < timezone('UTC', NOW()) - $1::interval \
         ORDER BY computed_at \
         LIMIT $2 \
     ) \
     DELETE FROM workload_profile_latest l USING expired e \
     WHERE l.cluster_id = e.cluster_id AND l.pod_namespace = e.pod_namespace \
       AND l.workload_kind = e.workload_kind AND l.workload_name = e.workload_name";

/// Versions older than the window, unless it is the newest version of a
/// workload that is still in the read model.
pub(crate) const PROFILE_VERSIONS_PRUNE_SQL: &str = "WITH expired AS (\
         SELECT v.id FROM workload_profile_versions v \
         WHERE v.created_at < timezone('UTC', NOW()) - $1::interval \
           AND (EXISTS (SELECT 1 FROM workload_profile_versions n \
                        WHERE n.cluster_id = v.cluster_id AND n.pod_namespace = v.pod_namespace \
                          AND n.workload_kind = v.workload_kind AND n.workload_name = v.workload_name \
                          AND n.revision > v.revision) \
                OR NOT EXISTS (SELECT 1 FROM workload_profile_latest l \
                        WHERE l.cluster_id = v.cluster_id AND l.pod_namespace = v.pod_namespace \
                          AND l.workload_kind = v.workload_kind AND l.workload_name = v.workload_name)) \
         ORDER BY v.created_at \
         LIMIT $2 \
     ) \
     DELETE FROM workload_profile_versions WHERE id IN (SELECT id FROM expired)";

fn spawn_workload_profiles(pool: DbPool) {
    let days = profile_versions_retention_days();
    let interval = profile_versions_retention_interval();
    info!(
        days,
        interval_secs = interval.as_secs(),
        "workload profile retention loop scheduled (days=0 means pruning off)"
    );
    if days == 0 {
        return;
    }
    actix_web::rt::spawn(async move {
        tokio::time::sleep(Duration::from_secs(180)).await;
        loop {
            run_workload_profiles_pass(&pool, days).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn run_workload_profiles_pass(pool: &DbPool, days: u32) {
    let batch = image_inventory_batch_size();
    // Read model first, so a gone workload's newest version is eligible
    // in the same pass.
    run_batched_prune(
        pool,
        "workload_profile_latest",
        PROFILE_LATEST_PRUNE_SQL,
        days,
        batch,
    )
    .await;
    run_batched_prune(
        pool,
        "workload_profile_versions",
        PROFILE_VERSIONS_PRUNE_SQL,
        days,
        batch,
    )
    .await;
}

#[cfg(test)]
mod workload_profile_retention_tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_prunes_old_versions_but_keeps_each_live_workloads_newest() {
        use diesel_migrations::MigrationHarness;
        let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("migrate");
        let ns = "kgtest-profile-retention";
        conn.batch_execute(&format!(
            "DELETE FROM workload_profile_versions WHERE pod_namespace = '{ns}'; \
             DELETE FROM workload_profile_latest WHERE pod_namespace = '{ns}'; \
             INSERT INTO workload_profile_latest (pod_namespace, workload_kind, workload_name, revision, content_hash, posture_status, summary) \
               VALUES ('{ns}', 'Deployment', 'live', 3, 'h3', 'ok', '{{}}'), \
                      ('{ns}', 'Deployment', 'gone', 1, 'g1', 'ok', '{{}}'); \
             UPDATE workload_profile_latest SET computed_at = timezone('UTC', NOW()) - INTERVAL '100 days' \
               WHERE pod_namespace = '{ns}' AND workload_name = 'gone'; \
             INSERT INTO workload_profile_versions (pod_namespace, workload_kind, workload_name, revision, content_hash, dimension_hashes, snapshot, posture, created_at) VALUES \
               ('{ns}', 'Deployment', 'live', 1, 'h1', '{{}}', '{{}}', '{{}}', timezone('UTC', NOW()) - INTERVAL '120 days'), \
               ('{ns}', 'Deployment', 'live', 2, 'h2', '{{}}', '{{}}', '{{}}', timezone('UTC', NOW()) - INTERVAL '110 days'), \
               ('{ns}', 'Deployment', 'live', 3, 'h3', '{{}}', '{{}}', '{{}}', timezone('UTC', NOW()) - INTERVAL '100 days'), \
               ('{ns}', 'Deployment', 'gone', 1, 'g1', '{{}}', '{{}}', '{{}}', timezone('UTC', NOW()) - INTERVAL '100 days'), \
               ('{ns}', 'Deployment', 'fresh', 1, 'f1', '{{}}', '{{}}', '{{}}', timezone('UTC', NOW()));"
        ))
        .unwrap();
        while prune_batch(&mut conn, PROFILE_LATEST_PRUNE_SQL, 90, 1000).unwrap() > 0 {}
        while prune_batch(&mut conn, PROFILE_VERSIONS_PRUNE_SQL, 90, 1000).unwrap() > 0 {}

        #[derive(QueryableByName)]
        struct R {
            #[diesel(sql_type = diesel::sql_types::Text)]
            workload_name: String,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            revision: i32,
        }
        let rows: Vec<R> = diesel::sql_query(format!(
            "SELECT workload_name, revision FROM workload_profile_versions \
             WHERE pod_namespace = '{ns}' ORDER BY workload_name, revision"
        ))
        .load(&mut conn)
        .unwrap();
        let got: Vec<(String, i32)> = rows
            .into_iter()
            .map(|r| (r.workload_name, r.revision))
            .collect();
        // live: only the newest survives; gone: its read-model row was
        // pruned, so its last version ages out too; fresh: in the window.
        assert_eq!(got, vec![("fresh".to_string(), 1), ("live".to_string(), 3)]);
        conn.batch_execute(&format!(
            "DELETE FROM workload_profile_versions WHERE pod_namespace = '{ns}'; \
             DELETE FROM workload_profile_latest WHERE pod_namespace = '{ns}';"
        ))
        .unwrap();
    }
}

// ---------------------------------------------------------------------
// Supply chain (#1533 P1-3)
// ---------------------------------------------------------------------
//
// One loop, three jobs, in this order each pass:
//
// 1. Relink every stored payload to the inventory (supplychain::relink),
//    so a digest the inventory learns after the scan arrived is joined
//    within one interval; refresh runtime in-use evidence, capture
//    coverage and observed exposure (in_use_store, P1-5); then rebuild the
//    per-CVE summary with tiers that GET /vulnerabilities reads
//    (vuln_cve_summary).
// 2. Expire staged SBOM sets that stopped receiving pages
//    (`SUPPLYCHAIN_SBOM_PAGE_TTL_SECS`, default 3600).
// 3. Delete payloads nothing runs: no linked inventory digest has a
//    workload container seen within `SUPPLYCHAIN_RETENTION_DAYS` (default
//    30; 0 disables this step) or running now by the inventory's own
//    predicate, and nothing received for the payload within
//    `SUPPLYCHAIN_UNLINKED_GRACE_HOURS` (default 24) so a scan that lands
//    before its pod's first inventory post is not deleted at once. A
//    digest the inventory itself pruned has no workload rows, so its
//    payloads follow it.
//
// - `SUPPLYCHAIN_RETENTION_INTERVAL_SECS` (default 300, floor 60)
// - `SUPPLYCHAIN_RETENTION_BATCH_SIZE` payloads per transaction (default
//   50, clamped to [1, 1000]); each payload is at most 50 000 findings
//   plus 100 000 components, so this bounds rows per statement too.

const DEFAULT_SUPPLYCHAIN_RETENTION_DAYS: u32 = 30;
const DEFAULT_SUPPLYCHAIN_GRACE_HOURS: u32 = 24;
const DEFAULT_SUPPLYCHAIN_INTERVAL_SECS: u64 = 300;
const DEFAULT_SUPPLYCHAIN_PAGE_TTL_SECS: i64 = 3600;
const DEFAULT_SUPPLYCHAIN_BATCH: i64 = 50;
/// Batches per step per pass.
const MAX_SUPPLYCHAIN_BATCHES: u32 = 200;

fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

fn supplychain_retention_days() -> u32 {
    env_parse("SUPPLYCHAIN_RETENTION_DAYS").unwrap_or(DEFAULT_SUPPLYCHAIN_RETENTION_DAYS)
}

fn supplychain_grace_hours() -> u32 {
    env_parse("SUPPLYCHAIN_UNLINKED_GRACE_HOURS").unwrap_or(DEFAULT_SUPPLYCHAIN_GRACE_HOURS)
}

fn supplychain_interval() -> Duration {
    Duration::from_secs(
        env_parse::<u64>("SUPPLYCHAIN_RETENTION_INTERVAL_SECS")
            .unwrap_or(DEFAULT_SUPPLYCHAIN_INTERVAL_SECS)
            .max(60),
    )
}

fn supplychain_page_ttl_secs() -> i64 {
    env_parse::<i64>("SUPPLYCHAIN_SBOM_PAGE_TTL_SECS")
        .unwrap_or(DEFAULT_SUPPLYCHAIN_PAGE_TTL_SECS)
        .max(60)
}

fn supplychain_batch() -> i64 {
    env_parse::<i64>("SUPPLYCHAIN_RETENTION_BATCH_SIZE")
        .map(|n| n.clamp(1, 1000))
        .unwrap_or(DEFAULT_SUPPLYCHAIN_BATCH)
}

fn spawn_supplychain(pool: DbPool) {
    let days = supplychain_retention_days();
    let grace = supplychain_grace_hours();
    let interval = supplychain_interval();
    info!(
        days,
        grace_hours = grace,
        interval_secs = interval.as_secs(),
        "supply-chain relink + retention loop scheduled (days=0 keeps payloads of images no longer running)"
    );
    actix_web::rt::spawn(async move {
        tokio::time::sleep(Duration::from_secs(45)).await;
        loop {
            run_supplychain_pass(&pool, days, grace).await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// One relink + expiry + GC pass. Each step is its own set of bounded
/// blocking calls; a failure is logged and the next step still runs.
pub(crate) async fn run_supplychain_pass(pool: &DbPool, days: u32, grace_hours: u32) {
    let batch = supplychain_batch();
    // 1. Relink.
    let mut cursor: Option<(String, String)> = None;
    let mut changed = 0usize;
    for _ in 0..MAX_SUPPLYCHAIN_BATCHES {
        let pool = pool.clone();
        let after = cursor.clone();
        let r = tokio::task::spawn_blocking(move || -> Result<_, RetentionError> {
            let mut conn = pool.get().map_err(RetentionError::Pool)?;
            crate::supplychain::relink_batch(&mut conn, after.as_ref(), batch * 4)
                .map_err(RetentionError::Diesel)
        })
        .await;
        match r {
            Ok(Ok((n, next))) => {
                changed += n;
                match next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            Ok(Err(e)) => {
                warn!(error = %e, "supply-chain relink failed");
                break;
            }
            Err(e) => {
                warn!(error = %e, "supply-chain relink task panicked");
                break;
            }
        }
    }
    if changed > 0 {
        info!(links_changed = changed, "supply-chain links refreshed");
    }
    // 1a. Runtime in-use evidence and exposure (P1-5), which the summary
    //     below tiers from.
    run_in_use_pass(pool, batch).await;
    // 1b. Rebuild the per-CVE summary GET /vulnerabilities reads, from the
    //     links just refreshed.
    let p = pool.clone();
    match tokio::task::spawn_blocking(move || -> Result<i64, RetentionError> {
        let mut conn = p.get().map_err(RetentionError::Pool)?;
        crate::supplychain_read::refresh_cve_summary(&mut conn).map_err(RetentionError::Diesel)
    })
    .await
    {
        Ok(Ok(n)) => debug!(cves = n, "supply-chain CVE summary rebuilt"),
        Ok(Err(e)) => warn!(error = %e, "supply-chain CVE summary rebuild failed"),
        Err(e) => warn!(error = %e, "supply-chain CVE summary task panicked"),
    }
    // 2. Staged pages.
    let ttl = supplychain_page_ttl_secs();
    let expired = run_supplychain_steps(pool, move |conn| {
        crate::supplychain::expire_pages_batch(conn, ttl, batch)
    })
    .await;
    if expired > 0 {
        info!(
            pages = expired,
            "supply-chain retention expired incomplete SBOM page sets"
        );
    }
    // 3. Payloads of images nothing runs.
    if days == 0 {
        return;
    }
    let window = crate::image_inventory::running_window_secs();
    let removed = run_supplychain_steps(pool, move |conn| {
        crate::supplychain::gc_batch(conn, days, grace_hours, window, batch)
    })
    .await;
    if removed > 0 {
        info!(
            payloads = removed,
            "supply-chain retention removed payloads of images no longer running"
        );
    } else {
        debug!("supply-chain retention: nothing to remove");
    }
}

/// Rebuild the derived in-use tables (in_use_store module docs): package
/// use from the runtime inventory, per-container coverage, and observed
/// exposure. Each step logs and gives up on its own error; a failed step
/// leaves the previous pass's rows, and unknowns only push tiers up.
async fn run_in_use_pass(pool: &DbPool, batch: i64) {
    use crate::in_use_store as s;
    let p = pool.clone();
    let available = match tokio::task::spawn_blocking(move || -> Result<bool, RetentionError> {
        let mut conn = p.get().map_err(RetentionError::Pool)?;
        s::runtime_inventory_available(&mut conn).map_err(RetentionError::Diesel)
    })
    .await
    {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => {
            warn!(error = %e, "in-use: runtime inventory check failed");
            false
        }
        Err(e) => {
            warn!(error = %e, "in-use: runtime inventory check panicked");
            false
        }
    };
    if available {
        let mut cursor: Option<String> = None;
        let mut rows = 0usize;
        for _ in 0..MAX_SUPPLYCHAIN_BATCHES {
            let p = pool.clone();
            let after = cursor.clone();
            let r = tokio::task::spawn_blocking(move || {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                s::refresh_package_use_batch(&mut conn, after.as_deref(), batch)
                    .map_err(|e| e.to_string())
            })
            .await;
            match r {
                Ok(Ok((n, next))) => {
                    rows += n;
                    match next {
                        Some(c) => cursor = Some(c),
                        None => break,
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "in-use: package use refresh failed");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "in-use: package use task panicked");
                    break;
                }
            }
        }
        debug!(rows, "in-use: package use refreshed");
    }
    let p = pool.clone();
    let r =
        tokio::task::spawn_blocking(move || -> Result<(usize, usize, usize), RetentionError> {
            let mut conn = p.get().map_err(RetentionError::Pool)?;
            let pruned = if available {
                s::prune_package_use(&mut conn)
            } else {
                s::clear_package_use(&mut conn)
            }
            .map_err(RetentionError::Diesel)?;
            let t = crate::in_use::TierSettings::from_env();
            let cov = s::refresh_coverage(&mut conn, &t).map_err(RetentionError::Diesel)?;
            let exp = s::refresh_exposure(
                &mut conn,
                crate::supplychain_read::EXPOSURE_DEFAULT_WINDOW_HOURS,
            )
            .map_err(RetentionError::Diesel)?;
            Ok((pruned, cov, exp))
        })
        .await;
    match r {
        Ok(Ok((pruned, cov, exp))) => debug!(
            pruned,
            coverage_rows = cov,
            exposure_rows = exp,
            runtime_inventory = available,
            "in-use: coverage and exposure refreshed"
        ),
        Ok(Err(e)) => warn!(error = %e, "in-use: coverage/exposure refresh failed"),
        Err(e) => warn!(error = %e, "in-use: coverage/exposure task panicked"),
    }
}

/// Repeat `step` until it reports 0 or the per-pass cap.
async fn run_supplychain_steps<F>(pool: &DbPool, step: F) -> usize
where
    F: Fn(&mut PgConnection) -> QueryResult<usize> + Send + Sync + Clone + 'static,
{
    let mut total = 0usize;
    for _ in 0..MAX_SUPPLYCHAIN_BATCHES {
        let pool = pool.clone();
        let step = step.clone();
        let r = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
            let mut conn = pool.get().map_err(RetentionError::Pool)?;
            step(&mut conn).map_err(RetentionError::Diesel)
        })
        .await;
        match r {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => {
                warn!(error = %e, removed_before_failure = total, "supply-chain retention failed");
                break;
            }
            Err(e) => {
                warn!(error = %e, "supply-chain retention task panicked");
                break;
            }
        }
    }
    total
}

#[cfg(test)]
mod supplychain_retention_tests {
    use super::*;

    #[test]
    fn env_defaults_overrides_and_clamps() {
        let _guard = crate::test_support::env_lock();
        let keys = [
            "SUPPLYCHAIN_RETENTION_DAYS",
            "SUPPLYCHAIN_UNLINKED_GRACE_HOURS",
            "SUPPLYCHAIN_RETENTION_INTERVAL_SECS",
            "SUPPLYCHAIN_SBOM_PAGE_TTL_SECS",
            "SUPPLYCHAIN_RETENTION_BATCH_SIZE",
        ];
        for k in keys {
            std::env::remove_var(k);
        }
        assert_eq!(supplychain_retention_days(), 30);
        assert_eq!(supplychain_grace_hours(), 24);
        assert_eq!(supplychain_interval(), Duration::from_secs(300));
        assert_eq!(supplychain_page_ttl_secs(), 3600);
        assert_eq!(supplychain_batch(), 50);
        std::env::set_var("SUPPLYCHAIN_RETENTION_DAYS", " 0 ");
        std::env::set_var("SUPPLYCHAIN_RETENTION_INTERVAL_SECS", "5");
        std::env::set_var("SUPPLYCHAIN_SBOM_PAGE_TTL_SECS", "1");
        std::env::set_var("SUPPLYCHAIN_RETENTION_BATCH_SIZE", "99999");
        assert_eq!(supplychain_retention_days(), 0);
        assert_eq!(supplychain_interval(), Duration::from_secs(60));
        assert_eq!(supplychain_page_ttl_secs(), 60);
        assert_eq!(supplychain_batch(), 1000);
        std::env::set_var("SUPPLYCHAIN_RETENTION_BATCH_SIZE", "0");
        assert_eq!(supplychain_batch(), 1);
        for k in keys {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn gc_sql_is_bounded_and_uses_the_running_predicate() {
        let sql = crate::supplychain::SUPPLYCHAIN_GC_KEYS_SQL;
        assert!(sql.contains("LIMIT $4"), "{sql}");
        assert!(sql.contains("make_interval(days => $2)"), "{sql}");
        assert!(
            sql.contains("wc.state_reason = 'CrashLoopBackOff'"),
            "{sql}"
        );
    }
}

#[cfg(test)]
mod image_inventory_retention_tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    #[test]
    fn env_defaults_overrides_and_clamps() {
        let _guard = crate::test_support::env_lock();
        for k in [
            "IMAGE_INVENTORY_RETENTION_DAYS",
            "IMAGE_INVENTORY_RETENTION_INTERVAL_SECS",
            "IMAGE_INVENTORY_RETENTION_BATCH_SIZE",
        ] {
            std::env::remove_var(k);
        }
        assert_eq!(image_inventory_retention_days(), 30);
        assert_eq!(
            image_inventory_retention_interval(),
            Duration::from_secs(3600)
        );
        assert_eq!(image_inventory_batch_size(), DEFAULT_BATCH_SIZE);
        std::env::set_var("IMAGE_INVENTORY_RETENTION_DAYS", " 7 ");
        std::env::set_var("IMAGE_INVENTORY_RETENTION_INTERVAL_SECS", "5");
        std::env::set_var("IMAGE_INVENTORY_RETENTION_BATCH_SIZE", "5");
        assert_eq!(image_inventory_retention_days(), 7);
        assert_eq!(
            image_inventory_retention_interval(),
            Duration::from_secs(60)
        );
        assert_eq!(image_inventory_batch_size(), MIN_BATCH_SIZE);
        std::env::set_var("IMAGE_INVENTORY_RETENTION_BATCH_SIZE", "99999999");
        assert_eq!(image_inventory_batch_size(), MAX_BATCH_SIZE);
        std::env::set_var("IMAGE_INVENTORY_RETENTION_DAYS", "nope");
        assert_eq!(image_inventory_retention_days(), 30);
        for k in [
            "IMAGE_INVENTORY_RETENTION_DAYS",
            "IMAGE_INVENTORY_RETENTION_INTERVAL_SECS",
            "IMAGE_INVENTORY_RETENTION_BATCH_SIZE",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn prune_sql_is_bounded() {
        for sql in [WORKLOAD_CONTAINERS_PRUNE_SQL, IMAGES_PRUNE_SQL] {
            assert!(sql.contains("LIMIT $2"), "{sql}");
            assert!(sql.contains("$1::interval"), "{sql}");
        }
        assert!(IMAGES_PRUNE_SQL.contains("NOT EXISTS"));
    }

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel_migrations::MigrationHarness;
        let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
            panic!("set KG_TEST_DATABASE_URL to run this test");
        };
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("apply the shipped migrations");
        conn.batch_execute("TRUNCATE images, workload_containers")
            .expect("reset the inventory tables");
        conn
    }

    fn seed(conn: &mut PgConnection, workload: &str, digest: &str, age_days: i64) {
        conn.batch_execute(&format!(
            "INSERT INTO images (digest, digest_kind, first_seen, last_seen) VALUES \
               ('{digest}', 'repo', timezone('UTC', NOW()) - INTERVAL '{age_days} days', \
                timezone('UTC', NOW()) - INTERVAL '{age_days} days') ON CONFLICT DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest, last_seen) VALUES \
               ('prod', 'Deployment', '{workload}', 'app', 'regular', 'r:1', '{digest}', \
                timezone('UTC', NOW()) - INTERVAL '{age_days} days');"
        ))
        .expect("seed");
    }

    fn remaining_rows(conn: &mut PgConnection) -> Vec<(String, String)> {
        #[derive(QueryableByName)]
        struct R {
            #[diesel(sql_type = diesel::sql_types::Text)]
            w: String,
            #[diesel(sql_type = diesel::sql_types::Text)]
            d: String,
        }
        sql_query(
            "SELECT workload_name AS w, image_digest AS d FROM workload_containers \
             ORDER BY workload_name, image_digest",
        )
        .load::<R>(conn)
        .expect("rows")
        .into_iter()
        .map(|r| (r.w, r.d))
        .collect()
    }

    fn count(conn: &mut PgConnection, table: &str) -> i64 {
        #[derive(QueryableByName)]
        struct C {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            n: i64,
        }
        sql_query(format!("SELECT count(*) AS n FROM {table}"))
            .get_result::<C>(conn)
            .expect("count")
            .n
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_prunes_stale_containers_then_unreferenced_images() {
        let mut conn = live_conn();
        let d = |i: u8| format!("sha256:{:064x}", i);
        seed(&mut conn, "live", &d(1), 0);
        seed(&mut conn, "gone-a", &d(2), 40);
        seed(&mut conn, "gone-b", &d(3), 45);
        // The live workload's container also has a digest it stopped
        // running 40 days ago (an old rollout): that row is pruned while
        // the workload's current digest row stays.
        seed(&mut conn, "live", &d(5), 40);
        // A workload whose only pod is stuck pulling the same ref: its last
        // known digest is 40 days old but was ref-seen just now, so it stays.
        seed(&mut conn, "pulling", &d(6), 40);
        conn.batch_execute(
            "UPDATE workload_containers SET ref_seen_at = timezone('UTC', NOW()) \
             WHERE workload_name = 'pulling'",
        )
        .unwrap();
        // An old image still referenced by a live container is kept.
        conn.batch_execute(&format!(
            "INSERT INTO images (digest, digest_kind, last_seen) VALUES \
               ('{}', 'repo', timezone('UTC', NOW()) - INTERVAL '90 days'); \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest) VALUES \
               ('prod', 'Deployment', 'live', 'sidecar', 'regular', 's:1', '{}');",
            d(4),
            d(4)
        ))
        .unwrap();

        // Before containers are pruned, every image is still referenced.
        assert_eq!(
            prune_batch(&mut conn, IMAGES_PRUNE_SQL, 30, 100).unwrap(),
            0
        );
        // Batch of one takes the OLDEST stale container first.
        assert_eq!(
            prune_batch(&mut conn, WORKLOAD_CONTAINERS_PRUNE_SQL, 30, 1).unwrap(),
            1
        );
        assert_eq!(count(&mut conn, "workload_containers"), 5);
        assert!(!remaining_rows(&mut conn).contains(&("gone-b".into(), d(3))));
        assert_eq!(
            prune_batch(&mut conn, WORKLOAD_CONTAINERS_PRUNE_SQL, 30, 100).unwrap(),
            2
        );
        assert_eq!(
            remaining_rows(&mut conn),
            vec![
                ("live".to_string(), d(1)),
                ("live".to_string(), d(4)),
                ("pulling".to_string(), d(6))
            ]
        );
        // Now the three unreferenced stale images go (including the
        // digest the live workload no longer runs); the fresh one and the
        // old-but-referenced one stay.
        assert_eq!(
            prune_batch(&mut conn, IMAGES_PRUNE_SQL, 30, 100).unwrap(),
            3
        );
        assert_eq!(count(&mut conn, "images"), 3);
        // Idempotent on a clean table.
        assert_eq!(
            prune_batch(&mut conn, WORKLOAD_CONTAINERS_PRUNE_SQL, 30, 100).unwrap(),
            0
        );
        assert_eq!(
            prune_batch(&mut conn, IMAGES_PRUNE_SQL, 30, 100).unwrap(),
            0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var helpers — guard the env so concurrent tests don't see
    // each other's mutations. The std test runner runs tests in
    // parallel by default.
    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        // Crate-wide env lock — std::env is process-global (see test_support).
        let _guard = crate::test_support::env_lock();
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn retention_days_default() {
        with_env("AUDIT_VERDICTS_RETENTION_DAYS", None, || {
            assert_eq!(retention_days(), DEFAULT_RETENTION_DAYS);
        });
    }

    #[test]
    fn retention_days_explicit() {
        with_env("AUDIT_VERDICTS_RETENTION_DAYS", Some("7"), || {
            assert_eq!(retention_days(), 7);
        });
    }

    #[test]
    fn retention_days_zero_disables() {
        // Documented contract: 0 disables retention. spawn() checks for
        // exactly this.
        with_env("AUDIT_VERDICTS_RETENTION_DAYS", Some("0"), || {
            assert_eq!(retention_days(), 0);
        });
    }

    #[test]
    fn dead_pod_window_decoupled_from_audit_disable() {
        // Regression guard: disabling audit retention (days==0) must NOT
        // disable dead-pod pruning — that coupling let pod_details bloat
        // unbounded and slowed /pod/info to a crawl. 0 -> standalone
        // default; any positive audit window is reused as-is.
        assert_eq!(
            dead_pod_retention_window(0),
            DEFAULT_DEAD_POD_RETENTION_DAYS
        );
        assert!(dead_pod_retention_window(0) > 0);
        assert_eq!(dead_pod_retention_window(30), 30);
        assert_eq!(dead_pod_retention_window(1), 1);
    }

    #[test]
    fn retention_days_invalid_falls_back_to_default() {
        // A typo or garbage in the env should NOT silently set retention
        // to 0 and disable cleanup; it should fall back to the safe
        // default.
        with_env(
            "AUDIT_VERDICTS_RETENTION_DAYS",
            Some("not-a-number"),
            || {
                assert_eq!(retention_days(), DEFAULT_RETENTION_DAYS);
            },
        );
    }

    #[test]
    fn retention_days_trims_whitespace() {
        // Operator-paste with trailing newline must honor the numeric
        // value, not fall back to the default. Same trim-defense
        // applied to db_pool_max_size and AUDIT_INFLIGHT_PERMITS.
        with_env("AUDIT_VERDICTS_RETENTION_DAYS", Some("  7\n"), || {
            assert_eq!(retention_days(), 7);
        });
    }

    #[test]
    fn retention_interval_trims_whitespace() {
        with_env(
            "AUDIT_VERDICTS_RETENTION_INTERVAL_SECS",
            Some("  3600 "),
            || {
                assert_eq!(retention_interval(), Duration::from_secs(3600));
            },
        );
    }

    #[test]
    fn retention_interval_default() {
        with_env("AUDIT_VERDICTS_RETENTION_INTERVAL_SECS", None, || {
            assert_eq!(
                retention_interval(),
                Duration::from_secs(DEFAULT_INTERVAL_SECS)
            );
        });
    }

    #[test]
    fn retention_interval_floor_60s() {
        // Anything below 60s is clamped — protects the DB from a
        // typo'd `1` interval that would hammer the table.
        with_env("AUDIT_VERDICTS_RETENTION_INTERVAL_SECS", Some("10"), || {
            assert_eq!(retention_interval(), Duration::from_secs(60));
        });
    }

    #[test]
    fn retention_interval_zero_clamped_to_60s() {
        with_env("AUDIT_VERDICTS_RETENTION_INTERVAL_SECS", Some("0"), || {
            assert_eq!(retention_interval(), Duration::from_secs(60));
        });
    }

    #[test]
    fn retention_interval_explicit_above_floor() {
        with_env(
            "AUDIT_VERDICTS_RETENTION_INTERVAL_SECS",
            Some("7200"),
            || {
                assert_eq!(retention_interval(), Duration::from_secs(7200));
            },
        );
    }

    #[test]
    fn retention_interval_invalid_falls_back_to_default() {
        with_env(
            "AUDIT_VERDICTS_RETENTION_INTERVAL_SECS",
            Some("garbage"),
            || {
                assert_eq!(
                    retention_interval(),
                    Duration::from_secs(DEFAULT_INTERVAL_SECS)
                );
            },
        );
    }

    #[test]
    fn retention_batch_size_default() {
        with_env("AUDIT_VERDICTS_RETENTION_BATCH_SIZE", None, || {
            assert_eq!(retention_batch_size(), DEFAULT_BATCH_SIZE);
        });
    }

    #[test]
    fn retention_batch_size_explicit_within_range() {
        with_env("AUDIT_VERDICTS_RETENTION_BATCH_SIZE", Some("10000"), || {
            assert_eq!(retention_batch_size(), 10_000);
        });
    }

    #[test]
    fn retention_batch_size_clamps_below_min() {
        // Operators sometimes typo `5` thinking it's `5000`. n=5 would
        // mean MAX_BATCHES_PER_PASS round-trips moving 1k rows total —
        // worse than not having retention at all under any real load.
        with_env("AUDIT_VERDICTS_RETENTION_BATCH_SIZE", Some("5"), || {
            assert_eq!(retention_batch_size(), MIN_BATCH_SIZE);
        });
        // Zero must also clamp upward, not disable batching.
        with_env("AUDIT_VERDICTS_RETENTION_BATCH_SIZE", Some("0"), || {
            assert_eq!(retention_batch_size(), MIN_BATCH_SIZE);
        });
        // Negative numbers (defensible against a typo `-5000`) clamp too.
        with_env("AUDIT_VERDICTS_RETENTION_BATCH_SIZE", Some("-1000"), || {
            assert_eq!(retention_batch_size(), MIN_BATCH_SIZE);
        });
    }

    #[test]
    fn retention_batch_size_clamps_above_max() {
        // 1M batch defeats the batching purpose — clamp to keep each
        // DELETE's lock hold bounded.
        with_env(
            "AUDIT_VERDICTS_RETENTION_BATCH_SIZE",
            Some("1000000"),
            || {
                assert_eq!(retention_batch_size(), MAX_BATCH_SIZE);
            },
        );
    }

    #[test]
    fn retention_batch_size_trims_whitespace() {
        // Same operator-paste defense as the other retention env vars.
        with_env(
            "AUDIT_VERDICTS_RETENTION_BATCH_SIZE",
            Some("  10000\n"),
            || {
                assert_eq!(retention_batch_size(), 10_000);
            },
        );
    }

    fn ts(s: &str) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").unwrap()
    }

    #[test]
    fn bucket_floor_is_five_minute_aligned() {
        assert_eq!(
            floor_to_bucket(ts("2026-09-10T02:43:59")),
            ts("2026-09-10T02:40:00")
        );
        assert_eq!(
            floor_to_bucket(ts("2026-09-10T02:40:00")),
            ts("2026-09-10T02:40:00")
        );
        assert_eq!(
            floor_to_bucket(ts("2026-09-10T02:44:59")),
            ts("2026-09-10T02:40:00")
        );
        assert_eq!(
            floor_to_bucket(ts("2026-09-10T02:45:00")),
            ts("2026-09-10T02:45:00")
        );
    }

    #[test]
    fn downsample_range_folds_whole_buckets_oldest_first() {
        // Oldest minute row at 02:41, cutoff 03:17 → first batch is the
        // two buckets [02:40, 02:50).
        let r = downsample_range(ts("2026-09-10T02:41:00"), ts("2026-09-10T03:17:00"), 2);
        assert_eq!(
            r,
            Some((ts("2026-09-10T02:40:00"), ts("2026-09-10T02:50:00")))
        );
    }

    #[test]
    fn downsample_range_never_touches_the_cutoff_bucket() {
        // Oldest 03:11, cutoff 03:17: both in bucket [03:10, 03:15) and
        // [03:15, 03:20) resp. Only [03:10, 03:15) is whole and below the
        // cutoff bucket; the range must stop at 03:15 even with a batch
        // size of 10 buckets.
        let r = downsample_range(ts("2026-09-10T03:11:00"), ts("2026-09-10T03:17:00"), 10);
        assert_eq!(
            r,
            Some((ts("2026-09-10T03:10:00"), ts("2026-09-10T03:15:00")))
        );
        // Oldest row inside the cutoff's own bucket → nothing yet.
        assert_eq!(
            downsample_range(ts("2026-09-10T03:16:00"), ts("2026-09-10T03:17:00"), 2),
            None
        );
        // Oldest row exactly on the cutoff bucket boundary → nothing.
        assert_eq!(
            downsample_range(ts("2026-09-10T03:15:00"), ts("2026-09-10T03:17:00"), 2),
            None
        );
    }

    #[test]
    fn downsample_range_batch_size_floors_at_one() {
        let r = downsample_range(ts("2026-09-10T02:41:00"), ts("2026-09-10T03:17:00"), 0);
        assert_eq!(
            r,
            Some((ts("2026-09-10T02:40:00"), ts("2026-09-10T02:45:00")))
        );
    }

    #[test]
    fn compute_retention_env_defaults_and_overrides() {
        with_env("COMPUTE_HISTORY_RETENTION_DAYS", None, || {
            assert_eq!(
                compute_history_retention_days(),
                DEFAULT_COMPUTE_RETENTION_DAYS
            );
        });
        with_env("COMPUTE_HISTORY_RETENTION_DAYS", Some("0"), || {
            assert_eq!(compute_history_retention_days(), 0, "0 disables history");
        });
        with_env("COMPUTE_HISTORY_RETENTION_DAYS", Some(" 3\n"), || {
            assert_eq!(compute_history_retention_days(), 3);
        });
        with_env("COMPUTE_HISTORY_MINUTE_HOURS", None, || {
            assert_eq!(compute_minute_hours(), DEFAULT_COMPUTE_MINUTE_HOURS);
        });
        with_env("COMPUTE_HISTORY_MINUTE_HOURS", Some("0"), || {
            assert_eq!(
                compute_minute_hours(),
                1,
                "floored so the engine window keeps minute rows"
            );
        });
        with_env("COMPUTE_RETENTION_INTERVAL_SECS", None, || {
            assert_eq!(
                compute_retention_interval(),
                Duration::from_secs(DEFAULT_COMPUTE_INTERVAL_SECS)
            );
        });
        with_env("COMPUTE_RETENTION_INTERVAL_SECS", Some("5"), || {
            assert_eq!(compute_retention_interval(), Duration::from_secs(60));
        });
    }

    #[test]
    fn downsample_sql_names_every_history_column_once() {
        // The INSERT column list must match the SELECT list one-to-one;
        // a column added to the table and to only one side would fail at
        // runtime in the retention loop, which has no test database. Pin
        // the count here so a mismatch fails locally.
        let sql = DOWNSAMPLE_INSERT_SQL;
        let cols = sql
            .split("INSERT INTO pod_compute_history (")
            .nth(1)
            .unwrap()
            .split(')')
            .next()
            .unwrap();
        let insert_cols: Vec<&str> = cols.split(',').map(str::trim).collect();
        assert_eq!(insert_cols.len(), 46, "46 = every column but id");
        let select = sql.split("SELECT g.container_uid").nth(1).unwrap();
        let select = select.split("FROM (").next().unwrap();
        let select_cols = select.matches("g.").count() + select.matches("h.hist").count();
        // + `g.container_uid` (consumed by the split above) + the literal
        // `300` standing in for resolution_secs.
        assert_eq!(select_cols + 2, insert_cols.len());
        assert!(sql.contains("resolution_secs = 60 AND ts >= $1 AND ts < $2"));
        assert!(sql.contains("GROUP BY container_uid, bucket"));
    }

    // ---- node_compute_latest stale prune ---------------------------

    /// Cadence of the node-only heartbeat a Controller with the gauges off
    /// posts (`HEARTBEAT_INTERVAL` in the controller's `compute_sampler.rs`).
    /// Restated here because the broker cannot see the controller crate; if
    /// that constant moves, this pin is what says the window must follow.
    const DISABLED_HEARTBEAT_SECS: i64 = 300;

    /// `const` blocks, as in `seccomp_denial`'s window test: these are
    /// compile-time facts about the constants, so they fail the build
    /// rather than a test run — and clippy refuses a runtime assertion
    /// whose value is constant anyway.
    #[test]
    fn node_compute_stale_window_outlives_pods_and_missed_heartbeats() {
        const {
            assert!(
                NODE_COMPUTE_LATEST_STALE_SECS > COMPUTE_LATEST_STALE_SECS,
                "a node row must outlive its pods' rows: between the two \
                 windows the UI keeps saying WHY a silent node's pods have no \
                 gauge (off / unsupported) instead of collapsing to pending"
            )
        };
        const {
            assert!(
                NODE_COMPUTE_LATEST_STALE_SECS >= 12 * DISABLED_HEARTBEAT_SECS,
                "a Controller with the gauges off must be able to miss a run \
                 of heartbeats — a rollout is a couple of them, not a dozen"
            )
        };
        const {
            assert!(
                NODE_COMPUTE_LATEST_STALE_SECS <= 24 * 3_600,
                "a departed node must not sit in GET /compute/nodes for \
                 days: that endpoint serves the whole table on every poll"
            )
        };
    }

    #[test]
    fn node_compute_stale_prune_sql_is_bounded_and_takes_the_oldest_first() {
        let sql = NODE_COMPUTE_STALE_PRUNE_SQL;
        // UTC-naive right-hand side, like every other naive-column prune in
        // this file; `updated_at` is TIMESTAMP, not TIMESTAMPTZ.
        let window = "updated_at < timezone('UTC', NOW()) - $1::interval";
        let (cte, delete) = sql
            .split_once("DELETE FROM node_compute_latest")
            .expect("a CTE followed by the DELETE");
        assert!(cte.contains("SELECT node FROM node_compute_latest"));
        assert!(cte.contains(window), "the CTE selects by the window");
        assert!(
            cte.contains("ORDER BY updated_at"),
            "longest-departed nodes go first"
        );
        assert!(cte.contains("LIMIT $2"), "bounded through the CTE");
        assert!(delete.contains("WHERE node IN (SELECT node FROM stale)"));
        assert!(
            delete.contains(&format!("AND {window}")),
            "the outer DELETE repeats the window, so the READ COMMITTED \
             recheck skips a row its node refreshed while the DELETE waited"
        );
    }

    // ---- live database ----------------------------------------------
    //
    // The prune is one SQL statement. The unit test above proves the right
    // statement is SENT; only Postgres proves the window and the LIMIT do
    // what they say. Same gate and shape as `seccomp_denial`'s live tests:
    // ignored by default, `KG_TEST_DATABASE_URL` to run, the REAL
    // migrations applied so the schema cannot drift from the one shipped,
    // and `--test-threads=1` because every live test shares one database.
    // Declared again here rather than shared because that module's helper
    // lives inside its own private `tests`.

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
        conn.batch_execute("TRUNCATE node_compute_latest")
            .expect("reset the table this test uses");
        conn
    }

    /// One node's row, `age_secs` behind the SERVER's clock. The prune
    /// compares against the server's `NOW()`; a row stamped from the test
    /// process would make the boundary depend on clock skew between the
    /// two, so the age is applied with the same expression the prune uses.
    fn seed_node(conn: &mut PgConnection, name: &str, age_secs: i64) {
        use crate::compute_types::NodeComputeLatest;
        use crate::schema::node_compute_latest::dsl::*;
        use diesel::connection::SimpleConnection;

        let now = chrono::Utc::now().naive_utc();
        let row = NodeComputeLatest {
            node: name.to_string(),
            ts: now,
            interval_ms: 5_000,
            ctxt_per_sec: 0.0,
            compute_enabled: true,
            compute_supported: true,
            contention_loaded: false,
            cpu_some10: 0.0,
            cpu_full10: 0.0,
            mem_some10: 0.0,
            mem_full10: 0.0,
            cpu_cores: 4,
            memory_bytes: 0,
            bpf_runq_enqueued: 0,
            bpf_runq_hist: 0,
            bpf_pair: 0,
            unknown_blame_share: 0.0,
            updated_at: now,
            bpf_hist_update_failures: None,
            bpf_pair_update_failures: None,
        };
        diesel::insert_into(node_compute_latest)
            .values(&row)
            .execute(conn)
            .expect("seed node_compute_latest");
        conn.batch_execute(&format!(
            "UPDATE node_compute_latest \
             SET updated_at = timezone('UTC', NOW()) - INTERVAL '{age_secs} seconds' \
             WHERE node = '{name}'"
        ))
        .expect("age the row");
    }

    fn remaining_nodes(conn: &mut PgConnection) -> Vec<String> {
        use crate::schema::node_compute_latest::dsl::*;
        node_compute_latest
            .select(node)
            .order(node.asc())
            .load(conn)
            .expect("list nodes")
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_prunes_departed_nodes_oldest_first_and_keeps_the_rest() {
        let mut conn = live_conn();
        let window = NODE_COMPUTE_LATEST_STALE_SECS;
        // One reporting now; one quiet but inside the window (a Controller
        // mid-rollout, or one with the gauges off between heartbeats); two
        // that left the cluster, at different times.
        seed_node(&mut conn, "live", 0);
        seed_node(&mut conn, "quiet", window / 2);
        seed_node(&mut conn, "left-this-morning", window * 2);
        seed_node(&mut conn, "left-yesterday", window * 24);

        // A batch of one: the CTE's LIMIT bounds the DELETE, and its ORDER
        // BY hands it the longest-departed node, not an arbitrary one.
        assert_eq!(prune_stale_node_latest(&mut conn, 1).expect("prune"), 1);
        assert_eq!(
            remaining_nodes(&mut conn),
            ["left-this-morning", "live", "quiet"].map(String::from)
        );

        // A full batch takes what is left outside the window and nothing
        // inside it.
        assert_eq!(
            prune_stale_node_latest(&mut conn, DEFAULT_BATCH_SIZE).expect("prune"),
            1
        );
        assert_eq!(
            remaining_nodes(&mut conn),
            ["live", "quiet"].map(String::from)
        );

        // And a pass over a table with nothing to prune deletes nothing:
        // the loop runs this every interval on healthy clusters.
        assert_eq!(
            prune_stale_node_latest(&mut conn, DEFAULT_BATCH_SIZE).expect("prune"),
            0
        );
    }

    // ---- seccomp denial retention ----------------------------------
    //
    // These read their own env vars rather than sharing the audit ones,
    // because this window is not only a prune window: the denial metrics
    // and the `denials` block on GET /seccomp/profiles report over exactly
    // what this leaves in the table. Coupling it to AUDIT_VERDICTS_* would
    // mean an operator shortening audit retention silently narrowed what a
    // CR's DenialsObserved condition considers current.

    #[test]
    fn seccomp_denial_retention_defaults() {
        with_env("SECCOMP_DENIALS_RETENTION_DAYS", None, || {
            assert_eq!(
                seccomp_denial_retention_days(),
                DEFAULT_SECCOMP_DENIAL_RETENTION_DAYS
            );
        });
        with_env("SECCOMP_DENIALS_RETENTION_INTERVAL_SECS", None, || {
            assert_eq!(
                seccomp_denial_retention_interval(),
                Duration::from_secs(DEFAULT_SECCOMP_DENIAL_INTERVAL_SECS)
            );
        });
        with_env("SECCOMP_DENIALS_RETENTION_BATCH_SIZE", None, || {
            assert_eq!(seccomp_denial_batch_size(), DEFAULT_BATCH_SIZE);
        });
    }

    #[test]
    fn seccomp_denial_retention_is_not_coupled_to_the_audit_window() {
        // Regression guard for the coupling described above: disabling or
        // shortening audit retention must leave the denial window alone.
        let _guard = crate::test_support::env_lock();
        let prev_audit = std::env::var("AUDIT_VERDICTS_RETENTION_DAYS").ok();
        let prev_denial = std::env::var("SECCOMP_DENIALS_RETENTION_DAYS").ok();
        std::env::set_var("AUDIT_VERDICTS_RETENTION_DAYS", "0");
        std::env::remove_var("SECCOMP_DENIALS_RETENTION_DAYS");
        assert_eq!(
            seccomp_denial_retention_days(),
            DEFAULT_SECCOMP_DENIAL_RETENTION_DAYS
        );
        match prev_audit {
            Some(v) => std::env::set_var("AUDIT_VERDICTS_RETENTION_DAYS", v),
            None => std::env::remove_var("AUDIT_VERDICTS_RETENTION_DAYS"),
        }
        match prev_denial {
            Some(v) => std::env::set_var("SECCOMP_DENIALS_RETENTION_DAYS", v),
            None => std::env::remove_var("SECCOMP_DENIALS_RETENTION_DAYS"),
        }
    }

    #[test]
    fn seccomp_denial_retention_zero_disables() {
        // Documented contract, and spawn_seccomp_denials checks for exactly
        // this before starting a task at all.
        with_env("SECCOMP_DENIALS_RETENTION_DAYS", Some("0"), || {
            assert_eq!(seccomp_denial_retention_days(), 0);
        });
    }

    #[test]
    fn seccomp_denial_retention_trims_clamps_and_falls_back() {
        with_env("SECCOMP_DENIALS_RETENTION_DAYS", Some("  7\n"), || {
            assert_eq!(seccomp_denial_retention_days(), 7);
        });
        with_env(
            "SECCOMP_DENIALS_RETENTION_DAYS",
            Some("not-a-number"),
            || {
                assert_eq!(
                    seccomp_denial_retention_days(),
                    DEFAULT_SECCOMP_DENIAL_RETENTION_DAYS
                );
            },
        );
        with_env(
            "SECCOMP_DENIALS_RETENTION_INTERVAL_SECS",
            Some("10"),
            || {
                assert_eq!(
                    seccomp_denial_retention_interval(),
                    Duration::from_secs(60),
                    "same 60s floor as the other loops, so a typo'd 1 cannot \
                 hammer the table"
                );
            },
        );
        with_env("SECCOMP_DENIALS_RETENTION_BATCH_SIZE", Some("5"), || {
            assert_eq!(seccomp_denial_batch_size(), MIN_BATCH_SIZE);
        });
        with_env(
            "SECCOMP_DENIALS_RETENTION_BATCH_SIZE",
            Some("1000000"),
            || {
                assert_eq!(seccomp_denial_batch_size(), MAX_BATCH_SIZE);
            },
        );
    }

    #[test]
    fn retention_batch_size_invalid_falls_back_to_default() {
        // A typo or garbage in the env should NOT silently set batch to
        // a tiny value; fall back to the safe default.
        with_env(
            "AUDIT_VERDICTS_RETENTION_BATCH_SIZE",
            Some("not-a-number"),
            || {
                assert_eq!(retention_batch_size(), DEFAULT_BATCH_SIZE);
            },
        );
    }

    // ---- pod_traffic retention -------------------------------------

    #[test]
    fn pod_traffic_retention_defaults() {
        with_env("POD_TRAFFIC_RETENTION_DAYS", None, || {
            assert_eq!(
                pod_traffic_retention_days(),
                DEFAULT_POD_TRAFFIC_RETENTION_DAYS
            );
        });
        with_env("POD_TRAFFIC_RETENTION_INTERVAL_SECS", None, || {
            assert_eq!(
                pod_traffic_retention_interval(),
                Duration::from_secs(DEFAULT_POD_TRAFFIC_INTERVAL_SECS)
            );
        });
        with_env("POD_TRAFFIC_RETENTION_BATCH_SIZE", None, || {
            assert_eq!(pod_traffic_batch_size(), DEFAULT_BATCH_SIZE);
        });
    }

    #[test]
    fn pod_traffic_retention_zero_disables() {
        with_env("POD_TRAFFIC_RETENTION_DAYS", Some("0"), || {
            assert_eq!(pod_traffic_retention_days(), 0);
        });
    }

    #[test]
    fn pod_traffic_retention_is_not_coupled_to_the_audit_window() {
        // Turning audit pruning off must not turn traffic pruning off.
        let _guard = crate::test_support::env_lock();
        let prev_audit = std::env::var("AUDIT_VERDICTS_RETENTION_DAYS").ok();
        let prev_traffic = std::env::var("POD_TRAFFIC_RETENTION_DAYS").ok();
        std::env::set_var("AUDIT_VERDICTS_RETENTION_DAYS", "0");
        std::env::remove_var("POD_TRAFFIC_RETENTION_DAYS");
        assert_eq!(
            pod_traffic_retention_days(),
            DEFAULT_POD_TRAFFIC_RETENTION_DAYS
        );
        match prev_audit {
            Some(v) => std::env::set_var("AUDIT_VERDICTS_RETENTION_DAYS", v),
            None => std::env::remove_var("AUDIT_VERDICTS_RETENTION_DAYS"),
        }
        match prev_traffic {
            Some(v) => std::env::set_var("POD_TRAFFIC_RETENTION_DAYS", v),
            None => std::env::remove_var("POD_TRAFFIC_RETENTION_DAYS"),
        }
    }

    #[test]
    fn pod_traffic_retention_trims_clamps_and_falls_back() {
        with_env("POD_TRAFFIC_RETENTION_DAYS", Some("  7\n"), || {
            assert_eq!(pod_traffic_retention_days(), 7);
        });
        with_env("POD_TRAFFIC_RETENTION_DAYS", Some("-3"), || {
            // Garbage (a u32 cannot be negative) falls back to the
            // default, never to 0 = disabled.
            assert_eq!(
                pod_traffic_retention_days(),
                DEFAULT_POD_TRAFFIC_RETENTION_DAYS
            );
        });
        with_env("POD_TRAFFIC_RETENTION_INTERVAL_SECS", Some("10"), || {
            assert_eq!(pod_traffic_retention_interval(), Duration::from_secs(60));
        });
        with_env("POD_TRAFFIC_RETENTION_INTERVAL_SECS", Some("junk"), || {
            assert_eq!(
                pod_traffic_retention_interval(),
                Duration::from_secs(DEFAULT_POD_TRAFFIC_INTERVAL_SECS)
            );
        });
        with_env("POD_TRAFFIC_RETENTION_BATCH_SIZE", Some("5"), || {
            assert_eq!(pod_traffic_batch_size(), MIN_BATCH_SIZE);
        });
        with_env("POD_TRAFFIC_RETENTION_BATCH_SIZE", Some("1000000"), || {
            assert_eq!(pod_traffic_batch_size(), MAX_BATCH_SIZE);
        });
        with_env("POD_TRAFFIC_RETENTION_BATCH_SIZE", Some("oops"), || {
            assert_eq!(pod_traffic_batch_size(), DEFAULT_BATCH_SIZE);
        });
    }

    #[test]
    fn pod_traffic_prune_sql_is_bounded_ordered_and_spares_live_pods() {
        for sql in [POD_TRAFFIC_PRUNE_SQL, POD_TRAFFIC_PRUNE_AFTER_SQL] {
            // Bounded, oldest first, in the order the time_stamp index
            // serves (walked backwards).
            assert!(sql.contains("ORDER BY t.time_stamp, t.uuid"), "{sql}");
            assert!(sql.contains("LIMIT $2"), "{sql}");
            // UTC-naive cutoff, same as every other naive-column prune.
            assert!(
                sql.contains("t.time_stamp < timezone('UTC', NOW()) - $1::interval"),
                "{sql}"
            );
            // The live-pod guard: without it a long-running pod loses the
            // rules it will never report again.
            assert!(sql.contains("NOT EXISTS"), "{sql}");
            assert!(sql.contains("p.is_dead = false"), "{sql}");
            // ...and it is applied to the bounded candidate set, not inside
            // the ordered scan (where it made Postgres sort every expired
            // row per batch).
            let scan = &sql[..sql.find("deleted AS").expect("deleted CTE")];
            assert!(!scan.contains("pod_details"), "{sql}");
            // The cursor is the last row EXAMINED, kept or deleted.
            assert!(
                sql.ends_with("FROM candidates c ORDER BY c.time_stamp DESC, c.uuid DESC LIMIT 1"),
                "{sql}"
            );
        }
        assert!(!POD_TRAFFIC_PRUNE_SQL.contains("$3"));
        assert!(POD_TRAFFIC_PRUNE_AFTER_SQL.contains("(t.time_stamp, t.uuid) > ($3, $4)"));
        // The two differ only by the cursor predicate.
        assert_eq!(
            POD_TRAFFIC_PRUNE_AFTER_SQL.replace("AND (t.time_stamp, t.uuid) > ($3, $4) ", ""),
            POD_TRAFFIC_PRUNE_SQL
        );
        // The supersede rule: only identified in-cluster peers, keyed the
        // way idx_pod_traffic_supersede is (the partial predicate and the
        // COALESCE expression must appear verbatim for the planner to use
        // it), and strictly newer so the newest row of a group survives.
        let sql = POD_TRAFFIC_PRUNE_SQL;
        assert!(sql.contains("c.peer_kind IN ('pod', 'service')"), "{sql}");
        assert!(sql.contains("n.peer_kind IN ('pod', 'service')"), "{sql}");
        assert!(
            sql.contains("COALESCE(n.peer_workload_name, n.peer_name)"),
            "{sql}"
        );
        assert!(
            sql.contains("(n.time_stamp, n.uuid) > (c.time_stamp, c.uuid)"),
            "{sql}"
        );
        for col in [
            "traffic_type",
            "ip_protocol",
            "pod_port",
            "traffic_in_out_port",
            "decision",
            "pod_namespace",
        ] {
            assert!(
                sql.contains(&format!("n.{col} IS NOT DISTINCT FROM c.{col}")),
                "supersede key must include {col}: {sql}"
            );
        }
        // A node peer's rule is its own IP; it must never supersede.
        assert!(!sql.contains("'node'"), "{sql}");
    }

    #[test]
    fn pod_traffic_max_rows_per_pod_defaults_off_and_parses() {
        with_env("POD_TRAFFIC_MAX_ROWS_PER_POD", None, || {
            assert_eq!(pod_traffic_max_rows_per_pod(), 0);
        });
        with_env("POD_TRAFFIC_MAX_ROWS_PER_POD", Some(" 50000\n"), || {
            assert_eq!(pod_traffic_max_rows_per_pod(), 50_000);
        });
        // It deletes regardless of age, so garbage must mean OFF, never
        // some accidental cap.
        for junk in ["-1", "lots", "1e6"] {
            with_env("POD_TRAFFIC_MAX_ROWS_PER_POD", Some(junk), || {
                assert_eq!(pod_traffic_max_rows_per_pod(), 0, "{junk}");
            });
        }
    }

    #[test]
    fn pod_traffic_cap_never_targets_identified_peers() {
        let sql = POD_TRAFFIC_CAP_PRUNE_SQL;
        assert!(sql.contains("peer_kind IS NULL"), "{sql}");
        assert!(sql.contains("ORDER BY time_stamp, uuid"), "{sql}");
        assert!(sql.contains("LIMIT $3"), "{sql}");
        assert!(
            sql.contains("pod_namespace IS NOT DISTINCT FROM $2"),
            "{sql}"
        );
    }

    fn reset_traffic_tables(conn: &mut PgConnection) {
        use diesel::connection::SimpleConnection;
        conn.batch_execute("TRUNCATE pod_traffic, pod_details")
            .expect("reset the tables this test uses");
    }

    /// A pod_traffic row `age_days` behind the server's clock (same reason
    /// as `seed_node`: the prune compares against the server's `NOW()`).
    fn seed_traffic(conn: &mut PgConnection, id: &str, pod: &str, ns: &str, age_days: i64) {
        use diesel::connection::SimpleConnection;
        conn.batch_execute(&format!(
            "INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, time_stamp) \
             VALUES ('{id}', '{pod}', '{ns}', \
                     timezone('UTC', NOW()) - INTERVAL '{age_days} days')"
        ))
        .expect("seed pod_traffic");
    }

    fn seed_pod(
        conn: &mut PgConnection,
        pod: &str,
        ns: &str,
        dead: bool,
        started_days_ago: Option<i64>,
    ) {
        use diesel::connection::SimpleConnection;
        let started = match started_days_ago {
            Some(d) => format!("timezone('UTC', NOW()) - INTERVAL '{d} days'"),
            None => "NULL".to_string(),
        };
        conn.batch_execute(&format!(
            "INSERT INTO pod_details \
               (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, started_at) \
             VALUES ('{pod}', '10.0.0.1', '{ns}', timezone('UTC', NOW()), 'node-a', \
                     {dead}, {started})"
        ))
        .expect("seed pod_details");
    }

    fn remaining_traffic(conn: &mut PgConnection) -> Vec<String> {
        use crate::schema::pod_traffic::dsl::*;
        pod_traffic
            .select(uuid)
            .order(uuid.asc())
            .load(conn)
            .expect("list traffic")
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_prunes_old_traffic_of_gone_pods_and_keeps_live_pods_rows() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        reset_traffic_tables(&mut conn);
        let days = 14;

        // A long-running pod: its month-old row is a flow it will never
        // report again, so it must survive.
        seed_pod(&mut conn, "api", "prod", false, Some(40));
        seed_traffic(&mut conn, "t01-live-old", "api", "prod", 30);
        seed_traffic(&mut conn, "t02-live-new", "api", "prod", 1);
        // A live pod whose start pod_details does not know yet: kept.
        seed_pod(&mut conn, "unknown-start", "prod", false, None);
        seed_traffic(&mut conn, "t03-live-nostart", "unknown-start", "prod", 30);
        // A dead pod: old rows go, recent rows stay.
        seed_pod(&mut conn, "job-1", "batch", true, Some(40));
        seed_traffic(&mut conn, "t04-dead-old", "job-1", "batch", 20);
        seed_traffic(&mut conn, "t05-dead-new", "job-1", "batch", 3);
        // A pod pod_details has already forgotten: old rows go.
        seed_traffic(&mut conn, "t06-gone-old", "vanished", "batch", 60);
        // Same name, other namespace, live: does not protect this row.
        seed_pod(&mut conn, "shared-name", "team-a", false, Some(40));
        seed_traffic(&mut conn, "t07-other-ns-old", "shared-name", "team-b", 20);
        // A StatefulSet pod recreated 5 days ago under the same name: the
        // previous incarnation's rows go, the current one's stay.
        seed_pod(&mut conn, "db-0", "prod", false, Some(5));
        seed_traffic(&mut conn, "t08-prev-incarnation", "db-0", "prod", 20);

        let batch = |conn: &mut PgConnection, size: i64, after: Option<&TrafficCursor>| {
            run_pod_traffic_batch(conn, days, size, after)
                .expect("prune")
                .map(|b| {
                    (
                        b.uuid.clone(),
                        b.examined,
                        b.deleted,
                        (b.time_stamp, b.uuid),
                    )
                })
        };

        // Batch of one: the LIMIT bounds the batch and the oldest expired
        // row is examined first.
        let (last, examined, deleted, cursor) = batch(&mut conn, 1, None).expect("rows to scan");
        assert_eq!((last.as_str(), examined, deleted), ("t06-gone-old", 1, 1));

        // The next oldest belongs to a live pod: kept, and the cursor still
        // moves past it. A batch that deletes nothing is not the end.
        let (last, examined, deleted, cursor) =
            batch(&mut conn, 1, Some(&cursor)).expect("rows to scan");
        assert_eq!((last.as_str(), examined, deleted), ("t01-live-old", 1, 0));

        // The rest of the window in one batch.
        let (last, examined, deleted, cursor) =
            batch(&mut conn, DEFAULT_BATCH_SIZE, Some(&cursor)).expect("rows to scan");
        assert_eq!(
            (last.as_str(), examined, deleted),
            ("t08-prev-incarnation", 4, 3)
        );
        // Past the last expired row: the scan is done.
        assert!(batch(&mut conn, DEFAULT_BATCH_SIZE, Some(&cursor)).is_none());

        assert_eq!(
            remaining_traffic(&mut conn),
            [
                "t01-live-old",
                "t02-live-new",
                "t03-live-nostart",
                "t05-dead-new"
            ]
            .map(String::from)
        );

        // A fresh scan finds only the live pods' expired rows, and keeps
        // them: this is what every interval does on a settled table.
        let (_, examined, deleted, _) =
            batch(&mut conn, DEFAULT_BATCH_SIZE, None).expect("rows to scan");
        assert_eq!((examined, deleted), (2, 0));

        // Once the long-running pod dies, its old row becomes eligible.
        conn.batch_execute("UPDATE pod_details SET is_dead = true WHERE pod_name = 'api'")
            .expect("kill api");
        let (_, examined, deleted, _) =
            batch(&mut conn, DEFAULT_BATCH_SIZE, None).expect("rows to scan");
        assert_eq!((examined, deleted), (2, 1));
        assert_eq!(
            remaining_traffic(&mut conn),
            ["t02-live-new", "t03-live-nostart", "t05-dead-new"].map(String::from)
        );
        reset_traffic_tables(&mut conn);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_pod_traffic_prune_walks_the_time_stamp_index() {
        use diesel::connection::SimpleConnection;
        #[derive(QueryableByName)]
        struct PlanLine {
            #[diesel(sql_type = diesel::sql_types::Text, column_name = "QUERY PLAN")]
            line: String,
        }
        let mut conn = live_conn();
        reset_traffic_tables(&mut conn);
        // Enough rows that a seq scan + sort is a real alternative, half
        // the pods alive, and fresh stats, so the planner's choice is
        // meaningful. With the liveness test inside the ordered scan this
        // shape planned a Seq Scan + Hash Anti Join + Sort.
        conn.batch_execute(
            "INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, time_stamp) \
             SELECT 'u' || g, 'p' || (g % 500), 'ns', \
                    timezone('UTC', NOW()) - (g || ' minutes')::interval \
             FROM generate_series(1, 50000) g; \
             INSERT INTO pod_details \
               (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead) \
             SELECT 'p' || g, '10.0.0.1', 'ns', timezone('UTC', NOW()), 'n', g % 2 = 0 \
             FROM generate_series(0, 499) g; \
             ANALYZE pod_traffic; ANALYZE pod_details;",
        )
        .expect("seed");
        for sql in [POD_TRAFFIC_PRUNE_SQL, POD_TRAFFIC_PRUNE_AFTER_SQL] {
            let explain = format!(
                "EXPLAIN {}",
                sql.replace("$1::interval", "'14 days'::interval")
                    .replace("$2", "5000")
                    .replace("($3, $4)", "(timestamp '2000-01-01', 'a')")
            );
            let plan: Vec<PlanLine> = sql_query(explain).load(&mut conn).expect("explain");
            let plan = plan
                .into_iter()
                .map(|l| l.line)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                plan.contains(
                    "Index Scan Backward using idx_pod_traffic_time_stamp on pod_traffic t"
                ),
                "the candidate scan should walk idx_pod_traffic_time_stamp:\n{plan}"
            );
            // The expired rows are never sorted: the only Sort allowed is
            // the top-1 over the already-bounded candidate set. (How the
            // DELETE finds its targets by uuid is the planner's call and
            // scale-dependent: a hash join on a small table, the primary
            // key on a large one.)
            assert!(
                !plan.contains("Sort Key: t.time_stamp"),
                "prune must not sort the expired rows:\n{plan}"
            );
        }
        reset_traffic_tables(&mut conn);
    }

    /// `(kind, namespace, name, workload_kind, workload_name)`; `None` is an
    /// unresolved/external peer.
    type Peer<'a> = Option<(&'a str, &'a str, &'a str, Option<&'a str>, Option<&'a str>)>;

    /// One flow row with a stored peer identity (see [`Peer`]).
    #[allow(clippy::too_many_arguments)]
    fn seed_flow(
        conn: &mut PgConnection,
        id: &str,
        pod: &str,
        ns: &str,
        age_days: i64,
        peer_ip: &str,
        port: &str,
        peer: Peer<'_>,
    ) {
        use diesel::connection::SimpleConnection;
        let q = |v: Option<&str>| v.map_or("NULL".to_string(), |s| format!("'{s}'"));
        let (kind, pns, pname, wk, wn) = match peer {
            Some((k, n, p, wk, wn)) => (Some(k), Some(n), Some(p), wk, wn),
            None => (None, None, None, None, None),
        };
        conn.batch_execute(&format!(
            "INSERT INTO pod_traffic \
               (uuid, pod_name, pod_namespace, pod_ip, pod_port, ip_protocol, traffic_type, \
                traffic_in_out_ip, traffic_in_out_port, decision, time_stamp, \
                peer_kind, peer_namespace, peer_name, peer_workload_kind, peer_workload_name) \
             VALUES ('{id}', '{pod}', '{ns}', '10.0.0.9', '{port}', 'TCP', 'INGRESS', \
                     '{peer_ip}', '0', 'ALLOW', \
                     timezone('UTC', NOW()) - INTERVAL '{age_days} days', \
                     {}, {}, {}, {}, {})",
            q(kind),
            q(pns),
            q(pname),
            q(wk),
            q(wn),
        ))
        .expect("seed flow");
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_supersedes_a_live_pods_rows_from_a_cronjob_caller() {
        let mut conn = live_conn();
        reset_traffic_tables(&mut conn);
        let days = 14;
        seed_pod(&mut conn, "api", "prod", false, Some(90));
        let nightly =
            |pod: &'static str| Some(("pod", "batch", pod, Some("CronJob"), Some("nightly")));

        // Three runs of a CronJob calling api:8080, each from a new pod on a
        // new IP. All expired; only the newest may stay.
        seed_flow(
            &mut conn,
            "r1",
            "api",
            "prod",
            40,
            "10.1.0.1",
            "8080",
            nightly("nightly-1"),
        );
        seed_flow(
            &mut conn,
            "r2",
            "api",
            "prod",
            30,
            "10.1.0.2",
            "8080",
            nightly("nightly-2"),
        );
        seed_flow(
            &mut conn,
            "r3",
            "api",
            "prod",
            20,
            "10.1.0.3",
            "8080",
            nightly("nightly-3"),
        );
        // Same caller on ANOTHER port is another rule: kept.
        seed_flow(
            &mut conn,
            "r4-port",
            "api",
            "prod",
            35,
            "10.1.0.1",
            "9090",
            nightly("nightly-1"),
        );
        // A different workload in the same namespace: kept.
        seed_flow(
            &mut conn,
            "r5-other-wl",
            "api",
            "prod",
            35,
            "10.1.0.7",
            "8080",
            Some(("pod", "batch", "weekly-1", Some("CronJob"), Some("weekly"))),
        );
        // Node peers render as their own ipBlock: two nodes, both kept.
        seed_flow(
            &mut conn,
            "r6-node-a",
            "api",
            "prod",
            40,
            "192.168.1.1",
            "8080",
            Some((
                "node",
                "kube-system",
                "cilium-a",
                Some("DaemonSet"),
                Some("cilium"),
            )),
        );
        seed_flow(
            &mut conn,
            "r7-node-b",
            "api",
            "prod",
            30,
            "192.168.1.2",
            "8080",
            Some((
                "node",
                "kube-system",
                "cilium-b",
                Some("DaemonSet"),
                Some("cilium"),
            )),
        );
        // No identity: nothing to supersede on, left to the cap.
        seed_flow(
            &mut conn,
            "r8-ext-a",
            "api",
            "prod",
            40,
            "203.0.113.1",
            "8080",
            None,
        );
        seed_flow(
            &mut conn,
            "r9-ext-b",
            "api",
            "prod",
            30,
            "203.0.113.2",
            "8080",
            None,
        );
        // A Service peer superseded by a newer row that is still INSIDE the
        // window: the old one goes, the fresh one stays.
        let svc = Some(("service", "data", "postgres", None, None));
        seed_flow(
            &mut conn,
            "s1",
            "api",
            "prod",
            30,
            "10.96.0.10",
            "8080",
            svc,
        );
        seed_flow(&mut conn, "s2", "api", "prod", 1, "10.96.0.10", "8080", svc);

        let mut cursor = None;
        let mut deleted = 0;
        while let Some(b) =
            run_pod_traffic_batch(&mut conn, days, 2, cursor.as_ref()).expect("prune")
        {
            deleted += b.deleted;
            cursor = Some((b.time_stamp, b.uuid));
        }
        assert_eq!(deleted, 3);
        assert_eq!(
            remaining_traffic(&mut conn),
            [
                "r3",
                "r4-port",
                "r5-other-wl",
                "r6-node-a",
                "r7-node-b",
                "r8-ext-a",
                "r9-ext-b",
                "s2",
            ]
            .map(String::from)
        );
        // Idempotent: a second full scan finds nothing more to supersede.
        let mut cursor = None;
        while let Some(b) =
            run_pod_traffic_batch(&mut conn, days, DEFAULT_BATCH_SIZE, cursor.as_ref())
                .expect("prune")
        {
            assert_eq!(b.deleted, 0);
            cursor = Some((b.time_stamp, b.uuid));
        }
        reset_traffic_tables(&mut conn);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_per_pod_cap_prunes_only_unidentified_rows_oldest_first() {
        let mut conn = live_conn();
        reset_traffic_tables(&mut conn);
        seed_pod(&mut conn, "ingress", "edge", false, Some(90));
        // 6 external client IPs (oldest first by age) and 3 in-cluster
        // peers, all fresh, so the age pass would touch none of them.
        for (i, age) in [9i64, 8, 7, 6, 5, 4].iter().enumerate() {
            seed_flow(
                &mut conn,
                &format!("x{i}"),
                "ingress",
                "edge",
                *age,
                &format!("198.51.100.{i}"),
                "443",
                None,
            );
        }
        for (i, age) in [9i64, 8, 7].iter().enumerate() {
            seed_flow(
                &mut conn,
                &format!("p{i}"),
                "ingress",
                "edge",
                *age,
                &format!("10.2.0.{i}"),
                "443",
                Some((
                    "pod",
                    "web",
                    "frontend-x",
                    Some("Deployment"),
                    Some(["a", "b", "c"][i]),
                )),
            );
        }
        // Same pod name in another namespace, under the cap: untouched, and
        // not counted towards edge/ingress.
        for i in 0..3 {
            seed_flow(
                &mut conn,
                &format!("o{i}"),
                "ingress",
                "other",
                9,
                &format!("198.51.100.{i}"),
                "443",
                None,
            );
        }

        // Cap 5: edge/ingress has 9, so 4 of its external rows go, oldest
        // first, in batches of 3 (the batch clamp floor is not applied here,
        // the function takes the size it is given).
        let out = cap_pod_traffic(&mut conn, 5, 3, MAX_BATCHES_PER_PASS).expect("cap");
        assert_eq!(
            out,
            vec![CapOutcome {
                pod_name: "ingress".into(),
                pod_namespace: Some("edge".into()),
                rows_before: 9,
                pruned: 4,
            }]
        );
        assert_eq!(
            remaining_traffic(&mut conn),
            ["o0", "o1", "o2", "p0", "p1", "p2", "x4", "x5"].map(String::from)
        );

        // Cap 2: only 2 external rows are left; the in-cluster rows are
        // never pruned, so the pod stays over the cap (the loop warns).
        let out = cap_pod_traffic(&mut conn, 2, 100, MAX_BATCHES_PER_PASS).expect("cap");
        let edge = out
            .iter()
            .find(|o| o.pod_namespace.as_deref() == Some("edge"))
            .expect("edge over cap");
        assert_eq!((edge.rows_before, edge.pruned), (5, 2));
        let left = remaining_traffic(&mut conn);
        assert!(left.iter().all(|u| !u.starts_with('x')), "{left:?}");
        assert!(["p0", "p1", "p2"]
            .iter()
            .all(|p| left.contains(&p.to_string())));

        // The batch budget bounds the work per call.
        reset_traffic_tables(&mut conn);
        for i in 0..10 {
            seed_flow(
                &mut conn,
                &format!("b{i:02}"),
                "busy",
                "edge",
                1,
                &format!("198.51.100.{i}"),
                "443",
                None,
            );
        }
        let out = cap_pod_traffic(&mut conn, 1, 2, 2).expect("cap");
        assert_eq!(out[0].pruned, 4, "two batches of two");
        reset_traffic_tables(&mut conn);
    }

    fn explain(conn: &mut PgConnection, sql: &str) -> String {
        #[derive(QueryableByName)]
        struct PlanLine {
            #[diesel(sql_type = diesel::sql_types::Text, column_name = "QUERY PLAN")]
            line: String,
        }
        let plan: Vec<PlanLine> = sql_query(format!("EXPLAIN {sql}"))
            .load(conn)
            .expect("explain");
        plan.into_iter()
            .map(|l| l.line)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_supersede_and_cap_lookups_use_their_indexes() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        reset_traffic_tables(&mut conn);
        // 50 live pods, 1 000 rows each, every row an identified CronJob
        // caller (20 workloads) on a fresh IP, half of them expired; plus
        // 500 small pods so a per-pod lookup is selective.
        conn.batch_execute(
            "INSERT INTO pod_details \
               (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead) \
             SELECT 'p' || g, '10.0.0.1', 'ns', timezone('UTC', NOW()), 'n', false \
             FROM generate_series(0, 549) g; \
             INSERT INTO pod_traffic \
               (uuid, pod_name, pod_namespace, pod_port, ip_protocol, traffic_type, \
                traffic_in_out_ip, traffic_in_out_port, decision, time_stamp, \
                peer_kind, peer_namespace, peer_name, peer_workload_kind, peer_workload_name) \
             SELECT 'u' || g, 'p' || (g % 50), 'ns', '8080', 'TCP', 'INGRESS', \
                    '10.9.' || (g % 250) || '.' || (g % 200), '0', 'ALLOW', \
                    timezone('UTC', NOW()) - ((g / 2) || ' minutes')::interval, \
                    'pod', 'batch', 'job-' || g, 'CronJob', 'cron-' || (g % 20) \
             FROM generate_series(1, 50000) g; \
             INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, time_stamp) \
             SELECT 'v' || g, 'p' || (50 + g % 500), 'ns', timezone('UTC', NOW()) \
             FROM generate_series(1, 5000) g; \
             ANALYZE pod_traffic; ANALYZE pod_details;",
        )
        .expect("seed");

        let prune = explain(
            &mut conn,
            &POD_TRAFFIC_PRUNE_SQL
                .replace("$1::interval", "'14 days'::interval")
                .replace("$2", "5000"),
        );
        assert!(
            prune.contains("idx_pod_traffic_supersede"),
            "the newer-row lookup should use idx_pod_traffic_supersede:\n{prune}"
        );
        assert!(
            !prune.contains("Sort Key: t.time_stamp"),
            "the supersede rule must not reintroduce a sort of expired rows:\n{prune}"
        );

        let pods = explain(
            &mut conn,
            &POD_TRAFFIC_OVER_CAP_PODS_SQL
                .replace("$1", "'p60'")
                .replace("$2", "5"),
        );
        let cap = explain(
            &mut conn,
            &POD_TRAFFIC_CAP_PRUNE_SQL
                .replace("$1", "'p60'")
                .replace("$2", "'ns'")
                .replace("$3", "5"),
        );
        for plan in [pods, cap] {
            assert!(
                plan.contains("idx_pod_traffic_pod_name"),
                "per-pod cap statements should use idx_pod_traffic_pod_name:\n{plan}"
            );
            assert!(!plan.contains("Seq Scan on pod_traffic"), "{plan}");
        }
        reset_traffic_tables(&mut conn);
    }
}
