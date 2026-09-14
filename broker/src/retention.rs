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
//! 3. **Dead containers**: `pod_compute_latest` rows not refreshed for
//!    10 minutes (the container is gone, or its node's controller is).
//!    Runs regardless of the history setting.
//!
//! # Seccomp denials
//!
//! A third loop prunes `seccomp_denials` by `last_seen`, on the same batched
//! CTE pattern:
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
        "seccomp denial retention loop scheduled (days=0 means pruning off)"
    );
    if days == 0 {
        return;
    }
    actix_web::rt::spawn(async move {
        // Staggered against the other two loops' 60 s and 90 s warmups so
        // three full-table prunes do not land on a cold pool together.
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            run_seccomp_denial_pass(&pool, days).await;
            // Once per pass, after the denial prune: the node table is one
            // row per node, so it needs no batching and no cadence of its
            // own.
            prune_stale_denial_nodes(&pool, days).await;
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
/// (minutes), this decides whether the node still exists (days). Pruning on
/// the staleness window would delete a node's row during a long Controller
/// outage and then recreate it on recovery, which loses nothing but churns
/// the table for no reason.
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
/// rows. Each step is independent — a failure in one is logged and the
/// next still runs — and each batch is its own `spawn_blocking`.
async fn run_compute_pass(pool: &DbPool, days: u32, minute_hours: u32) {
    if days > 0 {
        run_downsample(pool, minute_hours).await;
        run_compute_prune(pool, "pod_compute_history", days).await;
        run_compute_prune(pool, "pod_contention_history", days).await;
    }
    run_stale_latest(pool).await;
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
}
