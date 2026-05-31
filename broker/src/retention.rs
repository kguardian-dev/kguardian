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

/// Spawn a background task that periodically prunes audit_verdicts.
/// Returns immediately; the task lives for the broker's lifetime.
///
/// When `AUDIT_VERDICTS_RETENTION_DAYS=0`, retention is disabled and
/// the task is not spawned.
pub fn spawn(pool: DbPool) {
    let days = retention_days();
    if days == 0 {
        info!("audit_verdicts retention disabled (AUDIT_VERDICTS_RETENTION_DAYS=0)");
        return;
    }
    let interval = retention_interval();
    info!(
        days,
        interval_secs = interval.as_secs(),
        "audit_verdicts retention loop scheduled"
    );

    actix_web::rt::spawn(async move {
        // First pass after a short warmup so the broker doesn't hammer
        // a cold pool the second it starts.
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            run_pass(&pool, days).await;
            run_dead_pod_pass(&pool, days).await;
            tokio::time::sleep(interval).await;
        }
    });
}

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
