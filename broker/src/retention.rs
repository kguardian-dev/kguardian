//! Periodic cleanup of old audit_verdicts rows.
//!
//! The audit_verdicts table grows monotonically with the volume of
//! "would deny" flow events. Without a retention policy, indexes
//! degrade and disk usage climbs indefinitely on busy clusters.
//!
//! This module spawns a tokio task on broker startup that wakes every
//! `RETENTION_INTERVAL` and runs:
//!
//!     DELETE FROM audit_verdicts WHERE observed_at < NOW() - INTERVAL '<N> days';
//!
//! Configuration:
//!
//! - `AUDIT_VERDICTS_RETENTION_DAYS` (default 30) — anything older than
//!   N days is eligible for deletion. Setting to 0 disables retention.
//! - `AUDIT_VERDICTS_RETENTION_INTERVAL_SECS` (default 3600 = 1h) — how
//!   often the cleanup task runs.
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
            tokio::time::sleep(interval).await;
        }
    });
}

/// One cleanup pass — runs in a blocking pool task because diesel is
/// sync. Logs the result and never propagates errors.
async fn run_pass(pool: &DbPool, days: u32) {
    let pool = pool.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
        let mut conn = pool.get().map_err(RetentionError::Pool)?;
        let interval = format!("{} days", days);
        // The interval value is server-side computed (NOW() -
        // INTERVAL ...) using a parameterised value via diesel's
        // sql_query bind. We construct the literal in code and bind
        // as text — the server casts to interval. That avoids any
        // SQL-injection surface even if `days` were ever sourced from
        // user input (it isn't, but defensible).
        let deleted = sql_query(
            "DELETE FROM audit_verdicts \
             WHERE observed_at < (NOW() - $1::interval)",
        )
        .bind::<diesel::sql_types::Text, _>(interval)
        .execute(&mut conn)
        .map_err(RetentionError::Diesel)?;
        Ok(deleted)
    })
    .await;
    match result {
        Ok(Ok(0)) => debug!("audit_verdicts retention: 0 rows pruned"),
        Ok(Ok(n)) => info!(rows = n, "audit_verdicts retention pruned old rows"),
        Ok(Err(RetentionError::Pool(e))) => {
            warn!(error = %e, "audit_verdicts retention: could not get db conn")
        }
        Ok(Err(RetentionError::Diesel(e))) => {
            warn!(error = %e, "audit_verdicts retention: DELETE failed")
        }
        Err(e) => warn!(error = %e, "audit_verdicts retention task panicked"),
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
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

fn retention_interval() -> Duration {
    let secs = std::env::var("AUDIT_VERDICTS_RETENTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs.max(60))
}
