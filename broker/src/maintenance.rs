//! Maintenance VACUUM of the broker's small, high-churn tables.
//!
//! A handful of tables are rewritten continuously but stay small:
//! `pod_compute_latest` is upserted for every live container every 5 s,
//! `node_compute_latest` for every node, and the mirrors and rollups below
//! are replaced wholesale or refreshed on a timer. Page pruning keeps HOT
//! updates in check, but only VACUUM removes dead line pointers, dead TOAST
//! rows, the index entries of deleted rows, and keeps the visibility map
//! current. That is autovacuum's job, and the per-table settings in the
//! migrations make it visit these tables every round. But the broker must
//! not depend on it: on the dev cluster autovacuum stopped cluster-wide
//! (a platform fault on a shared Aurora cluster), and within hours
//! `pod_compute_latest` held 982 MB for 2 900 live rows.
//!
//! So the leader checks the tables every
//! `BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS` (default 300; paced by
//! `leader::Cadence`, so a hand-off neither repeats nor skips a pass, and a
//! pass that loses leadership stops before its next table) and runs a
//! plain `VACUUM (ANALYZE)` on each one whose dead
//! tuples, heap plus TOAST, reach `BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES`
//! (default 10 000) and a fifth of its live rows. With autovacuum healthy
//! the counts stay under that and a pass is one catalog query. Never
//! `VACUUM FULL`: that takes an ACCESS EXCLUSIVE lock and rewrites the
//! table, blocking every upsert and read for the duration.
//!
//! The big append-and-prune tables (`pod_compute_history`, `pod_traffic`,
//! `pod_contention_history`, ...) are deliberately not on the list: a
//! VACUUM of tens of GB is hours of I/O the broker should not start on its
//! own. Nor is any table the broker builds indexes on in the background
//! (`CREATE INDEX CONCURRENTLY`, e.g. the compute history minute index):
//! a VACUUM there would contend with the build's lock and must be
//! coordinated with it, not fired on a timer. See [`TABLES`] and
//! [`NEVER_VACUUMED`].
//!
//! VACUUM cannot run inside a transaction, so each pass opens its own
//! connection (like `background_index::ensure_index`), with a
//! `statement_timeout` sized for small tables ([`STATEMENT_TIMEOUT`]) and a
//! short `lock_timeout` ([`LOCK_TIMEOUT`]): VACUUM's lock conflicts only
//! with another VACUUM, ANALYZE or DDL on the same table, and if one holds
//! it (autovacuum doing the work after all) the table is skipped until the
//! next pass. It needs no privilege beyond owning the table, which the
//! broker's user does for every table its migrations created (or MAINTAIN
//! on PostgreSQL 17+). A table it may not vacuum is warned about once and
//! skipped; VACUUM itself would only emit a WARNING and do nothing.
//!
//! `BROKER_MAINTENANCE_VACUUM_ENABLED=false` turns the task off.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Bool, Text};
use tracing::{debug, info, warn};

type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>;

/// Tables the pass considers, in the order it vacuums them. Chosen by
/// churn and size: each is rewritten continuously (upserted every sample,
/// or deleted and re-inserted on a timer) but holds at most thousands of
/// rows, so a VACUUM of it takes seconds even when it is badly bloated.
/// A table missing from the schema is skipped. Never add one of
/// [`NEVER_VACUUMED`] (a unit test enforces it).
pub const TABLES: [&str; 7] = [
    // One row per live container, upserted every 5 s; a TOAST table.
    "pod_compute_latest",
    // One row per node, upserted with every compute batch.
    "node_compute_latest",
    // One row per SeccompProfile CR, refreshed by every Controller.
    "seccomp_crs",
    // One row per node, upserted with every denial drain.
    "seccomp_denial_nodes",
    // Deleted and rebuilt whole by every in-use refresh.
    "runtime_in_use_coverage",
    // One row per container of an image with a node SBOM, refreshed by
    // every in-use refresh (rows whose guard changed are updated, gone
    // ones deleted).
    "runtime_node_sbom_guard",
    // One row per workload container and digest, refreshed on a throttle.
    "workload_containers",
];

/// Tables this task must never VACUUM: the large append-and-prune tables,
/// whose VACUUM is heavy, and every table with a background
/// `CREATE INDEX CONCURRENTLY` (`background_index::INDEXES`), whose
/// maintenance goes through `background_index::with_table_maintenance`
/// instead. A unit test checks every table in that list is here.
pub const NEVER_VACUUMED: [&str; 7] = [
    "pod_compute_history",
    "pod_contention_history",
    "pod_traffic",
    "pod_syscalls",
    "image_sbom_components",
    "seccomp_denials",
    "audit_verdicts",
];

const DEFAULT_INTERVAL_SECS: u64 = 300;
const MIN_INTERVAL_SECS: u64 = 60;
const DEFAULT_DEAD_TUPLES: i64 = 10_000;
const MIN_DEAD_TUPLES: i64 = 1_000;
/// A table also needs this fraction of its live rows dead, autovacuum's own
/// default scale factor, so a large healthy table is not vacuumed for a
/// dead count that is noise next to its size.
const DEAD_FRACTION_OF_LIVE: i64 = 5;
/// Per VACUUM. A bloated `pod_compute_latest` of a few GB finishes well
/// inside this; anything slower is a sign the table is not small any more,
/// and a cancelled VACUUM keeps the pages it already pruned.
const STATEMENT_TIMEOUT: &str = "300s";
/// How long a VACUUM waits for its table lock before giving the table up
/// until the next pass.
const LOCK_TIMEOUT: &str = "5s";
/// First pass after startup: after the pool has warmed and the migrations'
/// own work is done, never on the startup path.
const WARMUP: Duration = Duration::from_secs(120);
/// The task's name in logs and `leader_task_runs`.
const TASK: &str = "maintenance vacuum";
/// Longest wait after repeated failures.
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// `BROKER_MAINTENANCE_VACUUM_ENABLED` (default true).
pub fn enabled() -> bool {
    std::env::var("BROKER_MAINTENANCE_VACUUM_ENABLED")
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "false" | "0" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

/// `BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS` (default 300, min 60).
pub fn interval() -> Duration {
    let secs = std::env::var("BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs.max(MIN_INTERVAL_SECS))
}

/// `BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES` (default 10 000, min 1 000).
pub fn dead_tuple_threshold() -> i64 {
    std::env::var("BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_DEAD_TUPLES)
        .max(MIN_DEAD_TUPLES)
}

/// Whether `dead` tuples (heap plus TOAST) out of `live` call for a VACUUM.
pub(crate) fn needs_vacuum(dead: i64, live: i64, threshold: i64) -> bool {
    dead >= threshold && dead >= live / DEAD_FRACTION_OF_LIVE
}

/// What the pass did with one table (the `outcome` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Outcome {
    /// Under the threshold: nothing to do (autovacuum is keeping up).
    Skipped,
    Vacuumed,
    /// Its lock was held (another VACUUM, ANALYZE or DDL); next pass.
    Busy,
    /// The broker's user neither owns it nor holds MAINTAIN.
    Denied,
    Failed,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Skipped => "skipped",
            Outcome::Vacuumed => "vacuumed",
            Outcome::Busy => "busy",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        }
    }
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

fn counts() -> &'static Mutex<BTreeMap<(&'static str, Outcome), u64>> {
    static COUNTS: OnceLock<Mutex<BTreeMap<(&'static str, Outcome), u64>>> = OnceLock::new();
    COUNTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Unix seconds of the last pass that checked every table without a
/// failure; 0 until one has.
static LAST_SUCCESS: AtomicI64 = AtomicI64::new(0);

fn record(table: &'static str, outcome: Outcome) {
    let mut c = counts().lock().unwrap_or_else(|p| p.into_inner());
    *c.entry((table, outcome)).or_insert(0) += 1;
}

/// Prometheus text for the maintenance task.
pub fn render_metrics() -> String {
    let mut out = String::from(
        "# HELP broker_maintenance_vacuum_total Maintenance VACUUM decisions per table (skipped = under the dead-tuple threshold, busy = lock held elsewhere, denied = not owner); leader only\n\
         # TYPE broker_maintenance_vacuum_total counter\n",
    );
    let c = counts().lock().unwrap_or_else(|p| p.into_inner());
    for ((table, outcome), n) in c.iter() {
        out.push_str(&format!(
            "broker_maintenance_vacuum_total{{table=\"{table}\",outcome=\"{}\"}} {n}\n",
            outcome.label()
        ));
    }
    out.push_str(&format!(
        "# HELP broker_maintenance_vacuum_last_success_timestamp_seconds Unix time of the last maintenance pass that checked every table without a failure; 0 before the first (only the leader runs passes)\n\
         # TYPE broker_maintenance_vacuum_last_success_timestamp_seconds gauge\n\
         broker_maintenance_vacuum_last_success_timestamp_seconds {}\n",
        LAST_SUCCESS.load(Ordering::Relaxed)
    ));
    out
}

// ---------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------

#[derive(QueryableByName, Debug)]
struct TableStat {
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = BigInt)]
    heap_dead: i64,
    #[diesel(sql_type = BigInt)]
    toast_dead: i64,
    #[diesel(sql_type = BigInt)]
    live: i64,
    #[diesel(sql_type = Bool)]
    permitted: bool,
}

/// Dead and live tuple counts for [`TABLES`] from the statistics
/// collector, and whether this session may vacuum each one. The TOAST
/// table's dead rows count too: they are most of the bloat when a large
/// column is rewritten, and they are invisible in `pg_stat_user_tables`.
const STATS_SQL: &str = "\
SELECT t.name, \
       pg_stat_get_dead_tuples(c.oid) AS heap_dead, \
       CASE WHEN c.reltoastrelid = 0 THEN 0 \
            ELSE pg_stat_get_dead_tuples(c.reltoastrelid) END AS toast_dead, \
       pg_stat_get_live_tuples(c.oid) AS live, \
       (pg_has_role(c.relowner, 'USAGE') OR \
        CASE WHEN current_setting('server_version_num')::int >= 170000 \
             THEN has_table_privilege(c.oid, 'MAINTAIN') ELSE false END) AS permitted \
FROM unnest($1::text[]) WITH ORDINALITY AS t(name, ord) \
JOIN pg_class c ON c.oid = to_regclass(t.name) \
ORDER BY t.ord";

/// Tables already warned about as not vacuumable, so the warning is once
/// per table per process rather than every pass.
fn warned_denied() -> &'static Mutex<HashSet<&'static str>> {
    static WARNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn is_lock_timeout(e: &diesel::result::Error) -> bool {
    matches!(e, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("lock timeout"))
}

/// One pass on `conn`, a dedicated session outside any transaction.
/// Returns each table's outcome, or an error when the tables could not be
/// examined at all.
pub(crate) fn run_pass(
    conn: &mut PgConnection,
    threshold: i64,
) -> Result<Vec<(&'static str, Outcome)>, diesel::result::Error> {
    conn.batch_execute(&format!(
        "SET statement_timeout = '{STATEMENT_TIMEOUT}'; SET lock_timeout = '{LOCK_TIMEOUT}'; \
         SET application_name = 'kguardian-broker-maintenance'"
    ))?;
    let names: Vec<String> = TABLES.iter().map(|t| t.to_string()).collect();
    let stats = diesel::sql_query(STATS_SQL)
        .bind::<Array<Text>, _>(&names)
        .load::<TableStat>(conn)?;
    let mut out = Vec::with_capacity(stats.len());
    for s in stats {
        // A pass that loses leadership stops before its next table; a
        // VACUUM already running finishes.
        if !crate::leader::still_leader(TASK) {
            break;
        }
        // The query returns names from TABLES only; map back to the
        // 'static entry for the metric label.
        let Some(table) = TABLES.iter().copied().find(|t| *t == s.name) else {
            continue;
        };
        // Also enforced by a unit test; this keeps a bad edit to TABLES
        // from ever reaching a heavy or index-building table.
        if NEVER_VACUUMED.contains(&table) {
            continue;
        }
        let dead = s.heap_dead.saturating_add(s.toast_dead);
        let outcome = if !needs_vacuum(dead, s.live, threshold) {
            debug!(table, dead, live = s.live, "maintenance vacuum not needed");
            Outcome::Skipped
        } else if !s.permitted {
            let first = warned_denied()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(table);
            if first {
                warn!(
                    table,
                    dead,
                    "maintenance VACUUM skipped: the broker's database user neither owns this table nor holds MAINTAIN on it; grant ownership (ALTER TABLE ... OWNER TO) or leave vacuuming to autovacuum. Warned once per table"
                );
            }
            Outcome::Denied
        } else {
            debug!(
                table,
                heap_dead = s.heap_dead,
                toast_dead = s.toast_dead,
                live = s.live,
                "maintenance VACUUM starting"
            );
            let started = Instant::now();
            // The name is one of TABLES, never input; quoted regardless.
            match conn.batch_execute(&format!("VACUUM (ANALYZE) \"{table}\"")) {
                Ok(()) => {
                    info!(
                        table,
                        heap_dead = s.heap_dead,
                        toast_dead = s.toast_dead,
                        live = s.live,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "maintenance VACUUM finished (autovacuum is not keeping this table clean)"
                    );
                    Outcome::Vacuumed
                }
                Err(e) if is_lock_timeout(&e) => {
                    info!(
                        table,
                        "maintenance VACUUM skipped: the table's lock is held (another VACUUM or DDL); next pass"
                    );
                    Outcome::Busy
                }
                Err(e) => {
                    warn!(
                        table,
                        error = %e,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "maintenance VACUUM failed"
                    );
                    Outcome::Failed
                }
            }
        };
        out.push((table, outcome));
    }
    Ok(out)
}

/// Start the maintenance loop (module docs). Leader only, paced by
/// [`crate::leader::Cadence`] like the retention loops, so replicas keep
/// one schedule across a hand-off; off with
/// `BROKER_MAINTENANCE_VACUUM_ENABLED=false`. `pool` records completed
/// passes (`leader_task_runs`); the VACUUMs run on their own connection.
pub fn spawn(pool: DbPool) {
    if !enabled() {
        info!("maintenance VACUUM disabled (BROKER_MAINTENANCE_VACUUM_ENABLED=false)");
        return;
    }
    let Some(url) = std::env::var("DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        warn!("DATABASE_URL unset; maintenance VACUUM not scheduled");
        return;
    };
    let interval = interval();
    let threshold = dead_tuple_threshold();
    info!(
        interval_secs = interval.as_secs(),
        dead_tuples = threshold,
        tables = ?TABLES,
        "maintenance VACUUM scheduled (leader only; a no-op while autovacuum keeps up)"
    );
    actix_web::rt::spawn(async move {
        tokio::time::sleep(WARMUP).await;
        let mut cadence = crate::leader::Cadence::new(TASK, interval);
        let mut failures: u32 = 0;
        loop {
            let url = url.clone();
            let ran = crate::leader::singleton(TASK, async move {
                tokio::task::spawn_blocking(move || -> Result<_, String> {
                    let mut conn =
                        PgConnection::establish(&url).map_err(|e| format!("connect: {e}"))?;
                    run_pass(&mut conn, threshold).map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| format!("task panicked: {e}"))
                .and_then(|r| r)
            })
            .await;
            if let Some(result) = ran {
                let ok = match result {
                    Ok(outcomes) => {
                        let mut ok = true;
                        for (table, outcome) in outcomes {
                            record(table, outcome);
                            ok &= outcome != Outcome::Failed;
                        }
                        ok
                    }
                    Err(e) => {
                        warn!(error = %e, "maintenance VACUUM pass failed");
                        false
                    }
                };
                if ok {
                    failures = 0;
                    LAST_SUCCESS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
                    // Only a clean pass counts as the cluster's last one, so
                    // a new leader retries a failed pass promptly.
                    cadence.completed(&pool).await;
                } else {
                    failures = failures.saturating_add(1);
                    let wait = backoff(interval, failures);
                    warn!(
                        failures,
                        retry_secs = wait.as_secs(),
                        "maintenance VACUUM backing off"
                    );
                    // The cadence waits one interval; the back-off is the rest.
                    tokio::time::sleep(wait.saturating_sub(interval)).await;
                }
            }
            cadence.wait(&pool).await;
        }
    });
}

/// The wait after `failures` failed passes in a row: the interval doubled
/// per failure, at most [`MAX_BACKOFF`].
pub(crate) fn backoff(interval: Duration, failures: u32) -> Duration {
    let factor = 1u32 << failures.min(10);
    interval
        .saturating_mul(factor)
        .min(MAX_BACKOFF.max(interval))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vacuum_only_past_both_thresholds() {
        assert!(!needs_vacuum(0, 0, 10_000));
        assert!(!needs_vacuum(9_999, 100, 10_000));
        assert!(needs_vacuum(10_000, 2_900, 10_000));
        // A large table needs a fifth of its rows dead as well.
        assert!(!needs_vacuum(50_000, 1_000_000, 10_000));
        assert!(needs_vacuum(200_000, 1_000_000, 10_000));
    }

    #[test]
    fn backoff_doubles_to_an_hour() {
        let i = Duration::from_secs(300);
        assert_eq!(backoff(i, 1), Duration::from_secs(600));
        assert_eq!(backoff(i, 2), Duration::from_secs(1200));
        assert_eq!(backoff(i, 4), MAX_BACKOFF);
        assert_eq!(backoff(i, 40), MAX_BACKOFF);
        // An interval longer than the cap is never shortened by a failure.
        let long = Duration::from_secs(7200);
        assert_eq!(backoff(long, 3), long);
    }

    #[test]
    fn env_settings_parse_and_clamp() {
        let _g = crate::test_support::env_lock();
        let set = |k: &str, v: Option<&str>| match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        };
        set("BROKER_MAINTENANCE_VACUUM_ENABLED", None);
        assert!(enabled());
        for off in ["false", " FALSE ", "0", "off", "no"] {
            set("BROKER_MAINTENANCE_VACUUM_ENABLED", Some(off));
            assert!(!enabled(), "{off:?}");
        }
        set("BROKER_MAINTENANCE_VACUUM_ENABLED", Some("true"));
        assert!(enabled());
        set("BROKER_MAINTENANCE_VACUUM_ENABLED", None);

        set("BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS", None);
        assert_eq!(interval(), Duration::from_secs(300));
        set("BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS", Some("5"));
        assert_eq!(interval(), Duration::from_secs(60));
        set("BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS", Some(" 600 "));
        assert_eq!(interval(), Duration::from_secs(600));
        set("BROKER_MAINTENANCE_VACUUM_INTERVAL_SECS", None);

        set("BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES", None);
        assert_eq!(dead_tuple_threshold(), 10_000);
        set("BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES", Some("10"));
        assert_eq!(dead_tuple_threshold(), 1_000);
        set("BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES", Some("50000"));
        assert_eq!(dead_tuple_threshold(), 50_000);
        set("BROKER_MAINTENANCE_VACUUM_DEAD_TUPLES", None);
    }

    #[test]
    fn heavy_and_index_building_tables_are_never_vacuumed() {
        for t in NEVER_VACUUMED {
            assert!(!TABLES.contains(&t), "{t} must not be on the VACUUM list");
        }
        // Every table a background index build runs on.
        for index in crate::background_index::INDEXES {
            assert!(
                NEVER_VACUUMED.contains(&index.table),
                "{} has a background build ({})",
                index.table,
                index.name
            );
        }
    }

    #[test]
    fn metrics_render_headers_and_series() {
        record("seccomp_crs", Outcome::Skipped);
        record("seccomp_crs", Outcome::Skipped);
        let text = render_metrics();
        assert!(text.contains("# TYPE broker_maintenance_vacuum_total counter\n"));
        assert!(text.contains(
            "broker_maintenance_vacuum_total{table=\"seccomp_crs\",outcome=\"skipped\"} "
        ));
        assert!(text
            .contains("# TYPE broker_maintenance_vacuum_last_success_timestamp_seconds gauge\n"));
    }

    // ---- live database ---------------------------------------------------

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
        conn
    }

    #[derive(QueryableByName)]
    struct Dead {
        #[diesel(sql_type = BigInt)]
        heap: i64,
        #[diesel(sql_type = BigInt)]
        toast: i64,
    }

    fn dead(conn: &mut PgConnection) -> Dead {
        conn.batch_execute("SELECT pg_stat_force_next_flush()").ok();
        diesel::sql_query(
            "SELECT pg_stat_get_dead_tuples(oid) AS heap, \
                    pg_stat_get_dead_tuples(reltoastrelid) AS toast \
             FROM pg_class WHERE oid = 'pod_compute_latest'::regclass",
        )
        .get_result::<Dead>(conn)
        .expect("read dead tuples")
    }

    /// With dead heap and TOAST tuples past the threshold the pass
    /// vacuums the table and the counts drop; below it, it does nothing;
    /// as a role that does not own the table, it reports `denied` rather
    /// than letting VACUUM skip it with a WARNING nobody reads.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_maintenance_vacuums_bloated_small_tables() {
        let mut conn = live_conn();
        // Big, incompressible blame values are TOASTed, and deleting the
        // rows leaves dead heap and TOAST tuples, the dev cluster's shape.
        conn.batch_execute(
            "TRUNCATE pod_compute_latest; \
             INSERT INTO pod_compute_latest (container_uid, pod_uid, namespace, pod_name, \
               container, node, cgroup_id, ts, interval_ms, cpu_usage_millis, cpu_period_usec, \
               cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec, cpu_psi_some10, \
               cpu_psi_full10, mem_current, mem_working_set, mem_psi_some10, mem_psi_full10, \
               mem_events_high, mem_events_max, mem_oom_kill, mem_refault, mem_pgmajfault, \
               blame, updated_at) \
             SELECT 'c-' || g, 'p', 'ns', 'pod', 'app', 'n', g, now(), 5000, 0, 100000, \
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
               (SELECT jsonb_agg(md5(g::text || ':' || k)) FROM generate_series(1, 150) k), now() \
             FROM generate_series(1, 3000) g; \
             DELETE FROM pod_compute_latest;",
        )
        .expect("bloat pod_compute_latest");
        let before = dead(&mut conn);
        assert!(before.heap >= 3000, "heap dead {}", before.heap);
        assert!(before.toast >= 3000, "toast dead {}", before.toast);

        let outcomes = run_pass(&mut conn, MIN_DEAD_TUPLES).expect("pass runs");
        assert!(
            outcomes.contains(&("pod_compute_latest", Outcome::Vacuumed)),
            "{outcomes:?}"
        );
        let after = dead(&mut conn);
        assert_eq!((after.heap, after.toast), (0, 0));

        // Nothing dead now: the next pass is a no-op for this table.
        let outcomes = run_pass(&mut conn, MIN_DEAD_TUPLES).expect("pass runs");
        assert!(outcomes.contains(&("pod_compute_latest", Outcome::Skipped)));

        // A role that does not own the tables is told so, not silently
        // skipped by VACUUM.
        conn.batch_execute(
            "DROP ROLE IF EXISTS kg_maint_other; CREATE ROLE kg_maint_other; \
             INSERT INTO pod_compute_latest (container_uid, pod_uid, namespace, pod_name, \
               container, node, cgroup_id, ts, interval_ms, cpu_usage_millis, cpu_period_usec, \
               cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec, cpu_psi_some10, \
               cpu_psi_full10, mem_current, mem_working_set, mem_psi_some10, mem_psi_full10, \
               mem_events_high, mem_events_max, mem_oom_kill, mem_refault, mem_pgmajfault, \
               blame, updated_at) \
             SELECT 'c-' || g, 'p', 'ns', 'pod', 'app', 'n', g, now(), 5000, 0, 100000, \
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '[]', now() \
             FROM generate_series(1, 2000) g; \
             DELETE FROM pod_compute_latest;",
        )
        .expect("bloat again");
        assert!(dead(&mut conn).heap >= 2000);
        conn.batch_execute("SET ROLE kg_maint_other")
            .expect("become a role that owns nothing");
        let outcomes = run_pass(&mut conn, MIN_DEAD_TUPLES).expect("pass runs");
        conn.batch_execute("RESET ROLE; DROP ROLE kg_maint_other")
            .expect("clean up the role");
        assert!(
            outcomes.contains(&("pod_compute_latest", Outcome::Denied)),
            "{outcomes:?}"
        );
        conn.batch_execute("VACUUM pod_compute_latest")
            .expect("leave the table clean");
    }
}
