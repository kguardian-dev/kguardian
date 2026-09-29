//! Indexes on tables that can be large, built `CONCURRENTLY` by a
//! background task instead of by a migration.
//!
//! # Why not a migration
//!
//! Migrations run before the HTTP server binds, inside a transaction, so a
//! plain `CREATE INDEX` on a large table (23 GB of `pod_compute_history` on
//! the dev cluster) can outlast the liveness probe's ~200 s. The kubelet
//! kills the pod and it starts the build again, while Postgres keeps every
//! orphaned build running with its SHARE lock, blocking every INSERT into
//! the table. Those inserts hold a pool connection each while they wait, so
//! the old pod's pool runs dry, `/health` fails, and a single-replica Broker
//! goes down entirely. `CONCURRENTLY` blocks no writes but cannot run in a
//! transaction, and a build that fails leaves an INVALID index that
//! `IF NOT EXISTS` would then skip for good, so it runs here, after startup,
//! on its own connection, and repairs that case itself.
//!
//! Two kinds of index are in [`INDEXES`]:
//!
//! - Indexes no migration creates (the compute history and contention
//!   ones): this task is their only builder, on fresh installs too.
//! - Indexes an older migration creates with a plain `CREATE INDEX`
//!   (`pod_traffic`, `pod_syscalls`, `image_sbom_components`). Those
//!   migrations now build inline only while the table is small (256 MiB of
//!   heap) and otherwise skip, so a fresh install still gets them from the
//!   migration and an install upgrading with a large table gets them from
//!   here. For an install that applied the old form the index is already
//!   there and valid, and this task only confirms it.
//!
//! # VACUUM and the build lock
//!
//! A `CREATE INDEX CONCURRENTLY` holds SHARE UPDATE EXCLUSIVE on its table
//! for the whole build (hours on the dev cluster's history table), and so
//! does VACUUM: the two cannot run on one table at once. A Broker-run
//! VACUUM that started during a build would queue behind it for hours,
//! holding its connection, while the retention passes keep deleting rows it
//! was meant to reclaim. So every build holds a session advisory lock for
//! its index ([`lock_key`]), and any Broker task that VACUUMs a table in
//! [`INDEXES`] must go through [`with_table_maintenance`], which takes the
//! same locks without waiting: it runs the VACUUM only when no build of an
//! index on that table is in progress, and a build started meanwhile finds
//! the lock taken and waits for its next attempt. ANALYZE takes the same
//! table lock, so the stale-statistics ANALYZE this task runs
//! ([`analyze_if_stale`]) goes through [`with_table_maintenance`] too.
//! Autovacuum does not take these locks; while a build runs, Postgres
//! cancels an ordinary autovacuum of the table in the build's favour, and an
//! anti-wraparound one makes the build wait instead. Both are one-off costs
//! of the first build.

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::Text;
use std::time::Duration;
use tracing::{debug, info, warn};

/// One index this task keeps present and valid.
#[derive(Debug)]
pub(crate) struct BackgroundIndex {
    pub name: &'static str,
    pub table: &'static str,
    /// `CREATE INDEX CONCURRENTLY IF NOT EXISTS <name> ...`.
    pub create: &'static str,
    /// Only while compute history is on (`COMPUTE_HISTORY_RETENTION_DAYS`
    /// > 0): its readers and writers are the history reads and passes.
    pub history_only: bool,
}

/// Partial index on the minute tier of `pod_compute_history`, for the
/// downsample's oldest-row lookup and batch range (retention.rs,
/// `OLDEST_MINUTE_ROW_SQL`). Partial rather than `(resolution_secs, ts)`
/// because nothing reads the five-minute tier by resolution.
pub(crate) const MINUTE_INDEX: &str = "idx_pod_compute_history_minute_ts";

/// Every index this task maintains, in build order. The minute index goes
/// first (the downsample times out without it), then the indexes the older
/// migrations may have skipped (the traffic prune and ingest dedup need
/// them), and the new history and contention read indexes last: those are
/// the multi-hour builds on a large install, and the reads they serve work,
/// more slowly, without them.
pub(crate) const INDEXES: &[BackgroundIndex] = &[
    BackgroundIndex {
        name: MINUTE_INDEX,
        table: "pod_compute_history",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_compute_history_minute_ts \
                 ON pod_compute_history (ts) WHERE resolution_secs = 60",
        history_only: true,
    },
    // The next seven are the migrations' own definitions (2026-06-01,
    // 2026-07-06, 2026-09-26, 2026-09-28), character for character but
    // CONCURRENTLY, for installs whose table was too large to build them
    // inline.
    BackgroundIndex {
        name: "idx_pod_traffic_pod_name",
        table: "pod_traffic",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_traffic_pod_name \
                 ON pod_traffic (pod_name)",
        history_only: false,
    },
    BackgroundIndex {
        name: "idx_pod_traffic_pod_ip",
        table: "pod_traffic",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_traffic_pod_ip \
                 ON pod_traffic (pod_ip)",
        history_only: false,
    },
    BackgroundIndex {
        name: "idx_pod_traffic_dedup",
        table: "pod_traffic",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_traffic_dedup \
                 ON pod_traffic (pod_ip, pod_port, traffic_type, traffic_in_out_ip, \
                 traffic_in_out_port, decision)",
        history_only: false,
    },
    BackgroundIndex {
        name: "idx_pod_syscalls_pod_name",
        table: "pod_syscalls",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_syscalls_pod_name \
                 ON pod_syscalls (pod_name)",
        history_only: false,
    },
    BackgroundIndex {
        name: "idx_pod_traffic_time_stamp",
        table: "pod_traffic",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_traffic_time_stamp \
                 ON pod_traffic (time_stamp DESC, uuid DESC)",
        history_only: false,
    },
    BackgroundIndex {
        name: "idx_pod_traffic_supersede",
        table: "pod_traffic",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_traffic_supersede \
                 ON pod_traffic (pod_name, peer_namespace, \
                 (COALESCE(peer_workload_name, peer_name)), time_stamp) \
                 WHERE peer_kind IN ('pod', 'service')",
        history_only: false,
    },
    BackgroundIndex {
        name: "idx_image_sbom_components_name",
        table: "image_sbom_components",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_image_sbom_components_name \
                 ON image_sbom_components (digest, source, name)",
        history_only: false,
    },
    // GET /compute/findings?namespace= finds its victims by namespace in
    // the last few minutes (compute_api.rs `load_findings_victims`).
    // Without it that read walks every row of the window for every
    // namespace, and on a table with stale statistics the planner picks far
    // worse (see that function).
    BackgroundIndex {
        name: "idx_pod_compute_history_ns_minute_ts",
        table: "pod_compute_history",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_compute_history_ns_minute_ts \
                 ON pod_compute_history (namespace, ts) WHERE resolution_secs = 60",
        history_only: true,
    },
    // GET /compute/contention?namespace= (compute_api.rs
    // `contention_pairs`), which otherwise reads every namespace's pairs in
    // the window and filters.
    BackgroundIndex {
        name: "idx_pod_contention_history_ns_ts",
        table: "pod_contention_history",
        create: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pod_contention_history_ns_ts \
                 ON pod_contention_history (victim_namespace, ts DESC)",
        history_only: true,
    },
];

/// Session advisory lock key held for the whole check-and-build of `index`,
/// so two replicas never race one build, a replica never drops the INVALID
/// index another is still building, and [`with_table_maintenance`] never
/// VACUUMs the table under a build. A build orphaned by a killed pod keeps
/// its backend, and so this lock, until it finishes. The minute index's key
/// is the one earlier Brokers used, so a rolling upgrade stays exclusive.
pub(crate) fn lock_key(index: &str) -> String {
    format!("kguardian:{index}")
}

/// First check after startup: after the pool has warmed and well before
/// the first downsample pass could need the minute index, but never on the
/// startup path.
const WARMUP: Duration = Duration::from_secs(30);
/// Re-check cadence once every index is valid. A catalog lookup per index,
/// so cheap; it catches an index dropped by hand or left INVALID by a build
/// that failed elsewhere.
const RECHECK: Duration = Duration::from_secs(3600);
/// First retry after a failed build, or while another session holds a
/// build or maintenance lock; doubled per failure up to [`RECHECK`].
const RETRY: Duration = Duration::from_secs(300);
/// How often a follower re-checks whether it has become the leader, so a
/// new leader ensures the indexes within a minute rather than an hour.
const FOLLOWER_POLL: Duration = Duration::from_secs(60);

/// What [`ensure_index`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexState {
    /// Present and valid; nothing to do.
    Valid,
    /// Was missing; built.
    Built,
    /// Was INVALID (a CONCURRENTLY build that failed or was interrupted);
    /// dropped and rebuilt.
    Rebuilt,
    /// Another session holds the index's lock (a build, or a VACUUM of the
    /// table through [`with_table_maintenance`]); try again later.
    Busy,
}

#[derive(diesel::QueryableByName)]
struct IndexValid {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Bool>)]
    valid: Option<bool>,
}

#[derive(diesel::QueryableByName)]
struct Locked {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    locked: bool,
}

fn try_lock(conn: &mut PgConnection, key: &str) -> QueryResult<bool> {
    Ok(
        sql_query("SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS locked")
            .bind::<Text, _>(key)
            .get_result::<Locked>(conn)?
            .locked,
    )
}

/// Released explicitly so a pooled or reused session never keeps it; a
/// dropped connection releases it anyway.
fn unlock(conn: &mut PgConnection, key: &str) {
    let _ = sql_query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind::<Text, _>(key)
        .execute(conn);
}

/// Whether `index` exists and, if so, whether it is valid.
pub(crate) fn index_valid(conn: &mut PgConnection, index: &str) -> QueryResult<Option<bool>> {
    Ok(sql_query(
        "SELECT (SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)) AS valid",
    )
    .bind::<Text, _>(index)
    .get_result::<IndexValid>(conn)?
    .valid)
}

/// Make sure `index` exists and is valid, building it with `CREATE INDEX
/// CONCURRENTLY` if not (module docs say why this is not a migration).
///
/// `conn` must be a dedicated connection, never a pool one: a build can
/// take hours on a large table, so the session's statement timeout is
/// switched off. It must also be a real session (direct, or a session-mode
/// pooler, never PgBouncer transaction mode): the advisory lock is
/// session-scoped, and a transaction-mode pooler could hand the lock and the
/// build to different server connections.
pub(crate) fn ensure_index(
    conn: &mut PgConnection,
    index: &BackgroundIndex,
) -> QueryResult<IndexState> {
    conn.batch_execute("SET statement_timeout = 0")?;
    let key = lock_key(index.name);
    if !try_lock(conn, &key)? {
        return Ok(IndexState::Busy);
    }
    let outcome = (|| -> QueryResult<IndexState> {
        let started = std::time::Instant::now();
        let outcome = match index_valid(conn, index.name)? {
            Some(true) => return Ok(IndexState::Valid),
            Some(false) => {
                warn!(
                    index = index.name,
                    "index is INVALID (an earlier build failed); rebuilding"
                );
                conn.batch_execute(&format!("DROP INDEX CONCURRENTLY IF EXISTS {}", index.name))?;
                IndexState::Rebuilt
            }
            None => IndexState::Built,
        };
        info!(
            index = index.name,
            table = index.table,
            "building index CONCURRENTLY (writes continue meanwhile)"
        );
        conn.batch_execute(index.create)?;
        info!(
            index = index.name,
            elapsed_secs = started.elapsed().as_secs(),
            "index built"
        );
        Ok(outcome)
    })();
    unlock(conn, &key);
    outcome
}

/// Run `f` (a VACUUM, typically) on `table` only while no background index
/// build on it is in progress, holding every such index's build lock
/// meanwhile so none starts. Returns `Ok(None)`, having run nothing, when a
/// build (or another maintenance run) holds one of them: the caller skips
/// the table this round rather than queue behind an hours-long build. A
/// table with no background index runs `f` directly.
///
/// `conn` must be a real session (see [`ensure_index`]); the locks are
/// released before this returns, whatever `f` did.
pub(crate) fn with_table_maintenance<T>(
    conn: &mut PgConnection,
    table: &str,
    f: impl FnOnce(&mut PgConnection) -> QueryResult<T>,
) -> QueryResult<Option<T>> {
    let mut held: Vec<String> = Vec::new();
    let release = |conn: &mut PgConnection, held: &[String]| {
        for key in held.iter().rev() {
            unlock(conn, key);
        }
    };
    for index in INDEXES.iter().filter(|i| i.table == table) {
        let key = lock_key(index.name);
        match try_lock(conn, &key) {
            Ok(true) => held.push(key),
            Ok(false) => {
                release(conn, &held);
                return Ok(None);
            }
            Err(e) => {
                release(conn, &held);
                return Err(e);
            }
        }
    }
    let result = f(conn);
    release(conn, &held);
    result.map(Some)
}

/// Tables this task also ANALYZEs when their statistics are missing or
/// stale. The findings and contention reads are planned from them, and
/// autovacuum, which normally keeps them, cannot be relied on: on the dev
/// cluster it stopped, `pod_contention_history` was never analyzed, the
/// planner's defaults put 772 rows at 917 k, and every
/// `GET /compute/findings` scanned 7.5 GB (8.5-10.4 s; 0.8-1 s once
/// analyzed by hand).
const ANALYZED: [&str; 2] = ["pod_compute_history", "pod_contention_history"];

/// Statistics older than this are refreshed. Autoanalyze visits these
/// tables several times a day at their insert rates, so a working
/// autovacuum keeps this a no-op.
const ANALYZE_STALE_HOURS: i32 = 24;

/// How long the stale-statistics ANALYZE waits for its table lock before
/// skipping the table until the next pass.
const ANALYZE_LOCK_TIMEOUT: &str = "5s";

#[derive(diesel::QueryableByName)]
struct Stale {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Bool>)]
    stale: Option<bool>,
}

/// ANALYZE `table` if it was never analyzed, or not for
/// [`ANALYZE_STALE_HOURS`]. `Some(true)`: analyzed; `Some(false)`: its
/// statistics are fresh; `None`: skipped, because an index build on the
/// table holds its lock (ANALYZE takes the same SHARE UPDATE EXCLUSIVE lock
/// as the build and VACUUM, so it goes through [`with_table_maintenance`]),
/// or because that lock was not granted within [`ANALYZE_LOCK_TIMEOUT`]
/// (an anti-wraparound autovacuum, or a manual VACUUM, holds it). ANALYZE
/// reads a fixed sample, not the table, and blocks no writes.
pub(crate) fn analyze_if_stale(conn: &mut PgConnection, table: &str) -> QueryResult<Option<bool>> {
    let stale = sql_query(
        "SELECT (SELECT COALESCE(GREATEST(last_analyze, last_autoanalyze) \
                    < now() - make_interval(hours => $2), true) \
                 FROM pg_stat_user_tables WHERE relid = to_regclass($1)) AS stale",
    )
    .bind::<Text, _>(table)
    .bind::<diesel::sql_types::Integer, _>(ANALYZE_STALE_HOURS)
    .get_result::<Stale>(conn)?
    .stale;
    if stale != Some(true) {
        return Ok(Some(false));
    }
    conn.batch_execute("SET statement_timeout = 0")?;
    // Bounded wait for the table lock: the pass is sequential and holds the
    // build locks while it waits, so an unbounded wait behind an
    // anti-wraparound autovacuum (which never yields) would stall every
    // build after it.
    let analyzed = with_table_maintenance(conn, table, |c| {
        c.batch_execute(&format!("SET lock_timeout = '{ANALYZE_LOCK_TIMEOUT}'"))?;
        let r = c.batch_execute(&format!("ANALYZE {table}"));
        c.batch_execute("RESET lock_timeout")?;
        match r {
            Ok(()) => Ok(true),
            Err(diesel::result::Error::DatabaseError(_, info))
                if info.message().contains("lock timeout") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    })?;
    match analyzed {
        Some(true) => {
            info!(table, "statistics missing or stale; analyzed");
            Ok(Some(true))
        }
        Some(false) => {
            info!(
                table,
                "statistics missing or stale; table lock busy, analyzing later"
            );
            Ok(None)
        }
        None => Ok(None),
    }
}

/// The indexes this Broker maintains, given whether compute history is on.
pub(crate) fn applicable(history_on: bool) -> impl Iterator<Item = &'static BackgroundIndex> {
    INDEXES
        .iter()
        .filter(move |i| history_on || !i.history_only)
}

/// One pass over every applicable index on one dedicated connection. The
/// result is the wait before the next pass: [`RECHECK`] when all are valid,
/// otherwise a retry. One index failing does not stop the others.
fn ensure_all(url: &str, history_on: bool) -> Result<bool, String> {
    let mut conn = PgConnection::establish(url).map_err(|e| format!("connect: {e}"))?;
    let mut settled = true;
    // First, and cheap: a build can take hours, and these reads should not
    // wait for it.
    for table in ANALYZED.iter().filter(|_| history_on) {
        match analyze_if_stale(&mut conn, table) {
            Ok(Some(_)) => {}
            Ok(None) => settled = false,
            Err(e) => {
                warn!(table, error = %e, "ANALYZE failed; retrying later");
                settled = false;
            }
        }
    }
    for index in applicable(history_on) {
        if !crate::leader::is_leader() {
            return Ok(false);
        }
        match ensure_index(&mut conn, index) {
            Ok(IndexState::Valid) => debug!(index = index.name, "index valid"),
            Ok(IndexState::Built | IndexState::Rebuilt) => {}
            Ok(IndexState::Busy) => {
                info!(
                    index = index.name,
                    "index lock held by another session (a build or a VACUUM); re-checking later"
                );
                settled = false;
            }
            Err(e) => {
                warn!(index = index.name, error = %e, "index build failed; retrying later");
                settled = false;
                // A failed CONCURRENTLY build may have left the session
                // mid-error; start the rest on a fresh one.
                conn = PgConnection::establish(url).map_err(|e| format!("connect: {e}"))?;
            }
        }
    }
    Ok(settled)
}

/// Background task that keeps every index in [`INDEXES`] present and valid
/// (see [`ensure_index`]). Leader only, off the startup path, and on its
/// own connection, so neither readiness nor the request pool ever waits on
/// a build.
pub(crate) fn spawn(history_on: bool) {
    let Some(url) = std::env::var("DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        warn!("DATABASE_URL unset; not maintaining the background indexes");
        return;
    };
    actix_web::rt::spawn(async move {
        tokio::time::sleep(WARMUP).await;
        let mut retry = RETRY;
        loop {
            if !crate::leader::is_leader() {
                tokio::time::sleep(FOLLOWER_POLL).await;
                continue;
            }
            let url = url.clone();
            let result = tokio::task::spawn_blocking(move || ensure_all(&url, history_on)).await;
            let next = match result {
                Ok(Ok(true)) => {
                    retry = RETRY;
                    RECHECK
                }
                Ok(Ok(false)) => {
                    let wait = retry;
                    retry = (retry * 2).min(RECHECK);
                    wait
                }
                Ok(Err(e)) => {
                    warn!(error = %e, retry_secs = retry.as_secs(), "background index pass failed");
                    let wait = retry;
                    retry = (retry * 2).min(RECHECK);
                    wait
                }
                Err(e) => {
                    warn!(error = %e, "background index task panicked");
                    let wait = retry;
                    retry = (retry * 2).min(RECHECK);
                    wait
                }
            };
            tokio::time::sleep(next).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::migration::MigrationSource;
    use diesel_migrations::MigrationHarness;

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    /// The indexes an older migration creates inline while its table is
    /// small, and this task otherwise.
    const FROM_MIGRATIONS: [&str; 7] = [
        "idx_pod_traffic_pod_name",
        "idx_pod_traffic_pod_ip",
        "idx_pod_traffic_dedup",
        "idx_pod_syscalls_pod_name",
        "idx_pod_traffic_time_stamp",
        "idx_pod_traffic_supersede",
        "idx_image_sbom_components_name",
    ];

    #[test]
    fn every_index_is_built_concurrently_under_its_own_name() {
        let mut names = std::collections::HashSet::new();
        for i in INDEXES {
            assert!(names.insert(i.name), "{} listed twice", i.name);
            let prefix = format!(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} ",
                i.name, i.table
            );
            assert!(i.create.starts_with(&prefix), "{}: {}", i.name, i.create);
        }
        assert_eq!(
            INDEXES[0].name, MINUTE_INDEX,
            "the downsample's index first"
        );
        for name in FROM_MIGRATIONS {
            let i = INDEXES.iter().find(|i| i.name == name).expect(name);
            assert!(
                !i.history_only,
                "{name} is maintained whatever the history setting"
            );
        }
        assert_eq!(applicable(true).count(), INDEXES.len());
        assert!(applicable(false).all(|i| !i.history_only));
    }

    fn admin_url() -> String {
        std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL")
    }

    /// A scratch database next to the test one, so migrations can be
    /// applied from an old schema without disturbing the shared database
    /// the other live tests use. Dropped on the way out, pass or fail.
    struct ScratchDb {
        name: String,
        url: String,
    }

    impl ScratchDb {
        fn new(tag: &str) -> Self {
            let name = format!("kg_scratch_{tag}_{}", std::process::id());
            let mut admin = PgConnection::establish(&admin_url()).expect("connect");
            admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS {name}"))
                .expect("drop a leftover scratch database");
            admin
                .batch_execute(&format!("CREATE DATABASE {name}"))
                .expect("create a scratch database (the test role needs CREATEDB)");
            let base = admin_url();
            let (prefix, rest) = base.rsplit_once('/').expect("a URL with a database name");
            let query = rest
                .split_once('?')
                .map(|(_, q)| format!("?{q}"))
                .unwrap_or_default();
            let url = format!("{prefix}/{name}{query}");
            ScratchDb { name, url }
        }

        fn conn(&self) -> PgConnection {
            PgConnection::establish(&self.url).expect("connect to the scratch database")
        }
    }

    impl Drop for ScratchDb {
        fn drop(&mut self) {
            if let Ok(mut admin) = PgConnection::establish(&admin_url()) {
                let _ = admin.batch_execute(&format!(
                    "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                    self.name
                ));
            }
        }
    }

    fn state_of(conn: &mut PgConnection) -> Vec<(&'static str, Option<bool>)> {
        INDEXES
            .iter()
            .map(|i| {
                (
                    i.name,
                    index_valid(conn, i.name).expect("read the index state"),
                )
            })
            .collect()
    }

    /// An install upgrading from before 2026-06-01 with large tables: the
    /// migrations skip the plain builds (forced here with the session
    /// setting they read, rather than by loading 256 MiB of rows), apply
    /// everything else, and the background pass then builds every index
    /// CONCURRENTLY. A fresh install gets the migrations' indexes from the
    /// migrations themselves.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_large_table_indexes_skip_the_migration_and_build_concurrently() {
        let old = ScratchDb::new("upgrade");
        let mut conn = old.conn();
        let all = MigrationSource::<diesel::pg::Pg>::migrations(&TEST_MIGRATIONS)
            .expect("list the shipped migrations");
        diesel::migration::MigrationConnection::setup(&mut conn)
            .expect("create the migrations table");
        for m in all
            .iter()
            .take_while(|m| m.name().to_string().as_str() < "2026-06-01")
        {
            conn.run_migration(m.as_ref())
                .unwrap_or_else(|e| panic!("apply {}: {e}", m.name()));
        }
        conn.batch_execute(
            "INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, pod_ip, pod_port, \
                ip_protocol, traffic_type, traffic_in_out_ip, traffic_in_out_port, time_stamp) \
             VALUES ('u1', 'api-1', 'shop', '10.0.0.1', '8080', 'TCP', 'INGRESS', '10.0.0.2', '0', \
                timezone('UTC', NOW()))",
        )
        .expect("a pre-upgrade traffic row");
        conn.batch_execute("SET kguardian.inline_index_max_bytes = '-1'")
            .expect("treat every table as large");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("the rest of the migrations apply");
        assert!(conn.pending_migrations(TEST_MIGRATIONS).unwrap().is_empty());
        assert!(
            state_of(&mut conn).iter().all(|(_, v)| v.is_none()),
            "no large-table index built by a migration: {:?}",
            state_of(&mut conn)
        );

        for index in applicable(true) {
            assert_eq!(
                ensure_index(&mut conn, index).unwrap(),
                IndexState::Built,
                "{}",
                index.name
            );
        }
        assert!(
            state_of(&mut conn).iter().all(|(_, v)| *v == Some(true)),
            "{:?}",
            state_of(&mut conn)
        );
        for index in applicable(true) {
            assert_eq!(ensure_index(&mut conn, index).unwrap(), IndexState::Valid);
        }
        drop(conn);
        drop(old);

        let fresh = ScratchDb::new("fresh");
        let mut conn = fresh.conn();
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("a fresh install migrates");
        for (name, valid) in state_of(&mut conn) {
            let expected = FROM_MIGRATIONS.contains(&name).then_some(true);
            assert_eq!(valid, expected, "{name} after a fresh install's migrations");
        }
    }

    /// A VACUUM through `with_table_maintenance` never starts while a build
    /// on the table holds its lock, and a build never starts while such a
    /// VACUUM runs. Tables with no background index are not held up.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_vacuum_and_index_builds_exclude_each_other() {
        let mut conn = PgConnection::establish(&admin_url()).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("migrate");
        let mut builder = PgConnection::establish(&admin_url()).expect("connect");
        let vacuum = |c: &mut PgConnection| c.batch_execute("VACUUM pod_compute_history");

        // A build of either history index holds its lock: no VACUUM.
        for index in INDEXES.iter().filter(|i| i.table == "pod_compute_history") {
            sql_query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(lock_key(index.name))
                .execute(&mut builder)
                .expect("hold the build lock");
            let ran = with_table_maintenance(&mut conn, "pod_compute_history", vacuum)
                .expect("maintenance");
            assert!(ran.is_none(), "VACUUM ran under a build of {}", index.name);
            unlock(&mut builder, &lock_key(index.name));
        }

        // Nothing building: the VACUUM runs, and a build attempted during
        // it stands aside.
        let mut during = None;
        let ran = with_table_maintenance(&mut conn, "pod_compute_history", |c| {
            during = Some(ensure_index(&mut builder, &INDEXES[0]).expect("ensure"));
            vacuum(c)
        })
        .expect("maintenance");
        assert!(ran.is_some(), "VACUUM ran");
        assert_eq!(during, Some(IndexState::Busy));
        assert_ne!(
            ensure_index(&mut builder, &INDEXES[0]).unwrap(),
            IndexState::Busy,
            "released afterwards"
        );

        // The stale-statistics ANALYZE stands aside for a build too, runs
        // on missing statistics, and then finds them fresh.
        sql_query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(lock_key(MINUTE_INDEX))
            .execute(&mut builder)
            .expect("hold the build lock");
        sql_query("SELECT pg_stat_reset_single_table_counters('pod_compute_history'::regclass)")
            .execute(&mut conn)
            .expect("forget the table's last analyze");
        assert_eq!(
            analyze_if_stale(&mut conn, "pod_compute_history").unwrap(),
            None
        );
        unlock(&mut builder, &lock_key(MINUTE_INDEX));
        assert_eq!(
            analyze_if_stale(&mut conn, "pod_compute_history").unwrap(),
            Some(true)
        );
        // The statistics view is updated when this backend's counters are
        // flushed; force it rather than wait.
        sql_query("SELECT pg_stat_force_next_flush()")
            .execute(&mut conn)
            .expect("flush");
        let mut fresh = None;
        for _ in 0..50 {
            fresh = analyze_if_stale(&mut conn, "pod_compute_history").unwrap();
            if fresh == Some(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(fresh, Some(false), "analyzed once, then fresh");

        // A session holding the table lock (as an anti-wraparound
        // autovacuum would) makes the ANALYZE give up after its lock
        // timeout, skip the table, and release the build locks.
        sql_query("SELECT pg_stat_reset_single_table_counters('pod_compute_history'::regclass)")
            .execute(&mut conn)
            .expect("forget the table's last analyze again");
        builder
            .batch_execute("BEGIN; LOCK TABLE pod_compute_history IN SHARE UPDATE EXCLUSIVE MODE")
            .expect("hold the table lock");
        let started = std::time::Instant::now();
        assert_eq!(
            analyze_if_stale(&mut conn, "pod_compute_history").unwrap(),
            None
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(15));
        builder.batch_execute("ROLLBACK").expect("release");
        assert_ne!(
            ensure_index(&mut builder, &INDEXES[0]).unwrap(),
            IndexState::Busy,
            "the build locks were released"
        );

        let other = with_table_maintenance(&mut conn, "pod_details", |c| {
            c.batch_execute("VACUUM pod_details")
        })
        .expect("maintenance");
        assert!(
            other.is_some(),
            "a table with no background index is not held up"
        );
    }
}
