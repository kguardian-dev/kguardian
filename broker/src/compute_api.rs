//! HTTP surface of the compute-contention feature: the two controller
//! ingest endpoints and the five read endpoints
//! (docs/design/compute-contention-monitoring.md, D5 / D7 / "Read
//! endpoints"; wire names per the compute contract).
//!
//! Ingest:
//! - `POST /pod/compute/batch` — every sample interval, one per node.
//!   Upserts `pod_compute_latest` (PK `container_uid`) and
//!   `node_compute_latest` (PK `node`), so neither table grows with
//!   cadence; `retention.rs` prunes the rows a node stops refreshing, so
//!   neither grows with churn either.
//! - `POST /pod/compute/history/batch` — every 60 s. Inserts one
//!   `pod_compute_history` row per container and one
//!   `pod_contention_history` row per blame pair. Silently accepted and
//!   dropped when `COMPUTE_HISTORY_RETENTION_DAYS=0` (history off).
//!
//! Reads: every GET validates its query first (a 400 must not wait on the
//! budget), then acquires a `ReadPermit` charged at
//! `COMPUTE_ROW_COST_BYTES` x the endpoint's row cap, held across the
//! query and the serialise. The caps are what bound the response, so the
//! charge is exact rather than guessed from the table size.

use actix_web::{get, post, web, Error, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::upsert::excluded;
use serde::Serialize;
use tracing::{debug, info};

use crate::compute::{compute_findings, ComputeThresholds, WINDOW_MINUTES};
use crate::compute_types::{
    Accepted, ComputeBatch, ComputeHistoryBatch, Finding, NewPodComputeHistory, NewPodContention,
    NodeComputeLatest, PodComputeHistoryRow, PodComputeLatest, PodContentionRow,
};
use crate::read_budget::{cost_kib, ReadBudget, COMPUTE_ROW_COST_BYTES};
use crate::retention::compute_history_retention_days;
use crate::schema;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// JSON body limit for the two ingest endpoints. actix's default is
/// 2 MiB; a node with ~600 sampled containers and the scheduler probe on
/// (24-bucket histogram + blame list per container) exceeds that, and a
/// 413 makes the controller retry the same batch forever. 16 MiB covers
/// several thousand containers per node.
pub const COMPUTE_JSON_LIMIT_BYTES: usize = 16 << 20;

/// The ingest routes under `/pod/compute`, carrying their own
/// `JsonConfig` so the raised body limit applies to these two POSTs
/// only. Register with `.service(compute_ingest_scope())`.
pub fn compute_ingest_scope() -> actix_web::Scope {
    web::scope("/pod/compute")
        .app_data(web::JsonConfig::default().limit(COMPUTE_JSON_LIMIT_BYTES))
        .service(add_compute_batch)
        .service(add_compute_history_batch)
}

/// Rows per INSERT statement. Postgres caps bind parameters at 65 535
/// and a history row binds 46 of them, so 500 rows is ~23 000 binds —
/// comfortably inside, and a batch from a 110-pod node never chunks.
const INSERT_CHUNK: usize = 500;

/// `GET /compute/latest` row cap and charge: one row per live container
/// in the namespace. 5 000 matches `ASSUMED_MAX_PODS` — a namespace
/// larger than that is truncated, and charged for what it can return.
pub const LATEST_ROW_CAP: i64 = 5_000;
/// `GET /compute/history/{pod_uid}` hard row cap (see
/// [`history_row_limit`]).
pub const HISTORY_ROW_CAP: i64 = 20_000;
/// Longest history window, minutes (7 days — the retention default).
pub const HISTORY_MAX_MINUTES: i64 = 10_080;
/// Pairs kept per victim by `GET /compute/contention` (contract).
pub const CONTENTION_PER_VICTIM: i64 = 50;
/// `GET /compute/contention` overall row cap and charge.
pub const CONTENTION_ROW_CAP: i64 = 10_000;
/// Victim containers evaluated per `GET /compute/findings` call (design:
/// "capped at 500 victims per call"). Past this the response says
/// `truncated: true` and clients narrow the scope.
pub const FINDINGS_MAX_VICTIMS: i64 = 500;
/// Minute rows loaded PER CONTAINER for the findings window: the window
/// plus one for a row straddling the cutoff. Bounding per container (a
/// `ROW_NUMBER() OVER (PARTITION BY container_uid ...)`) rather than
/// globally is what keeps the sustain rule evaluable at scale — a global
/// `LIMIT` shared by 1 000 containers would leave each with a handful
/// of rows and no two consecutive minutes.
pub const FINDINGS_ROWS_PER_CONTAINER: i64 = WINDOW_MINUTES + 1;
/// Containers whose history is loaded for one findings call: the
/// victims plus every other container on their nodes (culprits are
/// cross-namespace; the memory heuristic needs the whole node). 500
/// victims spread over ~25 nodes x 110 pods.
pub const FINDINGS_MAX_CONTAINERS: i64 = 3_000;
/// History row cap and charge for one findings call.
pub const FINDINGS_HISTORY_ROW_CAP: i64 = FINDINGS_MAX_CONTAINERS * FINDINGS_ROWS_PER_CONTAINER;
/// Pair rows loaded PER VICTIM for the window, by wait: the top-10 lists
/// of five minutes are at most 50 rows and the engine only needs the
/// heavy end to find a >= 40% culprit.
pub const FINDINGS_PAIRS_PER_VICTIM: i64 = 30;
/// Pair row cap and charge for one findings call.
pub const FINDINGS_PAIR_ROW_CAP: i64 = FINDINGS_MAX_VICTIMS * FINDINGS_PAIRS_PER_VICTIM;
/// `GET /compute/nodes` charge. The table is node-count sized only
/// because retention prunes rows their node stopped refreshing an hour
/// ago (`retention::NODE_COMPUTE_LATEST_STALE_SECS`); before that prune it
/// grew with node churn — 1 232 rows on a 44-node autoscaled cluster, a
/// 548 KB response already past this 512 KiB charge and growing daily.
/// The endpoint has no row cap of its own, so this constant is only exact
/// while that prune runs.
pub const NODES_ROWS_CHARGED: i64 = 512;

// ---------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------

/// Header validation shared by both ingest envelopes. Pure for tests.
pub(crate) fn validate_envelope(node: &str, interval_ms: i64) -> Result<(), &'static str> {
    if node.trim().is_empty() {
        return Err("node must not be empty");
    }
    if node.len() > 253 {
        return Err("node too long");
    }
    if interval_ms <= 0 {
        return Err("interval_ms must be positive");
    }
    Ok(())
}

/// `POST /pod/compute/batch` (path relative to [`compute_ingest_scope`]).
#[post(
    "/batch",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn add_compute_batch(
    pool: web::Data<DbPool>,
    form: web::Json<ComputeBatch>,
) -> Result<HttpResponse, Error> {
    let batch = form.into_inner();
    if let Err(msg) = validate_envelope(&batch.node, batch.interval_ms) {
        return Ok(HttpResponse::BadRequest().body(msg));
    }
    let now = chrono::Utc::now().naive_utc();
    let node_row = NodeComputeLatest::from_batch(&batch, now);
    // Dedup on the PK: two samples for one container in a batch would
    // make ON CONFLICT DO UPDATE touch the same row twice, which
    // Postgres rejects. Last one wins.
    let mut rows: Vec<PodComputeLatest> = Vec::with_capacity(batch.containers.len());
    for c in &batch.containers {
        if c.container_uid.trim().is_empty() || c.container_uid.len() > 512 {
            continue;
        }
        let row = PodComputeLatest::from_sample(&batch, c, now);
        match rows
            .iter_mut()
            .find(|r| r.container_uid == row.container_uid)
        {
            Some(existing) => *existing = row,
            None => rows.push(row),
        }
    }
    let accepted = rows.len();
    debug!(
        node = %batch.node,
        containers = accepted,
        "compute batch received"
    );

    web::block(move || -> Result<(), DbError> {
        let mut conn = pool.get()?;
        conn.transaction::<_, DbError, _>(|conn| {
            upsert_node(conn, &node_row)?;
            for chunk in rows.chunks(INSERT_CHUNK) {
                upsert_latest(conn, chunk)?;
            }
            Ok(())
        })
    })
    .await?
    .map_err(crate::db_error_response)?;

    Ok(HttpResponse::Ok().json(Accepted { accepted }))
}

fn upsert_node(conn: &mut PgConnection, row: &NodeComputeLatest) -> Result<(), DbError> {
    use schema::node_compute_latest::dsl::*;
    diesel::insert_into(node_compute_latest)
        .values(row)
        .on_conflict(node)
        .do_update()
        .set(row)
        .execute(conn)?;
    Ok(())
}

/// One statement per chunk: `INSERT ... ON CONFLICT (container_uid) DO
/// UPDATE SET <every column> = EXCLUDED.<column>`. This is the 5 s hot
/// path for every node, so it is one round-trip per node per interval
/// rather than one per container.
///
/// Every one of these updates must stay HOT, which means no column that
/// changes between samples may be indexed: an index on `updated_at` once
/// grew the table to 86 GB for 15 k live rows (see migration
/// `2026-10-01-100000_pod_compute_latest_hot_updates`, and
/// `live_database_latest_upserts_are_hot_updates` below).
fn upsert_latest(conn: &mut PgConnection, rows: &[PodComputeLatest]) -> Result<(), DbError> {
    use schema::pod_compute_latest::dsl::*;
    if rows.is_empty() {
        return Ok(());
    }
    diesel::insert_into(pod_compute_latest)
        .values(rows)
        .on_conflict(container_uid)
        .do_update()
        .set((
            pod_uid.eq(excluded(pod_uid)),
            namespace.eq(excluded(namespace)),
            pod_name.eq(excluded(pod_name)),
            container.eq(excluded(container)),
            node.eq(excluded(node)),
            cgroup_id.eq(excluded(cgroup_id)),
            ts.eq(excluded(ts)),
            interval_ms.eq(excluded(interval_ms)),
            cpu_usage_millis.eq(excluded(cpu_usage_millis)),
            cpu_quota_usec.eq(excluded(cpu_quota_usec)),
            cpu_period_usec.eq(excluded(cpu_period_usec)),
            cpu_request_millis.eq(excluded(cpu_request_millis)),
            cpu_limit_millis.eq(excluded(cpu_limit_millis)),
            cpu_nr_periods.eq(excluded(cpu_nr_periods)),
            cpu_nr_throttled.eq(excluded(cpu_nr_throttled)),
            cpu_throttled_usec.eq(excluded(cpu_throttled_usec)),
            cpu_psi_some10.eq(excluded(cpu_psi_some10)),
            cpu_psi_full10.eq(excluded(cpu_psi_full10)),
            mem_current.eq(excluded(mem_current)),
            mem_working_set.eq(excluded(mem_working_set)),
            mem_limit.eq(excluded(mem_limit)),
            mem_request.eq(excluded(mem_request)),
            mem_psi_some10.eq(excluded(mem_psi_some10)),
            mem_psi_full10.eq(excluded(mem_psi_full10)),
            mem_events_high.eq(excluded(mem_events_high)),
            mem_events_max.eq(excluded(mem_events_max)),
            mem_oom_kill.eq(excluded(mem_oom_kill)),
            mem_refault.eq(excluded(mem_refault)),
            mem_pgmajfault.eq(excluded(mem_pgmajfault)),
            runq_count.eq(excluded(runq_count)),
            runq_p50_us.eq(excluded(runq_p50_us)),
            runq_p95_us.eq(excluded(runq_p95_us)),
            runq_p99_us.eq(excluded(runq_p99_us)),
            runq_max_us.eq(excluded(runq_max_us)),
            runq_overflow.eq(excluded(runq_overflow)),
            blame.eq(excluded(blame)),
            updated_at.eq(excluded(updated_at)),
            blame_omitted.eq(excluded(blame_omitted)),
            blame_omitted_wait_ns.eq(excluded(blame_omitted_wait_ns)),
        ))
        .execute(conn)?;
    Ok(())
}

/// `POST /pod/compute/history/batch` (path relative to [`compute_ingest_scope`]).
#[post(
    "/history/batch",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn add_compute_history_batch(
    pool: web::Data<DbPool>,
    form: web::Json<ComputeHistoryBatch>,
) -> Result<HttpResponse, Error> {
    let batch = form.into_inner();
    if let Err(msg) = validate_envelope(&batch.node, batch.interval_ms) {
        return Ok(HttpResponse::BadRequest().body(msg));
    }
    if batch.resolution_secs <= 0 {
        return Ok(HttpResponse::BadRequest().body("resolution_secs must be positive"));
    }
    // History off: accept and drop. The controller keeps sending (it
    // does not know the broker's retention setting) and must not see
    // errors for a deliberate operator choice.
    if compute_history_retention_days() == 0 {
        debug!(node = %batch.node, "compute history disabled; batch dropped");
        return Ok(HttpResponse::Ok().json(Accepted { accepted: 0 }));
    }
    let mut rows: Vec<NewPodComputeHistory> = Vec::with_capacity(batch.containers.len());
    let mut pairs: Vec<NewPodContention> = Vec::new();
    for c in &batch.containers {
        if c.container_uid.trim().is_empty() || c.container_uid.len() > 512 {
            continue;
        }
        rows.push(NewPodComputeHistory::from_history(&batch, c));
        for b in &c.blame {
            if b.kind.is_empty() || b.wait_ns <= 0 {
                continue;
            }
            pairs.push(NewPodContention::from_blame(&batch, c, b));
        }
    }
    let accepted = rows.len();
    let pair_count = pairs.len();

    web::block(move || -> Result<(), DbError> {
        let mut conn = pool.get()?;
        conn.transaction::<_, DbError, _>(|conn| {
            for chunk in rows.chunks(INSERT_CHUNK) {
                diesel::insert_into(schema::pod_compute_history::table)
                    .values(chunk)
                    .execute(conn)?;
            }
            for chunk in pairs.chunks(INSERT_CHUNK) {
                diesel::insert_into(schema::pod_contention_history::table)
                    .values(chunk)
                    .execute(conn)?;
            }
            Ok(())
        })
    })
    .await?
    .map_err(crate::db_error_response)?;

    info!(
        node = %batch.node,
        rows = accepted,
        pairs = pair_count,
        "compute history batch inserted"
    );
    Ok(HttpResponse::Ok().json(Accepted { accepted }))
}

// ---------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------

/// Empty string → absent, so `?namespace=` from a blank form field is
/// "no filter", the same convention `get.rs` applies.
fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Clamp a `minutes` query param into `[1, HISTORY_MAX_MINUTES]`.
pub(crate) fn clamp_minutes(raw: Option<i64>, default: i64) -> i64 {
    raw.unwrap_or(default).clamp(1, HISTORY_MAX_MINUTES)
}

/// Containers per pod assumed for the FIRST permit of a history read,
/// before the pod's real container count is known.
pub const HISTORY_CONTAINERS_ASSUMED: i64 = 4;

/// Rows charged and returned for a history window: one row per minute
/// per container (far fewer at 5-minute resolution), capped at
/// [`HISTORY_ROW_CAP`]. The full 7-day window is 1 440 minute + 1 728
/// five-minute rows per container, so the cap covers six containers
/// over the whole retention.
///
/// The handler charges this for [`HISTORY_CONTAINERS_ASSUMED`] first,
/// counts the pod's containers, and charges the difference as a second
/// permit before reading — so a pod with more containers than assumed
/// is billed exactly and not truncated at the old end of its window.
pub(crate) fn history_row_limit(minutes: i64, containers: i64) -> i64 {
    minutes
        .saturating_mul(containers.max(1))
        .clamp(1, HISTORY_ROW_CAP)
}

#[derive(serde::Deserialize)]
pub struct NamespaceQuery {
    pub namespace: Option<String>,
}

#[derive(Serialize)]
pub struct LatestResponse {
    pub containers: Vec<PodComputeLatest>,
    pub nodes: Vec<NodeComputeLatest>,
}

#[get(
    "/compute/latest",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_compute_latest(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<NamespaceQuery>,
) -> actix_web::Result<impl Responder> {
    let Some(ns) = non_empty(query.into_inner().namespace) else {
        return Ok(HttpResponse::BadRequest().body("namespace query parameter is required"));
    };
    let _permit = match budget
        .acquire(cost_kib(LATEST_ROW_CAP, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let resp = web::block(move || -> Result<LatestResponse, DbError> {
        let mut conn = pool.get()?;
        latest_for_namespace(&mut conn, &ns)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(resp))
}

pub fn latest_for_namespace(conn: &mut PgConnection, ns: &str) -> Result<LatestResponse, DbError> {
    let containers = {
        use schema::pod_compute_latest::dsl::*;
        pod_compute_latest
            .filter(namespace.eq(ns))
            .order((pod_name.asc(), container.asc()))
            .limit(LATEST_ROW_CAP)
            .load::<PodComputeLatest>(conn)?
    };
    let mut node_names: Vec<String> = containers.iter().map(|c| c.node.clone()).collect();
    node_names.sort();
    node_names.dedup();
    let nodes = if node_names.is_empty() {
        Vec::new()
    } else {
        use schema::node_compute_latest::dsl::*;
        node_compute_latest
            .filter(node.eq_any(&node_names))
            .order(node.asc())
            .load::<NodeComputeLatest>(conn)?
    };
    Ok(LatestResponse { containers, nodes })
}

#[derive(serde::Deserialize)]
pub struct MinutesQuery {
    pub minutes: Option<i64>,
}

#[derive(Serialize)]
pub struct HistoryResponse {
    pub rows: Vec<PodComputeHistoryRow>,
}

#[get(
    "/compute/history/{pod_uid}",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_compute_history(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<MinutesQuery>,
) -> actix_web::Result<impl Responder> {
    let uid = path.into_inner();
    if uid.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().body("pod_uid must not be empty"));
    }
    let minutes = clamp_minutes(query.minutes, 60);
    let assumed_limit = history_row_limit(minutes, HISTORY_CONTAINERS_ASSUMED);
    // First permit, before any DB access, for the assumed container
    // count. Held across the count, the read and the serialise.
    let _permit = match budget
        .acquire(cost_kib(assumed_limit, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(minutes);
    let count_pool = pool.clone();
    let count_uid = uid.clone();
    let containers = web::block(move || -> Result<i64, DbError> {
        let mut conn = count_pool.get()?;
        pod_container_count(&mut conn, &count_uid, cutoff)
    })
    .await?
    .map_err(crate::db_error_response)?;
    let row_limit = history_row_limit(minutes, containers);
    // A pod with more containers than assumed is charged the difference
    // as a second permit rather than truncated. Refused (503) like any
    // other read that does not fit, never shortened.
    let _extra_permit = if row_limit > assumed_limit {
        match budget
            .acquire(cost_kib(row_limit - assumed_limit, COMPUTE_ROW_COST_BYTES))
            .await
        {
            Ok(p) => Some(p),
            Err(shed) => return Ok(shed.into_response()),
        }
    } else {
        None
    };
    let rows = web::block(move || -> Result<Vec<PodComputeHistoryRow>, DbError> {
        let mut conn = pool.get()?;
        history_for_pod(&mut conn, &uid, cutoff, row_limit)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(HistoryResponse { rows }))
}

/// Distinct containers of a pod with rows in the window. Served by the
/// `(pod_uid, ts DESC)` index; cheap next to the read it sizes.
pub fn pod_container_count(
    conn: &mut PgConnection,
    uid: &str,
    cutoff: NaiveDateTime,
) -> Result<i64, DbError> {
    use diesel::sql_types::{BigInt, Text, Timestamp};
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        n: i64,
    }
    let c = diesel::sql_query(
        "SELECT COUNT(DISTINCT container_uid) AS n FROM pod_compute_history \
         WHERE pod_uid = $1 AND ts >= $2",
    )
    .bind::<Text, _>(uid)
    .bind::<Timestamp, _>(cutoff)
    .get_result::<Count>(conn)?;
    Ok(c.n)
}

/// Newest rows first at the database (so a truncated read drops the
/// OLD end of the window, not the end the caller is looking at), then
/// reversed to the contract's `ts asc`.
pub fn history_for_pod(
    conn: &mut PgConnection,
    uid: &str,
    cutoff: NaiveDateTime,
    row_limit: i64,
) -> Result<Vec<PodComputeHistoryRow>, DbError> {
    use schema::pod_compute_history::dsl::*;
    let mut rows = pod_compute_history
        .filter(pod_uid.eq(uid))
        .filter(ts.ge(cutoff))
        .order((ts.desc(), id.desc()))
        .limit(row_limit)
        .load::<PodComputeHistoryRow>(conn)?;
    rows.reverse();
    Ok(rows)
}

#[derive(serde::Deserialize)]
pub struct ScopeQuery {
    pub namespace: Option<String>,
    pub node: Option<String>,
    pub minutes: Option<i64>,
}

#[derive(Serialize)]
pub struct ContentionResponse {
    pub pairs: Vec<PodContentionRow>,
}

#[get(
    "/compute/contention",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_compute_contention(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ScopeQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let ns = non_empty(q.namespace);
    let node = non_empty(q.node);
    if ns.is_none() && node.is_none() {
        return Ok(HttpResponse::BadRequest().body("namespace or node query parameter is required"));
    }
    let minutes = clamp_minutes(q.minutes, 5);
    let _permit = match budget
        .acquire(cost_kib(CONTENTION_ROW_CAP, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(minutes);
    let pairs = web::block(move || -> Result<Vec<PodContentionRow>, DbError> {
        let mut conn = pool.get()?;
        contention_pairs(&mut conn, ns, node, cutoff)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(ContentionResponse { pairs }))
}

/// Top [`CONTENTION_PER_VICTIM`] pairs by wait per victim in the window,
/// under an overall [`CONTENTION_ROW_CAP`]. A window function has no
/// diesel DSL form, hence `sql_query`; the row type is the same
/// `PodContentionRow` (`QueryableByName` on the table's columns).
pub fn contention_pairs(
    conn: &mut PgConnection,
    ns: Option<String>,
    node: Option<String>,
    cutoff: NaiveDateTime,
) -> Result<Vec<PodContentionRow>, DbError> {
    use diesel::sql_types::{BigInt, Nullable, Text, Timestamp};
    let rows = diesel::sql_query(
        "SELECT id, ts, node, victim_container_uid, victim_pod_uid, victim_namespace, \
                culprit_cgroup_id, culprit_kind, culprit_ref, culprit_container_uid, count, wait_ns \
         FROM ( \
             SELECT p.*, ROW_NUMBER() OVER ( \
                        PARTITION BY victim_container_uid ORDER BY wait_ns DESC, id DESC) AS rn \
             FROM pod_contention_history p \
             WHERE ts >= $1 \
               AND ($2::text IS NULL OR victim_namespace = $2) \
               AND ($3::text IS NULL OR node = $3) \
         ) ranked \
         WHERE rn <= $4 \
         ORDER BY victim_container_uid, wait_ns DESC, id DESC \
         LIMIT $5",
    )
    .bind::<Timestamp, _>(cutoff)
    .bind::<Nullable<Text>, _>(ns)
    .bind::<Nullable<Text>, _>(node)
    .bind::<BigInt, _>(CONTENTION_PER_VICTIM)
    .bind::<BigInt, _>(CONTENTION_ROW_CAP)
    .load::<PodContentionRow>(conn)?;
    Ok(rows)
}

#[derive(Serialize)]
pub struct FindingsResponse {
    pub findings: Vec<Finding>,
    /// True when the victim cap or a row cap was hit; narrow the scope
    /// (`namespace=` / `node=`) to see the rest.
    pub truncated: bool,
    /// Victim containers the engine actually evaluated.
    pub victims_evaluated: usize,
    /// True when `COMPUTE_HISTORY_RETENTION_DAYS=0`: the engine reads
    /// history only, so the list is necessarily empty.
    pub history_disabled: bool,
}

/// Engine input for one call plus the truncation bookkeeping.
pub struct FindingsScope {
    pub victims: Vec<String>,
    pub truncated: bool,
    pub history: Vec<PodComputeHistoryRow>,
    pub pairs: Vec<PodContentionRow>,
    pub nodes: Vec<NodeComputeLatest>,
}

#[get(
    "/compute/findings",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_compute_findings(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ScopeQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let ns = non_empty(q.namespace);
    let node = non_empty(q.node);
    if compute_history_retention_days() == 0 {
        return Ok(HttpResponse::Ok().json(FindingsResponse {
            findings: Vec::new(),
            truncated: false,
            victims_evaluated: 0,
            history_disabled: true,
        }));
    }
    // First permit, before any DB access: the victim-scope query only
    // (501 rows + one count). The heavy reads are charged separately
    // below, sized to what the scope actually contains, so a cluster-
    // wide poll on a small cluster does not reserve the 33 MiB worst
    // case and shed the reads next to it.
    let _scope_permit = match budget
        .acquire(cost_kib(FINDINGS_MAX_VICTIMS + 1, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let thresholds = ComputeThresholds::from_env();
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(WINDOW_MINUTES);
    let scope_pool = pool.clone();
    let victims = web::block(move || -> Result<FindingsVictims, DbError> {
        let mut conn = scope_pool.get()?;
        load_findings_victims(&mut conn, ns, node, cutoff)
    })
    .await?
    .map_err(crate::db_error_response)?;
    if victims.victims.is_empty() {
        return Ok(HttpResponse::Ok().json(FindingsResponse {
            findings: Vec::new(),
            truncated: victims.truncated,
            victims_evaluated: 0,
            history_disabled: false,
        }));
    }
    // Second permit, sized to the real scope. Refused (503) if it does
    // not fit — never a partial engine input.
    let rows = findings_scope_rows(victims.victims.len() as i64, victims.containers_on_nodes);
    let _rows_permit = match budget.acquire(cost_kib(rows, COMPUTE_ROW_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let scope = web::block(move || -> Result<FindingsScope, DbError> {
        let mut conn = pool.get()?;
        load_findings_rows(&mut conn, victims, cutoff)
    })
    .await?
    .map_err(crate::db_error_response)?;
    let (findings, victims_evaluated) = findings_for_scope(&scope, &thresholds);
    Ok(HttpResponse::Ok().json(FindingsResponse {
        findings,
        truncated: scope.truncated,
        victims_evaluated,
        history_disabled: false,
    }))
}

/// Run the engine over a loaded scope and keep only findings whose
/// victim is one of the scope's victims. Pure; the engine sees every
/// container on the victims' nodes but only the victims are reported.
pub fn findings_for_scope(
    scope: &FindingsScope,
    thresholds: &ComputeThresholds,
) -> (Vec<Finding>, usize) {
    let mut findings = compute_findings(&scope.history, &scope.pairs, &scope.nodes, thresholds);
    findings.retain(|f| scope.victims.binary_search(&f.victim.container_uid).is_ok());
    (findings, scope.victims.len())
}

/// Split the (sorted) victim list at the cap. Returns the kept victims
/// and whether any were dropped. Pure for tests.
pub(crate) fn cap_victims(mut victims: Vec<String>, cap: i64) -> (Vec<String>, bool) {
    victims.sort();
    victims.dedup();
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let truncated = victims.len() > cap;
    victims.truncate(cap);
    (victims, truncated)
}

#[derive(diesel::QueryableByName)]
struct VictimRef {
    #[diesel(sql_type = diesel::sql_types::Text)]
    container_uid: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    node: String,
}

/// Step one of a findings call: who is in scope and how much the heavy
/// read will cost.
pub struct FindingsVictims {
    /// Sorted, deduplicated, capped at [`FINDINGS_MAX_VICTIMS`].
    pub victims: Vec<String>,
    pub truncated: bool,
    /// Nodes hosting the victims.
    pub node_names: Vec<String>,
    /// Distinct containers with minute rows on those nodes in the window
    /// — what the history read will actually return rows for.
    pub containers_on_nodes: i64,
}

/// Rows the heavy read can return for a scope, and so what it is
/// charged: [`FINDINGS_ROWS_PER_CONTAINER`] per container on the
/// victims' nodes (never fewer than the victims themselves) plus
/// [`FINDINGS_PAIRS_PER_VICTIM`] per victim, each under its cap. Pure.
pub(crate) fn findings_scope_rows(victims: i64, containers_on_nodes: i64) -> i64 {
    let containers = containers_on_nodes.max(victims).max(1);
    let history = containers
        .saturating_mul(FINDINGS_ROWS_PER_CONTAINER)
        .min(FINDINGS_HISTORY_ROW_CAP);
    let pairs = victims
        .max(0)
        .saturating_mul(FINDINGS_PAIRS_PER_VICTIM)
        .min(FINDINGS_PAIR_ROW_CAP);
    history + pairs
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

/// Victims: every container with minute rows in the window that matches
/// the scope (`namespace=` / `node=`; none = cluster), ordered by
/// `container_uid`, capped at [`FINDINGS_MAX_VICTIMS`] (one extra row is
/// fetched to detect the cap); plus their nodes and a count of the
/// containers on those nodes, which sizes the second permit.
pub fn load_findings_victims(
    conn: &mut PgConnection,
    ns: Option<String>,
    node: Option<String>,
    cutoff: NaiveDateTime,
) -> Result<FindingsVictims, DbError> {
    use diesel::sql_types::{Array, BigInt, Nullable, Text, Timestamp};

    let victim_refs = diesel::sql_query(
        "SELECT DISTINCT container_uid, node FROM pod_compute_history \
         WHERE resolution_secs = 60 AND ts >= $1 \
           AND ($2::text IS NULL OR namespace = $2) \
           AND ($3::text IS NULL OR node = $3) \
         ORDER BY container_uid \
         LIMIT $4",
    )
    .bind::<Timestamp, _>(cutoff)
    .bind::<Nullable<Text>, _>(ns)
    .bind::<Nullable<Text>, _>(node)
    .bind::<BigInt, _>(FINDINGS_MAX_VICTIMS + 1)
    .load::<VictimRef>(conn)?;
    let (victims, truncated) = cap_victims(
        victim_refs
            .iter()
            .map(|v| v.container_uid.clone())
            .collect(),
        FINDINGS_MAX_VICTIMS,
    );
    let mut node_names: Vec<String> = victim_refs
        .iter()
        .filter(|v| victims.binary_search(&v.container_uid).is_ok())
        .map(|v| v.node.clone())
        .collect();
    node_names.sort();
    node_names.dedup();
    let containers_on_nodes = if node_names.is_empty() {
        0
    } else {
        // Served by the (node, ts DESC) index; cheap next to the read it
        // sizes.
        diesel::sql_query(
            "SELECT COUNT(DISTINCT container_uid) AS n FROM pod_compute_history \
             WHERE resolution_secs = 60 AND ts >= $1 AND node = ANY($2)",
        )
        .bind::<Timestamp, _>(cutoff)
        .bind::<Array<Text>, _>(&node_names)
        .get_result::<CountRow>(conn)?
        .n
    };
    Ok(FindingsVictims {
        victims,
        truncated,
        node_names,
        containers_on_nodes,
    })
}

/// Step two: the engine's input for the scope.
///
/// - History: for every container on the victims' NODES (culprits are
///   cross-namespace; the memory heuristic needs the whole node), the
///   newest [`FINDINGS_ROWS_PER_CONTAINER`] minute rows each, under
///   [`FINDINGS_HISTORY_ROW_CAP`].
/// - Pairs: for each victim, the top [`FINDINGS_PAIRS_PER_VICTIM`] by
///   wait in the window, under [`FINDINGS_PAIR_ROW_CAP`].
/// - The nodes' `node_compute_latest` rows.
///
/// Hitting either cap sets `truncated`.
pub fn load_findings_rows(
    conn: &mut PgConnection,
    scope: FindingsVictims,
    cutoff: NaiveDateTime,
) -> Result<FindingsScope, DbError> {
    use diesel::sql_types::{Array, BigInt, Text, Timestamp};
    let FindingsVictims {
        victims,
        mut truncated,
        node_names,
        ..
    } = scope;
    if victims.is_empty() {
        return Ok(FindingsScope {
            victims,
            truncated,
            history: Vec::new(),
            pairs: Vec::new(),
            nodes: Vec::new(),
        });
    }

    // `SELECT *` on the ranked subquery also yields `rn`; QueryableByName
    // reads columns by name and ignores it.
    let history = diesel::sql_query(
        "SELECT * FROM ( \
             SELECT h.*, ROW_NUMBER() OVER ( \
                        PARTITION BY container_uid ORDER BY ts DESC, id DESC) AS rn \
             FROM pod_compute_history h \
             WHERE resolution_secs = 60 AND ts >= $1 AND node = ANY($2) \
         ) ranked \
         WHERE rn <= $3 \
         ORDER BY container_uid, ts \
         LIMIT $4",
    )
    .bind::<Timestamp, _>(cutoff)
    .bind::<Array<Text>, _>(&node_names)
    .bind::<BigInt, _>(FINDINGS_ROWS_PER_CONTAINER)
    .bind::<BigInt, _>(FINDINGS_HISTORY_ROW_CAP)
    .load::<PodComputeHistoryRow>(conn)?;
    if history.len() as i64 >= FINDINGS_HISTORY_ROW_CAP {
        truncated = true;
    }

    let pairs = diesel::sql_query(
        "SELECT * FROM ( \
             SELECT p.*, ROW_NUMBER() OVER ( \
                        PARTITION BY victim_container_uid ORDER BY wait_ns DESC, id DESC) AS rn \
             FROM pod_contention_history p \
             WHERE ts >= $1 AND victim_container_uid = ANY($2) \
         ) ranked \
         WHERE rn <= $3 \
         ORDER BY victim_container_uid, wait_ns DESC \
         LIMIT $4",
    )
    .bind::<Timestamp, _>(cutoff)
    .bind::<Array<Text>, _>(&victims)
    .bind::<BigInt, _>(FINDINGS_PAIRS_PER_VICTIM)
    .bind::<BigInt, _>(FINDINGS_PAIR_ROW_CAP)
    .load::<PodContentionRow>(conn)?;
    if pairs.len() as i64 >= FINDINGS_PAIR_ROW_CAP {
        truncated = true;
    }

    let nodes = {
        use schema::node_compute_latest::dsl::*;
        node_compute_latest
            .filter(node.eq_any(&node_names))
            .load::<NodeComputeLatest>(conn)?
    };

    Ok(FindingsScope {
        victims,
        truncated,
        history,
        pairs,
        nodes,
    })
}

#[derive(Serialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeComputeLatest>,
}

#[get(
    "/compute/nodes",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_compute_nodes(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
) -> actix_web::Result<impl Responder> {
    let _permit = match budget
        .acquire(cost_kib(NODES_ROWS_CHARGED, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let nodes = web::block(move || -> Result<Vec<NodeComputeLatest>, DbError> {
        use schema::node_compute_latest::dsl::*;
        let mut conn = pool.get()?;
        Ok(node_compute_latest
            .order(node.asc())
            .load::<NodeComputeLatest>(&mut conn)?)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(NodesResponse { nodes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_validation() {
        assert_eq!(validate_envelope("worker-3", 5000), Ok(()));
        assert!(validate_envelope("", 5000).is_err());
        assert!(validate_envelope("   ", 5000).is_err());
        assert!(validate_envelope("worker-3", 0).is_err());
        assert!(validate_envelope("worker-3", -1).is_err());
        assert!(validate_envelope(&"x".repeat(300), 5000).is_err());
    }

    #[test]
    fn minutes_clamp() {
        assert_eq!(clamp_minutes(None, 60), 60);
        assert_eq!(clamp_minutes(Some(0), 60), 1);
        assert_eq!(clamp_minutes(Some(-5), 5), 1);
        assert_eq!(clamp_minutes(Some(30), 60), 30);
        assert_eq!(clamp_minutes(Some(99_999), 60), HISTORY_MAX_MINUTES);
    }

    #[test]
    fn history_row_limit_scales_and_caps() {
        assert_eq!(history_row_limit(1, HISTORY_CONTAINERS_ASSUMED), 4);
        assert_eq!(history_row_limit(60, HISTORY_CONTAINERS_ASSUMED), 240);
        // A six-container pod gets six rows per minute, not four.
        assert_eq!(history_row_limit(60, 6), 360);
        // Zero containers (nothing in the window) still reads one row.
        assert_eq!(history_row_limit(60, 0), 60);
        assert_eq!(
            history_row_limit(HISTORY_MAX_MINUTES, HISTORY_CONTAINERS_ASSUMED),
            HISTORY_ROW_CAP
        );
        // The cap must cover a single container over the whole default
        // retention (1 440 minute rows + 6 x 288 five-minute rows).
        const { assert!(HISTORY_ROW_CAP >= 1_440 + 6 * 288) };
    }

    #[test]
    fn victim_cap_sorts_dedups_and_flags_truncation() {
        let v: Vec<String> = (0..501).rev().map(|i| format!("c{i:04}/app")).collect();
        let (kept, truncated) = cap_victims(v, 500);
        assert!(truncated);
        assert_eq!(kept.len(), 500);
        assert_eq!(kept[0], "c0000/app");
        assert!(
            kept.windows(2).all(|w| w[0] < w[1]),
            "sorted for binary_search"
        );

        let (kept, truncated) = cap_victims(vec!["b".into(), "a".into(), "a".into()], 500);
        assert!(!truncated);
        assert_eq!(kept, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn findings_caps_are_derived_from_the_window() {
        // Every container must be able to carry the whole window plus a
        // straddling row, or the sustain rule cannot be evaluated.
        assert_eq!(FINDINGS_ROWS_PER_CONTAINER, WINDOW_MINUTES + 1);
        assert_eq!(
            FINDINGS_HISTORY_ROW_CAP,
            FINDINGS_MAX_CONTAINERS * FINDINGS_ROWS_PER_CONTAINER
        );
        const { assert!(FINDINGS_MAX_CONTAINERS >= FINDINGS_MAX_VICTIMS) };
    }

    #[test]
    fn findings_scope_rows_scale_with_the_real_scope() {
        // A 20-container namespace on nodes holding 80 containers: 80 x 6
        // history rows + 20 x 30 pairs, not the 33 000-row worst case.
        assert_eq!(findings_scope_rows(20, 80), 80 * 6 + 20 * 30);
        // Containers on the nodes can never be fewer than the victims
        // (they ARE on those nodes); a stale count is floored.
        assert_eq!(findings_scope_rows(20, 0), 20 * 6 + 20 * 30);
        // Empty scope still charges one container's rows.
        assert_eq!(findings_scope_rows(0, 0), FINDINGS_ROWS_PER_CONTAINER);
        // Both halves are capped independently.
        assert_eq!(
            findings_scope_rows(FINDINGS_MAX_VICTIMS, 1_000_000),
            FINDINGS_HISTORY_ROW_CAP + FINDINGS_PAIR_ROW_CAP
        );
        assert_eq!(
            findings_scope_rows(1_000_000, 1),
            FINDINGS_HISTORY_ROW_CAP + FINDINGS_PAIR_ROW_CAP
        );
        // The worst case equals what the single up-front permit used to
        // charge (minus the victim-scope permit taken separately).
        assert_eq!(
            findings_scope_rows(FINDINGS_MAX_VICTIMS, FINDINGS_MAX_CONTAINERS),
            FINDINGS_HISTORY_ROW_CAP + FINDINGS_PAIR_ROW_CAP
        );
    }

    #[test]
    fn findings_for_scope_reports_only_scoped_victims() {
        use crate::compute_types::PodComputeHistoryRow;
        use chrono::NaiveDate;
        let t0 = NaiveDate::from_ymd_opt(2026, 9, 10)
            .unwrap()
            .and_hms_opt(2, 40, 0)
            .unwrap();
        let mk = |id: i64, uid: &str, ns: &str, m: i64| PodComputeHistoryRow {
            id,
            container_uid: uid.into(),
            pod_uid: uid.split('/').next().unwrap().into(),
            namespace: ns.into(),
            pod_name: "p".into(),
            container: "c".into(),
            node: "n1".into(),
            ts: t0 + chrono::Duration::minutes(m),
            resolution_secs: 60,
            cpu_usage_millis_avg: 100.0,
            cpu_usage_millis_max: 100.0,
            cpu_usage_millis_last: 100.0,
            cpu_quota_usec: None,
            cpu_period_usec: 100_000,
            cpu_request_millis: None,
            cpu_limit_millis: None,
            cpu_nr_periods: 600,
            cpu_nr_throttled: 0,
            cpu_throttled_usec: 0,
            cpu_psi_some10_avg: 30.0,
            cpu_psi_some10_max: 30.0,
            cpu_psi_full10_avg: 0.0,
            cpu_psi_full10_max: 0.0,
            mem_current_avg: 0,
            mem_current_max: 0,
            mem_current_last: 0,
            mem_working_set_avg: 0,
            mem_working_set_max: 0,
            mem_working_set_last: 0,
            mem_limit: None,
            mem_request: None,
            mem_psi_some10_avg: 0.0,
            mem_psi_some10_max: 0.0,
            mem_psi_full10_avg: 0.0,
            mem_psi_full10_max: 0.0,
            mem_events_high: 0,
            mem_events_max: 0,
            mem_oom_kill: 0,
            mem_refault: 0,
            mem_pgmajfault: 0,
            runq_count: None,
            runq_p50_us: None,
            runq_p95_us: None,
            runq_p99_us: None,
            runq_max_us: None,
            runq_overflow: None,
            runq_hist: None,
        };
        // Two stalled containers on the node; only `a/c` is in scope.
        let mut history = Vec::new();
        for m in 0..5 {
            history.push(mk(m, "a/c", "payments", m));
            history.push(mk(100 + m, "b/c", "batch", m));
        }
        let scope = FindingsScope {
            victims: vec!["a/c".into()],
            truncated: true,
            history,
            pairs: Vec::new(),
            nodes: Vec::new(),
        };
        let (findings, evaluated) = findings_for_scope(&scope, &ComputeThresholds::default());
        assert_eq!(evaluated, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].victim.container_uid, "a/c");
    }

    /// Build a `POST /pod/compute/batch` body of at least `min_bytes`.
    fn big_batch(min_bytes: usize) -> String {
        let hist: Vec<i64> = (0..24).collect();
        let mut containers = Vec::new();
        let mut i = 0;
        loop {
            containers.push(serde_json::json!({
                "container_uid": format!("pod-{i:05}/app"),
                "pod_uid": format!("pod-{i:05}"), "pod_name": format!("workload-{i:05}"),
                "namespace": "fleet", "container": "app", "cgroup_id": i,
                "cpu": { "usage_usec": 412000, "quota_usec": null, "period_usec": 100000,
                         "request_millis": 250, "limit_millis": null,
                         "nr_periods": 50, "nr_throttled": 0, "throttled_usec": 0,
                         "psi_some10": 1.5, "psi_full10": 0.0 },
                "memory": { "current": 183500800, "working_set": 171000000, "limit": null,
                            "request": 134217728, "psi_some10": 0.0, "psi_full10": 0.0,
                            "events_high": 0, "events_max": 0, "oom_kill": 0,
                            "refault": 12, "pgmajfault": 0 },
                "runq": { "count": 340, "p50_us": 90, "p95_us": 1800, "p99_us": 24000,
                          "max_us": 61000, "overflow": 0, "hist": hist },
                "blame": [
                    { "cgroup_id": 21003, "kind": "pod", "ref": "batch/etl-1-x/worker",
                      "container_uid": "u/worker", "count": 210, "wait_ns": 6100000000_i64 },
                    { "cgroup_id": 77, "kind": "system", "ref": "system.slice/kubelet.service",
                      "container_uid": null, "count": 40, "wait_ns": 300000000_i64 }
                ]
            }));
            i += 1;
            if i % 500 == 0 {
                let body = serde_json::json!({
                    "node": "worker-3", "ts": "2026-09-10T02:41:05Z", "interval_ms": 5000,
                    "ctxt_per_sec": 41250.0, "compute_enabled": true, "compute_supported": true,
                    "contention_loaded": true,
                    "node_pressure": { "cpu_some10": 3.1, "cpu_full10": 0.0, "mem_some10": 0.0, "mem_full10": 0.0 },
                    "node_capacity": { "cpu_cores": 32, "memory_bytes": 137438953472_i64 },
                    "bpf_occupancy": { "runq_enqueued": 0, "runq_hist": 0, "pair": 0 },
                    "unknown_blame_share": 0.0,
                    "containers": containers,
                })
                .to_string();
                if body.len() >= min_bytes {
                    return body;
                }
            }
        }
    }

    fn unreachable_pool() -> DbPool {
        let manager = ConnectionManager::<PgConnection>::new("postgres://u:p@127.0.0.1:1/nodb");
        r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(50))
            .build_unchecked(manager)
    }

    /// A 3 MiB sample batch must get past body parsing on the scoped
    /// ingest routes (it then fails at the absent database — 500 — which
    /// is the success condition here), while the same body against the
    /// default `JsonConfig` is a 413. The second half proves the test
    /// would notice the config being dropped.
    #[actix_web::test]
    async fn compute_ingest_scope_accepts_a_3mib_batch() {
        use actix_web::{http::StatusCode, test, App};
        let body = big_batch(3 << 20);
        assert!(body.len() >= 3 << 20 && body.len() < COMPUTE_JSON_LIMIT_BYTES);

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(unreachable_pool()))
                .service(compute_ingest_scope()),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/pod/compute/batch")
            .insert_header(("content-type", "application/json"))
            .set_payload(body.clone())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a 3 MiB batch must be parsed and reach the (absent) database, not be rejected"
        );

        let bare = test::init_service(
            App::new()
                .app_data(web::Data::new(unreachable_pool()))
                .service(web::scope("/pod/compute").service(add_compute_batch)),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/pod/compute/batch")
            .insert_header(("content-type", "application/json"))
            .set_payload(body)
            .to_request();
        let resp = test::call_service(&bare, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "without the scoped JsonConfig actix's 2 MiB default rejects the same body"
        );
    }

    #[test]
    fn empty_filters_are_absent() {
        assert_eq!(non_empty(Some("".into())), None);
        assert_eq!(non_empty(Some("  ".into())), None);
        assert_eq!(
            non_empty(Some(" payments ".into())),
            Some("payments".into())
        );
        assert_eq!(non_empty(None), None);
    }

    // ---- live database ---------------------------------------------------

    use crate::compute_types::LATEST_BLAME_LIMIT;

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
        conn.batch_execute("TRUNCATE pod_compute_latest")
            .expect("reset the table this test uses");
        conn
    }

    #[derive(QueryableByName)]
    struct XactUpdates {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        updated: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        hot: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        toast_inserted: i64,
    }

    /// The property that keeps `pod_compute_latest` the size of the live
    /// container set: an upsert of a known container is a HOT update, so it
    /// adds no index entries and its old version is pruned from the page
    /// without VACUUM. While `updated_at` was indexed none of them was (741 M
    /// updates, 0 HOT, 86 GB on the dev cluster). Several rounds, each its
    /// own transaction like the ingest's, because a round only stays HOT if
    /// the fillfactor headroom is there and the previous round's versions
    /// get pruned out of it.
    ///
    /// And it writes nothing to the TOAST table. The rows carry the blame
    /// list a busy node sends (20 culprits with random pod UIDs, ~4 KB that
    /// compresses to ~1.8 KB, which was stored out of line) through the
    /// same `from_sample` the ingest uses. A TOASTed value is rewritten as
    /// new TOAST rows on every upsert, never HOT, and only VACUUM reclaims
    /// the old ones: 740 MB of the table's 982 MB on the dev cluster once
    /// autovacuum stopped.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_latest_upserts_are_hot_updates() {
        const CONTAINERS: usize = 200;
        const CULPRITS: usize = 20;
        let mut conn = live_conn();
        let t0 = chrono::Utc::now().naive_utc();
        let rows = realistic_rows(0, 0..CONTAINERS, 0, CULPRITS, t0);
        assert_eq!(
            rows[0].blame.as_array().map(Vec::len),
            Some(LATEST_BLAME_LIMIT)
        );
        assert_eq!(
            rows[0].blame_omitted,
            (CULPRITS - LATEST_BLAME_LIMIT) as i32
        );
        upsert_latest(&mut conn, &rows).expect("first sample inserts");

        for round in 1..=5i64 {
            let at = t0 + chrono::Duration::seconds(5 * round);
            let rows = realistic_rows(0, 0..CONTAINERS, round, CULPRITS, at);
            // The xact counters also hold earlier transactions' counts until
            // the backend flushes them, which it only does while idle, so
            // the round is the difference of two reads inside it.
            let (before, after) = conn
                .transaction::<_, DbError, _>(|conn| {
                    let read = |conn: &mut PgConnection| {
                        diesel::sql_query(
                            "SELECT \
                               pg_stat_get_xact_tuples_updated(oid) AS updated, \
                               pg_stat_get_xact_tuples_hot_updated(oid) AS hot, \
                               pg_stat_get_xact_tuples_inserted(reltoastrelid) AS toast_inserted \
                             FROM pg_class WHERE oid = 'pod_compute_latest'::regclass",
                        )
                        .get_result::<XactUpdates>(conn)
                    };
                    let before = read(conn)?;
                    upsert_latest(conn, &rows)?;
                    Ok((before, read(conn)?))
                })
                .expect("upsert round");
            let updated = after.updated - before.updated;
            let hot = after.hot - before.hot;
            assert_eq!(updated, CONTAINERS as i64, "round {round}");
            assert_eq!(
                hot, updated,
                "round {round}: every upsert of a known container must be HOT"
            );
            assert_eq!(
                after.toast_inserted - before.toast_inserted,
                0,
                "round {round}: the row must stay inline, or every upsert rewrites its TOAST value"
            );
        }
    }

    #[derive(QueryableByName)]
    struct Name {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }

    fn index_names(conn: &mut PgConnection, table: &str) -> Vec<String> {
        diesel::sql_query(
            "SELECT indexname::text AS name FROM pg_indexes \
             WHERE schemaname = current_schema() AND tablename = $1 ORDER BY indexname",
        )
        .bind::<diesel::sql_types::Text, _>(table)
        .load::<Name>(conn)
        .expect("list indexes")
        .into_iter()
        .map(|n| n.name)
        .collect()
    }

    fn reloptions(conn: &mut PgConnection, table: &str) -> Vec<String> {
        diesel::sql_query(
            "SELECT o AS name FROM pg_class, unnest(coalesce(reloptions, '{}')) AS o \
             WHERE pg_class.oid = $1::regclass ORDER BY o",
        )
        .bind::<diesel::sql_types::Text, _>(table)
        .load::<Name>(conn)
        .expect("read reloptions")
        .into_iter()
        .map(|n| n.name)
        .collect()
    }

    /// The TOAST table behind `table`, as a name `::regclass` accepts.
    fn toast_of(conn: &mut PgConnection, table: &str) -> String {
        diesel::sql_query(
            "SELECT reltoastrelid::regclass::text AS name FROM pg_class WHERE oid = $1::regclass",
        )
        .bind::<diesel::sql_types::Text, _>(table)
        .get_result::<Name>(conn)
        .expect("the table has a TOAST table")
        .name
    }

    /// The bloat migrations apply, revert and re-apply cleanly, and each
    /// direction leaves the schema it says it does. Reverted by name rather
    /// than with `revert_last_migration`, so a later migration does not turn
    /// this into a test of something else.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_bloat_migrations_revert_and_reapply() {
        use diesel::connection::SimpleConnection;
        use diesel::migration::MigrationSource;
        use diesel_migrations::MigrationHarness;
        const OURS: [&str; 2] = ["pod_compute_latest_hot_updates", "seccomp_crs_reclaim"];
        let mut conn = live_conn();
        let all = MigrationSource::<diesel::pg::Pg>::migrations(&TEST_MIGRATIONS)
            .expect("list the shipped migrations");
        let ours: Vec<_> = OURS
            .iter()
            .map(|suffix| {
                all.iter()
                    .find(|m| m.name().to_string().ends_with(suffix))
                    .unwrap_or_else(|| panic!("migration *_{suffix} is shipped"))
            })
            .collect();
        let toast = toast_of(&mut conn, "pod_compute_latest");

        let assert_applied = |conn: &mut PgConnection| {
            assert_eq!(
                index_names(conn, "pod_compute_latest"),
                [
                    "idx_pod_compute_latest_namespace",
                    "pod_compute_latest_pkey"
                ]
                .map(String::from)
            );
            assert_eq!(
                reloptions(conn, "pod_compute_latest"),
                [
                    "autovacuum_vacuum_cost_delay=0",
                    "autovacuum_vacuum_scale_factor=0",
                    "autovacuum_vacuum_threshold=1000",
                    "fillfactor=50",
                ]
                .map(String::from)
            );
            assert_eq!(
                reloptions(conn, &toast),
                [
                    "autovacuum_vacuum_scale_factor=0",
                    "autovacuum_vacuum_threshold=1000",
                ]
                .map(String::from)
            );
        };
        assert_applied(&mut conn);

        for m in ours.iter().rev() {
            conn.revert_migration(m.as_ref())
                .unwrap_or_else(|e| panic!("revert {}: {e}", m.name()));
        }
        assert_eq!(
            index_names(&mut conn, "pod_compute_latest"),
            [
                "idx_pod_compute_latest_namespace",
                "idx_pod_compute_latest_node",
                "idx_pod_compute_latest_updated_at",
                "pod_compute_latest_pkey",
            ]
            .map(String::from)
        );
        assert!(reloptions(&mut conn, "pod_compute_latest").is_empty());
        assert!(reloptions(&mut conn, &toast).is_empty());

        // A healthy seccomp_crs keeps its rows: the reclaim empties the
        // mirror only when it is bloated, because an empty mirror shows as
        // "no CR" on every workload until the Controllers re-send.
        conn.batch_execute(
            "TRUNCATE seccomp_crs; \
             INSERT INTO seccomp_crs (namespace, name, workload_kind, workload_name) \
             VALUES ('prod', 'deployment-web', 'Deployment', 'web')",
        )
        .expect("seed a mirror row");

        for m in &ours {
            conn.run_migration(m.as_ref())
                .unwrap_or_else(|e| panic!("re-apply {}: {e}", m.name()));
        }
        assert_applied(&mut conn);
        #[derive(QueryableByName)]
        struct Count {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            n: i64,
        }
        let mirrored = diesel::sql_query("SELECT count(*) AS n FROM seccomp_crs")
            .get_result::<Count>(&mut conn)
            .expect("count mirror rows")
            .n;
        assert_eq!(mirrored, 1, "a small seccomp_crs is left alone");
        conn.batch_execute("TRUNCATE seccomp_crs")
            .expect("leave the table empty for the other live tests");
        assert!(
            conn.pending_migrations(TEST_MIGRATIONS)
                .expect("list pending migrations")
                .is_empty(),
            "the schema is back where the other live tests expect it"
        );
    }

    /// One container's wire sample with a blame list the size and shape a
    /// busy node produces: `culprits` entries (the controller sends up to
    /// 20), pod culprits named `ns/deployment-hash-suffix/container` with a
    /// `pod-uid/container` identity, plus the kernel and two system units.
    /// Waits and counts change every round, as they do between samples.
    fn realistic_sample(i: usize, round: i64, culprits: usize) -> serde_json::Value {
        const NS: [&str; 5] = [
            "payments",
            "kube-system",
            "monitoring",
            "ingress-nginx",
            "checkout-service",
        ];
        const APP: [&str; 5] = [
            "api-gateway",
            "aws-node",
            "prometheus-node-exporter",
            "ingress-nginx-controller",
            "order-worker",
        ];
        const CTR: [&str; 5] = [
            "app",
            "aws-node",
            "node-exporter",
            "controller",
            "istio-proxy",
        ];
        const UNITS: [&str; 2] = [
            "system.slice/containerd.service",
            "system.slice/kubelet.service",
        ];
        let blame: Vec<serde_json::Value> = (0..culprits)
            .map(|k| {
                let seed = splitmix((i * 64 + k) as u64 ^ (round as u64) << 32);
                let wait = (seed % 400_000_000) as i64;
                let count = ((seed >> 32) % 500) as i64;
                match k {
                    0 => serde_json::json!({ "cgroup_id": 0, "kind": "kernel", "ref": "kernel",
                        "container_uid": null, "count": count, "wait_ns": wait }),
                    1 | 2 => serde_json::json!({ "cgroup_id": 4000 + k, "kind": "system",
                        "ref": UNITS[k - 1],
                        "container_uid": null, "count": count, "wait_ns": wait }),
                    _ => {
                        let peer = (i * 13 + k * 7) % 2900;
                        // Pod UIDs and ReplicaSet hashes are random, which
                        // is what keeps a real list from compressing well.
                        let h = |salt: u64| splitmix(peer as u64 * 1_000 + salt);
                        let uid = format!(
                            "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
                            h(1) as u32,
                            h(2) as u16,
                            h(3) & 0xfff,
                            h(4) & 0xfff,
                            h(5) & 0xffff_ffff_ffff
                        );
                        serde_json::json!({ "cgroup_id": 100_000 + peer, "kind": "pod",
                            "ref": format!("{}/{}-{:010x}-{:05x}/{}", NS[peer % 5], APP[peer % 5],
                                h(6) & 0xff_ffff_ffff, h(7) & 0xf_ffff, CTR[peer % 5]),
                            "container_uid": format!("{uid}/{}", CTR[peer % 5]),
                            "count": count, "wait_ns": wait })
                    }
                }
            })
            .collect();
        serde_json::json!({
            "container_uid": format!("pod-{i:05}/app"),
            "pod_uid": format!("pod-{i:05}"), "pod_name": format!("api-{i:05}"),
            "namespace": NS[i % 5], "container": "app", "cgroup_id": 100_000 + i,
            "cpu": { "usage_usec": 412_000 + round * 100 + i as i64, "quota_usec": 100_000,
                     "period_usec": 100_000, "request_millis": 250, "limit_millis": 1000,
                     "nr_periods": 50, "nr_throttled": round % 3, "throttled_usec": round * 10,
                     "psi_some10": 1.5, "psi_full10": 0.0 },
            "memory": { "current": 183_500_800 + round, "working_set": 171_000_000 + round,
                        "limit": 268_435_456, "request": 134_217_728, "psi_some10": 0.0,
                        "psi_full10": 0.0, "events_high": 0, "events_max": 0, "oom_kill": 0,
                        "refault": round % 7, "pgmajfault": 0 },
            "runq": { "count": 340 + round, "p50_us": 90, "p95_us": 1800, "p99_us": 24_000,
                      "max_us": 61_000, "overflow": 0, "hist": [] },
            "blame": blame,
        })
    }

    /// A deterministic 64-bit mix (SplitMix64), for test data that looks
    /// random without a dependency.
    fn splitmix(x: u64) -> u64 {
        let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// One node's `POST /pod/compute/batch` for containers `ids`, flattened
    /// to the rows `upsert_latest` receives.
    fn realistic_rows(
        node: usize,
        ids: std::ops::Range<usize>,
        round: i64,
        culprits: usize,
        at: NaiveDateTime,
    ) -> Vec<PodComputeLatest> {
        let batch: ComputeBatch = serde_json::from_value(serde_json::json!({
            "node": format!("ip-10-0-{node}-17.eu-west-1.compute.internal"),
            "ts": at.and_utc().to_rfc3339(), "interval_ms": 5000,
            "ctxt_per_sec": 41250.0, "compute_enabled": true, "compute_supported": true,
            "contention_loaded": true,
            "node_pressure": { "cpu_some10": 3.1, "cpu_full10": 0.0, "mem_some10": 0.0, "mem_full10": 0.0 },
            "node_capacity": { "cpu_cores": 32, "memory_bytes": 137_438_953_472_i64 },
            "bpf_occupancy": { "runq_enqueued": 0, "runq_hist": 0, "pair": 0 },
            "unknown_blame_share": 0.0,
            "containers": ids.map(|i| realistic_sample(i, round, culprits)).collect::<Vec<_>>(),
        }))
        .expect("realistic batch parses");
        batch
            .containers
            .iter()
            .map(|c| PodComputeLatest::from_sample(&batch, c, at))
            .collect()
    }
}
