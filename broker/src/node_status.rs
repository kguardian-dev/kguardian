//! `GET /node/status`: when each node's controller last posted a pod.
//!
//! The stale-alive sweep (`peer.rs`) marks a node's pods dead once its
//! controller stops re-posting them, and until now nothing named the
//! node: the pods simply vanished from the namespace picker, the
//! Workloads view and the maps. This read derives the answer from the
//! tables the controller already writes. `last_pod_post_at` is the
//! newest `pod_details.time_stamp` for the node, dead rows included, so
//! it keeps pointing at the last post after the sweep has run;
//! `last_heartbeat_at` is the compute heartbeat (`node_compute_latest`),
//! which every controller posts whether or not compute gauges are on,
//! so a client can tell "controller up, pods not reported" (the F-19
//! failure) from "node gone".

use crate::compute_types::utc_ts;
use crate::read_budget::{cost_kib, ReadBudget};
use actix_web::{get, web, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_types::{BigInt, Nullable, Text, Timestamp};
use serde::Serialize;
use std::time::Duration;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// One row per node; a few hundred bytes each, a few hundred nodes at most.
const NODE_ROWS_CHARGED: i64 = 1_000;
const NODE_ROW_COST_BYTES: u64 = 256;

#[derive(Debug, QueryableByName)]
struct NodeRow {
    #[diesel(sql_type = Text)]
    node: String,
    #[diesel(sql_type = Nullable<Timestamp>)]
    last_pod_post_at: Option<NaiveDateTime>,
    #[diesel(sql_type = BigInt)]
    alive_pods: i64,
    #[diesel(sql_type = Nullable<Timestamp>)]
    last_heartbeat_at: Option<NaiveDateTime>,
}

/// `utc_ts` for an optional column: RFC 3339 with `Z`, or `null`.
fn opt_utc_ts<S: serde::Serializer>(t: &Option<NaiveDateTime>, s: S) -> Result<S::Ok, S::Error> {
    match t {
        Some(t) => utc_ts::serialize(t, s),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub node: String,
    #[serde(serialize_with = "opt_utc_ts")]
    pub last_pod_post_at: Option<NaiveDateTime>,
    pub alive_pods: i64,
    #[serde(serialize_with = "opt_utc_ts")]
    pub last_heartbeat_at: Option<NaiveDateTime>,
    /// No pod post inside the stale window (or never): the sweep has
    /// marked, or is about to mark, this node's pods dead.
    pub stale: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatusResponse {
    /// `PEER_STALE_ALIVE_SECS`, so a client applies the same window.
    pub stale_after_secs: u64,
    pub nodes: Vec<NodeStatus>,
}

/// Every node the broker has heard from, from either table. The pod
/// aggregate is one pass over `pod_details`, which is the whole point:
/// no per-node round trips, and dead rows count towards the last post.
const NODE_STATUS_SQL: &str = "WITH pods AS ( \
         SELECT node_name AS node, \
                MAX(time_stamp) AS last_pod_post_at, \
                COUNT(*) FILTER (WHERE NOT is_dead) AS alive_pods \
         FROM pod_details GROUP BY node_name \
     ) \
     SELECT COALESCE(p.node, h.node) AS node, \
            p.last_pod_post_at, \
            COALESCE(p.alive_pods, 0) AS alive_pods, \
            h.updated_at AS last_heartbeat_at \
     FROM pods p \
     FULL OUTER JOIN node_compute_latest h ON h.node = p.node \
     ORDER BY 1";

pub fn node_status(
    conn: &mut PgConnection,
    now: NaiveDateTime,
    stale_after: Duration,
) -> Result<Vec<NodeStatus>, DbError> {
    let rows = diesel::sql_query(NODE_STATUS_SQL).load::<NodeRow>(conn)?;
    Ok(rows
        .into_iter()
        .map(|r| NodeStatus {
            stale: is_stale(r.last_pod_post_at, now, stale_after),
            node: r.node,
            last_pod_post_at: r.last_pod_post_at,
            alive_pods: r.alive_pods,
            last_heartbeat_at: r.last_heartbeat_at,
        })
        .collect())
}

/// The sweep's own arithmetic (`peer::window_cutoff`): a post older
/// than `now - stale_after` is stale, one exactly at the cutoff is not,
/// and a node with no post at all is stale.
pub fn is_stale(
    last_post: Option<NaiveDateTime>,
    now: NaiveDateTime,
    stale_after: Duration,
) -> bool {
    match last_post {
        None => true,
        Some(at) => at < crate::peer::window_cutoff(now, stale_after),
    }
}

#[get(
    "/node/status",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_node_status(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
) -> actix_web::Result<impl Responder> {
    let _permit = match budget
        .acquire(cost_kib(NODE_ROWS_CHARGED, NODE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let stale_after = crate::peer::stale_alive_window();
    let nodes = web::block(move || {
        let mut conn = pool.get()?;
        node_status(&mut conn, chrono::Utc::now().naive_utc(), stale_after)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(NodeStatusResponse {
        stale_after_secs: stale_after.as_secs(),
        nodes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").unwrap()
    }

    #[test]
    fn staleness_matches_the_sweep_cutoff_exactly() {
        let now = ts("2026-09-28T12:37:00");
        let window = Duration::from_secs(900);
        assert!(is_stale(None, now, window));
        assert!(is_stale(Some(ts("2026-09-28T07:37:12")), now, window));
        assert!(is_stale(Some(ts("2026-09-28T12:21:59")), now, window));
        // Exactly at the cutoff the sweep leaves the row alive; so do we.
        assert!(!is_stale(Some(ts("2026-09-28T12:22:00")), now, window));
        assert!(!is_stale(Some(ts("2026-09-28T12:36:30")), now, window));
    }

    #[test]
    fn response_names_fields_the_way_the_ui_reads_them() {
        let body = serde_json::to_value(NodeStatusResponse {
            stale_after_secs: 900,
            nodes: vec![NodeStatus {
                node: "ip-10-62-65-125".into(),
                last_pod_post_at: Some(ts("2026-09-28T07:37:12")),
                alive_pods: 0,
                last_heartbeat_at: None,
                stale: true,
            }],
        })
        .unwrap();
        assert_eq!(body["staleAfterSecs"], 900);
        let node = &body["nodes"][0];
        assert_eq!(node["node"], "ip-10-62-65-125");
        assert_eq!(node["lastPodPostAt"], "2026-09-28T07:37:12Z");
        assert_eq!(node["alivePods"], 0);
        assert!(node["lastHeartbeatAt"].is_null());
        assert_eq!(node["stale"], true);
    }

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel::connection::SimpleConnection;
        use diesel_migrations::MigrationHarness;
        let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("apply the shipped migrations");
        conn.batch_execute("TRUNCATE pod_details, node_compute_latest")
            .expect("reset the tables this test uses");
        conn
    }

    fn seed_pod(conn: &mut PgConnection, name: &str, node: &str, at: NaiveDateTime, dead: bool) {
        use crate::schema::pod_details::dsl as pd;
        diesel::insert_into(pd::pod_details)
            .values((
                pd::pod_name.eq(name),
                pd::pod_ip.eq("10.0.0.1"),
                pd::pod_namespace.eq("default"),
                pd::time_stamp.eq(at),
                pd::node_name.eq(node),
                pd::is_dead.eq(dead),
            ))
            .execute(conn)
            .expect("seed pod_details");
    }

    fn seed_heartbeat(conn: &mut PgConnection, node: &str, at: NaiveDateTime) {
        use diesel::connection::SimpleConnection;
        conn.batch_execute(&format!(
            "INSERT INTO node_compute_latest (node, ts, interval_ms, ctxt_per_sec, \
             compute_enabled, compute_supported, contention_loaded, cpu_some10, cpu_full10, \
             mem_some10, mem_full10, cpu_cores, memory_bytes, bpf_runq_enqueued, bpf_runq_hist, \
             bpf_pair, unknown_blame_share, updated_at) VALUES ('{node}', '{at}', 300000, 0, \
             false, false, false, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, '{at}')"
        ))
        .expect("seed node_compute_latest");
    }

    /// The F-19 shape: one node re-posting, one whose controller is up
    /// (heartbeat fresh) but has not posted a pod since the rollout and
    /// whose rows the sweep already marked dead, one gone entirely, and
    /// one with a heartbeat but no pod row yet.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_reports_last_post_alive_count_heartbeat_and_staleness_per_node() {
        let mut conn = live_conn();
        let now = ts("2026-09-28T12:37:00");
        let window = Duration::from_secs(900);
        seed_pod(
            &mut conn,
            "fresh-a",
            "ip-fresh",
            ts("2026-09-28T12:36:10"),
            false,
        );
        seed_pod(
            &mut conn,
            "fresh-b",
            "ip-fresh",
            ts("2026-09-28T12:35:40"),
            false,
        );
        seed_pod(
            &mut conn,
            "fresh-old",
            "ip-fresh",
            ts("2026-09-27T09:00:00"),
            true,
        );
        seed_heartbeat(&mut conn, "ip-fresh", ts("2026-09-28T12:36:00"));
        seed_pod(
            &mut conn,
            "stuck-a",
            "ip-stuck",
            ts("2026-09-28T07:37:12"),
            true,
        );
        seed_pod(
            &mut conn,
            "stuck-b",
            "ip-stuck",
            ts("2026-09-28T07:36:50"),
            true,
        );
        seed_heartbeat(&mut conn, "ip-stuck", ts("2026-09-28T12:35:00"));
        seed_pod(
            &mut conn,
            "gone-a",
            "ip-gone",
            ts("2026-09-26T01:00:00"),
            true,
        );
        seed_heartbeat(&mut conn, "ip-gone", ts("2026-09-26T01:02:00"));
        seed_heartbeat(&mut conn, "ip-new", ts("2026-09-28T12:36:30"));

        let got = node_status(&mut conn, now, window).expect("query");
        assert_eq!(
            got,
            vec![
                NodeStatus {
                    node: "ip-fresh".into(),
                    last_pod_post_at: Some(ts("2026-09-28T12:36:10")),
                    alive_pods: 2,
                    last_heartbeat_at: Some(ts("2026-09-28T12:36:00")),
                    stale: false,
                },
                NodeStatus {
                    node: "ip-gone".into(),
                    last_pod_post_at: Some(ts("2026-09-26T01:00:00")),
                    alive_pods: 0,
                    last_heartbeat_at: Some(ts("2026-09-26T01:02:00")),
                    stale: true,
                },
                NodeStatus {
                    node: "ip-new".into(),
                    last_pod_post_at: None,
                    alive_pods: 0,
                    last_heartbeat_at: Some(ts("2026-09-28T12:36:30")),
                    stale: true,
                },
                NodeStatus {
                    node: "ip-stuck".into(),
                    last_pod_post_at: Some(ts("2026-09-28T07:37:12")),
                    alive_pods: 0,
                    last_heartbeat_at: Some(ts("2026-09-28T12:35:00")),
                    stale: true,
                },
            ]
        );
    }
}
