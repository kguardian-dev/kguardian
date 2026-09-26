//! Workload security profile: read model, posture rollup, versions and
//! diff (#1533 P0-5). The API contract is
//! `docs/design/workload-security-profile-api.md`; field semantics
//! (null = unknown, [] = known empty, nothing omitted) are defined there.
//!
//! # What it joins
//!
//! One workload, keyed `(namespace, kind, name)` exactly as
//! `workload_syscalls` / `workload_containers` / the SeccompProfile
//! `workloadRef` are (the controller's owner resolution; an ownerless pod
//! is `("Pod", pod_name)`):
//!
//! - `podSecurity`: the PSS analyser ([`crate::pod_security`]) over the
//!   image inventory's securityContext rows;
//! - `images`: the inventory's running / previous digests. Vulnerabilities
//!   and supply chain are `null` (not configured) until those sources land;
//! - `syscalls`: the seccomp summary `GET /seccomp/profiles/{..}` serves
//!   (capture completeness, CR mode, drift, denials), built by the same
//!   code;
//! - `network`: a bounded aggregate of the workload pods' `pod_traffic`
//!   rows plus AuditNetworkPolicy verdicts from the last 24 h. Applied
//!   NetworkPolicies are not mirrored into the broker, so enforced policy
//!   state is always `null`;
//! - `compute`: `pod_compute_latest` for the live pods (informational).
//!
//! # Posture
//!
//! Each dimension scores `100 - sum(points of its findings)` or is
//! unscored (`null`). The rollup is the weighted mean over SCORED
//! dimensions only, with `coverage` = the weight fraction that is scored.
//! Unknown is never counted as 0 or 100.
//!
//! # Versions
//!
//! A background snapshotter ([`spawn`]) walks workloads (least recently
//! computed first), computes each profile, and stores an immutable
//! snapshot of its policy-relevant parts in `workload_profile_versions`
//! only when the canonical content hash changes. It also maintains
//! `workload_profile_latest`, which backs `GET /workloads`. Versions per
//! workload are capped ([`max_versions_per_workload`]); age-based
//! retention lives in `retention.rs`.
//!
//! # Bounds
//!
//! Every read is LIMITed and charged to the read budget: flows scanned
//! per profile ([`NETWORK_SCAN_ROWS`]), peers returned
//! ([`NETWORK_PEERS_MAX`]), pods ([`PODS_MAX`]), compute rows
//! ([`COMPUTE_ROWS_MAX`]), verdict groups ([`AUDIT_POLICIES_MAX`]), list and
//! version page sizes.

use crate::image_inventory::{
    self, ContainerDigest, ContainerImages, ContainerSecurity, PodSecurity, WorkloadContainers,
    DEFAULT_CLUSTER_ID, WORKLOAD_CONTAINERS_MAX, WORKLOAD_CONTAINER_ROW_COST_BYTES,
};
use crate::pod_security::{self, Analysis, Level};
use crate::read_budget::{
    cost_kib, ReadBudget, SECCOMP_DETAIL_ROWS_CHARGED, SECCOMP_WORKLOAD_COST_BYTES,
};
use actix_web::{get, http::StatusCode, web, HttpResponse, Responder};
use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Integer, Jsonb, Nullable, Text, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tracing::{debug, info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------
// Bounds and settings
// ---------------------------------------------------------------------

/// Flow rows scanned per profile (newest first) before aggregation.
pub const NETWORK_SCAN_ROWS: i64 = 50_000;
/// Aggregated peer rows returned.
pub const NETWORK_PEERS_MAX: i64 = 200;
/// Pods of one workload considered (flows are read for these).
pub const PODS_MAX: i64 = 500;
/// Live pod names listed in the header.
pub const POD_NAMES_LISTED: usize = 20;
/// Compute rows returned.
pub const COMPUTE_ROWS_MAX: i64 = 50;
/// AuditNetworkPolicy groups returned.
pub const AUDIT_POLICIES_MAX: i64 = 50;
/// Window for audit verdicts.
pub const AUDIT_WINDOW_HOURS: i64 = 24;
/// Findings surfaced in `attention`.
pub const ATTENTION_MAX: usize = 5;

pub const LIST_DEFAULT_LIMIT: i64 = 100;
pub const LIST_MAX_LIMIT: i64 = 500;
pub const VERSIONS_DEFAULT_LIMIT: i64 = 50;
pub const VERSIONS_MAX_LIMIT: i64 = 200;

/// Per list row: the stored summary is a few hundred bytes.
pub const LIST_ROW_COST_BYTES: u64 = 2_048;
/// Per version-list row (no snapshot body).
pub const VERSION_ROW_COST_BYTES: u64 = 1_024;
/// One stored snapshot: syscall names (hundreds), up to
/// NETWORK_PEERS_MAX rules and the container securityContexts, well under
/// 128 KiB serialised; charged at that with the parse transient.
pub const SNAPSHOT_COST_BYTES: u64 = 128 * 1_024;
/// One aggregated peer row.
pub const PEER_ROW_COST_BYTES: u64 = 1_024;

/// Scoring weights (contract section 2.2).
pub const WEIGHTS: [(&str, u32); 4] = [
    ("network", 20),
    ("syscalls", 15),
    ("podSecurity", 20),
    ("images", 30),
];

fn env_num(key: &str) -> Option<i64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

/// `PROFILE_SNAPSHOT_INTERVAL_SECS` (default 300, floor 60).
pub fn snapshot_interval() -> Duration {
    Duration::from_secs(
        env_num("PROFILE_SNAPSHOT_INTERVAL_SECS")
            .unwrap_or(300)
            .max(60) as u64,
    )
}

/// `PROFILE_SNAPSHOT_BATCH` workloads per tick (default 200, [1, 5000]).
pub fn snapshot_batch() -> i64 {
    env_num("PROFILE_SNAPSHOT_BATCH")
        .unwrap_or(200)
        .clamp(1, 5_000)
}

/// `PROFILE_VERSIONS_MAX_PER_WORKLOAD` (default 50, [1, 1000]).
pub fn max_versions_per_workload() -> i64 {
    env_num("PROFILE_VERSIONS_MAX_PER_WORKLOAD")
        .unwrap_or(50)
        .clamp(1, 1_000)
}

// ---------------------------------------------------------------------
// Key and errors
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub namespace: String,
    pub kind: String,
    pub name: String,
}

const MAX_SEGMENT: usize = 253;

fn valid_segment(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= MAX_SEGMENT && !s.contains('/')
}

impl Key {
    fn parse(ns: String, kind: String, name: String) -> Option<Key> {
        [&ns, &kind, &name]
            .iter()
            .all(|s| valid_segment(s))
            .then_some(Key {
                namespace: ns,
                kind,
                name,
            })
    }
}

fn bad_key() -> HttpResponse {
    error(
        StatusCode::BAD_REQUEST,
        "bad_request",
        "namespace, kind and name must be non-empty and at most 253 characters",
    )
}

fn error(status: StatusCode, code: &str, message: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({ "error": code, "message": message }))
}

fn not_found_workload() -> HttpResponse {
    error(
        StatusCode::NOT_FOUND,
        "workload_not_found",
        "the broker has no inventory, syscall aggregate, live pod or stored profile for this workload",
    )
}

fn utc(t: NaiveDateTime) -> DateTime<Utc> {
    t.and_utc()
}

// ---------------------------------------------------------------------
// Sources (database side)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, QueryableByName)]
struct PodRow {
    #[diesel(sql_type = Text)]
    pod_name: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_dead: bool,
}

/// One aggregated flow group.
#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct NetRow {
    #[diesel(sql_type = Text)]
    pub dir: String,
    #[diesel(sql_type = Text)]
    pub proto: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub port: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub peer_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub peer_namespace: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub peer_workload_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub peer_workload_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub peer_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub ip: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub flows: i64,
    #[diesel(sql_type = Timestamp)]
    pub first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    pub last_seen: NaiveDateTime,
    #[diesel(sql_type = BigInt)]
    pub scanned: i64,
}

/// Newest `$3` flow rows of the pods, grouped per (direction, protocol,
/// port, peer identity). A pod peer is grouped by its workload (or name
/// when it has none) and a service by name; only identity-less peers
/// (and nodes) are grouped by IP. Deterministic order.
const NETWORK_SQL: &str = "\
WITH t AS ( \
    SELECT traffic_type, ip_protocol, pod_port, traffic_in_out_ip, traffic_in_out_port, \
           peer_kind, peer_namespace, peer_name, peer_workload_kind, peer_workload_name, time_stamp \
    FROM pod_traffic WHERE pod_namespace = $1 AND pod_name = ANY($2) \
    ORDER BY time_stamp DESC LIMIT $3 \
), g AS ( \
    SELECT upper(trim(coalesce(traffic_type, ''))) AS dir, \
           upper(trim(coalesce(ip_protocol, 'TCP'))) AS proto, \
           CASE WHEN upper(trim(coalesce(traffic_type, ''))) = 'INGRESS' THEN pod_port \
                ELSE traffic_in_out_port END AS port, \
           peer_kind, peer_namespace, peer_workload_kind, peer_workload_name, \
           CASE WHEN peer_workload_name IS NULL THEN peer_name END AS grp_name, \
           CASE WHEN peer_kind IS NULL OR peer_kind = 'node' THEN traffic_in_out_ip END AS grp_ip, \
           peer_name, traffic_in_out_ip, time_stamp \
    FROM t \
) \
SELECT dir, proto, port, peer_kind, peer_namespace, peer_workload_kind, peer_workload_name, \
       max(peer_name) AS peer_name, max(traffic_in_out_ip) AS ip, count(*) AS flows, \
       min(time_stamp) AS first_seen, max(time_stamp) AS last_seen, \
       (SELECT count(*) FROM t) AS scanned \
FROM g WHERE dir IN ('INGRESS', 'EGRESS') \
GROUP BY dir, proto, port, peer_kind, peer_namespace, peer_workload_kind, peer_workload_name, grp_name, grp_ip \
ORDER BY dir DESC, proto, port, peer_kind NULLS LAST, peer_namespace NULLS LAST, \
         peer_workload_kind NULLS LAST, peer_workload_name NULLS LAST, grp_name NULLS LAST, grp_ip NULLS LAST \
LIMIT $4";

#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct AuditRow {
    #[diesel(sql_type = Text)]
    pub policy_namespace: String,
    #[diesel(sql_type = Text)]
    pub policy_name: String,
    #[diesel(sql_type = BigInt)]
    pub allow: i64,
    #[diesel(sql_type = BigInt)]
    pub would_deny: i64,
    #[diesel(sql_type = Timestamp)]
    pub last: NaiveDateTime,
}

const AUDIT_SQL: &str = "\
SELECT policy_namespace, policy_name, \
       count(*) FILTER (WHERE verdict = 'Allow') AS allow, \
       count(*) FILTER (WHERE verdict = 'WouldDeny') AS would_deny, \
       max(observed_at) AS last \
FROM audit_verdicts \
WHERE observed_at >= timezone('UTC', NOW()) - make_interval(hours => $3) \
  AND ((src_namespace = $1 AND src_pod = ANY($2)) OR (dst_namespace = $1 AND dst_pod = ANY($2))) \
GROUP BY policy_namespace, policy_name \
ORDER BY policy_namespace, policy_name \
LIMIT $4";

#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct ComputeRow {
    #[diesel(sql_type = Text)]
    pub pod_name: String,
    #[diesel(sql_type = Text)]
    pub container: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub cpu_request_millis: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub cpu_limit_millis: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub mem_request: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub mem_limit: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Double)]
    pub cpu_usage_millis: f64,
    #[diesel(sql_type = BigInt)]
    pub mem_working_set: i64,
    #[diesel(sql_type = BigInt)]
    pub mem_oom_kill: i64,
    #[diesel(sql_type = BigInt)]
    pub cpu_nr_periods: i64,
    #[diesel(sql_type = BigInt)]
    pub cpu_nr_throttled: i64,
    #[diesel(sql_type = Timestamp)]
    pub updated_at: NaiveDateTime,
}

const COMPUTE_SQL: &str = "\
SELECT pod_name, container, cpu_request_millis, cpu_limit_millis, mem_request, mem_limit, \
       cpu_usage_millis, mem_working_set, mem_oom_kill, cpu_nr_periods, cpu_nr_throttled, updated_at \
FROM pod_compute_latest WHERE namespace = $1 AND pod_name = ANY($2) \
ORDER BY pod_name, container LIMIT $3";

#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct StoredVersionHead {
    #[diesel(sql_type = Integer)]
    pub revision: i32,
    #[diesel(sql_type = Text)]
    pub content_hash: String,
    #[diesel(sql_type = Timestamp)]
    pub created_at: NaiveDateTime,
}

const LATEST_VERSION_SQL: &str = "\
SELECT revision, content_hash, created_at FROM workload_profile_versions \
WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
ORDER BY revision DESC LIMIT 1";

/// The seccomp summary as `GET /seccomp/profiles/{..}` serialises it.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SeccompSummary {
    pub hash: String,
    #[serde(rename = "syscallCount")]
    pub syscall_count: usize,
    pub architectures: Vec<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
    pub capture: CaptureIn,
    pub cr: Option<CrIn>,
    pub denials: Option<DenialIn>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CaptureIn {
    pub level: String,
    pub complete: bool,
    pub incomplete: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CrIn {
    pub name: String,
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub hash: String,
    #[serde(rename = "syscallCount")]
    pub syscall_count: usize,
    pub drift: DriftIn,
    pub distribution: DistIn,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DriftIn {
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    #[serde(rename = "inSync")]
    pub in_sync: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DistIn {
    pub ready: i64,
    pub total: i64,
    pub state: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DenialIn {
    pub total: i64,
    pub syscalls: Vec<String>,
    #[serde(rename = "lastSeen")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// Everything a profile is built from. Pure data, so [`build`] is unit
/// tested without a database.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    pub containers: Vec<ContainerImages>,
    pub containers_truncated: bool,
    pub running_window_seconds: i64,
    pub seccomp: Option<(SeccompSummary, BTreeSet<String>)>,
    pub live_pods: Vec<String>,
    pub any_pods: bool,
    pub network: Vec<NetRow>,
    pub network_truncated: bool,
    /// `None` = no verdict in the window mentions the pods.
    pub audit: Vec<AuditRow>,
    pub compute: Vec<ComputeRow>,
    pub compute_truncated: bool,
    pub stored: Option<StoredVersionHead>,
}

impl Sources {
    fn is_empty(&self) -> bool {
        self.containers.is_empty()
            && self.seccomp.is_none()
            && !self.any_pods
            && self.stored.is_none()
    }
}

/// Read every source for one workload.
pub fn load_sources(conn: &mut PgConnection, key: &Key) -> Result<Sources, DbError> {
    let WorkloadContainers {
        containers,
        truncated,
        running_window_seconds,
        ..
    } = image_inventory::workload_containers(conn, &key.namespace, &key.kind, &key.name)?;

    let seccomp =
        match crate::seccomp::workload_summary_json(conn, &key.namespace, &key.kind, &key.name)? {
            Some((v, names)) => Some((serde_json::from_value::<SeccompSummary>(v)?, names)),
            None => None,
        };

    let pods: Vec<PodRow> = sql_query(
        "SELECT pod_name, is_dead FROM pod_details WHERE pod_namespace = $1 \
         AND ((workload_kind = $2 AND workload_name = $3) \
              OR ($2 = 'Pod' AND pod_name = $3 AND workload_kind IS NULL)) \
         ORDER BY is_dead, pod_name LIMIT $4",
    )
    .bind::<Text, _>(&key.namespace)
    .bind::<Text, _>(&key.kind)
    .bind::<Text, _>(&key.name)
    .bind::<BigInt, _>(PODS_MAX)
    .load(conn)?;
    let all_pods: Vec<String> = pods.iter().map(|p| p.pod_name.clone()).collect();
    let live_pods: Vec<String> = pods
        .iter()
        .filter(|p| !p.is_dead)
        .map(|p| p.pod_name.clone())
        .collect();

    let (network, network_truncated) = if all_pods.is_empty() {
        (Vec::new(), false)
    } else {
        let mut rows: Vec<NetRow> = sql_query(NETWORK_SQL)
            .bind::<Text, _>(&key.namespace)
            .bind::<Array<Text>, _>(&all_pods)
            .bind::<BigInt, _>(NETWORK_SCAN_ROWS)
            .bind::<BigInt, _>(NETWORK_PEERS_MAX + 1)
            .load(conn)?;
        let scanned = rows.first().map(|r| r.scanned).unwrap_or(0);
        let truncated = rows.len() as i64 > NETWORK_PEERS_MAX || scanned >= NETWORK_SCAN_ROWS;
        rows.truncate(NETWORK_PEERS_MAX as usize);
        (rows, truncated)
    };

    let audit: Vec<AuditRow> = if all_pods.is_empty() {
        Vec::new()
    } else {
        sql_query(AUDIT_SQL)
            .bind::<Text, _>(&key.namespace)
            .bind::<Array<Text>, _>(&all_pods)
            .bind::<Integer, _>(AUDIT_WINDOW_HOURS as i32)
            .bind::<BigInt, _>(AUDIT_POLICIES_MAX)
            .load(conn)?
    };

    let (compute, compute_truncated) = if live_pods.is_empty() {
        (Vec::new(), false)
    } else {
        let mut rows: Vec<ComputeRow> = sql_query(COMPUTE_SQL)
            .bind::<Text, _>(&key.namespace)
            .bind::<Array<Text>, _>(&live_pods)
            .bind::<BigInt, _>(COMPUTE_ROWS_MAX + 1)
            .load(conn)?;
        let t = rows.len() as i64 > COMPUTE_ROWS_MAX;
        rows.truncate(COMPUTE_ROWS_MAX as usize);
        (rows, t)
    };

    let stored: Option<StoredVersionHead> = sql_query(LATEST_VERSION_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .get_result(conn)
        .optional()?;

    Ok(Sources {
        containers,
        containers_truncated: truncated,
        running_window_seconds,
        seccomp,
        any_pods: !all_pods.is_empty(),
        live_pods,
        network,
        network_truncated,
        audit,
        compute,
        compute_truncated,
        stored,
    })
}

/// Read-budget charge for one live profile: every bounded read above.
pub fn profile_charge_kib() -> u32 {
    cost_kib(
        WORKLOAD_CONTAINERS_MAX + 1,
        WORKLOAD_CONTAINER_ROW_COST_BYTES,
    )
    .saturating_add(cost_kib(
        SECCOMP_DETAIL_ROWS_CHARGED,
        SECCOMP_WORKLOAD_COST_BYTES,
    ))
    .saturating_add(crate::seccomp_denial::denial_index_for_charge_kib())
    .saturating_add(cost_kib(NETWORK_PEERS_MAX + 1, PEER_ROW_COST_BYTES))
    .saturating_add(cost_kib(PODS_MAX, 256))
    .saturating_add(cost_kib(COMPUTE_ROWS_MAX + 1, 1_024))
    .saturating_add(cost_kib(AUDIT_POLICIES_MAX, 512))
    .saturating_add(cost_kib(2, SNAPSHOT_COST_BYTES))
}

// ---------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Reason {
    pub code: &'static str,
    pub message: String,
}

fn reason(code: &'static str, message: impl Into<String>) -> Reason {
    Reason {
        code,
        message: message.into(),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub level: &'static str,
    pub fraction: Option<f64>,
    pub observed_since: Option<DateTime<Utc>>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub dimension: &'static str,
    pub severity: &'static str,
    pub tier: Option<&'static str>,
    pub title: String,
    pub detail: String,
    pub container: Option<String>,
    #[serde(skip)]
    pub points: u32,
}

fn tier(severity: &str) -> Option<&'static str> {
    match severity {
        "critical" => Some("P0"),
        "high" => Some("P1"),
        "medium" => Some("P2"),
        _ => None,
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn mk_finding(
    dimension: &'static str,
    id: String,
    severity: &'static str,
    points: u32,
    container: Option<String>,
    title: String,
    detail: String,
) -> Finding {
    Finding {
        id,
        dimension,
        severity,
        tier: tier(severity),
        title,
        detail,
        container,
        points,
    }
}

/// Status / score / coverage / reasons shared by every dimension.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub status: &'static str,
    pub score: Option<u32>,
    pub scored: bool,
    pub coverage: Coverage,
    pub reasons: Vec<Reason>,
}

fn status_from_score(score: u32) -> &'static str {
    if score >= 80 {
        "ok"
    } else if score >= 50 {
        "warn"
    } else {
        "risk"
    }
}

fn status_from_findings(f: &[Finding]) -> &'static str {
    if f.iter().any(|x| severity_rank(x.severity) <= 1) {
        "risk"
    } else if f.iter().any(|x| x.severity == "medium") {
        "warn"
    } else {
        "ok"
    }
}

fn score_of(f: &[Finding]) -> u32 {
    100u32.saturating_sub(f.iter().map(|x| x.points).sum())
}

fn status_rank(s: &str) -> u8 {
    match s {
        "risk" => 3,
        "warn" => 2,
        "ok" => 1,
        _ => 0,
    }
}

// ---- podSecurity --------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityDim {
    #[serde(flatten)]
    pub env: Envelope,
    #[serde(flatten)]
    pub analysis: Analysis,
}

/// The newest running row per container, else the newest row kept.
fn current_row(c: &ContainerImages) -> Option<(&ContainerDigest, &'static str)> {
    c.digests
        .first()
        .map(|d| (d, "running"))
        .or_else(|| c.previous_digests.first().map(|d| (d, "last_known")))
}

fn build_pod_security(key: &Key, s: &Sources) -> (PodSecurityDim, Vec<Finding>) {
    let mut inputs = Vec::new();
    let mut pod: Option<(NaiveDateTime, PodSecurity)> = None;
    let mut since: Option<NaiveDateTime> = None;
    for c in &s.containers {
        let Some((row, source)) = current_row(c) else {
            continue;
        };
        let sec: ContainerSecurity =
            serde_json::from_value(row.security_context.clone()).unwrap_or_default();
        let ps: PodSecurity = serde_json::from_value(row.pod_security.clone()).unwrap_or_default();
        if pod.as_ref().is_none_or(|(t, _)| row.last_seen > *t) {
            pod = Some((row.last_seen, ps));
        }
        since = Some(since.map_or(row.first_seen, |x: NaiveDateTime| x.min(row.first_seen)));
        inputs.push(pod_security::ContainerInput {
            name: c.container_name.clone(),
            kind: c.container_kind.clone(),
            source,
            digest: row.digest.clone(),
            security: sec,
        });
    }
    let pod = pod.map(|(_, p)| p).unwrap_or_default();
    let analysis = pod_security::analyse(&key.kind, &pod, &inputs);
    let evaluated = pod_security::ALL_CHECKS.len() - pod_security::UNEVALUATED.len();
    let findings: Vec<Finding> = analysis
        .findings
        .iter()
        .map(|f| {
            mk_finding(
                "podSecurity",
                f.id.clone(),
                f.severity,
                f.points,
                f.container.clone(),
                f.title.clone(),
                f.detail.clone(),
            )
        })
        .collect();
    let env = if inputs.is_empty() {
        Envelope {
            status: "unknown",
            score: None,
            scored: false,
            coverage: Coverage {
                level: "none",
                fraction: None,
                observed_since: None,
                note: "no container securityContext reported for this workload".into(),
            },
            reasons: vec![reason(
                "no_inventory",
                "The controller has not reported this workload's containers (image inventory)",
            )],
        }
    } else {
        let score = score_of(&findings);
        let mut reasons = Vec::new();
        match (analysis.level, analysis.level_confidence) {
            (Some(Level::Privileged), _) => reasons.push(reason(
                "pss_privileged",
                "At least one baseline check fails, so the workload is privileged under PSS",
            )),
            (Some(l), Some("upper_bound")) => reasons.push(reason(
                "pss_upper_bound",
                format!(
                    "Evaluated checks pass {}; unevaluated checks may lower the level",
                    l.as_str()
                ),
            )),
            _ => {}
        }
        Envelope {
            status: status_from_score(score),
            score: Some(score),
            scored: true,
            coverage: Coverage {
                level: "partial",
                fraction: Some(evaluated as f64 / pod_security::ALL_CHECKS.len() as f64),
                observed_since: since.map(utc),
                note: format!(
                    "{evaluated} of {} PSS checks evaluated; volumes, ports, probes, AppArmor, SELinux, procMount, sysctls and hostProcess are not ingested",
                    pod_security::ALL_CHECKS.len()
                ),
            },
            reasons,
        }
    };
    (PodSecurityDim { env, analysis }, findings)
}

// ---- images -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DigestView {
    pub digest: String,
    pub image_ref: String,
    pub state: Option<String>,
    pub state_reason: Option<String>,
    pub ran_as_init: bool,
    pub last_pod_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl From<&ContainerDigest> for DigestView {
    fn from(d: &ContainerDigest) -> Self {
        DigestView {
            digest: d.digest.clone(),
            image_ref: d.image_ref.clone(),
            state: d.state.clone(),
            state_reason: d.state_reason.clone(),
            ran_as_init: d.ran_as_init,
            last_pod_name: d.last_pod_name.clone(),
            first_seen: utc(d.first_seen),
            last_seen: utc(d.last_seen),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImageContainerView {
    pub name: String,
    pub kind: String,
    pub mixed_digests: bool,
    pub running: Vec<DigestView>,
    pub previous: Vec<DigestView>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImagesDim {
    #[serde(flatten)]
    pub env: Envelope,
    pub running_window_seconds: i64,
    pub containers: Vec<ImageContainerView>,
    pub truncated: bool,
    /// Always null in v1: no vulnerability source is configured.
    pub vulnerabilities: Option<Value>,
    /// Always null in v1: signatures/provenance are not configured.
    pub supply_chain: Option<Value>,
}

fn build_images(s: &Sources) -> (ImagesDim, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut since: Option<NaiveDateTime> = None;
    let containers: Vec<ImageContainerView> = s
        .containers
        .iter()
        .map(|c| {
            for d in c.digests.iter().chain(c.previous_digests.iter()) {
                since = Some(since.map_or(d.first_seen, |x: NaiveDateTime| x.min(d.first_seen)));
            }
            let n = &c.container_name;
            if c.mixed_digests {
                findings.push(mk_finding(
                    "images",
                    format!("images.mixedDigests/{n}"),
                    "low",
                    0,
                    Some(n.clone()),
                    format!("Container {n} runs {} digests at once", c.digests.len()),
                    "A rollout in progress, or nodes that resolved the same tag to different images.".into(),
                ));
            }
            if c.digests.iter().any(|d| {
                d.state.as_deref() == Some("waiting")
                    && d.state_reason.as_deref() == Some("CrashLoopBackOff")
            }) {
                findings.push(mk_finding(
                    "images",
                    format!("images.crashLoop/{n}"),
                    "medium",
                    0,
                    Some(n.clone()),
                    format!("Container {n} is in CrashLoopBackOff"),
                    "The running digest keeps exiting.".into(),
                ));
            }
            // The newest row overall stuck pulling.
            let newest = c
                .digests
                .iter()
                .chain(c.previous_digests.iter())
                .max_by_key(|d| d.last_seen);
            if newest.is_some_and(|d| {
                d.state.as_deref() == Some("waiting")
                    && matches!(
                        d.state_reason.as_deref(),
                        Some("ImagePullBackOff") | Some("ErrImagePull")
                    )
            }) {
                findings.push(mk_finding(
                    "images",
                    format!("images.pullBackOff/{n}"),
                    "medium",
                    0,
                    Some(n.clone()),
                    format!("Container {n} cannot pull its image"),
                    "The newest reported state is ImagePullBackOff / ErrImagePull.".into(),
                ));
            }
            ImageContainerView {
                name: c.container_name.clone(),
                kind: c.container_kind.clone(),
                mixed_digests: c.mixed_digests,
                running: c.digests.iter().map(DigestView::from).collect(),
                previous: c.previous_digests.iter().map(DigestView::from).collect(),
            }
        })
        .collect();
    let env = if containers.is_empty() {
        Envelope {
            status: "unknown",
            score: None,
            scored: false,
            coverage: Coverage {
                level: "none",
                fraction: None,
                observed_since: None,
                note: "no image inventory for this workload".into(),
            },
            reasons: vec![reason(
                "no_inventory",
                "The controller has not reported this workload's containers (image inventory)",
            )],
        }
    } else {
        Envelope {
            status: status_from_findings(&findings),
            score: None,
            scored: false,
            coverage: Coverage {
                level: "full",
                fraction: None,
                observed_since: since.map(utc),
                note: format!("running window {} s", s.running_window_seconds),
            },
            reasons: vec![reason(
                "vulnerabilities_not_configured",
                "No vulnerability source is configured; images are inventoried but not scored",
            )],
        }
    };
    (
        ImagesDim {
            env,
            running_window_seconds: s.running_window_seconds,
            containers,
            truncated: s.containers_truncated,
            vulnerabilities: None,
            supply_chain: None,
        },
        findings,
    )
}

// ---- syscalls -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObservedView {
    pub syscall_count: usize,
    pub hash: String,
    pub architectures: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureView {
    pub level: String,
    pub complete: bool,
    pub incomplete_pods: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CrView {
    pub name: String,
    pub default_action: String,
    pub mode: &'static str,
    pub syscall_count: usize,
    pub in_sync: bool,
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    pub distribution: DistIn,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DenialView {
    pub total: i64,
    pub syscalls: Vec<String>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyscallsDim {
    #[serde(flatten)]
    pub env: Envelope,
    pub observed: Option<ObservedView>,
    pub capture: Option<CaptureView>,
    pub cr: Option<CrView>,
    pub denials: Option<DenialView>,
}

/// `SCMP_ACT_LOG` / `SCMP_ACT_ALLOW` default actions only log.
pub fn cr_mode(default_action: &str) -> &'static str {
    match default_action {
        "SCMP_ACT_LOG" | "SCMP_ACT_ALLOW" => "audit",
        _ => "enforce",
    }
}

fn build_syscalls(s: &Sources) -> (SyscallsDim, Vec<Finding>) {
    let Some((sum, _names)) = &s.seccomp else {
        return (
            SyscallsDim {
                env: Envelope {
                    status: "unknown",
                    score: None,
                    scored: false,
                    coverage: Coverage {
                        level: "none",
                        fraction: None,
                        observed_since: None,
                        note: "no syscall aggregate for this workload".into(),
                    },
                    reasons: vec![reason(
                        "no_observations",
                        "No syscalls have been captured for this workload",
                    )],
                },
                observed: None,
                capture: None,
                cr: None,
                denials: None,
            },
            Vec::new(),
        );
    };
    let mut findings = Vec::new();
    let mut reasons = Vec::new();
    let cr = sum.cr.as_ref().map(|c| CrView {
        name: c.name.clone(),
        default_action: c.default_action.clone(),
        mode: cr_mode(&c.default_action),
        syscall_count: c.syscall_count,
        in_sync: c.drift.in_sync,
        missing: c.drift.missing.clone(),
        extra: c.drift.extra.clone(),
        distribution: c.distribution.clone(),
    });
    match &cr {
        None => {
            reasons.push(reason(
                "no_cr",
                "No SeccompProfile CR references this workload",
            ));
            findings.push(mk_finding(
                "syscalls",
                "syscalls.no_enforcing_profile".into(),
                "medium",
                40,
                None,
                "No SeccompProfile CR enforces the observed syscall set".into(),
                format!(
                    "Export the observed profile ({} syscalls) and apply it in audit mode first.",
                    sum.syscall_count
                ),
            ));
        }
        Some(c) if c.mode == "audit" => {
            reasons.push(reason(
                "cr_audit",
                format!("SeccompProfile {} only logs ({})", c.name, c.default_action),
            ));
            findings.push(mk_finding(
                "syscalls",
                "syscalls.no_enforcing_profile".into(),
                "medium",
                20,
                None,
                format!("SeccompProfile {} is in audit mode", c.name),
                "Its default action only logs; promote it to enforce once no denials appear."
                    .into(),
            ));
        }
        Some(_) => {}
    }
    if let Some(c) = &cr {
        if !c.in_sync {
            reasons.push(reason(
                "cr_drift",
                "The CR's allowed set differs from what is observed",
            ));
            findings.push(mk_finding(
                "syscalls",
                "syscalls.drift".into(),
                "medium",
                20,
                None,
                format!(
                    "SeccompProfile {} has drifted from observed behaviour",
                    c.name
                ),
                format!(
                    "{} observed syscall(s) not allowed, {} allowed but not observed.",
                    c.missing.len(),
                    c.extra.len()
                ),
            ));
        }
    }
    if let Some(d) = &sum.denials {
        if d.total > 0 {
            findings.push(mk_finding(
                "syscalls",
                "syscalls.denials".into(),
                "high",
                30,
                None,
                format!("{} seccomp denial(s) recorded", d.total),
                format!("Denied: {}", d.syscalls.join(", ")),
            ));
        }
    } else {
        reasons.push(reason(
            "denials_unknown",
            "Denial capture is not reporting for this workload's nodes, so an absence of denials cannot be confirmed",
        ));
    }
    let score = score_of(&findings);
    let mut status = status_from_score(score);
    if !sum.capture.complete {
        reasons.push(reason(
            "capture_incomplete",
            if sum.capture.level == "unknown" {
                "No contributing pod reported a capture tier; the observed set may be missing syscalls".to_string()
            } else {
                format!(
                    "Capture level {} on {} pod(s); the observed set may be missing syscalls",
                    sum.capture.level, sum.capture.incomplete
                )
            },
        ));
        if status == "ok" {
            status = "warn";
        }
    }
    let fraction = None;
    (
        SyscallsDim {
            env: Envelope {
                status,
                score: Some(score),
                scored: true,
                coverage: Coverage {
                    level: if sum.capture.complete {
                        "full"
                    } else {
                        "partial"
                    },
                    fraction,
                    observed_since: None,
                    note: format!("capture level {}", sum.capture.level),
                },
                reasons,
            },
            observed: Some(ObservedView {
                syscall_count: sum.syscall_count,
                hash: sum.hash.clone(),
                architectures: sum.architectures.clone(),
                updated_at: utc(sum.updated_at),
            }),
            capture: Some(CaptureView {
                level: sum.capture.level.clone(),
                complete: sum.capture.complete,
                incomplete_pods: sum.capture.incomplete,
            }),
            cr,
            denials: sum.denials.as_ref().map(|d| DenialView {
                total: d.total,
                syscalls: d.syscalls.clone(),
                last_seen: d.last_seen,
            }),
        },
        findings,
    )
}

// ---- network ------------------------------------------------------------

/// An identity-less peer IP: private / local ranges are in-cluster or
/// on-prem addresses whose identity was not resolved; anything else is
/// external.
pub fn classify_unknown_ip(ip: Option<&str>) -> &'static str {
    let Some(Ok(addr)) = ip.map(|s| s.trim().parse::<std::net::IpAddr>()) else {
        return "unresolved";
    };
    let local = match addr {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || v.to_ipv4_mapped()
                    .is_some_and(|m| m.is_private() || m.is_loopback())
        }
    };
    if local {
        "unresolved"
    } else {
        "external"
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct PeerView {
    pub kind: &'static str,
    pub namespace: Option<String>,
    pub workload_kind: Option<String>,
    pub workload_name: Option<String>,
    pub name: Option<String>,
    pub ip: Option<String>,
}

impl PeerView {
    fn from_row(r: &NetRow) -> PeerView {
        let kind = match r.peer_kind.as_deref() {
            Some("pod") => "pod",
            Some("service") => "service",
            Some("node") => "node",
            Some(_) => "unresolved",
            None => classify_unknown_ip(r.ip.as_deref()),
        };
        PeerView {
            kind,
            namespace: r.peer_namespace.clone(),
            workload_kind: r.peer_workload_kind.clone(),
            workload_name: r.peer_workload_name.clone(),
            name: r.peer_name.clone(),
            ip: r.ip.clone(),
        }
    }

    /// Stable identity used in snapshots and diffs.
    pub fn identity(&self) -> String {
        let ns = self.namespace.as_deref().unwrap_or("");
        match self.kind {
            "pod" => match (&self.workload_kind, &self.workload_name) {
                (Some(k), Some(n)) => format!("pod:{ns}/{k}/{n}"),
                _ => format!("pod:{ns}/{}", self.name.as_deref().unwrap_or("")),
            },
            "service" => format!("service:{ns}/{}", self.name.as_deref().unwrap_or("")),
            "node" => "node".into(),
            k => format!("{k}:{}", self.ip.as_deref().unwrap_or("")),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeerRowView {
    pub direction: &'static str,
    pub protocol: String,
    pub port: Option<u32>,
    pub peer: PeerView,
    pub flows: i64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DirSummary {
    pub peers: usize,
    pub external: usize,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditPolicyRef {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub policies: Vec<AuditPolicyRef>,
    pub allow: i64,
    pub would_deny: i64,
    pub last_verdict_at: DateTime<Utc>,
    pub window_hours: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyView {
    pub audit: Option<AuditView>,
    /// Always null in v1: applied NetworkPolicies are not mirrored.
    pub enforced: Option<Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDim {
    #[serde(flatten)]
    pub env: Envelope,
    pub summary: BTreeMap<&'static str, DirSummary>,
    pub peers: Vec<PeerRowView>,
    pub truncated: bool,
    pub policy: PolicyView,
}

fn direction(dir: &str) -> &'static str {
    if dir == "INGRESS" {
        "ingress"
    } else {
        "egress"
    }
}

fn build_network(s: &Sources) -> (NetworkDim, Vec<Finding>) {
    let peers: Vec<PeerRowView> = s
        .network
        .iter()
        .map(|r| PeerRowView {
            direction: direction(&r.dir),
            protocol: r.proto.clone(),
            port: r.port.as_deref().and_then(|p| p.trim().parse().ok()),
            peer: PeerView::from_row(r),
            flows: r.flows,
            first_seen: utc(r.first_seen),
            last_seen: utc(r.last_seen),
        })
        .collect();
    let mut summary = BTreeMap::new();
    for d in ["ingress", "egress"] {
        let rows: Vec<&PeerRowView> = peers.iter().filter(|p| p.direction == d).collect();
        let ids: BTreeSet<String> = rows.iter().map(|p| p.peer.identity()).collect();
        let ext: BTreeSet<String> = rows
            .iter()
            .filter(|p| p.peer.kind == "external")
            .map(|p| p.peer.identity())
            .collect();
        let ports: BTreeSet<String> = rows
            .iter()
            .filter_map(|p| p.port.map(|n| format!("{}/{n}", p.protocol)))
            .collect();
        summary.insert(
            d,
            DirSummary {
                peers: ids.len(),
                external: ext.len(),
                ports: ports.into_iter().collect(),
            },
        );
    }
    let audit = (!s.audit.is_empty()).then(|| AuditView {
        policies: s
            .audit
            .iter()
            .map(|a| AuditPolicyRef {
                namespace: a.policy_namespace.clone(),
                name: a.policy_name.clone(),
            })
            .collect(),
        allow: s.audit.iter().map(|a| a.allow).sum(),
        would_deny: s.audit.iter().map(|a| a.would_deny).sum(),
        last_verdict_at: utc(s.audit.iter().map(|a| a.last).max().expect("non-empty")),
        window_hours: AUDIT_WINDOW_HOURS,
    });
    let since = s.network.iter().map(|r| r.first_seen).min();
    let mut findings = Vec::new();
    let mut reasons = Vec::new();
    let (status, score, scored) = if peers.is_empty() {
        reasons.push(reason(
            "no_flows",
            "No flows observed for this workload's pods",
        ));
        ("unknown", None, false)
    } else if let Some(a) = &audit {
        if a.would_deny > 0 {
            findings.push(mk_finding(
                "network",
                "network.wouldDeny".into(),
                "high",
                30,
                None,
                format!(
                    "{} flow(s) would be denied by the audit policy in the last {} h",
                    a.would_deny, AUDIT_WINDOW_HOURS
                ),
                "The observed traffic is not covered by the audited NetworkPolicy; review before enforcing.".into(),
            ));
        } else {
            reasons.push(reason(
                "audit_clean",
                format!("Audit policy saw no would-deny in the last {AUDIT_WINDOW_HOURS} h"),
            ));
        }
        let sc = score_of(&findings);
        (status_from_score(sc), Some(sc), true)
    } else {
        reasons.push(reason(
            "policy_state_unknown",
            "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker",
        ));
        ("unknown", None, false)
    };
    if s.network_truncated {
        reasons.push(reason(
            "truncated",
            format!(
                "Flow summary truncated ({} peers / {} flow rows scanned)",
                NETWORK_PEERS_MAX, NETWORK_SCAN_ROWS
            ),
        ));
    }
    (
        NetworkDim {
            env: Envelope {
                status,
                score,
                scored,
                coverage: Coverage {
                    level: if peers.is_empty() {
                        "none"
                    } else if s.network_truncated {
                        "partial"
                    } else {
                        "full"
                    },
                    fraction: None,
                    observed_since: since.map(utc),
                    note: format!(
                        "Flows from {} pod(s) ({} live)",
                        if s.any_pods { "the workload's" } else { "no" },
                        s.live_pods.len()
                    ),
                },
                reasons,
            },
            summary,
            peers,
            truncated: s.network_truncated,
            policy: PolicyView {
                audit,
                enforced: None,
            },
        },
        findings,
    )
}

// ---- compute ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComputeView {
    pub pod: String,
    pub container: String,
    pub cpu_request_millis: Option<i64>,
    pub cpu_limit_millis: Option<i64>,
    pub mem_request_bytes: Option<i64>,
    pub mem_limit_bytes: Option<i64>,
    pub cpu_usage_millis: f64,
    pub mem_working_set_bytes: i64,
    pub oom_kills: i64,
    pub throttled_ratio: f64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComputeDim {
    #[serde(flatten)]
    pub env: Envelope,
    pub containers: Vec<ComputeView>,
    pub truncated: bool,
}

fn build_compute(s: &Sources) -> (ComputeDim, Vec<Finding>) {
    let mut findings = Vec::new();
    let containers: Vec<ComputeView> = s
        .compute
        .iter()
        .map(|r| {
            if r.mem_limit.is_none() {
                findings.push(mk_finding(
                    "compute",
                    format!("compute.missingMemoryLimit/{}", r.container),
                    "low",
                    0,
                    Some(r.container.clone()),
                    format!("Container {} has no memory limit", r.container),
                    format!("Pod {}", r.pod_name),
                ));
            }
            if r.mem_oom_kill > 0 {
                findings.push(mk_finding(
                    "compute",
                    format!("compute.oomKilled/{}", r.container),
                    "medium",
                    0,
                    Some(r.container.clone()),
                    format!("Container {} was OOM-killed", r.container),
                    format!("Pod {}, in the latest sample interval", r.pod_name),
                ));
            }
            ComputeView {
                pod: r.pod_name.clone(),
                container: r.container.clone(),
                cpu_request_millis: r.cpu_request_millis,
                cpu_limit_millis: r.cpu_limit_millis,
                mem_request_bytes: r.mem_request,
                mem_limit_bytes: r.mem_limit,
                cpu_usage_millis: r.cpu_usage_millis,
                mem_working_set_bytes: r.mem_working_set,
                oom_kills: r.mem_oom_kill,
                throttled_ratio: if r.cpu_nr_periods > 0 {
                    r.cpu_nr_throttled as f64 / r.cpu_nr_periods as f64
                } else {
                    0.0
                },
                updated_at: utc(r.updated_at),
            }
        })
        .collect();
    // One finding per id (several pods of a workload share container names).
    let mut seen = BTreeSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    let env = if containers.is_empty() {
        Envelope {
            status: "unknown",
            score: None,
            scored: false,
            coverage: Coverage {
                level: "none",
                fraction: None,
                observed_since: None,
                note: "no compute samples".into(),
            },
            reasons: vec![reason(
                "no_compute_data",
                "No compute samples for this workload's live pods (collection off or no live pods)",
            )],
        }
    } else {
        let missing = findings
            .iter()
            .filter(|f| f.id.starts_with("compute.missingMemoryLimit"))
            .count();
        let mut reasons = Vec::new();
        if missing > 0 {
            reasons.push(reason(
                "missing_limits",
                format!("{missing} container(s) have no memory limit"),
            ));
        }
        Envelope {
            status: status_from_findings(&findings),
            score: None,
            scored: false,
            coverage: Coverage {
                level: "full",
                fraction: None,
                observed_since: s.compute.iter().map(|r| r.updated_at).min().map(utc),
                note: format!("{} container(s) reporting", containers.len()),
            },
            reasons,
        }
    };
    (
        ComputeDim {
            env,
            containers,
            truncated: s.compute_truncated,
        },
        findings,
    )
}

// ---------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Deduction {
    pub dimension: &'static str,
    pub finding_id: String,
    pub points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostureHead {
    pub status: String,
    pub score: Option<u32>,
    pub coverage: f64,
    pub grade: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Posture {
    #[serde(flatten)]
    pub head: PostureHead,
    pub weights: BTreeMap<&'static str, u32>,
    pub unknown_dimensions: Vec<&'static str>,
    pub deductions: Vec<Deduction>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Control {
    pub control: &'static str,
    pub state: Option<&'static str>,
    pub detail: String,
    pub in_sync: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Readiness {
    pub id: &'static str,
    pub ok: Option<bool>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Exposure {
    pub ingress_peers: Option<usize>,
    pub ingress_external: Option<usize>,
    pub egress_peers: Option<usize>,
    pub egress_external: Option<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodsView {
    pub live: usize,
    pub names: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadView {
    pub cluster_id: &'static str,
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub transient: bool,
    pub pods: PodsView,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VersionRef {
    pub revision: i32,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Dimensions {
    pub network: NetworkDim,
    pub syscalls: SyscallsDim,
    pub pod_security: PodSecurityDim,
    pub images: ImagesDim,
    pub compute: ComputeDim,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub workload: WorkloadView,
    pub generated_at: DateTime<Utc>,
    pub content_hash: String,
    pub version: Option<VersionRef>,
    pub snapshot_pending: bool,
    pub posture: Posture,
    pub attention: Vec<Finding>,
    pub findings: Vec<Finding>,
    pub controls: Vec<Control>,
    pub readiness: Vec<Readiness>,
    pub exposure: Exposure,
    pub dimensions: Dimensions,
    #[serde(skip)]
    pub snapshot: Value,
    #[serde(skip)]
    pub dimension_hashes: BTreeMap<&'static str, String>,
}

fn grade(score: u32) -> &'static str {
    match score {
        90.. => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

/// Weighted mean over scored dimensions; coverage = scored weight / total.
pub fn rollup(dims: &[(&'static str, &Envelope)]) -> (PostureHead, Vec<&'static str>) {
    let total: u32 = WEIGHTS.iter().map(|(_, w)| w).sum();
    let mut num = 0f64;
    let mut den = 0u32;
    let mut unknown = Vec::new();
    for (name, w) in WEIGHTS {
        let env = dims.iter().find(|(n, _)| *n == name).map(|(_, e)| *e);
        match env.and_then(|e| e.score.filter(|_| e.scored)) {
            Some(s) => {
                num += (s * w) as f64;
                den += w;
            }
            None => unknown.push(name),
        }
    }
    let score = (den > 0).then(|| (num / den as f64).round() as u32);
    let coverage = ((den as f64 / total as f64) * 100.0).round() / 100.0;
    let worst = dims
        .iter()
        .map(|(_, e)| e.status)
        .max_by_key(|s| status_rank(s))
        .filter(|s| status_rank(s) > 0)
        .unwrap_or("unknown");
    let grade = score
        .filter(|_| den as f64 / total as f64 >= 0.8)
        .map(|s| grade(s).to_string());
    (
        PostureHead {
            status: worst.to_string(),
            score,
            coverage,
            grade,
        },
        unknown,
    )
}

fn fmt_age(secs: i64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    if d > 0 {
        format!("{d}d {h}h")
    } else {
        format!("{h}h {}m", (secs % 3_600) / 60)
    }
}

/// Build the whole profile from its sources. Pure.
pub fn build(key: &Key, s: &Sources, now: DateTime<Utc>) -> Profile {
    let (pod_security, f_ps) = build_pod_security(key, s);
    let (images, f_im) = build_images(s);
    let (syscalls, f_sc) = build_syscalls(s);
    let (network, f_net) = build_network(s);
    let (compute, f_co) = build_compute(s);

    let (head, unknown) = rollup(&[
        ("network", &network.env),
        ("syscalls", &syscalls.env),
        ("podSecurity", &pod_security.env),
        ("images", &images.env),
        ("compute", &compute.env),
    ]);
    let mut findings: Vec<Finding> = f_net
        .into_iter()
        .chain(f_sc)
        .chain(f_ps)
        .chain(f_im)
        .chain(f_co)
        .collect();
    findings.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| b.points.cmp(&a.points))
            .then_with(|| a.id.cmp(&b.id))
    });
    let scored: BTreeSet<&str> = [
        ("network", network.env.scored),
        ("syscalls", syscalls.env.scored),
        ("podSecurity", pod_security.env.scored),
    ]
    .into_iter()
    .filter(|(_, s)| *s)
    .map(|(n, _)| n)
    .collect();
    let deductions: Vec<Deduction> = findings
        .iter()
        .filter(|f| f.points > 0 && scored.contains(f.dimension))
        .map(|f| Deduction {
            dimension: f.dimension,
            finding_id: f.id.clone(),
            points: f.points,
        })
        .collect();
    let attention: Vec<Finding> = findings
        .iter()
        .filter(|f| severity_rank(f.severity) <= 2)
        .take(ATTENTION_MAX)
        .cloned()
        .collect();

    let audit = network.policy.audit.as_ref();
    let controls = vec![
        Control {
            control: "networkPolicy",
            state: Some(if audit.is_some() { "audit" } else { "unknown" }),
            detail: match audit {
                Some(a) => format!(
                    "Audited by {} polic(ies); {} would-deny in the last {} h",
                    a.policies.len(),
                    a.would_deny,
                    a.window_hours
                ),
                None => "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker".into(),
            },
            in_sync: audit.map(|a| a.would_deny == 0),
        },
        Control {
            control: "seccompProfile",
            state: Some(match &syscalls.cr {
                None => "none",
                Some(c) if c.mode == "enforce" => "enforcing",
                Some(_) => "audit",
            }),
            detail: match &syscalls.cr {
                None => "No SeccompProfile CR references this workload".into(),
                Some(c) => format!(
                    "SeccompProfile {} ({}), {} syscalls, distribution {}",
                    c.name, c.default_action, c.syscall_count, c.distribution.state
                ),
            },
            in_sync: syscalls.cr.as_ref().map(|c| c.in_sync),
        },
        Control {
            control: "imageAdmission",
            state: None,
            detail: "Signature/admission checks are not configured".into(),
            in_sync: None,
        },
    ];

    let since = s.network.iter().map(|r| r.first_seen).min();
    let readiness = vec![
        match since {
            Some(t) => {
                let age = (now - utc(t)).num_seconds();
                Readiness {
                    id: "trafficObserved24h",
                    ok: Some(age >= 86_400),
                    message: format!("Traffic observed for {}", fmt_age(age.max(0))),
                }
            }
            None => Readiness {
                id: "trafficObserved24h",
                ok: Some(false),
                message: "No flows observed".into(),
            },
        },
        match &syscalls.capture {
            Some(c) => Readiness {
                id: "syscallCaptureComplete",
                ok: Some(c.complete),
                message: if c.complete {
                    "Every contributing pod captured at level full (startup included)".into()
                } else if c.level == "unknown" {
                    "No contributing pod reported a capture tier".into()
                } else {
                    format!("Capture level {} on {} pod(s)", c.level, c.incomplete_pods)
                },
            },
            None => Readiness {
                id: "syscallCaptureComplete",
                ok: None,
                message: "No syscall capture for this workload".into(),
            },
        },
        match audit {
            Some(a) => Readiness {
                id: "noWouldDeny24h",
                ok: Some(a.would_deny == 0),
                message: format!(
                    "{} would-deny in the last {} h",
                    a.would_deny, a.window_hours
                ),
            },
            None => Readiness {
                id: "noWouldDeny24h",
                ok: None,
                message: "No audit policy covers this workload".into(),
            },
        },
        Readiness {
            id: "imageSigned",
            ok: None,
            message: "Signature verification is not configured".into(),
        },
        match pod_security.analysis.level {
            Some(l) => Readiness {
                id: "podSecurityRestricted",
                ok: Some(l == Level::Restricted),
                message: if l == Level::Restricted {
                    format!(
                        "Evaluated checks pass restricted; {} checks could not be evaluated",
                        pod_security::UNEVALUATED.len()
                    )
                } else {
                    format!("At most {}", l.as_str())
                },
            },
            None => Readiness {
                id: "podSecurityRestricted",
                ok: None,
                message: "No container securityContext reported".into(),
            },
        },
    ];

    let has_flows = !network.peers.is_empty();
    let pick = |d: &str, ext: bool| -> Option<usize> {
        has_flows.then(|| {
            network
                .summary
                .get(d)
                .map(|x| if ext { x.external } else { x.peers })
                .unwrap_or(0)
        })
    };
    let exposure = Exposure {
        ingress_peers: pick("ingress", false),
        ingress_external: pick("ingress", true),
        egress_peers: pick("egress", false),
        egress_external: pick("egress", true),
    };

    let dims = Dimensions {
        network,
        syscalls,
        pod_security,
        images,
        compute,
    };
    let (snapshot, dimension_hashes, content_hash) = snapshot_of(&dims, s);
    let version = s.stored.as_ref().map(|v| VersionRef {
        revision: v.revision,
        content_hash: v.content_hash.clone(),
        created_at: utc(v.created_at),
    });
    let snapshot_pending = version
        .as_ref()
        .is_none_or(|v| v.content_hash != content_hash);
    let names: Vec<String> = s.live_pods.iter().take(POD_NAMES_LISTED).cloned().collect();
    Profile {
        workload: WorkloadView {
            cluster_id: DEFAULT_CLUSTER_ID,
            namespace: key.namespace.clone(),
            kind: key.kind.clone(),
            name: key.name.clone(),
            transient: key.kind == "Pod",
            pods: PodsView {
                live: s.live_pods.len(),
                truncated: s.live_pods.len() > names.len(),
                names,
            },
        },
        generated_at: now,
        content_hash,
        version,
        snapshot_pending,
        posture: Posture {
            head,
            weights: WEIGHTS.into_iter().collect(),
            unknown_dimensions: unknown,
            deductions,
        },
        attention,
        findings,
        controls,
        readiness,
        exposure,
        dimensions: dims,
        snapshot,
        dimension_hashes,
    }
}

// ---------------------------------------------------------------------
// Snapshot, hash, diff
// ---------------------------------------------------------------------

/// Canonical JSON: object keys sorted at every level.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            out.push('{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// `fnv1a64:<16 hex>` over the canonical JSON. A change detector, not a
/// security primitive (same reasoning as seccomp.rs `fingerprint`).
pub fn content_hash(v: &Value) -> String {
    let mut s = String::new();
    canonical(v, &mut s);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{h:016x}")
}

pub const SNAPSHOT_DIMENSIONS: [&str; 4] = ["network", "syscalls", "podSecurity", "images"];

fn snapshot_of(d: &Dimensions, s: &Sources) -> (Value, BTreeMap<&'static str, String>, String) {
    let ps = &d.pod_security.analysis;
    let mut containers = serde_json::Map::new();
    for c in &ps.containers {
        containers.insert(
            c.name.clone(),
            json!({ "kind": c.kind, "securityContext": c.security_context }),
        );
    }
    let mut pod = serde_json::to_value(&ps.pod).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut pod {
        m.remove("failing");
    }
    let pod_security = json!({
        "level": ps.level,
        "pod": if ps.containers.is_empty() { Value::Null } else { pod },
        "containers": containers,
    });

    let mut images = serde_json::Map::new();
    for c in &d.images.containers {
        let digests: BTreeSet<&str> = c.running.iter().map(|x| x.digest.as_str()).collect();
        images.insert(c.name.clone(), json!(digests));
    }
    let images = json!({ "containers": images });

    let syscalls = match &s.seccomp {
        Some((sum, names)) => json!({
            "syscalls": names,
            "captureLevel": sum.capture.level,
            "cr": sum.cr.as_ref().map(|c| json!({
                "name": c.name, "defaultAction": c.default_action, "hash": c.hash
            })),
        }),
        None => json!({ "syscalls": Value::Null, "captureLevel": Value::Null, "cr": Value::Null }),
    };

    let rules: BTreeSet<(String, String, Option<u32>, String)> = d
        .network
        .peers
        .iter()
        .map(|p| {
            (
                p.direction.to_string(),
                p.protocol.clone(),
                p.port,
                p.peer.identity(),
            )
        })
        .collect();
    let network = json!({
        "rules": rules.into_iter().map(|(dir, proto, port, peer)| json!({
            "direction": dir, "protocol": proto, "port": port, "peer": peer
        })).collect::<Vec<_>>(),
        "audited": d.network.policy.audit.is_some(),
        "truncated": d.network.truncated,
    });

    let snap = json!({
        "podSecurity": pod_security,
        "images": images,
        "syscalls": syscalls,
        "network": network,
    });
    let mut hashes = BTreeMap::new();
    for dim in SNAPSHOT_DIMENSIONS {
        hashes.insert(dim, content_hash(&snap[dim]));
    }
    let h = content_hash(&snap);
    (snap, hashes, h)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FieldChange {
    pub field: String,
    pub from: Value,
    pub to: Value,
}

fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&p, x, out);
            }
        }
        other => {
            out.insert(prefix.to_string(), other.clone());
        }
    }
}

fn field_changes(a: &Value, b: &Value) -> Vec<FieldChange> {
    let (mut fa, mut fb) = (BTreeMap::new(), BTreeMap::new());
    flatten("", a, &mut fa);
    flatten("", b, &mut fb);
    let keys: BTreeSet<&String> = fa.keys().chain(fb.keys()).collect();
    keys.into_iter()
        .filter_map(|k| {
            let x = fa.get(k).cloned().unwrap_or(Value::Null);
            let y = fb.get(k).cloned().unwrap_or(Value::Null);
            (x != y).then(|| FieldChange {
                field: k.clone(),
                from: x,
                to: y,
            })
        })
        .collect()
}

fn scalar_change(a: &Value, b: &Value) -> Value {
    if a == b {
        Value::Null
    } else {
        json!({ "from": a, "to": b })
    }
}

fn obj(v: &Value, k: &str) -> serde_json::Map<String, Value> {
    v.get(k)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn str_set(v: Option<&Value>) -> BTreeSet<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Structured diff of two stored snapshots (contract section 3.3). `from`
/// may be `Value::Null` (diffing against nothing).
pub fn diff(from: &Value, to: &Value) -> Value {
    let get = |v: &Value, d: &str| v.get(d).cloned().unwrap_or(Value::Null);

    // podSecurity
    let (pa, pb) = (get(from, "podSecurity"), get(to, "podSecurity"));
    let (ca, cb) = (obj(&pa, "containers"), obj(&pb, "containers"));
    let names_a: BTreeSet<&String> = ca.keys().collect();
    let names_b: BTreeSet<&String> = cb.keys().collect();
    let containers: Vec<Value> = names_a
        .intersection(&names_b)
        .filter_map(|n| {
            let f = field_changes(&ca[*n], &cb[*n]);
            (!f.is_empty()).then(|| json!({ "name": n, "fields": f }))
        })
        .collect();
    let pod_fields = field_changes(&get(&pa, "pod"), &get(&pb, "pod"));
    let ps = json!({
        "changed": pa != pb,
        "level": scalar_change(&get(&pa, "level"), &get(&pb, "level")),
        "pod": pod_fields,
        "containersAdded": names_b.difference(&names_a).collect::<Vec<_>>(),
        "containersRemoved": names_a.difference(&names_b).collect::<Vec<_>>(),
        "containers": containers,
    });

    // images
    let (ia, ib) = (get(from, "images"), get(to, "images"));
    let (ma, mb) = (obj(&ia, "containers"), obj(&ib, "containers"));
    let ka: BTreeSet<&String> = ma.keys().collect();
    let kb: BTreeSet<&String> = mb.keys().collect();
    let im_containers: Vec<Value> = ka
        .intersection(&kb)
        .filter_map(|n| {
            let (a, b) = (str_set(ma.get(*n)), str_set(mb.get(*n)));
            (a != b).then(|| {
                json!({
                    "name": n,
                    "added": b.difference(&a).collect::<Vec<_>>(),
                    "removed": a.difference(&b).collect::<Vec<_>>(),
                })
            })
        })
        .collect();
    let im = json!({
        "changed": ia != ib,
        "containersAdded": kb.difference(&ka).collect::<Vec<_>>(),
        "containersRemoved": ka.difference(&kb).collect::<Vec<_>>(),
        "containers": im_containers,
    });

    // syscalls
    let (sa, sb) = (get(from, "syscalls"), get(to, "syscalls"));
    let (na, nb) = (str_set(sa.get("syscalls")), str_set(sb.get("syscalls")));
    let sc = json!({
        "changed": sa != sb,
        "added": nb.difference(&na).collect::<Vec<_>>(),
        "removed": na.difference(&nb).collect::<Vec<_>>(),
        "captureLevel": scalar_change(&get(&sa, "captureLevel"), &get(&sb, "captureLevel")),
        "cr": scalar_change(&get(&sa, "cr"), &get(&sb, "cr")),
    });

    // network
    let (xa, xb) = (get(from, "network"), get(to, "network"));
    let rules = |v: &Value| -> BTreeMap<String, Value> {
        v.get("rules")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|r| {
                        let mut k = String::new();
                        canonical(r, &mut k);
                        (k, r.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let (ra, rb) = (rules(&xa), rules(&xb));
    let net = json!({
        "changed": xa != xb,
        "added": rb.iter().filter(|(k, _)| !ra.contains_key(*k)).map(|(_, v)| v).collect::<Vec<_>>(),
        "removed": ra.iter().filter(|(k, _)| !rb.contains_key(*k)).map(|(_, v)| v).collect::<Vec<_>>(),
        "audited": scalar_change(&get(&xa, "audited"), &get(&xb, "audited")),
    });

    json!({
        "podSecurity": ps,
        "images": im,
        "syscalls": sc,
        "network": net,
    })
}

// ---------------------------------------------------------------------
// Persistence: latest + versions
// ---------------------------------------------------------------------

/// The `GET /workloads` list item body stored in `workload_profile_latest.summary`.
fn list_summary(p: &Profile) -> Value {
    let d = &p.dimensions;
    let mut counts = BTreeMap::from([
        ("critical", 0u32),
        ("high", 0),
        ("medium", 0),
        ("low", 0),
        ("info", 0),
    ]);
    for f in &p.findings {
        *counts.entry(f.severity).or_insert(0) += 1;
    }
    let running: BTreeSet<&str> = d
        .images
        .containers
        .iter()
        .flat_map(|c| c.running.iter().map(|x| x.digest.as_str()))
        .collect();
    json!({
        "posture": {
            "status": p.posture.head.status,
            "score": p.posture.head.score,
            "coverage": p.posture.head.coverage,
            "grade": p.posture.head.grade,
            "unknownDimensions": p.posture.unknown_dimensions,
        },
        "dimensions": {
            "network": { "status": d.network.env.status, "score": d.network.env.score },
            "syscalls": { "status": d.syscalls.env.status, "score": d.syscalls.env.score },
            "podSecurity": {
                "status": d.pod_security.env.status,
                "score": d.pod_security.env.score,
                "level": d.pod_security.analysis.level,
                "levelConfidence": d.pod_security.analysis.level_confidence,
            },
            "images": {
                "status": d.images.env.status,
                "score": d.images.env.score,
                "runningDigests": if d.images.containers.is_empty() { Value::Null } else { json!(running.len()) },
                "mixedDigests": if d.images.containers.is_empty() { Value::Null } else { json!(d.images.containers.iter().any(|c| c.mixed_digests)) },
            },
            "compute": { "status": d.compute.env.status, "score": d.compute.env.score },
        },
        "findingCounts": counts,
    })
}

/// Outcome of one snapshot write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotOutcome {
    Unchanged(i32),
    NewVersion(i32),
}

/// Store `p` for `key`: a new version only when the hash changed, trim
/// beyond `cap`, and refresh `workload_profile_latest`. One transaction.
pub fn store_snapshot(
    conn: &mut PgConnection,
    key: &Key,
    p: &Profile,
    cap: i64,
) -> Result<SnapshotOutcome, DbError> {
    conn.transaction::<_, DbError, _>(|conn| {
        let head: Option<StoredVersionHead> = sql_query(LATEST_VERSION_SQL)
            .bind::<Text, _>(DEFAULT_CLUSTER_ID)
            .bind::<Text, _>(&key.namespace)
            .bind::<Text, _>(&key.kind)
            .bind::<Text, _>(&key.name)
            .get_result(conn)
            .optional()?;
        let changed = head
            .as_ref()
            .is_none_or(|h| h.content_hash != p.content_hash);
        let revision = match head.as_ref().filter(|_| !changed) {
            Some(h) => h.revision,
            None => {
                let h = &head;
                let rev = h.as_ref().map_or(1, |h| h.revision + 1);
                let posture = serde_json::to_value(&p.posture.head)?;
                sql_query(
                    "INSERT INTO workload_profile_versions \
                     (cluster_id, pod_namespace, workload_kind, workload_name, revision, \
                      content_hash, dimension_hashes, snapshot, posture) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                     ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name, revision) DO NOTHING",
                )
                .bind::<Text, _>(DEFAULT_CLUSTER_ID)
                .bind::<Text, _>(&key.namespace)
                .bind::<Text, _>(&key.kind)
                .bind::<Text, _>(&key.name)
                .bind::<Integer, _>(rev)
                .bind::<Text, _>(&p.content_hash)
                .bind::<Jsonb, _>(serde_json::to_value(&p.dimension_hashes)?)
                .bind::<Jsonb, _>(&p.snapshot)
                .bind::<Jsonb, _>(posture)
                .execute(conn)?;
                sql_query(
                    "DELETE FROM workload_profile_versions \
                     WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 \
                       AND workload_name = $4 AND revision <= $5",
                )
                .bind::<Text, _>(DEFAULT_CLUSTER_ID)
                .bind::<Text, _>(&key.namespace)
                .bind::<Text, _>(&key.kind)
                .bind::<Text, _>(&key.name)
                .bind::<BigInt, _>(rev as i64 - cap)
                .execute(conn)?;
                rev
            }
        };
        sql_query(
            "INSERT INTO workload_profile_latest \
             (cluster_id, pod_namespace, workload_kind, workload_name, revision, content_hash, \
              posture_status, summary, computed_at, last_changed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, timezone('UTC', NOW()), timezone('UTC', NOW())) \
             ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name) DO UPDATE SET \
               revision = EXCLUDED.revision, content_hash = EXCLUDED.content_hash, \
               posture_status = EXCLUDED.posture_status, summary = EXCLUDED.summary, \
               computed_at = EXCLUDED.computed_at, \
               last_changed_at = CASE WHEN workload_profile_latest.content_hash = EXCLUDED.content_hash \
                                      THEN workload_profile_latest.last_changed_at \
                                      ELSE EXCLUDED.last_changed_at END",
        )
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<Integer, _>(revision)
        .bind::<Text, _>(&p.content_hash)
        .bind::<Text, _>(&p.posture.head.status)
        .bind::<Jsonb, _>(list_summary(p))
        .execute(conn)?;
        Ok(if changed {
            SnapshotOutcome::NewVersion(revision)
        } else {
            SnapshotOutcome::Unchanged(revision)
        })
    })
}

#[derive(Debug, Clone, QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = Text)]
    ns: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    name: String,
}

/// Workloads with any source data, least recently computed first.
const CANDIDATES_SQL: &str = "\
SELECT k.ns, k.kind, k.name FROM ( \
    SELECT pod_namespace AS ns, workload_kind AS kind, workload_name AS name FROM workload_containers \
    UNION SELECT pod_namespace, workload_kind, workload_name FROM workload_syscalls \
    UNION SELECT pod_namespace, workload_kind, workload_name FROM pod_details \
          WHERE NOT is_dead AND pod_namespace IS NOT NULL AND workload_kind IS NOT NULL AND workload_name IS NOT NULL \
) k \
LEFT JOIN workload_profile_latest l ON l.cluster_id = $1 AND l.pod_namespace = k.ns \
     AND l.workload_kind = k.kind AND l.workload_name = k.name \
ORDER BY l.computed_at ASC NULLS FIRST, k.ns, k.kind, k.name \
LIMIT $2";

/// Compute and store one workload's profile.
pub fn snapshot_one(
    conn: &mut PgConnection,
    key: &Key,
    cap: i64,
) -> Result<Option<SnapshotOutcome>, DbError> {
    let sources = load_sources(conn, key)?;
    if sources.is_empty() {
        return Ok(None);
    }
    let p = build(key, &sources, Utc::now());
    store_snapshot(conn, key, &p, cap).map(Some)
}

/// One snapshotter tick. Sequential: one workload's reads at a time.
pub fn snapshot_tick(
    conn: &mut PgConnection,
    batch: i64,
    cap: i64,
) -> Result<(usize, usize), DbError> {
    let keys: Vec<KeyRow> = sql_query(CANDIDATES_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<BigInt, _>(batch)
        .load(conn)?;
    let (mut done, mut new) = (0, 0);
    for k in keys {
        let key = Key {
            namespace: k.ns,
            kind: k.kind,
            name: k.name,
        };
        match snapshot_one(conn, &key, cap) {
            Ok(Some(SnapshotOutcome::NewVersion(_))) => {
                done += 1;
                new += 1;
            }
            Ok(_) => done += 1,
            Err(e) => {
                warn!(namespace = %key.namespace, kind = %key.kind, name = %key.name, error = %e,
                "workload profile snapshot failed")
            }
        }
    }
    Ok((done, new))
}

/// Spawn the snapshotter loop.
pub fn spawn(pool: DbPool) {
    let interval = snapshot_interval();
    let batch = snapshot_batch();
    let cap = max_versions_per_workload();
    info!(
        interval_secs = interval.as_secs(),
        batch, cap, "workload profile snapshotter scheduled"
    );
    actix_web::rt::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let pool = pool.clone();
            let r = tokio::task::spawn_blocking(move || -> Result<(usize, usize), DbError> {
                let mut conn = pool.get()?;
                snapshot_tick(&mut conn, batch, cap)
            })
            .await;
            match r {
                Ok(Ok((done, new))) => {
                    if new > 0 {
                        info!(
                            computed = done,
                            new_versions = new,
                            "workload profiles snapshotted"
                        );
                    } else {
                        debug!(computed = done, "workload profiles snapshotted; no changes");
                    }
                }
                Ok(Err(e)) => warn!(error = %e, "workload profile snapshotter tick failed"),
                Err(e) => warn!(error = %e, "workload profile snapshotter task panicked"),
            }
            tokio::time::sleep(interval).await;
        }
    });
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub namespace: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, QueryableByName)]
struct LatestRow {
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Text)]
    pod_namespace: String,
    #[diesel(sql_type = Text)]
    workload_kind: String,
    #[diesel(sql_type = Text)]
    workload_name: String,
    #[diesel(sql_type = Integer)]
    revision: i32,
    #[diesel(sql_type = Text)]
    content_hash: String,
    #[diesel(sql_type = Jsonb)]
    summary: Value,
    #[diesel(sql_type = Timestamp)]
    computed_at: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    last_changed_at: NaiveDateTime,
}

const LIST_SQL: &str = "\
SELECT cluster_id, pod_namespace, workload_kind, workload_name, revision, content_hash, summary, \
       computed_at, last_changed_at \
FROM workload_profile_latest \
WHERE cluster_id = $1 \
  AND ($2::text IS NULL OR pod_namespace = $2) \
  AND ($3::text IS NULL OR workload_kind = $3) \
  AND ($4::text IS NULL OR posture_status = $4) \
  AND ($5::text IS NULL OR (pod_namespace, workload_kind, workload_name) > ($5, $6, $7)) \
ORDER BY pod_namespace, workload_kind, workload_name \
LIMIT $8";

fn empty_to_none(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Parse `after` (`ns/kind/name`).
fn parse_after(s: &str) -> Option<(String, String, String)> {
    let mut it = s.splitn(3, '/');
    let (a, b, c) = (it.next()?, it.next()?, it.next()?);
    ([a, b, c].iter().all(|x| valid_segment(x))).then(|| (a.into(), b.into(), c.into()))
}

pub fn list_workloads(
    conn: &mut PgConnection,
    namespace: Option<&str>,
    kind: Option<&str>,
    status: Option<&str>,
    after: Option<&(String, String, String)>,
    limit: i64,
) -> Result<Value, DbError> {
    let mut rows: Vec<LatestRow> = sql_query(LIST_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Nullable<Text>, _>(namespace)
        .bind::<Nullable<Text>, _>(kind)
        .bind::<Nullable<Text>, _>(status)
        .bind::<Nullable<Text>, _>(after.map(|a| a.0.as_str()))
        .bind::<Nullable<Text>, _>(after.map(|a| a.1.as_str()))
        .bind::<Nullable<Text>, _>(after.map(|a| a.2.as_str()))
        .bind::<BigInt, _>(limit + 1)
        .load(conn)?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next_after = more.then(|| {
        rows.last().map(|r| {
            format!(
                "{}/{}/{}",
                r.pod_namespace, r.workload_kind, r.workload_name
            )
        })
    });
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let mut item = json!({
                "clusterId": r.cluster_id,
                "namespace": r.pod_namespace,
                "kind": r.workload_kind,
                "name": r.workload_name,
                "revision": r.revision,
                "contentHash": r.content_hash,
                "computedAt": utc(r.computed_at),
                "lastChangedAt": utc(r.last_changed_at),
            });
            if let (Value::Object(m), Value::Object(s)) = (&mut item, r.summary) {
                m.extend(s);
            }
            item
        })
        .collect();
    Ok(json!({ "items": items, "nextAfter": next_after.flatten() }))
}

#[get(
    "/workloads",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workloads(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ListQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let limit = q
        .limit
        .unwrap_or(LIST_DEFAULT_LIMIT)
        .clamp(1, LIST_MAX_LIMIT);
    let status = empty_to_none(q.status);
    if let Some(s) = status.as_deref() {
        if !["ok", "warn", "risk", "unknown"].contains(&s) {
            return Ok(error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "status must be ok, warn, risk or unknown",
            ));
        }
    }
    let after = match empty_to_none(q.after) {
        None => None,
        Some(a) => match parse_after(&a) {
            Some(t) => Some(t),
            None => {
                return Ok(error(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "after must be the nextAfter value of a previous page",
                ))
            }
        },
    };
    let namespace = empty_to_none(q.namespace);
    let kind = empty_to_none(q.kind);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, LIST_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        list_workloads(
            &mut conn,
            namespace.as_deref(),
            kind.as_deref(),
            status.as_deref(),
            after.as_ref(),
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(page))
}

#[get(
    "/workloads/{namespace}/{kind}/{name}/profile",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_profile(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    let Some(key) = Key::parse(ns, kind, name) else {
        return Ok(bad_key());
    };
    let _permit = match budget.acquire(profile_charge_kib()).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || -> Result<Option<Profile>, DbError> {
        let mut conn = pool.get()?;
        let s = load_sources(&mut conn, &key)?;
        if s.is_empty() {
            return Ok(None);
        }
        Ok(Some(build(&key, &s, Utc::now())))
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match out {
        Some(p) => HttpResponse::Ok().json(p),
        None => not_found_workload(),
    })
}

#[derive(Debug, Deserialize)]
pub struct VersionsQuery {
    pub limit: Option<i64>,
    pub before: Option<i32>,
}

#[derive(Debug, Clone, QueryableByName)]
struct VersionRow {
    #[diesel(sql_type = Integer)]
    revision: i32,
    #[diesel(sql_type = Text)]
    content_hash: String,
    #[diesel(sql_type = Timestamp)]
    created_at: NaiveDateTime,
    #[diesel(sql_type = Jsonb)]
    dimension_hashes: Value,
    #[diesel(sql_type = Jsonb)]
    posture: Value,
}

const VERSIONS_SQL: &str = "\
SELECT revision, content_hash, created_at, dimension_hashes, posture \
FROM workload_profile_versions \
WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
  AND ($5::int IS NULL OR revision < $5) \
ORDER BY revision DESC LIMIT $6";

fn workload_known(conn: &mut PgConnection, key: &Key) -> Result<bool, DbError> {
    #[derive(QueryableByName)]
    struct B {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        b: bool,
    }
    let r: B = sql_query(
        "SELECT (EXISTS (SELECT 1 FROM workload_containers WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3) \
              OR EXISTS (SELECT 1 FROM workload_syscalls WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3) \
              OR EXISTS (SELECT 1 FROM pod_details WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3) \
              OR EXISTS (SELECT 1 FROM workload_profile_latest WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3)) AS b",
    )
    .bind::<Text, _>(&key.namespace)
    .bind::<Text, _>(&key.kind)
    .bind::<Text, _>(&key.name)
    .get_result(conn)?;
    Ok(r.b)
}

/// Versions page. `None` = workload unknown.
pub fn list_versions(
    conn: &mut PgConnection,
    key: &Key,
    before: Option<i32>,
    limit: i64,
) -> Result<Option<Value>, DbError> {
    let rows: Vec<VersionRow> = sql_query(VERSIONS_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<Nullable<Integer>, _>(before)
        .bind::<BigInt, _>(limit + 1)
        .load(conn)?;
    if rows.is_empty() && before.is_none() && !workload_known(conn, key)? {
        return Ok(None);
    }
    let more = rows.len() as i64 > limit;
    let shown = rows.len().min(limit as usize);
    let items: Vec<Value> = (0..shown)
        .map(|i| {
            let r = &rows[i];
            // The predecessor is the next row (older); revision 1 changed
            // everything; an older retained row with no predecessor
            // available is unknown (null).
            let changed: Value = match rows.get(i + 1) {
                Some(prev) if prev.revision == r.revision - 1 => {
                    json!(SNAPSHOT_DIMENSIONS
                        .iter()
                        .filter(|d| r.dimension_hashes.get(**d) != prev.dimension_hashes.get(**d))
                        .collect::<Vec<_>>())
                }
                _ if r.revision == 1 => json!(SNAPSHOT_DIMENSIONS),
                _ => Value::Null,
            };
            json!({
                "revision": r.revision,
                "contentHash": r.content_hash,
                "createdAt": utc(r.created_at),
                "dimensionHashes": r.dimension_hashes,
                "changedDimensions": changed,
                "posture": r.posture,
            })
        })
        .collect();
    let next_before = more.then(|| rows[shown - 1].revision);
    Ok(Some(json!({
        "namespace": key.namespace,
        "kind": key.kind,
        "name": key.name,
        "items": items,
        "nextBefore": next_before,
    })))
}

#[get(
    "/workloads/{namespace}/{kind}/{name}/profile/versions",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_profile_versions(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
    query: web::Query<VersionsQuery>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    let Some(key) = Key::parse(ns, kind, name) else {
        return Ok(bad_key());
    };
    let q = query.into_inner();
    let limit = q
        .limit
        .unwrap_or(VERSIONS_DEFAULT_LIMIT)
        .clamp(1, VERSIONS_MAX_LIMIT);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, VERSION_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || {
        let mut conn = pool.get()?;
        list_versions(&mut conn, &key, q.before, limit)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match out {
        Some(v) => HttpResponse::Ok().json(v),
        None => not_found_workload(),
    })
}

#[derive(Debug, Clone, QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type = Integer)]
    revision: i32,
    #[diesel(sql_type = Text)]
    content_hash: String,
    #[diesel(sql_type = Timestamp)]
    created_at: NaiveDateTime,
    #[diesel(sql_type = Jsonb)]
    dimension_hashes: Value,
    #[diesel(sql_type = Jsonb)]
    posture: Value,
    #[diesel(sql_type = Jsonb)]
    snapshot: Value,
}

/// `revision = None` = the latest.
fn load_snapshot(
    conn: &mut PgConnection,
    key: &Key,
    revision: Option<i32>,
) -> Result<Option<SnapshotRow>, DbError> {
    Ok(sql_query(
        "SELECT revision, content_hash, created_at, dimension_hashes, posture, snapshot \
         FROM workload_profile_versions \
         WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
           AND ($5::int IS NULL OR revision = $5) \
         ORDER BY revision DESC LIMIT 1",
    )
    .bind::<Text, _>(DEFAULT_CLUSTER_ID)
    .bind::<Text, _>(&key.namespace)
    .bind::<Text, _>(&key.kind)
    .bind::<Text, _>(&key.name)
    .bind::<Nullable<Integer>, _>(revision)
    .get_result(conn)
    .optional()?)
}

fn revision_not_found() -> HttpResponse {
    error(
        StatusCode::NOT_FOUND,
        "revision_not_found",
        "no stored profile version with that revision",
    )
}

#[get(
    "/workloads/{namespace}/{kind}/{name}/profile/versions/{revision}",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_profile_version(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name, rev) = path.into_inner();
    let Some(key) = Key::parse(ns, kind, name) else {
        return Ok(bad_key());
    };
    let Ok(rev) = rev.trim().parse::<i32>() else {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "revision must be an integer",
        ));
    };
    let _permit = match budget.acquire(cost_kib(1, SNAPSHOT_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let k2 = key.clone();
    let row = web::block(move || {
        let mut conn = pool.get()?;
        load_snapshot(&mut conn, &k2, Some(rev))
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match row {
        None => revision_not_found(),
        Some(r) => HttpResponse::Ok().json(json!({
            "namespace": key.namespace,
            "kind": key.kind,
            "name": key.name,
            "revision": r.revision,
            "contentHash": r.content_hash,
            "createdAt": utc(r.created_at),
            "dimensionHashes": r.dimension_hashes,
            "posture": r.posture,
            "snapshot": r.snapshot,
        })),
    })
}

#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub from: Option<String>,
    pub to: Option<String>,
}

fn parse_rev(s: Option<String>) -> Result<Option<i32>, ()> {
    match empty_to_none(s) {
        None => Ok(None),
        Some(v) => v.parse::<i32>().map(Some).map_err(|_| ()),
    }
}

/// Diff outcome for the handler.
pub enum DiffResult {
    Ok(Value),
    NoVersions,
    RevisionMissing,
    BadOrder,
}

pub fn diff_versions(
    conn: &mut PgConnection,
    key: &Key,
    from: Option<i32>,
    to: Option<i32>,
) -> Result<DiffResult, DbError> {
    let Some(to_row) = load_snapshot(conn, key, to)? else {
        return Ok(
            if to.is_some() && load_snapshot(conn, key, None)?.is_some() {
                DiffResult::RevisionMissing
            } else {
                DiffResult::NoVersions
            },
        );
    };
    let from_rev = match from {
        Some(f) => Some(f),
        None if to_row.revision > 1 => Some(to_row.revision - 1),
        None => None,
    };
    if from_rev.is_some_and(|f| f >= to_row.revision) {
        return Ok(DiffResult::BadOrder);
    }
    let from_row = match from_rev {
        Some(f) => match load_snapshot(conn, key, Some(f))? {
            Some(r) => Some(r),
            None => return Ok(DiffResult::RevisionMissing),
        },
        None => None,
    };
    let from_snap = from_row
        .as_ref()
        .map_or(Value::Null, |r| r.snapshot.clone());
    let mut dims = diff(&from_snap, &to_row.snapshot);
    // `changed` per dimension is the stored hash comparison.
    if let Value::Object(m) = &mut dims {
        for d in SNAPSHOT_DIMENSIONS {
            let changed = from_row
                .as_ref()
                .is_none_or(|f| f.dimension_hashes.get(d) != to_row.dimension_hashes.get(d));
            if let Some(Value::Object(x)) = m.get_mut(d) {
                x.insert("changed".into(), json!(changed));
            }
        }
    }
    let r = |x: &SnapshotRow| json!({ "revision": x.revision, "contentHash": x.content_hash, "createdAt": utc(x.created_at) });
    Ok(DiffResult::Ok(json!({
        "namespace": key.namespace,
        "kind": key.kind,
        "name": key.name,
        "from": from_row.as_ref().map(r),
        "to": r(&to_row),
        "changed": from_row.as_ref().is_none_or(|f| f.content_hash != to_row.content_hash),
        "dimensions": dims,
    })))
}

#[get(
    "/workloads/{namespace}/{kind}/{name}/profile/diff",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_profile_diff(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
    query: web::Query<DiffQuery>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    let Some(key) = Key::parse(ns, kind, name) else {
        return Ok(bad_key());
    };
    let q = query.into_inner();
    let (Ok(from), Ok(to)) = (parse_rev(q.from), parse_rev(q.to)) else {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "from and to must be integer revisions",
        ));
    };
    // Up to four snapshot reads (to, latest-probe, from) plus the diff.
    let _permit = match budget.acquire(cost_kib(4, SNAPSHOT_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || {
        let mut conn = pool.get()?;
        diff_versions(&mut conn, &key, from, to)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match out {
        DiffResult::Ok(v) => HttpResponse::Ok().json(v),
        DiffResult::NoVersions => not_found_workload(),
        DiffResult::RevisionMissing => revision_not_found(),
        DiffResult::BadOrder => error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "from must be lower than to",
        ),
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn ts(h: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 9, 20)
            .unwrap()
            .and_hms_opt(h, 0, 0)
            .unwrap()
    }

    fn key() -> Key {
        Key {
            namespace: "payments".into(),
            kind: "Deployment".into(),
            name: "checkout".into(),
        }
    }

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    fn cd(d: &str, sc: Value, ps: Value) -> ContainerDigest {
        ContainerDigest {
            digest: d.into(),
            image_ref: "ghcr.io/example/checkout:1".into(),
            security_context: sc,
            pod_security: ps,
            last_pod_name: Some("checkout-1".into()),
            first_seen: ts(1),
            last_seen: ts(2),
            state: Some("running".into()),
            state_reason: None,
            ran_as_init: false,
        }
    }

    fn container(name: &str, sc: Value) -> ContainerImages {
        ContainerImages {
            cluster_id: "primary".into(),
            container_name: name.into(),
            container_kind: "regular".into(),
            mixed_digests: false,
            digests: vec![cd(
                &digest('a'),
                sc,
                json!({"automountServiceAccountToken": false}),
            )],
            previous_digests: vec![],
        }
    }

    fn restricted() -> Value {
        json!({
            "allowPrivilegeEscalation": false, "runAsNonRoot": true,
            "capabilitiesDrop": ["ALL"], "seccompProfileType": "RuntimeDefault",
            "readOnlyRootFilesystem": true
        })
    }

    fn net(dir: &str, port: &str, kind: Option<&str>, wl: Option<&str>, ip: &str) -> NetRow {
        NetRow {
            dir: dir.into(),
            proto: "TCP".into(),
            port: Some(port.into()),
            peer_kind: kind.map(String::from),
            peer_namespace: kind.map(|_| "observability".into()),
            peer_workload_kind: wl.map(|_| "Deployment".into()),
            peer_workload_name: wl.map(String::from),
            peer_name: kind.map(|_| "x-1".into()),
            ip: Some(ip.into()),
            flows: 3,
            first_seen: ts(1),
            last_seen: ts(5),
            scanned: 10,
        }
    }

    fn now() -> DateTime<Utc> {
        utc(ts(1)) + chrono::Duration::days(3)
    }

    #[test]
    fn empty_sources_are_all_unknown_and_never_scored() {
        let s = Sources {
            any_pods: true,
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        assert_eq!(p.posture.head.status, "unknown");
        assert_eq!(p.posture.head.score, None);
        assert_eq!(p.posture.head.coverage, 0.0);
        assert_eq!(p.posture.head.grade, None);
        assert_eq!(
            p.posture.unknown_dimensions,
            vec!["network", "syscalls", "podSecurity", "images"]
        );
        assert!(p.findings.is_empty());
        assert_eq!(p.exposure.ingress_peers, None);
        let v = serde_json::to_value(&p).unwrap();
        // Contract: nothing omitted, unknowns are null.
        assert!(v["dimensions"]["images"]["vulnerabilities"].is_null());
        assert!(v["dimensions"]["images"].get("vulnerabilities").is_some());
        assert!(v["dimensions"]["syscalls"]["cr"].is_null());
        assert!(v["dimensions"]["network"]["policy"]["enforced"].is_null());
        assert!(v["dimensions"]["podSecurity"]["level"].is_null());
        assert!(v["dimensions"]["podSecurity"]["recommendation"].is_null());
        assert!(v["version"].is_null());
        assert_eq!(v["snapshotPending"], json!(true));
    }

    #[test]
    fn rollup_excludes_unknown_and_reports_coverage() {
        let s = Sources {
            containers: vec![container("app", restricted())],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        // Only podSecurity is scored (images: inventory only, not scored).
        assert_eq!(p.dimensions.pod_security.env.score, Some(100));
        assert_eq!(p.posture.head.score, Some(100));
        assert_eq!(
            p.posture.head.coverage,
            (20.0f64 / 85.0 * 100.0).round() / 100.0
        );
        assert_eq!(p.posture.head.grade, None, "grade only at coverage >= 0.8");
        assert!(p.posture.unknown_dimensions.contains(&"network"));
        assert!(p.posture.unknown_dimensions.contains(&"images"));
        assert_eq!(p.dimensions.images.env.status, "ok");
        assert!(!p.dimensions.images.env.scored);

        // Full coverage gives a grade.
        let env = |score| Envelope {
            status: "ok",
            score: Some(score),
            scored: true,
            coverage: Coverage {
                level: "full",
                fraction: None,
                observed_since: None,
                note: String::new(),
            },
            reasons: vec![],
        };
        let (a, b, c, d) = (env(100), env(50), env(80), env(90));
        let (head, unknown) = rollup(&[
            ("network", &a),
            ("syscalls", &b),
            ("podSecurity", &c),
            ("images", &d),
        ]);
        // (100*20 + 50*15 + 80*20 + 90*30) / 85 = 7050 / 85 = 82.94
        assert_eq!(head.score, Some(83));
        assert_eq!(head.coverage, 1.0);
        assert_eq!(head.grade.as_deref(), Some("B"));
        assert!(unknown.is_empty());
    }

    #[test]
    fn pod_security_dimension_scores_findings_and_links_deductions() {
        let s = Sources {
            containers: vec![container("app", json!({"privileged": true}))],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert_eq!(ps.analysis.level, Some(Level::Privileged));
        assert_eq!(ps.env.status, "risk");
        let total: u32 = p
            .posture
            .deductions
            .iter()
            .filter(|d| d.dimension == "podSecurity")
            .map(|d| d.points)
            .sum();
        assert_eq!(ps.env.score, Some(100u32.saturating_sub(total)));
        assert!(p
            .attention
            .iter()
            .any(|f| f.id == "podSecurity.privileged/app" && f.tier == Some("P1")));
        assert!(ps.analysis.recommendation.is_some());
    }

    #[test]
    fn network_is_unknown_without_audit_and_scored_with_it() {
        let mut s = Sources {
            any_pods: true,
            live_pods: vec!["checkout-1".into()],
            network: vec![
                net(
                    "INGRESS",
                    "8080",
                    Some("pod"),
                    Some("prometheus"),
                    "10.0.0.5",
                ),
                net("EGRESS", "443", None, None, "203.0.113.10"),
                net("EGRESS", "5432", None, None, "10.9.9.9"),
            ],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let n = &p.dimensions.network;
        assert_eq!(n.env.status, "unknown");
        assert_eq!(n.env.score, None);
        assert_eq!(n.peers[1].peer.kind, "external");
        assert_eq!(n.peers[2].peer.kind, "unresolved");
        assert_eq!(p.exposure.egress_external, Some(1));
        assert_eq!(p.exposure.ingress_peers, Some(1));
        assert_eq!(p.readiness[0].ok, Some(true), "3 days of traffic");

        s.audit = vec![AuditRow {
            policy_namespace: "payments".into(),
            policy_name: "checkout".into(),
            allow: 10,
            would_deny: 2,
            last: ts(4),
        }];
        let p = build(&key(), &s, now());
        let n = &p.dimensions.network;
        assert_eq!(n.env.score, Some(70));
        assert_eq!(n.env.status, "warn");
        assert_eq!(p.controls[0].state, Some("audit"));
        assert_eq!(p.controls[0].in_sync, Some(false));
    }

    #[test]
    fn syscalls_dimension_from_the_seccomp_summary() {
        let sum = SeccompSummary {
            hash: "h".into(),
            syscall_count: 3,
            architectures: vec!["x86_64".into()],
            updated_at: ts(3),
            capture: CaptureIn {
                level: "medium".into(),
                complete: false,
                incomplete: 1,
            },
            cr: Some(CrIn {
                name: "checkout".into(),
                default_action: "SCMP_ACT_ERRNO".into(),
                hash: "x".into(),
                syscall_count: 2,
                drift: DriftIn {
                    missing: vec!["read".into()],
                    extra: vec![],
                    in_sync: false,
                },
                distribution: DistIn {
                    ready: 1,
                    total: 1,
                    state: "Ready".into(),
                },
            }),
            denials: Some(DenialIn {
                total: 0,
                syscalls: vec![],
                last_seen: None,
            }),
        };
        let names: BTreeSet<String> = ["read", "write", "exit"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let s = Sources {
            seccomp: Some((sum, names)),
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let sc = &p.dimensions.syscalls;
        assert_eq!(sc.cr.as_ref().unwrap().mode, "enforce");
        assert_eq!(sc.env.score, Some(80));
        assert_eq!(sc.env.status, "warn", "incomplete capture caps at warn");
        assert_eq!(sc.env.coverage.level, "partial");
        assert_eq!(p.controls[1].state, Some("enforcing"));
        assert_eq!(
            p.snapshot["syscalls"]["syscalls"],
            json!(["exit", "read", "write"])
        );
    }

    #[test]
    fn snapshot_hash_ignores_timestamps_and_counts() {
        let mut s = Sources {
            containers: vec![container("app", restricted())],
            network: vec![net("EGRESS", "443", None, None, "203.0.113.10")],
            any_pods: true,
            ..Default::default()
        };
        let a = build(&key(), &s, now());
        s.network[0].flows = 999;
        s.network[0].last_seen = ts(9);
        s.containers[0].digests[0].last_seen = ts(9);
        let b = build(&key(), &s, now() + chrono::Duration::hours(1));
        assert_eq!(a.content_hash, b.content_hash);
        assert!(a.content_hash.starts_with("fnv1a64:"));

        s.containers[0].digests[0].digest = digest('b');
        let c = build(&key(), &s, now());
        assert_ne!(a.content_hash, c.content_hash);
        assert_eq!(a.dimension_hashes["network"], c.dimension_hashes["network"]);
        assert_ne!(a.dimension_hashes["images"], c.dimension_hashes["images"]);
    }

    #[test]
    fn canonical_hash_is_key_order_independent() {
        let a = json!({"b": 1, "a": {"y": [1, 2], "x": null}});
        let b: Value = serde_json::from_str(r#"{"a":{"x":null,"y":[1,2]},"b":1}"#).unwrap();
        assert_eq!(content_hash(&a), content_hash(&b));
        assert_ne!(
            content_hash(&a),
            content_hash(&json!({"b": 2, "a": {"y": [1, 2], "x": null}}))
        );
    }

    #[test]
    fn diff_is_structured_per_dimension() {
        let mut s = Sources {
            containers: vec![container("app", json!({}))],
            network: vec![net("EGRESS", "443", None, None, "203.0.113.10")],
            any_pods: true,
            ..Default::default()
        };
        let a = build(&key(), &s, now()).snapshot;
        s.containers[0].digests[0].digest = digest('b');
        s.containers[0].digests[0].security_context = restricted();
        s.network.push(net(
            "INGRESS",
            "8080",
            Some("pod"),
            Some("prometheus"),
            "10.0.0.5",
        ));
        let b = build(&key(), &s, now()).snapshot;
        let d = diff(&a, &b);
        assert_eq!(
            d["podSecurity"]["level"],
            json!({"from": "baseline", "to": "restricted"})
        );
        let fields = &d["podSecurity"]["containers"][0]["fields"];
        assert!(fields
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["field"] == "securityContext.allowPrivilegeEscalation"
                && f["from"].is_null()
                && f["to"] == json!(false)));
        assert_eq!(d["images"]["containers"][0]["added"], json!([digest('b')]));
        assert_eq!(
            d["images"]["containers"][0]["removed"],
            json!([digest('a')])
        );
        assert_eq!(d["network"]["added"].as_array().unwrap().len(), 1);
        assert_eq!(
            d["network"]["added"][0]["peer"],
            json!("pod:observability/Deployment/prometheus")
        );
        assert_eq!(d["network"]["removed"], json!([]));
        assert!(d["syscalls"]["cr"].is_null());
        assert_eq!(d["syscalls"]["changed"], json!(false));

        // Against nothing: everything is added.
        let d0 = diff(&Value::Null, &b);
        assert_eq!(d0["images"]["containersAdded"], json!(["app"]));
        assert_eq!(d0["network"]["added"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn classify_ips() {
        assert_eq!(classify_unknown_ip(Some("10.1.2.3")), "unresolved");
        assert_eq!(classify_unknown_ip(Some("100.64.0.1")), "unresolved");
        assert_eq!(classify_unknown_ip(Some("fd00::1")), "unresolved");
        assert_eq!(classify_unknown_ip(Some("8.8.8.8")), "external");
        assert_eq!(classify_unknown_ip(Some("2001:4860::8888")), "external");
        assert_eq!(classify_unknown_ip(Some("garbage")), "unresolved");
        assert_eq!(classify_unknown_ip(None), "unresolved");
    }

    #[test]
    fn after_cursor_roundtrips_and_rejects_junk() {
        assert_eq!(
            parse_after("payments/Deployment/checkout"),
            Some(("payments".into(), "Deployment".into(), "checkout".into()))
        );
        assert_eq!(parse_after("payments/Deployment"), None);
        assert_eq!(parse_after("//x"), None);
    }

    #[test]
    fn cr_modes() {
        assert_eq!(cr_mode("SCMP_ACT_LOG"), "audit");
        assert_eq!(cr_mode("SCMP_ACT_ALLOW"), "audit");
        assert_eq!(cr_mode("SCMP_ACT_ERRNO"), "enforce");
        assert_eq!(cr_mode("SCMP_ACT_KILL_PROCESS"), "enforce");
    }
}

// ---------------------------------------------------------------------
// Live-Postgres tests (KG_TEST_DATABASE_URL)
// ---------------------------------------------------------------------

#[cfg(test)]
mod live_tests {
    use super::*;
    use diesel::connection::SimpleConnection;

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

    /// Each test owns a namespace so tests on one database cannot collide.
    fn reset(conn: &mut PgConnection, ns: &str) {
        conn.batch_execute(&format!(
            "DELETE FROM workload_containers WHERE pod_namespace = '{ns}'; \
             DELETE FROM workload_syscalls WHERE pod_namespace = '{ns}'; \
             DELETE FROM pod_traffic WHERE pod_namespace = '{ns}'; \
             DELETE FROM pod_details WHERE pod_namespace = '{ns}'; \
             DELETE FROM audit_verdicts WHERE policy_namespace = '{ns}'; \
             DELETE FROM workload_profile_versions WHERE pod_namespace = '{ns}'; \
             DELETE FROM workload_profile_latest WHERE pod_namespace = '{ns}';"
        ))
        .expect("reset");
    }

    fn seed(conn: &mut PgConnection, ns: &str, digest_char: char, sc: &str) {
        let d = format!("sha256:{}", digest_char.to_string().repeat(64));
        conn.batch_execute(&format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, workload_kind, workload_name) \
             VALUES ('checkout-1', '10.0.0.1', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'checkout') \
             ON CONFLICT (pod_name) DO UPDATE SET pod_namespace = EXCLUDED.pod_namespace, is_dead = false, \
               workload_kind = 'Deployment', workload_name = 'checkout'; \
             INSERT INTO images (digest, repository, tags, digest_kind) VALUES ('{d}', 'ghcr.io/example/checkout', '{{1}}', 'repo') \
             ON CONFLICT (digest) DO NOTHING; \
             DELETE FROM workload_containers WHERE pod_namespace = '{ns}'; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, container_name, image_digest, \
               container_kind, image_ref, security_context, pod_security, last_pod_name, state) \
             VALUES ('{ns}', 'Deployment', 'checkout', 'app', '{d}', 'regular', 'ghcr.io/example/checkout:1', \
               '{sc}'::jsonb, '{{\"automountServiceAccountToken\": false}}'::jsonb, 'checkout-1', 'running');"
        ))
        .expect("seed");
    }

    fn add_flow(conn: &mut PgConnection, ns: &str, uuid: &str, port: &str, ip: &str) {
        conn.batch_execute(&format!(
            "INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, pod_ip, pod_port, ip_protocol, traffic_type, \
               traffic_in_out_ip, traffic_in_out_port, time_stamp) \
             VALUES ('{uuid}', 'checkout-1', '{ns}', '10.0.0.1', '40000', 'TCP', 'EGRESS', '{ip}', '{port}', \
               timezone('UTC', NOW()) - INTERVAL '2 days');"
        ))
        .expect("flow");
    }

    fn key(ns: &str) -> Key {
        Key {
            namespace: ns.into(),
            kind: "Deployment".into(),
            name: "checkout".into(),
        }
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_profile_joins_inventory_flows_and_verdicts() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-join";
        reset(&mut conn, ns);
        seed(&mut conn, ns, 'a', r#"{"privileged": true}"#);
        add_flow(&mut conn, ns, "kgtest-join-1", "443", "203.0.113.10");
        add_flow(&mut conn, ns, "kgtest-join-2", "443", "203.0.113.10");
        conn.batch_execute(&format!(
            "INSERT INTO audit_verdicts (policy_uid, policy_namespace, policy_name, direction, src_namespace, src_pod, \
               dst_port, protocol, observed_at, verdict) \
             VALUES ('u', '{ns}', 'checkout-egress', 'Egress', '{ns}', 'checkout-1', 443, 'TCP', timezone('UTC', NOW()), 'WouldDeny');"
        ))
        .unwrap();

        let s = load_sources(&mut conn, &key(ns)).unwrap();
        assert_eq!(s.live_pods, vec!["checkout-1".to_string()]);
        assert_eq!(s.network.len(), 1, "two flows to one external peer group");
        assert_eq!(s.network[0].flows, 2);
        assert_eq!(s.audit.len(), 1);
        let p = build(&key(ns), &s, Utc::now());
        assert_eq!(
            p.dimensions.pod_security.analysis.level,
            Some(Level::Privileged)
        );
        assert_eq!(p.dimensions.network.env.score, Some(70));
        assert_eq!(p.dimensions.network.peers[0].peer.kind, "external");
        assert_eq!(p.dimensions.images.containers[0].running.len(), 1);
        assert!(p.dimensions.syscalls.observed.is_none());
        assert_eq!(p.readiness[0].ok, Some(true));

        // Syscall aggregate joins through the seccomp summary code path.
        conn.batch_execute(&format!(
            "INSERT INTO workload_syscalls (pod_namespace, workload_kind, workload_name, syscalls, arches, hash, updated_at, syscall_count) \
             VALUES ('{ns}', 'Deployment', 'checkout', 'exit,read,write', 'x86_64', 'abc', timezone('UTC', NOW()), 3);"
        ))
        .unwrap();
        let s = load_sources(&mut conn, &key(ns)).unwrap();
        let p = build(&key(ns), &s, Utc::now());
        let sc = &p.dimensions.syscalls;
        assert_eq!(sc.observed.as_ref().unwrap().syscall_count, 3);
        assert!(sc.cr.is_none());
        assert!(sc.env.scored);
        assert_eq!(
            p.snapshot["syscalls"]["syscalls"],
            json!(["exit", "read", "write"])
        );

        // The snapshotter tick picks the workload up and fills the read model.
        let (done, _) = snapshot_tick(&mut conn, 100_000, 50).unwrap();
        assert!(done >= 1);
        let l = list_workloads(&mut conn, Some(ns), None, None, None, 10).unwrap();
        assert_eq!(l["items"][0]["name"], json!("checkout"));
        assert_eq!(l["items"][0]["posture"]["status"], json!("risk"));
        let l = list_workloads(&mut conn, Some(ns), None, Some("ok"), None, 10).unwrap();
        assert_eq!(l["items"], json!([]));

        // Unknown workload: nothing at all.
        let none = load_sources(
            &mut conn,
            &Key {
                name: "nope".into(),
                ..key(ns)
            },
        )
        .unwrap();
        assert!(none.is_empty());
        reset(&mut conn, ns);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_versions_written_only_on_change_capped_and_diffed() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-versions";
        reset(&mut conn, ns);
        seed(&mut conn, ns, 'a', "{}");
        let k = key(ns);

        assert_eq!(
            snapshot_one(&mut conn, &k, 3).unwrap(),
            Some(SnapshotOutcome::NewVersion(1))
        );
        // Same content: no new version.
        assert_eq!(
            snapshot_one(&mut conn, &k, 3).unwrap(),
            Some(SnapshotOutcome::Unchanged(1))
        );

        // Image change -> revision 2.
        seed(&mut conn, ns, 'b', "{}");
        assert_eq!(
            snapshot_one(&mut conn, &k, 3).unwrap(),
            Some(SnapshotOutcome::NewVersion(2))
        );
        // securityContext change -> revision 3.
        seed(
            &mut conn,
            ns,
            'b',
            r#"{"allowPrivilegeEscalation": false, "runAsNonRoot": true, "capabilitiesDrop": ["ALL"], "seccompProfileType": "RuntimeDefault"}"#,
        );
        assert_eq!(
            snapshot_one(&mut conn, &k, 3).unwrap(),
            Some(SnapshotOutcome::NewVersion(3))
        );
        // New flow -> revision 4; cap 3 trims revision 1.
        add_flow(&mut conn, ns, "kgtest-ver-1", "5432", "10.9.9.9");
        assert_eq!(
            snapshot_one(&mut conn, &k, 3).unwrap(),
            Some(SnapshotOutcome::NewVersion(4))
        );

        let v = list_versions(&mut conn, &k, None, 50).unwrap().unwrap();
        let revs: Vec<i64> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["revision"].as_i64().unwrap())
            .collect();
        assert_eq!(revs, vec![4, 3, 2]);
        assert_eq!(v["items"][0]["changedDimensions"], json!(["network"]));
        assert_eq!(v["items"][1]["changedDimensions"], json!(["podSecurity"]));
        // Revision 2's predecessor was trimmed: unknown, not guessed.
        assert!(v["items"][2]["changedDimensions"].is_null());
        assert!(v["nextBefore"].is_null());

        // Paging.
        let p1 = list_versions(&mut conn, &k, None, 2).unwrap().unwrap();
        assert_eq!(p1["nextBefore"], json!(3));
        let p2 = list_versions(&mut conn, &k, Some(3), 2).unwrap().unwrap();
        assert_eq!(p2["items"][0]["revision"], json!(2));

        // Diff 2 -> 3: podSecurity level baseline -> restricted, images unchanged.
        let DiffResult::Ok(d) = diff_versions(&mut conn, &k, Some(2), Some(3)).unwrap() else {
            panic!("diff failed")
        };
        assert_eq!(d["dimensions"]["podSecurity"]["changed"], json!(true));
        assert_eq!(
            d["dimensions"]["podSecurity"]["level"],
            json!({"from": "baseline", "to": "restricted"})
        );
        assert_eq!(d["dimensions"]["images"]["changed"], json!(false));
        // Default diff = latest vs previous.
        let DiffResult::Ok(d) = diff_versions(&mut conn, &k, None, None).unwrap() else {
            panic!("diff failed")
        };
        assert_eq!(d["to"]["revision"], json!(4));
        assert_eq!(d["from"]["revision"], json!(3));
        assert_eq!(
            d["dimensions"]["network"]["added"][0]["peer"],
            json!("unresolved:10.9.9.9")
        );
        assert!(matches!(
            diff_versions(&mut conn, &k, Some(1), Some(3)).unwrap(),
            DiffResult::RevisionMissing
        ));
        assert!(matches!(
            diff_versions(&mut conn, &k, Some(4), Some(3)).unwrap(),
            DiffResult::BadOrder
        ));

        // List endpoint reads the latest row.
        let l = list_workloads(&mut conn, Some(ns), None, None, None, 10).unwrap();
        assert_eq!(l["items"].as_array().unwrap().len(), 1);
        assert_eq!(l["items"][0]["revision"], json!(4));
        assert_eq!(
            l["items"][0]["dimensions"]["podSecurity"]["level"],
            json!("restricted")
        );
        assert!(l["nextAfter"].is_null());

        // Unknown workload.
        let unknown = Key {
            name: "nope".into(),
            ..key(ns)
        };
        assert!(list_versions(&mut conn, &unknown, None, 10)
            .unwrap()
            .is_none());
        assert!(matches!(
            diff_versions(&mut conn, &unknown, None, None).unwrap(),
            DiffResult::NoVersions
        ));
        reset(&mut conn, ns);
    }
}
