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
//! No numeric score. Each dimension has a tier status (`ok|warn|risk|
//! unknown`) derived by fixed rules from its findings (and, for
//! podSecurity, its PSS level), with the reasons that produced it. The
//! rollup status is the worst KNOWN core-dimension status, `coverage` is
//! the fraction of core dimensions whose status is known, and an unknown
//! dimension never counts as ok or as risk.
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
//! version page sizes. The two flow aggregates also run under their own
//! statement timeout ([`network_read_timeout_ms`]); past it the profile is
//! served without its network dimension rather than failing.

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
/// One signature result row: verdict, reason and up to
/// [`SIGNERS_PER_DIGEST`] verified signers (issuer and SAN cut to 512
/// bytes each).
pub const SIGNATURE_ROW_COST_BYTES: u64 = 12 * 1_024;
/// Verified signers listed per digest.
pub const SIGNERS_PER_DIGEST: i64 = 8;
/// Digests listed in `images.supplyChain.digests`; the counts and the
/// worst verdict cover every current digest.
pub const SUPPLY_CHAIN_DIGESTS_LISTED: usize = 64;

/// Dimensions the posture rollup covers (compute is informational).
pub const CORE_DIMENSIONS: [&str; 4] = ["network", "syscalls", "podSecurity", "images"];

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

/// `PROFILE_SNAPSHOT_BATCH` workloads per candidate query (default 200,
/// [1, 5000]); a tick takes batches until its budget is spent.
pub fn snapshot_batch() -> i64 {
    env_num("PROFILE_SNAPSHOT_BATCH")
        .unwrap_or(200)
        .clamp(1, 5_000)
}

/// `PROFILE_SNAPSHOT_TICK_BUDGET_SECS`: a tick keeps taking batches while
/// candidates remain and this much time has not passed (default: the
/// interval; 0 = one batch per tick).
pub fn snapshot_tick_budget(interval: Duration) -> Duration {
    Duration::from_secs(
        env_num("PROFILE_SNAPSHOT_TICK_BUDGET_SECS")
            .map(|v| v.clamp(0, 86_400) as u64)
            .unwrap_or(interval.as_secs()),
    )
}

/// `PROFILE_NETWORK_READ_TIMEOUT_MS`: statement timeout of the profile's
/// two `pod_traffic` aggregates together (default 10 000; 0 = only the
/// pool's backstop). Past it the profile is served without its network
/// dimension, `coverage.note` saying so, instead of failing whole.
pub fn network_read_timeout_ms() -> u64 {
    env_num("PROFILE_NETWORK_READ_TIMEOUT_MS")
        .map(|v| v.clamp(0, 600_000) as u64)
        .unwrap_or(10_000)
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
    pub(crate) fn parse(ns: String, kind: String, name: String) -> Option<Key> {
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

pub(crate) fn bad_key() -> HttpResponse {
    error(
        StatusCode::BAD_REQUEST,
        "bad_request",
        "namespace, kind and name must be non-empty and at most 253 characters",
    )
}

pub(crate) fn error(status: StatusCode, code: &str, message: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({ "error": code, "message": message }))
}

pub(crate) fn not_found_workload() -> HttpResponse {
    error(
        StatusCode::NOT_FOUND,
        "workload_not_found",
        "the broker has no inventory, syscall aggregate, live pod or stored profile for this workload",
    )
}

pub(crate) fn utc(t: NaiveDateTime) -> DateTime<Utc> {
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

/// Distinct network rules a workload has shown, deduped over ALL retained
/// flows of its pods (not the newest-N scan the peer table uses), so the
/// versioned snapshot changes only when the rule set does. Bounded by the
/// number of distinct rules ([`NETWORK_RULES_MAX`]), not raw flows.
#[derive(Debug, Clone, QueryableByName, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetRuleRow {
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
}

impl From<&NetRow> for NetRuleRow {
    fn from(r: &NetRow) -> Self {
        NetRuleRow {
            dir: r.dir.clone(),
            proto: r.proto.clone(),
            port: r.port.clone(),
            peer_kind: r.peer_kind.clone(),
            peer_namespace: r.peer_namespace.clone(),
            peer_workload_kind: r.peer_workload_kind.clone(),
            peer_workload_name: r.peer_workload_name.clone(),
            peer_name: r
                .peer_workload_name
                .is_none()
                .then(|| r.peer_name.clone())
                .flatten(),
            ip: r.peer_kind.is_none().then(|| r.ip.clone()).flatten(),
        }
    }
}

/// Most distinct rules snapshotted per workload.
pub const NETWORK_RULES_MAX: i64 = 2_000;

/// Joined through `pod_details`, so every retained flow of every pod of the
/// workload counts, whatever the pod list's LIMIT and however many pods
/// have died. The peer is reduced to its identity: workload for a pod with
/// one, name for a pod without / a service, nothing for a node, IP only
/// for an identity-less peer.
const NETWORK_RULES_SQL: &str = "\
SELECT DISTINCT upper(trim(coalesce(t.traffic_type, ''))) AS dir, \
       upper(trim(coalesce(t.ip_protocol, 'TCP'))) AS proto, \
       CASE WHEN upper(trim(coalesce(t.traffic_type, ''))) = 'INGRESS' THEN t.pod_port \
            ELSE t.traffic_in_out_port END AS port, \
       t.peer_kind, t.peer_namespace, t.peer_workload_kind, t.peer_workload_name, \
       CASE WHEN t.peer_workload_name IS NULL AND t.peer_kind IS NOT NULL AND t.peer_kind <> 'node' \
            THEN t.peer_name END AS peer_name, \
       CASE WHEN t.peer_kind IS NULL THEN t.traffic_in_out_ip END AS ip \
FROM pod_traffic t JOIN pod_details pd ON pd.pod_name = t.pod_name \
WHERE t.pod_namespace = $1 AND pd.pod_namespace = $1 \
  AND ((pd.workload_kind = $2 AND pd.workload_name = $3) \
       OR ($2 = 'Pod' AND pd.pod_name = $3 AND pd.workload_kind IS NULL)) \
  AND upper(trim(coalesce(t.traffic_type, ''))) IN ('INGRESS', 'EGRESS') \
ORDER BY 1, 2, 3, 4 NULLS LAST, 5 NULLS LAST, 6 NULLS LAST, 7 NULLS LAST, 8 NULLS LAST, 9 NULLS LAST \
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
    /// The broker's count from node-status posts (nodes heard from
    /// recently).
    pub distribution: DistIn,
    /// The CR's own `status.distribution` (the controllers' count against
    /// the API server's node list); absent when the CR carries none.
    #[serde(rename = "statusDistribution", default)]
    pub status_distribution: Option<DistIn>,
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

/// The stored signature discovery result for one digest
/// (`image_attestations`, see `attestation.rs`).
#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct SignatureRow {
    #[diesel(sql_type = Text)]
    pub digest: String,
    #[diesel(sql_type = Text)]
    pub verdict: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub reason: Option<String>,
    #[diesel(sql_type = Timestamp)]
    pub checked_at: NaiveDateTime,
    /// Distinct verified signers WITH an identity, at most
    /// [`SIGNERS_PER_DIGEST`]: `{signerKind: "keyless", issuer, san}` or
    /// `{signerKind: "key", keyName, keyFingerprint}`. Unverified
    /// signatures, and verified ones with neither issuer+SAN nor a key
    /// fingerprint, never appear.
    #[diesel(sql_type = Jsonb)]
    pub signers: Value,
    /// How many distinct such signers there are (before the cap).
    #[diesel(sql_type = BigInt)]
    pub signer_count: i64,
}

const SIGNATURES_SQL: &str = "SELECT a.digest, a.verdict, a.reason, a.checked_at, \
    COALESCE(ids.agg, '[]'::jsonb) AS signers, ids.n AS signer_count \
    FROM image_attestations a \
    LEFT JOIN LATERAL ( \
      SELECT jsonb_agg(x ORDER BY x::text) FILTER (WHERE rn <= $2) AS agg, count(*) AS n FROM ( \
        SELECT x, row_number() OVER (ORDER BY x::text) AS rn FROM ( \
          SELECT DISTINCT jsonb_strip_nulls(jsonb_build_object(\
              'signerKind', COALESCE(s->>'signerKind', 'keyless'), 'issuer', left(s->>'issuer', 512), \
              'san', left(s->>'san', 512), 'keyName', left(s->>'keyName', 256), \
              'keyFingerprint', left(s->>'keyFingerprint', 128))) AS x \
          FROM jsonb_array_elements(a.signatures) s \
          WHERE (s->>'verified')::boolean \
            AND CASE WHEN s->>'signerKind' = 'key' \
                     THEN btrim(COALESCE(s->>'keyFingerprint', '')) <> '' \
                     ELSE btrim(COALESCE(s->>'issuer', '')) <> '' AND btrim(COALESCE(s->>'san', '')) <> '' END \
        ) d \
      ) r \
    ) ids ON true \
    WHERE a.digest = ANY($1) ORDER BY a.digest LIMIT $3";

/// Whether image signature discovery is configured, from the chart-set
/// SIGNATURE_DISCOVERY_ENABLED. Only an explicit off value (false, 0, no,
/// off) says it is not; unset or anything else is configured, so a broker
/// that cannot tell never reports "not configured" for missing results.
pub fn signature_discovery_configured() -> bool {
    signature_discovery_configured_from(
        std::env::var("SIGNATURE_DISCOVERY_ENABLED").ok().as_deref(),
    )
}

pub(crate) fn signature_discovery_configured_from(v: Option<&str>) -> bool {
    !matches!(
        v.map(|x| x.trim().to_ascii_lowercase()).as_deref(),
        Some("false" | "0" | "no" | "off")
    )
}

/// A signer entry names who signed: a keyless issuer AND SAN, or a key
/// fingerprint. `{signerKind: "keyless"}` alone names no one.
fn has_signer_identity(signers: &Value) -> bool {
    let set = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
    };
    // Same rule as ingest and the evaluator: a key signer by fingerprint,
    // any other (including one with no kind) by issuer AND SAN.
    signers.as_array().is_some_and(|a| {
        a.iter()
            .any(|x| match x.get("signerKind").and_then(Value::as_str) {
                Some("key") => set(x, "keyFingerprint"),
                _ => set(x, "issuer") && set(x, "san"),
            })
    })
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
    /// Distinct rule set for the snapshot (see [`NetRuleRow`]).
    pub network_rules: Vec<NetRuleRow>,
    /// Why the flow aggregates were not read (their statement timeout ran
    /// out): `network` and `network_rules` are then empty and say nothing.
    pub network_unread: Option<String>,
    /// `None` = no verdict in the window mentions the pods.
    pub audit: Vec<AuditRow>,
    pub compute: Vec<ComputeRow>,
    pub compute_truncated: bool,
    pub stored: Option<StoredVersionHead>,
    /// Drift baselines (see `profile_drift.rs`): the latest export record
    /// and the newest stored versions, newest first.
    pub last_export: Option<crate::profile_drift::ExportBaseline>,
    pub recent_versions: Vec<crate::profile_drift::RecentVersion>,
    /// Capability use and its coverage (contract 2.9).
    pub capabilities: crate::runtime_capabilities::CapEvidence,
    /// Runtime inventory input of the `unshippedExecutable` drift check;
    /// `None` = not loaded (the check is then not evaluated).
    pub runtime: Option<crate::profile_drift::RuntimeDriftInput>,
    /// Signature discovery results for the workload's digests, by digest.
    /// A digest missing here has not been checked.
    pub signatures: BTreeMap<String, SignatureRow>,
    /// Signature discovery is switched off in the deployment
    /// (SIGNATURE_DISCOVERY_ENABLED=false, set by the chart). `false`, the
    /// default, means configured: the broker assumes it is on unless told.
    pub signature_discovery_off: bool,
    /// ImageTrustPolicy results for the workload (contract v1.9), read from
    /// the evaluator by the async profile handler; `None` where it is not
    /// read (snapshots, exports), shown as `null`.
    pub image_trust: Option<crate::image_trust::Answer>,
}

impl Sources {
    pub(crate) fn is_empty(&self) -> bool {
        self.containers.is_empty()
            && self.seccomp.is_none()
            && !self.any_pods
            && self.stored.is_none()
    }
}

/// The two `pod_traffic` aggregates, `Err(why)` when their statement
/// timeout ran out: the profile is then served without its network
/// dimension instead of failing whole (a busy namespace's flow rows can
/// outlast the pool's 30 s backstop).
type NetworkRead = Result<(Vec<NetRow>, bool, Vec<NetRuleRow>), String>;

fn read_network(
    conn: &mut PgConnection,
    key: &Key,
    pods: &[String],
    timeout_ms: u64,
) -> Result<NetworkRead, DbError> {
    let started = std::time::Instant::now();
    // Whether our bound, rather than the session's own tighter timeout,
    // was in force for the statement that ran last.
    let mut bounded = false;
    let out = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        bounded = bound_statement(conn, timeout_ms)?;
        let mut rows: Vec<NetRow> = sql_query(NETWORK_SQL)
            .bind::<Text, _>(&key.namespace)
            .bind::<Array<Text>, _>(pods)
            .bind::<BigInt, _>(NETWORK_SCAN_ROWS)
            .bind::<BigInt, _>(NETWORK_PEERS_MAX + 1)
            .load(conn)?;
        let scanned = rows.first().map(|r| r.scanned).unwrap_or(0);
        let truncated = rows.len() as i64 > NETWORK_PEERS_MAX || scanned >= NETWORK_SCAN_ROWS;
        rows.truncate(NETWORK_PEERS_MAX as usize);
        // The rules query gets what is left of the bound.
        if timeout_ms > 0 {
            let left = timeout_ms.saturating_sub(started.elapsed().as_millis() as u64);
            bounded = bound_statement(conn, left.max(1))?;
        }
        let mut rules: Vec<NetRuleRow> = sql_query(NETWORK_RULES_SQL)
            .bind::<Text, _>(&key.namespace)
            .bind::<Text, _>(&key.kind)
            .bind::<Text, _>(&key.name)
            .bind::<BigInt, _>(NETWORK_RULES_MAX)
            .load(conn)?;
        rules.dedup();
        Ok((rows, truncated, rules))
    });
    match out {
        Ok(v) => Ok(Ok(v)),
        Err(e) if is_statement_timeout(&e) => Ok(Err(if bounded {
            format!(
                "the flow aggregate was not read: the pod_traffic query exceeded its {timeout_ms} ms bound"
            )
        } else {
            "the flow aggregate was not read: the pod_traffic query exceeded the database's \
             statement timeout"
                .into()
        })),
        Err(e) => Err(e.into()),
    }
}

/// `SET LOCAL statement_timeout`, never above the session's own: true
/// when it applied, false when the session's tighter timeout stays.
fn bound_statement(conn: &mut PgConnection, ms: u64) -> QueryResult<bool> {
    #[derive(QueryableByName)]
    struct Applied {
        #[diesel(sql_type = Text)]
        #[allow(dead_code)]
        applied: String,
    }
    if ms == 0 {
        return Ok(false);
    }
    let v = format!("{ms}ms");
    sql_query(
        "SELECT set_config('statement_timeout', $1, true) AS applied \
         WHERE current_setting('statement_timeout') = '0' \
            OR current_setting('statement_timeout')::interval > $2::interval",
    )
    .bind::<Text, _>(&v)
    .bind::<Text, _>(&v)
    .load::<Applied>(conn)
    .map(|rows| !rows.is_empty())
}

fn is_statement_timeout(e: &diesel::result::Error) -> bool {
    matches!(e, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("statement timeout"))
}

/// Read every source for one workload.
pub fn load_sources(conn: &mut PgConnection, key: &Key) -> Result<Sources, DbError> {
    load_sources_bounded(conn, key, network_read_timeout_ms())
}

/// [`load_sources`] with an explicit statement timeout (ms) for the flow
/// aggregates; 0 leaves only the pool's backstop.
pub fn load_sources_bounded(
    conn: &mut PgConnection,
    key: &Key,
    network_timeout_ms: u64,
) -> Result<Sources, DbError> {
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

    // The rules query joins through pod_details too: no pods, no rows.
    let (network, network_truncated, network_rules, network_unread) = if all_pods.is_empty() {
        (Vec::new(), false, Vec::new(), None)
    } else {
        match read_network(conn, key, &all_pods, network_timeout_ms)? {
            Ok((rows, truncated, rules)) => (rows, truncated, rules, None),
            Err(why) => (Vec::new(), false, Vec::new(), Some(why)),
        }
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

    let (last_export, recent_versions) = crate::profile_drift::load_baselines(conn, key)?;
    let capabilities = crate::runtime_capabilities::load_evidence(
        conn,
        &key.namespace,
        &key.kind,
        &key.name,
        &crate::runtime_capabilities::current_pairs(&containers),
        crate::runtime_capabilities::evidence_window_hours(),
    )?;
    let runtime = Some(crate::profile_drift::load_runtime(
        conn,
        key,
        &crate::runtime_capabilities::current_pairs(&containers),
    )?);

    // Every digest the inventory holds for the workload (at most
    // WORKLOAD_CONTAINERS_MAX rows); the builder picks the current ones.
    let digests: Vec<String> = containers
        .iter()
        .flat_map(|c| c.digests.iter().chain(c.previous_digests.iter()))
        .map(|d| d.digest.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let signatures: BTreeMap<String, SignatureRow> = if digests.is_empty() {
        BTreeMap::new()
    } else {
        sql_query(SIGNATURES_SQL)
            .bind::<Array<Text>, _>(&digests)
            .bind::<BigInt, _>(SIGNERS_PER_DIGEST)
            .bind::<BigInt, _>(WORKLOAD_CONTAINERS_MAX)
            .load::<SignatureRow>(conn)?
            .into_iter()
            .map(|r| (r.digest.clone(), r))
            .collect()
    };

    Ok(Sources {
        containers,
        containers_truncated: truncated,
        running_window_seconds,
        seccomp,
        any_pods: !all_pods.is_empty(),
        live_pods,
        network,
        network_truncated,
        network_rules,
        network_unread,
        audit,
        compute,
        compute_truncated,
        stored,
        last_export,
        recent_versions,
        capabilities,
        runtime,
        signatures,
        signature_discovery_off: !signature_discovery_configured(),
        image_trust: None,
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
    .saturating_add(cost_kib(NETWORK_RULES_MAX, 512))
    .saturating_add(crate::profile_drift::runtime_charge_kib())
    .saturating_add(cost_kib(COMPUTE_ROWS_MAX + 1, 1_024))
    .saturating_add(cost_kib(AUDIT_POLICIES_MAX, 512))
    .saturating_add(cost_kib(2, SNAPSHOT_COST_BYTES))
    .saturating_add(cost_kib(
        crate::runtime_capabilities::CAP_READ_COST_ROWS,
        512,
    ))
    .saturating_add(cost_kib(WORKLOAD_CONTAINERS_MAX, SIGNATURE_ROW_COST_BYTES))
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

pub(crate) fn mk_finding(
    dimension: &'static str,
    id: String,
    severity: &'static str,
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
    }
}

/// Status / coverage / reasons shared by every dimension.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub status: &'static str,
    pub coverage: Coverage,
    pub reasons: Vec<Reason>,
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

fn status_rank(s: &str) -> u8 {
    match s {
        "risk" => 3,
        "warn" => 2,
        "ok" => 1,
        _ => 0,
    }
}

/// The worse of two known statuses.
fn worse(a: &'static str, b: &'static str) -> &'static str {
    if status_rank(b) > status_rank(a) {
        b
    } else {
        a
    }
}

/// podSecurity status (contract v1.2, section 2.2), fixed rules, no score:
///
/// - level `privileged` (a baseline check fails, in any container
///   including init and ephemeral, or at pod level) -> `risk`;
/// - any high/critical finding -> `risk`, any medium -> `warn`;
/// - level `baseline` (a restricted check fails) -> at least `warn`;
/// - level `restricted` only as an upper bound (checks kguardian cannot
///   see may still fail) -> never `ok`: `unknown` unless a finding makes
///   it warn/risk. `ok` needs a confirmed restricted level, which v1
///   cannot produce.
pub fn pod_security_status(
    level: Level,
    confidence: Option<&str>,
    findings: &[Finding],
) -> &'static str {
    let from_findings = status_from_findings(findings);
    match level {
        Level::Privileged => "risk",
        Level::Baseline => worse("warn", from_findings),
        Level::Restricted if confidence == Some("confirmed") => from_findings,
        Level::Restricted => {
            if from_findings == "ok" {
                "unknown"
            } else {
                from_findings
            }
        }
    }
}

// ---- podSecurity --------------------------------------------------------

/// A container the inventory still holds but no current pod reports: it
/// was renamed or removed from the spec. Shown, never evaluated.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaleContainer {
    pub name: String,
    pub kind: String,
    pub digest: String,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityDim {
    #[serde(flatten)]
    pub env: Envelope,
    #[serde(flatten)]
    pub analysis: Analysis,
    /// Containers no longer in the current spec; excluded from the level,
    /// the findings and the patch.
    pub stale_containers: Vec<StaleContainer>,
}

/// A row is CURRENT when a pod of the workload still reports it: refreshed
/// within the running window, or its last reporting pod is still live.
/// The inventory's running predicate minus the container-state term, so a
/// completed init container is current, while a container that was renamed
/// or removed from the spec (its pods gone, no refresh) is not.
fn is_current(d: &ContainerDigest, s: &Sources, now: DateTime<Utc>) -> bool {
    utc(d.last_seen) >= now - chrono::Duration::seconds(s.running_window_seconds)
        || d.last_pod_name
            .as_ref()
            .is_some_and(|p| s.live_pods.contains(p))
}

/// The row a container is evaluated from: its newest running row, else its
/// newest current row (`last_known`), else `None` (stale).
fn current_row<'a>(
    c: &'a ContainerImages,
    s: &Sources,
    now: DateTime<Utc>,
) -> Option<(&'a ContainerDigest, &'static str)> {
    c.digests.first().map(|d| (d, "running")).or_else(|| {
        c.previous_digests
            .iter()
            .find(|d| is_current(d, s, now))
            .map(|d| (d, "last_known"))
    })
}

/// A container is stale when none of its rows is current.
fn is_stale(c: &ContainerImages, s: &Sources, now: DateTime<Utc>) -> bool {
    current_row(c, s, now).is_none()
}

/// The pod-level block, or `None` when it is empty or malformed (older
/// controller): pod-level checks are then unevaluated, not "unset".
fn parse_pod_security(v: &Value) -> Option<PodSecurity> {
    match v {
        Value::Object(m) if !m.is_empty() => serde_json::from_value(v.clone()).ok(),
        _ => None,
    }
}

fn build_pod_security(
    key: &Key,
    s: &Sources,
    now: DateTime<Utc>,
    caps: &crate::runtime_capabilities::CapabilitiesView,
) -> (PodSecurityDim, Vec<Finding>) {
    let mut inputs = Vec::new();
    let mut stale = Vec::new();
    let mut pod: Option<(NaiveDateTime, Option<PodSecurity>)> = None;
    let mut since: Option<NaiveDateTime> = None;
    for c in &s.containers {
        let Some((row, source)) = current_row(c, s, now) else {
            if let Some(d) = c.previous_digests.first() {
                stale.push(StaleContainer {
                    name: c.container_name.clone(),
                    kind: c.container_kind.clone(),
                    digest: d.digest.clone(),
                    last_seen: utc(d.last_seen),
                });
            }
            continue;
        };
        let sec: ContainerSecurity =
            serde_json::from_value(row.security_context.clone()).unwrap_or_default();
        if pod.as_ref().is_none_or(|(t, _)| row.last_seen > *t) {
            pod = Some((row.last_seen, parse_pod_security(&row.pod_security)));
        }
        since = Some(since.map_or(row.first_seen, |x: NaiveDateTime| x.min(row.first_seen)));
        inputs.push(pod_security::ContainerInput {
            name: c.container_name.clone(),
            kind: c.container_kind.clone(),
            source,
            digest: row.digest.clone(),
            security: sec,
            observed_capabilities: caps
                .containers
                .iter()
                .find(|x| x.container == c.container_name)
                .and_then(|x| x.recommendation.as_ref())
                .map(|r| r.add.clone()),
            probed_capabilities: caps
                .containers
                .iter()
                .find(|x| x.container == c.container_name)
                .and_then(|x| x.recommendation.as_ref())
                .map(|r| r.probed_kept.clone())
                .unwrap_or_default(),
            probed_omitted: caps
                .containers
                .iter()
                .find(|x| x.container == c.container_name)
                .and_then(|x| x.recommendation.as_ref())
                .map(|r| {
                    r.probed_omitted
                        .iter()
                        .map(|o| o.capability.clone())
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    let pod = pod.and_then(|(_, p)| p);
    let analysis = pod_security::analyse(&key.kind, pod.as_ref(), &inputs);
    let evaluated = pod_security::ALL_CHECKS.len() - analysis.unevaluated_checks.len();
    let findings: Vec<Finding> = analysis
        .findings
        .iter()
        .map(|f| {
            mk_finding(
                "podSecurity",
                f.id.clone(),
                f.severity,
                f.container.clone(),
                f.title.clone(),
                f.detail.clone(),
            )
        })
        .collect();
    let env = if inputs.is_empty() {
        Envelope {
            status: "unknown",
            coverage: Coverage {
                level: "none",
                fraction: None,
                observed_since: None,
                note: "no current container securityContext reported for this workload".into(),
            },
            reasons: vec![if stale.is_empty() {
                reason(
                    "no_inventory",
                    "The controller has not reported this workload's containers (image inventory)",
                )
            } else {
                reason(
                    "only_stale_containers",
                    "Only containers no longer in the current spec are known",
                )
            }],
        }
    } else {
        let level = analysis.level.unwrap_or(Level::Restricted);
        let mut reasons = Vec::new();
        // Name the containers that set the level (init and ephemeral
        // included), so the reason is never a bare verdict.
        let failing_at = |lv: Level| -> String {
            let mut names: Vec<String> = analysis
                .containers
                .iter()
                .filter(|c| c.level == lv)
                .map(|c| format!("{} ({})", c.name, c.kind))
                .collect();
            if analysis
                .pod
                .failing
                .iter()
                .any(|f| lv == pod_security::level_of(std::slice::from_ref(f)))
            {
                names.insert(0, "pod spec".into());
            }
            names.join(", ")
        };
        match analysis.level {
            Some(Level::Privileged) => reasons.push(reason(
                "pss_fails_baseline",
                format!(
                    "Privileged under PSS: {} fail(s) a baseline check",
                    failing_at(Level::Privileged)
                ),
            )),
            Some(Level::Baseline) => reasons.push(reason(
                "pss_fails_restricted",
                format!(
                    "At most baseline: {} fail(s) a restricted check; unevaluated checks may lower it further",
                    failing_at(Level::Baseline)
                ),
            )),
            Some(Level::Restricted) => reasons.push(reason(
                "pss_unverified",
                format!(
                    "Every evaluated check passes restricted, but {} checks cannot be seen (e.g. hostPath), so restricted is not confirmed",
                    analysis.unevaluated_checks.len()
                ),
            )),
            None => {}
        }
        if !analysis.pod.known {
            reasons.push(reason(
                "pod_fields_unknown",
                "The pod-level block (host namespaces, pod securityContext) was not reported; those checks are unevaluated",
            ));
        }
        let eph: Vec<&str> = analysis
            .containers
            .iter()
            .filter(|c| c.kind == "ephemeral" && !c.failing.is_empty())
            .map(|c| c.name.as_str())
            .collect();
        if !eph.is_empty() {
            reasons.push(reason(
                "ephemeral_unpatchable",
                format!(
                    "Ephemeral container(s) {} fail checks and cannot be patched",
                    eph.join(", ")
                ),
            ));
        }
        if !stale.is_empty() {
            reasons.push(reason(
                "stale_containers_excluded",
                format!(
                    "{} container(s) no longer in the current spec are listed in staleContainers and not evaluated",
                    stale.len()
                ),
            ));
        }
        Envelope {
            status: pod_security_status(level, analysis.level_confidence, &findings),
            coverage: Coverage {
                level: "partial",
                fraction: Some(
                    ((evaluated as f64 / pod_security::ALL_CHECKS.len() as f64) * 100.0).round()
                        / 100.0,
                ),
                observed_since: since.map(utc),
                note: format!(
                    "{evaluated} of {} PSS checks evaluated; volumes, ports, probes, AppArmor, SELinux, procMount, sysctls and hostProcess are not ingested",
                    pod_security::ALL_CHECKS.len()
                ),
            },
            reasons,
        }
    };
    (
        PodSecurityDim {
            env,
            analysis,
            stale_containers: stale,
        },
        findings,
    )
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
    /// No current pod reports this container any more (renamed or removed
    /// from the spec); kept until inventory retention prunes it.
    pub stale: bool,
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
    /// Signature discovery results for the current digests (contract
    /// v1.8, section 2.6); `null` when the workload has no current digest.
    pub supply_chain: Option<SupplyChainView>,
}

/// One current digest's signature result. `verdict: null` = not checked.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignatureView {
    pub container: String,
    pub digest: String,
    pub verdict: Option<String>,
    pub reason: Option<String>,
    pub signers: Value,
    /// Signers beyond the [`SIGNERS_PER_DIGEST`] listed; omitted when 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub signers_omitted: usize,
    pub checked_at: Option<DateTime<Utc>>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignatureCounts {
    pub verified: usize,
    pub key_signed: usize,
    pub unsigned: usize,
    pub invalid: usize,
    pub unknown: usize,
    pub not_checked: usize,
}

/// `images.supplyChain` (contract v1.8): the worst signature verdict over
/// the workload's current digests, the digest it came from, and every
/// digest's result.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SupplyChainView {
    /// `configured`, or `not_configured` when signature discovery is
    /// switched off in the deployment: then nothing below is evaluated and
    /// signatures do not gate the images status.
    pub status: &'static str,
    /// Worst over the current digests: invalid, unsigned, key_signed,
    /// unknown (also a digest never checked, reason `not_checked`),
    /// verified. `verified` only when every current digest verified.
    /// `not_configured` with status `not_configured`.
    pub verdict: String,
    pub reason: Option<String>,
    /// The worst digest and its container; `null` when not configured.
    pub container: Option<String>,
    pub digest: Option<String>,
    /// The worst digest's verified signers (empty unless it verified).
    pub signers: Value,
    #[serde(skip_serializing_if = "is_zero")]
    pub signers_omitted: usize,
    pub checked_at: Option<DateTime<Utc>>,
    pub counts: SignatureCounts,
    /// Which ImageTrustPolicies would deny this workload's containers
    /// (contract v1.9), from the evaluator. `available: false` (with
    /// `reason`) is unknown, never "nothing would be denied"; `null` where
    /// it is not read (stored versions, exports). Report-only, outside
    /// posture and the snapshot hash.
    pub image_trust: Option<crate::image_trust::Answer>,
    pub digests: Vec<SignatureView>,
    pub truncated: bool,
}

/// Worst first. An unrecognised verdict ranks as unknown.
fn signature_rank(verdict: Option<&str>) -> u8 {
    match verdict {
        Some("invalid") => 0,
        Some("unsigned") => 1,
        Some("key_signed") => 2,
        Some("verified") => 4,
        _ => 3,
    }
}

fn build_supply_chain(s: &Sources, findings: &mut Vec<Finding>) -> Option<SupplyChainView> {
    // The current (container, digest) pairs, exactly as the drift checks
    // read them: every running digest of each container. A completed init
    // container or a stale container is not current.
    let current = crate::runtime_capabilities::current_pairs(&s.containers);
    if s.signature_discovery_off {
        // Feature off is not missing data: say so, list nothing, gate
        // nothing. Stored results from before it was switched off are not
        // current evidence.
        return (!current.is_empty()).then(|| SupplyChainView {
            status: "not_configured",
            verdict: "not_configured".into(),
            reason: None,
            container: None,
            digest: None,
            signers: json!([]),
            signers_omitted: 0,
            checked_at: None,
            counts: SignatureCounts::default(),
            image_trust: s.image_trust.clone(),
            digests: Vec::new(),
            truncated: false,
        });
    }
    let mut seen = BTreeSet::new();
    let views: Vec<SignatureView> = current
        .into_iter()
        .filter(|(c, d)| seen.insert((c.clone(), d.clone())))
        .map(|(c, d)| match s.signatures.get(&d) {
            // "verified" with no signer identity (no issuer+SAN, no key
            // fingerprint) names no one: unknown, never signed.
            Some(r) if r.verdict == "verified" && !has_signer_identity(&r.signers) => {
                SignatureView {
                    container: c.clone(),
                    digest: d.clone(),
                    verdict: Some("unknown".into()),
                    reason: Some("no_signer_identity".into()),
                    signers: json!([]),
                    signers_omitted: 0,
                    checked_at: Some(utc(r.checked_at)),
                }
            }
            Some(r) => {
                let verified = r.verdict == "verified";
                let shown = r.signers.as_array().map_or(0, Vec::len);
                SignatureView {
                    container: c.clone(),
                    digest: d.clone(),
                    verdict: Some(r.verdict.clone()),
                    reason: r.reason.clone(),
                    signers: if verified {
                        r.signers.clone()
                    } else {
                        json!([])
                    },
                    signers_omitted: if verified {
                        usize::try_from(r.signer_count)
                            .unwrap_or(0)
                            .saturating_sub(shown)
                    } else {
                        0
                    },
                    checked_at: Some(utc(r.checked_at)),
                }
            }
            None => SignatureView {
                container: c.clone(),
                digest: d.clone(),
                verdict: None,
                reason: None,
                signers: json!([]),
                signers_omitted: 0,
                checked_at: None,
            },
        })
        .collect();
    let worst = views
        .iter()
        .min_by_key(|v| signature_rank(v.verdict.as_deref()))?
        .clone();
    let mut counts = SignatureCounts::default();
    let mut flagged = BTreeSet::new();
    for v in &views {
        let c = &v.container;
        match v.verdict.as_deref() {
            Some("verified") => counts.verified += 1,
            Some("key_signed") => counts.key_signed += 1,
            Some("unsigned") => counts.unsigned += 1,
            Some("invalid") => counts.invalid += 1,
            Some(_) => counts.unknown += 1,
            None => counts.not_checked += 1,
        }
        // One finding per container and kind, from its worst digest.
        let f = match v.verdict.as_deref() {
            Some("invalid") => Some((
                "signatureInvalid",
                "high",
                format!("Container {c} runs an image whose signature does not verify"),
                format!(
                    "{} has signatures and none verified ({}): tampered, made for another digest or malformed.",
                    v.digest,
                    v.reason.as_deref().unwrap_or("no reason given")
                ),
            )),
            Some("unsigned") => Some((
                "unsigned",
                "low",
                format!("Container {c} runs an unsigned image"),
                format!("No signature was found for {}.", v.digest),
            )),
            Some("key_signed") => Some((
                "signatureNotVerified",
                "low",
                format!("Container {c} runs an image signed with a key kguardian was not given"),
                format!(
                    "{} carries a key signature that was not checked; give the supplychain component the public key.",
                    v.digest
                ),
            )),
            _ => None,
        };
        if let Some((kind, sev, title, detail)) = f {
            if flagged.insert((kind, c.clone())) {
                findings.push(mk_finding(
                    "images",
                    format!("images.{kind}/{c}"),
                    sev,
                    Some(c.clone()),
                    title,
                    detail,
                ));
            }
        }
    }
    let truncated = views.len() > SUPPLY_CHAIN_DIGESTS_LISTED;
    let (verdict, reason) = match worst.verdict.as_deref() {
        None => ("unknown".to_string(), Some("not_checked".to_string())),
        Some(v) if signature_rank(Some(v)) == 3 => ("unknown".to_string(), worst.reason.clone()),
        Some(v) => (v.to_string(), worst.reason.clone()),
    };
    Some(SupplyChainView {
        status: "configured",
        verdict,
        reason,
        container: Some(worst.container.clone()),
        digest: Some(worst.digest.clone()),
        signers: worst.signers.clone(),
        signers_omitted: worst.signers_omitted,
        checked_at: worst.checked_at,
        counts,
        image_trust: s.image_trust.clone(),
        digests: views
            .into_iter()
            .take(SUPPLY_CHAIN_DIGESTS_LISTED)
            .collect(),
        truncated,
    })
}

impl SupplyChainView {
    fn configured(&self) -> bool {
        self.status == "configured"
    }

    /// "N digest(s): 2 verified, 1 not checked".
    fn summary(&self) -> String {
        if !self.configured() {
            return "image signature discovery is not configured (supplychain.signatureDiscovery.enabled); signatures are not checked".into();
        }
        let c = &self.counts;
        let parts: Vec<String> = [
            (c.invalid, "invalid"),
            (c.unsigned, "unsigned"),
            (c.key_signed, "key-signed (not checked)"),
            (c.unknown, "could not be checked"),
            (c.not_checked, "not checked"),
            (c.verified, "verified"),
        ]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, l)| format!("{n} {l}"))
        .collect();
        let total = c.invalid + c.unsigned + c.key_signed + c.unknown + c.not_checked + c.verified;
        format!("{total} current digest(s): {}", parts.join(", "))
    }
}

/// The images status (contract v1.8), pure so it is tested before the
/// vulnerability source is wired:
///
/// - a current digest whose signature does not verify -> `risk`, with or
///   without vulnerability data;
/// - no vulnerability data -> `unknown`;
/// - with vulnerability data, the findings decide, except that `ok` needs
///   every current digest verified: an unknown, never-checked, unsigned or
///   key-signed digest leaves it `unknown`, never `ok`.
fn images_status(
    vulnerability_data: bool,
    findings: &[Finding],
    supply_chain: Option<&SupplyChainView>,
) -> &'static str {
    // Signatures gate only when discovery is configured: "feature off" is
    // not unknown data. No supplyChain means no current digest, so there is
    // nothing to vouch for: never ok.
    let gate = supply_chain.filter(|sc| sc.configured());
    if gate.is_some_and(|sc| sc.counts.invalid > 0) {
        return "risk";
    }
    if !vulnerability_data {
        return "unknown";
    }
    match status_from_findings(findings) {
        "ok" if supply_chain.is_none() || gate.is_some_and(|sc| sc.verdict != "verified") => {
            "unknown"
        }
        st => st,
    }
}

fn build_images(s: &Sources, now: DateTime<Utc>) -> (ImagesDim, Vec<Finding>) {
    let mut findings = Vec::new();
    let supply_chain = build_supply_chain(s, &mut findings);
    let mut since: Option<NaiveDateTime> = None;
    let containers: Vec<ImageContainerView> = s
        .containers
        .iter()
        .map(|c| {
            for d in c.digests.iter().chain(c.previous_digests.iter()) {
                since = Some(since.map_or(d.first_seen, |x: NaiveDateTime| x.min(d.first_seen)));
            }
            let n = &c.container_name;
            let stale = is_stale(c, s, now);
            if stale {
                // Not in the current spec: listed, never a finding.
                return ImageContainerView {
                    name: c.container_name.clone(),
                    kind: c.container_kind.clone(),
                    mixed_digests: c.mixed_digests,
                    stale,
                    running: c.digests.iter().map(DigestView::from).collect(),
                    previous: c.previous_digests.iter().map(DigestView::from).collect(),
                };
            }
            if c.mixed_digests {
                findings.push(mk_finding(
                    "images",
                    format!("images.mixedDigests/{n}"),
                    "low",
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
                    Some(n.clone()),
                    format!("Container {n} cannot pull its image"),
                    "The newest reported state is ImagePullBackOff / ErrImagePull.".into(),
                ));
            }
            ImageContainerView {
                name: c.container_name.clone(),
                kind: c.container_kind.clone(),
                mixed_digests: c.mixed_digests,
                stale,
                running: c.digests.iter().map(DigestView::from).collect(),
                previous: c.previous_digests.iter().map(DigestView::from).collect(),
            }
        })
        .collect();
    let env = if containers.is_empty() {
        Envelope {
            status: "unknown",
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
        // Contract v1.3: the images dimension is about what the running
        // digests contain. With no vulnerability data for them its status
        // is unknown, whatever the inventory says; the inventory facts
        // (digests, mixed rollouts, crash loops) stay as details, reasons
        // and findings. Once vulnerability data exists the status is
        // derived from findings.
        let current: Vec<&ImageContainerView> = containers.iter().filter(|c| !c.stale).collect();
        let running: BTreeSet<&str> = current
            .iter()
            .flat_map(|c| c.running.iter().map(|d| d.digest.as_str()))
            .collect();
        let vulnerability_data = false;
        // Contract v1.8: a signature that does not verify is known-bad
        // evidence about the running content, so it makes the dimension
        // `risk` even without vulnerability data. Nothing about signatures
        // can make it `ok`: unsigned, key-signed, unknown and not-checked
        // leave it as it was, and a verified signature is not a pass.
        let mut reasons = vec![reason(
            "vulnerabilities_not_configured",
            format!(
                "{} running digest(s) across {} container(s); vulnerability data not configured",
                running.len(),
                current.len()
            ),
        )];
        if let Some(sc) = &supply_chain {
            reasons.push(reason(
                if sc.configured() {
                    "signatures"
                } else {
                    "signatures_not_configured"
                },
                sc.summary(),
            ));
        }
        Envelope {
            status: images_status(vulnerability_data, &findings, supply_chain.as_ref()),
            coverage: Coverage {
                level: "partial",
                fraction: None,
                observed_since: since.map(utc),
                note: format!(
                    "inventory only (running window {} s); no vulnerability data",
                    s.running_window_seconds
                ),
            },
            reasons,
        }
    };
    (
        ImagesDim {
            env,
            running_window_seconds: s.running_window_seconds,
            containers,
            truncated: s.containers_truncated,
            vulnerabilities: None,
            supply_chain,
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
    pub status_distribution: Option<DistIn>,
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
        status_distribution: c.status_distribution.clone(),
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
    let mut status = status_from_findings(&findings);
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
    fn from_rule(r: &NetRuleRow) -> PeerView {
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
    let status = if let Some(why) = &s.network_unread {
        reasons.push(reason("network_unread", why.clone()));
        "unknown"
    } else if peers.is_empty() {
        reasons.push(reason(
            "no_flows",
            "No flows observed for this workload's pods",
        ));
        "unknown"
    } else if let Some(a) = &audit {
        if a.would_deny > 0 {
            findings.push(mk_finding(
                "network",
                "network.wouldDeny".into(),
                "medium",
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
        status_from_findings(&findings)
    } else {
        reasons.push(reason(
            "policy_state_unknown",
            "No audit policy covers this workload; applied NetworkPolicies are not visible to the broker",
        ));
        "unknown"
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
                    note: match &s.network_unread {
                        Some(why) => why.clone(),
                        None => format!(
                            "Flows from {} pod(s) ({} live)",
                            if s.any_pods { "the workload's" } else { "no" },
                            s.live_pods.len()
                        ),
                    },
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostureHead {
    pub status: String,
    pub coverage: f64,
}

/// Why the rollup is what it is: one entry per core dimension that is not
/// ok (warn / risk / unknown), in dimension order.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostureReason {
    pub dimension: &'static str,
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Posture {
    #[serde(flatten)]
    pub head: PostureHead,
    pub unknown_dimensions: Vec<&'static str>,
    pub reasons: Vec<PostureReason>,
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
    /// Drift against the last export / previous version (contract 2.8).
    pub drift: crate::profile_drift::DriftView,
    /// Observed capability use and the evidence-based recommendation
    /// (contract 2.9). Not part of the snapshot: counts move constantly;
    /// the recommendation reaches the snapshot through podSecurity.
    pub capabilities: crate::runtime_capabilities::CapabilitiesView,
    pub dimensions: Dimensions,
    #[serde(skip)]
    pub snapshot: Value,
    #[serde(skip)]
    pub dimension_hashes: BTreeMap<&'static str, String>,
}

/// Rollup over the core dimensions: worst known status, except that it can
/// only be `ok` when no core dimension is unknown (else `unknown`, partial
/// data); coverage = the fraction of core dimensions whose status is known;
/// unknown dimensions are always listed and never count as ok or risk.
pub fn rollup(dims: &[(&'static str, &Envelope)]) -> (PostureHead, Vec<&'static str>) {
    let mut unknown = Vec::new();
    let mut worst = "unknown";
    let mut known = 0usize;
    for name in CORE_DIMENSIONS {
        let status = dims
            .iter()
            .find(|(n, _)| *n == name)
            .map_or("unknown", |(_, e)| e.status);
        if status == "unknown" {
            unknown.push(name);
        } else {
            known += 1;
            if status_rank(status) > status_rank(worst) {
                worst = status;
            }
        }
    }
    let coverage = ((known as f64 / CORE_DIMENSIONS.len() as f64) * 100.0).round() / 100.0;
    // Contract v1.3: "ok" needs every core dimension known. With any
    // unknown dimension the rollup is the worst known status only when
    // that is warn/risk; otherwise it is unknown (partial data).
    if !unknown.is_empty() && status_rank(worst) < status_rank("warn") {
        worst = "unknown";
    }
    (
        PostureHead {
            status: worst.to_string(),
            coverage,
        },
        unknown,
    )
}

/// `imageSigned`: true only when every current digest has a verified
/// signature; false when any is invalid, unsigned or key-signed (not
/// checked); unknown (`null`) when any could not be checked or was never
/// checked. A verified signature is valid for its signer, not trusted.
fn image_signed_readiness(sc: Option<&SupplyChainView>) -> Readiness {
    let id = "imageSigned";
    let Some(sc) = sc else {
        return Readiness {
            id,
            ok: None,
            message: "No current image digest for this workload".into(),
        };
    };
    if !sc.configured() {
        return Readiness {
            id,
            ok: None,
            message: "Image signature discovery is not configured (supplychain.signatureDiscovery.enabled)".into(),
        };
    }
    let c = &sc.counts;
    let ok = if c.invalid + c.unsigned + c.key_signed > 0 {
        Some(false)
    } else if c.unknown + c.not_checked > 0 {
        None
    } else {
        Some(true)
    };
    let message = match ok {
        Some(true) => format!(
            "{}; verified means valid for its signer, not trusted",
            sc.summary()
        ),
        Some(false) => sc.summary(),
        None if c.not_checked > 0 && c.unknown == 0 && c.verified == 0 => format!(
            "{} (no result yet: discovery has not reached it)",
            sc.summary()
        ),
        None => sc.summary(),
    };
    Readiness { id, ok, message }
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
    let capabilities = crate::runtime_capabilities::build_view(&s.containers, &s.capabilities);
    let (pod_security, f_ps) = build_pod_security(key, s, now, &capabilities);
    let (images, f_im) = build_images(s, now);
    let (syscalls, f_sc) = build_syscalls(s);
    let (network, f_net) = build_network(s);
    let (compute, f_co) = build_compute(s);

    let core: [(&'static str, &Envelope); 4] = [
        ("network", &network.env),
        ("syscalls", &syscalls.env),
        ("podSecurity", &pod_security.env),
        ("images", &images.env),
    ];
    let (head, unknown) = rollup(&core);
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
            .then_with(|| a.id.cmp(&b.id))
    });
    // One reason per core dimension that is not ok: its most severe
    // finding, else its first stated reason.
    let posture_reasons: Vec<PostureReason> = core
        .iter()
        .filter(|(_, e)| e.status != "ok")
        .map(|(d, e)| PostureReason {
            dimension: d,
            status: e.status,
            // podSecurity leads with its level reason (which containers
            // set it); the others with their most severe finding.
            message: (*d == "podSecurity" || e.status == "unknown")
                .then(|| e.reasons.first().map(|r| r.message.clone()))
                .flatten()
                .or_else(|| {
                    findings
                        .iter()
                        .find(|f| f.dimension == *d && severity_rank(f.severity) <= 2)
                        .map(|f| f.title.clone())
                })
                .or_else(|| e.reasons.first().map(|r| r.message.clone()))
                .unwrap_or_default(),
        })
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
            detail: "kguardian does not enforce image admission; signature results are in images.supplyChain and ImageTrustPolicy results are report-only".into(),
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
        image_signed_readiness(images.supply_chain.as_ref()),
        match pod_security.analysis.level {
            // A restricted level that is only an upper bound cannot say
            // yes: checks kguardian cannot see (hostPath...) may fail.
            Some(Level::Restricted) => Readiness {
                id: "podSecurityRestricted",
                ok: (pod_security.analysis.level_confidence == Some("confirmed")).then_some(true),
                message: format!(
                    "Every evaluated check passes restricted; {} checks cannot be seen, so restricted is not confirmed",
                    pod_security.analysis.unevaluated_checks.len()
                ),
            },
            Some(l) => Readiness {
                id: "podSecurityRestricted",
                ok: Some(false),
                message: format!("At most {}", l.as_str()),
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
    // Drift (P2-5) compares the live snapshot with a baseline, so it runs
    // after the snapshot; its findings join the list before attention is
    // picked. Drift is not a core dimension and never sets posture.
    let (drift, drift_findings) = crate::profile_drift::detect(
        &key.kind,
        &dims.images.containers,
        &snapshot,
        &dimension_hashes,
        s,
    );
    findings.extend(drift_findings);
    findings.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.id.cmp(&b.id))
    });
    let attention: Vec<Finding> = findings
        .iter()
        .filter(|f| severity_rank(f.severity) <= 2)
        .take(ATTENTION_MAX)
        .cloned()
        .collect();
    let version = s.stored.as_ref().map(|v| VersionRef {
        revision: v.revision,
        content_hash: v.content_hash.clone(),
        created_at: utc(v.created_at),
    });
    // A partial profile is never versioned (snapshot_one refuses it), so
    // it must not promise a snapshot.
    let snapshot_pending = s.network_unread.is_none()
        && version
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
            unknown_dimensions: unknown,
            reasons: posture_reasons,
        },
        attention,
        findings,
        controls,
        readiness,
        exposure,
        drift,
        capabilities,
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
    for c in d.images.containers.iter().filter(|c| !c.stale) {
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

    // The policy-relevant rule set only: no counts, no truncation flag,
    // no audit-window state, nothing that moves without the rules moving.
    let rules: BTreeSet<(String, String, Option<u32>, String)> = s
        .network_rules
        .iter()
        .map(|r| {
            (
                direction(&r.dir).to_string(),
                r.proto.clone(),
                r.port.as_deref().and_then(|p| p.trim().parse().ok()),
                PeerView::from_rule(r).identity(),
            )
        })
        .collect();
    // Not read is not "no rules": a null section, and never a version.
    let network = if s.network_unread.is_some() {
        Value::Null
    } else {
        json!({
            "rules": rules.into_iter().map(|(dir, proto, port, peer)| json!({
                "direction": dir, "protocol": proto, "port": port, "peer": peer
            })).collect::<Vec<_>>(),
        })
    };

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
            "coverage": p.posture.head.coverage,
            "unknownDimensions": p.posture.unknown_dimensions,
        },
        "dimensions": {
            "network": { "status": d.network.env.status },
            "syscalls": { "status": d.syscalls.env.status },
            "podSecurity": {
                "status": d.pod_security.env.status,
                "level": d.pod_security.analysis.level,
                "levelConfidence": d.pod_security.analysis.level_confidence,
            },
            "images": {
                "status": d.images.env.status,
                "runningDigests": if d.images.containers.is_empty() { Value::Null } else { json!(running.len()) },
                "mixedDigests": if d.images.containers.is_empty() { Value::Null } else { json!(d.images.containers.iter().any(|c| c.mixed_digests)) },
                "signature": d.images.supply_chain.as_ref().map(|sc| &sc.verdict),
            },
            "compute": { "status": d.compute.env.status },
        },
        "findingCounts": counts,
        "drift": {
            "count": p.drift.items.len(),
            "byType": p.drift.items.iter().fold(BTreeMap::<&str, usize>::new(), |mut m, i| {
                *m.entry(i.kind).or_default() += 1;
                m
            }),
        },
    })
}

/// Outcome of one snapshot write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotOutcome {
    Unchanged(i32),
    NewVersion(i32),
    /// Another writer stored a DIFFERENT profile at the revision this one
    /// would have taken (two brokers racing). Nothing is written; the next
    /// visit recomputes on top of the winner.
    LostRace(i32),
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
        store_with_head(conn, key, p, cap, head)
    })
}

/// The write half of [`store_snapshot`], given the head this writer read.
/// Split out so a test can hand it a head that another writer has already
/// moved past (the race the ON CONFLICT guard exists for).
fn store_with_head(
    conn: &mut PgConnection,
    key: &Key,
    p: &Profile,
    cap: i64,
    head: Option<StoredVersionHead>,
) -> Result<SnapshotOutcome, DbError> {
    {
        let changed = head
            .as_ref()
            .is_none_or(|h| h.content_hash != p.content_hash);
        let revision = match head.as_ref().filter(|_| !changed) {
            Some(h) => h.revision,
            None => {
                let h = &head;
                let rev = h.as_ref().map_or(1, |h| h.revision + 1);
                let posture = serde_json::to_value(&p.posture.head)?;
                let inserted = sql_query(
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
                if inserted == 0 {
                    // The revision exists already. Only an identical row
                    // lets this writer carry on and point latest at it.
                    #[derive(QueryableByName)]
                    struct H {
                        #[diesel(sql_type = Text)]
                        content_hash: String,
                    }
                    let existing: Option<H> = sql_query(
                        "SELECT content_hash FROM workload_profile_versions \
                         WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 \
                           AND workload_name = $4 AND revision = $5",
                    )
                    .bind::<Text, _>(DEFAULT_CLUSTER_ID)
                    .bind::<Text, _>(&key.namespace)
                    .bind::<Text, _>(&key.kind)
                    .bind::<Text, _>(&key.name)
                    .bind::<Integer, _>(rev)
                    .get_result(conn)
                    .optional()?;
                    if existing.is_none_or(|e| e.content_hash != p.content_hash) {
                        return Ok(SnapshotOutcome::LostRace(rev));
                    }
                }
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
                                      ELSE EXCLUDED.last_changed_at END \
             WHERE workload_profile_latest.revision <= EXCLUDED.revision",
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
    }
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

/// `EXISTS`: the workload keyed by the three SQL expressions has a pod the
/// controller still reports (an ownerless pod is keyed `("Pod", name)`).
macro_rules! alive_sql {
    ($ns:expr, $kind:expr, $name:expr) => {
        concat!(
            "EXISTS (SELECT 1 FROM pod_details pd WHERE NOT pd.is_dead \
               AND pd.pod_namespace = ",
            $ns,
            " AND ((pd.workload_kind = ",
            $kind,
            " AND pd.workload_name = ",
            $name,
            ") OR (",
            $kind,
            " = 'Pod' AND pd.pod_name = ",
            $name,
            " AND pd.workload_kind IS NULL)))"
        )
    };
}

/// Workloads with any source data, minus `$3..$5` (visited this tick):
/// those with alive pods first, then by last attempt (never attempted
/// first), so finished Jobs and replaced ReplicaSets cannot keep live
/// workloads waiting.
const CANDIDATES_SQL: &str = concat!(
    "WITH k AS ( \
        SELECT pod_namespace AS ns, workload_kind AS kind, workload_name AS name FROM workload_containers \
        UNION SELECT pod_namespace, workload_kind, workload_name FROM workload_syscalls \
        UNION SELECT pod_namespace, workload_kind, workload_name FROM pod_details \
              WHERE NOT is_dead AND pod_namespace IS NOT NULL AND workload_kind IS NOT NULL AND workload_name IS NOT NULL \
    ) \
    SELECT k.ns, k.kind, k.name FROM k \
    LEFT JOIN workload_profile_latest l ON l.cluster_id = $1 AND l.pod_namespace = k.ns \
         AND l.workload_kind = k.kind AND l.workload_name = k.name \
    LEFT JOIN workload_profile_failures f ON f.cluster_id = $1 AND f.pod_namespace = k.ns \
         AND f.workload_kind = k.kind AND f.workload_name = k.name \
    WHERE NOT EXISTS (SELECT 1 FROM unnest($3::text[], $4::text[], $5::text[]) AS s(ns, kind, name) \
                      WHERE s.ns = k.ns AND s.kind = k.kind AND s.name = k.name) \
    ORDER BY ",
    alive_sql!("k.ns", "k.kind", "k.name"),
    " DESC, GREATEST(l.computed_at, f.failed_at) ASC NULLS FIRST, k.ns, k.kind, k.name \
    LIMIT $2"
);

/// The next `batch` candidates after `seen`.
fn candidates(conn: &mut PgConnection, batch: i64, seen: &[KeyRow]) -> QueryResult<Vec<KeyRow>> {
    sql_query(CANDIDATES_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<BigInt, _>(batch)
        .bind::<Array<Text>, _>(seen.iter().map(|k| k.ns.as_str()).collect::<Vec<_>>())
        .bind::<Array<Text>, _>(seen.iter().map(|k| k.kind.as_str()).collect::<Vec<_>>())
        .bind::<Array<Text>, _>(seen.iter().map(|k| k.name.as_str()).collect::<Vec<_>>())
        .load(conn)
}

/// Longest `lastError` kept (the database's message, never a statement).
pub const FAILURE_MESSAGE_MAX: usize = 512;

/// Remember that the last snapshot attempt for `key` failed and why.
fn record_failure(conn: &mut PgConnection, key: &Key, error: &str) -> QueryResult<()> {
    let mut msg = error.to_string();
    if msg.len() > FAILURE_MESSAGE_MAX {
        let mut cut = FAILURE_MESSAGE_MAX;
        while !msg.is_char_boundary(cut) {
            cut -= 1;
        }
        msg.truncate(cut);
    }
    sql_query(
        "INSERT INTO workload_profile_failures \
         (cluster_id, pod_namespace, workload_kind, workload_name, last_error, failed_at) \
         VALUES ($1, $2, $3, $4, $5, timezone('UTC', NOW())) \
         ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name) DO UPDATE SET \
           last_error = EXCLUDED.last_error, failed_at = EXCLUDED.failed_at",
    )
    .bind::<Text, _>(DEFAULT_CLUSTER_ID)
    .bind::<Text, _>(&key.namespace)
    .bind::<Text, _>(&key.kind)
    .bind::<Text, _>(&key.name)
    .bind::<Text, _>(&msg)
    .execute(conn)
    .map(|_| ())
}

fn clear_failure(conn: &mut PgConnection, key: &Key) -> QueryResult<usize> {
    sql_query(
        "DELETE FROM workload_profile_failures WHERE cluster_id = $1 AND pod_namespace = $2 \
         AND workload_kind = $3 AND workload_name = $4",
    )
    .bind::<Text, _>(DEFAULT_CLUSTER_ID)
    .bind::<Text, _>(&key.namespace)
    .bind::<Text, _>(&key.kind)
    .bind::<Text, _>(&key.name)
    .execute(conn)
}

/// Failure rows of workloads with no source data left: never visited
/// again, so they would otherwise stay forever.
const FAILURES_PRUNE_SQL: &str = concat!(
    "DELETE FROM workload_profile_failures f WHERE f.cluster_id = $1 \
       AND NOT EXISTS (SELECT 1 FROM workload_containers wc WHERE wc.pod_namespace = f.pod_namespace \
             AND wc.workload_kind = f.workload_kind AND wc.workload_name = f.workload_name) \
       AND NOT EXISTS (SELECT 1 FROM workload_syscalls ws WHERE ws.pod_namespace = f.pod_namespace \
             AND ws.workload_kind = f.workload_kind AND ws.workload_name = f.workload_name) \
       AND NOT ",
    alive_sql!("f.pod_namespace", "f.workload_kind", "f.workload_name")
);

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
    if let Some(why) = &sources.network_unread {
        // Served live as a partial profile, never versioned: a snapshot
        // with no rules would read as every peer removed.
        return Err(format!("network dimension not read; profile not snapshotted: {why}").into());
    }
    let p = build(key, &sources, Utc::now());
    store_snapshot(conn, key, &p, cap).map(Some)
}

/// What one tick did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickStats {
    pub computed: usize,
    pub new_versions: usize,
    pub failed: usize,
    pub batches: usize,
}

/// One snapshotter tick. Sequential: one workload's reads at a time. Takes
/// batches of `batch` candidates until none are left or `budget` has
/// passed (the first batch always runs). A failed workload gets a
/// `workload_profile_failures` row; a computed one loses it.
pub fn snapshot_tick(
    conn: &mut PgConnection,
    batch: i64,
    cap: i64,
    budget: Duration,
) -> Result<TickStats, DbError> {
    let started = std::time::Instant::now();
    let mut stats = TickStats::default();
    let mut seen: Vec<KeyRow> = Vec::new();
    loop {
        let keys = candidates(conn, batch, &seen)?;
        if keys.is_empty() {
            break;
        }
        let full = keys.len() as i64 >= batch;
        stats.batches += 1;
        for k in keys {
            let key = Key {
                namespace: k.ns.clone(),
                kind: k.kind.clone(),
                name: k.name.clone(),
            };
            match snapshot_one(conn, &key, cap) {
                Ok(outcome) => {
                    stats.computed += 1;
                    if matches!(outcome, Some(SnapshotOutcome::NewVersion(_))) {
                        stats.new_versions += 1;
                    }
                    clear_failure(conn, &key)?;
                }
                Err(e) => {
                    stats.failed += 1;
                    warn!(namespace = %key.namespace, kind = %key.kind, name = %key.name, error = %e,
                        "workload profile snapshot failed");
                    if let Err(e) = record_failure(conn, &key, &e.to_string()) {
                        warn!(namespace = %key.namespace, kind = %key.kind, name = %key.name, error = %e,
                            "could not record the snapshot failure");
                    }
                }
            }
            seen.push(k);
        }
        if !full
            || started.elapsed() >= budget
            || !crate::leader::still_leader("workload profile snapshotter")
        {
            break;
        }
    }
    sql_query(FAILURES_PRUNE_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .execute(conn)?;
    Ok(stats)
}

/// Spawn the snapshotter loop.
pub fn spawn(pool: DbPool) {
    let interval = snapshot_interval();
    let batch = snapshot_batch();
    let cap = max_versions_per_workload();
    let budget = snapshot_tick_budget(interval);
    info!(
        interval_secs = interval.as_secs(),
        batch,
        budget_secs = budget.as_secs(),
        cap,
        "workload profile snapshotter scheduled"
    );
    actix_web::rt::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            // Leader only (leader.rs): two replicas snapshotting the same
            // workload can both see the old hash and both write a version.
            if !crate::leader::is_leader() {
                tokio::time::sleep(interval).await;
                continue;
            }
            let pool = pool.clone();
            let r = tokio::task::spawn_blocking(move || -> Result<TickStats, DbError> {
                let mut conn = pool.get()?;
                snapshot_tick(&mut conn, batch, cap, budget)
            })
            .await;
            match r {
                Ok(Ok(t)) => {
                    if t.new_versions > 0 || t.failed > 0 {
                        info!(
                            computed = t.computed,
                            new_versions = t.new_versions,
                            failed = t.failed,
                            batches = t.batches,
                            "workload profiles snapshotted"
                        );
                    } else {
                        debug!(
                            computed = t.computed,
                            batches = t.batches,
                            "workload profiles snapshotted; no changes"
                        );
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
    /// Case-insensitive substring of the workload name.
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub after: Option<String>,
    /// `true` also lists workloads none of whose pods are alive (finished
    /// Jobs, replaced ReplicaSets, deleted Deployments still in the read
    /// model). Default `false`.
    pub include_gone: Option<bool>,
}

/// A list row: the last good profile (null fields when the workload has
/// never been computed) and the last failure, if the most recent attempt
/// failed.
#[derive(Debug, Clone, QueryableByName)]
struct ListRow {
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Text)]
    pod_namespace: String,
    #[diesel(sql_type = Text)]
    workload_kind: String,
    #[diesel(sql_type = Text)]
    workload_name: String,
    #[diesel(sql_type = Nullable<Integer>)]
    revision: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    content_hash: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    summary: Option<Value>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    computed_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    last_changed_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    failed_at: Option<NaiveDateTime>,
}

/// Computed and failed workloads, one row each; `$10` (include_gone) false
/// keeps only workloads with an alive pod.
const LIST_SQL: &str = concat!(
    "WITH k AS ( \
        SELECT pod_namespace, workload_kind, workload_name FROM workload_profile_latest WHERE cluster_id = $1 \
        UNION \
        SELECT pod_namespace, workload_kind, workload_name FROM workload_profile_failures WHERE cluster_id = $1 \
    ) \
    SELECT $1::text AS cluster_id, k.pod_namespace, k.workload_kind, k.workload_name, \
           l.revision, l.content_hash, l.summary, l.computed_at, l.last_changed_at, \
           f.last_error, f.failed_at \
    FROM k \
    LEFT JOIN workload_profile_latest l ON l.cluster_id = $1 AND l.pod_namespace = k.pod_namespace \
         AND l.workload_kind = k.workload_kind AND l.workload_name = k.workload_name \
    LEFT JOIN workload_profile_failures f ON f.cluster_id = $1 AND f.pod_namespace = k.pod_namespace \
         AND f.workload_kind = k.workload_kind AND f.workload_name = k.workload_name \
    WHERE ($2::text IS NULL OR k.pod_namespace = $2) \
      AND ($3::text IS NULL OR k.workload_kind = $3) \
      AND ($4::text IS NULL OR l.posture_status = $4) \
      AND ($5::text IS NULL OR (k.pod_namespace, k.workload_kind, k.workload_name) > ($5, $6, $7)) \
      AND ($9::text IS NULL OR strpos(lower(k.workload_name), lower($9)) > 0) \
      AND ($10 OR ",
    alive_sql!("k.pod_namespace", "k.workload_kind", "k.workload_name"),
    ") \
    ORDER BY k.pod_namespace, k.workload_kind, k.workload_name \
    LIMIT $8"
);

fn empty_to_none(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Parse `after` (`ns/kind/name`).
fn parse_after(s: &str) -> Option<(String, String, String)> {
    let mut it = s.splitn(3, '/');
    let (a, b, c) = (it.next()?, it.next()?, it.next()?);
    ([a, b, c].iter().all(|x| valid_segment(x))).then(|| (a.into(), b.into(), c.into()))
}

#[allow(clippy::too_many_arguments)]
pub fn list_workloads(
    conn: &mut PgConnection,
    namespace: Option<&str>,
    kind: Option<&str>,
    status: Option<&str>,
    search: Option<&str>,
    after: Option<&(String, String, String)>,
    include_gone: bool,
    limit: i64,
) -> Result<Value, DbError> {
    let mut rows: Vec<ListRow> = sql_query(LIST_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Nullable<Text>, _>(namespace)
        .bind::<Nullable<Text>, _>(kind)
        .bind::<Nullable<Text>, _>(status)
        .bind::<Nullable<Text>, _>(after.map(|a| a.0.as_str()))
        .bind::<Nullable<Text>, _>(after.map(|a| a.1.as_str()))
        .bind::<Nullable<Text>, _>(after.map(|a| a.2.as_str()))
        .bind::<BigInt, _>(limit + 1)
        .bind::<Nullable<Text>, _>(search)
        .bind::<diesel::sql_types::Bool, _>(include_gone)
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
                "computedAt": r.computed_at.map(utc),
                "lastChangedAt": r.last_changed_at.map(utc),
                "lastError": r.last_error,
                "failedAt": r.failed_at.map(utc),
            });
            if let (Value::Object(m), Some(Value::Object(s))) = (&mut item, r.summary) {
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
    let search = empty_to_none(q.search).filter(|x| x.len() <= MAX_SEGMENT);
    let include_gone = q.include_gone.unwrap_or(false);
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
            search.as_deref(),
            after.as_ref(),
            include_gone,
            limit,
        )
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(page))
}

#[get(
    "/workloads/{namespace}/{kind}/{name}/profile",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_profile(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    audit: Option<web::Data<crate::audit::AuditClient>>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    let Some(key) = Key::parse(ns, kind, name) else {
        return Ok(bad_key());
    };
    // 1. A cheap gate, without the profile's read permit: does the
    //    workload exist (the same test as `Sources::is_empty`), and does it
    //    run an image now? An unknown workload is 404 here, for one small
    //    query; only a running one reaches the evaluator.
    let gate = match budget.acquire(GATE_CHARGE_KIB).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let k = key.clone();
    let pool2 = pool.clone();
    let (known, running) = web::block(move || -> Result<(bool, bool), DbError> {
        let mut conn = pool2.get()?;
        workload_gate(&mut conn, &k)
    })
    .await?
    .map_err(crate::db_error_response)?;
    drop(gate);
    if !known {
        return Ok(not_found_workload());
    }
    // 2. The evaluator read, holding only its own 1 MiB charge (on a real
    //    read): async, at most 2 s, shared by concurrent requests and
    //    cached per namespace.
    let image_trust = if running {
        Some(
            crate::image_trust::for_workload(
                audit.as_ref().map(|a| a.get_ref()),
                &budget,
                &key.namespace,
                &key.kind,
                &key.name,
            )
            .await,
        )
    } else {
        None
    };
    // 3. Only now the profile's read permit, for the full read and build.
    let _permit = match budget.acquire(profile_charge_kib()).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || -> Result<Option<Profile>, DbError> {
        let mut conn = pool.get()?;
        let mut s = load_sources(&mut conn, &key)?;
        if s.is_empty() {
            return Ok(None);
        }
        s.image_trust = image_trust;
        Ok(Some(build(&key, &s, Utc::now())))
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(match out {
        Some(p) => HttpResponse::Ok().json(p),
        None => not_found_workload(),
    })
}

/// Read-budget charge of the profile's existence gate: one boolean.
const GATE_CHARGE_KIB: u32 = 1;

/// `known`: the workload has any of the data a profile is built from, the
/// same four sources as [`Sources::is_empty`] (inventory rows, a syscall
/// aggregate, a pod, a stored version). `running`: it has a current
/// (container, digest) pair, by the inventory's running predicate. Each
/// is an indexed EXISTS: one bounded row.
const GATE_SQL: &str = concat!(
    "SELECT (EXISTS (SELECT 1 FROM workload_containers WHERE pod_namespace = $2 \
               AND workload_kind = $3 AND workload_name = $4) \
          OR EXISTS (SELECT 1 FROM workload_syscalls WHERE pod_namespace = $2 \
               AND workload_kind = $3 AND workload_name = $4) \
          OR EXISTS (SELECT 1 FROM pod_details WHERE pod_namespace = $2 \
               AND ((workload_kind = $3 AND workload_name = $4) \
                    OR ($3 = 'Pod' AND pod_name = $4 AND workload_kind IS NULL))) \
          OR EXISTS (SELECT 1 FROM workload_profile_versions WHERE cluster_id = $1 \
               AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4)) AS known, \
     EXISTS (SELECT 1 FROM workload_containers wc \
     WHERE wc.pod_namespace = $2 AND wc.workload_kind = $3 \
       AND wc.workload_name = $4 AND ",
    crate::image_inventory::running_sql!("$5"),
    ") AS running"
);

/// `(known, running)` for the profile handler's gate; see [`GATE_SQL`].
pub fn workload_gate(conn: &mut PgConnection, key: &Key) -> Result<(bool, bool), DbError> {
    #[derive(QueryableByName)]
    struct G {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        known: bool,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        running: bool,
    }
    let r: G = sql_query(GATE_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<diesel::sql_types::Double, _>(image_inventory::running_window_secs() as f64)
        .get_result(conn)?;
    Ok((r.known, r.running))
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
    .map_err(crate::db_error_response)?;
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

/// The newest stored revision below `rev`.
fn load_snapshot_before(
    conn: &mut PgConnection,
    key: &Key,
    rev: i32,
) -> Result<Option<SnapshotRow>, DbError> {
    Ok(sql_query(
        "SELECT revision, content_hash, created_at, dimension_hashes, posture, snapshot \
         FROM workload_profile_versions \
         WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
           AND revision < $5 \
         ORDER BY revision DESC LIMIT 1",
    )
    .bind::<Text, _>(DEFAULT_CLUSTER_ID)
    .bind::<Text, _>(&key.namespace)
    .bind::<Text, _>(&key.kind)
    .bind::<Text, _>(&key.name)
    .bind::<Integer, _>(rev)
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
    .map_err(crate::db_error_response)?;
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
    if from.is_some_and(|f| f >= to_row.revision) {
        return Ok(DiffResult::BadOrder);
    }
    // An explicit `from` must exist. The default is the previous revision;
    // when retention trimmed it, fall back to the newest retained revision
    // below `to` (or to nothing) and say so with `fromTrimmed`.
    let (from_row, from_trimmed) = match from {
        Some(f) => match load_snapshot(conn, key, Some(f))? {
            Some(r) => (Some(r), false),
            None => return Ok(DiffResult::RevisionMissing),
        },
        None if to_row.revision == 1 => (None, false),
        None => match load_snapshot_before(conn, key, to_row.revision)? {
            Some(r) => {
                let trimmed = r.revision != to_row.revision - 1;
                (Some(r), trimmed)
            }
            None => (None, true),
        },
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
        "fromTrimmed": from_trimmed,
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
    .map_err(crate::db_error_response)?;
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

    /// Tests set `network`; the snapshot reads the distinct rule set.
    fn with_rules(mut s: Sources) -> Sources {
        s.network_rules = s.network.iter().map(NetRuleRow::from).collect();
        s
    }

    fn now() -> DateTime<Utc> {
        utc(ts(1)) + chrono::Duration::days(3)
    }

    #[test]
    fn empty_sources_are_all_unknown_and_never_count_as_ok() {
        let s = Sources {
            any_pods: true,
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        assert_eq!(p.posture.head.status, "unknown");
        assert_eq!(p.posture.head.coverage, 0.0);
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
        // No numeric score anywhere in the response (contract v1.2).
        assert!(v["posture"].get("score").is_none());
        assert!(v["posture"].get("grade").is_none());
        for d in ["network", "syscalls", "podSecurity", "images", "compute"] {
            assert!(v["dimensions"][d].get("score").is_none(), "{d}");
            assert!(v["dimensions"][d].get("scored").is_none(), "{d}");
        }
        assert_eq!(v["posture"]["reasons"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn rollup_excludes_unknown_and_reports_coverage() {
        let s = Sources {
            containers: vec![container("app", restricted())],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        // podSecurity passes every evaluated check, but restricted is only
        // an upper bound, so it is unknown, never ok. images has an
        // inventory but no vulnerability data: unknown too (v1.3).
        assert_eq!(p.dimensions.pod_security.env.status, "unknown");
        assert_eq!(
            p.dimensions.pod_security.env.reasons[0].code,
            "pss_unverified"
        );
        assert_eq!(p.dimensions.images.env.status, "unknown");
        assert_eq!(p.posture.head.status, "unknown");
        assert_eq!(p.posture.head.coverage, 0.0);
        assert_eq!(
            p.posture.unknown_dimensions,
            vec!["network", "syscalls", "podSecurity", "images"]
        );
        let dims: Vec<&str> = p.posture.reasons.iter().map(|r| r.dimension).collect();
        assert_eq!(dims, vec!["network", "syscalls", "podSecurity", "images"]);
        assert!(p.posture.reasons.iter().all(|r| r.status == "unknown"));
        let images_reason = &p.posture.reasons[3].message;
        assert!(
            images_reason.contains("1 running digest(s)")
                && images_reason.contains("vulnerability data not configured"),
            "{images_reason}"
        );

        // Worst known status wins; unknown never counts as ok or risk.
        let env = |status| Envelope {
            status,
            coverage: Coverage {
                level: "full",
                fraction: None,
                observed_since: None,
                note: String::new(),
            },
            reasons: vec![],
        };
        let (a, b, c, d) = (env("ok"), env("warn"), env("unknown"), env("ok"));
        let (head, unknown) = rollup(&[
            ("network", &a),
            ("syscalls", &b),
            ("podSecurity", &c),
            ("images", &d),
        ]);
        assert_eq!(head.status, "warn");
        assert_eq!(head.coverage, 0.75);
        assert_eq!(unknown, vec!["podSecurity"]);
    }

    /// Contract v1.3: the rollup is ok only when no core dimension is
    /// unknown. With an unknown dimension, all-ok known dimensions give
    /// unknown (partial data); warn/risk still surface.
    #[test]
    fn rollup_is_never_ok_with_an_unknown_dimension() {
        let env = |status: &'static str| Envelope {
            status,
            coverage: Coverage {
                level: "full",
                fraction: None,
                observed_since: None,
                note: String::new(),
            },
            reasons: vec![],
        };
        let roll = |n: &'static str, sc: &'static str, ps: &'static str, im: &'static str| {
            let (a, b, c, d) = (env(n), env(sc), env(ps), env(im));
            rollup(&[
                ("network", &a),
                ("syscalls", &b),
                ("podSecurity", &c),
                ("images", &d),
            ])
        };
        // Three ok, one unknown: partial data, not ok.
        let (h, u) = roll("ok", "ok", "ok", "unknown");
        assert_eq!((h.status.as_str(), h.coverage), ("unknown", 0.75));
        assert_eq!(u, vec!["images"]);
        // Every dimension known and ok: ok.
        let (h, u) = roll("ok", "ok", "ok", "ok");
        assert_eq!((h.status.as_str(), h.coverage), ("ok", 1.0));
        assert!(u.is_empty());
        // Warn / risk surface even with unknown dimensions.
        assert_eq!(roll("warn", "ok", "unknown", "unknown").0.status, "warn");
        assert_eq!(roll("ok", "risk", "unknown", "ok").0.status, "risk");
        // Nothing known.
        let (h, u) = roll("unknown", "unknown", "unknown", "unknown");
        assert_eq!((h.status.as_str(), h.coverage), ("unknown", 0.0));
        assert_eq!(u.len(), 4);
    }

    /// Contract v1.3: images is unknown without vulnerability data even when
    /// the inventory is clean; inventory findings still appear as findings.
    #[test]
    fn images_unknown_without_vulnerability_data() {
        let mut c = container("app", restricted());
        c.digests[0].state = Some("waiting".into());
        c.digests[0].state_reason = Some("CrashLoopBackOff".into());
        let s = Sources {
            containers: vec![container("sidecar", restricted()), c],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let im = &p.dimensions.images;
        assert_eq!(im.env.status, "unknown");
        assert_eq!(im.env.reasons[0].code, "vulnerabilities_not_configured");
        assert!(im.env.reasons[0]
            .message
            .starts_with("1 running digest(s) across 2 container(s)"));
        assert!(im.vulnerabilities.is_none());
        assert!(p.findings.iter().any(|f| f.id == "images.crashLoop/app"));
        assert!(p.posture.unknown_dimensions.contains(&"images"));
    }

    fn sig(d: &str, verdict: &str, reason: Option<&str>, signers: Value) -> (String, SignatureRow) {
        (
            d.to_string(),
            SignatureRow {
                digest: d.into(),
                verdict: verdict.into(),
                reason: reason.map(Into::into),
                checked_at: ts(3),
                signer_count: signers.as_array().map_or(0, |a| a.len() as i64),
                signers,
            },
        )
    }

    fn keyless() -> Value {
        json!([{"signerKind": "keyless", "issuer": "https://token.actions.githubusercontent.com",
                "san": "https://github.com/example/app/.github/workflows/release.yaml@refs/heads/main"}])
    }

    /// Two containers, one digest each ('a' and 'b').
    fn two_containers(sigs: Vec<(String, SignatureRow)>) -> Sources {
        let mut b = container("sidecar", restricted());
        b.digests[0].digest = digest('b');
        Sources {
            containers: vec![container("app", restricted()), b],
            signatures: sigs.into_iter().collect(),
            ..Default::default()
        }
    }

    fn readiness<'a>(p: &'a Profile, id: &str) -> &'a Readiness {
        p.readiness.iter().find(|r| r.id == id).unwrap()
    }

    /// Contract v1.8: never checked is unknown, never ok or unsigned.
    #[test]
    fn supply_chain_not_checked_is_unknown() {
        let p = build(&key(), &two_containers(vec![]), now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.verdict.as_str(), sc.reason.as_deref()),
            ("unknown", Some("not_checked"))
        );
        assert_eq!(sc.counts.not_checked, 2);
        assert!(sc
            .digests
            .iter()
            .all(|d| d.verdict.is_none() && d.checked_at.is_none()));
        assert_eq!(p.dimensions.images.env.status, "unknown");
        let r = readiness(&p, "imageSigned");
        assert_eq!(r.ok, None);
        assert!(r.message.contains("2 not checked"), "{}", r.message);
        assert!(!p
            .findings
            .iter()
            .any(|f| f.id.contains("unsigned") || f.id.contains("signature")));
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(
            v["dimensions"]["images"]["supplyChain"]["counts"]["notChecked"],
            2
        );
    }

    /// Everything verified is readiness true, but never makes images ok.
    #[test]
    fn supply_chain_all_verified_is_ready_but_not_ok() {
        let s = two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "verified", None, keyless()),
        ]);
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(sc.verdict, "verified");
        assert_eq!(sc.signers, keyless());
        assert_eq!(sc.checked_at, Some(utc(ts(3))));
        assert_eq!(readiness(&p, "imageSigned").ok, Some(true));
        assert!(readiness(&p, "imageSigned").message.contains("not trusted"));
        assert_eq!(p.dimensions.images.env.status, "unknown");
        assert_ne!(p.posture.head.status, "ok");
    }

    /// The worst verdict wins; a known-bad beats unknown, unknown beats
    /// verified.
    #[test]
    fn supply_chain_worst_verdict_and_findings() {
        let s = two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "unknown", Some("registry_auth"), json!([])),
        ]);
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.verdict.as_str(), sc.reason.as_deref()),
            ("unknown", Some("registry_auth"))
        );
        assert_eq!(
            (sc.container.as_deref().unwrap(), sc.signers.clone()),
            ("sidecar", json!([]))
        );
        assert_eq!(readiness(&p, "imageSigned").ok, None);

        let s = two_containers(vec![
            sig(&digest('a'), "key_signed", Some("untrusted_key"), keyless()),
            sig(&digest('b'), "unknown", Some("timeout"), json!([])),
        ]);
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(sc.verdict, "key_signed");
        // Signers of a result that did not verify are never shown.
        assert_eq!(sc.signers, json!([]));
        assert_eq!(readiness(&p, "imageSigned").ok, Some(false));
        let f = p
            .findings
            .iter()
            .find(|f| f.id == "images.signatureNotVerified/app")
            .unwrap();
        assert_eq!(f.severity, "low");
        assert_eq!(p.dimensions.images.env.status, "unknown");

        let s = two_containers(vec![sig(&digest('a'), "unsigned", None, json!([]))]);
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(sc.verdict, "unsigned");
        assert_eq!((sc.counts.unsigned, sc.counts.not_checked), (1, 1));
        assert!(p
            .findings
            .iter()
            .any(|f| f.id == "images.unsigned/app" && f.severity == "low"));
        assert_eq!(p.dimensions.images.env.status, "unknown");
    }

    /// A verified result must name its signer: an empty signer list or a
    /// kind-only entry is unknown (`no_signer_identity`), never signed.
    #[test]
    fn supply_chain_verified_without_identity_is_unknown() {
        for signers in [
            json!([]),
            json!([{"signerKind": "keyless"}]),
            json!([{"signerKind": "keyless", "issuer": "https://x"}]),
            json!([{"signerKind": "key", "keyName": "k"}]),
            // A fingerprint without signerKind "key" is not an identity.
            json!([{"keyFingerprint": "e2312c28"}]),
        ] {
            let s = two_containers(vec![
                sig(&digest('a'), "verified", None, keyless()),
                sig(&digest('b'), "verified", None, signers.clone()),
            ]);
            let p = build(&key(), &s, now());
            let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
            assert_eq!(
                (sc.verdict.as_str(), sc.reason.as_deref()),
                ("unknown", Some("no_signer_identity")),
                "{signers}"
            );
            assert_eq!((sc.counts.verified, sc.counts.unknown), (1, 1), "{signers}");
            let d = sc.digests.iter().find(|d| d.digest == digest('b')).unwrap();
            assert_eq!(d.verdict.as_deref(), Some("unknown"));
            assert_eq!(d.signers, json!([]));
            assert_eq!(readiness(&p, "imageSigned").ok, None, "{signers}");
        }
        // A key fingerprint alone is an identity.
        let s = two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(
                &digest('b'),
                "verified",
                None,
                json!([{"signerKind": "key", "keyFingerprint": "e2312c28"}]),
            ),
        ]);
        let p = build(&key(), &s, now());
        assert_eq!(
            p.dimensions.images.supply_chain.as_ref().unwrap().verdict,
            "verified"
        );
        assert_eq!(readiness(&p, "imageSigned").ok, Some(true));
    }

    /// signersOmitted counts the signers beyond the listed ones.
    #[test]
    fn supply_chain_counts_omitted_signers() {
        let (d, mut row) = sig(&digest('a'), "verified", None, keyless());
        row.signer_count = 11;
        let mut s = two_containers(vec![
            (d, row),
            sig(&digest('b'), "verified", None, keyless()),
        ]);
        s.containers.truncate(1);
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.signers_omitted, sc.digests[0].signers_omitted),
            (10, 10)
        );
        let v = serde_json::to_value(sc).unwrap();
        assert_eq!(v["signersOmitted"], 10);
        // Omitted when zero.
        let p = build(
            &key(),
            &two_containers(vec![sig(&digest('a'), "verified", None, keyless())]),
            now(),
        );
        let v = serde_json::to_value(p.dimensions.images.supply_chain.as_ref().unwrap()).unwrap();
        assert!(v.get("signersOmitted").is_none());
    }

    /// Guard for when vulnerability data is wired: images is `ok` only
    /// when the findings allow it AND every current digest verified.
    #[test]
    fn images_status_never_ok_with_unverified_signatures() {
        let sc = |s: Sources| build(&key(), &s, now()).dimensions.images.supply_chain;
        let verified = sc(two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "verified", None, keyless()),
        ]));
        let not_checked = sc(two_containers(vec![]));
        let unsigned = sc(two_containers(vec![sig(
            &digest('a'),
            "unsigned",
            None,
            json!([]),
        )]));
        let invalid = sc(two_containers(vec![sig(
            &digest('a'),
            "invalid",
            Some("bad_signature"),
            json!([]),
        )]));
        assert_eq!(images_status(true, &[], verified.as_ref()), "ok");
        assert_eq!(images_status(true, &[], not_checked.as_ref()), "unknown");
        assert_eq!(images_status(true, &[], unsigned.as_ref()), "unknown");
        assert_eq!(images_status(true, &[], None), "unknown");
        assert_eq!(images_status(true, &[], invalid.as_ref()), "risk");
        assert_eq!(images_status(false, &[], verified.as_ref()), "unknown");
        assert_eq!(images_status(false, &[], invalid.as_ref()), "risk");
        let medium = mk_finding(
            "images",
            "x".into(),
            "medium",
            None,
            String::new(),
            String::new(),
        );
        assert_eq!(images_status(true, &[medium], not_checked.as_ref()), "warn");
    }

    /// SIGNATURE_DISCOVERY_ENABLED: only an explicit off value is "not
    /// configured"; unset or anything else is configured.
    #[test]
    fn signature_discovery_configured_only_off_when_told() {
        for v in [
            None,
            Some(""),
            Some("true"),
            Some("1"),
            Some("yes"),
            Some("maybe"),
        ] {
            assert!(signature_discovery_configured_from(v), "{v:?}");
        }
        for v in ["false", "FALSE", " 0 ", "no", "off"] {
            assert!(!signature_discovery_configured_from(Some(v)), "{v}");
        }
    }

    /// Discovery switched off: supplyChain says not_configured, gates
    /// nothing, and stored results (from before it was switched off) are
    /// not used. Not the same as unknown or not_checked.
    #[test]
    fn supply_chain_not_configured_does_not_gate() {
        let mut s = two_containers(vec![sig(
            &digest('a'),
            "invalid",
            Some("bad_signature"),
            json!([]),
        )]);
        s.signature_discovery_off = true;
        let p = build(&key(), &s, now());
        let im = &p.dimensions.images;
        let sc = im.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.status, sc.verdict.as_str()),
            ("not_configured", "not_configured")
        );
        assert!(sc.digests.is_empty() && sc.container.is_none() && sc.reason.is_none());
        assert_eq!(
            im.env.status, "unknown",
            "no vulnerability data: unknown as before, not risk"
        );
        assert_eq!(im.env.reasons[1].code, "signatures_not_configured");
        assert!(!p
            .findings
            .iter()
            .any(|f| f.id.starts_with("images.signature") || f.id.starts_with("images.unsigned")));
        let r = readiness(&p, "imageSigned");
        assert_eq!(r.ok, None);
        assert!(r.message.contains("not configured"), "{}", r.message);
        let v = serde_json::to_value(sc).unwrap();
        assert_eq!(v["status"], "not_configured");
        assert_eq!(
            list_summary(&p)["dimensions"]["images"]["signature"],
            "not_configured"
        );
        // With vulnerability data, the findings alone decide: ok is reachable.
        assert_eq!(images_status(true, &[], Some(sc)), "ok");
        // No current digest: no supplyChain at all.
        let empty = Sources {
            signature_discovery_off: true,
            ..Default::default()
        };
        assert!(build(&key(), &empty, now())
            .dimensions
            .images
            .supply_chain
            .is_none());
    }

    /// The ruled modes with vulnerability data: configured and not all
    /// verified-with-a-named-signer -> never ok; not configured -> not
    /// gated; configured and all verified with named signers -> eligible.
    #[test]
    fn images_status_modes() {
        let sc = |s: Sources| build(&key(), &s, now()).dimensions.images.supply_chain;
        let configured_unverified = sc(two_containers(vec![sig(
            &digest('a'),
            "verified",
            None,
            keyless(),
        )]));
        let anonymous = sc(two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(
                &digest('b'),
                "verified",
                None,
                json!([{"signerKind": "keyless", "issuer": "https://x", "san": "   "}]),
            ),
        ]));
        let all_verified = sc(two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "verified", None, keyless()),
        ]));
        let mut off = two_containers(vec![]);
        off.signature_discovery_off = true;
        let not_configured = sc(off);
        assert_eq!(
            images_status(true, &[], configured_unverified.as_ref()),
            "unknown"
        );
        assert_eq!(images_status(true, &[], anonymous.as_ref()), "unknown");
        assert_eq!(images_status(true, &[], all_verified.as_ref()), "ok");
        assert_eq!(images_status(true, &[], not_configured.as_ref()), "ok");
    }

    /// Whitespace-only identity fields are missing (S1b).
    #[test]
    fn supply_chain_whitespace_identity_is_missing() {
        for signers in [
            json!([{"signerKind": "keyless", "issuer": "https://token.actions.githubusercontent.com", "san": "   "}]),
            json!([{"signerKind": "keyless", "issuer": " ", "san": "https://github.com/example/app"}]),
            json!([{"signerKind": "key", "keyFingerprint": "  "}]),
        ] {
            let s = two_containers(vec![
                sig(&digest('a'), "verified", None, keyless()),
                sig(&digest('b'), "verified", None, signers.clone()),
            ]);
            let p = build(&key(), &s, now());
            let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
            assert_eq!(
                (sc.verdict.as_str(), sc.reason.as_deref()),
                ("unknown", Some("no_signer_identity")),
                "{signers}"
            );
            assert_eq!(readiness(&p, "imageSigned").ok, None, "{signers}");
        }
    }

    /// An unrecognised verdict counts as unknown, never as verified.
    #[test]
    fn supply_chain_unrecognised_verdict_is_unknown() {
        let s = two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "trusted_somehow", None, json!([])),
        ]);
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(sc.verdict, "unknown");
        assert_eq!(sc.counts.unknown, 1);
        assert_eq!(readiness(&p, "imageSigned").ok, None);
    }

    /// An invalid signature is known-bad evidence: images and posture are
    /// risk even without vulnerability data.
    #[test]
    fn supply_chain_invalid_signature_is_risk() {
        let s = two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "invalid", Some("bad_signature"), json!([])),
        ]);
        let p = build(&key(), &s, now());
        let im = &p.dimensions.images;
        assert_eq!(im.env.status, "risk");
        assert_eq!(im.env.reasons[0].code, "vulnerabilities_not_configured");
        assert_eq!(im.env.reasons[1].code, "signatures");
        assert!(im.env.reasons[1]
            .message
            .starts_with("2 current digest(s): 1 invalid"));
        let sc = im.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.verdict.as_str(), sc.digest.clone()),
            ("invalid", Some(digest('b')))
        );
        let f = p
            .findings
            .iter()
            .find(|f| f.id == "images.signatureInvalid/sidecar")
            .unwrap();
        assert_eq!(f.severity, "high");
        assert!(p.attention.iter().any(|a| a.id == f.id));
        assert_eq!(p.posture.head.status, "risk");
        assert!(!p.posture.unknown_dimensions.contains(&"images"));
        assert_eq!(readiness(&p, "imageSigned").ok, Some(false));
    }

    /// Only current digests count; stale containers and no inventory give
    /// no supplyChain.
    #[test]
    fn supply_chain_current_digests_only() {
        assert!(build(&key(), &Sources::default(), now())
            .dimensions
            .images
            .supply_chain
            .is_none());
        let p = build(&key(), &Sources::default(), now());
        assert_eq!(readiness(&p, "imageSigned").ok, None);

        // A stale container (not running, not current) is ignored.
        let mut stale = container("legacy", restricted());
        stale.previous_digests = std::mem::take(&mut stale.digests);
        stale.previous_digests[0].digest = digest('c');
        stale.previous_digests[0].last_pod_name = None;
        let mut s = two_containers(vec![
            sig(&digest('a'), "verified", None, keyless()),
            sig(&digest('b'), "verified", None, keyless()),
            sig(&digest('c'), "invalid", Some("bad_signature"), json!([])),
        ]);
        s.containers.push(stale);
        s.running_window_seconds = 900;
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(sc.verdict, "verified");
        assert_eq!(sc.digests.len(), 2);
        assert_ne!(p.dimensions.images.env.status, "risk");
    }

    /// Current pairs are the running (container, digest) pairs, as drift
    /// reads them: a completed init container (current, not running) is not
    /// one, so its signature does not decide the verdict.
    #[test]
    fn supply_chain_uses_the_current_pairs() {
        let mut init = container("migrate", restricted());
        init.container_kind = "init".into();
        init.previous_digests = std::mem::take(&mut init.digests);
        init.previous_digests[0].digest = digest('c');
        init.previous_digests[0].ran_as_init = true;
        init.previous_digests[0].state = Some("terminated".into());
        let s = Sources {
            containers: vec![container("app", restricted()), init],
            live_pods: vec!["checkout-1".into()],
            signatures: [
                sig(&digest('a'), "verified", None, keyless()),
                sig(&digest('c'), "invalid", Some("bad_signature"), json!([])),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(sc.verdict, "verified");
        assert_eq!(sc.digests.len(), 1);
        assert_eq!(sc.digests[0].container, "app");
    }

    /// The workload changed between the handler's running-image gate and
    /// its full load. Pairs gone by the load: no supplyChain, images never
    /// ok (with or without the fetched imageTrust). Pairs appeared after a
    /// "not running" gate: supplyChain without imageTrust (null, not read),
    /// its verdict from the signature results alone (not_checked here).
    #[test]
    fn gate_and_load_disagreeing_is_still_correct() {
        let answer = crate::image_trust::shape(None, vec![], None, None, 20);
        // Gate said running, load finds only a stale container.
        let mut stale = container("app", restricted());
        stale.previous_digests = std::mem::take(&mut stale.digests);
        stale.previous_digests[0].last_pod_name = None;
        let gone = Sources {
            containers: vec![stale],
            running_window_seconds: 900,
            image_trust: Some(answer),
            ..Default::default()
        };
        let p = build(&key(), &gone, now());
        assert!(p.dimensions.images.supply_chain.is_none());
        assert_ne!(p.dimensions.images.env.status, "ok");
        assert_eq!(
            images_status(true, &[], None),
            "unknown",
            "no pairs is never ok"
        );
        // Gate said not running (no read), load finds a running image.
        let appeared = two_containers(vec![]);
        let p = build(&key(), &appeared, now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert!(sc.image_trust.is_none());
        assert_eq!(
            (sc.verdict.as_str(), sc.reason.as_deref()),
            ("unknown", Some("not_checked"))
        );
        assert_eq!(images_status(true, &[], Some(sc)), "unknown");
    }

    /// imageTrust (contract v1.9) rides on supplyChain, and like the
    /// signature results it never changes the snapshot hash or posture.
    #[test]
    fn supply_chain_carries_image_trust_outside_the_hash() {
        let base = two_containers(vec![sig(&digest('a'), "verified", None, keyless())]);
        let answer = crate::image_trust::shape(
            Some("2026-09-27T12:00:00Z".into()),
            vec![crate::image_trust::TrustResult {
                policy: "shop/p".into(),
                namespace: "shop".into(),
                workload: "Deployment/checkout".into(),
                container: "app".into(),
                digest: digest('a'),
                image: "ghcr.io/example/checkout".into(),
                verdict: "WouldDeny".into(),
                reason: Some("untrusted-signer".into()),
            }],
            None,
            None,
            20,
        );
        let with = Sources {
            image_trust: Some(answer),
            ..base.clone()
        };
        let a = build(&key(), &base, now());
        let b = build(&key(), &with, now());
        assert!(a
            .dimensions
            .images
            .supply_chain
            .as_ref()
            .unwrap()
            .image_trust
            .is_none());
        let it = b
            .dimensions
            .images
            .supply_chain
            .as_ref()
            .unwrap()
            .image_trust
            .as_ref()
            .unwrap();
        assert_eq!(it.would_deny, 1);
        assert_eq!(a.content_hash, b.content_hash);
        assert_eq!(a.posture.head.status, b.posture.head.status);
        assert_eq!(
            a.dimensions.images.env.status,
            b.dimensions.images.env.status
        );
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(
            v["dimensions"]["images"]["supplyChain"]["imageTrust"]["wouldDeny"],
            1
        );
        let v = serde_json::to_value(&a).unwrap();
        assert!(v["dimensions"]["images"]["supplyChain"]["imageTrust"].is_null());
    }

    /// Signature results are re-checked daily; they must not create new
    /// stored versions.
    #[test]
    fn supply_chain_does_not_change_the_snapshot_hash() {
        let a = build(&key(), &two_containers(vec![]), now());
        let b = build(
            &key(),
            &two_containers(vec![sig(
                &digest('a'),
                "invalid",
                Some("bad_signature"),
                json!([]),
            )]),
            now(),
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn pod_security_findings_drive_status_and_attention() {
        let s = Sources {
            containers: vec![container("app", json!({"privileged": true}))],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert_eq!(ps.analysis.level, Some(Level::Privileged));
        assert_eq!(ps.env.status, "risk");
        assert_eq!(p.posture.head.status, "risk");
        assert!(p
            .posture
            .reasons
            .iter()
            .any(|r| r.dimension == "podSecurity" && r.status == "risk"));
        assert!(p
            .attention
            .iter()
            .any(|f| f.id == "podSecurity.privileged/app" && f.tier == Some("P1")));
        assert!(ps.analysis.recommendation.is_some());
    }

    /// Review of #1669: a clean app container plus an init container that
    /// fails restricted checks must roll the workload down to baseline and
    /// the dimension to warn, never "ok / restricted".
    #[test]
    fn failing_init_container_lowers_the_workload_level_and_status() {
        let mut init = container("migrate", json!({}));
        init.container_kind = "init".into();
        // A completed init container is not running: it is evaluated from
        // its last known row.
        init.previous_digests = std::mem::take(&mut init.digests);
        init.previous_digests[0].state = Some("terminated".into());
        init.previous_digests[0].ran_as_init = true;
        let s = Sources {
            containers: vec![container("app", restricted()), init],
            live_pods: vec!["checkout-1".into()],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert!(ps.stale_containers.is_empty());
        let app = &ps.analysis.containers[0];
        let mig = &ps.analysis.containers[1];
        assert_eq!((app.name.as_str(), app.level), ("app", Level::Restricted));
        assert_eq!((mig.name.as_str(), mig.level), ("migrate", Level::Baseline));
        assert_eq!(mig.source, "last_known");
        let failing: Vec<&str> = mig.failing.iter().map(|f| f.check).collect();
        assert!(failing.contains(&"privilegeEscalation"));
        assert!(failing.contains(&"capabilitiesRestricted"));
        assert_eq!(ps.analysis.level, Some(Level::Baseline));
        assert_eq!(ps.analysis.level_confidence, Some("upper_bound"));
        assert_eq!(ps.env.status, "warn");
        assert_eq!(ps.env.reasons[0].code, "pss_fails_restricted");
        assert!(ps.env.reasons[0].message.contains("migrate (init)"));
        assert!(!ps.env.reasons[0].message.contains("app"));
        assert_ne!(p.posture.head.status, "ok");
        assert!(p
            .posture
            .reasons
            .iter()
            .any(|r| r.dimension == "podSecurity" && r.message.contains("migrate (init)")));
        assert_eq!(p.readiness[4].ok, Some(false));
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["dimensions"]["podSecurity"]["level"], json!("baseline"));
        let y = ps.analysis.recommendation.as_ref().unwrap().yaml.clone();
        assert!(y.contains("initContainers:\n      - name: migrate"));
        assert!(!y.contains("name: app"));
    }

    /// Ephemeral containers count toward the level too (PSS covers them).
    #[test]
    fn failing_ephemeral_container_lowers_the_workload_level() {
        let mut dbg = container("debugger", json!({"privileged": true}));
        dbg.container_kind = "ephemeral".into();
        let s = Sources {
            containers: vec![container("app", restricted()), dbg],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert_eq!(ps.analysis.level, Some(Level::Privileged));
        assert_eq!(ps.env.status, "risk");
    }

    /// Status is a tier rule (contract v1.2): privileged -> risk,
    /// baseline -> at least warn, restricted only as an upper bound ->
    /// never ok.
    #[test]
    fn pod_security_status_rules() {
        let f = |sev| {
            mk_finding(
                "podSecurity",
                "x".into(),
                sev,
                None,
                String::new(),
                String::new(),
            )
        };
        let ub = Some("upper_bound");
        assert_eq!(pod_security_status(Level::Restricted, ub, &[]), "unknown");
        assert_eq!(
            pod_security_status(Level::Restricted, ub, &[f("low")]),
            "unknown"
        );
        assert_eq!(
            pod_security_status(Level::Restricted, Some("confirmed"), &[]),
            "ok"
        );
        assert_eq!(pod_security_status(Level::Baseline, ub, &[]), "warn");
        assert_eq!(
            pod_security_status(Level::Baseline, ub, &[f("high")]),
            "risk"
        );
        assert_eq!(
            pod_security_status(Level::Privileged, Some("confirmed"), &[]),
            "risk"
        );
    }

    /// Review item 2: a privileged container, or hostNetwork alone, is risk
    /// (it used to score 50 / 70 and read warn).
    #[test]
    fn privileged_container_or_host_network_alone_is_risk() {
        let s = Sources {
            containers: vec![container("app", json!({"privileged": true}))],
            ..Default::default()
        };
        assert_eq!(
            build(&key(), &s, now()).dimensions.pod_security.env.status,
            "risk"
        );

        let mut c = container("agent", restricted());
        c.digests[0].pod_security = json!({"serviceAccountName": "agent", "hostNetwork": true, "automountServiceAccountToken": false});
        let s = Sources {
            containers: vec![c],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        assert_eq!(
            p.dimensions.pod_security.analysis.level,
            Some(Level::Privileged)
        );
        assert_eq!(p.dimensions.pod_security.env.status, "risk");
        assert_eq!(p.posture.head.status, "risk");
    }

    /// Review item 3: a restricted upper bound never reads as ready.
    #[test]
    fn restricted_upper_bound_readiness_is_unknown() {
        let s = Sources {
            containers: vec![container("app", restricted())],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        assert_eq!(
            p.dimensions.pod_security.analysis.level,
            Some(Level::Restricted)
        );
        let r = &p.readiness[4];
        assert_eq!(r.id, "podSecurityRestricted");
        assert_eq!(r.ok, None);
        assert!(r.message.contains("not confirmed"));
        assert_ne!(p.dimensions.pod_security.env.status, "ok");
    }

    /// Review item 1: only an ephemeral container fails -> no patch at all
    /// (a bare template would be a strategic-merge deletion), plus a reason.
    #[test]
    fn ephemeral_only_failure_yields_no_patch() {
        let mut dbg = container("debugger", json!({}));
        dbg.container_kind = "ephemeral".into();
        let mut app = container("app", restricted());
        app.digests[0].pod_security = json!({
            "serviceAccountName": "app",
            "automountServiceAccountToken": false,
            "securityContext": {"runAsNonRoot": true, "seccompProfileType": "RuntimeDefault"}
        });
        dbg.digests[0].pod_security = app.digests[0].pod_security.clone();
        let s = Sources {
            containers: vec![app, dbg],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert_eq!(ps.analysis.level, Some(Level::Baseline));
        assert!(ps.analysis.recommendation.is_none());
        assert!(ps
            .env
            .reasons
            .iter()
            .any(|r| r.code == "ephemeral_unpatchable" && r.message.contains("debugger")));
    }

    /// Review item 5: a container no longer in the spec (renamed/removed:
    /// no running row, not refreshed, its pod gone) neither lowers the level
    /// nor enters the patch; it is listed as stale.
    #[test]
    fn stale_container_is_listed_not_evaluated() {
        let mut old = container("old-sidecar", json!({"privileged": true}));
        old.previous_digests = std::mem::take(&mut old.digests);
        old.previous_digests[0].last_pod_name = Some("checkout-gone".into());
        let mut app = container("app", restricted());
        app.digests[0].pod_security = json!({
            "serviceAccountName": "app",
            "automountServiceAccountToken": false,
            "securityContext": {"runAsNonRoot": true, "seccompProfileType": "RuntimeDefault"}
        });
        let s = Sources {
            containers: vec![app, old],
            live_pods: vec!["checkout-1".into()],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert_eq!(ps.analysis.containers.len(), 1);
        assert_eq!(ps.analysis.level, Some(Level::Restricted));
        assert_eq!(ps.stale_containers.len(), 1);
        assert_eq!(ps.stale_containers[0].name, "old-sidecar");
        assert!(ps.analysis.recommendation.is_none());
        assert!(!p.findings.iter().any(|f| f.id.contains("old-sidecar")));
        let im = &p.dimensions.images.containers;
        assert!(im.iter().any(|c| c.name == "old-sidecar" && c.stale));
        assert!(p.snapshot["images"]["containers"]
            .get("old-sidecar")
            .is_none());

        // Freshly refreshed, it is current again even with its pod gone.
        let mut fresh = s.clone();
        fresh.containers[1].previous_digests[0].last_seen = now().naive_utc();
        let p = build(&key(), &fresh, now());
        assert_eq!(
            p.dimensions.pod_security.analysis.level,
            Some(Level::Privileged)
        );
    }

    /// Review item 7: an empty or malformed pod-level block makes the host
    /// namespace checks unevaluated, never a pass.
    #[test]
    fn missing_pod_block_leaves_host_namespaces_unevaluated() {
        for bad in [json!({}), json!({"hostNetwork": "yes"}), json!(null)] {
            let mut c = container("app", restricted());
            c.digests[0].pod_security = bad.clone();
            let s = Sources {
                containers: vec![c],
                ..Default::default()
            };
            let p = build(&key(), &s, now());
            let ps = &p.dimensions.pod_security;
            assert!(!ps.analysis.pod.known, "{bad}");
            assert!(
                ps.analysis.unevaluated_checks.contains(&"hostNamespaces"),
                "{bad}"
            );
            assert!(ps.analysis.pod.host_network.is_none());
            assert!(ps
                .env
                .reasons
                .iter()
                .any(|r| r.code == "pod_fields_unknown"));
            // No pod-level finding is invented from missing data.
            assert!(!p
                .findings
                .iter()
                .any(|f| f.id == "podSecurity.automountToken"));
            assert_ne!(ps.env.status, "ok");
        }
        // A container that leaves runAsNonRoot / seccomp to the pod cannot be
        // failed on them when the pod block is unknown.
        let mut c = container(
            "app",
            json!({"allowPrivilegeEscalation": false, "capabilitiesDrop": ["ALL"]}),
        );
        c.digests[0].pod_security = json!({});
        let s = Sources {
            containers: vec![c],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        let ps = &p.dimensions.pod_security;
        assert!(ps.analysis.containers[0].failing.is_empty());
        assert!(ps.analysis.unevaluated_checks.contains(&"runAsNonRoot"));
        assert!(ps
            .analysis
            .unevaluated_checks
            .contains(&"seccompRestricted"));
        assert_eq!(ps.analysis.level, Some(Level::Restricted));
        assert_eq!(ps.analysis.level_confidence, Some("upper_bound"));
    }

    #[test]
    fn network_is_unknown_without_audit_and_known_with_it() {
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
        assert_eq!(n.env.status, "warn");
        assert_eq!(p.controls[0].state, Some("audit"));
        assert_eq!(p.controls[0].in_sync, Some(false));
    }

    /// The CR block carries both counts the seccomp summary has: the
    /// broker's node-status count and the CR's own `status.distribution`,
    /// which differ when a node stops reporting (48/48 beside 60/60).
    #[test]
    fn cr_status_distribution_is_mirrored_from_the_seccomp_summary() {
        let summary = |cr_extra: Value| {
            let mut v = json!({
                "hash": "h", "syscallCount": 3, "architectures": ["x86_64"],
                "updatedAt": "2026-09-14T00:33:00",
                "capture": {"level": "full", "complete": true, "incomplete": 0},
                "cr": {
                    "name": "media-transform-api", "defaultAction": "SCMP_ACT_LOG", "hash": "x",
                    "syscallCount": 2, "drift": {"missing": [], "extra": [], "inSync": true},
                    "distribution": {"ready": 48, "total": 48, "state": "Ready"}
                },
                "denials": null
            });
            if let (Value::Object(cr), Value::Object(x)) = (&mut v["cr"], cr_extra) {
                cr.extend(x);
            }
            serde_json::from_value::<SeccompSummary>(v).unwrap()
        };
        let with = summary(json!({
            "statusDistribution": {"ready": 60, "total": 60, "state": "Ready"}
        }));
        let names: BTreeSet<String> = ["read", "write"].iter().map(|x| x.to_string()).collect();
        let p = build(
            &key(),
            &Sources {
                seccomp: Some((with, names.clone())),
                ..Default::default()
            },
            now(),
        );
        let cr = p.dimensions.syscalls.cr.as_ref().unwrap();
        assert_eq!((cr.distribution.ready, cr.distribution.total), (48, 48));
        let sd = cr.status_distribution.as_ref().expect("mirrored");
        assert_eq!((sd.ready, sd.total, sd.state.as_str()), (60, 60, "Ready"));
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(
            v["dimensions"]["syscalls"]["cr"]["statusDistribution"],
            json!({"ready": 60, "total": 60, "state": "Ready"})
        );
        assert_eq!(
            v["dimensions"]["syscalls"]["cr"]["distribution"]["ready"],
            48
        );
        // A CR without one (older controller, or nothing distributed yet).
        for absent in [json!({}), json!({"statusDistribution": null})] {
            let p = build(
                &key(),
                &Sources {
                    seccomp: Some((summary(absent), names.clone())),
                    ..Default::default()
                },
                now(),
            );
            let v = serde_json::to_value(&p).unwrap();
            assert!(v["dimensions"]["syscalls"]["cr"]["statusDistribution"].is_null());
            assert_eq!(
                v["dimensions"]["syscalls"]["cr"]["distribution"]["ready"],
                48
            );
        }
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
                status_distribution: None,
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
        assert_eq!(sc.env.status, "warn", "drift, and incomplete capture");
        assert_eq!(sc.env.coverage.level, "partial");
        assert_eq!(p.controls[1].state, Some("enforcing"));
        assert_eq!(
            p.snapshot["syscalls"]["syscalls"],
            json!(["exit", "read", "write"])
        );
    }

    #[test]
    fn list_query_parses_include_gone() {
        let q: ListQuery = serde_urlencoded::from_str("limit=5&include_gone=true").unwrap();
        assert_eq!((q.limit, q.include_gone), (Some(5), Some(true)));
        let q: ListQuery = serde_urlencoded::from_str("namespace=shop").unwrap();
        assert_eq!(q.include_gone, None);
        assert!(serde_urlencoded::from_str::<ListQuery>("include_gone=maybe").is_err());
    }

    #[test]
    fn unread_network_is_unknown_with_the_reason_and_never_a_snapshot() {
        let key = Key {
            namespace: "shop".into(),
            kind: "Deployment".into(),
            name: "api".into(),
        };
        let why = "the flow aggregate was not read: the pod_traffic query exceeded 10000 ms";
        let s = Sources {
            any_pods: true,
            live_pods: vec!["api-1".into()],
            network_unread: Some(why.into()),
            ..Default::default()
        };
        let p = build(&key, &s, Utc::now());
        let n = &p.dimensions.network;
        assert_eq!(n.env.status, "unknown");
        assert_eq!(n.env.coverage.level, "none");
        assert_eq!(n.env.coverage.note, why);
        assert_eq!(n.env.reasons[0].code, "network_unread");
        assert_eq!(n.env.reasons[0].message, why);
        assert!(n.peers.is_empty() && !n.truncated);
        assert!(p.posture.unknown_dimensions.contains(&"network"));
        assert!(p.snapshot["network"].is_null(), "{}", p.snapshot);
        assert!(p.findings.iter().all(|f| f.dimension != "network"));
        assert!(!p.snapshot_pending, "no version will follow a partial read");
        // The same sources with the flows read: the usual empty answer.
        let read = Sources {
            network_unread: None,
            ..s
        };
        let p = build(&key, &read, Utc::now());
        assert_eq!(p.dimensions.network.env.reasons[0].code, "no_flows");
        assert!(p.snapshot_pending, "no stored version yet: pending");
        assert!(p
            .dimensions
            .network
            .env
            .coverage
            .note
            .starts_with("Flows from"));
        assert!(p.snapshot["network"]["rules"].is_array());
    }

    #[test]
    fn snapshot_hash_ignores_timestamps_and_counts() {
        let mut s = Sources {
            containers: vec![container("app", restricted())],
            network: vec![net("EGRESS", "443", None, None, "203.0.113.10")],
            any_pods: true,
            ..Default::default()
        };
        let a = build(&key(), &with_rules(s.clone()), now());
        s.network[0].flows = 999;
        s.network[0].last_seen = ts(9);
        s.containers[0].digests[0].last_seen = ts(9);
        // Truncation and the audit window do not move the hash either.
        s.network_truncated = true;
        s.audit = vec![AuditRow {
            policy_namespace: "payments".into(),
            policy_name: "checkout".into(),
            allow: 1,
            would_deny: 0,
            last: ts(4),
        }];
        let b = build(
            &key(),
            &with_rules(s.clone()),
            now() + chrono::Duration::hours(1),
        );
        assert_eq!(a.content_hash, b.content_hash);
        assert!(a.content_hash.starts_with("fnv1a64:"));

        s.containers[0].digests[0].digest = digest('b');
        let c = build(&key(), &with_rules(s.clone()), now());
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
        let a = build(&key(), &with_rules(s.clone()), now()).snapshot;
        s.containers[0].digests[0].digest = digest('b');
        s.containers[0].digests[0].security_context = restricted();
        s.network.push(net(
            "INGRESS",
            "8080",
            Some("pod"),
            Some("prometheus"),
            "10.0.0.5",
        ));
        let b = build(&key(), &with_rules(s.clone()), now()).snapshot;
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

    // ---- drift (P2-5) ----------------------------------------------------

    fn drift_types(p: &Profile) -> Vec<&'static str> {
        p.drift.items.iter().map(|i| i.kind).collect()
    }

    // ---- drift: unshippedExecutable (runtime inventory, #1683) ----------

    fn rt_entry(path: &str, origin: &str) -> crate::runtime_inventory::RuntimeEntry {
        crate::runtime_inventory::RuntimeEntry {
            path: path.into(),
            kind: "exec".into(),
            source: "ebpf".into(),
            origin: origin.into(),
            path_complete: true,
            first_seen: now().naive_utc(),
            last_seen: now().naive_utc(),
        }
    }

    fn cov(
        c: &str,
        d: &str,
        covered: Option<bool>,
        reason: Option<&str>,
    ) -> crate::runtime_inventory::CoverageView {
        crate::runtime_inventory::CoverageView {
            container_name: c.into(),
            image_digest: d.into(),
            instances: 1,
            last_heartbeat: now().naive_utc(),
            mode: "full".into(),
            libraries_tracked: true,
            covered,
            observed_since: None,
            reason: reason.map(String::from),
            window_hours: 24,
        }
    }

    /// Sources with container `app` running digest 'a' and the given
    /// runtime input.
    fn with_runtime(rt: Option<crate::profile_drift::RuntimeDriftInput>) -> Sources {
        Sources {
            containers: vec![container("app", restricted())],
            runtime: rt,
            ..Default::default()
        }
    }

    fn rt(
        has_inventory: bool,
        rows: Vec<(&str, String, Vec<crate::runtime_inventory::RuntimeEntry>)>,
        coverage: Vec<crate::runtime_inventory::CoverageView>,
        truncated: bool,
    ) -> Option<crate::profile_drift::RuntimeDriftInput> {
        Some(crate::profile_drift::RuntimeDriftInput {
            has_inventory,
            unshipped: rows
                .into_iter()
                .map(|(c, d, entries)| crate::profile_drift::UnshippedPair {
                    container: c.into(),
                    digest: d,
                    total: entries.len() as i64,
                    entries,
                })
                .collect(),
            pairs_truncated: truncated,
            coverage,
            coverage_unavailable: false,
        })
    }

    fn not_evaluated(p: &Profile) -> Vec<(Option<String>, String)> {
        p.drift
            .not_evaluated
            .iter()
            .filter(|n| n.kind == "unshippedExecutable")
            .map(|n| (n.container.clone(), n.reason.clone()))
            .collect()
    }

    #[test]
    fn unshipped_is_not_evaluated_without_inventory_or_coverage() {
        // Not loaded at all.
        let p = build(&key(), &with_runtime(None), now());
        assert!(!p.drift.evaluated.contains(&"unshippedExecutable"));
        assert_eq!(not_evaluated(&p), [(None, "no_inventory".to_string())]);
        // Loaded, no inventory for the workload.
        let p = build(
            &key(),
            &with_runtime(rt(false, vec![], vec![], false)),
            now(),
        );
        assert!(!p.drift.evaluated.contains(&"unshippedExecutable"));
        assert_eq!(
            not_evaluated(&p),
            [(Some("app".into()), "no_inventory".into())]
        );
        // Inventory, but no coverage row for the running digest.
        let p = build(
            &key(),
            &with_runtime(rt(true, vec![], vec![], false)),
            now(),
        );
        assert_eq!(
            not_evaluated(&p),
            [(Some("app".into()), "no_runtime_data".into())]
        );
        // Covered = false with the coverage function's reason.
        let p = build(
            &key(),
            &with_runtime(rt(
                true,
                vec![],
                vec![cov("app", &digest('a'), Some(false), Some("lost_events"))],
                false,
            )),
            now(),
        );
        assert_eq!(
            not_evaluated(&p),
            [(Some("app".into()), "lost_events".into())]
        );
        assert!(
            p.drift.items.is_empty(),
            "not evaluated is not drift either way"
        );
        // Covered, nothing unshipped: evaluated, no item.
        let p = build(
            &key(),
            &with_runtime(rt(
                true,
                vec![],
                vec![cov("app", &digest('a'), Some(true), None)],
                false,
            )),
            now(),
        );
        assert!(p.drift.evaluated.contains(&"unshippedExecutable"));
        assert!(not_evaluated(&p).is_empty());
        assert!(p.drift.items.is_empty());
        // Covered but more current pairs than were read: cannot say "none".
        let p = build(
            &key(),
            &with_runtime(rt(
                true,
                vec![],
                vec![cov("app", &digest('a'), Some(true), None)],
                true,
            )),
            now(),
        );
        assert_eq!(not_evaluated(&p), [(None, "truncated".into())]);
        assert!(!p.drift.evaluated.contains(&"unshippedExecutable"));
        // The coverage function itself is missing: its own reason, not
        // "no heartbeat".
        let mut input = rt(true, vec![], vec![], false).unwrap();
        input.coverage_unavailable = true;
        let p = build(&key(), &with_runtime(Some(input)), now());
        assert_eq!(
            not_evaluated(&p),
            [(Some("app".into()), "coverage_unavailable".into())]
        );
    }

    /// Every drift check that did not run is in notEvaluated with a
    /// reason, so an empty items list is never read as "no drift".
    #[test]
    fn every_check_not_evaluated_says_why() {
        let all = |p: &Profile| -> Vec<(&'static str, Option<String>, String)> {
            p.drift
                .not_evaluated
                .iter()
                .map(|n| (n.kind, n.container.clone(), n.reason.clone()))
                .collect()
        };
        // Nothing known at all.
        let p = build(&key(), &Sources::default(), now());
        assert!(p.drift.evaluated.is_empty());
        assert_eq!(
            all(&p),
            [
                ("unshippedExecutable", None, "no_inventory".to_string()),
                ("tagMoved", None, "no_image_inventory".to_string()),
                ("imageChangedSinceExport", None, "no_export".to_string()),
                ("securityContextRegression", None, "no_baseline".to_string()),
            ]
        );
        // An image inventory but no running container: the runtime check
        // says so instead of an empty list.
        // (the only digest is a previous one: nothing runs now).
        let mut c = container("app", restricted());
        let d = c.digests.remove(0);
        c.previous_digests.push(d);
        let p = build(
            &key(),
            &Sources {
                containers: vec![c],
                runtime: rt(true, vec![], vec![], false),
                ..Default::default()
            },
            now(),
        );
        assert!(p.drift.evaluated.contains(&"tagMoved"));
        assert!(all(&p).contains(&(
            "unshippedExecutable",
            None,
            "no_running_containers".to_string()
        )));
        // Every check is either evaluated or not evaluated, never neither.
        for t in [
            "tagMoved",
            "imageChangedSinceExport",
            "securityContextRegression",
            "unshippedExecutable",
        ] {
            let ne = p.drift.not_evaluated.iter().any(|n| n.kind == t);
            assert!(p.drift.evaluated.contains(&t) != ne, "{t}");
        }
    }

    #[test]
    fn an_unshipped_file_is_drift_whatever_the_coverage() {
        let rows = |origin: &str| {
            vec![(
                "app",
                digest('a'),
                vec![rt_entry("/tmp/x", origin), rt_entry("/usr/bin/ok", origin)],
            )]
        };
        // Not covered, a memfd exec: reported (high), and the check is
        // still listed as not evaluated for the rest.
        let p = build(
            &key(),
            &with_runtime(rt(true, rows("memfd"), vec![], false)),
            now(),
        );
        assert_eq!(drift_types(&p), ["unshippedExecutable"]);
        let i = &p.drift.items[0];
        assert_eq!((i.severity, i.container.as_deref()), ("high", Some("app")));
        assert_eq!(i.detail["origins"], json!(["memfd"]));
        assert_eq!(i.detail["filesTotal"], json!(2));
        assert_eq!(
            not_evaluated(&p),
            [(Some("app".into()), "no_runtime_data".into())]
        );
        assert!(p
            .findings
            .iter()
            .any(|f| f.id == "drift.unshippedExecutable/app"
                && f.dimension == "drift"
                && f.severity == "high"));
        // Writable layer: high. Deleted only: medium.
        let covered = vec![cov("app", &digest('a'), Some(true), None)];
        let p = build(
            &key(),
            &with_runtime(rt(true, rows("writableLayer"), covered.clone(), false)),
            now(),
        );
        assert_eq!(p.drift.items[0].severity, "high");
        assert!(p.drift.evaluated.contains(&"unshippedExecutable"));
        let p = build(
            &key(),
            &with_runtime(rt(true, rows("deleted"), covered.clone(), false)),
            now(),
        );
        assert_eq!(p.drift.items[0].severity, "medium");
        // Rows of a digest the container no longer runs are not current drift.
        let old = vec![("app", digest('z'), vec![rt_entry("/tmp/x", "memfd")])];
        let p = build(&key(), &with_runtime(rt(true, old, covered, false)), now());
        assert!(p.drift.items.is_empty());
    }

    #[test]
    fn unshipped_drift_never_sets_posture() {
        let covered = vec![cov("app", &digest('a'), Some(true), None)];
        let clean = build(
            &key(),
            &with_runtime(rt(true, vec![], covered.clone(), false)),
            now(),
        );
        let drifted = build(
            &key(),
            &with_runtime(rt(
                true,
                vec![("app", digest('a'), vec![rt_entry("/tmp/x", "memfd")])],
                covered,
                false,
            )),
            now(),
        );
        assert_eq!(drifted.drift.items.len(), 1);
        assert_eq!(
            serde_json::to_value(&clean.posture).unwrap(),
            serde_json::to_value(&drifted.posture).unwrap()
        );
        assert_eq!(
            clean.content_hash, drifted.content_hash,
            "drift is not in the snapshot"
        );
    }

    #[test]
    fn tag_moved_is_drift_but_a_retag_is_not() {
        let mut c = container("app", restricted());
        let mut old = cd(&digest('b'), restricted(), json!({}));
        old.state = Some("terminated".into());
        c.previous_digests.push(old.clone());
        let s = Sources {
            containers: vec![c.clone()],
            ..Default::default()
        };
        let p = build(&key(), &s, now());
        assert_eq!(drift_types(&p), vec!["tagMoved"]);
        let item = &p.drift.items[0];
        assert_eq!(item.container.as_deref(), Some("app"));
        assert_eq!(item.detail["imageRef"], json!("ghcr.io/example/checkout:1"));
        assert_eq!(item.detail["digests"], json!([digest('a'), digest('b')]));
        assert!(p.findings.iter().any(|f| f.id == "drift.tagMoved/app"
            && f.dimension == "drift"
            && f.severity == "medium"));
        assert!(p.drift.evaluated.contains(&"tagMoved"));

        // A new tag (a normal rollout) is not a moved tag.
        c.previous_digests[0].image_ref = "ghcr.io/example/checkout:0".into();
        let p = build(
            &key(),
            &Sources {
                containers: vec![c.clone()],
                ..Default::default()
            },
            now(),
        );
        assert!(p.drift.items.is_empty());

        // A digest reference cannot move.
        c.previous_digests[0].image_ref = format!("ghcr.io/example/checkout@{}", digest('b'));
        c.digests[0].image_ref = format!("ghcr.io/example/checkout@{}", digest('a'));
        let p = build(
            &key(),
            &Sources {
                containers: vec![c],
                ..Default::default()
            },
            now(),
        );
        assert!(p.drift.items.is_empty());
    }

    fn export_of(p: &Profile, revision: Option<i32>) -> crate::profile_drift::ExportBaseline {
        crate::profile_drift::ExportBaseline {
            id: 1,
            revision,
            content_hash: p.content_hash.clone(),
            mode: "audit".into(),
            artifacts: vec!["networkpolicy".into()],
            baseline: json!({
                "images": p.snapshot["images"].clone(),
                "podSecurity": p.snapshot["podSecurity"].clone(),
            }),
            exported_at: ts(2),
        }
    }

    #[test]
    fn image_drift_needs_an_export_and_names_new_digests() {
        let base = Sources {
            containers: vec![container("app", restricted())],
            ..Default::default()
        };
        let exported = build(&key(), &base, now());
        // Without an export the check does not run and nothing is claimed.
        assert!(!exported
            .drift
            .evaluated
            .contains(&"imageChangedSinceExport"));
        assert!(exported.drift.baselines.export.is_none());

        let mut s = base.clone();
        s.last_export = Some(export_of(&exported, Some(3)));
        // Same image as exported: evaluated, no drift.
        let p = build(&key(), &s, now());
        assert!(p.drift.evaluated.contains(&"imageChangedSinceExport"));
        assert!(p.drift.items.is_empty());
        assert_eq!(p.drift.baselines.export.as_ref().unwrap().revision, Some(3));

        // A new digest and a new container after the export.
        s.containers[0].digests[0].digest = digest('c');
        s.containers[0].digests[0].image_ref = "ghcr.io/example/checkout:2".into();
        s.containers.push(container("sidecar", restricted()));
        let p = build(&key(), &s, now());
        let items: Vec<(&str, Option<&str>)> = p
            .drift
            .items
            .iter()
            .map(|i| (i.kind, i.container.as_deref()))
            .collect();
        assert_eq!(
            items,
            vec![
                ("imageChangedSinceExport", Some("app")),
                ("imageChangedSinceExport", Some("sidecar")),
            ]
        );
        assert_eq!(p.drift.items[0].detail["newDigests"], json!([digest('c')]));
        assert_eq!(p.drift.items[1].detail["containerInExport"], json!(false));
    }

    #[test]
    fn security_context_regression_against_the_previous_version() {
        let before = build(
            &key(),
            &Sources {
                containers: vec![container("app", restricted())],
                ..Default::default()
            },
            now(),
        );
        let mut s = Sources {
            containers: vec![container(
                "app",
                json!({"privileged": true, "allowPrivilegeEscalation": false, "runAsNonRoot": true,
                       "capabilitiesDrop": ["ALL"], "seccompProfileType": "RuntimeDefault"}),
            )],
            ..Default::default()
        };
        // No baseline yet: not evaluated.
        let p = build(&key(), &s, now());
        assert!(!p.drift.evaluated.contains(&"securityContextRegression"));

        s.recent_versions = vec![crate::profile_drift::RecentVersion {
            revision: 4,
            created_at: ts(1),
            pod_security_hash: before.dimension_hashes.get("podSecurity").cloned(),
            pod_security: before.snapshot["podSecurity"].clone(),
        }];
        let p = build(&key(), &s, now());
        let reg: Vec<&crate::profile_drift::DriftItem> = p
            .drift
            .items
            .iter()
            .filter(|i| i.kind == "securityContextRegression")
            .collect();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0].severity, "high", "a baseline check newly fails");
        assert_eq!(reg[0].detail["newlyFailing"], json!(["privileged"]));
        assert_eq!(reg[0].detail["levelFrom"], json!("restricted"));
        assert_eq!(reg[0].detail["levelTo"], json!("privileged"));
        let b = p.drift.baselines.security_context.as_ref().unwrap();
        assert_eq!((b.source, b.revision), ("previousVersion", Some(4)));
        assert!(p
            .attention
            .iter()
            .any(|f| f.id == "drift.securityContextRegression/app"));

        // The version whose podSecurity equals the live one is skipped, so a
        // later unrelated version does not hide the regression.
        let live_hash = p.dimension_hashes.get("podSecurity").cloned();
        s.recent_versions.insert(
            0,
            crate::profile_drift::RecentVersion {
                revision: 5,
                created_at: ts(3),
                pod_security_hash: live_hash,
                pod_security: p.snapshot["podSecurity"].clone(),
            },
        );
        let p = build(&key(), &s, now());
        assert_eq!(
            p.drift
                .baselines
                .security_context
                .as_ref()
                .unwrap()
                .revision,
            Some(4)
        );
        assert!(drift_types(&p).contains(&"securityContextRegression"));

        // An improvement is not a regression.
        let mut better = s.clone();
        better.containers = vec![container("app", restricted())];
        better.recent_versions = vec![crate::profile_drift::RecentVersion {
            revision: 6,
            created_at: ts(4),
            pod_security_hash: Some("fnv1a64:other".into()),
            pod_security: p.snapshot["podSecurity"].clone(),
        }];
        let p = build(&key(), &better, now());
        assert!(p.drift.evaluated.contains(&"securityContextRegression"));
        assert!(!drift_types(&p).contains(&"securityContextRegression"));
    }

    #[test]
    fn the_export_is_the_security_context_baseline_when_present() {
        let accepted = build(
            &key(),
            &Sources {
                containers: vec![container("app", restricted())],
                ..Default::default()
            },
            now(),
        );
        let mut s = Sources {
            containers: vec![container("app", json!({}))],
            ..Default::default()
        };
        s.last_export = Some(export_of(&accepted, None));
        // A previous version that already had the weak context would hide
        // the regression; the export wins.
        s.recent_versions = vec![crate::profile_drift::RecentVersion {
            revision: 9,
            created_at: ts(3),
            pod_security_hash: Some("fnv1a64:x".into()),
            pod_security: json!({"containers": {"app": {"kind": "regular", "securityContext": {}}}, "pod": null, "level": "baseline"}),
        }];
        let p = build(&key(), &s, now());
        let b = p.drift.baselines.security_context.as_ref().unwrap();
        assert_eq!(b.source, "export");
        let reg = p
            .drift
            .items
            .iter()
            .find(|i| i.kind == "securityContextRegression")
            .expect("regressed against the export");
        assert_eq!(reg.severity, "medium", "only restricted checks newly fail");
        let failing: Vec<&str> = reg.detail["newlyFailing"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(failing.contains(&"privilegeEscalation"));
        // Drift never sets posture on its own, and the list summary counts it.
        let summary = list_summary(&p);
        assert_eq!(
            summary["drift"]["byType"]["securityContextRegression"],
            json!(1)
        );
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
             DELETE FROM workload_profile_failures WHERE pod_namespace = '{ns}'; \
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

    /// The handler's gate agrees with `Sources::is_empty`: a running
    /// workload, a pod-only workload, a bare Pod (no owner) and an unknown
    /// one.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_gate_matches_load_sources() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-gate";
        reset(&mut conn, ns);
        seed(&mut conn, ns, '5', "{}");
        conn.batch_execute(&format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, workload_kind, workload_name) \
             VALUES ('gate-podonly-1', '10.0.0.21', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'podonly'), \
                    ('gate-bare', '10.0.0.22', '{ns}', timezone('UTC', NOW()), 'n1', false, NULL, NULL) \
             ON CONFLICT (pod_name) DO UPDATE SET pod_namespace = EXCLUDED.pod_namespace, is_dead = false, \
               workload_kind = EXCLUDED.workload_kind, workload_name = EXCLUDED.workload_name;"
        ))
        .unwrap();
        // One workload per source, so dropping any source (or adding or
        // losing a cluster filter) fails an assertion below.
        let d = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        conn.batch_execute(&format!(
            "INSERT INTO workload_syscalls (pod_namespace, workload_kind, workload_name, syscalls, arches, hash, updated_at, syscall_count) \
             VALUES ('{ns}', 'Deployment', 'sysonly', 'exit,read,write', 'x86_64', 'abc', timezone('UTC', NOW()), 3); \
             INSERT INTO workload_profile_versions (pod_namespace, workload_kind, workload_name, revision, \
               content_hash, dimension_hashes, snapshot, posture) \
             VALUES ('{ns}', 'Deployment', 'veronly', 1, 'fnv1a64:x', '{{}}', '{{}}', '{{}}'); \
             INSERT INTO workload_profile_versions (cluster_id, pod_namespace, workload_kind, workload_name, revision, \
               content_hash, dimension_hashes, snapshot, posture) \
             VALUES ('other', '{ns}', 'Deployment', 'veronly-other', 1, 'fnv1a64:x', '{{}}', '{{}}', '{{}}'); \
             INSERT INTO images (digest, repository, tags, digest_kind) VALUES ('{t}', 'ghcr.io/example/t', '{{1}}', 'repo'), \
               ('{o}', 'ghcr.io/example/o', '{{1}}', 'repo') ON CONFLICT (digest) DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, container_name, image_digest, \
               container_kind, image_ref, last_pod_name, state, state_reason, last_seen) \
             VALUES ('{ns}', 'Job', 'termonly', 'app', '{t}', 'regular', 'ghcr.io/example/t:1', 'gone-1', 'terminated', 'Completed', \
               timezone('UTC', NOW()) - INTERVAL '2 days'); \
             INSERT INTO workload_containers (cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest, \
               container_kind, image_ref, last_pod_name, state) \
             VALUES ('other', '{ns}', 'Deployment', 'elsewhere', 'app', '{o}', 'regular', 'ghcr.io/example/o:1', 'elsewhere-1', 'running');",
            t = d('3'),
            o = d('4'),
        ))
        .unwrap();
        let k = |kind: &str, name: &str| Key {
            namespace: ns.into(),
            kind: kind.into(),
            name: name.into(),
        };
        for (key, want) in [
            (k("Deployment", "checkout"), (true, true)),
            (k("Deployment", "podonly"), (true, false)),
            (k("Pod", "gate-bare"), (true, false)),
            (k("Deployment", "sysonly"), (true, false)),
            (k("Deployment", "veronly"), (true, false)),
            (k("Deployment", "veronly-other"), (false, false)),
            (k("Job", "termonly"), (true, false)),
            (k("Deployment", "elsewhere"), (true, true)),
            (k("Deployment", "nothing"), (false, false)),
        ] {
            let got = workload_gate(&mut conn, &key).unwrap();
            assert_eq!(got, want, "{key:?}");
            let s = load_sources(&mut conn, &key).unwrap();
            assert_eq!(got.0, !s.is_empty(), "gate vs load_sources for {key:?}");
            assert_eq!(
                got.1,
                !crate::runtime_capabilities::current_pairs(&s.containers).is_empty(),
                "running vs current pairs for {key:?}"
            );
        }
        conn.batch_execute(&format!(
            "DELETE FROM pod_details WHERE pod_name IN ('gate-podonly-1', 'gate-bare'); \
             DELETE FROM workload_profile_versions WHERE pod_namespace = '{ns}';"
        ))
        .unwrap();
        reset(&mut conn, ns);
    }

    /// Unknown workloads never reach the evaluator: 404 first, no read, no
    /// budget charge, no cache entry. A workload with no running image has
    /// no supplyChain and does not read it either.
    #[actix_web::test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    async fn live_unknown_workloads_never_read_the_evaluator() {
        use actix_web::{test as atest, App, HttpServer};
        let ns = "kgtest-profile-noread";
        {
            let mut conn = live_conn();
            reset(&mut conn, ns);
            seed(&mut conn, ns, '9', "{}");
            // Only a syscall-less, image-less pod for another workload.
            conn.batch_execute(&format!(
                "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, workload_kind, workload_name) \
                 VALUES ('noimg-1', '10.0.0.9', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'noimg') \
                 ON CONFLICT (pod_name) DO UPDATE SET pod_namespace = EXCLUDED.pod_namespace, is_dead = false, \
                   workload_kind = 'Deployment', workload_name = 'noimg';"
            ))
            .unwrap();
        }
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let srv = HttpServer::new(move || {
            let h = h.clone();
            App::new().route(
                "/image-trust",
                web::get().to(move || {
                    let h = h.clone();
                    async move {
                        h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        HttpResponse::Ok()
                            .content_type("application/json")
                            .body(r#"{"evaluatedAt":null,"results":[]}"#)
                    }
                }),
            )
        })
        .workers(1)
        .bind("127.0.0.1:0")
        .unwrap();
        let addr = srv.addrs()[0];
        actix_web::rt::spawn(srv.run());
        let audit = {
            let _g = crate::test_support::env_lock();
            std::env::set_var("EVALUATOR_URL", format!("http://{addr}"));
            let a = crate::audit::AuditClient::from_env();
            std::env::remove_var("EVALUATOR_URL");
            a
        };
        let pool: DbPool = r2d2::Pool::builder()
            .max_size(2)
            .build(ConnectionManager::<PgConnection>::new(
                std::env::var("KG_TEST_DATABASE_URL").unwrap(),
            ))
            .unwrap();
        let app = atest::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(ReadBudget::with_budget_kib(
                    512 * 1024,
                    std::time::Duration::from_millis(0),
                )))
                .app_data(web::Data::new(audit))
                .service(get_workload_profile),
        )
        .await;
        let get = |uri: String| {
            let app = &app;
            async move {
                atest::call_service(app, atest::TestRequest::get().uri(&uri).to_request()).await
            }
        };
        for i in 0..20 {
            let r = get(format!("/workloads/fake-ns-{i}/Deployment/nothing/profile")).await;
            assert_eq!(r.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no read for unknown workloads"
        );
        // A known workload with pods but no image inventory: 200, no read.
        let r = get(format!("/workloads/{ns}/Deployment/noimg/profile")).await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: Value = atest::read_body_json(r).await;
        assert!(v["dimensions"]["images"]["supplyChain"].is_null());
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        // A workload with a running image reads it, once.
        let r = get(format!("/workloads/{ns}/Deployment/checkout/profile")).await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: Value = atest::read_body_json(r).await;
        assert_eq!(
            v["dimensions"]["images"]["supplyChain"]["imageTrust"]["available"],
            true
        );
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        reset(&mut live_conn(), ns);
    }

    /// While profile GETs wait on a stalled evaluator they hold only the
    /// shared 1 MiB evaluator charge, never the profile's own permit, so
    /// the read budget stays free and an unrelated read is not queued.
    #[actix_web::test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    async fn live_profile_wait_does_not_hold_the_read_budget() {
        use actix_web::{App, HttpServer};
        let ns = "kgtest-profile-budget";
        {
            let mut conn = live_conn();
            reset(&mut conn, ns);
            seed(&mut conn, ns, '6', "{}");
        }
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let eval = HttpServer::new(move || {
            let h = h.clone();
            App::new().route(
                "/image-trust",
                web::get().to(move || {
                    let h = h.clone();
                    async move {
                        h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        actix_web::rt::time::sleep(std::time::Duration::from_secs(10)).await;
                        HttpResponse::Ok().body("{}")
                    }
                }),
            )
        })
        .workers(1)
        .bind("127.0.0.1:0")
        .unwrap();
        let eval_addr = eval.addrs()[0];
        actix_web::rt::spawn(eval.run());
        let audit = {
            let _g = crate::test_support::env_lock();
            std::env::set_var("EVALUATOR_URL", format!("http://{eval_addr}"));
            let a = crate::audit::AuditClient::from_env();
            std::env::remove_var("EVALUATOR_URL");
            web::Data::new(a)
        };
        let pool: DbPool = r2d2::Pool::builder()
            .max_size(40)
            .build(ConnectionManager::<PgConnection>::new(
                std::env::var("KG_TEST_DATABASE_URL").unwrap(),
            ))
            .unwrap();
        // Room for every request to finish; what is measured is how much
        // is held while they wait on the evaluator (the old order held one
        // profile permit per request, about N x 11 MiB, for the whole wait).
        const N: u32 = 30;
        let total = profile_charge_kib() * (N + 2);
        let budget = web::Data::new(ReadBudget::with_budget_kib(
            total,
            std::time::Duration::from_millis(0),
        ));
        let (b, a, p) = (budget.clone(), audit.clone(), web::Data::new(pool));
        let srv = HttpServer::new(move || {
            App::new()
                .app_data(p.clone())
                .app_data(b.clone())
                .app_data(a.clone())
                .service(get_workload_profile)
                .service(crate::image_inventory::get_images)
        })
        .workers(4)
        .bind("127.0.0.1:0")
        .unwrap();
        let addr = srv.addrs()[0];
        actix_web::rt::spawn(srv.run());
        let url = format!("http://{addr}/workloads/{ns}/Deployment/checkout/profile");
        let tasks: Vec<_> = (0..N)
            .map(|_| {
                let url = url.clone();
                actix_web::rt::spawn(
                    async move { reqwest::get(url).await.unwrap().status().as_u16() },
                )
            })
            .collect();
        // Sample while the requests are waiting on the evaluator: after its
        // first request arrived, well inside the 2 s wait.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while hits.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the evaluator was never read"
            );
            actix_web::rt::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        actix_web::rt::time::sleep(std::time::Duration::from_millis(300)).await;
        let free = budget.available_kib();
        assert!(
            free >= total - 1024 - 8,
            "during the evaluator wait only the shared 1 MiB read is charged: {free} of {total} KiB free"
        );
        assert!(
            budget.acquire(profile_charge_kib()).await.is_ok(),
            "an unrelated read is admitted at once"
        );
        // A real unrelated read over HTTP during the stall: fast, not shed.
        let started = std::time::Instant::now();
        let r = reqwest::get(format!("http://{addr}/images?limit=10"))
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "unrelated read during the stall");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "unrelated read took {:?}",
            started.elapsed()
        );
        for t in tasks {
            assert_eq!(t.await.unwrap(), 200);
        }
        reset(&mut live_conn(), ns);
    }

    /// EVALUATOR_URL at a closed port: the profile's imageTrust reason is
    /// the fixed, user-safe one, never the evaluator's URL or the client's
    /// error text.
    #[actix_web::test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    async fn live_profile_evaluator_reason_hides_the_url() {
        use actix_web::{test as atest, App};
        let ns = "kgtest-profile-reason";
        {
            let mut conn = live_conn();
            reset(&mut conn, ns);
            seed(&mut conn, ns, '4', "{}");
        }
        let audit = {
            let _g = crate::test_support::env_lock();
            std::env::set_var("EVALUATOR_URL", "http://127.0.0.1:1");
            let a = crate::audit::AuditClient::from_env();
            std::env::remove_var("EVALUATOR_URL");
            a
        };
        let pool: DbPool = r2d2::Pool::builder()
            .max_size(2)
            .build(ConnectionManager::<PgConnection>::new(
                std::env::var("KG_TEST_DATABASE_URL").unwrap(),
            ))
            .unwrap();
        let app = atest::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(ReadBudget::with_budget_kib(
                    512 * 1024,
                    std::time::Duration::from_millis(0),
                )))
                .app_data(web::Data::new(audit))
                .service(get_workload_profile),
        )
        .await;
        let req = atest::TestRequest::get()
            .uri(&format!("/workloads/{ns}/Deployment/checkout/profile"))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let v: Value = serde_json::from_slice(&body).unwrap();
        let it = &v["dimensions"]["images"]["supplyChain"]["imageTrust"];
        assert_eq!(it["available"], false);
        assert_eq!(
            it["reason"],
            "the evaluator could not be reached: connection failed"
        );
        let text = String::from_utf8_lossy(&body);
        for bad in [
            "127.0.0.1:1",
            "http://127.0.0.1",
            "error sending request",
            "?namespace=",
        ] {
            assert!(!text.contains(bad), "{bad} in the profile body");
        }
        reset(&mut live_conn(), ns);
    }

    /// The profile GET with a stalled evaluator: served in about
    /// PROFILE_TIMEOUT with imageTrust unavailable, everything else intact.
    #[actix_web::test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    async fn live_profile_is_served_when_the_evaluator_stalls() {
        use actix_web::{test as atest, App, HttpServer};
        let ns = "kgtest-profile-stall";
        {
            let mut conn = live_conn();
            reset(&mut conn, ns);
            seed(&mut conn, ns, '8', "{}");
        }
        // An evaluator that never answers in time.
        let srv = HttpServer::new(|| {
            App::new().route(
                "/image-trust",
                web::get().to(|| async {
                    actix_web::rt::time::sleep(std::time::Duration::from_secs(10)).await;
                    HttpResponse::Ok().body("{}")
                }),
            )
        })
        .workers(1)
        .bind("127.0.0.1:0")
        .unwrap();
        let addr = srv.addrs()[0];
        actix_web::rt::spawn(srv.run());
        let audit = {
            let _g = crate::test_support::env_lock();
            std::env::set_var("EVALUATOR_URL", format!("http://{addr}"));
            let a = crate::audit::AuditClient::from_env();
            std::env::remove_var("EVALUATOR_URL");
            a
        };
        let pool: DbPool = r2d2::Pool::builder()
            .max_size(2)
            .build(ConnectionManager::<PgConnection>::new(
                std::env::var("KG_TEST_DATABASE_URL").unwrap(),
            ))
            .unwrap();
        let app = atest::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(ReadBudget::with_budget_kib(
                    512 * 1024,
                    std::time::Duration::from_millis(0),
                )))
                .app_data(web::Data::new(audit))
                .service(get_workload_profile),
        )
        .await;
        let started = std::time::Instant::now();
        let req = atest::TestRequest::get()
            .uri(&format!("/workloads/{ns}/Deployment/checkout/profile"))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        let took = started.elapsed();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = atest::read_body_json(resp).await;
        let it = &v["dimensions"]["images"]["supplyChain"]["imageTrust"];
        assert_eq!(it["available"], false, "{it}");
        assert!(it["reason"]
            .as_str()
            .unwrap()
            .contains("did not answer within 2000 ms"));
        assert!(v["posture"]["status"].is_string());
        assert!(v["dimensions"]["podSecurity"]["status"].is_string());
        assert!(
            took < crate::image_trust::PROFILE_TIMEOUT + std::time::Duration::from_millis(1_500),
            "took {took:?}"
        );
        // The failure is cached: the next GET does not wait again.
        let started = std::time::Instant::now();
        let req = atest::TestRequest::get()
            .uri(&format!("/workloads/{ns}/Deployment/checkout/profile"))
            .to_request();
        assert_eq!(
            atest::call_service(&app, req).await.status(),
            StatusCode::OK
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1_500),
            "{:?}",
            started.elapsed()
        );
        reset(&mut live_conn(), ns);
    }

    /// Contract v1.8 against the real schema: signature rows join by
    /// digest, only verified signers are read (at most
    /// SIGNERS_PER_DIGEST), and the profile and list summary carry them.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_profile_reads_signature_results() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-signatures";
        reset(&mut conn, ns);
        seed(&mut conn, ns, '7', "{}");
        let d = format!("sha256:{}", "7".repeat(64));
        let mut sigs: Vec<Value> = (0..10)
            .map(|i| json!({"format": "cosign-bundle", "source": "referrers", "verified": true,
                "signerKind": "keyless", "issuer": "https://token.actions.githubusercontent.com",
                "san": format!("https://github.com/example/checkout/.github/workflows/r{i}.yaml@refs/heads/main")}))
            .collect();
        sigs.push(
            json!({"format": "cosign-legacy", "source": "sig-tag", "verified": false,
            "error": "bad_signature", "issuer": "https://claimed.example", "san": "attacker"}),
        );
        // Verified but naming no one: never read as a signer.
        sigs.push(json!({"format": "cosign-bundle", "source": "referrers", "verified": true}));
        sigs.push(json!({"format": "cosign-bundle", "source": "referrers", "verified": true,
            "signerKind": "keyless", "issuer": "https://token.actions.githubusercontent.com", "san": ""}));
        sigs.push(json!({"format": "cosign-bundle", "source": "referrers", "verified": true,
            "signerKind": "keyless", "issuer": "https://token.actions.githubusercontent.com", "san": "   "}));
        sigs.push(
            json!({"format": "cosign-legacy", "source": "sig-tag", "verified": true,
            "signerKind": "key", "keyFingerprint": "  "}),
        );
        // A fingerprint without signerKind "key" names no one either.
        sigs.push(
            json!({"format": "cosign-legacy", "source": "sig-tag", "verified": true,
            "keyFingerprint": "ab".repeat(32)}),
        );
        conn.batch_execute(&format!(
            "DELETE FROM image_attestations WHERE digest = '{d}'; \
             INSERT INTO image_attestations (digest, repository, verdict, signatures, checked_at) \
             VALUES ('{d}', 'ghcr.io/example/checkout', 'verified', '{}'::jsonb, timezone('UTC', NOW()));",
            Value::Array(sigs)
        ))
        .expect("attestation");
        let k = key(ns);
        let s = load_sources(&mut conn, &k).expect("load");
        let row = s.signatures.get(&d).expect("joined by digest");
        let signers = row.signers.as_array().unwrap();
        assert_eq!(signers.len(), SIGNERS_PER_DIGEST as usize);
        assert_eq!(
            row.signer_count, 10,
            "only the ten signers with an identity count"
        );
        assert!(signers
            .iter()
            .all(|x| x["san"].as_str().is_some_and(|s| !s.is_empty())));
        assert!(signers.iter().all(|x| x["signerKind"] == "keyless"
            && x["issuer"] == "https://token.actions.githubusercontent.com"));
        assert!(
            !row.signers.to_string().contains("attacker"),
            "an unverified signer was read"
        );
        let p = build(&k, &s, Utc::now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!((sc.verdict.as_str(), sc.counts.verified), ("verified", 1));
        assert_eq!(sc.signers_omitted, 2);
        assert_eq!(
            p.readiness
                .iter()
                .find(|r| r.id == "imageSigned")
                .unwrap()
                .ok,
            Some(true)
        );
        assert_eq!(
            list_summary(&p)["dimensions"]["images"]["signature"],
            "verified"
        );

        // Verified with only identity-less signatures: unknown.
        conn.batch_execute(&format!(
            "UPDATE image_attestations SET signatures = \
             '[{{\"verified\": true}}, {{\"verified\": true, \"signerKind\": \"keyless\"}}]'::jsonb \
             WHERE digest = '{d}';"
        ))
        .unwrap();
        let s = load_sources(&mut conn, &k).unwrap();
        assert_eq!(s.signatures[&d].signer_count, 0);
        let p = build(&k, &s, Utc::now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.verdict.as_str(), sc.reason.as_deref()),
            ("unknown", Some("no_signer_identity"))
        );
        assert_eq!(
            p.readiness
                .iter()
                .find(|r| r.id == "imageSigned")
                .unwrap()
                .ok,
            None
        );

        // No row: not checked, unknown.
        conn.batch_execute(&format!(
            "DELETE FROM image_attestations WHERE digest = '{d}';"
        ))
        .unwrap();
        let p = build(&k, &load_sources(&mut conn, &k).unwrap(), Utc::now());
        let sc = p.dimensions.images.supply_chain.as_ref().unwrap();
        assert_eq!(
            (sc.verdict.as_str(), sc.reason.as_deref()),
            ("unknown", Some("not_checked"))
        );
        reset(&mut conn, ns);
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
        assert_eq!(p.dimensions.network.env.status, "warn");
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
        assert_eq!(sc.env.status, "warn");
        assert_eq!(
            p.snapshot["syscalls"]["syscalls"],
            json!(["exit", "read", "write"])
        );

        // The snapshotter tick picks the workload up and fills the read model.
        let t = snapshot_tick(&mut conn, 100_000, 50, Duration::ZERO).unwrap();
        assert!(t.computed >= 1);
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        assert_eq!(l["items"][0]["name"], json!("checkout"));
        assert_eq!(l["items"][0]["posture"]["status"], json!("risk"));
        let l =
            list_workloads(&mut conn, Some(ns), None, Some("ok"), None, None, false, 10).unwrap();
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
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        assert_eq!(l["items"].as_array().unwrap().len(), 1);
        assert_eq!(l["items"][0]["revision"], json!(4));
        assert_eq!(
            l["items"][0]["dimensions"]["podSecurity"]["level"],
            json!("restricted")
        );
        assert!(l["nextAfter"].is_null());

        // Default diff whose predecessor was trimmed (cap 3 dropped rev 1):
        // falls back instead of 404ing, and says so.
        let DiffResult::Ok(d) = diff_versions(&mut conn, &k, None, Some(2)).unwrap() else {
            panic!("trimmed-predecessor diff must not fail")
        };
        assert!(d["from"].is_null());
        assert_eq!(d["fromTrimmed"], json!(true));
        let DiffResult::Ok(d) = diff_versions(&mut conn, &k, None, Some(3)).unwrap() else {
            panic!("diff failed")
        };
        assert_eq!(d["fromTrimmed"], json!(false));

        // Race: this writer read head = rev 4, but another writer stored a
        // DIFFERENT profile as rev 5 in between. Nothing is written and the
        // latest pointer is left alone.
        conn.batch_execute(&format!(
            "INSERT INTO workload_profile_versions (pod_namespace, workload_kind, workload_name, revision, \
               content_hash, dimension_hashes, snapshot, posture) \
             VALUES ('{ns}', 'Deployment', 'checkout', 5, 'fnv1a64:theirs', '{{}}', '{{}}', '{{}}');"
        ))
        .unwrap();
        let stale_head = StoredVersionHead {
            revision: 4,
            content_hash: "fnv1a64:ours-before".into(),
            created_at: Utc::now().naive_utc(),
        };
        let s = load_sources(&mut conn, &k).unwrap();
        let p = build(&k, &s, Utc::now());
        assert_eq!(
            store_with_head(&mut conn, &k, &p, 50, Some(stale_head.clone())).unwrap(),
            SnapshotOutcome::LostRace(5)
        );
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        assert_eq!(l["items"][0]["revision"], json!(4));
        // An identical row at that revision is not a conflict.
        conn.batch_execute(&format!(
            "UPDATE workload_profile_versions SET content_hash = '{}' \
             WHERE pod_namespace = '{ns}' AND revision = 5;",
            p.content_hash
        ))
        .unwrap();
        assert_eq!(
            store_with_head(&mut conn, &k, &p, 50, Some(stale_head)).unwrap(),
            SnapshotOutcome::NewVersion(5)
        );
        // The latest pointer never moves backwards.
        conn.batch_execute(&format!(
            "UPDATE workload_profile_latest SET revision = 99 WHERE pod_namespace = '{ns}';"
        ))
        .unwrap();
        store_snapshot(&mut conn, &k, &p, 50).unwrap();
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        assert_eq!(l["items"][0]["revision"], json!(99));

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
    /// `GET /workloads` lists workloads with alive pods unless
    /// `include_gone`; a failed attempt is carried as `lastError` /
    /// `failedAt` beside the last good profile, a failed-only workload is
    /// listed with null profile fields, and a computed profile clears it.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_list_hides_gone_workloads_and_reports_failures() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-gone";
        reset(&mut conn, ns);
        seed(&mut conn, ns, 'c', "{}");
        let d = format!("sha256:{}", "d".repeat(64));
        conn.batch_execute(&format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, workload_kind, workload_name) \
             VALUES ('retired-1', '10.0.0.31', '{ns}', timezone('UTC', NOW()), 'n1', true, 'Deployment', 'retired'), \
                    ('ghost-1', '10.0.0.32', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'ghost') \
             ON CONFLICT (pod_name) DO UPDATE SET pod_namespace = EXCLUDED.pod_namespace, is_dead = EXCLUDED.is_dead, \
               workload_kind = EXCLUDED.workload_kind, workload_name = EXCLUDED.workload_name; \
             INSERT INTO images (digest, repository, tags, digest_kind) VALUES ('{d}', 'ghcr.io/example/retired', '{{1}}', 'repo') \
             ON CONFLICT (digest) DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, container_name, image_digest, \
               container_kind, image_ref, last_pod_name, state, state_reason, last_seen) \
             VALUES ('{ns}', 'Deployment', 'retired', 'app', '{d}', 'regular', 'ghcr.io/example/retired:1', 'retired-1', \
               'terminated', 'Completed', timezone('UTC', NOW()) - INTERVAL '1 day');"
        ))
        .unwrap();
        let k = |n: &str| Key {
            namespace: ns.into(),
            kind: "Deployment".into(),
            name: n.into(),
        };
        let names = |v: &Value| -> Vec<String> {
            v["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["name"].as_str().unwrap().to_string())
                .collect()
        };
        let list = |conn: &mut PgConnection, gone: bool, limit: i64| {
            list_workloads(conn, Some(ns), None, None, None, None, gone, limit).unwrap()
        };

        // Nothing computed yet: a failure alone puts the workload on the list.
        record_failure(&mut conn, &k("ghost"), "boom").unwrap();
        let l = list(&mut conn, false, 10);
        assert_eq!(names(&l), vec!["ghost"]);
        let g = &l["items"][0];
        assert_eq!(g["lastError"], json!("boom"));
        assert!(g["failedAt"].is_string());
        assert!(g["revision"].is_null() && g["computedAt"].is_null(), "{g}");
        assert!(
            ["posture", "dimensions", "findingCounts", "drift"]
                .iter()
                .all(|k| g.get(k).is_none()),
            "profile keys are absent, not null: {g}"
        );

        // A tick computes checkout, ghost (pod only) and retired (inventory only).
        let t = snapshot_tick(&mut conn, 1_000, 50, Duration::ZERO).unwrap();
        assert!(t.computed >= 3, "{t:?}");
        let l = list(&mut conn, false, 10);
        assert_eq!(
            names(&l),
            vec!["checkout", "ghost"],
            "no alive pod: not listed"
        );
        let g = &l["items"][1];
        assert!(
            g["lastError"].is_null() && g["failedAt"].is_null(),
            "a computed profile clears the failure: {g}"
        );
        assert_eq!(g["revision"], json!(1));
        assert_eq!(
            names(&list(&mut conn, true, 10)),
            vec!["checkout", "ghost", "retired"]
        );

        // A later failure sits beside the last good profile, cut to size.
        record_failure(
            &mut conn,
            &k("checkout"),
            &"x".repeat(FAILURE_MESSAGE_MAX + 50),
        )
        .unwrap();
        let l = list(&mut conn, false, 10);
        let c = &l["items"][0];
        assert_eq!(c["name"], json!("checkout"));
        assert_eq!(c["revision"], json!(1));
        assert!(c["posture"]["status"].is_string());
        assert_eq!(c["lastError"].as_str().unwrap().len(), FAILURE_MESSAGE_MAX);
        assert!(c["failedAt"].is_string());

        // The cursor walks computed and failed-only rows in one key order.
        let p1 = list_workloads(&mut conn, Some(ns), None, None, None, None, true, 1).unwrap();
        assert_eq!(names(&p1), vec!["checkout"]);
        let after = parse_after(p1["nextAfter"].as_str().unwrap()).unwrap();
        let p2 =
            list_workloads(&mut conn, Some(ns), None, None, None, Some(&after), true, 1).unwrap();
        assert_eq!(names(&p2), vec!["ghost"]);

        // A failure row with no source data behind it is pruned; the
        // recompute clears checkout's.
        record_failure(&mut conn, &k("vanished"), "gone").unwrap();
        snapshot_tick(&mut conn, 1_000, 50, Duration::ZERO).unwrap();
        let l = list(&mut conn, true, 10);
        assert_eq!(names(&l), vec!["checkout", "ghost", "retired"]);
        assert!(l["items"][0]["lastError"].is_null());
        conn.batch_execute("DELETE FROM pod_details WHERE pod_name IN ('retired-1', 'ghost-1')")
            .unwrap();
        reset(&mut conn, ns);
    }

    /// Candidates: alive workloads before gone ones, never attempted
    /// before least recently attempted (computed or failed), and the keys
    /// already visited this tick left out.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_snapshot_candidates_put_alive_workloads_first() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-order";
        reset(&mut conn, ns);
        // a: alive, never attempted; c: alive, computed an hour ago; e:
        // alive, failed half an hour ago; b: gone, never attempted; d:
        // gone, computed two hours ago.
        conn.batch_execute(&format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, workload_kind, workload_name) VALUES \
               ('ord-a-1', '10.0.1.1', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'a'), \
               ('ord-c-1', '10.0.1.3', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'c'), \
               ('ord-e-1', '10.0.1.5', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'e'), \
               ('ord-b-1', '10.0.1.2', '{ns}', timezone('UTC', NOW()), 'n1', true, 'Deployment', 'b'), \
               ('ord-d-1', '10.0.1.4', '{ns}', timezone('UTC', NOW()), 'n1', true, 'Deployment', 'd') \
             ON CONFLICT (pod_name) DO UPDATE SET pod_namespace = EXCLUDED.pod_namespace, is_dead = EXCLUDED.is_dead, \
               workload_kind = EXCLUDED.workload_kind, workload_name = EXCLUDED.workload_name; \
             INSERT INTO workload_syscalls (pod_namespace, workload_kind, workload_name, syscalls, arches, hash, updated_at, syscall_count) VALUES \
               ('{ns}', 'Deployment', 'b', 'exit', 'x86_64', 'b', timezone('UTC', NOW()), 1), \
               ('{ns}', 'Deployment', 'd', 'exit', 'x86_64', 'd', timezone('UTC', NOW()), 1);"
        ))
        .unwrap();
        let k = |n: &str| Key {
            namespace: ns.into(),
            kind: "Deployment".into(),
            name: n.into(),
        };
        snapshot_one(&mut conn, &k("c"), 50).unwrap();
        snapshot_one(&mut conn, &k("d"), 50).unwrap();
        record_failure(&mut conn, &k("e"), "timeout").unwrap();
        conn.batch_execute(&format!(
            "UPDATE workload_profile_latest SET computed_at = timezone('UTC', NOW()) - INTERVAL '1 hour' \
               WHERE pod_namespace = '{ns}' AND workload_name = 'c'; \
             UPDATE workload_profile_latest SET computed_at = timezone('UTC', NOW()) - INTERVAL '2 hours' \
               WHERE pod_namespace = '{ns}' AND workload_name = 'd'; \
             UPDATE workload_profile_failures SET failed_at = timezone('UTC', NOW()) - INTERVAL '30 minutes' \
               WHERE pod_namespace = '{ns}' AND workload_name = 'e';"
        ))
        .unwrap();
        let ours = |rows: &[KeyRow]| -> Vec<String> {
            rows.iter()
                .filter(|r| r.ns == ns)
                .map(|r| r.name.clone())
                .collect()
        };
        let all = candidates(&mut conn, 100_000, &[]).unwrap();
        assert_eq!(ours(&all), vec!["a", "c", "e", "b", "d"]);
        let seen: Vec<KeyRow> = all
            .into_iter()
            .filter(|r| r.ns == ns && (r.name == "a" || r.name == "c"))
            .collect();
        assert_eq!(
            ours(&candidates(&mut conn, 100_000, &seen).unwrap()),
            vec!["e", "b", "d"]
        );
        conn.batch_execute("DELETE FROM pod_details WHERE pod_name LIKE 'ord-%'")
            .unwrap();
        reset(&mut conn, ns);
    }

    /// A tick takes one batch with no budget, and batches until no
    /// candidate is left with one.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_snapshot_tick_takes_batches_until_the_budget_is_spent() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-tick";
        reset(&mut conn, ns);
        conn.batch_execute(&format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead, workload_kind, workload_name) VALUES \
               ('bud-1-1', '10.0.2.1', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'bud-1'), \
               ('bud-2-1', '10.0.2.2', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'bud-2'), \
               ('bud-3-1', '10.0.2.3', '{ns}', timezone('UTC', NOW()), 'n1', false, 'Deployment', 'bud-3') \
             ON CONFLICT (pod_name) DO UPDATE SET pod_namespace = EXCLUDED.pod_namespace, is_dead = false, \
               workload_kind = EXCLUDED.workload_kind, workload_name = EXCLUDED.workload_name;"
        ))
        .unwrap();
        let t = snapshot_tick(&mut conn, 1, 50, Duration::ZERO).unwrap();
        assert_eq!((t.batches, t.computed + t.failed), (1, 1), "{t:?}");
        let t = snapshot_tick(&mut conn, 1, 50, Duration::from_secs(600)).unwrap();
        assert!(
            t.batches >= 2 && t.batches == t.computed + t.failed,
            "{t:?}"
        );
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        let names: Vec<&str> = l["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["bud-1", "bud-2", "bud-3"]);
        conn.batch_execute("DELETE FROM pod_details WHERE pod_name LIKE 'bud-%'")
            .unwrap();
        reset(&mut conn, ns);
    }
    /// A flow aggregate that runs past its bound leaves the profile
    /// readable without its network dimension; the snapshotter records
    /// the failure instead of versioning a partial profile, and clears it
    /// once the read fits.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_profile_survives_a_slow_flow_read() {
        let mut conn = live_conn();
        let ns = "kgtest-profile-slow";
        reset(&mut conn, ns);
        seed(&mut conn, ns, 'e', "{}");
        // Enough rows for the newest-first scan and sort to outlast 1 ms.
        conn.batch_execute(&format!(
            "INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, pod_ip, pod_port, ip_protocol, traffic_type, \
               traffic_in_out_ip, traffic_in_out_port, time_stamp) \
             SELECT 'kgtest-slow-' || g, 'checkout-1', '{ns}', '10.0.0.1', '8080', 'TCP', 'INGRESS', \
               '10.1.' || (g / 250) || '.' || (g % 250), '40000', \
               timezone('UTC', NOW()) - make_interval(secs => g) \
             FROM generate_series(1, 60000) g;"
        ))
        .unwrap();
        let k = key(ns);
        let s = load_sources_bounded(&mut conn, &k, 1).unwrap();
        let why = s.network_unread.clone().expect("the 1 ms bound ran out");
        assert!(why.ends_with("exceeded its 1 ms bound"), "{why}");
        assert!(s.network.is_empty() && s.network_rules.is_empty());
        assert_eq!(
            s.live_pods,
            vec!["checkout-1".to_string()],
            "other sources read"
        );
        assert_eq!(s.containers.len(), 1);
        let p = build(&k, &s, Utc::now());
        assert_eq!(p.dimensions.network.env.status, "unknown");
        assert_eq!(p.dimensions.network.env.coverage.note, why);
        assert_eq!(p.dimensions.images.containers.len(), 1);
        // A generous bound reads them (and hits the scan limit).
        let s = load_sources_bounded(&mut conn, &k, 30_000).unwrap();
        assert!(s.network_unread.is_none());
        assert!(!s.network.is_empty() && s.network_truncated);
        // The session's own tighter timeout stays in force, and is what
        // the reason names.
        conn.batch_execute("SET statement_timeout = 1").unwrap();
        let r = read_network(&mut conn, &k, &["checkout-1".to_string()], 60_000).unwrap();
        conn.batch_execute("RESET statement_timeout").unwrap();
        assert_eq!(
            r.expect_err("the session's 1 ms timeout ran out"),
            "the flow aggregate was not read: the pod_traffic query exceeded the database's \
             statement timeout"
        );
        assert!(
            read_network(&mut conn, &k, &["checkout-1".to_string()], 30_000)
                .unwrap()
                .is_ok()
        );
        // The snapshotter under the tight bound: a failure, not a version.
        let t = {
            let _g = crate::test_support::env_lock();
            std::env::set_var("PROFILE_NETWORK_READ_TIMEOUT_MS", "1");
            let one = snapshot_one(&mut conn, &k, 50);
            let t = snapshot_tick(&mut conn, 1_000, 50, Duration::ZERO).unwrap();
            std::env::remove_var("PROFILE_NETWORK_READ_TIMEOUT_MS");
            let e = one.expect_err("a partial profile is not snapshotted");
            assert!(e.to_string().contains("not snapshotted"), "{e}");
            t
        };
        assert!(t.failed >= 1, "{t:?}");
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        let c = &l["items"][0];
        assert_eq!(c["name"], json!("checkout"));
        assert!(c["revision"].is_null(), "{c}");
        assert!(c["lastError"].as_str().unwrap().contains("not read"), "{c}");
        // With the read fitting again, the next tick computes and clears it.
        let t = snapshot_tick(&mut conn, 1_000, 50, Duration::ZERO).unwrap();
        assert!(t.computed >= 1, "{t:?}");
        let l = list_workloads(&mut conn, Some(ns), None, None, None, None, false, 10).unwrap();
        let c = &l["items"][0];
        assert_eq!(c["revision"], json!(1));
        assert!(c["lastError"].is_null() && c["failedAt"].is_null(), "{c}");
        assert!(c["posture"]["status"].is_string());
        reset(&mut conn, ns);
    }
}
