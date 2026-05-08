//! Audit-policy bridge: forwards observed pod_traffic events to the
//! kguardian-evaluator and persists `WouldDeny` verdicts in
//! `audit_verdicts` for query by the frontend / advisor.
//!
//! Best-effort by design: the evaluator can be down, slow, or absent
//! and the broker's hot-path ingest must keep working. All errors are
//! logged at debug/warn and swallowed.

use crate::schema;
use crate::types::PodTraffic;
use chrono::Utc;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Debug, thiserror::Error)]
enum AuditInsertError {
    #[error("connection pool: {0}")]
    Pool(#[from] diesel::r2d2::PoolError),
    #[error("insert: {0}")]
    Diesel(#[from] diesel::result::Error),
}

/// Wire format consumed by `POST /evaluate` — must match
/// `evaluator/pkg/matcher.Flow` exactly.
#[derive(Debug, Serialize)]
struct Flow<'a> {
    #[serde(rename = "srcPodNamespace", skip_serializing_if = "Option::is_none")]
    src_pod_namespace: Option<&'a str>,
    #[serde(rename = "srcPodName", skip_serializing_if = "Option::is_none")]
    src_pod_name: Option<&'a str>,
    #[serde(rename = "dstPodNamespace", skip_serializing_if = "Option::is_none")]
    dst_pod_namespace: Option<&'a str>,
    #[serde(rename = "dstPodName", skip_serializing_if = "Option::is_none")]
    dst_pod_name: Option<&'a str>,
    #[serde(rename = "srcIP", skip_serializing_if = "Option::is_none")]
    src_ip: Option<&'a str>,
    #[serde(rename = "dstIP", skip_serializing_if = "Option::is_none")]
    dst_ip: Option<&'a str>,
    #[serde(rename = "dstPort")]
    dst_port: i32,
    protocol: &'a str,
    timestamp: String,
}

/// Wire format returned by the evaluator — one entry per
/// (policy, direction) the flow was checked against.
#[derive(Debug, Deserialize)]
struct EvaluateResponse {
    #[serde(default)]
    results: Vec<VerdictResult>,
}

#[derive(Debug, Deserialize)]
struct VerdictResult {
    #[serde(rename = "policyNamespace")]
    policy_namespace: String,
    #[serde(rename = "policyName")]
    policy_name: String,
    #[serde(rename = "policyUID", default)]
    policy_uid: String,
    direction: String,
    verdict: String,
    #[serde(default)]
    reason: String,
}

/// Diesel insertable for the audit_verdicts table. Owned-strings only
/// so the value can cross the `tokio::spawn_blocking` 'static boundary
/// without borrowing from the response body.
#[derive(Debug, Insertable)]
#[diesel(table_name = schema::audit_verdicts)]
struct AuditVerdictInsert {
    policy_uid: String,
    policy_namespace: String,
    policy_name: String,
    direction: String,
    src_namespace: Option<String>,
    src_pod: Option<String>,
    dst_namespace: Option<String>,
    dst_pod: Option<String>,
    dst_port: i32,
    protocol: String,
    reason: Option<String>,
    observed_at: chrono::NaiveDateTime,
    /// "Allow" or "WouldDeny". NotApplicable verdicts are dropped at
    /// the filter site and never reach this struct.
    verdict: String,
}

/// Long-lived client cached by the actix application state. Holds the
/// evaluator base URL and a connection-pooled reqwest client.
#[derive(Clone)]
pub struct AuditClient {
    enabled: bool,
    base_url: String,
    http: reqwest::Client,
}

impl AuditClient {
    /// Construct from the `EVALUATOR_URL` env var. When unset, the
    /// client is disabled and `evaluate_and_persist` is a no-op.
    pub fn from_env() -> Self {
        let base_url = std::env::var("EVALUATOR_URL").unwrap_or_default();
        let enabled = !base_url.is_empty();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .pool_max_idle_per_host(8)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { enabled, base_url, http }
    }

    pub fn enabled(&self) -> bool { self.enabled }
    pub fn base_url(&self) -> &str { &self.base_url }

    /// Best-effort: build a Flow from the PodTraffic event, POST to
    /// `/evaluate`, and persist any `WouldDeny` results. Errors are
    /// logged but never propagated — the broker's ingest path must not
    /// stall on evaluator hiccups.
    pub async fn evaluate_and_persist(&self, pool: DbPool, traffic: PodTraffic) {
        if !self.enabled {
            return;
        }
        let url = format!("{}/evaluate", self.base_url.trim_end_matches('/'));

        // INGRESS: pod_name/pod_namespace is the destination.
        // EGRESS: pod_name/pod_namespace is the source.
        let traffic_type = traffic.traffic_type.as_deref().unwrap_or("");
        let (src_ns, src_name, src_ip, dst_ns, dst_name, dst_ip, dst_port_str) = match traffic_type {
            "INGRESS" => (
                None,
                None, // We don't know the source pod identity from PodTraffic alone.
                traffic.traffic_in_out_ip.as_deref(),
                traffic.pod_namespace.as_deref(),
                traffic.pod_name.as_deref(),
                traffic.pod_ip.as_deref(),
                traffic.pod_port.as_deref().unwrap_or("0"),
            ),
            "EGRESS" => (
                traffic.pod_namespace.as_deref(),
                traffic.pod_name.as_deref(),
                traffic.pod_ip.as_deref(),
                None,
                None, // Likewise — destination pod is identified by IP only here.
                traffic.traffic_in_out_ip.as_deref(),
                traffic.traffic_in_out_port.as_deref().unwrap_or("0"),
            ),
            _ => {
                debug!(?traffic_type, "skipping audit eval for unknown traffic_type");
                return;
            }
        };

        let dst_port: i32 = dst_port_str.parse().unwrap_or(0);
        let protocol = traffic.ip_protocol.as_deref().unwrap_or("TCP");

        let flow = Flow {
            src_pod_namespace: src_ns,
            src_pod_name: src_name,
            dst_pod_namespace: dst_ns,
            dst_pod_name: dst_name,
            src_ip,
            dst_ip,
            dst_port,
            protocol,
            timestamp: traffic.time_stamp.and_utc().to_rfc3339(),
        };

        let resp = match self.http.post(&url).json(&flow).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "evaluator unreachable; skipping audit eval");
                return;
            }
        };
        if !resp.status().is_success() {
            debug!(status = %resp.status(), "evaluator returned non-2xx");
            return;
        }
        let body: EvaluateResponse = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "could not decode evaluator response");
                return;
            }
        };

        // Persist Allow + WouldDeny verdicts so operators can preview
        // both sides of policy impact (what's permitted, what would be
        // blocked). NotApplicable is dropped — every flow checks
        // against every cluster-scoped policy plus all namespaced ones
        // in scope, and most produce NotApplicable; storing them all
        // would inflate audit_verdicts by 1-2 orders of magnitude with
        // no analytical value.
        let now = Utc::now().naive_utc();
        let to_insert: Vec<AuditVerdictInsert> = body
            .results
            .into_iter()
            .filter(|r| r.verdict == "Allow" || r.verdict == "WouldDeny")
            .map(|r| AuditVerdictInsert {
                policy_uid: r.policy_uid,
                policy_namespace: r.policy_namespace,
                policy_name: r.policy_name,
                direction: r.direction,
                src_namespace: src_ns.map(str::to_owned),
                src_pod: src_name.map(str::to_owned),
                dst_namespace: dst_ns.map(str::to_owned),
                dst_pod: dst_name.map(str::to_owned),
                dst_port,
                protocol: protocol.to_owned(),
                reason: if r.reason.is_empty() { None } else { Some(r.reason) },
                observed_at: now,
                verdict: r.verdict,
            })
            .collect();

        if to_insert.is_empty() {
            return;
        }

        // Use a dedicated error enum so we can distinguish pool
        // exhaustion from a real diesel error in logs without abusing
        // `diesel::result::Error` variants for unrelated failure modes.
        let result = tokio::task::spawn_blocking(move || -> Result<usize, AuditInsertError> {
            let mut conn = pool.get().map_err(AuditInsertError::Pool)?;
            diesel::insert_into(schema::audit_verdicts::table)
                .values(&to_insert)
                .execute(&mut conn)
                .map_err(AuditInsertError::Diesel)
        })
        .await;

        match result {
            Ok(Ok(n)) => debug!(rows = n, "persisted audit verdicts"),
            Ok(Err(AuditInsertError::Pool(e))) => {
                warn!(error = %e, "could not get db conn for audit verdict insert")
            }
            Ok(Err(AuditInsertError::Diesel(e))) => {
                warn!(error = %e, "audit verdict insert failed")
            }
            Err(e) => warn!(error = %e, "audit verdict task panicked"),
        }
    }
}
