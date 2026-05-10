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
/// evaluator base URL, a connection-pooled reqwest client, and a
/// semaphore that bounds the number of concurrent in-flight audit
/// evaluations.
#[derive(Clone)]
pub struct AuditClient {
    enabled: bool,
    base_url: String,
    http: reqwest::Client,
    /// Permits the maximum number of concurrent /evaluate calls. The
    /// add.rs path spawns one audit task per ingested flow; without a
    /// cap, a 1000-event batch would create 1000 concurrent reqwest
    /// futures + 1000 connection-pool waiters. Bounding here gives
    /// upstream backpressure without changing the call sites.
    in_flight: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Maximum concurrent audit /evaluate calls. Sized roughly to twice
/// `pool_max_idle_per_host(8)` so the connection pool stays the
/// effective rate limit; further audit calls queue on this semaphore.
const AUDIT_INFLIGHT_PERMITS: usize = 16;

impl AuditClient {
    /// Construct from the `EVALUATOR_URL` env var. When unset, the
    /// client is disabled and `evaluate_and_persist` is a no-op.
    pub fn from_env() -> Self {
        let base_url = std::env::var("EVALUATOR_URL").unwrap_or_default();
        let enabled = !base_url.is_empty();
        let permits = std::env::var("AUDIT_INFLIGHT_PERMITS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|n| n.max(1))
            .unwrap_or(AUDIT_INFLIGHT_PERMITS);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .pool_max_idle_per_host(8)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            enabled,
            base_url,
            http,
            in_flight: std::sync::Arc::new(tokio::sync::Semaphore::new(permits)),
        }
    }

    pub fn enabled(&self) -> bool { self.enabled }
    pub fn base_url(&self) -> &str { &self.base_url }

    /// Number of permits currently available — visible to tests and
    /// future Prometheus exposition (saturation = configured - available).
    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.in_flight.available_permits()
    }

    /// Best-effort: build a Flow from the PodTraffic event, POST to
    /// `/evaluate`, and persist any `WouldDeny` results. Errors are
    /// logged but never propagated — the broker's ingest path must not
    /// stall on evaluator hiccups.
    pub async fn evaluate_and_persist(&self, pool: DbPool, traffic: PodTraffic) {
        if !self.enabled {
            return;
        }
        // Bound concurrent in-flight evaluations. Without this, a large
        // ingest batch (the broker's add_pods_batch fires N tasks per
        // event for an N-event batch) would create unbounded futures
        // racing for the small connection pool. A failed acquire would
        // mean the global semaphore is poisoned (extremely unlikely);
        // treat that as 'just skip the audit step' rather than crashing
        // the ingest path.
        let _permit = match self.in_flight.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "audit semaphore closed; skipping evaluation");
                return;
            }
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    // Wire-format contract tests for the broker ↔ evaluator boundary.
    // These lock down the JSON shapes both sides must agree on.
    // See kguardian-dev/kguardian#880 for the original divergence.

    #[test]
    fn decodes_empty_results_array() {
        // Evaluator's `{"results":[]}` must deserialise into an empty Vec.
        let json = r#"{"results":[]}"#;
        let resp: EvaluateResponse = serde_json::from_str(json).expect("must decode `[]`");
        assert!(resp.results.is_empty());
    }

    #[test]
    fn decodes_missing_results_field() {
        // `#[serde(default)]` on the field means a missing key defaults
        // to an empty Vec. This guards against future evaluator versions
        // that might omit the field entirely.
        let json = r#"{}"#;
        let resp: EvaluateResponse = serde_json::from_str(json).expect("must decode missing field");
        assert!(resp.results.is_empty());
    }

    #[test]
    fn rejects_null_results_field() {
        // The pre-#880 bug: evaluator emitted `{"results":null}` (Go
        // nil-slice gotcha) and the broker's Vec<VerdictResult> deser
        // rejected it, producing the "could not decode evaluator
        // response" warning spam. If this test ever passes, either
        // serde changed semantics or someone added a custom deserializer
        // that silently maps null → empty — both worth scrutinising.
        let json = r#"{"results":null}"#;
        let resp: Result<EvaluateResponse, _> = serde_json::from_str(json);
        assert!(
            resp.is_err(),
            "null must fail to decode; got {:?}. Evaluator MUST emit [] for empty results.",
            resp,
        );
    }

    #[test]
    fn decodes_populated_verdict_result() {
        // Lock down all field renames (policyNamespace, policyName,
        // policyUID) and the Allow/WouldDeny verdict strings.
        let json = r#"{
            "results": [
                {
                    "policyNamespace": "prod",
                    "policyName": "web-deny",
                    "policyUID": "uid-abc-123",
                    "direction": "Ingress",
                    "verdict": "WouldDeny",
                    "reason": "policy has no ingress rules — default-deny"
                },
                {
                    "policyNamespace": "",
                    "policyName": "cluster-baseline-audit",
                    "policyUID": "uid-cluster-1",
                    "direction": "Ingress",
                    "verdict": "Allow",
                    "reason": ""
                }
            ]
        }"#;
        let resp: EvaluateResponse = serde_json::from_str(json).expect("must decode");
        assert_eq!(resp.results.len(), 2);

        assert_eq!(resp.results[0].policy_namespace, "prod");
        assert_eq!(resp.results[0].policy_name, "web-deny");
        assert_eq!(resp.results[0].policy_uid, "uid-abc-123");
        assert_eq!(resp.results[0].direction, "Ingress");
        assert_eq!(resp.results[0].verdict, "WouldDeny");
        assert_eq!(
            resp.results[0].reason,
            "policy has no ingress rules — default-deny"
        );

        assert_eq!(resp.results[1].policy_namespace, "");
        assert_eq!(resp.results[1].verdict, "Allow");
    }

    #[test]
    fn decodes_verdict_result_with_optional_fields_omitted() {
        // policyUID is `#[serde(default)]` (some synthetic test policies
        // have no UID) and reason is `#[serde(default)]` (only populated
        // for WouldDeny). Their absence must not break decoding.
        let json = r#"{
            "results": [
                {
                    "policyNamespace": "prod",
                    "policyName": "web-allow",
                    "direction": "Egress",
                    "verdict": "Allow"
                }
            ]
        }"#;
        let resp: EvaluateResponse = serde_json::from_str(json).expect("must decode");
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].policy_uid, "");
        assert_eq!(resp.results[0].reason, "");
    }

    #[test]
    fn audit_client_disabled_when_evaluator_url_unset() {
        // Save and restore env for test isolation.
        let prev = std::env::var("EVALUATOR_URL").ok();
        std::env::remove_var("EVALUATOR_URL");
        let client = AuditClient::from_env();
        assert!(!client.enabled());
        if let Some(v) = prev {
            std::env::set_var("EVALUATOR_URL", v);
        }
    }

    #[test]
    fn audit_client_enabled_when_evaluator_url_set() {
        let prev = std::env::var("EVALUATOR_URL").ok();
        std::env::set_var("EVALUATOR_URL", "http://evaluator.kguardian.svc:8082");
        let client = AuditClient::from_env();
        assert!(client.enabled());
        assert_eq!(
            client.base_url(),
            "http://evaluator.kguardian.svc:8082"
        );
        match prev {
            Some(v) => std::env::set_var("EVALUATOR_URL", v),
            None => std::env::remove_var("EVALUATOR_URL"),
        }
    }

    // Concurrency-cap regression tests for the semaphore that bounds
    // in-flight audit evaluations. Without this cap, a 1000-event
    // batch from add_pods_batch creates 1000 concurrent reqwest
    // futures and starves the (8-host) connection pool.

    #[test]
    fn semaphore_starts_with_default_permits_when_env_unset() {
        let prev = std::env::var("AUDIT_INFLIGHT_PERMITS").ok();
        std::env::remove_var("AUDIT_INFLIGHT_PERMITS");
        let c = AuditClient::from_env();
        assert_eq!(c.available_permits(), AUDIT_INFLIGHT_PERMITS);
        if let Some(v) = prev {
            std::env::set_var("AUDIT_INFLIGHT_PERMITS", v);
        }
    }

    #[test]
    fn semaphore_size_is_configurable() {
        let prev = std::env::var("AUDIT_INFLIGHT_PERMITS").ok();
        std::env::set_var("AUDIT_INFLIGHT_PERMITS", "4");
        let c = AuditClient::from_env();
        assert_eq!(c.available_permits(), 4);
        match prev {
            Some(v) => std::env::set_var("AUDIT_INFLIGHT_PERMITS", v),
            None => std::env::remove_var("AUDIT_INFLIGHT_PERMITS"),
        }
    }

    #[test]
    fn semaphore_floors_invalid_values_to_default() {
        // Operators sometimes typo `0` or non-numeric values; we don't
        // want either to silently disable concurrency (a 0-permit
        // semaphore would block every audit task forever).
        let prev = std::env::var("AUDIT_INFLIGHT_PERMITS").ok();

        std::env::set_var("AUDIT_INFLIGHT_PERMITS", "0");
        let c = AuditClient::from_env();
        // 0 floors to 1, not the full default — operators have made a
        // deliberate (if perhaps misguided) choice.
        assert_eq!(c.available_permits(), 1);

        std::env::set_var("AUDIT_INFLIGHT_PERMITS", "not-a-number");
        let c = AuditClient::from_env();
        assert_eq!(c.available_permits(), AUDIT_INFLIGHT_PERMITS);

        match prev {
            Some(v) => std::env::set_var("AUDIT_INFLIGHT_PERMITS", v),
            None => std::env::remove_var("AUDIT_INFLIGHT_PERMITS"),
        }
    }

    #[test]
    fn semaphore_clones_share_permits() {
        // AuditClient is Clone; web::Data wraps it in Arc but each
        // route handler does .get_ref().clone() to detach. The
        // semaphore must be shared, not duplicated, otherwise each
        // handler gets its own bucket of permits and the cap doesn't
        // apply globally.
        let prev = std::env::var("AUDIT_INFLIGHT_PERMITS").ok();
        std::env::set_var("AUDIT_INFLIGHT_PERMITS", "2");
        let a = AuditClient::from_env();
        let b = a.clone();

        let _p1 = a.in_flight.clone().try_acquire_owned().expect("a permit available");
        let _p2 = a.in_flight.clone().try_acquire_owned().expect("second permit available");
        // Now zero permits remain. The clone must see that.
        assert_eq!(b.available_permits(), 0);
        assert!(b.in_flight.clone().try_acquire_owned().is_err());

        match prev {
            Some(v) => std::env::set_var("AUDIT_INFLIGHT_PERMITS", v),
            None => std::env::remove_var("AUDIT_INFLIGHT_PERMITS"),
        }
    }
}
