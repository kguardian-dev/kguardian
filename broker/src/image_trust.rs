//! `GET /image-trust` (read): the evaluator's ImageTrustPolicy results
//! (#1533 P2-2), served through the broker so the assistant, the CLI and
//! the UI need only the broker and its READ token.
//!
//! The evaluator computes, per policy and running container, Trusted /
//! WouldDeny / Unknown with a reason, and serves them at its own
//! `GET /image-trust` behind the same READ token. This route forwards the
//! namespace and verdict filters, applies the workload filter, bounds the
//! answer, and says plainly when there is nothing to report on:
//!
//! - `available: false` with a `reason` when the evaluator is not
//!   configured (`EVALUATOR_URL` unset), image trust evaluation is off in
//!   it, it refused the token, or it could not be read. Never an empty
//!   "all clear".
//! - `evaluatedAt: null` when the evaluator has not finished a pass.
//!
//! Results are report-only: kguardian never admits or blocks anything.

use crate::audit::AuditClient;
use crate::read_budget::ReadBudget;
use actix_web::{get, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

/// Largest evaluator answer read; more is refused (filter by namespace).
pub const MAX_EVALUATOR_BODY: usize = 16 * 1024 * 1024;
/// Results returned by default / at most.
pub const DEFAULT_LIMIT: usize = 200;
pub const MAX_LIMIT: usize = 2000;
const TIMEOUT: Duration = Duration::from_secs(10);
pub const VERDICTS: [&str; 3] = ["Trusted", "WouldDeny", "Unknown"];

#[derive(Debug, Deserialize)]
pub struct Query {
    pub namespace: Option<String>,
    pub workload_kind: Option<String>,
    pub workload_name: Option<String>,
    pub verdict: Option<String>,
    pub limit: Option<usize>,
}

/// One (policy, container) result, as the evaluator reports it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TrustResult {
    pub policy: String,
    pub namespace: String,
    pub workload: String,
    pub container: String,
    pub digest: String,
    #[serde(default)]
    pub image: String,
    pub verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EvaluatorAnswer {
    #[serde(rename = "evaluatedAt")]
    evaluated_at: Option<String>,
    #[serde(default)]
    results: Vec<TrustResult>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Answer {
    pub available: bool,
    /// Why nothing can be reported (`available: false`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evaluated_at: Option<String>,
    /// Counts over every matching result (before `limit`).
    pub total: usize,
    pub would_deny: usize,
    pub unknown: usize,
    pub trusted: usize,
    pub policies: Vec<String>,
    /// WouldDeny first, then Unknown, then Trusted.
    pub results: Vec<TrustResult>,
    pub truncated: bool,
}

fn unavailable(reason: impl Into<String>) -> Answer {
    Answer {
        available: false,
        reason: Some(reason.into()),
        evaluated_at: None,
        total: 0,
        would_deny: 0,
        unknown: 0,
        trusted: 0,
        policies: Vec::new(),
        results: Vec::new(),
        truncated: false,
    }
}

/// WouldDeny first, then Unknown, then Trusted. A verdict this broker does
/// not know (a newer evaluator) sorts and counts as Unknown, never Trusted.
fn rank(v: &str) -> u8 {
    match v {
        "WouldDeny" => 0,
        "Trusted" => 2,
        _ => 1,
    }
}

/// Filters, orders and bounds evaluator results. Pure.
pub fn shape(
    evaluated_at: Option<String>,
    mut results: Vec<TrustResult>,
    kind: Option<&str>,
    name: Option<&str>,
    limit: usize,
) -> Answer {
    if kind.is_some() || name.is_some() {
        results.retain(|r| {
            let (k, n) = r
                .workload
                .split_once('/')
                .unwrap_or(("", r.workload.as_str()));
            kind.is_none_or(|x| x.eq_ignore_ascii_case(k)) && name.is_none_or(|x| x == n)
        });
    }
    results.sort_by(|a, b| {
        (
            rank(&a.verdict),
            &a.namespace,
            &a.workload,
            &a.container,
            &a.policy,
        )
            .cmp(&(
                rank(&b.verdict),
                &b.namespace,
                &b.workload,
                &b.container,
                &b.policy,
            ))
    });
    let count = |v: &str| results.iter().filter(|r| r.verdict == v).count();
    let mut policies: Vec<String> = results.iter().map(|r| r.policy.clone()).collect();
    policies.sort();
    policies.dedup();
    let total = results.len();
    let (would_deny, trusted) = (count("WouldDeny"), count("Trusted"));
    // Everything else is Unknown, including verdicts this broker does not
    // know, so the three counts always add up to `total`.
    let unknown = total - would_deny - trusted;
    let truncated = total > limit;
    results.truncate(limit);
    Answer {
        available: true,
        reason: None,
        evaluated_at,
        total,
        would_deny,
        unknown,
        trusted,
        policies,
        results,
        truncated,
    }
}

/// The READ credential the evaluator checks: the scoped read token, or the
/// shared token.
pub(crate) fn read_token() -> Option<String> {
    ["BROKER_TOKEN_READ", "BROKER_AUTH_TOKEN"]
        .into_iter()
        .filter_map(|k| std::env::var(k).ok())
        .map(|t| t.trim().to_string())
        .find(|t| !t.is_empty())
}

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Reads the evaluator's results (namespace and verdict filters applied
/// there), presenting `token` as the READ credential. The error is the
/// reason nothing can be reported.
pub async fn fetch(
    base_url: &str,
    token: Option<&str>,
    namespace: Option<&str>,
    verdict: Option<&str>,
) -> Result<(Option<String>, Vec<TrustResult>), String> {
    let filters: Vec<(&str, &str)> = [("namespace", namespace), ("verdict", verdict)]
        .into_iter()
        .filter_map(|(k, v)| Some((k, v?)))
        .collect();
    let mut req = client()
        .get(format!("{}/image-trust", base_url.trim_end_matches('/')))
        .query(&filters);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "image trust: evaluator unreachable");
            return Err(if e.is_timeout() {
                format!(
                    "the evaluator did not answer within {} s",
                    TIMEOUT.as_secs()
                )
            } else {
                format!("the evaluator could not be reached: {e}")
            });
        }
    };
    match resp.status().as_u16() {
        200 => {}
        404 => {
            return Err(String::from(
                "image trust evaluation is off in the evaluator (evaluator.imageTrust; it follows supplychain.signatureDiscovery)",
            ))
        }
        401 | 403 => {
            return Err(String::from(
                "the evaluator refused the broker's read token; check that the broker and the evaluator hold the same READ-scope token",
            ))
        }
        s => return Err(format!("the evaluator answered {s}")),
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                if body.len() + c.len() > MAX_EVALUATOR_BODY {
                    return Err(format!(
                        "the evaluator's answer is larger than {MAX_EVALUATOR_BODY} bytes; filter by namespace"
                    ));
                }
                body.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(e) if e.is_timeout() => {
                return Err(format!(
                    "the evaluator's answer did not arrive within {} s",
                    TIMEOUT.as_secs()
                ))
            }
            Err(e) => return Err(format!("reading the evaluator's answer: {e}")),
        }
    }
    match serde_json::from_slice::<EvaluatorAnswer>(&body) {
        Ok(a) => Ok((a.evaluated_at, a.results)),
        Err(e) => Err(format!("the evaluator's answer did not parse: {e}")),
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[get(
    "/image-trust",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_image_trust(
    audit: web::Data<AuditClient>,
    budget: web::Data<ReadBudget>,
    query: web::Query<Query>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let verdict = non_empty(q.verdict);
    if let Some(v) = verdict.as_deref() {
        if !VERDICTS.contains(&v) {
            return Ok(
                HttpResponse::BadRequest().body(format!("verdict must be one of {VERDICTS:?}"))
            );
        }
    }
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    if !audit.enabled() {
        return Ok(HttpResponse::Ok().json(unavailable(
            "no evaluator is configured (EVALUATOR_URL): ImageTrustPolicy results are not available",
        )));
    }
    // The evaluator's answer is held while it is filtered.
    let _permit = match budget
        .acquire(crate::read_budget::cost_kib(1, MAX_EVALUATOR_BODY as u64))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let namespace = non_empty(q.namespace);
    let token = read_token();
    let answer = match fetch(
        audit.base_url(),
        token.as_deref(),
        namespace.as_deref(),
        verdict.as_deref(),
    )
    .await
    {
        Ok((at, results)) => shape(
            at,
            results,
            non_empty(q.workload_kind).as_deref(),
            non_empty(q.workload_name).as_deref(),
            limit,
        ),
        Err(reason) => unavailable(reason),
    };
    Ok(HttpResponse::Ok().json(answer))
}

#[cfg(test)]
#[path = "image_trust_tests.rs"]
mod tests;
