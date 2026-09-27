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

#[derive(Debug, Clone, Serialize, PartialEq)]
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

pub(crate) fn unavailable(reason: impl Into<String>) -> Answer {
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

/// The result belongs to the workload `kind` (case-insensitive) /
/// `name`; `None` matches any.
fn is_workload(r: &TrustResult, kind: Option<&str>, name: Option<&str>) -> bool {
    let (k, n) = r
        .workload
        .split_once('/')
        .unwrap_or(("", r.workload.as_str()));
    kind.is_none_or(|x| x.eq_ignore_ascii_case(k)) && name.is_none_or(|x| x == n)
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
        results.retain(|r| is_workload(r, kind, name));
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
    fetch_bounded(
        base_url,
        token,
        namespace,
        verdict,
        MAX_EVALUATOR_BODY,
        TIMEOUT,
    )
    .await
}

/// [`fetch`] with a smaller body cap and timeout, for callers that read
/// it on every request (the workload profile).
pub async fn fetch_bounded(
    base_url: &str,
    token: Option<&str>,
    namespace: Option<&str>,
    verdict: Option<&str>,
    max_body: usize,
    timeout: Duration,
) -> Result<(Option<String>, Vec<TrustResult>), String> {
    let filters: Vec<(&str, &str)> = [("namespace", namespace), ("verdict", verdict)]
        .into_iter()
        .filter_map(|(k, v)| Some((k, v?)))
        .collect();
    let mut req = client()
        .get(format!("{}/image-trust", base_url.trim_end_matches('/')))
        .query(&filters)
        .timeout(timeout);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    // Every reason below is a fixed phrase plus a coarse cause: API
    // clients (read scope) see it, so it never carries the evaluator's URL,
    // host, port, query or the HTTP client's error text. The full error is
    // logged here instead.
    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "image trust: evaluator request failed");
            return Err(Cause::from_send(&e).reason(timeout));
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
        s => {
            warn!(status = s, "image trust: evaluator answered an unexpected status");
            return Err(Cause::Status(s).reason(timeout));
        }
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                if body.len() + c.len() > max_body {
                    return Err(format!(
                        "the evaluator's answer is larger than {max_body} bytes; filter by namespace"
                    ));
                }
                body.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "image trust: reading the evaluator's answer failed");
                return Err(if e.is_timeout() {
                    Cause::BodyTimeout
                } else {
                    Cause::BodyRead
                }
                .reason(timeout));
            }
        }
    }
    match serde_json::from_slice::<EvaluatorAnswer>(&body) {
        Ok(a) => Ok((a.evaluated_at, a.results)),
        Err(e) => {
            warn!(error = %e, "image trust: the evaluator's answer did not parse");
            Err(Cause::Invalid.reason(timeout))
        }
    }
}

/// Why an evaluator read failed, coarse enough to show to any API client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    Timeout,
    Connect,
    Request,
    Status(u16),
    BodyTimeout,
    BodyRead,
    Invalid,
}

impl Cause {
    fn from_send(e: &reqwest::Error) -> Cause {
        if e.is_timeout() {
            Cause::Timeout
        } else if e.is_connect() {
            Cause::Connect
        } else {
            Cause::Request
        }
    }

    /// The user-safe reason: fixed words and numbers only.
    pub(crate) fn reason(self, timeout: Duration) -> String {
        let ms = timeout.as_millis();
        match self {
            Cause::Timeout => format!("the evaluator did not answer within {ms} ms"),
            Cause::Connect => "the evaluator could not be reached: connection failed".into(),
            Cause::Request => "the evaluator could not be reached: request failed".into(),
            Cause::Status(s) => format!("the evaluator answered with status {s}"),
            Cause::BodyTimeout => format!("the evaluator's answer did not arrive within {ms} ms"),
            Cause::BodyRead => "the evaluator's answer could not be read".into(),
            Cause::Invalid => "the evaluator sent an invalid response".into(),
        }
    }
}

/// The largest evaluator answer the workload profile reads (one
/// namespace); more makes its imageTrust unavailable, and
/// `GET /image-trust?namespace=` still has it.
pub const PROFILE_MAX_EVALUATOR_BODY: usize = 1024 * 1024;
/// Results listed in a workload profile's imageTrust.
pub const PROFILE_RESULTS: usize = 20;
/// The profile's evaluator read gives up after this, so a slow or down
/// evaluator costs a workload page at most this long.
pub const PROFILE_TIMEOUT: Duration = Duration::from_millis(2_000);
/// How long a namespace's answer is reused by later profile reads.
pub const CACHE_TTL: Duration = Duration::from_secs(30);
/// How long a failed read ("unavailable") is reused, so a down evaluator
/// is asked at most this often per namespace.
pub const CACHE_TTL_UNAVAILABLE: Duration = Duration::from_secs(10);
/// Namespaces cached at most; the oldest finished entry goes first.
pub const CACHE_MAX_ENTRIES: usize = 128;
/// Estimated bytes of cached results at most, across every namespace.
/// The cache lives outside the read budget, so it is bounded here; a
/// single answer larger than this is served but not kept.
pub const CACHE_MAX_BYTES: usize = 16 * 1024 * 1024;

type Fetched = Result<(Option<String>, std::sync::Arc<Vec<TrustResult>>), String>;

/// A finished read of one (evaluator, namespace).
#[derive(Clone)]
enum Done {
    Value {
        at: std::time::Instant,
        value: Fetched,
        bytes: usize,
    },
    /// The read budget was exhausted: nothing was read, nothing is kept.
    Shed,
}

/// One read of one key, shared by every request that needs it while it
/// runs (single-flight) and, once finished, until it expires.
#[derive(Default)]
struct Flight {
    cell: tokio::sync::OnceCell<Done>,
}

impl Flight {
    /// Usable now: still running (join it) or finished and fresh.
    fn usable(&self, now: std::time::Instant) -> bool {
        match self.cell.get() {
            None => true,
            Some(Done::Shed) => false,
            Some(Done::Value { at, value, .. }) => {
                let ttl = if value.is_ok() {
                    CACHE_TTL
                } else {
                    CACHE_TTL_UNAVAILABLE
                };
                now.duration_since(*at) < ttl
            }
        }
    }

    fn finished(&self) -> Option<(std::time::Instant, usize)> {
        match self.cell.get() {
            Some(Done::Value { at, bytes, .. }) => Some((*at, *bytes)),
            _ => None,
        }
    }
}

type Key = (String, String);

/// (evaluator URL, namespace) -> its read. Bounded by entries and bytes;
/// the oldest finished entries go first. Running reads are never evicted.
#[derive(Default)]
struct Cache {
    entries: std::collections::HashMap<Key, std::sync::Arc<Flight>>,
}

impl Cache {
    /// The flight for `key`: the running or fresh one, else a new one.
    fn flight(&mut self, key: &Key, now: std::time::Instant) -> std::sync::Arc<Flight> {
        if let Some(f) = self.entries.get(key).filter(|f| f.usable(now)) {
            return f.clone();
        }
        self.entries.remove(key);
        let f = std::sync::Arc::new(Flight::default());
        if self.entries.len() >= CACHE_MAX_ENTRIES && !self.evict_oldest(None) {
            // Every entry is a running read: serve this one uncached rather
            // than grow past the bound.
            return f;
        }
        self.entries.insert(key.clone(), f.clone());
        f
    }

    fn evict_oldest(&mut self, keep: Option<&Key>) -> bool {
        let oldest = self
            .entries
            .iter()
            .filter(|(k, _)| Some(*k) != keep)
            .filter_map(|(k, f)| f.finished().map(|(at, _)| (at, k.clone())))
            .min();
        match oldest {
            Some((_, k)) => {
                self.entries.remove(&k);
                true
            }
            None => false,
        }
    }

    fn bytes(&self) -> usize {
        self.entries
            .values()
            .filter_map(|f| f.finished().map(|(_, b)| b))
            .sum()
    }

    /// After `key`'s flight finished: drop it if it was shed or is larger
    /// than the whole cap, then evict the oldest others until the byte cap
    /// holds.
    fn settle(&mut self, key: &Key, flight: &std::sync::Arc<Flight>) {
        let mine = self
            .entries
            .get(key)
            .is_some_and(|f| std::sync::Arc::ptr_eq(f, flight));
        match flight.cell.get() {
            Some(Done::Shed) if mine => {
                self.entries.remove(key);
            }
            Some(Done::Value { bytes, .. }) if mine && *bytes > CACHE_MAX_BYTES => {
                self.entries.remove(key);
            }
            _ => {}
        }
        while self.bytes() > CACHE_MAX_BYTES && self.evict_oldest(Some(key)) {}
    }
}

fn cache() -> &'static std::sync::Mutex<Cache> {
    static C: OnceLock<std::sync::Mutex<Cache>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// Rough resident size of cached results: their strings plus overhead.
fn estimate_bytes(v: &Fetched) -> usize {
    match v {
        Err(reason) => reason.len() + 64,
        Ok((at, results)) => {
            at.as_ref().map_or(0, String::len)
                + results
                    .iter()
                    .map(|r| {
                        r.policy.len()
                            + r.namespace.len()
                            + r.workload.len()
                            + r.container.len()
                            + r.digest.len()
                            + r.image.len()
                            + r.verdict.len()
                            + r.reason.as_ref().map_or(0, String::len)
                            + 8 * std::mem::size_of::<String>()
                    })
                    .sum::<usize>()
        }
    }
}

/// The ImageTrustPolicy results for one workload, for its profile
/// (contract v1.9): the namespace's results from the evaluator, shaped to
/// the workload. No evaluator, or any failure, is `available: false` with
/// the reason: unknown, never "nothing would be denied".
///
/// Call it only for a workload that exists (the profile handler resolves
/// the workload first), so unknown namespaces never cost a read or a cache
/// entry. Concurrent requests for one namespace share one read and one
/// budget charge; a finished read is reused for [`CACHE_TTL`] (an
/// unavailable one for [`CACHE_TTL_UNAVAILABLE`]).
pub async fn for_workload(
    audit: Option<&AuditClient>,
    budget: &ReadBudget,
    namespace: &str,
    kind: &str,
    name: &str,
) -> Answer {
    let Some(audit) = audit.filter(|a| a.enabled()) else {
        return unavailable(
            "no evaluator is configured (EVALUATOR_URL): ImageTrustPolicy results are not available",
        );
    };
    let key: Key = (audit.base_url().to_string(), namespace.to_string());
    let Ok(flight) = cache()
        .lock()
        .map(|mut c| c.flight(&key, std::time::Instant::now()))
    else {
        return unavailable("the image trust cache is unavailable");
    };
    let done = flight
        .cell
        .get_or_init(|| async {
            // Charged once per real read, by whichever request runs it.
            let Ok(_permit) = budget
                .acquire(crate::read_budget::cost_kib(
                    1,
                    PROFILE_MAX_EVALUATOR_BODY as u64,
                ))
                .await
            else {
                return Done::Shed;
            };
            let token = read_token();
            let value = fetch_bounded(
                audit.base_url(),
                token.as_deref(),
                Some(namespace),
                None,
                PROFILE_MAX_EVALUATOR_BODY,
                PROFILE_TIMEOUT,
            )
            .await
            .map(|(at, results)| (at, std::sync::Arc::new(results)));
            let bytes = estimate_bytes(&value);
            Done::Value {
                at: std::time::Instant::now(),
                value,
                bytes,
            }
        })
        .await
        .clone();
    if let Ok(mut c) = cache().lock() {
        c.settle(&key, &flight);
    }
    match done {
        Done::Shed => unavailable("the broker is shedding reads (read budget); try again"),
        Done::Value {
            value: Err(reason), ..
        } => unavailable(reason),
        Done::Value {
            value: Ok((at, results)),
            ..
        } => {
            // Copy out only this workload's rows.
            let mine: Vec<TrustResult> = results
                .iter()
                .filter(|r| is_workload(r, Some(kind), Some(name)))
                .cloned()
                .collect();
            shape(at, mine, Some(kind), Some(name), PROFILE_RESULTS)
        }
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
