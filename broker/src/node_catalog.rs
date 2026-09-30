//! Node catalog: the broker side of in-house node SBOM cataloging
//! (docs/design/node-catalog.md).
//!
//! Each node's Controller offers the inventory digests it runs; the broker
//! grants each digest to exactly one node that really runs it, and stores
//! the SBOM that node's cataloger produced as SBOM source `node` (trust
//! `scanned`) in the supply-chain tables, where the read side, the
//! CycloneDX export and the matcher already find it.
//!
//! # Routes
//!
//! | route | scope | |
//! |---|---|---|
//! | `POST /catalog/claims` | catalog | offer digests, get at most one grant |
//! | `PUT /catalog/claims/{digest}` | catalog | renew, fail or skip a held claim |
//! | `POST /catalog/images/{digest}/sbom` | catalog | upload the SBOM (paged) under a claim |
//! | `GET /catalog/coverage` | read | cluster-wide coverage |
//! | `GET /catalog/status?node=` | read | one node's claims and outcomes |
//!
//! The three writes refuse with 503 unless `BROKER_TOKEN_CATALOG` is
//! configured (which also means broker auth is on): an open broker would
//! let any pod post a node SBOM. The reads always answer.
//!
//! # Claims
//!
//! One transaction per offer, the database's `now()` the only clock:
//! insert the offered digests the inventory knows as `pending`, then grant
//! the first claimable one ([`GRANT_SQL`]) with `FOR UPDATE SKIP LOCKED`,
//! so concurrent claimers never wait on each other and never share a
//! digest. A digest is claimable when it is pending, failed with its
//! backoff elapsed, claimed with an expired lease, or done under an older
//! catalog epoch; and only by a node whose epoch is at least the row's,
//! that is not in the row's `skipped_nodes` (24 h), and on which the
//! inventory sees a live pod running it (`kg_digest_runs_on_node`, in the
//! migration). `NODE_CATALOG_GRANTS=false` stops every grant at once;
//! uploads under a live lease still complete.
//!
//! A held claim ends in one of three ways ([`release`] is the state
//! machine): an upload stores the SBOM (`done`); the node reports a failure
//! (`timeout`/`oom`/`error` back off 1 h, 6 h, then 24 h; `pid_gone` and
//! `drift` release it to other nodes at once, at most 3 times per node in
//! 24 h before that node is skipped; the per-node reasons skip the node for
//! 24 h); or the lease expires and another claimer takes it.
//!
//! # Uploads
//!
//! The body is the supply-chain `ImageSBOM` v1 (pages and all, the same
//! staging, the same limits) plus the cataloger's own fields
//! (cataloger/PROTOCOL.md 4.1): top-level `epoch`, `completeness`,
//! `partial_reasons`, `stats`, optional `platform`, and per component
//! `files_truncated` / `interpreted_content`. A component may carry up to
//! [`MAX_CATALOG_PATHS`] file paths (the generic route keeps 16). Every page
//! re-checks, in the transaction that stores it, that `X-Kguardian-Claim`
//! is the row's token and its lease is live, and that the payload's epoch
//! is not below the row's; otherwise 409 and nothing is written. The page
//! that completes the set marks the claim `done`.

use crate::auth::AuthConfig;
use crate::image_inventory::{is_valid_digest, running_sql, running_window_secs};
use crate::read_budget::{cost_kib, ReadBudget};
use crate::supplychain::{
    self, bounded_vec, de_licenses, de_observed_in, inflate_bounded, normalise_sbom_from,
    store_sbom_with, Assembled, DbError, Outcome, PrepareError, SbomPayload, WireComponent,
    WireImage, WireImageSbom, WirePage, WireScanner, NODE_SOURCE, TOO_MANY_ITEMS,
};
use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Bool, Double, Jsonb, Nullable, Text, Timestamptz};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use tracing::{debug, info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

/// The token env var the catalog writes require.
pub const TOKEN_ENV: &str = "BROKER_TOKEN_CATALOG";
/// Request header carrying the claim token on renew and upload.
pub const CLAIM_HEADER: &str = "x-kguardian-claim";
/// What every node SBOM is stored as.
pub const SCANNER_NAME: &str = "kguardian-cataloger";
pub const SBOM_TRUST: &str = "scanned";

/// Lease granted (and renewed) per claim. The Controller renews every 60 s.
pub const LEASE_SECS: i64 = 15 * 60;
/// Digests one offer may carry.
pub const MAX_OFFER: usize = 512;
/// JSON body limit for the claim routes.
pub const CLAIM_JSON_LIMIT_BYTES: usize = 64 * 1024;
/// File paths kept per component on the catalog route: the cataloger's
/// `max_paths_per_package` ceiling. More sets `files_truncated`.
pub const MAX_CATALOG_PATHS: usize = 4096;
/// File paths one page may carry in all, counted while parsing: the memory
/// bound for a page of path-heavy components. A single 4096-path
/// component fits many times over.
pub const MAX_CATALOG_PATHS_PER_PAGE: usize = 200_000;
/// Compressed body limit for an upload page. Above the supply-chain
/// route's 1 MiB so one component with 4096 long paths fits in a page.
pub const MAX_CATALOG_COMPRESSED_BYTES: usize = 8 * 1024 * 1024;
/// Inflated body ceiling for an upload page (4096 paths of 1024 bytes is
/// about 4.3 MiB of JSON).
pub const MAX_CATALOG_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
/// `stats` kept per SBOM, serialised.
const MAX_STATS_BYTES: usize = 16 * 1024;
const MAX_PARTIAL_REASONS: usize = 16;
/// pid_gone / drift failures one node may report for one digest within
/// [`SKIP_SECS`] before it is skipped.
pub const RETRY_CAP: i64 = 3;
/// How long a skipped node stays skipped, and the retry-cap window.
pub const SKIP_SECS: i64 = 24 * 3600;
/// Backoff after the 1st, 2nd and 3rd-or-later timeout/oom/error.
pub const BACKOFF_SECS: [i64; 3] = [3600, 6 * 3600, 24 * 3600];
/// `NODE_CATALOG_RETENTION_DAYS` default.
pub const DEFAULT_RETENTION_DAYS: u32 = 14;
/// `NODE_CATALOG_MAX_EPOCH` default: the highest catalog epoch the broker
/// accepts. The epoch is asserted by the caller, so without a ceiling one
/// claim at i64::MAX would leave every done row un-re-catalogable.
pub const DEFAULT_MAX_EPOCH: i64 = 1000;
/// `NODE_CATALOG_MAX_HOLD_SECS` default: a claim is not renewed once held
/// this long (twice the cataloger's 30 min scan ceiling, plus the upload).
pub const DEFAULT_MAX_HOLD_SECS: i64 = 2 * 3600;
/// Upload bodies being read or waiting for the ingest worker at once;
/// beyond this a new upload gets 503 before its body is read.
pub const UPLOAD_SLOTS: usize = 2 * supplychain::INGEST_QUEUE;
/// Node uploads queued on the shared ingest worker at once: half its
/// queue, so node traffic cannot fill it for the supply-chain sources.
pub const NODE_QUEUE_SLOTS: usize = supplychain::INGEST_QUEUE / 2;

/// Per-package flag bits in `node_sbom_package_flags`.
pub const FLAG_FILES_TRUNCATED: i16 = 1;
pub const FLAG_INTERPRETED_CONTENT: i16 = 2;

pub const COMPLETENESS: [&str; 3] = ["full", "partial", "os_only"];

const LEN_NODE: usize = 253;
const LEN_PLATFORM: usize = 64;
const LEN_REASON: usize = 64;

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

/// Settings read once from the environment. Handlers take a
/// `web::Data<CatalogConfig>` when one is registered (tests), else this.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CatalogConfig {
    /// `NODE_CATALOG_GRANTS` (default true): the kill switch.
    pub grants: bool,
    /// `NODE_CATALOG_RETENTION_DAYS` (default 14; 0 keeps rows forever).
    pub retention_days: u32,
    /// `NODE_CATALOG_MAX_EPOCH` (default 1000): higher epochs get 422.
    pub max_epoch: i64,
    /// `NODE_CATALOG_MAX_HOLD_SECS` (default 7200, at least the lease):
    /// renewing a claim held longer gets 409.
    pub max_hold_secs: i64,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        CatalogConfig {
            grants: true,
            retention_days: DEFAULT_RETENTION_DAYS,
            max_epoch: DEFAULT_MAX_EPOCH,
            max_hold_secs: DEFAULT_MAX_HOLD_SECS,
        }
    }
}

pub(crate) fn parse_max_epoch(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(DEFAULT_MAX_EPOCH)
}

pub(crate) fn parse_max_hold(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n.max(LEASE_SECS))
        .unwrap_or(DEFAULT_MAX_HOLD_SECS)
}

pub(crate) fn parse_grants(raw: Option<&str>) -> bool {
    !matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("false" | "0" | "no" | "off")
    )
}

pub(crate) fn parse_retention_days(raw: Option<&str>) -> u32 {
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

impl CatalogConfig {
    pub fn from_env() -> Self {
        CatalogConfig {
            grants: parse_grants(std::env::var("NODE_CATALOG_GRANTS").ok().as_deref()),
            retention_days: parse_retention_days(
                std::env::var("NODE_CATALOG_RETENTION_DAYS").ok().as_deref(),
            ),
            max_epoch: parse_max_epoch(std::env::var("NODE_CATALOG_MAX_EPOCH").ok().as_deref()),
            max_hold_secs: parse_max_hold(
                std::env::var("NODE_CATALOG_MAX_HOLD_SECS").ok().as_deref(),
            ),
        }
    }

    /// The process-wide config, read once.
    pub fn global() -> CatalogConfig {
        static C: std::sync::OnceLock<CatalogConfig> = std::sync::OnceLock::new();
        *C.get_or_init(CatalogConfig::from_env)
    }
}

fn config_of(req: &HttpRequest) -> CatalogConfig {
    req.app_data::<web::Data<CatalogConfig>>()
        .map(|c| *c.get_ref())
        .unwrap_or_else(CatalogConfig::global)
}

/// Catalog writes run only when `BROKER_TOKEN_CATALOG` supplied a token.
pub fn catalog_allowed(cfg: Option<&AuthConfig>) -> bool {
    cfg.is_some_and(|c| c.enabled() && c.configured_by(TOKEN_ENV))
}

fn not_configured() -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header(("Retry-After", "60"))
        .body(format!(
            "the node catalog requires scoped broker auth: set {TOKEN_ENV} \
             (chart: broker.auth.keys.catalog) and give the controller that token"
        ))
}

/// The pool, taken inside the handler (not as an extractor) so the 503
/// for an unconfigured catalog comes first.
fn pool_of(req: &HttpRequest) -> actix_web::Result<web::Data<DbPool>> {
    req.app_data::<web::Data<DbPool>>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("no database pool"))
}

fn auth_of(req: &HttpRequest) -> Option<&AuthConfig> {
    req.app_data::<web::Data<AuthConfig>>().map(|d| d.get_ref())
}

/// Record, once at startup, whether the catalog token is configured (the
/// `kguardian_node_catalog_token_missing` gauge).
pub fn record_auth(cfg: &AuthConfig) {
    TOKEN_STATE.store(
        if catalog_allowed(Some(cfg)) { 1 } else { 2 },
        Ordering::Relaxed,
    );
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

/// A Kubernetes node name (DNS subdomain).
pub fn valid_node(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= LEN_NODE
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

/// `os/arch[/variant]`, lower-case.
pub fn valid_platform(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    s.len() <= LEN_PLATFORM
        && (2..=3).contains(&parts.len())
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn refuse(msg: impl Into<String>) -> Box<HttpResponse> {
    Box::new(bad(msg))
}

fn bad(msg: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().body(msg.into())
}

// Boxed: HttpResponse is large (clippy::result_large_err).
fn claim_token(req: &HttpRequest) -> Result<uuid::Uuid, Box<HttpResponse>> {
    let raw = req
        .headers()
        .get(CLAIM_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if raw.is_empty() {
        return Err(refuse(format!("the {CLAIM_HEADER} header is required")));
    }
    uuid::Uuid::parse_str(raw).map_err(|_| refuse(format!("{CLAIM_HEADER} is not a claim token")))
}

// ---------------------------------------------------------------------
// The claim state machine
// ---------------------------------------------------------------------

/// How a reported failure releases a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClass {
    /// The image's fault or the scan's: back off 1 h, 6 h, then 24 h.
    Backoff,
    /// This instance's fault (the container went away, drifted): any node
    /// may take it at once; capped per node.
    Retry,
    /// This node can't catalog it: skip the node for 24 h, others may.
    PerNode,
    /// Nothing to catalog, whoever tries (`no_packages_found`).
    Terminal,
}

const BACKOFF_REASONS: [&str; 3] = ["timeout", "oom", "error"];
const RETRY_REASONS: [&str; 3] = ["pid_gone", "drift", "exited_before_catalog"];
const PER_NODE_REASONS: [&str; 9] = [
    "sandboxed",
    "lazy_snapshotter",
    "unsupported_rootfs",
    "kernel_unsupported",
    "lsm_denied",
    "caps_unavailable",
    "deferred_pressure",
    "worker_unavailable",
    "no_cataloger",
];
const TERMINAL_REASONS: [&str; 1] = ["no_packages_found"];

/// The class of a failure reason; `None` for a reason the broker does not
/// know (refused, so the label sets stay closed).
pub fn classify(reason: &str) -> Option<FailClass> {
    if BACKOFF_REASONS.contains(&reason) {
        Some(FailClass::Backoff)
    } else if RETRY_REASONS.contains(&reason) {
        Some(FailClass::Retry)
    } else if PER_NODE_REASONS.contains(&reason) {
        Some(FailClass::PerNode)
    } else if TERMINAL_REASONS.contains(&reason) {
        Some(FailClass::Terminal)
    } else {
        None
    }
}

/// Backoff after the `failures`-th consecutive timeout/oom/error.
pub fn backoff_secs(failures: i32) -> i64 {
    BACKOFF_SECS[(failures.max(1) as usize - 1).min(BACKOFF_SECS.len() - 1)]
}

/// Whether an upload under epoch `payload` may complete a claim granted
/// under `grant`: never below the grant's epoch.
pub fn accepts_epoch(grant: i64, payload: i64) -> bool {
    payload >= grant
}

/// A node's pid_gone / drift failures for one digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeRetry {
    pub n: i64,
    pub since: DateTime<Utc>,
}

/// The row after a failure or skip.
#[derive(Debug, Clone, PartialEq)]
pub struct Released {
    pub state: &'static str,
    pub failures: i32,
    /// `next_attempt_at` = now + this, for a `failed` row.
    pub backoff_secs: Option<i64>,
    pub skipped_nodes: BTreeMap<String, DateTime<Utc>>,
    pub node_retries: BTreeMap<String, NodeRetry>,
    /// This release put `node` into `skipped_nodes`.
    pub skipped: bool,
}

/// Apply a failure of class `class` reported by `node` at `now` (the
/// database's clock) to a claimed row. Pure; [`update_claim`] writes it.
/// Expired skips and retry windows are dropped on the way.
pub fn release(
    failures: i32,
    mut skipped_nodes: BTreeMap<String, DateTime<Utc>>,
    mut node_retries: BTreeMap<String, NodeRetry>,
    node: &str,
    class: FailClass,
    now: DateTime<Utc>,
) -> Released {
    let window = chrono::Duration::seconds(SKIP_SECS);
    skipped_nodes.retain(|_, at| now - *at < window);
    node_retries.retain(|_, r| now - r.since < window);
    let mut out = Released {
        state: "pending",
        failures,
        backoff_secs: None,
        skipped_nodes,
        node_retries,
        skipped: false,
    };
    match class {
        FailClass::Backoff => {
            out.failures = failures.saturating_add(1);
            out.state = "failed";
            out.backoff_secs = Some(backoff_secs(out.failures));
        }
        FailClass::Retry => {
            let r = out
                .node_retries
                .entry(node.to_string())
                .or_insert(NodeRetry { n: 0, since: now });
            r.n += 1;
            if r.n >= RETRY_CAP {
                out.node_retries.remove(node);
                out.skipped_nodes.insert(node.to_string(), now);
                out.skipped = true;
            }
        }
        FailClass::PerNode => {
            out.skipped_nodes.insert(node.to_string(), now);
            out.skipped = true;
        }
        FailClass::Terminal => out.state = "done",
    }
    out
}

// ---------------------------------------------------------------------
// Metrics (process atomics; the two table-derived gauges are refreshed by
// the leader's supply-chain pass)
// ---------------------------------------------------------------------

/// Why a grant was possible.
const GRANT_REASONS: [&str; 5] = [
    "pending",
    "backoff_elapsed",
    "lease_expired",
    "epoch",
    "sbom_missing",
];
/// How a claim became done.
const CATALOGED_REASONS: [&str; 5] = [
    "full",
    "partial",
    "os_only",
    "no_packages_found",
    "superseded",
];
const FAILED_REASONS: [&str; 6] = [
    "timeout",
    "oom",
    "error",
    "pid_gone",
    "drift",
    "exited_before_catalog",
];
/// Per-node reasons plus `retry_cap` (a node skipped for too many
/// pid_gone/drift failures).
const SKIPPED_REASONS: [&str; 10] = [
    "sandboxed",
    "lazy_snapshotter",
    "unsupported_rootfs",
    "kernel_unsupported",
    "lsm_denied",
    "caps_unavailable",
    "deferred_pressure",
    "worker_unavailable",
    "no_cataloger",
    "retry_cap",
];
/// Scan duration buckets (seconds).
const DURATION_BUCKETS: [f64; 9] = [1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0];

struct Counters<const N: usize> {
    labels: &'static [&'static str; N],
    values: [AtomicU64; N],
}

impl<const N: usize> Counters<N> {
    const fn new(labels: &'static [&'static str; N]) -> Self {
        Counters {
            labels,
            values: [const { AtomicU64::new(0) }; N],
        }
    }

    fn inc(&self, label: &str) {
        if let Some(i) = self.labels.iter().position(|l| *l == label) {
            self.values[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn get(&self, label: &str) -> u64 {
        self.labels
            .iter()
            .position(|l| *l == label)
            .map(|i| self.values[i].load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
        for (l, v) in self.labels.iter().zip(&self.values) {
            out.push_str(&format!(
                "{name}{{reason=\"{l}\"}} {}\n",
                v.load(Ordering::Relaxed)
            ));
        }
    }
}

static GRANTED: Counters<5> = Counters::new(&GRANT_REASONS);
static CATALOGED: Counters<5> = Counters::new(&CATALOGED_REASONS);
static FAILED: Counters<6> = Counters::new(&FAILED_REASONS);
static SKIPPED: Counters<10> = Counters::new(&SKIPPED_REASONS);
static DURATION_BUCKET_COUNTS: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
static DURATION_COUNT: AtomicU64 = AtomicU64::new(0);
/// Sum in milliseconds (integer, so it stays an atomic).
static DURATION_SUM_MS: AtomicU64 = AtomicU64::new(0);
/// Rows not done, from the last leader pass; -1 until one ran here.
static QUEUE_DEPTH: AtomicI64 = AtomicI64::new(-1);
/// Coverage ratio as f64 bits; valid once COVERAGE_SET.
static COVERAGE_BITS: AtomicU64 = AtomicU64::new(0);
static COVERAGE_SET: AtomicBool = AtomicBool::new(false);
/// 0 unknown (record_auth not called), 1 configured, 2 missing.
static TOKEN_STATE: AtomicU8 = AtomicU8::new(0);

fn observe_duration(ms: f64) {
    if !ms.is_finite() || ms < 0.0 {
        return;
    }
    let secs = ms / 1000.0;
    for (i, b) in DURATION_BUCKETS.iter().enumerate() {
        if secs <= *b {
            DURATION_BUCKET_COUNTS[i].fetch_add(1, Ordering::Relaxed);
        }
    }
    DURATION_COUNT.fetch_add(1, Ordering::Relaxed);
    DURATION_SUM_MS.fetch_add(ms.round() as u64, Ordering::Relaxed);
}

/// Prometheus text for the node catalog, appended to `/metrics`.
pub fn render_metrics() -> String {
    render_metrics_with(CatalogConfig::global())
}

pub(crate) fn render_metrics_with(cfg: CatalogConfig) -> String {
    let mut out = String::new();
    GRANTED.render(
        &mut out,
        "kguardian_node_catalog_granted_total",
        "Node catalog claims granted, by why the digest was claimable",
    );
    CATALOGED.render(
        &mut out,
        "kguardian_node_catalog_cataloged_total",
        "Node catalog claims completed, by completeness (or no_packages_found, superseded)",
    );
    FAILED.render(
        &mut out,
        "kguardian_node_catalog_failed_total",
        "Node catalog claims released by a failure, by reason",
    );
    SKIPPED.render(
        &mut out,
        "kguardian_node_catalog_skipped_total",
        "Nodes skipped for a digest for 24 h, by reason",
    );
    let name = "kguardian_node_catalog_scan_duration_seconds";
    out.push_str(&format!(
        "# HELP {name} Cataloger scan duration reported with completed node SBOMs\n# TYPE {name} histogram\n"
    ));
    for (b, c) in DURATION_BUCKETS.iter().zip(&DURATION_BUCKET_COUNTS) {
        out.push_str(&format!(
            "{name}_bucket{{le=\"{b}\"}} {}\n",
            c.load(Ordering::Relaxed)
        ));
    }
    let count = DURATION_COUNT.load(Ordering::Relaxed);
    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
    out.push_str(&format!(
        "{name}_sum {}\n{name}_count {count}\n",
        DURATION_SUM_MS.load(Ordering::Relaxed) as f64 / 1000.0
    ));
    out.push_str(&format!(
        "# HELP kguardian_node_catalog_grants_enabled 1 unless NODE_CATALOG_GRANTS=false\n\
         # TYPE kguardian_node_catalog_grants_enabled gauge\n\
         kguardian_node_catalog_grants_enabled {}\n",
        u8::from(cfg.grants)
    ));
    match TOKEN_STATE.load(Ordering::Relaxed) {
        0 => {}
        s => out.push_str(&format!(
            "# HELP kguardian_node_catalog_token_missing 1 while {TOKEN_ENV} is not configured (catalog writes answer 503)\n\
             # TYPE kguardian_node_catalog_token_missing gauge\n\
             kguardian_node_catalog_token_missing {}\n",
            u8::from(s == 2)
        )),
    }
    // Table-derived, so only where the leader's pass computed them: a
    // follower's zero would read as an empty queue.
    let depth = QUEUE_DEPTH.load(Ordering::Relaxed);
    if depth >= 0 {
        out.push_str(&format!(
            "# HELP kguardian_node_catalog_queue_depth Offered digests not yet cataloged (pending, claimed, failed)\n\
             # TYPE kguardian_node_catalog_queue_depth gauge\n\
             kguardian_node_catalog_queue_depth {depth}\n"
        ));
    }
    if COVERAGE_SET.load(Ordering::Relaxed) {
        out.push_str(&format!(
            "# HELP kguardian_node_catalog_coverage_ratio Share of running image digests with a trusted SBOM (Trivy Operator or node)\n\
             # TYPE kguardian_node_catalog_coverage_ratio gauge\n\
             kguardian_node_catalog_coverage_ratio {}\n",
            f64::from_bits(COVERAGE_BITS.load(Ordering::Relaxed))
        ));
    }
    out
}

// ---------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------

/// `POST /catalog/claims` body.
#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    pub node: String,
    pub platform: String,
    pub epoch: i64,
    #[serde(default)]
    pub offer: Vec<String>,
}

/// A validated offer: digests sorted and deduplicated, so concurrent
/// inserts take row locks in one order and cannot deadlock.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub node: String,
    pub platform: String,
    pub epoch: i64,
    pub digests: Vec<String>,
}

pub fn validate_offer(r: ClaimRequest, max_epoch: i64) -> Result<Offer, Box<HttpResponse>> {
    let node = r.node.trim().to_string();
    if !valid_node(&node) {
        return Err(refuse("node must be a Kubernetes node name"));
    }
    let platform = r.platform.trim().to_ascii_lowercase();
    if !valid_platform(&platform) {
        return Err(refuse("platform must be os/arch[/variant]"));
    }
    if r.epoch < 0 {
        return Err(refuse("epoch must be >= 0"));
    }
    if r.epoch > max_epoch {
        return Err(Box::new(HttpResponse::UnprocessableEntity().body(format!(
            "epoch {} is above this broker's NODE_CATALOG_MAX_EPOCH ({max_epoch})",
            r.epoch
        ))));
    }
    if r.offer.len() > MAX_OFFER {
        return Err(Box::new(
            HttpResponse::PayloadTooLarge().body(format!("at most {MAX_OFFER} digests per offer")),
        ));
    }
    let mut digests = Vec::with_capacity(r.offer.len());
    for d in r.offer {
        let d = d.trim().to_string();
        if !is_valid_digest(&d) {
            return Err(refuse(
                "offer must hold sha256:<64 hex> or sha512:<128 hex> digests",
            ));
        }
        digests.push(d);
    }
    digests.sort();
    digests.dedup();
    Ok(Offer {
        node,
        platform,
        epoch: r.epoch,
        digests,
    })
}

/// A grant, as returned to the Controller.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub digest: String,
    pub claim_token: String,
    pub lease_expires_at: DateTime<Utc>,
    pub lease_seconds: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResponse {
    pub grants_enabled: bool,
    /// At most one digest per offer; `null` when none is claimable.
    pub grant: Option<Grant>,
}

/// A node whose recorded platform is about to change: the in-use guard
/// rows that passed for containers with an instance on it were judged
/// against the old platform, so they are marked `platform_mismatch` (fail
/// closed) until the next in-use refresh judges them again. Rows that
/// already failed keep their reason, which ranks first. Runs in the
/// offer's transaction, before [`UPSERT_PLATFORM_SQL`].
pub(crate) const INVALIDATE_GUARD_SQL: &str = "\
UPDATE runtime_node_sbom_guard g SET reason = 'platform_mismatch' \
WHERE g.reason IS NULL \
  AND EXISTS (SELECT 1 FROM node_catalog_platforms p WHERE p.node = $1 AND p.platform <> $2) \
  AND EXISTS (SELECT 1 FROM runtime_coverage rc WHERE rc.node_name = $1 \
      AND rc.cluster_id = g.cluster_id AND rc.pod_namespace = g.pod_namespace \
      AND rc.workload_kind = g.workload_kind AND rc.workload_name = g.workload_name \
      AND rc.container_name = g.container_name AND rc.image_digest = g.image_digest)";

/// Record the platform `node` reports, invalidating the in-use guard rows
/// judged against its old one ([`INVALIDATE_GUARD_SQL`]). Call inside a
/// transaction.
pub(crate) fn record_platform(
    conn: &mut PgConnection,
    node: &str,
    platform: &str,
) -> QueryResult<()> {
    sql_query(INVALIDATE_GUARD_SQL)
        .bind::<Text, _>(node)
        .bind::<Text, _>(platform)
        .execute(conn)?;
    sql_query(UPSERT_PLATFORM_SQL)
        .bind::<Text, _>(node)
        .bind::<Text, _>(platform)
        .execute(conn)?;
    Ok(())
}

pub(crate) const UPSERT_PLATFORM_SQL: &str = "\
INSERT INTO node_catalog_platforms (node, platform, seen_at) VALUES ($1, $2, now()) \
ON CONFLICT (node) DO UPDATE SET platform = EXCLUDED.platform, seen_at = EXCLUDED.seen_at \
WHERE node_catalog_platforms.platform <> EXCLUDED.platform \
   OR node_catalog_platforms.seen_at < now() - interval '60 seconds'";

/// The design's insert, restricted to digests the inventory knows so a
/// token holder cannot mint rows for made-up digests.
pub(crate) const OFFER_INSERT_SQL: &str = "\
INSERT INTO node_catalog_claims (inventory_digest, state, updated_at) \
SELECT d, 'pending', now() FROM unnest($1::text[]) d \
WHERE EXISTS (SELECT 1 FROM images i WHERE i.digest = d) \
ON CONFLICT DO NOTHING";

/// Grant the first claimable offered digest. `$1` offer, `$2` node, `$3`
/// node epoch, `$4` running window (s), `$5` lease (s). The candidate is
/// picked and locked by the `LIMIT 1 FOR UPDATE SKIP LOCKED` subquery, so
/// a row another claimer holds is skipped, never waited on; `why` is the
/// clause that made it claimable (the granted counter's label).
///
/// The grant records its epoch in `grant_epoch` and never touches
/// `epoch`, which only a stored SBOM sets: a node that asserts a high
/// epoch and never uploads moves nothing, and after a rollback the older
/// cataloger still takes every row that is not done. A done row is
/// claimable again under a higher epoch, or when its node SBOM is gone
/// (the supply-chain GC removed it while the image was away).
pub(crate) const GRANT_SQL: &str = "\
UPDATE node_catalog_claims c SET state = 'claimed', node = $2, claim_token = gen_random_uuid(), \
    lease_expires_at = now() + make_interval(secs => $5), attempts = c.attempts + 1, \
    grant_epoch = $3, claimed_at = now(), updated_at = now() \
FROM ( \
    SELECT inventory_digest, CASE state WHEN 'pending' THEN 'pending' \
        WHEN 'failed' THEN 'backoff_elapsed' WHEN 'claimed' THEN 'lease_expired' \
        ELSE CASE WHEN epoch < $3 THEN 'epoch' ELSE 'sbom_missing' END END AS why \
    FROM node_catalog_claims n \
    WHERE inventory_digest = ANY($1) \
      AND ( state = 'pending' \
         OR (state = 'failed'  AND next_attempt_at <= now()) \
         OR (state = 'claimed' AND lease_expires_at <= now()) \
         OR (state = 'done'    AND (epoch < $3 \
             OR (reason IS DISTINCT FROM 'no_packages_found' AND NOT EXISTS ( \
                 SELECT 1 FROM vuln_sources vs WHERE vs.digest = n.inventory_digest \
                   AND vs.source = 'node' AND vs.kind = 'sbom')))) ) \
      AND NOT COALESCE((skipped_nodes ->> $2)::timestamptz > now() - interval '24 hours', false) \
      AND kg_digest_runs_on_node(inventory_digest, $2, $4) \
    ORDER BY priority DESC, inventory_digest LIMIT 1 \
    FOR UPDATE SKIP LOCKED \
) g \
WHERE c.inventory_digest = g.inventory_digest \
RETURNING c.inventory_digest, c.claim_token::text AS claim_token, c.lease_expires_at, g.why";

#[derive(QueryableByName)]
struct GrantRow {
    #[diesel(sql_type = Text)]
    inventory_digest: String,
    #[diesel(sql_type = Text)]
    claim_token: String,
    #[diesel(sql_type = Timestamptz)]
    lease_expires_at: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    why: String,
}

/// One offer, one transaction: record the node's platform, insert the
/// offered digests, and (unless `grants` is off) grant at most one.
pub fn claim(
    conn: &mut PgConnection,
    offer: &Offer,
    grants: bool,
    window_secs: i64,
) -> QueryResult<Option<Grant>> {
    let row = conn.transaction(|conn| {
        record_platform(conn, &offer.node, &offer.platform)?;
        if offer.digests.is_empty() {
            return Ok(None);
        }
        sql_query(OFFER_INSERT_SQL)
            .bind::<Array<Text>, _>(&offer.digests)
            .execute(conn)?;
        if !grants {
            return Ok(None);
        }
        sql_query(GRANT_SQL)
            .bind::<Array<Text>, _>(&offer.digests)
            .bind::<Text, _>(&offer.node)
            .bind::<BigInt, _>(offer.epoch)
            .bind::<Double, _>(window_secs as f64)
            .bind::<Double, _>(LEASE_SECS as f64)
            .get_result::<GrantRow>(conn)
            .optional()
    })?;
    Ok(row.map(|r| {
        GRANTED.inc(&r.why);
        Grant {
            digest: r.inventory_digest,
            claim_token: r.claim_token,
            lease_expires_at: r.lease_expires_at,
            lease_seconds: LEASE_SECS,
        }
    }))
}

async fn post_claims(
    req: HttpRequest,
    body: Result<web::Json<ClaimRequest>, actix_web::Error>,
) -> actix_web::Result<HttpResponse> {
    if !catalog_allowed(auth_of(&req)) {
        return Ok(not_configured());
    }
    let cfg = config_of(&req);
    let offer = match validate_offer(body?.into_inner(), cfg.max_epoch) {
        Ok(o) => o,
        Err(resp) => return Ok(*resp),
    };
    let grants = cfg.grants;
    let pool = pool_of(&req)?;
    let grant = web::block(move || {
        let mut conn = pool.get()?;
        claim(&mut conn, &offer, grants, running_window_secs()).map_err(DbError::from)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(ClaimResponse {
        grants_enabled: grants,
        grant,
    }))
}

/// `PUT /catalog/claims/{digest}` body.
#[derive(Debug, Deserialize)]
pub struct ClaimUpdate {
    /// `renew` | `fail` | `skip`.
    pub action: String,
    /// The node holding the claim.
    pub node: String,
    /// Required for `fail` and `skip`: a reason from the closed set.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Renew,
    Release(String, FailClass),
}

pub fn validate_update(u: &ClaimUpdate) -> Result<Action, String> {
    let reason = u.reason.as_deref().map(str::trim).unwrap_or("");
    match u.action.trim() {
        "renew" => Ok(Action::Renew),
        "fail" => match classify(reason) {
            Some(c) => Ok(Action::Release(reason.to_string(), c)),
            None => Err(format!("unknown failure reason {reason:?}")),
        },
        "skip" => match classify(reason) {
            Some(FailClass::PerNode) => Ok(Action::Release(reason.to_string(), FailClass::PerNode)),
            _ => Err(format!("skip needs a per-node reason, got {reason:?}")),
        },
        other => Err(format!("action must be renew, fail or skip, got {other:?}")),
    }
}

/// The claim token no longer holds the digest (released, re-granted, or
/// lease expired). Surfaces as 409.
#[derive(Debug)]
pub struct StaleClaim(pub String);

impl std::fmt::Display for StaleClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StaleClaim {}

#[derive(QueryableByName)]
struct HeldRow {
    #[diesel(sql_type = Nullable<Text>)]
    node: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    failures: i32,
    #[diesel(sql_type = Jsonb)]
    skipped_nodes: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    node_retries: serde_json::Value,
    /// The stored SBOM's epoch.
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    /// The epoch this claim was granted under.
    #[diesel(sql_type = BigInt)]
    grant_epoch: i64,
    #[diesel(sql_type = Bool)]
    live: bool,
    /// Seconds since the grant.
    #[diesel(sql_type = Double)]
    held_secs: f64,
    #[diesel(sql_type = Timestamptz)]
    now: DateTime<Utc>,
}

/// Lock the row `token` holds on `digest`, in the caller's transaction.
fn held(conn: &mut PgConnection, digest: &str, token: &uuid::Uuid) -> QueryResult<Option<HeldRow>> {
    sql_query(
        "SELECT node, failures, skipped_nodes, node_retries, epoch, \
             COALESCE(grant_epoch, epoch) AS grant_epoch, \
             COALESCE(lease_expires_at > now(), false) AS live, \
             COALESCE(extract(epoch FROM now() - claimed_at), 0)::float8 AS held_secs, \
             now() AS now \
         FROM node_catalog_claims \
         WHERE inventory_digest = $1 AND claim_token = $2::uuid AND state = 'claimed' \
         FOR UPDATE",
    )
    .bind::<Text, _>(digest)
    .bind::<Text, _>(token.to_string())
    .get_result(conn)
    .optional()
}

/// What a PUT did.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Updated {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<Utc>>,
}

pub fn update_claim(
    conn: &mut PgConnection,
    digest: &str,
    token: &uuid::Uuid,
    node: &str,
    action: &Action,
    max_hold_secs: i64,
) -> Result<Updated, DbError> {
    let out = conn.transaction::<_, DbError, _>(|conn| {
        let Some(row) = held(conn, digest, token)? else {
            return Err(Box::new(StaleClaim(
                "this claim token does not hold the digest".into(),
            )));
        };
        if row.node.as_deref() != Some(node) {
            return Err(Box::new(StaleClaim(
                "the claim is held by another node".into(),
            )));
        }
        match action {
            Action::Renew => {
                if !row.live {
                    return Err(Box::new(StaleClaim("the lease has expired".into())));
                }
                if row.held_secs > max_hold_secs as f64 {
                    return Err(Box::new(StaleClaim(format!(
                        "the claim has been held for {:.0} s, over the {max_hold_secs} s limit; \
                         let the lease expire",
                        row.held_secs
                    ))));
                }
                #[derive(QueryableByName)]
                struct L {
                    #[diesel(sql_type = Timestamptz)]
                    lease_expires_at: DateTime<Utc>,
                }
                let l: L = sql_query(
                    "UPDATE node_catalog_claims \
                     SET lease_expires_at = now() + make_interval(secs => $2), updated_at = now() \
                     WHERE inventory_digest = $1 RETURNING lease_expires_at",
                )
                .bind::<Text, _>(digest)
                .bind::<Double, _>(LEASE_SECS as f64)
                .get_result(conn)?;
                Ok((
                    Updated {
                        state: "claimed".into(),
                        lease_expires_at: Some(l.lease_expires_at),
                        next_attempt_at: None,
                    },
                    None,
                ))
            }
            Action::Release(reason, class) => {
                let skipped: BTreeMap<String, DateTime<Utc>> =
                    serde_json::from_value(row.skipped_nodes).unwrap_or_default();
                let retries: BTreeMap<String, NodeRetry> =
                    serde_json::from_value(row.node_retries).unwrap_or_default();
                let r = release(row.failures, skipped, retries, node, *class, row.now);
                let next = r
                    .backoff_secs
                    .map(|s| row.now + chrono::Duration::seconds(s));
                sql_query(
                    "UPDATE node_catalog_claims SET state = $2, failures = $3, \
                         next_attempt_at = $4, reason = $5, skipped_nodes = $6::jsonb, \
                         node_retries = $7::jsonb, claim_token = NULL, lease_expires_at = NULL, \
                         epoch = CASE WHEN $2 = 'done' THEN $8 ELSE epoch END, updated_at = now() \
                     WHERE inventory_digest = $1",
                )
                .bind::<Text, _>(digest)
                .bind::<Text, _>(r.state)
                .bind::<diesel::sql_types::Integer, _>(r.failures)
                .bind::<Nullable<Timestamptz>, _>(next)
                .bind::<Text, _>(reason)
                .bind::<Text, _>(serde_json::to_string(&r.skipped_nodes)?)
                .bind::<Text, _>(serde_json::to_string(&r.node_retries)?)
                .bind::<BigInt, _>(row.grant_epoch)
                .execute(conn)?;
                Ok((
                    Updated {
                        state: r.state.into(),
                        lease_expires_at: None,
                        next_attempt_at: next,
                    },
                    Some(r.skipped),
                ))
            }
        }
    })?;
    let (updated, skipped) = out;
    if let (Action::Release(reason, class), Some(skipped)) = (action, skipped) {
        match class {
            FailClass::PerNode => SKIPPED.inc(reason),
            FailClass::Terminal => CATALOGED.inc(reason),
            _ => {
                FAILED.inc(reason);
                if skipped {
                    SKIPPED.inc("retry_cap");
                }
            }
        }
    }
    Ok(updated)
}

fn stale_or_error(e: DbError) -> actix_web::Error {
    if let Some(s) = e.downcast_ref::<StaleClaim>() {
        let msg = s.0.clone();
        return actix_web::error::InternalError::from_response(
            msg.clone(),
            HttpResponse::Conflict().body(msg),
        )
        .into();
    }
    crate::db_error_response(e)
}

async fn put_claim(
    req: HttpRequest,
    path: web::Path<String>,
    body: Result<web::Json<ClaimUpdate>, actix_web::Error>,
) -> actix_web::Result<HttpResponse> {
    if !catalog_allowed(auth_of(&req)) {
        return Ok(not_configured());
    }
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(bad("digest must be sha256:<64 hex> or sha512:<128 hex>"));
    }
    let token = match claim_token(&req) {
        Ok(t) => t,
        Err(resp) => return Ok(*resp),
    };
    let u = body?.into_inner();
    let node = u.node.trim().to_string();
    if !valid_node(&node) {
        return Ok(bad("node must be a Kubernetes node name"));
    }
    let action = match validate_update(&u) {
        Ok(a) => a,
        Err(m) => return Ok(HttpResponse::UnprocessableEntity().body(m)),
    };
    let pool = pool_of(&req)?;
    let max_hold = config_of(&req).max_hold_secs;
    let updated = web::block(move || -> Result<Updated, DbError> {
        let mut conn = pool.get()?;
        update_claim(&mut conn, &digest, &token, &node, &action, max_hold)
    })
    .await?
    .map_err(stale_or_error)?;
    Ok(HttpResponse::Ok().json(updated))
}

// ---------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------

std::thread_local! {
    /// Paths the page being parsed may still carry
    /// ([`MAX_CATALOG_PATHS_PER_PAGE`]). Set by [`prepare_upload`] on the
    /// ingest worker thread for each parse; `None` (any other parse) keeps
    /// only the per-component cap.
    static PATH_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// A component's file paths: the first [`MAX_CATALOG_PATHS`], and whether
/// there were more.
#[derive(Debug, Default)]
pub struct CatalogPaths {
    pub paths: Vec<String>,
    pub truncated: bool,
}

struct CatalogPathsVisitor;

impl<'de> serde::de::Visitor<'de> for CatalogPathsVisitor {
    type Value = CatalogPaths;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "a list of paths")
    }

    fn visit_unit<E>(self) -> Result<CatalogPaths, E> {
        Ok(CatalogPaths::default())
    }

    fn visit_none<E>(self) -> Result<CatalogPaths, E> {
        Ok(CatalogPaths::default())
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<CatalogPaths, D::Error> {
        d.deserialize_seq(self)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<CatalogPaths, A::Error> {
        let mut out = CatalogPaths::default();
        loop {
            if out.paths.len() >= MAX_CATALOG_PATHS {
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    out.truncated = true;
                    while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                }
                return Ok(out);
            }
            let left = PATH_BUDGET.with(|b| b.get());
            if left == Some(0) {
                if seq.next_element::<serde::de::IgnoredAny>()?.is_none() {
                    return Ok(out);
                }
                return Err(serde::de::Error::custom(format!(
                    "{TOO_MANY_ITEMS}: more than {MAX_CATALOG_PATHS_PER_PAGE} file paths in one page"
                )));
            }
            match seq.next_element::<String>()? {
                Some(p) => {
                    PATH_BUDGET.with(|b| b.set(left.map(|n| n - 1)));
                    out.paths.push(p);
                }
                None => return Ok(out),
            }
        }
    }
}

fn de_catalog_paths<'de, D: serde::Deserializer<'de>>(d: D) -> Result<CatalogPaths, D::Error> {
    d.deserialize_option(CatalogPathsVisitor)
}

fn de_node_components<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<WireNodeComponent>, D::Error> {
    bounded_vec(d, supplychain::MAX_COMPONENTS_PER_REQUEST, true)
}

fn de_reasons<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    bounded_vec(d, MAX_PARTIAL_REASONS, false)
}

/// A component as the cataloger sends it (PROTOCOL.md 4.3): the
/// `WireComponent` fields plus the two per-package flags.
#[derive(Debug, Default, Deserialize)]
pub struct WireNodeComponent {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default, rename = "type")]
    pub comp_type: Option<String>,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub src_name: Option<String>,
    #[serde(default)]
    pub src_version: Option<String>,
    #[serde(default, deserialize_with = "de_licenses")]
    pub licenses: Vec<String>,
    #[serde(default)]
    pub layer_digest: Option<String>,
    #[serde(default, deserialize_with = "de_catalog_paths")]
    pub file_paths: CatalogPaths,
    #[serde(default)]
    pub files_truncated: bool,
    #[serde(default)]
    pub interpreted_content: bool,
}

/// The upload body: `ImageSBOM` v1 plus the cataloger's fields
/// (PROTOCOL.md 4.1). Unknown fields are ignored, as on the supply-chain
/// route.
#[derive(Debug, Deserialize)]
pub struct WireNodeSbom {
    pub schema_version: i64,
    pub image: WireImage,
    pub source: String,
    #[serde(default)]
    pub scanner: WireScanner,
    pub scanned_at: DateTime<Utc>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub spec_version: Option<String>,
    #[serde(default, deserialize_with = "de_observed_in")]
    pub observed_in: Vec<supplychain::WireWorkloadRef>,
    #[serde(default)]
    pub page: Option<WirePage>,
    #[serde(default, deserialize_with = "de_node_components")]
    pub components: Vec<WireNodeComponent>,
    /// The catalog epoch the grant was made under (echoed by the worker).
    pub epoch: i64,
    /// `full` | `partial` | `os_only`; anything else (or absent) is stored
    /// as `partial`.
    #[serde(default)]
    pub completeness: Option<String>,
    #[serde(default, deserialize_with = "de_reasons")]
    pub partial_reasons: Vec<String>,
    #[serde(default)]
    pub stats: Option<serde_json::Value>,
    /// os/arch[/variant] cataloged for; else the node's recorded platform.
    #[serde(default)]
    pub platform: Option<String>,
}

/// Per-scan fields stored on the claim row when the SBOM completes.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanMeta {
    pub epoch: i64,
    pub completeness: String,
    pub partial_reasons: Vec<String>,
    pub stats: serde_json::Value,
    pub platform: Option<String>,
    pub manifest_digest: Option<String>,
}

#[derive(Debug)]
pub struct Upload {
    pub payload: SbomPayload,
    pub meta: ScanMeta,
}

fn clean_short(s: &str, max: usize) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
    .then(|| s.to_string())
}

/// `stats` as stored: an object of at most [`MAX_STATS_BYTES`]; a larger
/// one keeps its scalar fields only (nested objects such as `budgets`
/// dropped), and anything else is `{}`.
pub fn bound_stats(v: Option<serde_json::Value>) -> serde_json::Value {
    let Some(serde_json::Value::Object(m)) = v else {
        return serde_json::json!({});
    };
    let whole = serde_json::Value::Object(m);
    if whole.to_string().len() <= MAX_STATS_BYTES {
        return whole;
    }
    let serde_json::Value::Object(m) = whole else {
        unreachable!()
    };
    let mut out = serde_json::Map::new();
    for (k, v) in m {
        if out.len() >= 64 || k.len() > LEN_REASON {
            break;
        }
        match &v {
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
                out.insert(k, v);
            }
            serde_json::Value::String(s) if s.len() <= 128 => {
                out.insert(k, v);
            }
            _ => {}
        }
    }
    serde_json::Value::Object(out)
}

/// Normalise a parsed upload for `digest` (pure, testable): source must
/// be `node`; trust and scanner name are fixed; the flags ride on each
/// component row into staging.
pub fn normalise_upload(
    digest: &str,
    w: WireNodeSbom,
    now: DateTime<Utc>,
    max_epoch: i64,
) -> Result<Upload, supplychain::Reject> {
    if w.epoch < 0 || w.epoch > max_epoch {
        return Err(supplychain::Reject::Invalid(format!(
            "epoch must be in [0, {max_epoch}] (NODE_CATALOG_MAX_EPOCH)"
        )));
    }
    let completeness = w
        .completeness
        .as_deref()
        .map(str::trim)
        .filter(|c| COMPLETENESS.contains(c))
        .unwrap_or("partial")
        .to_string();
    let mut partial_reasons: Vec<String> = w
        .partial_reasons
        .iter()
        .filter_map(|r| clean_short(r, LEN_REASON))
        .collect();
    partial_reasons.sort();
    partial_reasons.dedup();
    let platform = w
        .platform
        .as_deref()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| valid_platform(p));
    let mut flags = Vec::with_capacity(w.components.len());
    let mut components = Vec::with_capacity(w.components.len());
    for c in w.components {
        let mut f = 0i16;
        if c.files_truncated || c.file_paths.truncated {
            f |= FLAG_FILES_TRUNCATED;
        }
        if c.interpreted_content {
            f |= FLAG_INTERPRETED_CONTENT;
        }
        flags.push(f);
        components.push(WireComponent {
            name: c.name,
            version: c.version,
            purl: c.purl,
            comp_type: c.comp_type,
            class: c.class,
            src_name: c.src_name,
            src_version: c.src_version,
            licenses: c.licenses,
            layer_digest: c.layer_digest,
            file_paths: c.file_paths.paths,
        });
    }
    let sbom = WireImageSbom {
        schema_version: w.schema_version,
        image: w.image,
        source: w.source,
        scanner: w.scanner,
        scanned_at: w.scanned_at,
        format: w.format,
        spec_version: w.spec_version,
        observed_in: w.observed_in,
        page: w.page,
        components,
        attestation: None,
        sbom_trust: Some(SBOM_TRUST.into()),
    };
    let mut payload = normalise_sbom_from(
        digest,
        sbom,
        now,
        |s| s == NODE_SOURCE,
        NODE_SOURCE,
        MAX_CATALOG_PATHS,
    )?;
    payload.header.scanner_name = Some(SCANNER_NAME.into());
    payload.header.sbom_trust = Some(SBOM_TRUST.into());
    payload.header.attestation = None;
    for (row, f) in payload.rows.iter_mut().zip(flags) {
        if f != 0 {
            row.flags = Some(f);
        }
    }
    let manifest_digest = platform
        .as_ref()
        .and_then(|p| payload.header.platform_manifests.get(p).cloned());
    // The SBOM belongs to the claimed digest only: the payload's manifest
    // list, index and workloads never link it to another inventory image
    // (supplychain WANTED_LINKS_CTE also refuses them for source node).
    // The platform it was cataloged for is kept, as provenance.
    payload.header.platform_manifests = match (&platform, &manifest_digest) {
        (Some(p), Some(d)) => BTreeMap::from([(p.clone(), d.clone())]),
        _ => BTreeMap::new(),
    };
    payload.header.manifest_digests = Vec::new();
    payload.header.index_digest = None;
    payload.header.observed_in = Vec::new();
    Ok(Upload {
        payload,
        meta: ScanMeta {
            epoch: w.epoch,
            completeness,
            partial_reasons,
            stats: bound_stats(w.stats),
            platform,
            manifest_digest,
        },
    })
}

/// Inflate, parse (paths budgeted per page) and normalise one page.
pub fn prepare_upload(
    digest: &str,
    raw: &[u8],
    gzip: bool,
    now: DateTime<Utc>,
    max_epoch: i64,
) -> Result<Upload, PrepareError> {
    let inflated;
    let bytes: &[u8] = if gzip {
        inflated =
            inflate_bounded(raw, MAX_CATALOG_DECOMPRESSED_BYTES).map_err(PrepareError::Body)?;
        &inflated
    } else {
        if raw.len() > MAX_CATALOG_DECOMPRESSED_BYTES {
            return Err(PrepareError::TooMany(format!(
                "body exceeds {MAX_CATALOG_DECOMPRESSED_BYTES} bytes"
            )));
        }
        raw
    };
    PATH_BUDGET.with(|b| b.set(Some(MAX_CATALOG_PATHS_PER_PAGE)));
    let parsed = serde_json::from_slice::<WireNodeSbom>(bytes);
    PATH_BUDGET.with(|b| b.set(None));
    let w = parsed.map_err(|e| {
        let m = e.to_string();
        if m.contains(TOO_MANY_ITEMS) {
            PrepareError::TooMany(m)
        } else {
            PrepareError::Json(m)
        }
    })?;
    normalise_upload(digest, w, now, max_epoch).map_err(PrepareError::Reject)
}

/// Per-package flags of the SBOM that just replaced the stored one, from
/// the rows (whole) or the staged pages (paged), keyed `name@version`.
fn write_flags(conn: &mut PgConnection, digest: &str, a: Assembled<'_>) -> Result<(), DbError> {
    sql_query("DELETE FROM node_sbom_package_flags WHERE digest = $1")
        .bind::<Text, _>(digest)
        .execute(conn)?;
    const RECORD: &str = "(name text, version text, flags smallint)";
    const SELECT: &str = "SELECT $1, r.name || '@' || COALESCE(r.version, '') AS k, \
        bit_or(r.flags) FROM";
    const TAIL: &str = "AND COALESCE(r.flags, 0) <> 0 GROUP BY k";
    match a {
        Assembled::Whole(rows) => sql_query(format!(
            "INSERT INTO node_sbom_package_flags (digest, pkg_key, flags) \
             {SELECT} jsonb_to_recordset($2::jsonb) AS r{RECORD} WHERE true {TAIL}"
        ))
        .bind::<Text, _>(digest)
        .bind::<Text, _>(rows)
        .execute(conn)?,
        Assembled::Paged(set_id) => sql_query(format!(
            "INSERT INTO node_sbom_package_flags (digest, pkg_key, flags) \
             {SELECT} image_sbom_pages p CROSS JOIN LATERAL jsonb_to_recordset(p.components) \
                AS r{RECORD} \
             WHERE p.digest = $1 AND p.source = 'node' AND p.set_id = $2 {TAIL}"
        ))
        .bind::<Text, _>(digest)
        .bind::<Text, _>(set_id)
        .execute(conn)?,
    };
    Ok(())
}

/// Whether a node SBOM is stored for `digest`.
fn node_sbom_stored(conn: &mut PgConnection, digest: &str) -> QueryResult<bool> {
    #[derive(QueryableByName)]
    struct E {
        #[diesel(sql_type = Bool)]
        e: bool,
    }
    sql_query(
        "SELECT EXISTS (SELECT 1 FROM vuln_sources \
             WHERE digest = $1 AND source = 'node' AND kind = 'sbom') AS e",
    )
    .bind::<Text, _>(digest)
    .get_result::<E>(conn)
    .map(|r| r.e)
}

/// The result of one upload page.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Uploaded {
    #[serde(flatten)]
    pub outcome: Outcome,
    /// The claim's state after this page: `claimed` or `done`.
    pub claim: &'static str,
}

/// Store one page under `token`. One transaction: lock the claim row
/// (token, state and a live lease re-checked here, on every page and so
/// on the final one), refuse an epoch below the row's, store through the
/// supply-chain staging, and mark the claim done when this page completed
/// the SBOM. A refusal writes nothing.
pub fn store_upload(
    conn: &mut PgConnection,
    digest: &str,
    token: &uuid::Uuid,
    up: Upload,
) -> Result<Uploaded, DbError> {
    let Upload { payload, meta } = up;
    let set_id = payload.page.as_ref().map(|p| p.set_id.clone());
    let r = conn.transaction::<_, DbError, _>(|conn| {
        let Some(row) = held(conn, digest, token)? else {
            return Err(Box::new(StaleClaim(
                "this claim token does not hold the digest".into(),
            )));
        };
        if !row.live {
            return Err(Box::new(StaleClaim("the lease has expired".into())));
        }
        if !accepts_epoch(row.grant_epoch, meta.epoch) {
            return Err(Box::new(StaleClaim(format!(
                "epoch {} is below the epoch {} this claim was granted under",
                meta.epoch, row.grant_epoch
            ))));
        }
        // A higher epoch than the stored SBOM's replaces it whatever the
        // two scan times say (a node clock behind the last one's). So does
        // any upload while no node SBOM is stored (first catalog, or after
        // the supply-chain GC): nothing is there to protect, and an
        // orphaned staged set from an expired holder, with a later scan
        // time, must not turn this holder's pages Stale and the claim
        // into a superseded / sbom_missing re-grant loop.
        let supersedes = meta.epoch > row.epoch || !node_sbom_stored(conn, digest)?;
        let outcome = store_sbom_with(conn, payload, supersedes, &mut |conn, a| {
            write_flags(conn, digest, a)
        })?;
        let label = match &outcome {
            Outcome::Staged { .. } | Outcome::DuplicatePage { .. } => return Ok((outcome, None)),
            Outcome::Stale { .. } => {
                sql_query(
                    "UPDATE node_catalog_claims SET state = 'done', claim_token = NULL, \
                         lease_expires_at = NULL, failures = 0, next_attempt_at = NULL, \
                         reason = 'superseded', updated_at = now() \
                     WHERE inventory_digest = $1",
                )
                .bind::<Text, _>(digest)
                .execute(conn)?;
                "superseded"
            }
            Outcome::Stored { .. } | Outcome::Unchanged => {
                let empty = matches!(outcome, Outcome::Stored { items: 0 });
                sql_query(FINALIZE_SQL)
                    .bind::<Text, _>(digest)
                    .bind::<Nullable<Text>, _>(empty.then_some("no_packages_found"))
                    .bind::<BigInt, _>(meta.epoch)
                    .bind::<Nullable<Text>, _>(meta.platform.as_deref())
                    .bind::<Nullable<Text>, _>(meta.manifest_digest.as_deref())
                    .bind::<Text, _>(&meta.completeness)
                    .bind::<Array<Text>, _>(&meta.partial_reasons)
                    .bind::<Text, _>(meta.stats.to_string())
                    .bind::<Nullable<Text>, _>(set_id.as_deref())
                    .execute(conn)?;
                if empty {
                    "no_packages_found"
                } else {
                    meta.completeness.as_str()
                }
            }
        };
        Ok((outcome, Some(label.to_string())))
    })?;
    let (outcome, done) = r;
    let claim = match done {
        Some(label) => {
            CATALOGED.inc(&label);
            if let Some(ms) = meta.stats.get("duration_ms").and_then(|v| v.as_f64()) {
                observe_duration(ms);
            }
            "done"
        }
        None => "claimed",
    };
    Ok(Uploaded { outcome, claim })
}

pub(crate) const FINALIZE_SQL: &str = "\
UPDATE node_catalog_claims SET state = 'done', claim_token = NULL, lease_expires_at = NULL, \
    failures = 0, next_attempt_at = NULL, reason = $2, epoch = $3, \
    platform = COALESCE($4, (SELECT p.platform FROM node_catalog_platforms p \
        WHERE p.node = node_catalog_claims.node), platform), \
    manifest_digest = COALESCE($5, manifest_digest), completeness = $6, \
    partial_reasons = $7, stats = $8::jsonb, sbom_set_id = $9, \
    content_hash = (SELECT vs.content_hash FROM vuln_sources vs \
        WHERE vs.digest = $1 AND vs.source = 'node' AND vs.kind = 'sbom'), \
    cataloged_at = now(), updated_at = now() \
WHERE inventory_digest = $1";

enum UploadError {
    Prepare(PrepareError),
    Db(DbError),
}

/// Upload slots ([`UPLOAD_SLOTS`]); tests register their own.
#[derive(Clone)]
pub struct UploadSlots(pub std::sync::Arc<tokio::sync::Semaphore>);

impl UploadSlots {
    pub fn new(n: usize) -> Self {
        UploadSlots(std::sync::Arc::new(tokio::sync::Semaphore::new(n)))
    }
}

fn upload_slots(req: &HttpRequest) -> std::sync::Arc<tokio::sync::Semaphore> {
    static GLOBAL: std::sync::OnceLock<UploadSlots> = std::sync::OnceLock::new();
    req.app_data::<web::Data<UploadSlots>>()
        .map(|s| s.0.clone())
        .unwrap_or_else(|| {
            GLOBAL
                .get_or_init(|| UploadSlots::new(UPLOAD_SLOTS))
                .0
                .clone()
        })
}

fn node_queue_slots() -> std::sync::Arc<tokio::sync::Semaphore> {
    static Q: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    Q.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(NODE_QUEUE_SLOTS)))
        .clone()
}

fn busy(msg: &str) -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header(("Retry-After", "5"))
        .body(msg.to_string())
}

async fn post_catalog_sbom(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Payload,
) -> HttpResponse {
    if !catalog_allowed(auth_of(&req)) {
        return not_configured();
    }
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return bad("digest must be sha256:<64 hex> or sha512:<128 hex>");
    }
    let token = match claim_token(&req) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    // A slot before the body is read: at most UPLOAD_SLOTS bodies (8 MiB
    // each) in memory at once, whatever the number of connections.
    let Ok(slot) = upload_slots(&req).try_acquire_owned() else {
        warn!(%digest, "node catalog upload refused: every upload slot is busy");
        return busy("every node catalog upload slot is busy; retry");
    };
    let (raw, gzip) = match supplychain::read_ingest_body_limited(
        &req,
        body,
        &digest,
        MAX_CATALOG_COMPRESSED_BYTES,
    )
    .await
    {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    let pool = req.app_data::<web::Data<DbPool>>().cloned();
    let d = digest.clone();
    let max_epoch = config_of(&req).max_epoch;
    // The node share of the shared ingest queue, held until the job ends.
    let Ok(queued) = node_queue_slots().try_acquire_owned() else {
        warn!(%digest, "node catalog upload refused: the node share of the ingest queue is full");
        return busy("the node catalog's share of the ingest queue is full; retry");
    };
    let work = move || -> Result<Uploaded, UploadError> {
        let _held = (slot, queued);
        let up =
            prepare_upload(&d, &raw, gzip, Utc::now(), max_epoch).map_err(UploadError::Prepare)?;
        drop(raw);
        let pool = pool.ok_or_else(|| UploadError::Db("no database pool".into()))?;
        let mut conn = pool.get().map_err(|e| UploadError::Db(Box::new(e)))?;
        store_upload(&mut conn, &d, &token, up).map_err(UploadError::Db)
    };
    let Some(result) = supplychain::submit_ingest(work, || {
        Err(UploadError::Db("ingest worker panicked".into()))
    }) else {
        warn!(%digest, "node catalog upload: ingest queue full");
        return supplychain::queue_full();
    };
    match result.await {
        Ok(Ok(u)) => {
            if u.claim == "done" {
                info!(%digest, outcome = ?u.outcome, "node SBOM stored");
            } else {
                debug!(%digest, outcome = ?u.outcome, "node SBOM page handled");
            }
            let status = if matches!(u.outcome, Outcome::Staged { .. }) {
                actix_web::http::StatusCode::ACCEPTED
            } else {
                actix_web::http::StatusCode::OK
            };
            HttpResponse::build(status).json(u)
        }
        Ok(Err(UploadError::Prepare(e))) => {
            warn!(%digest, error = ?e, "node SBOM refused");
            e.into_response()
        }
        Ok(Err(UploadError::Db(e))) => {
            if let Some(s) = e.downcast_ref::<StaleClaim>() {
                warn!(%digest, error = %s, "node SBOM refused: stale claim");
                return HttpResponse::Conflict().body(s.0.clone());
            }
            if let Some(c) = e.downcast_ref::<supplychain::SetConflict>() {
                return HttpResponse::UnprocessableEntity().body(c.0.clone());
            }
            if let Some(f) = e.downcast_ref::<supplychain::StagingFull>() {
                return HttpResponse::TooManyRequests()
                    .insert_header(("Retry-After", "60"))
                    .body(f.0.clone());
            }
            warn!(%digest, error = %e, "node SBOM store failed");
            HttpResponse::InternalServerError().body("storing the node SBOM failed")
        }
        Err(e) => {
            warn!(%digest, error = %e, "node SBOM task failed");
            HttpResponse::InternalServerError().finish()
        }
    }
}

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------

/// Charge for either report: a handful of aggregates.
const REPORT_COST_BYTES: u64 = 64 * 1024;
/// Claims listed on one node's status.
pub const STATUS_CLAIMS_MAX: i64 = 64;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub grants_enabled: bool,
    pub token_configured: bool,
    /// Image digests running now (the inventory's rule).
    pub running_images: i64,
    /// Of those, with an SBOM or report from Trivy Operator.
    pub trivy: i64,
    /// Of those, with a node SBOM.
    pub node: i64,
    /// Of those, with either (a trusted SBOM).
    pub trusted: i64,
    /// trusted / running_images (0 with nothing running).
    pub coverage_ratio: f64,
    /// Claim rows by state.
    pub by_state: BTreeMap<String, i64>,
    /// Done rows by completeness.
    pub by_completeness: BTreeMap<String, i64>,
    /// Rows not done that carry a reason, by reason (failed and released).
    pub by_reason: BTreeMap<String, i64>,
    /// Nodes that offered, by platform.
    pub platforms: BTreeMap<String, i64>,
}

#[derive(QueryableByName)]
struct CoverageCounts {
    #[diesel(sql_type = BigInt)]
    running: i64,
    #[diesel(sql_type = BigInt)]
    trivy: i64,
    #[diesel(sql_type = BigInt)]
    node: i64,
    #[diesel(sql_type = BigInt)]
    trusted: i64,
}

pub(crate) const COVERAGE_SQL: &str = concat!(
    "WITH running AS (SELECT DISTINCT wc.image_digest AS digest FROM workload_containers wc \
         WHERE ",
    running_sql!("$1"),
    "), src AS ( \
        SELECT r.digest, \
            EXISTS (SELECT 1 FROM supplychain_image_links l WHERE l.image_digest = r.digest \
                AND l.source = 'trivy-operator') AS trivy, \
            EXISTS (SELECT 1 FROM node_catalog_claims c JOIN vuln_sources vs \
                ON vs.digest = c.inventory_digest AND vs.source = 'node' AND vs.kind = 'sbom' \
                WHERE c.inventory_digest = r.digest AND c.state = 'done') AS node \
        FROM running r \
     ) SELECT count(*) AS running, count(*) FILTER (WHERE trivy) AS trivy, \
        count(*) FILTER (WHERE node) AS node, count(*) FILTER (WHERE trivy OR node) AS trusted \
     FROM src"
);

#[derive(QueryableByName)]
struct KeyCount {
    #[diesel(sql_type = Text)]
    k: String,
    #[diesel(sql_type = BigInt)]
    n: i64,
}

fn key_counts(conn: &mut PgConnection, sql: &str) -> QueryResult<BTreeMap<String, i64>> {
    Ok(sql_query(sql)
        .load::<KeyCount>(conn)?
        .into_iter()
        .map(|r| (r.k, r.n))
        .collect())
}

pub fn coverage(
    conn: &mut PgConnection,
    window_secs: i64,
    grants: bool,
    token_configured: bool,
) -> QueryResult<Coverage> {
    let c: CoverageCounts = sql_query(COVERAGE_SQL)
        .bind::<Double, _>(window_secs as f64)
        .get_result(conn)?;
    Ok(Coverage {
        grants_enabled: grants,
        token_configured,
        running_images: c.running,
        trivy: c.trivy,
        node: c.node,
        trusted: c.trusted,
        coverage_ratio: ratio(c.trusted, c.running),
        by_state: key_counts(
            conn,
            "SELECT state AS k, count(*) AS n FROM node_catalog_claims GROUP BY state",
        )?,
        by_completeness: key_counts(
            conn,
            "SELECT completeness AS k, count(*) AS n FROM node_catalog_claims \
             WHERE state = 'done' AND completeness IS NOT NULL GROUP BY completeness",
        )?,
        by_reason: key_counts(
            conn,
            "SELECT reason AS k, count(*) AS n FROM node_catalog_claims \
             WHERE state <> 'done' AND reason IS NOT NULL GROUP BY reason",
        )?,
        platforms: key_counts(
            conn,
            "SELECT platform AS k, count(*) AS n FROM node_catalog_platforms GROUP BY platform",
        )?,
    })
}

fn ratio(a: i64, b: i64) -> f64 {
    if b <= 0 {
        0.0
    } else {
        a as f64 / b as f64
    }
}

async fn get_coverage(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
) -> actix_web::Result<HttpResponse> {
    let _permit = match budget.acquire(cost_kib(1, REPORT_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let grants = config_of(&req).grants;
    let token = catalog_allowed(auth_of(&req));
    let c = web::block(move || {
        let mut conn = pool.get()?;
        coverage(&mut conn, running_window_secs(), grants, token).map_err(DbError::from)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(c))
}

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub node: Option<String>,
}

#[derive(Debug, Clone, QueryableByName, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HeldClaim {
    #[diesel(sql_type = Text)]
    pub digest: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub lease_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub attempts: i32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub node: String,
    /// From the node's last offer; `null` if it never offered.
    pub platform: Option<String>,
    pub seen_at: Option<DateTime<Utc>>,
    /// Claims this node holds now.
    pub claims: Vec<HeldClaim>,
    /// Digests this node cataloged (done, last held by it).
    pub cataloged: i64,
    /// Digests last released by this node with a reason, by reason.
    pub by_reason: BTreeMap<String, i64>,
    /// Digests this node is skipped for now.
    pub skipped: i64,
}

pub fn node_status(conn: &mut PgConnection, node: &str) -> QueryResult<NodeStatus> {
    #[derive(QueryableByName)]
    struct P {
        #[diesel(sql_type = Text)]
        platform: String,
        #[diesel(sql_type = Timestamptz)]
        seen_at: DateTime<Utc>,
    }
    let p: Option<P> =
        sql_query("SELECT platform, seen_at FROM node_catalog_platforms WHERE node = $1")
            .bind::<Text, _>(node)
            .get_result(conn)
            .optional()?;
    let claims: Vec<HeldClaim> = sql_query(
        "SELECT inventory_digest AS digest, lease_expires_at, attempts FROM node_catalog_claims \
         WHERE node = $1 AND state = 'claimed' AND lease_expires_at > now() \
         ORDER BY inventory_digest LIMIT $2",
    )
    .bind::<Text, _>(node)
    .bind::<BigInt, _>(STATUS_CLAIMS_MAX)
    .load(conn)?;
    #[derive(QueryableByName)]
    struct N {
        #[diesel(sql_type = BigInt)]
        cataloged: i64,
        #[diesel(sql_type = BigInt)]
        skipped: i64,
    }
    let n: N = sql_query(
        "SELECT count(*) FILTER (WHERE state = 'done' AND node = $1) AS cataloged, \
             count(*) FILTER (WHERE COALESCE((skipped_nodes ->> $1)::timestamptz \
                 > now() - interval '24 hours', false)) AS skipped \
         FROM node_catalog_claims",
    )
    .bind::<Text, _>(node)
    .get_result(conn)?;
    let by_reason: BTreeMap<String, i64> = sql_query(
        "SELECT reason AS k, count(*) AS n FROM node_catalog_claims \
         WHERE node = $1 AND state <> 'done' AND reason IS NOT NULL GROUP BY reason",
    )
    .bind::<Text, _>(node)
    .load::<KeyCount>(conn)?
    .into_iter()
    .map(|r| (r.k, r.n))
    .collect();
    Ok(NodeStatus {
        node: node.to_string(),
        platform: p.as_ref().map(|p| p.platform.clone()),
        seen_at: p.map(|p| p.seen_at),
        claims,
        cataloged: n.cataloged,
        by_reason,
        skipped: n.skipped,
    })
}

async fn get_status(
    req: HttpRequest,
    budget: web::Data<ReadBudget>,
    query: web::Query<StatusQuery>,
) -> actix_web::Result<HttpResponse> {
    let node = query
        .into_inner()
        .node
        .map(|n| n.trim().to_string())
        .unwrap_or_default();
    if !valid_node(&node) {
        return Ok(bad("?node= must be a Kubernetes node name"));
    }
    let _permit = match budget.acquire(cost_kib(1, REPORT_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let pool = pool_of(&req)?;
    let s = web::block(move || {
        let mut conn = pool.get()?;
        node_status(&mut conn, &node).map_err(DbError::from)
    })
    .await?
    .map_err(crate::db_error_response)?;
    Ok(HttpResponse::Ok().json(s))
}

// ---------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------

fn claim_json() -> web::JsonConfig {
    web::JsonConfig::default().limit(CLAIM_JSON_LIMIT_BYTES)
}

/// `POST /catalog/claims`.
pub fn claims_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/catalog/claims")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(claim_json())
        .route(web::post().to(post_claims))
}

/// `PUT /catalog/claims/{digest}`.
pub fn claim_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/catalog/claims/{digest}")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(claim_json())
        .route(web::put().to(put_claim))
}

/// `POST /catalog/images/{digest}/sbom`: reads and caps its own body.
pub fn sbom_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/catalog/images/{digest}/sbom")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(web::PayloadConfig::new(MAX_CATALOG_COMPRESSED_BYTES))
        .route(web::post().to(post_catalog_sbom))
}

/// `GET /catalog/coverage`.
pub fn coverage_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/catalog/coverage")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .route(web::get().to(get_coverage))
}

/// `GET /catalog/status?node=`.
pub fn status_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/catalog/status")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .route(web::get().to(get_status))
}

// ---------------------------------------------------------------------
// Leader pass (retention.rs, inside the supply-chain pass)
// ---------------------------------------------------------------------

/// Whether any node ever offered: without that the pass does nothing.
pub fn in_use(conn: &mut PgConnection) -> QueryResult<bool> {
    #[derive(QueryableByName)]
    struct E {
        #[diesel(sql_type = Bool)]
        e: bool,
    }
    sql_query(
        "SELECT (EXISTS (SELECT 1 FROM node_catalog_claims) \
             OR EXISTS (SELECT 1 FROM node_catalog_platforms)) AS e",
    )
    .get_result::<E>(conn)
    .map(|r| r.e)
}

pub(crate) const PRIORITY_SQL: &str = concat!(
    "WITH n AS (SELECT wc.image_digest, count(*)::int AS n FROM workload_containers wc \
         WHERE ",
    running_sql!("$1"),
    " GROUP BY wc.image_digest), \
     t AS (SELECT c.inventory_digest, COALESCE(n.n, 0) AS p FROM node_catalog_claims c \
         LEFT JOIN n ON n.image_digest = c.inventory_digest \
         WHERE c.state <> 'claimed' AND c.priority <> COALESCE(n.n, 0) \
         ORDER BY c.inventory_digest LIMIT $2 \
         FOR UPDATE OF c SKIP LOCKED) \
     UPDATE node_catalog_claims c SET priority = t.p FROM t \
     WHERE c.inventory_digest = t.inventory_digest"
);

/// Rows one priority transaction touches: small, and `SKIP LOCKED`, so a
/// claimer never finds all its candidates locked by this pass for long
/// and this pass never waits on a grant.
pub const PRIORITY_BATCH: i64 = 200;
const PRIORITY_MAX_BATCHES: usize = 100;

/// Set each row's priority to its running container count, a small batch
/// per transaction. Claimed rows, and rows a grant holds, are left for
/// the next pass.
pub fn refresh_priorities(conn: &mut PgConnection, window_secs: i64) -> QueryResult<usize> {
    let mut total = 0;
    for _ in 0..PRIORITY_MAX_BATCHES {
        let n = sql_query(PRIORITY_SQL)
            .bind::<Double, _>(window_secs as f64)
            .bind::<BigInt, _>(PRIORITY_BATCH)
            .execute(conn)?;
        total += n;
        if (n as i64) < PRIORITY_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Refresh the table-derived gauges.
pub fn refresh_gauges(conn: &mut PgConnection, window_secs: i64) -> QueryResult<()> {
    #[derive(QueryableByName)]
    struct D {
        #[diesel(sql_type = BigInt)]
        n: i64,
    }
    let d: D = sql_query("SELECT count(*) AS n FROM node_catalog_claims WHERE state <> 'done'")
        .get_result(conn)?;
    let c: CoverageCounts = sql_query(COVERAGE_SQL)
        .bind::<Double, _>(window_secs as f64)
        .get_result(conn)?;
    QUEUE_DEPTH.store(d.n, Ordering::Relaxed);
    COVERAGE_BITS.store(ratio(c.trusted, c.running).to_bits(), Ordering::Relaxed);
    COVERAGE_SET.store(true, Ordering::Relaxed);
    Ok(())
}

/// Digests whose claim, node SBOM and flags go: the inventory has not seen
/// them for `days` (their `images` row is older, or already pruned).
pub(crate) const RETENTION_KEYS_SQL: &str = "\
SELECT c.inventory_digest AS digest FROM node_catalog_claims c \
LEFT JOIN images i ON i.digest = c.inventory_digest \
WHERE (i.digest IS NULL OR i.last_seen < timezone('UTC', now()) - make_interval(days => $1)) \
ORDER BY c.inventory_digest LIMIT $2 \
FOR UPDATE OF c SKIP LOCKED";

const RETENTION_TABLES: [&str; 4] = [
    "image_sbom_components",
    "image_sbom_pages",
    "supplychain_image_links",
    "vuln_sources",
];

/// Delete up to `batch` expired digests (claims, flags and the node
/// source's SBOM rows), one transaction. Returns digests removed.
pub fn retention_batch(conn: &mut PgConnection, days: u32, batch: i64) -> QueryResult<usize> {
    conn.transaction(|conn| {
        #[derive(QueryableByName)]
        struct K {
            #[diesel(sql_type = Text)]
            digest: String,
        }
        let keys: Vec<String> = sql_query(RETENTION_KEYS_SQL)
            .bind::<diesel::sql_types::Integer, _>(days as i32)
            .bind::<BigInt, _>(batch)
            .load::<K>(conn)?
            .into_iter()
            .map(|k| k.digest)
            .collect();
        if keys.is_empty() {
            return Ok(0);
        }
        for table in RETENTION_TABLES {
            sql_query(format!(
                "DELETE FROM {table} WHERE source = $2 AND digest = ANY($1)"
            ))
            .bind::<Array<Text>, _>(&keys)
            .bind::<Text, _>(NODE_SOURCE)
            .execute(conn)?;
        }
        sql_query("DELETE FROM node_sbom_package_flags WHERE digest = ANY($1)")
            .bind::<Array<Text>, _>(&keys)
            .execute(conn)?;
        sql_query("DELETE FROM node_catalog_claims WHERE inventory_digest = ANY($1)")
            .bind::<Array<Text>, _>(&keys)
            .execute(conn)?;
        Ok(keys.len())
    })
}

/// Nodes that have not offered for `days`.
pub fn prune_platforms(conn: &mut PgConnection, days: u32) -> QueryResult<usize> {
    sql_query(
        "DELETE FROM node_catalog_platforms \
         WHERE seen_at < now() - make_interval(days => $1)",
    )
    .bind::<diesel::sql_types::Integer, _>(days as i32)
    .execute(conn)
}

#[cfg(test)]
#[path = "node_catalog_tests.rs"]
mod tests;
