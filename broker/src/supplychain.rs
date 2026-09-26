//! Supply-chain ingest: vulnerability and SBOM payloads from the
//! `supplychain` component (#1533 P1-3). The wire contract is
//! `supplychain/README.md` ("Payload schema (v1)", "SBOM paging").
//!
//! # Routes
//!
//! - `POST /images/{digest}/vulnerabilities`: an `ImageVulnerabilities`.
//! - `POST /images/{digest}/sbom`: an `ImageSBOM`, whole or one page.
//!
//! Both need the `supplychain` scope, and both refuse to run at all
//! unless broker auth is on with a token that carries it: an
//! unauthenticated broker would otherwise let any pod post a forged
//! "clean" scan. The read side is `supplychain_read.rs`.
//!
//! # Bodies
//!
//! The component sends gzip JSON of at most 1 MiB compressed
//! ([`MAX_COMPRESSED_BYTES`]). The handler reads the raw payload itself
//! (no app-wide JSON/Payload limit applies to it), refuses more than that
//! many compressed bytes, then inflates into a buffer that stops at
//! [`max_decompressed_bytes`]: a decompression bomb costs at most that
//! much memory and gets 413. Only two ingests run at once
//! ([`INGEST_CONCURRENCY`]), so the ceiling bounds memory in aggregate too.
//!
//! # Storage and replacement
//!
//! Keyed by the digest the source reported, never by pod. Each payload
//! replaces what is stored for `(digest, source)` of its kind, inside one
//! transaction serialised by an advisory lock on that key:
//!
//! - an older `scanned_at` than the stored one is ignored (`stale`), so a
//!   delayed retry of an old scan never overwrites a newer one;
//! - identical content (same findings hash, or the same SBOM `set_id`) is
//!   a no-op (`unchanged`) apart from refreshing the header;
//! - paged SBOMs are staged in `image_sbom_pages` and swapped in only when
//!   all `total` pages of one `set_id` are present; duplicates are
//!   harmless, order does not matter, and a newer set drops an older
//!   incomplete one. Incomplete sets expire in the retention loop.
//!
//! # Join to the inventory
//!
//! [`relink`] records which inventory digests a payload applies to, and
//! by which rule, in the order the charter fixes: the kubelet imageID
//! digest, then the payload's platform manifests (index -> manifest), and
//! only if neither matches, (namespace, workload, container) from
//! `observed_in` plus the same repository:tag.

use crate::auth::{AuthConfig, Scope};
use crate::image_inventory::is_valid_digest;
use actix_web::http::header;
use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub(crate) type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Largest request body accepted, compressed. Matches the component's
/// `broker.MaxRequestBytes`.
pub const MAX_COMPRESSED_BYTES: usize = 1024 * 1024;
/// Default ceiling for the inflated body.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MIN_DECOMPRESSED_BYTES: usize = MAX_COMPRESSED_BYTES;
const MAX_DECOMPRESSED_CEILING: usize = 128 * 1024 * 1024;
/// Supply-chain ingests allowed to hold a body at once.
pub const INGEST_CONCURRENCY: usize = 2;

/// The only schema version this broker reads.
pub const SCHEMA_VERSION: i64 = 1;

pub const MAX_VULNERABILITIES: usize = 50_000;
pub const MAX_SBOM_COMPONENTS: usize = 100_000;
pub const MAX_SBOM_PAGES: i64 = 128;
const MAX_OBSERVED_IN: usize = 64;
const MAX_PLATFORM_MANIFESTS: usize = 64;
/// File paths kept per finding / component, and their length.
pub const MAX_FILE_PATHS: usize = 16;
const MAX_PATH_LEN: usize = 1024;
const MAX_LICENSES: usize = 8;
const MAX_CVSS_VENDORS: usize = 8;
/// A scan dated further ahead than this is refused: a far-future
/// `scanned_at` would otherwise block every later scan as "older".
const MAX_CLOCK_SKEW_SECS: i64 = 600;

const LEN_ID: usize = 128;
const LEN_NAME: usize = 256;
const LEN_SHORT: usize = 64;
const LEN_VERSION: usize = 128;
const LEN_URL: usize = 1024;
const LEN_TITLE: usize = 512;
const LEN_REF: usize = 1024;

pub const KIND_VULNERABILITIES: &str = "vulnerabilities";
pub const KIND_SBOM: &str = "sbom";

/// Read `SUPPLYCHAIN_MAX_DECOMPRESSED_BYTES` (chart:
/// `broker.supplychain.maxDecompressedBytes`), clamped to [1 MiB, 128 MiB].
pub(crate) fn parse_max_decompressed(raw: Option<&str>) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .map(|n| n.clamp(MIN_DECOMPRESSED_BYTES, MAX_DECOMPRESSED_CEILING))
        .unwrap_or(DEFAULT_MAX_DECOMPRESSED_BYTES)
}

pub fn max_decompressed_bytes() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        parse_max_decompressed(
            std::env::var("SUPPLYCHAIN_MAX_DECOMPRESSED_BYTES")
                .ok()
                .as_deref(),
        )
    })
}

static INGEST_SLOTS: Semaphore = Semaphore::const_new(INGEST_CONCURRENCY);

// ---------------------------------------------------------------------
// Wire format (supplychain/pkg/types). Unknown fields are ignored so a
// newer component's additive fields don't fail ingest.
// ---------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct WireImage {
    pub digest: String,
    #[serde(default, rename = "ref")]
    pub image_ref: Option<String>,
    #[serde(default)]
    pub registry: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub digest_kind: Option<String>,
    #[serde(default)]
    pub platform_manifests: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WireScanner {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WireOs {
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub eosl: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct WireWorkloadRef {
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub container: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct WirePackage {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, rename = "type")]
    pub pkg_type: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct WireCvss {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2_vector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v3_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v3_vector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v40_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v40_vector: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WireVulnerability {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub package: WirePackage,
    #[serde(default)]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub cvss: Option<BTreeMap<String, WireCvss>>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub primary_url: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub published_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_modified_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub file_paths: Vec<String>,
    /// In CISA KEV (Grype only; absent = unknown, not "not exploited").
    #[serde(default)]
    pub kev: Option<bool>,
    #[serde(default)]
    pub kev_date_added: Option<DateTime<Utc>>,
    #[serde(default)]
    pub epss: Option<f64>,
    #[serde(default)]
    pub epss_percentile: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct WireImageVulnerabilities {
    pub schema_version: i64,
    pub image: WireImage,
    pub source: String,
    #[serde(default)]
    pub scanner: WireScanner,
    pub scanned_at: DateTime<Utc>,
    #[serde(default)]
    pub db_updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub os: WireOs,
    #[serde(default)]
    pub observed_in: Vec<WireWorkloadRef>,
    #[serde(default)]
    pub vulnerabilities: Vec<WireVulnerability>,
    /// For a matcher's findings: the SBOM source that was matched.
    #[serde(default)]
    pub sbom_source: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WireComponent {
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
    #[serde(default)]
    pub licenses: Vec<String>,
    #[serde(default)]
    pub layer_digest: Option<String>,
    #[serde(default)]
    pub file_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WirePage {
    pub set_id: String,
    pub index: i64,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct WireImageSbom {
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
    #[serde(default)]
    pub observed_in: Vec<WireWorkloadRef>,
    #[serde(default)]
    pub page: Option<WirePage>,
    #[serde(default)]
    pub components: Vec<WireComponent>,
    /// Where a registry-attached SBOM was found. `verified` says whether a
    /// signature was checked; the broker stores it as sent.
    #[serde(default)]
    pub attestation: Option<WireAttestation>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct WireAttestation {
    #[serde(default)]
    pub mechanism: Option<String>,
    #[serde(default)]
    pub artifact_digest: Option<String>,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub predicate_type: Option<String>,
    #[serde(default)]
    pub verified: bool,
}

// ---------------------------------------------------------------------
// Normalised rows. Field names are the column names: they are handed to
// Postgres as one jsonb value and expanded with jsonb_populate_record /
// jsonb_to_recordset, so a 50 000-finding payload is one statement.
// ---------------------------------------------------------------------

/// A `vuln_sources` row.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Header {
    pub digest: String,
    pub source: String,
    pub kind: String,
    pub digest_kind: String,
    pub platform_manifests: BTreeMap<String, String>,
    pub manifest_digests: Vec<String>,
    pub image_ref: Option<String>,
    pub registry: Option<String>,
    pub repository: Option<String>,
    pub norm_repository: Option<String>,
    pub tag: Option<String>,
    pub scanner_name: Option<String>,
    pub scanner_vendor: Option<String>,
    pub scanner_version: Option<String>,
    pub scanned_at: NaiveDateTime,
    pub db_updated_at: Option<NaiveDateTime>,
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub os_eosl: bool,
    pub observed_in: Vec<WireWorkloadRef>,
    pub content_hash: String,
    pub sbom_format: Option<String>,
    pub sbom_spec_version: Option<String>,
    pub item_count: i32,
    pub sbom_source: Option<String>,
    pub attestation: Option<WireAttestation>,
}

/// An `image_vulnerabilities` row (without key and scan time, which the
/// insert binds once).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VulnRow {
    pub ord: i64,
    pub vuln_id: String,
    pub pkg_name: String,
    pub pkg_type: Option<String>,
    pub pkg_purl: Option<String>,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub severity_rank: i16,
    pub score: Option<f64>,
    pub cvss: BTreeMap<String, WireCvss>,
    pub title: Option<String>,
    pub primary_url: Option<String>,
    pub target: Option<String>,
    pub class: Option<String>,
    pub published_at: Option<NaiveDateTime>,
    pub last_modified_at: Option<NaiveDateTime>,
    pub file_paths: Vec<String>,
    pub kev: Option<bool>,
    pub kev_date_added: Option<NaiveDateTime>,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
}

/// An `image_sbom_components` row.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ComponentRow {
    pub ord: i64,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    #[serde(rename = "type")]
    pub comp_type: Option<String>,
    pub class: Option<String>,
    pub src_name: Option<String>,
    pub src_version: Option<String>,
    pub licenses: Vec<String>,
    pub layer_digest: Option<String>,
    pub file_paths: Vec<String>,
}

/// Why a payload was refused; each maps to one 4xx.
#[derive(Debug, PartialEq)]
pub enum Reject {
    /// 422: well-formed JSON that breaks the contract.
    Invalid(String),
    /// 413: too many items after parsing.
    TooLarge(String),
}

impl Reject {
    fn into_response(self) -> HttpResponse {
        match self {
            Reject::Invalid(m) => HttpResponse::UnprocessableEntity().body(m),
            Reject::TooLarge(m) => HttpResponse::PayloadTooLarge().body(m),
        }
    }
}

/// Severity order, highest first. Anything unrecognised is UNKNOWN (0):
/// it sorts last but is never dropped or read as "none".
pub fn severity_rank(s: &str) -> (String, i16) {
    let up = s.trim().to_ascii_uppercase();
    let rank = match up.as_str() {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "NONE" => 1,
        _ => return ("UNKNOWN".to_string(), 0),
    };
    (up, rank)
}

pub fn severity_from_rank(rank: i16) -> &'static str {
    match rank {
        5 => "CRITICAL",
        4 => "HIGH",
        3 => "MEDIUM",
        2 => "LOW",
        1 => "NONE",
        _ => "UNKNOWN",
    }
}

/// Trim, drop control characters, cap at `max` bytes on a char boundary;
/// empty becomes `None`.
fn clean(s: Option<&str>, max: usize) -> Option<String> {
    let s: String = s?.trim().chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() {
        return None;
    }
    if s.len() <= max {
        return Some(s);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_string())
}

fn clean_list(v: &[String], max_items: usize, max_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in v {
        if out.len() >= max_items {
            break;
        }
        if let Some(c) = clean(Some(s), max_len) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// A probability: finite and within [0, 1], else unknown.
fn unit_interval(x: Option<f64>) -> Option<f64> {
    x.filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
}

fn naive(t: DateTime<Utc>) -> NaiveDateTime {
    t.naive_utc()
}

/// `source` becomes part of the key and of every label in the UI: keep it
/// to a short slug.
fn valid_source(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= LEN_SHORT
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn valid_set_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= LEN_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// `registry` + `repository` in the inventory's form
/// (`images.repository`, controller `normalise_repository`): Docker Hub
/// spelled `docker.io/library/nginx`, registry host lower-cased.
pub fn normalise_repository(registry: Option<&str>, repository: Option<&str>) -> Option<String> {
    let repo = repository?.trim().trim_matches('/');
    if repo.is_empty() {
        return None;
    }
    let reg = registry
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty());
    let reg = match reg.as_deref() {
        None | Some("docker.io") | Some("index.docker.io") | Some("registry-1.docker.io") => {
            // The repository may itself carry a host (a source that fills
            // only `repository`).
            let (first, rest) = match repo.split_once('/') {
                Some((f, r)) => (f, Some(r)),
                None => (repo, None),
            };
            let is_host = first.contains('.') || first.contains(':') || first == "localhost";
            if reg.is_none() && is_host {
                if let Some(rest) = rest {
                    return normalise_repository(Some(first), Some(rest));
                }
            }
            return Some(if repo.contains('/') {
                format!("docker.io/{repo}")
            } else {
                format!("docker.io/library/{repo}")
            });
        }
        Some(r) => r.to_string(),
    };
    Some(format!("{reg}/{repo}"))
}

struct Common {
    digest: String,
    source: String,
    scanned_at: NaiveDateTime,
}

fn validate_common(
    path_digest: &str,
    schema_version: i64,
    image: &WireImage,
    source: &str,
    scanned_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Common, Reject> {
    if schema_version != SCHEMA_VERSION {
        return Err(Reject::Invalid(format!(
            "schema_version {schema_version} is not supported (this broker reads {SCHEMA_VERSION})"
        )));
    }
    if !is_valid_digest(&image.digest) {
        return Err(Reject::Invalid(
            "image.digest must be sha256:<64 hex> or sha512:<128 hex>".into(),
        ));
    }
    if image.digest != path_digest {
        return Err(Reject::Invalid(
            "image.digest does not match the digest in the path".into(),
        ));
    }
    if !valid_source(source) {
        return Err(Reject::Invalid(
            "source must be 1-64 characters of [a-z0-9.-]".into(),
        ));
    }
    if (scanned_at - now).num_seconds() > MAX_CLOCK_SKEW_SECS {
        return Err(Reject::Invalid(
            "scanned_at is in the future; refusing it so it cannot block newer scans".into(),
        ));
    }
    Ok(Common {
        digest: image.digest.clone(),
        source: source.to_string(),
        scanned_at: naive(scanned_at),
    })
}

fn build_header(
    c: &Common,
    kind: &str,
    image: &WireImage,
    scanner: &WireScanner,
    observed_in: &[WireWorkloadRef],
) -> Header {
    let digest_kind = match image.digest_kind.as_deref().map(str::trim) {
        Some("index") => "index",
        Some("manifest") => "manifest",
        _ => "unknown",
    }
    .to_string();
    let mut platform_manifests = BTreeMap::new();
    if let Some(pm) = &image.platform_manifests {
        for (platform, d) in pm.iter() {
            if platform_manifests.len() >= MAX_PLATFORM_MANIFESTS {
                break;
            }
            if let Some(p) = clean(Some(platform), LEN_SHORT) {
                if is_valid_digest(d) {
                    platform_manifests.insert(p, d.clone());
                }
            }
        }
    }
    let mut manifest_digests: Vec<String> = platform_manifests.values().cloned().collect();
    manifest_digests.sort();
    manifest_digests.dedup();
    let mut obs: Vec<WireWorkloadRef> = Vec::new();
    for o in observed_in {
        if obs.len() >= MAX_OBSERVED_IN {
            break;
        }
        let r = WireWorkloadRef {
            namespace: clean(Some(&o.namespace), LEN_NAME).unwrap_or_default(),
            kind: clean(Some(&o.kind), LEN_SHORT).unwrap_or_default(),
            name: clean(Some(&o.name), LEN_NAME).unwrap_or_default(),
            container: clean(Some(&o.container), LEN_NAME).unwrap_or_default(),
        };
        if !r.namespace.is_empty() && !r.name.is_empty() && !obs.contains(&r) {
            obs.push(r);
        }
    }
    let registry = clean(image.registry.as_deref(), LEN_NAME);
    let repository = clean(image.repository.as_deref(), LEN_REF);
    Header {
        digest: c.digest.clone(),
        source: c.source.clone(),
        kind: kind.to_string(),
        digest_kind,
        platform_manifests,
        manifest_digests,
        image_ref: clean(image.image_ref.as_deref(), LEN_REF),
        norm_repository: normalise_repository(registry.as_deref(), repository.as_deref()),
        registry,
        repository,
        tag: clean(image.tag.as_deref(), LEN_VERSION),
        scanner_name: clean(scanner.name.as_deref(), LEN_SHORT),
        scanner_vendor: clean(scanner.vendor.as_deref(), LEN_SHORT),
        scanner_version: clean(scanner.version.as_deref(), LEN_SHORT),
        scanned_at: c.scanned_at,
        db_updated_at: None,
        os_family: None,
        os_name: None,
        os_eosl: false,
        observed_in: obs,
        content_hash: String::new(),
        sbom_format: None,
        sbom_spec_version: None,
        item_count: 0,
        sbom_source: None,
        attestation: None,
    }
}

/// A validated `ImageVulnerabilities`.
#[derive(Debug)]
pub struct VulnPayload {
    pub header: Header,
    pub rows: Vec<VulnRow>,
}

pub fn normalise_vulnerabilities(
    path_digest: &str,
    p: WireImageVulnerabilities,
    now: DateTime<Utc>,
) -> Result<VulnPayload, Reject> {
    let c = validate_common(
        path_digest,
        p.schema_version,
        &p.image,
        &p.source,
        p.scanned_at,
        now,
    )?;
    if p.vulnerabilities.len() > MAX_VULNERABILITIES {
        return Err(Reject::TooLarge(format!(
            "{} findings; at most {MAX_VULNERABILITIES} per payload",
            p.vulnerabilities.len()
        )));
    }
    let mut header = build_header(
        &c,
        KIND_VULNERABILITIES,
        &p.image,
        &p.scanner,
        &p.observed_in,
    );
    header.db_updated_at = p.db_updated_at.map(naive);
    header.os_family = clean(p.os.family.as_deref(), LEN_SHORT);
    header.os_name = clean(p.os.name.as_deref(), LEN_SHORT);
    header.os_eosl = p.os.eosl.unwrap_or(false);
    header.sbom_source = clean(p.sbom_source.as_deref(), LEN_SHORT);

    let mut rows = Vec::with_capacity(p.vulnerabilities.len());
    for (i, v) in p.vulnerabilities.into_iter().enumerate() {
        let Some(vuln_id) = clean(Some(&v.id), LEN_ID) else {
            return Err(Reject::Invalid(format!("vulnerabilities[{i}].id is empty")));
        };
        let Some(pkg_name) = clean(Some(&v.package.name), LEN_NAME) else {
            return Err(Reject::Invalid(format!(
                "vulnerabilities[{i}].package.name is empty"
            )));
        };
        let (severity, rank) = severity_rank(&v.severity);
        let mut cvss = BTreeMap::new();
        for (vendor, s) in v.cvss.unwrap_or_default() {
            if cvss.len() >= MAX_CVSS_VENDORS {
                break;
            }
            if let Some(vendor) = clean(Some(&vendor), LEN_SHORT) {
                cvss.insert(
                    vendor,
                    WireCvss {
                        v2_score: s.v2_score.filter(|x| x.is_finite()),
                        v2_vector: clean(s.v2_vector.as_deref(), LEN_ID),
                        v3_score: s.v3_score.filter(|x| x.is_finite()),
                        v3_vector: clean(s.v3_vector.as_deref(), LEN_ID),
                        v40_score: s.v40_score.filter(|x| x.is_finite()),
                        v40_vector: clean(s.v40_vector.as_deref(), LEN_TITLE),
                    },
                );
            }
        }
        rows.push(VulnRow {
            ord: i as i64,
            vuln_id,
            pkg_name,
            pkg_type: clean(v.package.pkg_type.as_deref(), LEN_SHORT),
            pkg_purl: clean(v.package.purl.as_deref(), LEN_URL),
            installed_version: clean(Some(&v.package.version), LEN_VERSION).unwrap_or_default(),
            fixed_version: clean(v.fixed_version.as_deref(), LEN_TITLE),
            severity,
            severity_rank: rank,
            score: v.score.filter(|x| x.is_finite()),
            cvss,
            title: clean(v.title.as_deref(), LEN_TITLE),
            primary_url: clean(v.primary_url.as_deref(), LEN_URL),
            target: clean(v.target.as_deref(), LEN_TITLE),
            class: clean(v.class.as_deref(), LEN_SHORT),
            published_at: v.published_at.map(naive),
            last_modified_at: v.last_modified_at.map(naive),
            file_paths: clean_list(&v.file_paths, MAX_FILE_PATHS, MAX_PATH_LEN),
            kev: v.kev,
            kev_date_added: v.kev_date_added.map(naive),
            epss: unit_interval(v.epss),
            epss_percentile: unit_interval(v.epss_percentile),
        });
    }
    header.item_count = rows.len() as i32;
    Ok(VulnPayload { header, rows })
}

/// A validated `ImageSBOM` (one page, or the whole SBOM).
#[derive(Debug)]
pub struct SbomPayload {
    pub header: Header,
    pub page: Option<WirePage>,
    pub rows: Vec<ComponentRow>,
}

pub fn normalise_sbom(
    path_digest: &str,
    p: WireImageSbom,
    now: DateTime<Utc>,
) -> Result<SbomPayload, Reject> {
    let c = validate_common(
        path_digest,
        p.schema_version,
        &p.image,
        &p.source,
        p.scanned_at,
        now,
    )?;
    if p.components.len() > MAX_SBOM_COMPONENTS {
        return Err(Reject::TooLarge(format!(
            "{} components; at most {MAX_SBOM_COMPONENTS} per SBOM",
            p.components.len()
        )));
    }
    if let Some(pg) = &p.page {
        if !valid_set_id(&pg.set_id) {
            return Err(Reject::Invalid(
                "page.set_id must be 1-128 characters of [A-Za-z0-9._:-]".into(),
            ));
        }
        if pg.total < 1 || pg.total > MAX_SBOM_PAGES {
            return Err(Reject::Invalid(format!(
                "page.total must be 1-{MAX_SBOM_PAGES}"
            )));
        }
        if pg.index < 0 || pg.index >= pg.total {
            return Err(Reject::Invalid("page.index must be in [0, total)".into()));
        }
    }
    let mut header = build_header(&c, KIND_SBOM, &p.image, &p.scanner, &p.observed_in);
    header.sbom_format = clean(p.format.as_deref(), LEN_SHORT);
    header.sbom_spec_version = clean(p.spec_version.as_deref(), LEN_SHORT);
    header.attestation = p.attestation.as_ref().map(|a| WireAttestation {
        mechanism: clean(a.mechanism.as_deref(), LEN_SHORT),
        artifact_digest: a
            .artifact_digest
            .as_deref()
            .filter(|d| is_valid_digest(d))
            .map(str::to_string),
        media_type: clean(a.media_type.as_deref(), LEN_NAME),
        predicate_type: clean(a.predicate_type.as_deref(), LEN_NAME),
        verified: a.verified,
    });
    let mut rows = Vec::with_capacity(p.components.len());
    for (i, comp) in p.components.into_iter().enumerate() {
        let Some(name) = clean(Some(&comp.name), LEN_NAME) else {
            return Err(Reject::Invalid(format!("components[{i}].name is empty")));
        };
        rows.push(ComponentRow {
            ord: i as i64,
            name,
            version: clean(comp.version.as_deref(), LEN_VERSION),
            purl: clean(comp.purl.as_deref(), LEN_URL),
            comp_type: clean(comp.comp_type.as_deref(), LEN_SHORT),
            class: clean(comp.class.as_deref(), LEN_SHORT),
            src_name: clean(comp.src_name.as_deref(), LEN_NAME),
            src_version: clean(comp.src_version.as_deref(), LEN_VERSION),
            licenses: clean_list(&comp.licenses, MAX_LICENSES, LEN_VERSION),
            layer_digest: clean(comp.layer_digest.as_deref(), LEN_ID + 8),
            file_paths: clean_list(&comp.file_paths, MAX_FILE_PATHS, MAX_PATH_LEN),
        });
    }
    header.item_count = rows.len() as i32;
    Ok(SbomPayload {
        header,
        page: p.page,
        rows,
    })
}

// ---------------------------------------------------------------------
// Body handling
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum BodyError {
    /// 413: compressed or inflated size over the limit.
    TooLarge(String),
    /// 415: an encoding other than gzip / identity.
    UnsupportedEncoding(String),
    /// 400: not valid gzip.
    Corrupt(String),
}

impl BodyError {
    fn into_response(self) -> HttpResponse {
        match self {
            BodyError::TooLarge(m) => HttpResponse::PayloadTooLarge().body(m),
            BodyError::UnsupportedEncoding(m) => HttpResponse::UnsupportedMediaType().body(m),
            BodyError::Corrupt(m) => HttpResponse::BadRequest().body(m),
        }
    }
}

/// The request's `Content-Encoding`, lower-cased; `None` for identity.
fn content_encoding(req: &HttpRequest) -> Result<Option<String>, BodyError> {
    let Some(v) = req.headers().get(header::CONTENT_ENCODING) else {
        return Ok(None);
    };
    let v = v
        .to_str()
        .map_err(|_| BodyError::UnsupportedEncoding("unreadable Content-Encoding".into()))?
        .trim()
        .to_ascii_lowercase();
    match v.as_str() {
        "" | "identity" => Ok(None),
        "gzip" | "x-gzip" => Ok(Some("gzip".into())),
        other => Err(BodyError::UnsupportedEncoding(format!(
            "Content-Encoding {other} is not supported; send gzip"
        ))),
    }
}

/// Inflate a gzip body into at most `ceiling` bytes. Reading stops one
/// byte past the ceiling, so a bomb costs `ceiling` bytes of memory and
/// is refused, never expanded in full.
pub fn inflate_bounded(compressed: &[u8], ceiling: usize) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::with_capacity(compressed.len().saturating_mul(4).min(ceiling));
    let decoder = flate2::read::MultiGzDecoder::new(compressed);
    let n = decoder
        .take(ceiling as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| BodyError::Corrupt(format!("body is not valid gzip: {e}")))?;
    if n > ceiling {
        return Err(BodyError::TooLarge(format!(
            "decompressed body exceeds {ceiling} bytes"
        )));
    }
    Ok(out)
}

async fn read_body(
    req: &HttpRequest,
    payload: web::Payload,
    ceiling: usize,
) -> Result<Vec<u8>, BodyError> {
    let encoding = content_encoding(req)?;
    if let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        if len > MAX_COMPRESSED_BYTES as u64 {
            return Err(BodyError::TooLarge(format!(
                "body of {len} bytes exceeds the {MAX_COMPRESSED_BYTES}-byte limit"
            )));
        }
    }
    let raw = match payload.to_bytes_limited(MAX_COMPRESSED_BYTES).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Err(BodyError::Corrupt(format!("reading body: {e}"))),
        Err(_) => {
            return Err(BodyError::TooLarge(format!(
                "body exceeds the {MAX_COMPRESSED_BYTES}-byte limit"
            )))
        }
    };
    match encoding {
        None => Ok(raw.to_vec()),
        Some(_) => web::block(move || inflate_bounded(&raw, ceiling))
            .await
            .map_err(|e| BodyError::Corrupt(format!("inflate task failed: {e}")))?,
    }
}

/// Supply-chain ingest runs only with scoped broker auth: a token with the
/// `supplychain` scope must be configured. With auth off, anyone who can
/// reach the broker could post a forged scan result.
pub fn ingest_allowed(cfg: Option<&AuthConfig>) -> bool {
    cfg.is_some_and(|c| c.enabled() && c.configures(Scope::SupplyChain))
}

fn not_scoped() -> HttpResponse {
    HttpResponse::Forbidden().body(
        "supply-chain ingest requires scoped broker auth: set BROKER_TOKEN_SUPPLYCHAIN \
         (chart: broker.auth) and give the supplychain component that token",
    )
}

// ---------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------

/// Outcome of one ingest, returned as `{"status": ...}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// Replaced what was stored.
    Stored { items: i64 },
    /// Same content as stored; nothing rewritten.
    Unchanged,
    /// Older than what is stored (or than a set being assembled); ignored.
    Stale { stored_scanned_at: NaiveDateTime },
    /// SBOM page kept; the set is not complete yet.
    Staged { received: i64, total: i64 },
    /// SBOM page already held.
    DuplicatePage { received: i64, total: i64 },
}

#[derive(QueryableByName)]
struct StoredHeader {
    #[diesel(sql_type = Timestamp)]
    scanned_at: NaiveDateTime,
    #[diesel(sql_type = Text)]
    content_hash: String,
}

#[derive(QueryableByName)]
struct HashRow {
    #[diesel(sql_type = Text)]
    h: String,
}

fn lock_key(conn: &mut PgConnection, h: &Header) -> QueryResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(format!("supplychain|{}|{}|{}", h.digest, h.source, h.kind))
        .execute(conn)
        .map(|_| ())
}

fn stored_header(conn: &mut PgConnection, h: &Header) -> QueryResult<Option<StoredHeader>> {
    sql_query(
        "SELECT scanned_at, content_hash FROM vuln_sources \
         WHERE digest = $1 AND source = $2 AND kind = $3",
    )
    .bind::<Text, _>(&h.digest)
    .bind::<Text, _>(&h.source)
    .bind::<Text, _>(&h.kind)
    .get_result(conn)
    .optional()
}

const HEADER_UPSERT_SQL: &str = "\
INSERT INTO vuln_sources (digest, source, kind, digest_kind, platform_manifests, manifest_digests, \
    image_ref, registry, repository, norm_repository, tag, scanner_name, scanner_vendor, \
    scanner_version, scanned_at, db_updated_at, os_family, os_name, os_eosl, observed_in, \
    content_hash, sbom_format, sbom_spec_version, item_count, sbom_source, attestation, \
    received_at) \
SELECT r.digest, r.source, r.kind, r.digest_kind, r.platform_manifests, r.manifest_digests, \
    r.image_ref, r.registry, r.repository, r.norm_repository, r.tag, r.scanner_name, \
    r.scanner_vendor, r.scanner_version, r.scanned_at, r.db_updated_at, r.os_family, r.os_name, \
    r.os_eosl, r.observed_in, r.content_hash, r.sbom_format, r.sbom_spec_version, r.item_count, \
    r.sbom_source, r.attestation, timezone('UTC', NOW()) \
FROM jsonb_populate_record(NULL::vuln_sources, $1) r \
ON CONFLICT (digest, source, kind) DO UPDATE SET \
    digest_kind = EXCLUDED.digest_kind, platform_manifests = EXCLUDED.platform_manifests, \
    manifest_digests = EXCLUDED.manifest_digests, image_ref = EXCLUDED.image_ref, \
    registry = EXCLUDED.registry, repository = EXCLUDED.repository, \
    norm_repository = EXCLUDED.norm_repository, tag = EXCLUDED.tag, \
    scanner_name = EXCLUDED.scanner_name, scanner_vendor = EXCLUDED.scanner_vendor, \
    scanner_version = EXCLUDED.scanner_version, scanned_at = EXCLUDED.scanned_at, \
    db_updated_at = EXCLUDED.db_updated_at, os_family = EXCLUDED.os_family, \
    os_name = EXCLUDED.os_name, os_eosl = EXCLUDED.os_eosl, observed_in = EXCLUDED.observed_in, \
    content_hash = EXCLUDED.content_hash, sbom_format = EXCLUDED.sbom_format, \
    sbom_spec_version = EXCLUDED.sbom_spec_version, item_count = EXCLUDED.item_count, \
    sbom_source = EXCLUDED.sbom_source, attestation = EXCLUDED.attestation, \
    received_at = EXCLUDED.received_at";

fn upsert_header(conn: &mut PgConnection, h: &Header) -> Result<(), DbError> {
    sql_query(HEADER_UPSERT_SQL)
        .bind::<Jsonb, _>(serde_json::to_value(h)?)
        .execute(conn)?;
    Ok(())
}

const VULNS_INSERT_SQL: &str = "\
INSERT INTO image_vulnerabilities (digest, source, vuln_id, pkg_name, pkg_type, pkg_purl, \
    installed_version, fixed_version, severity, severity_rank, score, cvss, title, primary_url, \
    target, class, published_at, last_modified_at, file_paths, kev, kev_date_added, epss, \
    epss_percentile, scanned_at) \
SELECT $1, $2, r.vuln_id, r.pkg_name, r.pkg_type, r.pkg_purl, r.installed_version, \
    r.fixed_version, r.severity, r.severity_rank, r.score, COALESCE(r.cvss, '{}'::jsonb), \
    r.title, r.primary_url, r.target, r.class, r.published_at, r.last_modified_at, \
    COALESCE(r.file_paths, '{}'), r.kev, r.kev_date_added, r.epss, r.epss_percentile, $3 \
FROM jsonb_to_recordset($4) AS r(ord bigint, vuln_id text, pkg_name text, pkg_type text, \
    pkg_purl text, installed_version text, fixed_version text, severity text, \
    severity_rank smallint, score real, cvss jsonb, title text, primary_url text, target text, \
    class text, published_at timestamp, last_modified_at timestamp, file_paths text[], \
    kev boolean, kev_date_added timestamp, epss real, epss_percentile real) \
ORDER BY r.ord";

/// Column list shared by the direct SBOM insert and the page assembly.
const COMPONENT_RECORD: &str = "(ord bigint, name text, version text, purl text, type text, \
    class text, src_name text, src_version text, licenses text[], layer_digest text, \
    file_paths text[])";

fn components_insert_sql() -> String {
    format!(
        "INSERT INTO image_sbom_components (digest, source, name, version, purl, type, class, \
            src_name, src_version, licenses, layer_digest, file_paths) \
         SELECT $1, $2, r.name, r.version, r.purl, r.type, r.class, r.src_name, r.src_version, \
            COALESCE(r.licenses, '{{}}'), r.layer_digest, COALESCE(r.file_paths, '{{}}') \
         FROM jsonb_to_recordset($3) AS r{COMPONENT_RECORD} ORDER BY r.ord"
    )
}

fn assemble_pages_sql() -> String {
    format!(
        "INSERT INTO image_sbom_components (digest, source, name, version, purl, type, class, \
            src_name, src_version, licenses, layer_digest, file_paths) \
         SELECT p.digest, p.source, r.name, r.version, r.purl, r.type, r.class, r.src_name, \
            r.src_version, COALESCE(r.licenses, '{{}}'), r.layer_digest, \
            COALESCE(r.file_paths, '{{}}') \
         FROM image_sbom_pages p CROSS JOIN LATERAL jsonb_to_recordset(p.components) \
            AS r{COMPONENT_RECORD} \
         WHERE p.digest = $1 AND p.source = $2 AND p.set_id = $3 \
         ORDER BY p.page_index, r.ord"
    )
}

fn md5_of(conn: &mut PgConnection, s: &str) -> QueryResult<String> {
    sql_query("SELECT md5($1) AS h")
        .bind::<Text, _>(s)
        .get_result::<HashRow>(conn)
        .map(|r| r.h)
}

/// Replace the findings for `(digest, source)`; see the module docs for
/// the stale / unchanged rules.
pub fn store_vulnerabilities(
    conn: &mut PgConnection,
    mut p: VulnPayload,
) -> Result<Outcome, DbError> {
    let rows_json = serde_json::to_string(&p.rows)?;
    conn.transaction::<_, DbError, _>(|conn| {
        lock_key(conn, &p.header)?;
        p.header.content_hash = md5_of(conn, &rows_json)?;
        let existing = stored_header(conn, &p.header)?;
        if let Some(e) = &existing {
            if p.header.scanned_at < e.scanned_at {
                return Ok(Outcome::Stale {
                    stored_scanned_at: e.scanned_at,
                });
            }
            if e.content_hash == p.header.content_hash {
                upsert_header(conn, &p.header)?;
                relink(conn, &p.header.digest, &p.header.source)?;
                return Ok(Outcome::Unchanged);
            }
        }
        sql_query("DELETE FROM image_vulnerabilities WHERE digest = $1 AND source = $2")
            .bind::<Text, _>(&p.header.digest)
            .bind::<Text, _>(&p.header.source)
            .execute(conn)?;
        let n = sql_query(VULNS_INSERT_SQL)
            .bind::<Text, _>(&p.header.digest)
            .bind::<Text, _>(&p.header.source)
            .bind::<Timestamp, _>(p.header.scanned_at)
            .bind::<Jsonb, _>(serde_json::from_str::<serde_json::Value>(&rows_json)?)
            .execute(conn)?;
        upsert_header(conn, &p.header)?;
        relink(conn, &p.header.digest, &p.header.source)?;
        Ok(Outcome::Stored { items: n as i64 })
    })
}

fn replace_components_from_json(
    conn: &mut PgConnection,
    h: &Header,
    rows: serde_json::Value,
) -> Result<i64, DbError> {
    sql_query("DELETE FROM image_sbom_components WHERE digest = $1 AND source = $2")
        .bind::<Text, _>(&h.digest)
        .bind::<Text, _>(&h.source)
        .execute(conn)?;
    let n = sql_query(components_insert_sql())
        .bind::<Text, _>(&h.digest)
        .bind::<Text, _>(&h.source)
        .bind::<Jsonb, _>(rows)
        .execute(conn)?;
    Ok(n as i64)
}

/// Drop staged pages of other sets for this key that are no newer than
/// `scanned_at` (superseded).
fn drop_superseded_pages(
    conn: &mut PgConnection,
    h: &Header,
    keep_set: Option<&str>,
) -> QueryResult<usize> {
    sql_query(
        "DELETE FROM image_sbom_pages WHERE digest = $1 AND source = $2 \
         AND ($3::text IS NULL OR set_id <> $3) AND scanned_at <= $4",
    )
    .bind::<Text, _>(&h.digest)
    .bind::<Text, _>(&h.source)
    .bind::<Nullable<Text>, _>(keep_set)
    .bind::<Timestamp, _>(h.scanned_at)
    .execute(conn)
}

#[derive(QueryableByName)]
struct Inserted {
    #[diesel(sql_type = Bool)]
    inserted: bool,
}

#[derive(QueryableByName)]
struct NewestStaged {
    #[diesel(sql_type = Nullable<Timestamp>)]
    newest: Option<NaiveDateTime>,
}

#[derive(QueryableByName)]
struct SetShape {
    #[diesel(sql_type = BigInt)]
    pages: i64,
    #[diesel(sql_type = BigInt)]
    totals: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    total: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    components: Option<i64>,
}

/// Store an SBOM or one page of it; see the module docs.
pub fn store_sbom(conn: &mut PgConnection, mut p: SbomPayload) -> Result<Outcome, DbError> {
    let rows_json = serde_json::to_string(&p.rows)?;
    conn.transaction::<_, DbError, _>(|conn| {
        lock_key(conn, &p.header)?;
        p.header.content_hash = match &p.page {
            Some(pg) => pg.set_id.clone(),
            None => format!("md5:{}", md5_of(conn, &rows_json)?),
        };
        let existing = stored_header(conn, &p.header)?;
        if let Some(e) = &existing {
            if p.header.scanned_at < e.scanned_at {
                return Ok(Outcome::Stale {
                    stored_scanned_at: e.scanned_at,
                });
            }
            if e.content_hash == p.header.content_hash {
                // A complete copy of this very set is already live: a
                // re-sent page (or whole SBOM) changes nothing.
                return Ok(Outcome::Unchanged);
            }
        }
        // A newer set is being assembled: this one is already outdated.
        let newest: NewestStaged = sql_query(
            "SELECT max(scanned_at) AS newest FROM image_sbom_pages \
             WHERE digest = $1 AND source = $2 AND set_id <> $3",
        )
        .bind::<Text, _>(&p.header.digest)
        .bind::<Text, _>(&p.header.source)
        .bind::<Text, _>(&p.header.content_hash)
        .get_result(conn)?;
        if let Some(n) = newest.newest {
            if n > p.header.scanned_at {
                return Ok(Outcome::Stale {
                    stored_scanned_at: n,
                });
            }
        }

        let Some(page) = p.page.clone() else {
            let n =
                replace_components_from_json(conn, &p.header, serde_json::from_str(&rows_json)?)?;
            p.header.item_count = n as i32;
            upsert_header(conn, &p.header)?;
            drop_superseded_pages(conn, &p.header, None)?;
            relink(conn, &p.header.digest, &p.header.source)?;
            return Ok(Outcome::Stored { items: n });
        };

        drop_superseded_pages(conn, &p.header, Some(&page.set_id))?;
        // Re-sending a page refreshes its timestamp so a slow set being
        // retried does not expire under the retry.
        let ins: Inserted = sql_query(
            "INSERT INTO image_sbom_pages (digest, source, set_id, page_index, total, \
                 scanned_at, components) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (digest, source, set_id, page_index) \
             DO UPDATE SET received_at = timezone('UTC', NOW()) \
             RETURNING (xmax = 0) AS inserted",
        )
        .bind::<Text, _>(&p.header.digest)
        .bind::<Text, _>(&p.header.source)
        .bind::<Text, _>(&page.set_id)
        .bind::<diesel::sql_types::Integer, _>(page.index as i32)
        .bind::<diesel::sql_types::Integer, _>(page.total as i32)
        .bind::<Timestamp, _>(p.header.scanned_at)
        .bind::<Jsonb, _>(serde_json::from_str::<serde_json::Value>(&rows_json)?)
        .get_result(conn)?;
        let shape: SetShape = sql_query(
            "SELECT count(*) AS pages, count(DISTINCT total) AS totals, \
                 max(total)::bigint AS total, \
                 sum(jsonb_array_length(components))::bigint AS components \
             FROM image_sbom_pages WHERE digest = $1 AND source = $2 AND set_id = $3",
        )
        .bind::<Text, _>(&p.header.digest)
        .bind::<Text, _>(&p.header.source)
        .bind::<Text, _>(&page.set_id)
        .get_result(conn)?;
        if shape.totals > 1 || shape.total != Some(page.total) {
            return Err(Box::new(SetConflict(format!(
                "pages of set {} disagree on total",
                page.set_id
            ))));
        }
        if shape.components.unwrap_or(0) > MAX_SBOM_COMPONENTS as i64 {
            sql_query(
                "DELETE FROM image_sbom_pages WHERE digest = $1 AND source = $2 AND set_id = $3",
            )
            .bind::<Text, _>(&p.header.digest)
            .bind::<Text, _>(&p.header.source)
            .bind::<Text, _>(&page.set_id)
            .execute(conn)?;
            return Err(Box::new(SetConflict(format!(
                "set {} holds more than {MAX_SBOM_COMPONENTS} components; dropped",
                page.set_id
            ))));
        }
        if shape.pages < page.total {
            return Ok(if ins.inserted {
                Outcome::Staged {
                    received: shape.pages,
                    total: page.total,
                }
            } else {
                Outcome::DuplicatePage {
                    received: shape.pages,
                    total: page.total,
                }
            });
        }
        // Complete: swap the whole set in, then drop its pages.
        sql_query("DELETE FROM image_sbom_components WHERE digest = $1 AND source = $2")
            .bind::<Text, _>(&p.header.digest)
            .bind::<Text, _>(&p.header.source)
            .execute(conn)?;
        let n = sql_query(assemble_pages_sql())
            .bind::<Text, _>(&p.header.digest)
            .bind::<Text, _>(&p.header.source)
            .bind::<Text, _>(&page.set_id)
            .execute(conn)? as i64;
        sql_query("DELETE FROM image_sbom_pages WHERE digest = $1 AND source = $2 AND set_id = $3")
            .bind::<Text, _>(&p.header.digest)
            .bind::<Text, _>(&p.header.source)
            .bind::<Text, _>(&page.set_id)
            .execute(conn)?;
        p.header.item_count = n as i32;
        upsert_header(conn, &p.header)?;
        relink(conn, &p.header.digest, &p.header.source)?;
        Ok(Outcome::Stored { items: n })
    })
}

/// A paged set that cannot be assembled (pages disagree on `total`, or the
/// set is over the component cap). Surfaces as 422.
#[derive(Debug)]
pub struct SetConflict(pub String);

impl std::fmt::Display for SetConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SetConflict {}

// ---------------------------------------------------------------------
// Join to the inventory
// ---------------------------------------------------------------------

pub const JOIN_IMAGE_ID: &str = "image_id";
pub const JOIN_PLATFORM_MANIFEST: &str = "platform_manifest";
pub const JOIN_WORKLOAD_TAG: &str = "workload_tag";

/// The links a payload `(digest, source)` should have, as a CTE named
/// `wanted(image_digest, join_kind, join_rank)`. Rules in charter order;
/// the tag rule is consulted only when neither digest rule matched.
///
/// The tag rule maps the source's workload to the inventory's: Trivy
/// Operator names the ReplicaSet (`api-7c9d8f6b5`) or the Job
/// (`backup-29012345`) where the inventory keys the Deployment (`api`)
/// or CronJob (`backup`), so a ReplicaSet/Job name that is the inventory
/// workload name plus one `-<suffix>` of [a-z0-9]{1,12} matches.
const WANTED_LINKS_CTE: &str = "\
WITH hdr AS ( \
    SELECT manifest_digests, norm_repository, tag, observed_in FROM vuln_sources \
    WHERE digest = $1 AND source = $2 \
), exact AS ( \
    SELECT i.digest AS image_digest, 'image_id'::text AS join_kind, 1::smallint AS join_rank \
    FROM images i WHERE i.digest = $1 AND EXISTS (SELECT 1 FROM hdr) \
    UNION ALL \
    SELECT i.digest, 'platform_manifest'::text, 2::smallint FROM images i \
    WHERE i.digest <> $1 AND i.digest IN (SELECT unnest(h.manifest_digests) FROM hdr h) \
), tagged AS ( \
    SELECT DISTINCT wc.image_digest, 'workload_tag'::text AS join_kind, 3::smallint AS join_rank \
    FROM hdr h \
    CROSS JOIN LATERAL jsonb_array_elements(h.observed_in) o \
    JOIN workload_containers wc ON wc.pod_namespace = o->>'namespace' \
        AND wc.container_name = o->>'container' \
    JOIN images i ON i.digest = wc.image_digest \
    WHERE NOT EXISTS (SELECT 1 FROM exact) \
      AND h.tag IS NOT NULL AND h.norm_repository IS NOT NULL \
      AND i.repository = h.norm_repository AND h.tag = ANY(i.tags) \
      AND ((wc.workload_kind = o->>'kind' AND wc.workload_name = o->>'name') \
        OR (o->>'kind' IN ('ReplicaSet', 'Job') \
            AND wc.workload_kind = CASE o->>'kind' WHEN 'ReplicaSet' THEN 'Deployment' ELSE 'CronJob' END \
            AND left(o->>'name', length(wc.workload_name) + 1) = wc.workload_name || '-' \
            AND substr(o->>'name', length(wc.workload_name) + 2) ~ '^[a-z0-9]{1,12}$')) \
), wanted AS ( \
    SELECT DISTINCT ON (image_digest) image_digest, join_kind, join_rank \
    FROM (SELECT * FROM exact UNION ALL SELECT * FROM tagged) c \
    ORDER BY image_digest, join_rank \
) ";

/// Bring `supplychain_image_links` for one payload in line with the
/// inventory. Writes only what changed, so the periodic pass does not
/// churn rows.
pub fn relink(conn: &mut PgConnection, digest: &str, source: &str) -> QueryResult<usize> {
    let removed = sql_query(format!(
        "{WANTED_LINKS_CTE} DELETE FROM supplychain_image_links l \
         WHERE l.digest = $1 AND l.source = $2 \
           AND NOT EXISTS (SELECT 1 FROM wanted w WHERE w.image_digest = l.image_digest \
               AND w.join_kind = l.join_kind)"
    ))
    .bind::<Text, _>(digest)
    .bind::<Text, _>(source)
    .execute(conn)?;
    let added = sql_query(format!(
        "{WANTED_LINKS_CTE} INSERT INTO supplychain_image_links \
             (digest, source, image_digest, join_kind, join_rank) \
         SELECT $1, $2, w.image_digest, w.join_kind, w.join_rank FROM wanted w \
         ON CONFLICT (digest, source, image_digest) DO NOTHING"
    ))
    .bind::<Text, _>(digest)
    .bind::<Text, _>(source)
    .execute(conn)?;
    Ok(removed + added)
}

#[derive(QueryableByName)]
struct Key {
    #[diesel(sql_type = Text)]
    digest: String,
    #[diesel(sql_type = Text)]
    source: String,
}

/// Relink up to `batch` payloads after the cursor, in key order. Returns
/// the last key processed, or `None` when the pass is complete.
pub fn relink_batch(
    conn: &mut PgConnection,
    after: Option<&(String, String)>,
    batch: i64,
) -> QueryResult<(usize, Option<(String, String)>)> {
    let keys: Vec<Key> = sql_query(
        "SELECT DISTINCT digest, source FROM vuln_sources \
         WHERE $1::text IS NULL OR (digest, source) > ($1, $2) \
         ORDER BY digest, source LIMIT $3",
    )
    .bind::<Nullable<Text>, _>(after.map(|a| a.0.as_str()))
    .bind::<Nullable<Text>, _>(after.map(|a| a.1.as_str()))
    .bind::<BigInt, _>(batch)
    .load(conn)?;
    let mut changed = 0;
    for k in &keys {
        changed += conn.transaction(|conn| relink(conn, &k.digest, &k.source))?;
    }
    let last = if (keys.len() as i64) < batch {
        None
    } else {
        keys.last().map(|k| (k.digest.clone(), k.source.clone()))
    };
    Ok((changed, last))
}

// ---------------------------------------------------------------------
// Retention (driven from retention.rs)
// ---------------------------------------------------------------------

/// Payload keys to delete: nothing they link to has run for `$2` days
/// (no linked `workload_containers` row seen since then, and none running
/// by the inventory's own predicate), and nothing has been received for
/// them within the grace (`$1` hours), which covers a scan that lands
/// before its pod's first inventory post.
pub(crate) const SUPPLYCHAIN_GC_KEYS_SQL: &str = concat!(
    "SELECT k.digest, k.source FROM ( \
        SELECT digest, source, max(received_at) AS received_at FROM vuln_sources \
        GROUP BY digest, source \
     ) k \
     WHERE k.received_at < timezone('UTC', NOW()) - make_interval(hours => $1) \
       AND NOT EXISTS ( \
         SELECT 1 FROM supplychain_image_links l \
         JOIN workload_containers wc ON wc.image_digest = l.image_digest \
         WHERE l.digest = k.digest AND l.source = k.source \
           AND (wc.last_seen >= timezone('UTC', NOW()) - make_interval(days => $2) OR ",
    crate::image_inventory::running_sql!("$3"),
    ")) ORDER BY k.received_at LIMIT $4"
);

const GC_TABLES: [&str; 5] = [
    "image_vulnerabilities",
    "image_sbom_components",
    "image_sbom_pages",
    "supplychain_image_links",
    "vuln_sources",
];

/// Delete up to `batch` expired payloads (every table, one transaction).
/// Returns how many payload keys went.
pub fn gc_batch(
    conn: &mut PgConnection,
    days: u32,
    grace_hours: u32,
    running_window_secs: i64,
    batch: i64,
) -> QueryResult<usize> {
    conn.transaction(|conn| {
        let keys: Vec<Key> = sql_query(SUPPLYCHAIN_GC_KEYS_SQL)
            .bind::<diesel::sql_types::Integer, _>(grace_hours as i32)
            .bind::<diesel::sql_types::Integer, _>(days as i32)
            .bind::<diesel::sql_types::Double, _>(running_window_secs as f64)
            .bind::<BigInt, _>(batch)
            .load(conn)?;
        if keys.is_empty() {
            return Ok(0);
        }
        let digests: Vec<&str> = keys.iter().map(|k| k.digest.as_str()).collect();
        let sources: Vec<&str> = keys.iter().map(|k| k.source.as_str()).collect();
        for table in GC_TABLES {
            sql_query(format!(
                "DELETE FROM {table} t USING unnest($1::text[], $2::text[]) AS k(digest, source) \
                 WHERE t.digest = k.digest AND t.source = k.source"
            ))
            .bind::<diesel::sql_types::Array<Text>, _>(&digests)
            .bind::<diesel::sql_types::Array<Text>, _>(&sources)
            .execute(conn)?;
        }
        Ok(keys.len())
    })
}

/// Expire staged SBOM sets whose newest page is older than `ttl_secs`.
/// Returns pages deleted.
pub fn expire_pages_batch(
    conn: &mut PgConnection,
    ttl_secs: i64,
    batch: i64,
) -> QueryResult<usize> {
    sql_query(
        "WITH stale AS ( \
            SELECT digest, source, set_id FROM image_sbom_pages \
            GROUP BY digest, source, set_id \
            HAVING max(received_at) < timezone('UTC', NOW()) - make_interval(secs => $1) \
            LIMIT $2 \
         ) \
         DELETE FROM image_sbom_pages p USING stale s \
         WHERE p.digest = s.digest AND p.source = s.source AND p.set_id = s.set_id",
    )
    .bind::<diesel::sql_types::Double, _>(ttl_secs as f64)
    .bind::<BigInt, _>(batch)
    .execute(conn)
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

enum Kind {
    Vulnerabilities,
    Sbom,
}

async fn ingest(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Payload,
    kind: Kind,
) -> HttpResponse {
    if !ingest_allowed(req.app_data::<web::Data<AuthConfig>>().map(|d| d.get_ref())) {
        return not_scoped();
    }
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return HttpResponse::BadRequest()
            .body("digest must be sha256:<64 hex> or sha512:<128 hex>");
    }
    let Ok(_slot) = INGEST_SLOTS.acquire().await else {
        return HttpResponse::ServiceUnavailable().finish();
    };
    let bytes = match read_body(&req, body, max_decompressed_bytes()).await {
        Ok(b) => b,
        Err(e) => {
            warn!(%digest, error = ?e, "supply-chain ingest body refused");
            return e.into_response();
        }
    };
    let now = Utc::now();
    let parsed = match kind {
        Kind::Vulnerabilities => serde_json::from_slice::<WireImageVulnerabilities>(&bytes)
            .map_err(|e| e.to_string())
            .map(|p| normalise_vulnerabilities(&digest, p, now).map(Parsed::Vulns)),
        Kind::Sbom => serde_json::from_slice::<WireImageSbom>(&bytes)
            .map_err(|e| e.to_string())
            .map(|p| normalise_sbom(&digest, p, now).map(Parsed::Sbom)),
    };
    drop(bytes);
    let parsed = match parsed {
        Err(e) => return HttpResponse::BadRequest().body(format!("invalid JSON: {e}")),
        Ok(Err(r)) => {
            warn!(%digest, reason = ?r, "supply-chain payload refused");
            return r.into_response();
        }
        Ok(Ok(p)) => p,
    };
    let Some(pool) = req.app_data::<web::Data<DbPool>>().cloned() else {
        return HttpResponse::InternalServerError().body("no database pool");
    };
    let result = web::block(move || -> Result<Outcome, DbError> {
        let mut conn = pool.get()?;
        match parsed {
            Parsed::Vulns(p) => store_vulnerabilities(&mut conn, p),
            Parsed::Sbom(p) => store_sbom(&mut conn, p),
        }
    })
    .await;
    match result {
        Ok(Ok(o)) => {
            match &o {
                Outcome::Stored { items } => {
                    info!(%digest, items, "supply-chain payload stored")
                }
                other => debug!(%digest, outcome = ?other, "supply-chain payload handled"),
            }
            let status = if matches!(o, Outcome::Staged { .. }) {
                actix_web::http::StatusCode::ACCEPTED
            } else {
                actix_web::http::StatusCode::OK
            };
            HttpResponse::build(status).json(o)
        }
        Ok(Err(e)) => {
            if let Some(c) = e.downcast_ref::<SetConflict>() {
                warn!(%digest, error = %c, "supply-chain SBOM set refused");
                return HttpResponse::UnprocessableEntity().body(c.0.clone());
            }
            warn!(%digest, error = %e, "supply-chain ingest failed");
            HttpResponse::InternalServerError().body("storing the payload failed")
        }
        Err(e) => {
            warn!(%digest, error = %e, "supply-chain ingest task failed");
            HttpResponse::InternalServerError().finish()
        }
    }
}

enum Parsed {
    Vulns(VulnPayload),
    Sbom(SbomPayload),
}

pub async fn post_image_vulnerabilities(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Payload,
) -> HttpResponse {
    ingest(req, path, body, Kind::Vulnerabilities).await
}

pub async fn post_image_sbom(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Payload,
) -> HttpResponse {
    ingest(req, path, body, Kind::Sbom).await
}

#[cfg(test)]
#[path = "supplychain_tests.rs"]
mod tests;
