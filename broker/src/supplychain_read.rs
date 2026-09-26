//! Supply-chain reads (#1533 P1-3): vulnerabilities and SBOM components
//! per image, CVEs cluster-wide, and one CVE's exposure.
//!
//! Every handler clamps its page size, charges the read budget before it
//! touches the pool, and never returns more than one page of rows. List
//! responses never carry SBOM documents: components are paged rows, and
//! the CycloneDX document is its own route.
//!
//! # Which payload answers for an image
//!
//! A request names an inventory digest (what the kubelet ran). For each
//! source, the payload linked to it by the best rule is used
//! (`supplychain_image_links`: image_id, then platform_manifest, then
//! workload_tag; newest scan on a tie). A digest with no link but with a
//! payload stored under exactly that digest answers as `report_digest`.
//! The rule is returned as `join` so the UI can show confidence.
//!
//! # "In use"
//!
//! `inUse` is `null` and `inUseState` is `"unknown"` everywhere until the
//! runtime path→package join (P1-5) fills it. Unknown is not "not in use"
//! and must never be shown as safe.

use crate::image_inventory::{is_valid_digest, running_sql, running_window_secs};
use crate::read_budget::{cost_kib, ReadBudget};
use crate::supplychain::{severity_rank, KIND_SBOM, KIND_VULNERABILITIES};
use actix_web::{get, web, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{
    Array, BigInt, Bool, Double, Float, Integer, Jsonb, Nullable, SmallInt, Text, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

pub const VULNS_DEFAULT_LIMIT: i64 = 100;
pub const VULNS_MAX_LIMIT: i64 = 500;
/// Per finding row: bounded strings (title 512 B, url 1 KiB, cvss for at
/// most 8 vendors) plus at most 16 file paths of at most 1 KiB each. The
/// paths dominate the worst case; 20 KiB covers the row, its serialised
/// form and the transient copy.
pub const VULN_ROW_COST_BYTES: u64 = 20 * 1024;
/// Per component row: at most 8 licences and 16 paths, as above.
pub const COMPONENT_ROW_COST_BYTES: u64 = 20 * 1024;
/// Per CycloneDX component (no file paths in the export): bounded
/// name/version/purl/licences, ~2.5 KiB worst case, charged at 4 KiB.
pub const EXPORT_COMPONENT_COST_BYTES: u64 = 4 * 1024;
/// Per grouped CVE row: id, a few counts, up to 5 package names.
pub const CVE_ROW_COST_BYTES: u64 = 2 * 1024;
/// Images and workloads listed in one exposure answer.
pub const EXPOSURE_MAX_IMAGES: i64 = 200;
pub const EXPOSURE_MAX_WORKLOADS: i64 = 200;
/// Package findings listed per image in an exposure answer.
pub const EXPOSURE_MAX_PACKAGES: i64 = 50;
/// Pods per workload whose traffic is examined, most recent first.
pub const EXPOSURE_PODS_PER_WORKLOAD: i64 = 50;
/// Distinct unresolved peer IPs examined per workload.
pub const EXPOSURE_PEERS_PER_WORKLOAD: i64 = 256;
pub const EXPOSURE_DEFAULT_WINDOW_HOURS: i64 = 168;
pub const EXPOSURE_MAX_WINDOW_HOURS: i64 = 720;
/// One exposure answer: images x packages + workloads with their peers.
pub const EXPOSURE_COST_BYTES: u64 = 8 * 1024 * 1024;

pub const IN_USE_UNKNOWN: &str = "unknown";

pub(crate) fn clamp_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(VULNS_DEFAULT_LIMIT).clamp(1, VULNS_MAX_LIMIT)
}

fn empty_to_none(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `severity=CRITICAL,high` → ranks. Unknown names are a 400, not a
/// silently empty filter.
pub(crate) fn parse_severities(raw: Option<&str>) -> Result<Option<Vec<i16>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, rank) = severity_rank(part);
        if name == "UNKNOWN" && !part.eq_ignore_ascii_case("unknown") {
            return Err(format!(
                "unknown severity '{part}'; use CRITICAL, HIGH, MEDIUM, LOW, NONE or UNKNOWN"
            ));
        }
        if !out.contains(&rank) {
            out.push(rank);
        }
    }
    Ok(Some(out))
}

/// Keyset cursor `<rank>.<tail>`; the tail is an id or a CVE id.
pub(crate) fn parse_cursor(raw: Option<&str>) -> Result<Option<(i16, String)>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let (rank, tail) = raw
        .split_once('.')
        .ok_or_else(|| "after must be the nextAfter of the previous page".to_string())?;
    let rank: i16 = rank
        .parse()
        .ok()
        .filter(|r| (0..=5).contains(r))
        .ok_or_else(|| "after must be the nextAfter of the previous page".to_string())?;
    if tail.is_empty() || tail.len() > 256 {
        return Err("after must be the nextAfter of the previous page".into());
    }
    Ok(Some((rank, tail.to_string())))
}

/// Public (internet-routable) address: not private, loopback, link-local,
/// CGNAT, ULA, multicast, unspecified or documentation space.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] == 0
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

// ---------------------------------------------------------------------
// Resolution: which payload(s) answer for a digest
// ---------------------------------------------------------------------

#[derive(Debug, Clone, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    #[diesel(sql_type = Text)]
    pub source: String,
    /// The digest the source reported (may be an index).
    #[diesel(sql_type = Text)]
    pub report_digest: String,
    /// image_id | platform_manifest | workload_tag | report_digest
    #[diesel(sql_type = Text)]
    pub join: String,
    #[diesel(sql_type = Text)]
    pub digest_kind: String,
    #[diesel(sql_type = Timestamp)]
    pub scanned_at: NaiveDateTime,
    #[diesel(sql_type = Nullable<Timestamp>)]
    pub db_updated_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    pub scanner_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub scanner_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub os_family: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub os_name: Option<String>,
    #[diesel(sql_type = Bool)]
    pub os_eosl: bool,
    #[diesel(sql_type = Nullable<Text>)]
    pub image_ref: Option<String>,
    #[diesel(sql_type = Integer)]
    pub item_count: i32,
    #[diesel(sql_type = Nullable<Text>)]
    pub sbom_format: Option<String>,
    #[diesel(sql_type = Timestamp)]
    pub received_at: NaiveDateTime,
    /// Matcher findings: the SBOM source that was matched.
    #[diesel(sql_type = Nullable<Text>)]
    pub sbom_source: Option<String>,
    /// Registry-attached SBOM: where it was found. `verified: false`
    /// means no signature was checked; never show it as signed.
    #[diesel(sql_type = Nullable<Jsonb>)]
    pub attestation: Option<serde_json::Value>,
}

const RESOLVE_SQL: &str = "\
WITH cand AS ( \
    SELECT l.digest, l.source, l.join_kind, l.join_rank FROM supplychain_image_links l \
    WHERE l.image_digest = $1 \
    UNION ALL \
    SELECT vs.digest, vs.source, 'report_digest', 4 FROM vuln_sources vs \
    WHERE vs.digest = $1 AND vs.kind = $2 \
) \
SELECT DISTINCT ON (c.source) c.source, c.digest AS report_digest, c.join_kind AS join, \
    vs.digest_kind, vs.scanned_at, vs.db_updated_at, vs.scanner_name, vs.scanner_version, \
    vs.os_family, vs.os_name, vs.os_eosl, vs.image_ref, vs.item_count, vs.sbom_format, \
    vs.received_at, vs.sbom_source, vs.attestation \
FROM cand c JOIN vuln_sources vs ON vs.digest = c.digest AND vs.source = c.source \
    AND vs.kind = $2 \
WHERE ($3::text IS NULL OR c.source = $3) \
ORDER BY c.source, c.join_rank, vs.scanned_at DESC";

pub fn resolve_reports(
    conn: &mut PgConnection,
    digest: &str,
    kind: &str,
    source: Option<&str>,
) -> QueryResult<Vec<Report>> {
    sql_query(RESOLVE_SQL)
        .bind::<Text, _>(digest)
        .bind::<Text, _>(kind)
        .bind::<Nullable<Text>, _>(source)
        .load(conn)
}

// ---------------------------------------------------------------------
// GET /images/{digest}/vulnerabilities
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ImageVulnsQuery {
    /// Comma-separated severities to include.
    pub severity: Option<String>,
    /// true: only findings with a fixed version; false: only without.
    pub fixable: Option<bool>,
    /// Only this source's report.
    pub source: Option<String>,
    pub limit: Option<i64>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, QueryableByName)]
struct VulnDbRow {
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Text)]
    report_digest: String,
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Text)]
    vuln_id: String,
    #[diesel(sql_type = Text)]
    pkg_name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pkg_type: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pkg_purl: Option<String>,
    #[diesel(sql_type = Text)]
    installed_version: String,
    #[diesel(sql_type = Nullable<Text>)]
    fixed_version: Option<String>,
    #[diesel(sql_type = Text)]
    severity: String,
    #[diesel(sql_type = SmallInt)]
    severity_rank: i16,
    #[diesel(sql_type = Nullable<Float>)]
    score: Option<f32>,
    #[diesel(sql_type = Jsonb)]
    cvss: serde_json::Value,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    primary_url: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    target: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    class: Option<String>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    published_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    last_modified_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Array<Text>)]
    file_paths: Vec<String>,
    #[diesel(sql_type = Nullable<Bool>)]
    kev: Option<bool>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    kev_date_added: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Float>)]
    epss: Option<f32>,
    #[diesel(sql_type = Nullable<Float>)]
    epss_percentile: Option<f32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageRef {
    pub name: String,
    #[serde(rename = "type")]
    pub pkg_type: Option<String>,
    pub purl: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub package: PackageRef,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub fixable: bool,
    pub severity: String,
    pub score: Option<f32>,
    pub cvss: serde_json::Value,
    /// Third-party text: render, never execute or fetch.
    pub title: Option<String>,
    pub primary_url: Option<String>,
    pub target: Option<String>,
    pub class: Option<String>,
    pub published_at: Option<NaiveDateTime>,
    pub last_modified_at: Option<NaiveDateTime>,
    pub file_paths: Vec<String>,
    /// In CISA KEV. `null` = the source does not say (unknown).
    pub kev: Option<bool>,
    pub kev_date_added: Option<NaiveDateTime>,
    pub epss: Option<f32>,
    pub epss_percentile: Option<f32>,
    pub source: String,
    pub report_digest: String,
    /// Filled by the runtime join (P1-5). `null` = unknown, never "safe".
    pub in_use: Option<bool>,
    pub in_use_state: &'static str,
}

impl From<VulnDbRow> for Finding {
    fn from(r: VulnDbRow) -> Self {
        Finding {
            id: r.vuln_id,
            package: PackageRef {
                name: r.pkg_name,
                pkg_type: r.pkg_type,
                purl: r.pkg_purl,
            },
            installed_version: r.installed_version,
            fixable: r.fixed_version.is_some(),
            fixed_version: r.fixed_version,
            severity: r.severity,
            score: r.score,
            cvss: r.cvss,
            title: r.title,
            primary_url: r.primary_url,
            target: r.target,
            class: r.class,
            published_at: r.published_at,
            last_modified_at: r.last_modified_at,
            file_paths: r.file_paths,
            kev: r.kev,
            kev_date_added: r.kev_date_added,
            epss: r.epss,
            epss_percentile: r.epss_percentile,
            source: r.source,
            report_digest: r.report_digest,
            in_use: None,
            in_use_state: IN_USE_UNKNOWN,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageVulnsPage {
    pub digest: String,
    /// The report used per source, with the join rule that selected it.
    /// Empty = no vulnerability data for this image (unknown, not clean).
    pub reports: Vec<Report>,
    pub items: Vec<Finding>,
    pub next_after: Option<String>,
}

const IMAGE_VULNS_SQL: &str = "\
SELECT v.id, v.digest AS report_digest, v.source, v.vuln_id, v.pkg_name, v.pkg_type, v.pkg_purl, \
    v.installed_version, v.fixed_version, v.severity, v.severity_rank, v.score, v.cvss, v.title, \
    v.primary_url, v.target, v.class, v.published_at, v.last_modified_at, v.file_paths, \
    v.kev, v.kev_date_added, v.epss, v.epss_percentile \
FROM image_vulnerabilities v \
JOIN unnest($1::text[], $2::text[]) AS k(digest, source) \
    ON v.digest = k.digest AND v.source = k.source \
WHERE ($3::smallint[] IS NULL OR v.severity_rank = ANY($3)) \
  AND ($4::bool IS NULL OR (v.fixed_version IS NOT NULL) = $4) \
  AND ($5::smallint IS NULL OR v.severity_rank < $5 OR (v.severity_rank = $5 AND v.id > $6)) \
ORDER BY v.severity_rank DESC, v.id \
LIMIT $7";

#[allow(clippy::too_many_arguments)]
pub fn image_vulnerabilities(
    conn: &mut PgConnection,
    digest: &str,
    source: Option<&str>,
    severities: Option<&[i16]>,
    fixable: Option<bool>,
    after: Option<(i16, i64)>,
    limit: i64,
) -> Result<ImageVulnsPage, DbError> {
    let reports = resolve_reports(conn, digest, KIND_VULNERABILITIES, source)?;
    let digests: Vec<&str> = reports.iter().map(|r| r.report_digest.as_str()).collect();
    let sources: Vec<&str> = reports.iter().map(|r| r.source.as_str()).collect();
    let mut rows: Vec<VulnDbRow> = if reports.is_empty() {
        Vec::new()
    } else {
        sql_query(IMAGE_VULNS_SQL)
            .bind::<Array<Text>, _>(&digests)
            .bind::<Array<Text>, _>(&sources)
            .bind::<Nullable<Array<SmallInt>>, _>(severities)
            .bind::<Nullable<Bool>, _>(fixable)
            .bind::<Nullable<SmallInt>, _>(after.map(|a| a.0))
            .bind::<BigInt, _>(after.map(|a| a.1).unwrap_or(0))
            .bind::<BigInt, _>(limit + 1)
            .load(conn)?
    };
    let next_after = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|r| format!("{}.{}", r.severity_rank, r.id))
    } else {
        None
    };
    Ok(ImageVulnsPage {
        digest: digest.to_string(),
        reports,
        items: rows.into_iter().map(Finding::from).collect(),
        next_after,
    })
}

fn bad_digest() -> HttpResponse {
    HttpResponse::BadRequest().body("digest must be sha256:<64 hex> or sha512:<128 hex>")
}

pub async fn get_image_vulnerabilities(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<ImageVulnsQuery>,
) -> actix_web::Result<HttpResponse> {
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(bad_digest());
    }
    let q = query.into_inner();
    let limit = clamp_limit(q.limit);
    let severities = match parse_severities(q.severity.as_deref()) {
        Ok(s) => s,
        Err(e) => return Ok(HttpResponse::BadRequest().body(e)),
    };
    let after = match parse_cursor(q.after.as_deref()) {
        Ok(None) => None,
        Ok(Some((rank, tail))) => match tail.parse::<i64>() {
            Ok(id) => Some((rank, id)),
            Err(_) => {
                return Ok(HttpResponse::BadRequest()
                    .body("after must be the nextAfter of the previous page"))
            }
        },
        Err(e) => return Ok(HttpResponse::BadRequest().body(e)),
    };
    let source = empty_to_none(q.source);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, VULN_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        image_vulnerabilities(
            &mut conn,
            &digest,
            source.as_deref(),
            severities.as_deref(),
            q.fixable,
            after,
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(page))
}

// ---------------------------------------------------------------------
// GET /images/{digest}/sbom (+ /cyclonedx)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SbomQuery {
    pub source: Option<String>,
    pub limit: Option<i64>,
    /// The `nextAfter` of the previous page (a component id).
    pub after: Option<i64>,
}

#[derive(Debug, Clone, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[diesel(sql_type = BigInt)]
    pub id: i64,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub purl: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(rename = "type")]
    pub comp_type: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub class: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub src_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub src_version: Option<String>,
    #[diesel(sql_type = Array<Text>)]
    pub licenses: Vec<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub layer_digest: Option<String>,
    #[diesel(sql_type = Array<Text>)]
    pub file_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomPage {
    pub digest: String,
    /// The SBOM used (one source): `null` = no SBOM for this image.
    pub report: Option<Report>,
    pub items: Vec<Component>,
    pub next_after: Option<i64>,
}

const COMPONENTS_SQL: &str = "\
SELECT id, name, version, purl, type AS comp_type, class, src_name, src_version, licenses, \
    layer_digest, file_paths \
FROM image_sbom_components WHERE digest = $1 AND source = $2 AND id > $3 \
ORDER BY id LIMIT $4";

fn load_components(
    conn: &mut PgConnection,
    report: &Report,
    after: i64,
    limit: i64,
) -> QueryResult<Vec<Component>> {
    sql_query(COMPONENTS_SQL)
        .bind::<Text, _>(&report.report_digest)
        .bind::<Text, _>(&report.source)
        .bind::<BigInt, _>(after)
        .bind::<BigInt, _>(limit)
        .load(conn)
}

/// The SBOM for `digest`: the best-joined one, or `source`'s.
fn pick_sbom(
    conn: &mut PgConnection,
    digest: &str,
    source: Option<&str>,
) -> QueryResult<Option<Report>> {
    let mut reports = resolve_reports(conn, digest, KIND_SBOM, source)?;
    // One SBOM per answer: best join, then the preferred source
    // (registry-attached over Trivy Operator), then newest scan.
    reports.sort_by(|a, b| {
        join_rank(&a.join)
            .cmp(&join_rank(&b.join))
            .then(sbom_source_rank(&a.source).cmp(&sbom_source_rank(&b.source)))
            .then(b.scanned_at.cmp(&a.scanned_at))
    });
    Ok(reports.into_iter().next())
}

/// SBOM source preference (supplychain README): registry > trivy-operator
/// > anything else.
fn sbom_source_rank(s: &str) -> u8 {
    match s {
        "registry" => 0,
        "trivy-operator" => 1,
        _ => 2,
    }
}

fn join_rank(j: &str) -> u8 {
    match j {
        "image_id" => 1,
        "platform_manifest" => 2,
        "workload_tag" => 3,
        _ => 4,
    }
}

pub fn image_sbom(
    conn: &mut PgConnection,
    digest: &str,
    source: Option<&str>,
    after: i64,
    limit: i64,
) -> Result<SbomPage, DbError> {
    let Some(report) = pick_sbom(conn, digest, source)? else {
        return Ok(SbomPage {
            digest: digest.to_string(),
            report: None,
            items: Vec::new(),
            next_after: None,
        });
    };
    let mut items = load_components(conn, &report, after, limit + 1)?;
    let next_after = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(|c| c.id)
    } else {
        None
    };
    Ok(SbomPage {
        digest: digest.to_string(),
        report: Some(report),
        items,
        next_after,
    })
}

pub async fn get_image_sbom(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<SbomQuery>,
) -> actix_web::Result<HttpResponse> {
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(bad_digest());
    }
    let q = query.into_inner();
    let limit = clamp_limit(q.limit);
    let after = q.after.unwrap_or(0).max(0);
    let source = empty_to_none(q.source);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, COMPONENT_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        image_sbom(&mut conn, &digest, source.as_deref(), after, limit)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(page))
}

/// Largest SBOM exported as one CycloneDX document: the ingest cap, so
/// every stored SBOM can be exported.
pub const EXPORT_MAX_COMPONENTS: i64 = crate::supplychain::MAX_SBOM_COMPONENTS as i64;
/// Rows fetched per statement while building an export.
const EXPORT_CHUNK: i64 = 5_000;

/// CycloneDX 1.5 JSON from stored components. Deterministic for a given
/// SBOM (no serial number or timestamp), so exports diff cleanly.
pub fn cyclonedx_document(digest: &str, report: &Report, comps: &[Component]) -> serde_json::Value {
    use serde_json::json;
    let components: Vec<serde_json::Value> = comps
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut o = serde_json::Map::new();
            o.insert("bom-ref".into(), json!(format!("c{i}")));
            o.insert(
                "type".into(),
                json!(if c.comp_type.as_deref() == Some("operating-system") {
                    "operating-system"
                } else {
                    "library"
                }),
            );
            o.insert("name".into(), json!(c.name));
            if let Some(v) = &c.version {
                o.insert("version".into(), json!(v));
            }
            if let Some(p) = &c.purl {
                o.insert("purl".into(), json!(p));
            }
            if !c.licenses.is_empty() {
                o.insert(
                    "licenses".into(),
                    json!(c
                        .licenses
                        .iter()
                        .map(|l| json!({"license": {"name": l}}))
                        .collect::<Vec<_>>()),
                );
            }
            let mut props = Vec::new();
            for (k, v) in [
                ("aquasecurity:trivy:PkgType", &c.comp_type),
                ("aquasecurity:trivy:Class", &c.class),
                ("aquasecurity:trivy:SrcName", &c.src_name),
                ("aquasecurity:trivy:SrcVersion", &c.src_version),
                ("aquasecurity:trivy:LayerDigest", &c.layer_digest),
            ] {
                if let Some(v) = v {
                    props.push(json!({"name": k, "value": v}));
                }
            }
            if !props.is_empty() {
                o.insert("properties".into(), json!(props));
            }
            serde_json::Value::Object(o)
        })
        .collect();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {"components": [{
                "type": "application",
                "name": report.scanner_name.clone().unwrap_or_else(|| report.source.clone()),
                "version": report.scanner_version,
            }]},
            "component": {
                "type": "container",
                "bom-ref": digest,
                "name": report.image_ref.clone().unwrap_or_else(|| digest.to_string()),
                "version": digest,
            },
            "properties": [
                {"name": "kguardian:source", "value": report.source},
                {"name": "kguardian:reportDigest", "value": report.report_digest},
                {"name": "kguardian:join", "value": report.join},
                {"name": "kguardian:scannedAt", "value": report.scanned_at.and_utc().to_rfc3339()},
            ],
        },
        "components": components,
    })
}

enum Export {
    None,
    TooLarge(i32),
    Doc(serde_json::Value),
}

pub async fn get_image_sbom_cyclonedx(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<SbomQuery>,
) -> actix_web::Result<HttpResponse> {
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(bad_digest());
    }
    let source = empty_to_none(query.into_inner().source);
    // The size is known only from the stored header, so this one indexed
    // primary-key read happens before the charge; the charge then covers
    // exactly the document being built.
    let p = pool.clone();
    let (d2, s2) = (digest.clone(), source.clone());
    let report = web::block(move || -> Result<Option<Report>, DbError> {
        let mut conn = p.get()?;
        Ok(pick_sbom(&mut conn, &d2, s2.as_deref())?)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some(report) = report else {
        return Ok(HttpResponse::NotFound().body("No SBOM for this image"));
    };
    let _permit = match budget
        .acquire(cost_kib(
            i64::from(report.item_count).max(1),
            EXPORT_COMPONENT_COST_BYTES,
        ))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let d3 = digest.clone();
    let out = web::block(move || -> Result<Export, DbError> {
        if i64::from(report.item_count) > EXPORT_MAX_COMPONENTS {
            return Ok(Export::TooLarge(report.item_count));
        }
        let mut conn = pool.get()?;
        let mut comps = Vec::with_capacity(report.item_count.max(0) as usize);
        let mut after = 0;
        loop {
            let chunk = load_components(&mut conn, &report, after, EXPORT_CHUNK)?;
            let n = chunk.len() as i64;
            if let Some(last) = chunk.last() {
                after = last.id;
            }
            comps.extend(chunk);
            if n < EXPORT_CHUNK || comps.len() as i64 > EXPORT_MAX_COMPONENTS {
                break;
            }
        }
        if comps.is_empty() && report.item_count > 0 {
            return Ok(Export::None);
        }
        Ok(Export::Doc(cyclonedx_document(&d3, &report, &comps)))
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match out {
        Export::None => HttpResponse::NotFound().body("No SBOM for this image"),
        Export::TooLarge(n) => HttpResponse::PayloadTooLarge().body(format!(
            "SBOM has {n} components; page it with GET /images/{{digest}}/sbom"
        )),
        Export::Doc(doc) => HttpResponse::Ok()
            .content_type("application/vnd.cyclonedx+json; version=1.5")
            .insert_header((
                "Content-Disposition",
                format!(
                    "attachment; filename=\"{}.cdx.json\"",
                    digest.replace(':', "_")
                ),
            ))
            .json(doc),
    })
}

// ---------------------------------------------------------------------
// GET /vulnerabilities (cluster-wide, grouped by CVE)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VulnsQuery {
    pub severity: Option<String>,
    pub fixable: Option<bool>,
    /// Only workloads (and so CVEs) in this namespace.
    pub namespace: Option<String>,
    /// true: only CVEs with at least one running workload.
    pub running: Option<bool>,
    pub limit: Option<i64>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveSummary {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub severity: String,
    #[serde(skip)]
    #[diesel(sql_type = SmallInt)]
    pub severity_rank: i16,
    #[diesel(sql_type = Nullable<Float>)]
    pub max_score: Option<f32>,
    /// Some affected package has a fixed version.
    #[diesel(sql_type = Bool)]
    pub fixable: bool,
    /// Some source lists it in CISA KEV. `null` = no source says either
    /// way (unknown).
    #[diesel(sql_type = Nullable<Bool>)]
    pub kev: Option<bool>,
    #[diesel(sql_type = Nullable<Float>)]
    pub max_epss: Option<f32>,
    /// Up to five affected package names.
    #[diesel(sql_type = Array<Text>)]
    pub packages: Vec<String>,
    /// Inventory digests affected (in scope).
    #[diesel(sql_type = BigInt)]
    pub images: i64,
    /// Workloads running (or having run) an affected digest.
    #[diesel(sql_type = BigInt)]
    pub workloads: i64,
    #[diesel(sql_type = BigInt)]
    pub running_workloads: i64,
    #[diesel(sql_type = BigInt)]
    pub namespaces: i64,
    /// Weakest join among the matches: image_id / platform_manifest are
    /// exact; workload_tag means a tag match only.
    #[diesel(sql_type = Text)]
    pub weakest_join: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveItem {
    #[serde(flatten)]
    pub summary: CveSummary,
    pub in_use: Option<bool>,
    pub in_use_state: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CvePage {
    pub items: Vec<CveItem>,
    pub next_after: Option<String>,
}

/// The effective vulnerability payload per (inventory digest, source):
/// best join, then newest scan.
const EFFECTIVE_CTE: &str = "\
eff AS ( \
    SELECT DISTINCT ON (l.image_digest, l.source) l.image_digest, l.digest, l.source, \
        l.join_kind, l.join_rank \
    FROM supplychain_image_links l \
    JOIN vuln_sources vs ON vs.digest = l.digest AND vs.source = l.source \
        AND vs.kind = 'vulnerabilities' \
    ORDER BY l.image_digest, l.source, l.join_rank, vs.scanned_at DESC \
)";

fn cves_sql() -> String {
    format!(
        "WITH {EFFECTIVE_CTE}, \
         hits AS ( \
            SELECT v.vuln_id, v.severity_rank, v.score, v.fixed_version, v.pkg_name, \
                v.kev, v.epss, e.image_digest, e.join_rank \
            FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
            WHERE ($1::smallint[] IS NULL OR v.severity_rank = ANY($1)) \
              AND ($2::bool IS NULL OR (v.fixed_version IS NOT NULL) = $2) \
         ), \
         agg AS ( \
            SELECT vuln_id, max(severity_rank) AS severity_rank, max(score) AS max_score, \
                bool_or(fixed_version IS NOT NULL) AS fixable, bool_or(kev) AS kev, \
                max(epss) AS max_epss, \
                (array_agg(DISTINCT pkg_name))[1:5] AS packages, \
                max(join_rank) AS weakest \
            FROM hits GROUP BY vuln_id \
         ), \
         wl AS ( \
            SELECT h.vuln_id, count(DISTINCT h.image_digest) AS images, \
                count(DISTINCT wc.cluster_id || '/' || wc.pod_namespace || '/' || \
                    wc.workload_kind || '/' || wc.workload_name) AS workloads, \
                count(DISTINCT wc.cluster_id || '/' || wc.pod_namespace || '/' || \
                    wc.workload_kind || '/' || wc.workload_name) FILTER (WHERE {running}) \
                    AS running_workloads, \
                count(DISTINCT wc.pod_namespace) AS namespaces \
            FROM (SELECT DISTINCT vuln_id, image_digest FROM hits) h \
            JOIN workload_containers wc ON wc.image_digest = h.image_digest \
            WHERE ($3::text IS NULL OR wc.pod_namespace = $3) \
            GROUP BY h.vuln_id \
         ) \
         SELECT a.vuln_id AS id, \
            CASE a.severity_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH' WHEN 3 THEN 'MEDIUM' \
                WHEN 2 THEN 'LOW' WHEN 1 THEN 'NONE' ELSE 'UNKNOWN' END AS severity, \
            a.severity_rank, a.max_score, a.fixable, a.kev, a.max_epss, a.packages, w.images, \
            w.workloads, \
            w.running_workloads, w.namespaces, \
            CASE a.weakest WHEN 1 THEN 'image_id' WHEN 2 THEN 'platform_manifest' \
                ELSE 'workload_tag' END AS weakest_join \
         FROM agg a JOIN wl w ON w.vuln_id = a.vuln_id \
         WHERE ($4::bool IS NOT TRUE OR w.running_workloads > 0) \
           AND ($5::smallint IS NULL OR a.severity_rank < $5 \
                OR (a.severity_rank = $5 AND a.vuln_id > $6)) \
         ORDER BY a.severity_rank DESC, a.vuln_id \
         LIMIT $7",
        running = running_sql!("$8"),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn list_cves(
    conn: &mut PgConnection,
    severities: Option<&[i16]>,
    fixable: Option<bool>,
    namespace: Option<&str>,
    running_only: bool,
    after: Option<(i16, String)>,
    limit: i64,
) -> Result<CvePage, DbError> {
    let mut rows: Vec<CveSummary> = sql_query(cves_sql())
        .bind::<Nullable<Array<SmallInt>>, _>(severities)
        .bind::<Nullable<Bool>, _>(fixable)
        .bind::<Nullable<Text>, _>(namespace)
        .bind::<Bool, _>(running_only)
        .bind::<Nullable<SmallInt>, _>(after.as_ref().map(|a| a.0))
        .bind::<Text, _>(after.as_ref().map(|a| a.1.clone()).unwrap_or_default())
        .bind::<BigInt, _>(limit + 1)
        .bind::<Double, _>(running_window_secs() as f64)
        .load(conn)?;
    let next_after = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|r| format!("{}.{}", r.severity_rank, r.id))
    } else {
        None
    };
    Ok(CvePage {
        items: rows
            .into_iter()
            .map(|summary| CveItem {
                summary,
                in_use: None,
                in_use_state: IN_USE_UNKNOWN,
            })
            .collect(),
        next_after,
    })
}

#[get(
    "/vulnerabilities",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_vulnerabilities(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<VulnsQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let limit = clamp_limit(q.limit);
    let severities = match parse_severities(q.severity.as_deref()) {
        Ok(s) => s,
        Err(e) => return Ok(HttpResponse::BadRequest().body(e)),
    };
    let after = match parse_cursor(q.after.as_deref()) {
        Ok(a) => a,
        Err(e) => return Ok(HttpResponse::BadRequest().body(e)),
    };
    let namespace = empty_to_none(q.namespace);
    let _permit = match budget
        .acquire(cost_kib(limit + 1, CVE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        list_cves(
            &mut conn,
            severities.as_deref(),
            q.fixable,
            namespace.as_deref(),
            q.running.unwrap_or(false),
            after,
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(page))
}

// ---------------------------------------------------------------------
// GET /vulnerabilities/{id}/exposure
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ExposureQuery {
    /// How far back observed ingress counts, hours (default 168, max 720).
    pub window_hours: Option<i64>,
}

#[derive(Debug, Clone, QueryableByName)]
struct ExposedImageRow {
    #[diesel(sql_type = Text)]
    image_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    repository: Option<String>,
    #[diesel(sql_type = Array<Text>)]
    tags: Vec<String>,
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Text)]
    report_digest: String,
    #[diesel(sql_type = Text)]
    join_kind: String,
    #[diesel(sql_type = Jsonb)]
    packages: serde_json::Value,
    #[diesel(sql_type = SmallInt)]
    severity_rank: i16,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedImage {
    pub digest: String,
    pub repository: Option<String>,
    pub tags: Vec<String>,
    pub source: String,
    pub report_digest: String,
    pub join: String,
    pub severity: &'static str,
    /// `[{name, installedVersion, fixedVersion, severity}]`, capped.
    pub packages: serde_json::Value,
}

#[derive(Debug, Clone, QueryableByName)]
struct ExposedWorkloadRow {
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Text)]
    namespace: String,
    #[diesel(sql_type = Text)]
    workload_kind: String,
    #[diesel(sql_type = Text)]
    workload_name: String,
    #[diesel(sql_type = Text)]
    container_name: String,
    #[diesel(sql_type = Text)]
    image_digest: String,
    #[diesel(sql_type = Text)]
    join_kind: String,
    #[diesel(sql_type = Bool)]
    running: bool,
    #[diesel(sql_type = Timestamp)]
    last_seen: NaiveDateTime,
}

#[derive(Debug, Clone, QueryableByName)]
struct NetRow {
    #[diesel(sql_type = BigInt)]
    idx: i64,
    #[diesel(sql_type = BigInt)]
    pods: i64,
    #[diesel(sql_type = BigInt)]
    cross_namespace: i64,
    #[diesel(sql_type = BigInt)]
    from_nodes: i64,
    #[diesel(sql_type = Array<Text>)]
    unresolved_ips: Vec<String>,
    #[diesel(sql_type = BigInt)]
    unresolved: i64,
}

/// Observed network exposure of one workload. See the endpoint docs for
/// how it is computed; `exposed: null` means unknown.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkExposure {
    pub window_hours: i64,
    /// Pods of the workload the broker knows (live, or dead within its
    /// retention) whose traffic was examined.
    pub pods_observed: i64,
    /// Distinct pod/service peers in ANOTHER namespace that sent ingress.
    pub ingress_from_other_namespaces: i64,
    /// Distinct peer IPs the broker never attributed to a pod, service or
    /// node: external clients, or pods it could not identify.
    pub ingress_from_unattributed_peers: i64,
    /// Of those, public (internet-routable) addresses.
    pub ingress_from_public_ips: i64,
    /// Distinct node / host-network peers (kubelet probes land here; not
    /// counted towards `exposed`).
    pub ingress_from_nodes: i64,
    /// true: ingress from outside the namespace was observed. false: none
    /// observed in the window (not proof there is none). null: no pods to
    /// examine, so unknown.
    pub exposed: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedWorkload {
    pub cluster_id: String,
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub container: String,
    pub image_digest: String,
    pub join: String,
    pub running: bool,
    pub last_seen: NaiveDateTime,
    pub network: NetworkExposure,
    pub in_use: Option<bool>,
    pub in_use_state: &'static str,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceExposure {
    pub namespace: String,
    pub workloads: i64,
    pub running_workloads: i64,
    /// `exposed == true` workloads.
    pub exposed_workloads: i64,
    /// `exposed == null` workloads.
    pub unknown_exposure_workloads: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exposure {
    pub id: String,
    pub severity: &'static str,
    pub fixable: bool,
    pub images: Vec<ExposedImage>,
    pub workloads: Vec<ExposedWorkload>,
    pub namespaces: Vec<NamespaceExposure>,
    /// More images or workloads than listed.
    pub truncated: bool,
    pub in_use: Option<bool>,
    pub in_use_state: &'static str,
}

fn exposure_images_sql() -> String {
    format!(
        "WITH {EFFECTIVE_CTE} \
         SELECT e.image_digest, i.repository, i.tags, e.source, e.digest AS report_digest, \
            e.join_kind, max(v.severity_rank) AS severity_rank, \
            (jsonb_agg(jsonb_build_object('name', v.pkg_name, \
                'installedVersion', v.installed_version, 'fixedVersion', v.fixed_version, \
                'severity', v.severity) ORDER BY v.severity_rank DESC, v.id))  \
                AS packages \
         FROM eff e \
         JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
         JOIN images i ON i.digest = e.image_digest \
         WHERE v.vuln_id = $1 \
         GROUP BY e.image_digest, i.repository, i.tags, e.source, e.digest, e.join_kind \
         ORDER BY e.image_digest, e.source \
         LIMIT $2"
    )
}

fn exposure_workloads_sql() -> String {
    format!(
        "WITH {EFFECTIVE_CTE}, \
         hit AS ( \
            SELECT e.image_digest, min(e.join_rank) AS join_rank FROM eff e \
            WHERE EXISTS (SELECT 1 FROM image_vulnerabilities v \
                WHERE v.digest = e.digest AND v.source = e.source AND v.vuln_id = $1) \
            GROUP BY e.image_digest \
         ) \
         SELECT wc.cluster_id, wc.pod_namespace AS namespace, wc.workload_kind, \
            wc.workload_name, wc.container_name, wc.image_digest, \
            CASE h.join_rank WHEN 1 THEN 'image_id' WHEN 2 THEN 'platform_manifest' \
                ELSE 'workload_tag' END AS join_kind, \
            {running} AS running, wc.last_seen \
         FROM hit h JOIN workload_containers wc ON wc.image_digest = h.image_digest \
         ORDER BY running DESC, wc.pod_namespace, wc.workload_kind, wc.workload_name, \
            wc.container_name, wc.image_digest \
         LIMIT $2",
        running = running_sql!("$3"),
    )
}

/// Per workload (by position in the arrays): its pods known to the broker
/// and the ingress they received in the window, from `pod_traffic` with
/// the peer identity stamped at ingest (peer.rs).
const NETWORK_SQL: &str = "\
WITH w AS ( \
    SELECT * FROM unnest($1::text[], $2::text[], $3::text[]) WITH ORDINALITY AS w(ns, kind, name, idx) \
), pods AS ( \
    SELECT w.idx, p.pod_name, p.pod_namespace FROM w \
    CROSS JOIN LATERAL ( \
        SELECT pd.pod_name, pd.pod_namespace FROM pod_details pd \
        WHERE pd.pod_namespace = w.ns \
          AND ((pd.workload_kind = w.kind AND pd.workload_name = w.name) \
            OR (w.kind = 'Pod' AND pd.pod_name = w.name)) \
        ORDER BY pd.time_stamp DESC LIMIT $5 \
    ) p \
), ing AS ( \
    SELECT p.idx, p.pod_namespace, pt.peer_kind, pt.peer_namespace, \
        COALESCE(pt.peer_workload_name, pt.peer_name) AS peer, pt.traffic_in_out_ip \
    FROM pods p JOIN pod_traffic pt ON pt.pod_name = p.pod_name \
    WHERE upper(pt.traffic_type) = 'INGRESS' \
      AND pt.time_stamp >= timezone('UTC', NOW()) - make_interval(hours => $4) \
) \
SELECT w.idx, \
    (SELECT count(*) FROM pods WHERE pods.idx = w.idx) AS pods, \
    count(DISTINCT i.peer_namespace || '/' || i.peer) FILTER ( \
        WHERE i.peer_kind IN ('pod', 'service') \
          AND i.peer_namespace IS DISTINCT FROM i.pod_namespace) AS cross_namespace, \
    count(DISTINCT i.traffic_in_out_ip) FILTER (WHERE i.peer_kind = 'node') AS from_nodes, \
    COALESCE((array_agg(DISTINCT i.traffic_in_out_ip) \
        FILTER (WHERE i.peer_kind IS NULL AND i.traffic_in_out_ip IS NOT NULL))[1:$6], '{}') \
        AS unresolved_ips, \
    count(DISTINCT i.traffic_in_out_ip) FILTER (WHERE i.peer_kind IS NULL) AS unresolved \
FROM w LEFT JOIN ing i ON i.idx = w.idx \
GROUP BY w.idx ORDER BY w.idx";

fn network_from(row: Option<&NetRow>, window_hours: i64) -> NetworkExposure {
    let Some(r) = row else {
        return NetworkExposure {
            window_hours,
            pods_observed: 0,
            ingress_from_other_namespaces: 0,
            ingress_from_unattributed_peers: 0,
            ingress_from_public_ips: 0,
            ingress_from_nodes: 0,
            exposed: None,
        };
    };
    let public = r
        .unresolved_ips
        .iter()
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .filter(is_public_ip)
        .count() as i64;
    NetworkExposure {
        window_hours,
        pods_observed: r.pods,
        ingress_from_other_namespaces: r.cross_namespace,
        ingress_from_unattributed_peers: r.unresolved,
        ingress_from_public_ips: public,
        ingress_from_nodes: r.from_nodes,
        exposed: if r.pods == 0 {
            None
        } else {
            Some(r.cross_namespace > 0 || r.unresolved > 0)
        },
    }
}

fn summarise_namespaces(workloads: &[ExposedWorkload]) -> Vec<NamespaceExposure> {
    // Per namespace, count each workload once (it can list several
    // containers/digests); a workload is exposed if any row is.
    // (cluster, kind, name) -> (any row running, exposure so far)
    type PerWorkload<'a> = BTreeMap<(&'a str, &'a str, &'a str), (bool, Option<bool>)>;
    let mut by_ns: BTreeMap<&str, PerWorkload> = BTreeMap::new();
    for w in workloads {
        let e = by_ns
            .entry(&w.namespace)
            .or_default()
            .entry((&w.cluster_id, &w.kind, &w.name))
            .or_insert((false, Some(false)));
        e.0 |= w.running;
        e.1 = match (e.1, w.network.exposed) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (None, _) | (_, None) => None,
            _ => Some(false),
        };
    }
    by_ns
        .into_iter()
        .map(|(ns, wl)| NamespaceExposure {
            namespace: ns.to_string(),
            workloads: wl.len() as i64,
            running_workloads: wl.values().filter(|v| v.0).count() as i64,
            exposed_workloads: wl.values().filter(|v| v.1 == Some(true)).count() as i64,
            unknown_exposure_workloads: wl.values().filter(|v| v.1.is_none()).count() as i64,
        })
        .collect()
}

pub fn vulnerability_exposure(
    conn: &mut PgConnection,
    id: &str,
    window_hours: i64,
) -> Result<Option<Exposure>, DbError> {
    let mut images: Vec<ExposedImageRow> = sql_query(exposure_images_sql())
        .bind::<Text, _>(id)
        .bind::<BigInt, _>(EXPOSURE_MAX_IMAGES + 1)
        .load(conn)?;
    if images.is_empty() {
        return Ok(None);
    }
    let mut truncated = images.len() as i64 > EXPOSURE_MAX_IMAGES;
    images.truncate(EXPOSURE_MAX_IMAGES as usize);
    let mut rows: Vec<ExposedWorkloadRow> = sql_query(exposure_workloads_sql())
        .bind::<Text, _>(id)
        .bind::<BigInt, _>(EXPOSURE_MAX_WORKLOADS + 1)
        .bind::<Double, _>(running_window_secs() as f64)
        .load(conn)?;
    truncated |= rows.len() as i64 > EXPOSURE_MAX_WORKLOADS;
    rows.truncate(EXPOSURE_MAX_WORKLOADS as usize);

    // Network exposure per distinct workload.
    let mut keys: Vec<(String, String, String)> = rows
        .iter()
        .map(|r| {
            (
                r.namespace.clone(),
                r.workload_kind.clone(),
                r.workload_name.clone(),
            )
        })
        .collect();
    keys.sort();
    keys.dedup();
    let net: Vec<NetRow> = if keys.is_empty() {
        Vec::new()
    } else {
        sql_query(NETWORK_SQL)
            .bind::<Array<Text>, _>(keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>())
            .bind::<Array<Text>, _>(keys.iter().map(|k| k.1.as_str()).collect::<Vec<_>>())
            .bind::<Array<Text>, _>(keys.iter().map(|k| k.2.as_str()).collect::<Vec<_>>())
            .bind::<Integer, _>(window_hours as i32)
            .bind::<BigInt, _>(EXPOSURE_PODS_PER_WORKLOAD)
            .bind::<Integer, _>(EXPOSURE_PEERS_PER_WORKLOAD as i32)
            .load(conn)?
    };
    let net_for = |r: &ExposedWorkloadRow| {
        let pos = keys
            .iter()
            .position(|k| k.0 == r.namespace && k.1 == r.workload_kind && k.2 == r.workload_name);
        let row = pos.and_then(|p| net.iter().find(|n| n.idx == p as i64 + 1));
        network_from(row, window_hours)
    };
    let workloads: Vec<ExposedWorkload> = rows
        .iter()
        .map(|r| ExposedWorkload {
            network: net_for(r),
            cluster_id: r.cluster_id.clone(),
            namespace: r.namespace.clone(),
            kind: r.workload_kind.clone(),
            name: r.workload_name.clone(),
            container: r.container_name.clone(),
            image_digest: r.image_digest.clone(),
            join: r.join_kind.clone(),
            running: r.running,
            last_seen: r.last_seen,
            in_use: None,
            in_use_state: IN_USE_UNKNOWN,
        })
        .collect();

    let severity_rank = images.iter().map(|i| i.severity_rank).max().unwrap_or(0);
    let mut fixable = false;
    let images: Vec<ExposedImage> = images
        .into_iter()
        .map(|i| {
            let mut pkgs = match i.packages {
                serde_json::Value::Array(a) => a,
                _ => Vec::new(),
            };
            fixable |= pkgs.iter().any(|p| !p["fixedVersion"].is_null());
            if pkgs.len() as i64 > EXPOSURE_MAX_PACKAGES {
                pkgs.truncate(EXPOSURE_MAX_PACKAGES as usize);
                truncated = true;
            }
            ExposedImage {
                digest: i.image_digest,
                repository: i.repository,
                tags: i.tags,
                source: i.source,
                report_digest: i.report_digest,
                join: i.join_kind,
                severity: crate::supplychain::severity_from_rank(i.severity_rank),
                packages: serde_json::Value::Array(pkgs),
            }
        })
        .collect();
    Ok(Some(Exposure {
        id: id.to_string(),
        severity: crate::supplychain::severity_from_rank(severity_rank),
        fixable,
        namespaces: summarise_namespaces(&workloads),
        images,
        workloads,
        truncated,
        in_use: None,
        in_use_state: IN_USE_UNKNOWN,
    }))
}

fn valid_vuln_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

#[get(
    "/vulnerabilities/{id}/exposure",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_vulnerability_exposure(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<ExposureQuery>,
) -> actix_web::Result<impl Responder> {
    let id = path.into_inner();
    if !valid_vuln_id(&id) {
        return Ok(
            HttpResponse::BadRequest().body("id must be a vulnerability id such as CVE-2024-1234")
        );
    }
    let window_hours = query
        .window_hours
        .unwrap_or(EXPOSURE_DEFAULT_WINDOW_HOURS)
        .clamp(1, EXPOSURE_MAX_WINDOW_HOURS);
    let _permit = match budget.acquire(cost_kib(1, EXPOSURE_COST_BYTES)).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || {
        let mut conn = pool.get()?;
        vulnerability_exposure(&mut conn, &id, window_hours)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match out {
        Some(e) => HttpResponse::Ok().json(e),
        None => HttpResponse::NotFound().body("No affected image in the inventory"),
    })
}

// ---------------------------------------------------------------------
// Routing: one resource per path that carries both GET and POST, so the
// ingest body settings stay scoped to the ingest verb's resource.
// ---------------------------------------------------------------------

/// `/images/{digest}/vulnerabilities`: GET (read) + POST (supplychain).
pub fn image_vulnerabilities_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/images/{digest}/vulnerabilities")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        // The handler reads the raw body itself and enforces the
        // compressed and inflated caps; this bounds any extractor that
        // might be added later to the same compressed cap.
        .app_data(web::PayloadConfig::new(
            crate::supplychain::MAX_COMPRESSED_BYTES,
        ))
        .route(web::get().to(get_image_vulnerabilities))
        .route(web::post().to(crate::supplychain::post_image_vulnerabilities))
}

/// `/images/{digest}/sbom`: GET (read, paged components) + POST (supplychain).
pub fn image_sbom_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/images/{digest}/sbom")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(web::PayloadConfig::new(
            crate::supplychain::MAX_COMPRESSED_BYTES,
        ))
        .route(web::get().to(get_image_sbom))
        .route(web::post().to(crate::supplychain::post_image_sbom))
}

/// `/images/{digest}/sbom/cyclonedx`: the SBOM as one CycloneDX document.
pub fn image_sbom_cyclonedx_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/images/{digest}/sbom/cyclonedx")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .route(web::get().to(get_image_sbom_cyclonedx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_parse_and_reject_unknown_names() {
        assert_eq!(parse_severities(None).unwrap(), None);
        assert_eq!(parse_severities(Some(" ")).unwrap(), None);
        assert_eq!(
            parse_severities(Some("critical, HIGH,high")).unwrap(),
            Some(vec![5, 4])
        );
        assert_eq!(parse_severities(Some("unknown")).unwrap(), Some(vec![0]));
        assert!(parse_severities(Some("HIGH,severe")).is_err());
    }

    #[test]
    fn cursor_round_trips_and_rejects_garbage() {
        assert_eq!(parse_cursor(None).unwrap(), None);
        assert_eq!(
            parse_cursor(Some("4.CVE-2024-1.2")).unwrap(),
            Some((4, "CVE-2024-1.2".to_string()))
        );
        assert!(parse_cursor(Some("9.x")).is_err());
        assert!(parse_cursor(Some("x")).is_err());
        assert!(parse_cursor(Some("3.")).is_err());
    }

    #[test]
    fn limits_clamp() {
        assert_eq!(clamp_limit(None), VULNS_DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(10_000)), VULNS_MAX_LIMIT);
    }

    #[test]
    fn public_ip_classification() {
        for (ip, public) in [
            ("8.8.8.8", true),
            ("10.1.2.3", false),
            ("172.16.0.1", false),
            ("192.168.1.1", false),
            ("100.64.0.1", false),
            ("100.128.0.1", true),
            ("169.254.169.254", false),
            ("127.0.0.1", false),
            ("192.0.2.10", false),
            ("2606:4700::1111", true),
            ("fd00::1", false),
            ("fe80::1", false),
            ("::1", false),
            ("::ffff:10.0.0.1", false),
            ("::ffff:1.1.1.1", true),
            ("2001:db8::1", false),
        ] {
            assert_eq!(
                is_public_ip(&ip.parse().unwrap()),
                public,
                "{ip} public={public}"
            );
        }
    }

    #[test]
    fn network_exposure_unknown_is_never_false() {
        let n = network_from(None, 24);
        assert_eq!(n.exposed, None);
        let row = NetRow {
            idx: 1,
            pods: 0,
            cross_namespace: 0,
            from_nodes: 0,
            unresolved_ips: vec![],
            unresolved: 0,
        };
        assert_eq!(network_from(Some(&row), 24).exposed, None);
        let quiet = NetRow {
            pods: 2,
            from_nodes: 3,
            ..row.clone()
        };
        // Node-only ingress (kubelet probes) is not exposure.
        assert_eq!(network_from(Some(&quiet), 24).exposed, Some(false));
        let internet = NetRow {
            pods: 2,
            unresolved: 2,
            unresolved_ips: vec!["8.8.8.8".into(), "10.0.0.9".into()],
            ..row.clone()
        };
        let n = network_from(Some(&internet), 24);
        assert_eq!(n.exposed, Some(true));
        assert_eq!(n.ingress_from_public_ips, 1);
        let cross = NetRow {
            pods: 1,
            cross_namespace: 1,
            ..row
        };
        assert_eq!(network_from(Some(&cross), 24).exposed, Some(true));
    }

    #[test]
    fn vuln_ids_are_validated() {
        assert!(valid_vuln_id("CVE-2024-3094"));
        assert!(valid_vuln_id("GHSA-xxxx-yyyy-zzzz"));
        assert!(!valid_vuln_id(""));
        assert!(!valid_vuln_id("CVE 1"));
        assert!(!valid_vuln_id("../etc"));
    }
}
