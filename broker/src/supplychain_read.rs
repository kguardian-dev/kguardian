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

/// `in_use=executed,loaded` -> the states asked for. Unknown names are a
/// 400.
pub(crate) fn parse_in_use(raw: Option<&str>) -> Result<Option<Vec<String>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let p = part.to_ascii_lowercase();
        if !["executed", "loaded", "unknown", "installed_not_observed"].contains(&p.as_str()) {
            return Err(format!(
                "unknown in_use '{part}'; use executed, loaded, unknown or installed_not_observed"
            ));
        }
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(Some(out))
}

/// `tier=P0,P1` (or `background`) -> tier ranks.
pub(crate) fn parse_tiers(raw: Option<&str>) -> Result<Option<Vec<i16>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let r = match part.to_ascii_lowercase().as_str() {
            "p0" => 0,
            "p1" => 1,
            "p2" => 2,
            "background" => 3,
            _ => {
                return Err(format!(
                    "unknown tier '{part}'; use P0, P1, P2 or Background"
                ))
            }
        };
        if !out.contains(&r) {
            out.push(r);
        }
    }
    Ok(Some(out))
}

pub(crate) fn parse_epss_min(raw: Option<f64>) -> Result<Option<f64>, String> {
    match raw {
        None => Ok(None),
        Some(v) if v.is_finite() && (0.0..=1.0).contains(&v) => Ok(Some(v)),
        Some(_) => Err("epss_min must be between 0 and 1".into()),
    }
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
    /// Matcher findings: the SBOM source(s) that were matched.
    #[diesel(sql_type = Array<Text>)]
    pub sbom_sources: Vec<String>,
    /// `attached-unbound` | `unverified` | `scanned` | `verified`, weakest
    /// first. Only `verified` may be shown as signed. A registry SBOM is
    /// additive evidence, never a replacement for a scanner's.
    #[diesel(sql_type = Nullable<Text>)]
    pub sbom_trust: Option<String>,
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
    vs.received_at, vs.sbom_sources, vs.sbom_trust, vs.attestation \
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
    /// true: only KEV-listed; false: only findings a source says are NOT
    /// in KEV. Findings no source says either way are in neither.
    pub kev: Option<bool>,
    /// Only findings with EPSS at or above this (0-1); unknown EPSS is
    /// excluded.
    pub epss_min: Option<f64>,
    /// Comma-separated in-use states.
    pub in_use: Option<String>,
    /// Comma-separated tiers: P0, P1, P2, Background.
    pub tier: Option<String>,
    pub limit: Option<i64>,
    pub after: Option<String>,
}

/// Filters shared by the per-image and cluster-wide lists.
#[derive(Debug, Clone, Default)]
pub struct ListFilters {
    pub severities: Option<Vec<i16>>,
    pub fixable: Option<bool>,
    pub kev: Option<bool>,
    pub epss_min: Option<f64>,
    pub in_use: Option<Vec<String>>,
    pub tiers: Option<Vec<i16>>,
}

#[derive(Debug, Clone, QueryableByName)]
struct VulnDbRow {
    /// The lowest row id in the group: the page cursor.
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Array<Text>)]
    report_digests: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    sources: Vec<String>,
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
    #[diesel(sql_type = Array<Text>)]
    fixed_versions: Vec<String>,
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
    /// kg_pkg_in_use of the strongest container.
    #[diesel(sql_type = Text)]
    in_use_state: String,
    #[diesel(sql_type = SmallInt)]
    tier_rank: i16,
    /// The in-use state and exposure of the container that set the tier.
    #[diesel(sql_type = Text)]
    tier_state: String,
    #[diesel(sql_type = Nullable<Bool>)]
    tier_exposed: Option<bool>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    observed_since: Option<NaiveDateTime>,
    #[diesel(sql_type = BigInt)]
    containers: i64,
}

/// In-use of a finding, with its evidence window (P1-5).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InUseDetail {
    /// executed | loaded | installed_not_observed | unknown
    pub state: &'static str,
    /// Why it is unknown: no_runtime_data | capture_gap | host_network |
    /// language_package | no_package_files. `null` otherwise.
    pub reason: Option<&'static str>,
    /// Start of continuous capture coverage (the common window across the
    /// containers), when covered.
    pub observed_since: Option<NaiveDateTime>,
    /// Minimum window required before installed_not_observed is claimed.
    pub window_hours: i64,
    /// Workload containers the state was derived from.
    pub containers: i64,
    /// What exec/mmap capture can see for this package type: `file` (OS
    /// package), `static_binary` (Go/Rust module: the whole binary is
    /// credited when it runs), `interpreted` (npm/pip/jar/...: never seen,
    /// always unknown).
    pub coverage: &'static str,
}

impl InUseDetail {
    pub(crate) fn from_state(
        state: &str,
        observed_since: Option<NaiveDateTime>,
        containers: i64,
        coverage: crate::in_use::Coverage,
    ) -> Self {
        let (s, reason) = crate::in_use_store::parse_state(state);
        InUseDetail {
            state: s.as_str(),
            reason: reason.map(|r| r.as_str()),
            observed_since: if s == crate::in_use::InUse::Unknown {
                None
            } else {
                observed_since
            },
            window_hours: crate::in_use::TierSettings::from_env().min_window_hours,
            containers,
            coverage: coverage.as_str(),
        }
    }
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
    /// Every distinct fixed version the sources give, ordered by source.
    /// Empty = no source knows a fix. Not reduced to one: sources can
    /// disagree, and version order depends on the ecosystem.
    pub fixed_versions: Vec<String>,
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
    /// Every source that reported this (id, package, installed version).
    /// One finding, however many sources agree.
    pub sources: Vec<String>,
    pub report_digests: Vec<String>,
    /// true executed/loaded, false installed_not_observed (covered),
    /// `null` unknown. Unknown is never "safe".
    pub in_use: Option<bool>,
    pub in_use_state: &'static str,
    pub in_use_detail: InUseDetail,
    /// P0 | P1 | P2 | Background (team/04-ux.md section 3).
    pub tier: &'static str,
    /// The factors that produced the tier, for the chips.
    pub tier_factors: Vec<String>,
}

impl From<VulnDbRow> for Finding {
    fn from(r: VulnDbRow) -> Self {
        let detail = InUseDetail::from_state(
            &r.in_use_state,
            r.observed_since,
            r.containers,
            crate::in_use::coverage_of(r.pkg_type.as_deref(), r.class.as_deref()),
        );
        let (in_use, _) = crate::in_use_store::parse_state(&r.in_use_state);
        let (tier_in_use, _) = crate::in_use_store::parse_state(&r.tier_state);
        let fixable = !r.fixed_versions.is_empty();
        let factors = crate::in_use::tier_factors(
            &crate::in_use::TierInput {
                in_use: tier_in_use,
                severity_rank: r.severity_rank,
                kev: r.kev.unwrap_or(false),
                epss: r.epss.map(f64::from),
                exposed: r.tier_exposed,
                fixable,
            },
            &crate::in_use::TierSettings::from_env(),
        );
        Finding {
            id: r.vuln_id,
            package: PackageRef {
                name: r.pkg_name,
                pkg_type: r.pkg_type,
                purl: r.pkg_purl,
            },
            installed_version: r.installed_version,
            fixable: !r.fixed_versions.is_empty(),
            fixed_versions: r.fixed_versions,
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
            sources: r.sources,
            report_digests: r.report_digests,
            in_use: in_use.as_bool(),
            in_use_state: in_use.as_str(),
            in_use_detail: detail,
            tier: crate::in_use::Tier::from_rank(r.tier_rank).as_str(),
            tier_factors: factors,
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

/// Findings of the chosen report per source, deduplicated across sources
/// on (vulnerability id, package name, installed version): one row per
/// group listing the contributing sources. Descriptive fields come from
/// the group's first row; severity, score and EPSS are the highest any
/// source gives, `kev` is true if any source says so, and a fix from any
/// source makes it fixable. Fixed versions are NOT reduced to one: text
/// order is not version order ("10.1" < "9.2"), so every distinct fixed
/// version is returned, ordered by the first source that gives it.
const IMAGE_VULNS_SQL: &str = "\
WITH v AS ( \
    SELECT v.* FROM image_vulnerabilities v \
    JOIN unnest($1::text[], $2::text[]) AS k(digest, source) \
        ON v.digest = k.digest AND v.source = k.source \
), g AS ( \
    SELECT min(id) AS rep, vuln_id, pkg_name, installed_version, \
        max(severity_rank) AS severity_rank, max(score) AS score, \
        COALESCE((SELECT array_agg(f.fv ORDER BY f.first_source, f.fv) FROM ( \
            SELECT v2.fixed_version AS fv, min(v2.source) AS first_source FROM v v2 \
            WHERE v2.vuln_id = v.vuln_id AND v2.pkg_name = v.pkg_name \
              AND v2.installed_version = v.installed_version \
              AND v2.fixed_version IS NOT NULL \
            GROUP BY v2.fixed_version) f), '{}') AS fixed_versions, \
        bool_or(kev) AS kev, \
        min(kev_date_added) AS kev_date_added, max(epss) AS epss, \
        max(epss_percentile) AS epss_percentile, \
        array_agg(DISTINCT source ORDER BY source) AS sources, \
        array_agg(DISTINCT digest ORDER BY digest) AS report_digests, \
        bool_or(kg_pkg_observable(pkg_type, class)) AS obs \
    FROM v GROUP BY vuln_id, pkg_name, installed_version \
), c AS ( \
    SELECT wc.cluster_id, wc.pod_namespace, wc.workload_kind, wc.workload_name, \
        wc.container_name, wc.image_digest \
    FROM workload_containers wc WHERE wc.image_digest = $8 \
), s AS ( \
    SELECT g.*, \
        COALESCE(st.state, 'unknown:no_runtime_data') AS in_use_state, \
        COALESCE(st.tier, kg_vuln_tier('unknown', g.severity_rank, g.kev, g.epss, NULL, \
            cardinality(g.fixed_versions) > 0, $9, $10)) AS tier_rank, \
        COALESCE(st.tier_state, 'unknown:no_runtime_data') AS tier_state, \
        st.tier_exposed, st.observed_since, COALESCE(st.containers, 0) AS containers \
    FROM g LEFT JOIN LATERAL ( \
        SELECT (array_agg(x.st ORDER BY kg_in_use_rank(x.st)))[1] AS state, \
            min(x.tier) AS tier, \
            (array_agg(x.st ORDER BY x.tier, kg_in_use_rank(x.st)))[1] AS tier_state, \
            (array_agg(x.exposed ORDER BY x.tier, kg_in_use_rank(x.st)))[1] AS tier_exposed, \
            max(x.observed_since) FILTER (WHERE x.covered) AS observed_since, \
            count(*) AS containers \
        FROM ( \
            SELECT y.st, e.exposed, cv.covered IS TRUE AS covered, cv.observed_since, \
                kg_vuln_tier(split_part(y.st, ':', 1), g.severity_rank, g.kev, g.epss, \
                    e.exposed, cardinality(g.fixed_versions) > 0, $9, $10) AS tier \
            FROM c \
            CROSS JOIN LATERAL (SELECT kg_pkg_in_use(c.cluster_id, c.pod_namespace, \
                c.workload_kind, c.workload_name, c.container_name, c.image_digest, \
                g.pkg_name, g.obs) AS st) y \
            LEFT JOIN workload_network_exposure e ON e.cluster_id = c.cluster_id \
                AND e.pod_namespace = c.pod_namespace AND e.workload_kind = c.workload_kind \
                AND e.workload_name = c.workload_name \
            LEFT JOIN runtime_in_use_coverage cv ON cv.cluster_id = c.cluster_id \
                AND cv.pod_namespace = c.pod_namespace AND cv.workload_kind = c.workload_kind \
                AND cv.workload_name = c.workload_name AND cv.container_name = c.container_name \
                AND cv.image_digest = c.image_digest \
        ) x \
    ) st ON true \
) \
SELECT s.rep AS id, s.report_digests, s.sources, s.vuln_id, s.pkg_name, r.pkg_type, r.pkg_purl, \
    s.installed_version, s.fixed_versions, \
    CASE s.severity_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH' WHEN 3 THEN 'MEDIUM' \
        WHEN 2 THEN 'LOW' WHEN 1 THEN 'NONE' ELSE 'UNKNOWN' END AS severity, \
    s.severity_rank, s.score, r.cvss, r.title, r.primary_url, r.target, r.class, \
    r.published_at, r.last_modified_at, r.file_paths, s.kev, s.kev_date_added, s.epss, \
    s.epss_percentile, s.in_use_state, s.tier_rank, s.tier_state, s.tier_exposed, \
    s.observed_since, s.containers \
FROM s JOIN image_vulnerabilities r ON r.id = s.rep \
WHERE ($3::smallint[] IS NULL OR s.severity_rank = ANY($3)) \
  AND ($4::bool IS NULL OR (cardinality(s.fixed_versions) > 0) = $4) \
  AND ($5::smallint IS NULL OR s.severity_rank < $5 OR (s.severity_rank = $5 AND s.rep > $6)) \
  AND ($11::bool IS NULL OR s.kev = $11) \
  AND ($12::double precision IS NULL OR s.epss >= $12) \
  AND ($13::text[] IS NULL OR split_part(s.in_use_state, ':', 1) = ANY($13)) \
  AND ($14::smallint[] IS NULL OR s.tier_rank = ANY($14)) \
ORDER BY s.severity_rank DESC, s.rep \
LIMIT $7";

/// Test shorthand for the unfiltered-by-tier read.
#[cfg(test)]
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
    let f = ListFilters {
        severities: severities.map(|s| s.to_vec()),
        fixable,
        ..Default::default()
    };
    image_vulnerabilities_filtered(conn, digest, source, &f, after, limit)
}

pub fn image_vulnerabilities_filtered(
    conn: &mut PgConnection,
    digest: &str,
    source: Option<&str>,
    f: &ListFilters,
    after: Option<(i16, i64)>,
    limit: i64,
) -> Result<ImageVulnsPage, DbError> {
    let t = crate::in_use::TierSettings::from_env();
    let reports = resolve_reports(conn, digest, KIND_VULNERABILITIES, source)?;
    let digests: Vec<&str> = reports.iter().map(|r| r.report_digest.as_str()).collect();
    let sources: Vec<&str> = reports.iter().map(|r| r.source.as_str()).collect();
    let mut rows: Vec<VulnDbRow> = if reports.is_empty() {
        Vec::new()
    } else {
        sql_query(IMAGE_VULNS_SQL)
            .bind::<Array<Text>, _>(&digests)
            .bind::<Array<Text>, _>(&sources)
            .bind::<Nullable<Array<SmallInt>>, _>(f.severities.as_deref())
            .bind::<Nullable<Bool>, _>(f.fixable)
            .bind::<Nullable<SmallInt>, _>(after.map(|a| a.0))
            .bind::<BigInt, _>(after.map(|a| a.1).unwrap_or(0))
            .bind::<BigInt, _>(limit + 1)
            .bind::<Text, _>(digest)
            .bind::<Double, _>(t.epss_threshold)
            .bind::<Bool, _>(t.unknown_exposure_as_exposed)
            .bind::<Nullable<Bool>, _>(f.kev)
            .bind::<Nullable<Double>, _>(f.epss_min)
            .bind::<Nullable<Array<Text>>, _>(f.in_use.as_deref())
            .bind::<Nullable<Array<SmallInt>>, _>(f.tiers.as_deref())
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

fn list_filters(
    severities: Option<Vec<i16>>,
    fixable: Option<bool>,
    kev: Option<bool>,
    epss_min: Option<f64>,
    in_use: Option<&str>,
    tier: Option<&str>,
) -> Result<ListFilters, String> {
    Ok(ListFilters {
        severities,
        fixable,
        kev,
        epss_min: parse_epss_min(epss_min)?,
        in_use: parse_in_use(in_use)?,
        tiers: parse_tiers(tier)?,
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
    let filters = match list_filters(
        severities,
        q.fixable,
        q.kev,
        q.epss_min,
        q.in_use.as_deref(),
        q.tier.as_deref(),
    ) {
        Ok(f) => f,
        Err(e) => return Ok(HttpResponse::BadRequest().body(e)),
    };
    let _permit = match budget
        .acquire(cost_kib(limit + 1, VULN_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        image_vulnerabilities_filtered(
            &mut conn,
            &digest,
            source.as_deref(),
            &filters,
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
    /// Every source's SBOM for this image, each with its trust. They are
    /// kept side by side; one never replaces another.
    pub reports: Vec<Report>,
    /// The SBOM these items come from: `?source=`, else Trivy Operator's,
    /// else another scanner's, and a registry-attached one only when it is
    /// the only SBOM (or asked for). `null` = no SBOM for this image.
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

/// Every source's SBOM for `digest`, and the one to show: `source`'s,
/// else by source preference (a registry SBOM is unverified evidence and
/// never displaces a scanner's), then best join, then newest.
fn pick_sbom(
    conn: &mut PgConnection,
    digest: &str,
    source: Option<&str>,
) -> QueryResult<(Vec<Report>, Option<Report>)> {
    let mut reports = resolve_reports(conn, digest, KIND_SBOM, None)?;
    reports.sort_by(|a, b| {
        sbom_source_rank(&a.source)
            .cmp(&sbom_source_rank(&b.source))
            .then(join_rank(&a.join).cmp(&join_rank(&b.join)))
            .then(b.scanned_at.cmp(&a.scanned_at))
    });
    let chosen = match source {
        Some(src) => reports.iter().find(|r| r.source == src).cloned(),
        None => reports.first().cloned(),
    };
    Ok((reports, chosen))
}

/// Which SBOM to show by default: Trivy Operator's, then any other
/// scanner, registry-attached last.
fn sbom_source_rank(s: &str) -> u8 {
    match s {
        "trivy-operator" => 0,
        "registry" => 2,
        _ => 1,
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
    let (reports, chosen) = pick_sbom(conn, digest, source)?;
    let Some(report) = chosen else {
        return Ok(SbomPage {
            digest: digest.to_string(),
            reports,
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
        reports,
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
                {"name": "kguardian:sbomTrust", "value": report.sbom_trust.clone().unwrap_or_else(|| "n/a".into())},
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

/// Every component of `report`'s SBOM, in id order, read in chunks.
/// Stops past `max` (the caller checks the count first).
fn load_all_components(
    conn: &mut PgConnection,
    report: &Report,
    max: i64,
) -> QueryResult<Vec<Component>> {
    let mut comps = Vec::with_capacity(report.item_count.clamp(0, max as i32) as usize);
    let mut after = 0;
    loop {
        let chunk = load_components(conn, report, after, EXPORT_CHUNK)?;
        let n = chunk.len() as i64;
        if let Some(last) = chunk.last() {
            after = last.id;
        }
        comps.extend(chunk);
        if n < EXPORT_CHUNK || comps.len() as i64 > max {
            break;
        }
    }
    Ok(comps)
}

/// The SBOM of one inventory digest as a CycloneDX document, for callers
/// inside the broker (the workload export bundle).
#[derive(Debug)]
pub(crate) enum CycloneDx {
    /// No source has an SBOM for the digest: its contents are unknown.
    NoSbom,
    /// The chosen SBOM has more components than `max_components`.
    TooLarge(Report),
    Doc(serde_json::Value, Report),
}

/// The SBOM the per-image route would choose (Trivy Operator's first, a
/// registry SBOM only when it is the only one), as CycloneDX. Refuses
/// more than `max_components` without loading them.
pub(crate) fn cyclonedx_for(
    conn: &mut PgConnection,
    digest: &str,
    max_components: i64,
) -> Result<CycloneDx, DbError> {
    let Some(report) = pick_sbom(conn, digest, None)?.1 else {
        return Ok(CycloneDx::NoSbom);
    };
    if i64::from(report.item_count) > max_components {
        return Ok(CycloneDx::TooLarge(report));
    }
    let comps = load_all_components(conn, &report, max_components)?;
    if comps.is_empty() && report.item_count > 0 {
        return Ok(CycloneDx::NoSbom);
    }
    if comps.len() as i64 > max_components {
        return Ok(CycloneDx::TooLarge(report));
    }
    Ok(CycloneDx::Doc(
        cyclonedx_document(digest, &report, &comps),
        report,
    ))
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
        Ok(pick_sbom(&mut conn, &d2, s2.as_deref())?.1)
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
        let comps = load_all_components(&mut conn, &report, EXPORT_MAX_COMPONENTS)?;
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
    /// true: only KEV-listed; false: only CVEs a source says are not.
    pub kev: Option<bool>,
    /// Only CVEs whose highest EPSS is at or above this (0-1).
    pub epss_min: Option<f64>,
    /// Comma-separated in-use states (strongest over the workloads).
    pub in_use: Option<String>,
    /// Comma-separated tiers: P0, P1, P2, Background.
    pub tier: Option<String>,
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
    /// Sources reporting it. Counts below are per image and workload, so
    /// two sources agreeing never count twice.
    #[diesel(sql_type = Array<Text>)]
    pub sources: Vec<String>,
    /// Inventory digests affected (in scope: the cluster, or the
    /// namespace asked for).
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
    /// P0 | P1 | P2 | Background: the most urgent tier over every
    /// affected workload container in scope.
    #[diesel(sql_type = Text)]
    pub tier: String,
    /// Strongest in-use state over the affected workloads in scope.
    #[serde(skip)]
    #[diesel(sql_type = Text)]
    pub in_use_raw: String,
    /// Workloads by in-use state of the affected package(s), and those
    /// with observed exposure.
    #[diesel(sql_type = BigInt)]
    pub executed_workloads: i64,
    #[diesel(sql_type = BigInt)]
    pub loaded_workloads: i64,
    #[diesel(sql_type = BigInt)]
    pub unknown_workloads: i64,
    #[diesel(sql_type = BigInt)]
    pub not_observed_workloads: i64,
    #[diesel(sql_type = BigInt)]
    pub exposed_workloads: i64,
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
    /// When the summary these rows come from was last rebuilt (the
    /// retention pass does it, every `SUPPLYCHAIN_RETENTION_INTERVAL_SECS`).
    /// `null` = not built yet since the broker started on this database.
    pub computed_at: Option<NaiveDateTime>,
    /// Seconds since `computedAt`.
    pub stale_seconds: Option<i64>,
}

/// The effective vulnerability payload per (inventory digest, source):
/// best join, then newest scan. `{filter}` narrows the links considered
/// (by image digest) before the choice is made.
fn effective_cte(filter: &str) -> String {
    format!(
        "eff AS ( \
            SELECT DISTINCT ON (l.image_digest, l.source) l.image_digest, l.digest, l.source, \
                l.join_kind, l.join_rank \
            FROM supplychain_image_links l \
            JOIN vuln_sources vs ON vs.digest = l.digest AND vs.source = l.source \
                AND vs.kind = 'vulnerabilities' \
            WHERE {filter} \
            ORDER BY l.image_digest, l.source, l.join_rank, vs.scanned_at DESC \
        )"
    )
}

/// Only images some payload holding `$1` (a vuln id) links to. The choice
/// of payload per image still considers every link of those images.
const FOR_VULN: &str = "l.image_digest IN (SELECT l2.image_digest FROM supplychain_image_links l2 \
    JOIN image_vulnerabilities v2 ON v2.digest = l2.digest AND v2.source = l2.source \
    WHERE v2.vuln_id = $1)";

/// Rebuild `vuln_cve_summary`: one row per CVE cluster-wide
/// (`scope_namespace = ''`) and one per (namespace, CVE), from the
/// effective payload per image and the workloads running each image.
/// Run by the retention loop, so `GET /vulnerabilities` is an indexed
/// read however many findings there are.
fn refresh_cve_summary_sql() -> String {
    format!(
        "WITH {eff}, \
         hp AS ( \
            SELECT v.vuln_id, e.image_digest, v.pkg_name, max(v.severity_rank) AS sr, \
                max(v.score) AS sc, bool_or(v.fixed_version IS NOT NULL) AS fx, \
                bool_or(v.kev) AS kev, max(v.epss) AS ep, max(e.join_rank) AS jr, \
                bool_or(kg_pkg_observable(v.pkg_type, v.class)) AS obs \
            FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
            GROUP BY v.vuln_id, e.image_digest, v.pkg_name \
         ), \
         pk AS ( \
            SELECT v.vuln_id, (array_agg(DISTINCT v.pkg_name ORDER BY v.pkg_name))[1:5] AS packages, \
                array_agg(DISTINCT v.source ORDER BY v.source) AS sources \
            FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
            GROUP BY v.vuln_id \
         ), \
         iu AS ( \
            SELECT p.image_digest, p.pkg_name, wc.cluster_id, wc.pod_namespace, \
                wc.workload_kind, wc.workload_name, wc.container_name, \
                kg_in_use_rank(kg_pkg_in_use(wc.cluster_id, wc.pod_namespace, wc.workload_kind, \
                    wc.workload_name, wc.container_name, wc.image_digest, p.pkg_name, p.obs)) AS iur \
            FROM (SELECT image_digest, pkg_name, bool_or(obs) AS obs FROM hp \
                  GROUP BY image_digest, pkg_name) p \
            JOIN workload_containers wc ON wc.image_digest = p.image_digest \
         ), \
         b AS ( \
            SELECT hp.vuln_id, hp.image_digest, wc.cluster_id, wc.pod_namespace AS ns, \
                wc.workload_kind, wc.workload_name, wc.container_name, \
                bool_or({running}) AS running, max(hp.sr) AS sr, max(hp.sc) AS sc, \
                bool_or(hp.fx) AS fx, bool_or(hp.kev) AS kev, max(hp.ep) AS ep, \
                max(hp.jr) AS jr, min(iu.iur) AS iur \
            FROM hp JOIN workload_containers wc ON wc.image_digest = hp.image_digest \
            JOIN iu ON iu.image_digest = hp.image_digest AND iu.pkg_name = hp.pkg_name \
                AND iu.cluster_id = wc.cluster_id AND iu.pod_namespace = wc.pod_namespace \
                AND iu.workload_kind = wc.workload_kind AND iu.workload_name = wc.workload_name \
                AND iu.container_name = wc.container_name \
            GROUP BY hp.vuln_id, hp.image_digest, wc.cluster_id, wc.pod_namespace, \
                wc.workload_kind, wc.workload_name, wc.container_name \
         ), \
         bt AS ( \
            SELECT b.*, \
                b.cluster_id || '/' || b.ns || '/' || b.workload_kind || '/' || b.workload_name AS wl, \
                x.exposed, \
                kg_vuln_tier(CASE b.iur WHEN 0 THEN 'executed' WHEN 1 THEN 'loaded' \
                    WHEN 3 THEN 'installed_not_observed' ELSE 'unknown' END, \
                    b.sr, b.kev, b.ep, x.exposed, b.fx, $2, $3) AS tier \
            FROM b LEFT JOIN workload_network_exposure x ON x.cluster_id = b.cluster_id \
                AND x.pod_namespace = b.ns AND x.workload_kind = b.workload_kind \
                AND x.workload_name = b.workload_name \
         ), \
         w AS ( \
            SELECT vuln_id, ns, wl, min(iur) AS iur, min(tier) AS tier, bool_or(running) AS running, \
                bool_or(exposed IS TRUE) AS exposed \
            FROM bt GROUP BY vuln_id, ns, wl \
         ), \
         ai AS ( \
            SELECT COALESCE(ns, '') AS scope, vuln_id, max(sr) AS sr, max(sc) AS sc, \
                bool_or(fx) AS fx, bool_or(kev) AS kev, max(ep) AS ep, max(jr) AS jr, \
                count(DISTINCT image_digest) AS images \
            FROM bt GROUP BY GROUPING SETS ((vuln_id), (vuln_id, ns)) \
         ), \
         aw AS ( \
            SELECT COALESCE(ns, '') AS scope, vuln_id, count(DISTINCT wl) AS workloads, \
                count(DISTINCT wl) FILTER (WHERE running) AS running_workloads, \
                count(DISTINCT ns) AS namespaces, min(tier) AS tier, min(iur) AS iur, \
                count(DISTINCT wl) FILTER (WHERE iur = 0) AS executed, \
                count(DISTINCT wl) FILTER (WHERE iur = 1) AS loaded, \
                count(DISTINCT wl) FILTER (WHERE iur = 2) AS unknown, \
                count(DISTINCT wl) FILTER (WHERE iur = 3) AS not_observed, \
                count(DISTINCT wl) FILTER (WHERE exposed) AS exposed \
            FROM w GROUP BY GROUPING SETS ((vuln_id), (vuln_id, ns)) \
         ) \
         INSERT INTO vuln_cve_summary (scope_namespace, vuln_id, severity_rank, max_score, \
            fixable, kev, max_epss, packages, sources, images, workloads, running_workloads, \
            namespaces, weakest_rank, tier, in_use, executed_workloads, loaded_workloads, \
            unknown_workloads, not_observed_workloads, exposed_workloads) \
         SELECT ai.scope, ai.vuln_id, ai.sr, ai.sc, ai.fx, ai.kev, ai.ep, \
            COALESCE(pk.packages, '{{}}'), COALESCE(pk.sources, '{{}}'), ai.images, \
            aw.workloads, aw.running_workloads, aw.namespaces, ai.jr, aw.tier, \
            CASE aw.iur WHEN 0 THEN 'executed' WHEN 1 THEN 'loaded' \
                WHEN 3 THEN 'installed_not_observed' ELSE 'unknown' END, \
            aw.executed, aw.loaded, aw.unknown, aw.not_observed, aw.exposed \
         FROM ai JOIN aw ON aw.scope = ai.scope AND aw.vuln_id = ai.vuln_id \
         JOIN pk ON pk.vuln_id = ai.vuln_id",
        eff = effective_cte("true"),
        running = running_sql!("$1"),
    )
}

/// Rebuild the CVE summary in one transaction (readers see the old or the
/// new table, never half). Returns the cluster-wide CVE count.
pub fn refresh_cve_summary(conn: &mut PgConnection) -> QueryResult<i64> {
    conn.transaction(|conn| {
        sql_query("DELETE FROM vuln_cve_summary").execute(conn)?;
        let t = crate::in_use::TierSettings::from_env();
        sql_query(refresh_cve_summary_sql())
            .bind::<Double, _>(running_window_secs() as f64)
            .bind::<Double, _>(t.epss_threshold)
            .bind::<Bool, _>(t.unknown_exposure_as_exposed)
            .execute(conn)?;
        #[derive(QueryableByName)]
        struct N {
            #[diesel(sql_type = BigInt)]
            n: i64,
        }
        let n = sql_query(
            "INSERT INTO vuln_cve_summary_state (id, refreshed_at, cves) \
             SELECT 1, timezone('UTC', NOW()), count(*) FROM vuln_cve_summary \
                 WHERE scope_namespace = '' \
             ON CONFLICT (id) DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at, \
                 cves = EXCLUDED.cves \
             RETURNING cves AS n",
        )
        .get_result::<N>(conn)?
        .n;
        Ok(n)
    })
}

const CVES_SQL: &str = "\
SELECT vuln_id AS id, \
    CASE severity_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH' WHEN 3 THEN 'MEDIUM' \
        WHEN 2 THEN 'LOW' WHEN 1 THEN 'NONE' ELSE 'UNKNOWN' END AS severity, \
    severity_rank, max_score, fixable, kev, max_epss, packages, sources, images, workloads, \
    running_workloads, namespaces, \
    CASE weakest_rank WHEN 1 THEN 'image_id' WHEN 2 THEN 'platform_manifest' \
        ELSE 'workload_tag' END AS weakest_join, \
    CASE tier WHEN 0 THEN 'P0' WHEN 1 THEN 'P1' WHEN 2 THEN 'P2' ELSE 'Background' END AS tier, \
    in_use AS in_use_raw, executed_workloads, loaded_workloads, \
    unknown_workloads, not_observed_workloads, exposed_workloads \
FROM vuln_cve_summary \
WHERE scope_namespace = COALESCE($3, '') \
  AND ($8::bool IS NULL OR kev = $8) \
  AND ($9::double precision IS NULL OR max_epss >= $9) \
  AND ($10::text[] IS NULL OR in_use = ANY($10)) \
  AND ($11::smallint[] IS NULL OR tier = ANY($11)) \
  AND ($1::smallint[] IS NULL OR severity_rank = ANY($1)) \
  AND ($2::bool IS NULL OR fixable = $2) \
  AND ($4::bool IS NOT TRUE OR running_workloads > 0) \
  AND ($5::smallint IS NULL OR severity_rank < $5 OR (severity_rank = $5 AND vuln_id > $6)) \
ORDER BY severity_rank DESC, vuln_id \
LIMIT $7";

#[derive(QueryableByName)]
struct SummaryState {
    #[diesel(sql_type = Timestamp)]
    refreshed_at: NaiveDateTime,
    #[diesel(sql_type = BigInt)]
    age: i64,
}

/// Test shorthand for the unfiltered-by-tier read.
#[cfg(test)]
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
    let f = ListFilters {
        severities: severities.map(|s| s.to_vec()),
        fixable,
        ..Default::default()
    };
    list_cves_filtered(conn, &f, namespace, running_only, after, limit)
}

pub fn list_cves_filtered(
    conn: &mut PgConnection,
    f: &ListFilters,
    namespace: Option<&str>,
    running_only: bool,
    after: Option<(i16, String)>,
    limit: i64,
) -> Result<CvePage, DbError> {
    let mut rows: Vec<CveSummary> = sql_query(CVES_SQL)
        .bind::<Nullable<Array<SmallInt>>, _>(f.severities.as_deref())
        .bind::<Nullable<Bool>, _>(f.fixable)
        .bind::<Nullable<Text>, _>(namespace)
        .bind::<Bool, _>(running_only)
        .bind::<Nullable<SmallInt>, _>(after.as_ref().map(|a| a.0))
        .bind::<Text, _>(after.as_ref().map(|a| a.1.clone()).unwrap_or_default())
        .bind::<BigInt, _>(limit + 1)
        .bind::<Nullable<Bool>, _>(f.kev)
        .bind::<Nullable<Double>, _>(f.epss_min)
        .bind::<Nullable<Array<Text>>, _>(f.in_use.as_deref())
        .bind::<Nullable<Array<SmallInt>>, _>(f.tiers.as_deref())
        .load(conn)?;
    let state: Option<SummaryState> = sql_query(
        "SELECT refreshed_at, \
             EXTRACT(EPOCH FROM timezone('UTC', NOW()) - refreshed_at)::bigint AS age \
         FROM vuln_cve_summary_state WHERE id = 1",
    )
    .get_result(conn)
    .optional()?;
    let next_after = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|r| format!("{}.{}", r.severity_rank, r.id))
    } else {
        None
    };
    Ok(CvePage {
        items: rows
            .into_iter()
            .map(|summary| {
                let (u, _) = crate::in_use_store::parse_state(&summary.in_use_raw);
                CveItem {
                    summary,
                    in_use: u.as_bool(),
                    in_use_state: u.as_str(),
                }
            })
            .collect(),
        next_after,
        computed_at: state.as_ref().map(|s| s.refreshed_at),
        stale_seconds: state.map(|s| s.age.max(0)),
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
    let filters = match list_filters(
        severities,
        q.fixable,
        q.kev,
        q.epss_min,
        q.in_use.as_deref(),
        q.tier.as_deref(),
    ) {
        Ok(f) => f,
        Err(e) => return Ok(HttpResponse::BadRequest().body(e)),
    };
    let _permit = match budget
        .acquire(cost_kib(limit + 1, CVE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        list_cves_filtered(
            &mut conn,
            &filters,
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
    #[diesel(sql_type = Array<Text>)]
    sources: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    report_digests: Vec<String>,
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
    /// Sources reporting the CVE for this image; one entry per image.
    pub sources: Vec<String>,
    pub report_digests: Vec<String>,
    /// Best join among them.
    pub join: String,
    pub severity: &'static str,
    /// `[{name, installedVersion, fixedVersions, severity, sources}]`,
    /// deduplicated across sources on (name, installed version), capped.
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
    /// kg_in_use_rank of the strongest affected package in this container.
    #[diesel(sql_type = SmallInt)]
    in_use_rank: i16,
}

#[derive(Debug, Clone, QueryableByName)]
struct NetRow {
    #[diesel(sql_type = BigInt)]
    idx: i64,
    #[diesel(sql_type = BigInt)]
    pods: i64,
    #[diesel(sql_type = BigInt)]
    flows: i64,
    #[diesel(sql_type = BigInt)]
    ingress_flows: i64,
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
    /// Flows (either direction) those pods had in the window.
    pub flows_observed: i64,
    /// Of those, INGRESS flows: the evidence `exposed` rests on. Egress
    /// alone is not: the controller does not capture inbound UDP, so a
    /// UDP-only server can show outbound flows and no ingress.
    pub ingress_flows_observed: i64,
    /// Distinct pod/service peers in ANOTHER namespace that sent ingress.
    pub ingress_from_other_namespaces: i64,
    /// Distinct peer IPs the broker never attributed to a pod, service or
    /// node: external clients, or pods it could not identify.
    pub ingress_from_unattributed_peers: i64,
    /// Of those, public (internet-routable) addresses.
    pub ingress_from_public_ips: i64,
    /// Distinct node / host-network peers. A NodePort or LoadBalancer
    /// Service with `externalTrafficPolicy: Cluster` SNATs outside clients
    /// to a node IP, so this counts as possible exposure (kubelet probes
    /// land here too; the broker cannot tell them apart).
    pub ingress_from_nodes: i64,
    /// true: ingress from outside the namespace, an unattributed peer or a
    /// node was observed; `exposedVia` says which. false: INGRESS flows
    /// were observed in the window and none came from outside. null:
    /// unknown (no pods, or no ingress flows captured in the window, even
    /// if there was egress). Never read false as "cannot be reached".
    pub exposed: Option<bool>,
    /// Why `exposed` is true: any of `other_namespace`, `unattributed`,
    /// `public_ip`, `node`.
    pub exposed_via: Vec<&'static str>,
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
        "WITH {eff}, \
         x AS ( \
            SELECT e.image_digest, e.source, e.digest, e.join_rank, v.pkg_name, \
                v.installed_version, v.fixed_version, v.severity_rank \
            FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
            WHERE v.vuln_id = $1 \
         ), \
         pk AS ( \
            SELECT image_digest, pkg_name, installed_version, \
                COALESCE((SELECT array_agg(f.fv ORDER BY f.first_source, f.fv) FROM ( \
            SELECT x2.fixed_version AS fv, min(x2.source) AS first_source FROM x x2 \
            WHERE x2.image_digest = x.image_digest AND x2.pkg_name = x.pkg_name \
              AND x2.installed_version = x.installed_version \
              AND x2.fixed_version IS NOT NULL \
            GROUP BY x2.fixed_version) f), '{{}}') AS fvs, \
                max(severity_rank) AS sr, array_agg(DISTINCT source ORDER BY source) AS srcs \
            FROM x GROUP BY image_digest, pkg_name, installed_version \
         ), \
         img AS ( \
            SELECT image_digest, array_agg(DISTINCT source ORDER BY source) AS sources, \
                array_agg(DISTINCT digest ORDER BY digest) AS report_digests, \
                min(join_rank) AS jr, max(severity_rank) AS sr \
            FROM x GROUP BY image_digest \
         ) \
         SELECT img.image_digest, i.repository, i.tags, img.sources, img.report_digests, \
            CASE img.jr WHEN 1 THEN 'image_id' WHEN 2 THEN 'platform_manifest' \
                ELSE 'workload_tag' END AS join_kind, \
            img.sr AS severity_rank, \
            (SELECT jsonb_agg(jsonb_build_object('name', pk.pkg_name, \
                'installedVersion', pk.installed_version, 'fixedVersions', pk.fvs, \
                'severity', CASE pk.sr WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH' \
                    WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' WHEN 1 THEN 'NONE' \
                    ELSE 'UNKNOWN' END, \
                'sources', pk.srcs) ORDER BY pk.sr DESC, pk.pkg_name, pk.installed_version) \
             FROM pk WHERE pk.image_digest = img.image_digest) AS packages \
         FROM img JOIN images i ON i.digest = img.image_digest \
         ORDER BY img.image_digest \
         LIMIT $2",
        eff = effective_cte(FOR_VULN),
    )
}

fn exposure_workloads_sql() -> String {
    format!(
        "WITH {eff}, \
         hit AS ( \
            SELECT e.image_digest, min(e.join_rank) AS join_rank FROM eff e \
            WHERE EXISTS (SELECT 1 FROM image_vulnerabilities v \
                WHERE v.digest = e.digest AND v.source = e.source AND v.vuln_id = $1) \
            GROUP BY e.image_digest \
         ), \
         pk AS ( \
            SELECT e.image_digest, v.pkg_name, bool_or(kg_pkg_observable(v.pkg_type, v.class)) AS obs \
            FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
            WHERE v.vuln_id = $1 GROUP BY e.image_digest, v.pkg_name \
         ) \
         SELECT wc.cluster_id, wc.pod_namespace AS namespace, wc.workload_kind, \
            wc.workload_name, wc.container_name, wc.image_digest, \
            CASE h.join_rank WHEN 1 THEN 'image_id' WHEN 2 THEN 'platform_manifest' \
                ELSE 'workload_tag' END AS join_kind, \
            {running} AS running, wc.last_seen, \
            COALESCE((SELECT min(kg_in_use_rank(kg_pkg_in_use(wc.cluster_id, wc.pod_namespace, \
                wc.workload_kind, wc.workload_name, wc.container_name, wc.image_digest, \
                p.pkg_name, p.obs))) FROM pk p WHERE p.image_digest = wc.image_digest), 2)::smallint \
                AS in_use_rank \
         FROM hit h JOIN workload_containers wc ON wc.image_digest = h.image_digest \
         ORDER BY running DESC, wc.pod_namespace, wc.workload_kind, wc.workload_name, \
            wc.container_name, wc.image_digest \
         LIMIT $2",
        eff = effective_cte(FOR_VULN),
        running = running_sql!("$3"),
    )
}

/// Per workload (by position in the arrays): its pods known to the broker
/// and the flows they had in the window, from `pod_traffic` with the peer
/// identity stamped at ingest (peer.rs). Rows are matched on pod name AND
/// namespace: pod names repeat across namespaces (postgres-0).
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
), flows AS ( \
    SELECT p.idx, p.pod_namespace, upper(pt.traffic_type) = 'INGRESS' AS ingress, \
        pt.peer_kind, pt.peer_namespace, \
        COALESCE(pt.peer_workload_name, pt.peer_name) AS peer, pt.traffic_in_out_ip \
    FROM pods p JOIN pod_traffic pt ON pt.pod_name = p.pod_name \
        AND pt.pod_namespace = p.pod_namespace \
    WHERE pt.time_stamp >= timezone('UTC', NOW()) - make_interval(hours => $4) \
) \
SELECT w.idx, \
    (SELECT count(*) FROM pods WHERE pods.idx = w.idx) AS pods, \
    count(i.idx) AS flows, \
    count(i.idx) FILTER (WHERE i.ingress) AS ingress_flows, \
    count(DISTINCT i.peer_namespace || '/' || i.peer) FILTER ( \
        WHERE i.ingress AND i.peer_kind IN ('pod', 'service') \
          AND i.peer_namespace IS DISTINCT FROM i.pod_namespace) AS cross_namespace, \
    count(DISTINCT i.traffic_in_out_ip) FILTER (WHERE i.ingress AND i.peer_kind = 'node') \
        AS from_nodes, \
    COALESCE((array_agg(DISTINCT i.traffic_in_out_ip) \
        FILTER (WHERE i.ingress AND i.peer_kind IS NULL AND i.traffic_in_out_ip IS NOT NULL)) \
        [1:$6], '{}') AS unresolved_ips, \
    count(DISTINCT i.traffic_in_out_ip) FILTER (WHERE i.ingress AND i.peer_kind IS NULL) \
        AS unresolved \
FROM w LEFT JOIN flows i ON i.idx = w.idx \
GROUP BY w.idx ORDER BY w.idx";

/// Observed network exposure of each (namespace, kind, name) in `keys`,
/// in the same order. One statement for all of them. Shared by the
/// exposure view and the retention pass that precomputes exposure for
/// tiers, so the two can never disagree.
pub(crate) fn network_exposure_for(
    conn: &mut PgConnection,
    keys: &[(String, String, String)],
    window_hours: i64,
) -> QueryResult<Vec<NetworkExposure>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let net: Vec<NetRow> = sql_query(NETWORK_SQL)
        .bind::<Array<Text>, _>(keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>())
        .bind::<Array<Text>, _>(keys.iter().map(|k| k.1.as_str()).collect::<Vec<_>>())
        .bind::<Array<Text>, _>(keys.iter().map(|k| k.2.as_str()).collect::<Vec<_>>())
        .bind::<Integer, _>(window_hours as i32)
        .bind::<BigInt, _>(EXPOSURE_PODS_PER_WORKLOAD)
        .bind::<Integer, _>(EXPOSURE_PEERS_PER_WORKLOAD as i32)
        .load(conn)?;
    Ok((0..keys.len())
        .map(|p| network_from(net.iter().find(|n| n.idx == p as i64 + 1), window_hours))
        .collect())
}

fn network_from(row: Option<&NetRow>, window_hours: i64) -> NetworkExposure {
    let Some(r) = row else {
        return NetworkExposure {
            window_hours,
            pods_observed: 0,
            ingress_from_other_namespaces: 0,
            ingress_from_unattributed_peers: 0,
            ingress_from_public_ips: 0,
            flows_observed: 0,
            ingress_flows_observed: 0,
            ingress_from_nodes: 0,
            exposed: None,
            exposed_via: Vec::new(),
        };
    };
    let public = r
        .unresolved_ips
        .iter()
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .filter(is_public_ip)
        .count() as i64;
    let mut via = Vec::new();
    if r.cross_namespace > 0 {
        via.push("other_namespace");
    }
    if r.unresolved > 0 {
        via.push("unattributed");
    }
    if public > 0 {
        via.push("public_ip");
    }
    if r.from_nodes > 0 {
        via.push("node");
    }
    NetworkExposure {
        window_hours,
        pods_observed: r.pods,
        flows_observed: r.flows,
        ingress_flows_observed: r.ingress_flows,
        ingress_from_other_namespaces: r.cross_namespace,
        ingress_from_unattributed_peers: r.unresolved,
        ingress_from_public_ips: public,
        ingress_from_nodes: r.from_nodes,
        // No pods or no captured ingress: nothing inbound was observed, so
        // unknown (inbound UDP is not captured; egress proves nothing).
        exposed: if r.pods == 0 || r.ingress_flows == 0 {
            None
        } else {
            Some(!via.is_empty())
        },
        exposed_via: if r.pods == 0 || r.ingress_flows == 0 {
            Vec::new()
        } else {
            via
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
    let net = network_exposure_for(conn, &keys, window_hours)?;
    let net_for = |r: &ExposedWorkloadRow| {
        keys.iter()
            .position(|k| k.0 == r.namespace && k.1 == r.workload_kind && k.2 == r.workload_name)
            .map(|p| net[p].clone())
            .unwrap_or_else(|| network_from(None, window_hours))
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
            in_use: crate::in_use::InUse::from_rank(r.in_use_rank).as_bool(),
            in_use_state: crate::in_use::InUse::from_rank(r.in_use_rank).as_str(),
        })
        .collect();
    // The CVE as a whole: the strongest listed workload's state; no
    // workloads (an image nothing runs any more) is unknown.
    let overall =
        crate::in_use::InUse::from_rank(rows.iter().map(|r| r.in_use_rank).min().unwrap_or(2));

    let severity_rank = images.iter().map(|i| i.severity_rank).max().unwrap_or(0);
    let mut fixable = false;
    let images: Vec<ExposedImage> = images
        .into_iter()
        .map(|i| {
            let mut pkgs = match i.packages {
                serde_json::Value::Array(a) => a,
                _ => Vec::new(),
            };
            fixable |= pkgs
                .iter()
                .any(|p| p["fixedVersions"].as_array().is_some_and(|a| !a.is_empty()));
            if pkgs.len() as i64 > EXPOSURE_MAX_PACKAGES {
                pkgs.truncate(EXPOSURE_MAX_PACKAGES as usize);
                truncated = true;
            }
            ExposedImage {
                digest: i.image_digest,
                repository: i.repository,
                tags: i.tags,
                sources: i.sources,
                report_digests: i.report_digests,
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
        in_use: overall.as_bool(),
        in_use_state: overall.as_str(),
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
            flows: 0,
            ingress_flows: 0,
            cross_namespace: 0,
            from_nodes: 0,
            unresolved_ips: vec![],
            unresolved: 0,
        };
        assert_eq!(network_from(Some(&row), 24).exposed, None, "no pods");
        let silent = NetRow {
            pods: 2,
            ..row.clone()
        };
        assert_eq!(
            network_from(Some(&silent), 24).exposed,
            None,
            "pods but no captured flows is unknown, not safe"
        );
        // Egress only (e.g. a UDP server: inbound UDP is not captured):
        // unknown, not "not exposed".
        let egress_only = NetRow {
            pods: 2,
            flows: 5,
            ..row.clone()
        };
        assert_eq!(network_from(Some(&egress_only), 24).exposed, None);
        let internal = NetRow {
            pods: 2,
            flows: 5,
            ingress_flows: 2,
            ..row.clone()
        };
        let n = network_from(Some(&internal), 24);
        assert_eq!(n.exposed, Some(false));
        assert!(n.exposed_via.is_empty());
        // Node ingress: NodePort / LoadBalancer with Cluster policy SNATs
        // to a node IP, so it is possible exposure.
        let node = NetRow {
            pods: 2,
            flows: 5,
            ingress_flows: 1,
            from_nodes: 1,
            ..row.clone()
        };
        let n = network_from(Some(&node), 24);
        assert_eq!(n.exposed, Some(true));
        assert_eq!(n.exposed_via, vec!["node"]);
        let internet = NetRow {
            pods: 2,
            flows: 3,
            ingress_flows: 2,
            unresolved: 2,
            unresolved_ips: vec!["8.8.8.8".into(), "10.0.0.9".into()],
            ..row.clone()
        };
        let n = network_from(Some(&internet), 24);
        assert_eq!(n.exposed, Some(true));
        assert_eq!(n.ingress_from_public_ips, 1);
        assert_eq!(n.exposed_via, vec!["unattributed", "public_ip"]);
        let cross = NetRow {
            pods: 1,
            flows: 1,
            ingress_flows: 1,
            cross_namespace: 1,
            ..row
        };
        assert_eq!(
            network_from(Some(&cross), 24).exposed_via,
            vec!["other_namespace"]
        );
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
