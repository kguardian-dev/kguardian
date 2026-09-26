//! Database side of runtime "in use" (#1533 P1-5): the retention-pass
//! steps that turn the runtime inventory (P1-2, `runtime_executables`)
//! into the derived tables the reads use, and the OpenVEX draft.
//!
//! # Steps (each pass, after the supply-chain relink)
//!
//! 1. [`refresh_package_use_batch`]: per inventory digest, map every
//!    executed / mapped path to the SBOM packages that own it
//!    ([`crate::in_use::owners_of`]) -> `runtime_package_use`, and the
//!    paths nothing owns -> `runtime_unowned_paths`.
//! 2. [`refresh_coverage`]: per workload container and digest, whether
//!    capture covered it for the minimum window -> `runtime_in_use_coverage`.
//! 3. [`refresh_exposure`]: observed network exposure per workload that
//!    runs an image with findings -> `workload_network_exposure`.
//!
//! The per-package state is then one SQL function, `kg_pkg_in_use`
//! (migration 2026-09-28-200000), shared by the CVE summary, the per-image
//! reads, the exposure view and the VEX draft.
//!
//! # Coverage
//!
//! Whether capture watched a container continuously for the window is
//! owned by the runtime inventory (P1-2), which knows probe status per
//! node, backfill, drops and heartbeats. It exposes one SQL function,
//! `kg_runtime_coverage(cluster, ns, kind, name, container, image,
//! window_hours) -> (covered, observed_since, reason)`, and
//! [`refresh_coverage`] calls it for every inventory workload container.
//! Runtime rows alone are never taken as coverage: a path is re-posted
//! only hourly and an old controller writes nothing, so "no new rows"
//! cannot be told apart from "not watching".
//!
//! Until that function exists (P1-2 not deployed), every container is
//! `unknown: no_runtime_data`, so installed_not_observed is never claimed
//! and every finding is tiered as in use.

use crate::in_use::{self, Component, InUse, PackageKey, PathMatch, TierSettings, UnknownReason};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Bool, Integer, Nullable, Text, Timestamp};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type DbError = Box<dyn std::error::Error + Send + Sync>;

/// The runtime inventory (P1-2). Every statement that reads it is below,
/// so a change to its shape is one edit here.
pub const RUNTIME_TABLE: &str = "runtime_executables";

/// Runtime rows read per image in one pass; beyond this the image's
/// newest rows are used and the rest wait for the next pass.
pub const MAX_RUNTIME_ROWS_PER_IMAGE: i64 = 20_000;
/// Unowned paths kept per image.
pub const MAX_UNOWNED_PER_IMAGE: usize = 200;

// ---------------------------------------------------------------------
// 1. Path -> package
// ---------------------------------------------------------------------

#[derive(QueryableByName, Debug, Clone)]
struct RtRow {
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Text)]
    pod_namespace: String,
    #[diesel(sql_type = Text)]
    workload_kind: String,
    #[diesel(sql_type = Text)]
    workload_name: String,
    #[diesel(sql_type = Text)]
    container_name: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    path: String,
    #[diesel(sql_type = Timestamp)]
    first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    last_seen: NaiveDateTime,
}

#[derive(QueryableByName, Debug, Clone)]
struct CompRow {
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Text)]
    version: String,
    #[diesel(sql_type = Array<Text>)]
    file_paths: Vec<String>,
}

#[derive(QueryableByName)]
struct DigestRow {
    #[diesel(sql_type = Text)]
    image_digest: String,
}

#[derive(Serialize)]
struct UseRow {
    cluster_id: String,
    pod_namespace: String,
    workload_kind: String,
    workload_name: String,
    container_name: String,
    pkg_name: String,
    pkg_version: String,
    state: String,
    path_match: String,
    sample_path: String,
    first_seen: NaiveDateTime,
    last_seen: NaiveDateTime,
}

#[derive(Serialize)]
struct UnownedRow {
    path: String,
    kind: String,
    workloads: i32,
    first_seen: NaiveDateTime,
    last_seen: NaiveDateTime,
}

fn path_match_str(m: PathMatch) -> &'static str {
    match m {
        PathMatch::Exact => "exact",
        PathMatch::MergedUsrAlias => "merged_usr_alias",
        PathMatch::Soname => "soname",
    }
}

/// What one image's runtime rows prove, computed in memory.
#[derive(Default)]
struct ImageUse {
    uses: BTreeMap<(String, String, String, String, String, PackageKey), UseAcc>,
    unowned: BTreeMap<(String, String), UnownedAcc>,
}

struct UseAcc {
    executed: bool,
    how: PathMatch,
    sample: String,
    first: NaiveDateTime,
    last: NaiveDateTime,
}

struct UnownedAcc {
    workloads: BTreeSet<(String, String, String, String)>,
    first: NaiveDateTime,
    last: NaiveDateTime,
}

fn compute_image_use(rows: &[RtRow], comps: &[Component], has_sbom: bool) -> ImageUse {
    let mut out = ImageUse::default();
    let mut owners_cache: BTreeMap<&str, in_use::Ownership> = BTreeMap::new();
    for r in rows {
        let o = owners_cache
            .entry(r.path.as_str())
            .or_insert_with(|| in_use::owners_of(&r.path, comps));
        let executed = r.kind == "exec";
        if o.unowned() {
            if has_sbom {
                let e = out
                    .unowned
                    .entry((r.path.clone(), r.kind.clone()))
                    .or_insert_with(|| UnownedAcc {
                        workloads: BTreeSet::new(),
                        first: r.first_seen,
                        last: r.last_seen,
                    });
                e.workloads.insert((
                    r.cluster_id.clone(),
                    r.pod_namespace.clone(),
                    r.workload_kind.clone(),
                    r.workload_name.clone(),
                ));
                e.first = e.first.min(r.first_seen);
                e.last = e.last.max(r.last_seen);
            }
            continue;
        }
        let how = o.how.unwrap_or(PathMatch::Soname);
        for pkg in &o.owners {
            let key = (
                r.cluster_id.clone(),
                r.pod_namespace.clone(),
                r.workload_kind.clone(),
                r.workload_name.clone(),
                r.container_name.clone(),
                pkg.clone(),
            );
            let e = out.uses.entry(key).or_insert_with(|| UseAcc {
                executed,
                how,
                sample: r.path.clone(),
                first: r.first_seen,
                last: r.last_seen,
            });
            if executed && !e.executed {
                e.executed = true;
                e.sample = r.path.clone();
            }
            e.how = e.how.min(how);
            e.first = e.first.min(r.first_seen);
            e.last = e.last.max(r.last_seen);
        }
    }
    out
}

/// What one image's refresh did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageRefresh {
    pub rows_written: usize,
    /// The image had more runtime rows than were read: packages seen only
    /// in the rest are not recorded, so its coverage must not be trusted.
    pub truncated: bool,
}

/// Recompute package use for one inventory digest.
pub fn refresh_image_use(conn: &mut PgConnection, image: &str) -> Result<ImageRefresh, DbError> {
    refresh_image_use_capped(conn, image, MAX_RUNTIME_ROWS_PER_IMAGE)
}

pub(crate) fn refresh_image_use_capped(
    conn: &mut PgConnection,
    image: &str,
    cap: i64,
) -> Result<ImageRefresh, DbError> {
    let mut rows: Vec<RtRow> = sql_query(format!(
        "SELECT cluster_id, pod_namespace, workload_kind, workload_name, container_name, \
             kind, path, first_seen, last_seen \
         FROM {RUNTIME_TABLE} \
         WHERE image_digest = $1 AND path_complete AND kind IN ('exec', 'lib') \
         ORDER BY last_seen DESC LIMIT $2"
    ))
    .bind::<Text, _>(image)
    .bind::<BigInt, _>(cap + 1)
    .load(conn)?;
    let truncated = rows.len() as i64 > cap;
    rows.truncate(cap as usize);
    let paths: BTreeSet<&str> = rows.iter().map(|r| r.path.as_str()).collect();
    let mut cands: Vec<String> = paths
        .iter()
        .flat_map(|p| in_use::candidates(p).into_iter().map(|(c, _)| c))
        .collect();
    cands.sort();
    cands.dedup();
    #[derive(QueryableByName)]
    struct Has {
        #[diesel(sql_type = Bool)]
        has: bool,
    }
    let has_sbom = sql_query(
        "SELECT EXISTS (SELECT 1 FROM supplychain_image_links l JOIN vuln_sources vs \
             ON vs.digest = l.digest AND vs.source = l.source AND vs.kind = 'sbom' \
         WHERE l.image_digest = $1) AS has",
    )
    .bind::<Text, _>(image)
    .get_result::<Has>(conn)?
    .has;
    let comps: Vec<CompRow> = if cands.is_empty() {
        Vec::new()
    } else {
        sql_query(
            "SELECT DISTINCT c.name, COALESCE(c.version, '') AS version, c.file_paths \
             FROM supplychain_image_links l \
             JOIN image_sbom_components c ON c.digest = l.digest AND c.source = l.source \
             WHERE l.image_digest = $1 AND c.file_paths && $2::text[]",
        )
        .bind::<Text, _>(image)
        .bind::<Array<Text>, _>(&cands)
        .load(conn)?
    };
    let comps: Vec<Component> = comps
        .into_iter()
        .map(|c| Component {
            key: PackageKey {
                name: c.name,
                version: Some(c.version),
            },
            file_paths: c.file_paths,
        })
        .collect();
    let u = compute_image_use(&rows, &comps, has_sbom);

    let uses: Vec<UseRow> = u
        .uses
        .into_iter()
        .map(|((c, ns, k, n, ct, pkg), a)| UseRow {
            cluster_id: c,
            pod_namespace: ns,
            workload_kind: k,
            workload_name: n,
            container_name: ct,
            pkg_name: pkg.name,
            pkg_version: pkg.version.unwrap_or_default(),
            state: if a.executed { "executed" } else { "loaded" }.into(),
            path_match: path_match_str(a.how).into(),
            sample_path: a.sample,
            first_seen: a.first,
            last_seen: a.last,
        })
        .collect();
    let mut unowned: Vec<UnownedRow> = u
        .unowned
        .into_iter()
        .map(|((path, kind), a)| UnownedRow {
            path,
            kind,
            workloads: a.workloads.len() as i32,
            first_seen: a.first,
            last_seen: a.last,
        })
        .collect();
    unowned.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.path.cmp(&b.path)));
    unowned.truncate(MAX_UNOWNED_PER_IMAGE);
    let uses_json = serde_json::to_string(&uses)?;
    let unowned_json = serde_json::to_string(&unowned)?;
    conn.transaction::<_, DbError, _>(|conn| {
        sql_query("DELETE FROM runtime_package_use WHERE image_digest = $1")
            .bind::<Text, _>(image)
            .execute(conn)?;
        sql_query("DELETE FROM runtime_unowned_paths WHERE image_digest = $1")
            .bind::<Text, _>(image)
            .execute(conn)?;
        let a = sql_query(
            "INSERT INTO runtime_package_use (cluster_id, pod_namespace, workload_kind, \
                 workload_name, container_name, image_digest, pkg_name, pkg_version, state, \
                 path_match, sample_path, first_seen, last_seen) \
             SELECT r.cluster_id, r.pod_namespace, r.workload_kind, r.workload_name, \
                 r.container_name, $1, r.pkg_name, r.pkg_version, r.state, r.path_match, \
                 r.sample_path, r.first_seen, r.last_seen \
             FROM jsonb_to_recordset($2::jsonb) AS r(cluster_id text, pod_namespace text, \
                 workload_kind text, workload_name text, container_name text, pkg_name text, \
                 pkg_version text, state text, path_match text, sample_path text, \
                 first_seen timestamp, last_seen timestamp)",
        )
        .bind::<Text, _>(image)
        .bind::<Text, _>(&uses_json)
        .execute(conn)?;
        let b = sql_query(
            "INSERT INTO runtime_unowned_paths (image_digest, path, kind, workloads, \
                 first_seen, last_seen) \
             SELECT $1, r.path, r.kind, r.workloads, r.first_seen, r.last_seen \
             FROM jsonb_to_recordset($2::jsonb) AS r(path text, kind text, workloads integer, \
                 first_seen timestamp, last_seen timestamp)",
        )
        .bind::<Text, _>(image)
        .bind::<Text, _>(&unowned_json)
        .execute(conn)?;
        Ok(ImageRefresh {
            rows_written: a + b,
            truncated,
        })
    })
}

/// Whether the runtime inventory table (P1-2) exists in this database. A
/// broker built from this branch can run before P1-2's migration lands;
/// then there is no evidence of use, every container stays unknown and
/// every finding is tiered as in use.
pub fn runtime_inventory_available(conn: &mut PgConnection) -> QueryResult<bool> {
    #[derive(QueryableByName)]
    struct E {
        #[diesel(sql_type = Bool)]
        e: bool,
    }
    sql_query("SELECT to_regclass($1) IS NOT NULL AS e")
        .bind::<Text, _>(RUNTIME_TABLE)
        .get_result::<E>(conn)
        .map(|r| r.e)
}

/// Drop all derived use rows (the runtime inventory is absent).
pub fn clear_package_use(conn: &mut PgConnection) -> QueryResult<usize> {
    let a = sql_query("DELETE FROM runtime_package_use").execute(conn)?;
    let b = sql_query("DELETE FROM runtime_unowned_paths").execute(conn)?;
    Ok(a + b)
}

/// One batch of [`refresh_package_use_batch`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchRefresh {
    pub rows_written: usize,
    /// The cursor for the next batch; `None` when every digest is done.
    pub next: Option<String>,
    /// Digests whose runtime rows were cut at the per-image cap.
    pub truncated: Vec<String>,
}

/// Recompute package use for up to `batch` digests after the cursor.
pub fn refresh_package_use_batch(
    conn: &mut PgConnection,
    after: Option<&str>,
    batch: i64,
) -> Result<BatchRefresh, DbError> {
    let digests: Vec<DigestRow> = sql_query(format!(
        "SELECT DISTINCT image_digest FROM {RUNTIME_TABLE} \
         WHERE image_digest <> '' AND ($1::text IS NULL OR image_digest > $1) \
         ORDER BY image_digest LIMIT $2"
    ))
    .bind::<Nullable<Text>, _>(after)
    .bind::<BigInt, _>(batch)
    .load(conn)?;
    let mut out = BatchRefresh::default();
    for d in &digests {
        let r = refresh_image_use(conn, &d.image_digest)?;
        out.rows_written += r.rows_written;
        if r.truncated {
            out.truncated.push(d.image_digest.clone());
        }
    }
    out.next = if (digests.len() as i64) < batch {
        None
    } else {
        digests.last().map(|d| d.image_digest.clone())
    };
    Ok(out)
}

/// Drop derived rows of digests the runtime inventory no longer has.
pub fn prune_package_use(conn: &mut PgConnection) -> QueryResult<usize> {
    let a = sql_query(format!(
        "DELETE FROM runtime_package_use u WHERE NOT EXISTS \
         (SELECT 1 FROM {RUNTIME_TABLE} r WHERE r.image_digest = u.image_digest)"
    ))
    .execute(conn)?;
    let b = sql_query(format!(
        "DELETE FROM runtime_unowned_paths u WHERE NOT EXISTS \
         (SELECT 1 FROM {RUNTIME_TABLE} r WHERE r.image_digest = u.image_digest)"
    ))
    .execute(conn)?;
    Ok(a + b)
}

// ---------------------------------------------------------------------
// 2. Coverage
// ---------------------------------------------------------------------

/// The coverage function the runtime inventory provides (module docs).
pub const COVERAGE_FN: &str = "kg_runtime_coverage(text,text,text,text,text,text,integer)";

/// Whether the runtime inventory's coverage function is installed.
pub fn coverage_available(conn: &mut PgConnection) -> QueryResult<bool> {
    #[derive(QueryableByName)]
    struct E {
        #[diesel(sql_type = Bool)]
        e: bool,
    }
    sql_query("SELECT to_regprocedure($1) IS NOT NULL AS e")
        .bind::<Text, _>(COVERAGE_FN)
        .get_result::<E>(conn)
        .map(|r| r.e)
}

/// Whether this pass's package-use evidence is whole, so coverage may be
/// believed. Coverage says capture watched a container; it proves
/// "installed, not observed" only if every path capture saw was also
/// matched to its package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UseEvidence {
    /// Every inventory digest's package use was refreshed this pass.
    pub complete: bool,
    /// Digests whose runtime rows were cut at the per-image cap.
    pub truncated: Vec<String>,
}

/// Rebuild `runtime_in_use_coverage` for every inventory workload
/// container: from `kg_runtime_coverage` when present, else unknown
/// (`no_runtime_data`) everywhere. Where the package-use evidence is not
/// whole (`evidence`: the pass stopped early, or a digest's runtime rows
/// were truncated), a covered container is downgraded to
/// `capture_gap`, so nothing is claimed installed-but-not-observed from
/// part of the evidence.
pub fn refresh_coverage(
    conn: &mut PgConnection,
    s: &TierSettings,
    evidence: &UseEvidence,
) -> QueryResult<usize> {
    let available = coverage_available(conn)?;
    conn.transaction(|conn| {
        sql_query("DELETE FROM runtime_in_use_coverage").execute(conn)?;
        let select = if available {
            "SELECT wc.cluster_id, wc.pod_namespace, wc.workload_kind, wc.workload_name, \
                 wc.container_name, wc.image_digest, COALESCE(k.covered, false) AND NOT g.gap, \
                 CASE WHEN k.covered IS TRUE AND NOT g.gap THEN NULL \
                      WHEN k.covered IS TRUE THEN 'capture_gap' \
                      ELSE COALESCE(NULLIF(k.reason, ''), 'no_runtime_data') END, \
                 CASE WHEN k.covered IS TRUE AND NOT g.gap THEN k.observed_since END, \
                 $1, timezone('UTC', NOW()) \
             FROM workload_containers wc \
             LEFT JOIN LATERAL kg_runtime_coverage(wc.cluster_id, wc.pod_namespace, \
                 wc.workload_kind, wc.workload_name, wc.container_name, wc.image_digest, $1) k \
                 ON true \
             CROSS JOIN LATERAL (SELECT (NOT $2 OR wc.image_digest = ANY($3)) AS gap) g"
        } else {
            "SELECT wc.cluster_id, wc.pod_namespace, wc.workload_kind, wc.workload_name, \
                 wc.container_name, wc.image_digest, false, 'no_runtime_data', \
                 NULL::timestamp, $1, timezone('UTC', NOW()) \
             FROM workload_containers wc"
        };
        sql_query(format!(
            "INSERT INTO runtime_in_use_coverage (cluster_id, pod_namespace, workload_kind, \
                 workload_name, container_name, image_digest, covered, reason, observed_since, \
                 window_hours, computed_at) {select}"
        ))
        .bind::<Integer, _>(s.min_window_hours as i32)
        .bind::<Bool, _>(evidence.complete)
        .bind::<Array<Text>, _>(&evidence.truncated)
        .execute(conn)
    })
}

// ---------------------------------------------------------------------
// 3. Exposure
// ---------------------------------------------------------------------

/// Rebuild `workload_network_exposure` for every workload running an
/// image that has a linked vulnerability report, in chunks of 200.
pub fn refresh_exposure(conn: &mut PgConnection, window_hours: i64) -> QueryResult<usize> {
    #[derive(QueryableByName)]
    struct W {
        #[diesel(sql_type = Text)]
        cluster_id: String,
        #[diesel(sql_type = Text)]
        ns: String,
        #[diesel(sql_type = Text)]
        kind: String,
        #[diesel(sql_type = Text)]
        name: String,
    }
    let ws: Vec<W> = sql_query(
        "SELECT DISTINCT wc.cluster_id, wc.pod_namespace AS ns, wc.workload_kind AS kind, \
             wc.workload_name AS name \
         FROM workload_containers wc \
         WHERE EXISTS (SELECT 1 FROM supplychain_image_links l JOIN vuln_sources vs \
             ON vs.digest = l.digest AND vs.source = l.source AND vs.kind = 'vulnerabilities' \
             WHERE l.image_digest = wc.image_digest) \
         ORDER BY 1, 2, 3, 4",
    )
    .load(conn)?;
    let mut rows = Vec::with_capacity(ws.len());
    for chunk in ws.chunks(200) {
        let keys: Vec<(String, String, String)> = chunk
            .iter()
            .map(|w| (w.ns.clone(), w.kind.clone(), w.name.clone()))
            .collect();
        let net = crate::supplychain_read::network_exposure_for(conn, &keys, window_hours)?;
        for (w, n) in chunk.iter().zip(net) {
            rows.push(serde_json::json!({
                "cluster_id": w.cluster_id, "pod_namespace": w.ns, "workload_kind": w.kind,
                "workload_name": w.name, "window_hours": window_hours, "pods": n.pods_observed,
                "ingress_flows": n.ingress_flows_observed, "exposed": n.exposed,
                "exposed_via": n.exposed_via,
            }));
        }
    }
    let json = serde_json::Value::Array(rows).to_string();
    conn.transaction(|conn| {
        sql_query("DELETE FROM workload_network_exposure").execute(conn)?;
        sql_query(
            "INSERT INTO workload_network_exposure (cluster_id, pod_namespace, workload_kind, \
                 workload_name, window_hours, pods, ingress_flows, exposed, exposed_via, \
                 computed_at) \
             SELECT r.cluster_id, r.pod_namespace, r.workload_kind, r.workload_name, \
                 r.window_hours, r.pods, r.ingress_flows, r.exposed, \
                 COALESCE(r.exposed_via, '{}'), timezone('UTC', NOW()) \
             FROM jsonb_to_recordset($1::jsonb) AS r(cluster_id text, pod_namespace text, \
                 workload_kind text, workload_name text, window_hours integer, pods bigint, \
                 ingress_flows bigint, exposed boolean, exposed_via text[])",
        )
        .bind::<Text, _>(&json)
        .execute(conn)
    })
}

// ---------------------------------------------------------------------
// State text from kg_pkg_in_use
// ---------------------------------------------------------------------

/// Parse `kg_pkg_in_use` output: `executed`, `loaded`,
/// `installed_not_observed`, or `unknown:<reason>`.
pub fn parse_state(s: &str) -> (InUse, Option<UnknownReason>) {
    match s {
        "executed" => (InUse::Executed, None),
        "loaded" => (InUse::Loaded, None),
        "installed_not_observed" => (InUse::InstalledNotObserved, None),
        other => {
            // `unknown` alone (or anything unparseable) has no reason: no
            // runtime data. A reason the coverage function reports that
            // this broker does not know is still a gap in capture.
            let reason = match other.strip_prefix("unknown:") {
                Some("no_runtime_data") | Some("") | None => UnknownReason::NoRuntimeData,
                Some("capture_gap") => UnknownReason::CaptureGap,
                Some("host_network") => UnknownReason::HostNetwork,
                Some("language_package") => UnknownReason::LanguagePackage,
                Some("no_package_files") => UnknownReason::NoPackageFiles,
                Some("probes_missing") => UnknownReason::ProbesMissing,
                Some(_) => UnknownReason::CaptureGap,
            };
            (InUse::Unknown, Some(reason))
        }
    }
}

// ---------------------------------------------------------------------
// OpenVEX draft (consumed in-process by the profile export bundle)
// ---------------------------------------------------------------------

/// A draft OpenVEX document for one workload.
#[derive(Debug, Clone)]
pub struct VexDraft {
    pub doc: serde_json::Value,
    pub statements: usize,
    pub input_hash: String,
}

/// Either a draft, or why none can be produced (no SBOM, no findings, no
/// covered container, no statement qualifies).
#[derive(Debug, Clone)]
pub enum VexOutcome {
    Draft(VexDraft),
    Unavailable(String),
}

#[derive(QueryableByName, Debug, Clone)]
struct VexRow {
    #[diesel(sql_type = Text)]
    vuln_id: String,
    #[diesel(sql_type = Text)]
    pkg_name: String,
    #[diesel(sql_type = Text)]
    installed_version: String,
    #[diesel(sql_type = Nullable<Text>)]
    pkg_purl: Option<String>,
    #[diesel(sql_type = Text)]
    image_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    repository: Option<String>,
    #[diesel(sql_type = Text)]
    container_name: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamp>)]
    observed_since: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    computed_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Text)]
    report_digests: String,
}

/// Findings of every image the workload runs, with the per-container
/// in-use state of the affected package (one row per finding per
/// container).
const VEX_ROWS_SQL: &str = "\
WITH wc AS ( \
    SELECT cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest \
    FROM workload_containers \
    WHERE pod_namespace = $1 AND workload_kind = $2 AND workload_name = $3 \
), eff AS ( \
    SELECT DISTINCT ON (l.image_digest, l.source) l.image_digest, l.digest, l.source \
    FROM supplychain_image_links l \
    JOIN vuln_sources vs ON vs.digest = l.digest AND vs.source = l.source \
        AND vs.kind = 'vulnerabilities' \
    WHERE l.image_digest IN (SELECT image_digest FROM wc) \
    ORDER BY l.image_digest, l.source, l.join_rank, vs.scanned_at DESC \
), f AS ( \
    SELECT e.image_digest, v.vuln_id, v.pkg_name, v.installed_version, \
        min(v.pkg_purl) AS pkg_purl \
    FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
    GROUP BY e.image_digest, v.vuln_id, v.pkg_name, v.installed_version \
), o AS ( \
    SELECT e.image_digest, v.pkg_name, bool_or(kg_pkg_observable(v.pkg_type, v.class)) AS observable \
    FROM eff e JOIN image_vulnerabilities v ON v.digest = e.digest AND v.source = e.source \
    GROUP BY e.image_digest, v.pkg_name \
), rd AS ( \
    SELECT image_digest, string_agg(DISTINCT digest || '@' || source, ',') AS report_digests \
    FROM eff GROUP BY image_digest \
) \
SELECT f.vuln_id, f.pkg_name, f.installed_version, f.pkg_purl, f.image_digest, i.repository, \
    wc.container_name, \
    kg_pkg_in_use(wc.cluster_id, wc.pod_namespace, wc.workload_kind, wc.workload_name, \
        wc.container_name, wc.image_digest, f.pkg_name, o.observable) AS state, \
    cv.observed_since, cv.computed_at, \
    COALESCE(rd.report_digests, '') AS report_digests \
FROM f JOIN wc ON wc.image_digest = f.image_digest \
JOIN o ON o.image_digest = f.image_digest AND o.pkg_name = f.pkg_name \
LEFT JOIN rd ON rd.image_digest = f.image_digest \
LEFT JOIN images i ON i.digest = f.image_digest \
LEFT JOIN runtime_in_use_coverage cv ON cv.cluster_id = wc.cluster_id \
    AND cv.pod_namespace = wc.pod_namespace AND cv.workload_kind = wc.workload_kind \
    AND cv.workload_name = wc.workload_name AND cv.container_name = wc.container_name \
    AND cv.image_digest = wc.image_digest \
ORDER BY f.image_digest, f.vuln_id, f.pkg_name, f.installed_version, wc.container_name \
LIMIT $4";

/// Statements at most per draft.
pub const VEX_MAX_ROWS: i64 = 20_000;

fn purl_of_image(repo: Option<&str>, digest: &str) -> String {
    let name = repo.and_then(|r| r.rsplit('/').next()).unwrap_or("image");
    let mut s = format!("pkg:oci/{name}@{}", digest.replace(':', "%3A"));
    if let Some(r) = repo {
        if let Some((host, _)) = r.rsplit_once('/') {
            s.push_str(&format!("?repository_url={host}/{name}"));
        }
    }
    s
}

fn ts(t: &NaiveDateTime) -> String {
    t.and_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The OpenVEX 0.2.0 draft for one workload: `not_affected /
/// vulnerable_code_not_in_execute_path` ONLY for a finding whose package
/// is installed_not_observed in EVERY container of the workload that runs
/// the image, each with full coverage over the window. Marked as a draft
/// requiring human review, with the window and coverage in each
/// statement. Deterministic: same inputs, same document and `@id`.
pub fn openvex_draft(
    conn: &mut PgConnection,
    key: &crate::workload_profile::Key,
) -> Result<VexOutcome, DbError> {
    openvex_draft_capped(conn, key, VEX_MAX_ROWS)
}

/// [`openvex_draft`] with the row cap as a parameter (tests).
pub(crate) fn openvex_draft_capped(
    conn: &mut PgConnection,
    key: &crate::workload_profile::Key,
    cap: i64,
) -> Result<VexOutcome, DbError> {
    let s = TierSettings::from_env();
    // Rows come grouped by finding (image, vuln, package, version), then
    // container, which drop_partial_group relies on.
    let mut rows: Vec<VexRow> = sql_query(VEX_ROWS_SQL)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<BigInt, _>(cap + 1)
        .load(conn)?;
    drop_partial_group(&mut rows, cap as usize);
    if rows.is_empty() {
        return Ok(VexOutcome::Unavailable(
            "no vulnerability findings for the images this workload runs".into(),
        ));
    }
    Ok(build_openvex(key, &rows, s.min_window_hours))
}

/// Rows are ordered by finding then container. When the read hit its cap,
/// the last finding may be missing some containers, and a statement needs
/// every container to be unseen, so that finding is dropped whole rather
/// than judged on part of its evidence.
fn drop_partial_group(rows: &mut Vec<VexRow>, cap: usize) {
    if rows.len() <= cap {
        return;
    }
    rows.truncate(cap);
    let Some(last) = rows.last().cloned() else {
        return;
    };
    rows.retain(|r| {
        (
            &r.image_digest,
            &r.vuln_id,
            &r.pkg_name,
            &r.installed_version,
        ) != (
            &last.image_digest,
            &last.vuln_id,
            &last.pkg_name,
            &last.installed_version,
        )
    });
}

fn build_openvex(
    key: &crate::workload_profile::Key,
    rows: &[VexRow],
    min_window_hours: i64,
) -> VexOutcome {
    // (image, vuln, pkg, version) -> the rows for every container.
    let mut groups: BTreeMap<(String, String, String, String), Vec<&VexRow>> = BTreeMap::new();
    for r in rows {
        groups
            .entry((
                r.image_digest.clone(),
                r.vuln_id.clone(),
                r.pkg_name.clone(),
                r.installed_version.clone(),
            ))
            .or_default()
            .push(r);
    }
    let mut statements = Vec::new();
    let mut inputs = Vec::new();
    let mut window_start: Option<NaiveDateTime> = None;
    let mut window_end: Option<NaiveDateTime> = None;
    for ((image, vuln, pkg, version), rs) in &groups {
        inputs.push(serde_json::json!([
            image,
            vuln,
            pkg,
            version,
            rs.iter()
                .map(|r| (&r.container_name, &r.state))
                .collect::<Vec<_>>(),
            rs[0].report_digests
        ]));
        if !rs.iter().all(|r| r.state == "installed_not_observed") {
            continue;
        }
        let (Some(since), Some(until)) = (
            rs.iter().filter_map(|r| r.observed_since).max(),
            rs.iter().filter_map(|r| r.computed_at).min(),
        ) else {
            continue;
        };
        window_start = Some(window_start.map_or(since, |w| w.max(since)));
        window_end = Some(window_end.map_or(until, |w| w.min(until)));
        let containers: Vec<&str> = rs.iter().map(|r| r.container_name.as_str()).collect();
        let hours = (until - since).num_hours();
        let mut product = serde_json::json!({
            "@id": purl_of_image(rs[0].repository.as_deref(), image),
        });
        let sub_id = rs[0]
            .pkg_purl
            .clone()
            .unwrap_or_else(|| format!("{pkg}@{version}"));
        product["subcomponents"] = serde_json::json!([{ "@id": sub_id }]);
        statements.push(serde_json::json!({
            "vulnerability": { "name": vuln },
            "products": [product],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "status_notes": format!(
                "DRAFT, requires human review. kguardian did not observe {pkg} {version} \
                 executed or loaded in container(s) {} of {}/{} {} between {} and {} ({} h; \
                 minimum window {} h). Coverage: exec and shared-library capture, backfill of \
                 running processes complete, capture reporting within the freshness window. \
                 Not observed is not proof: code paths not exercised in the window are not \
                 covered.",
                containers.join(", "), key.namespace, key.kind, key.name, ts(&since),
                ts(&until), hours, min_window_hours
            ),
        }));
    }
    let input_hash = crate::workload_profile::content_hash(&serde_json::json!({
        "workload": [&key.namespace, &key.kind, &key.name],
        "min_window_hours": min_window_hours,
        "findings": inputs,
    }));
    if statements.is_empty() {
        return VexOutcome::Unavailable(
            "no finding is installed-but-not-observed with full capture coverage in every \
             container over the window"
                .into(),
        );
    }
    let n = statements.len();
    let hash_id = input_hash.trim_start_matches("fnv1a64:").to_string();
    let doc = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("https://kguardian.dev/vex/{}/{}/{}/{}", key.namespace, key.kind, key.name, hash_id),
        "author": "kguardian (draft, requires human review)",
        "role": "Document Creator",
        "timestamp": window_end.map(|t| ts(&t)),
        "version": 1,
        "statements": statements,
        "kguardian:draft": true,
        "kguardian:input_hash": input_hash,
        "kguardian_window": {
            "start": window_start.map(|t| ts(&t)),
            "end": window_end.map(|t| ts(&t)),
            "min_hours": min_window_hours,
        },
    });
    VexOutcome::Draft(VexDraft {
        doc,
        statements: n,
        input_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap()
    }

    fn rt(container: &str, kind: &str, path: &str) -> RtRow {
        RtRow {
            cluster_id: "primary".into(),
            pod_namespace: "ns".into(),
            workload_kind: "Deployment".into(),
            workload_name: "w".into(),
            container_name: container.into(),
            kind: kind.into(),
            path: path.into(),
            first_seen: t("2026-09-20 00:00"),
            last_seen: t("2026-09-27 00:00"),
        }
    }

    fn comp(name: &str, paths: &[&str]) -> Component {
        Component {
            key: PackageKey {
                name: name.into(),
                version: Some("1".into()),
            },
            file_paths: paths.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn image_use_marks_executed_over_loaded_and_collects_unowned() {
        let comps = vec![
            comp("coreutils", &["/bin/cat"]),
            comp("libc6", &["/lib/x86_64-linux-gnu/libc.so.6"]),
        ];
        let rows = vec![
            rt("app", "lib", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
            rt("app", "exec", "/usr/bin/cat"),
            rt("app", "exec", "/usr/local/bin/app"),
            rt("side", "lib", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
        ];
        let u = compute_image_use(&rows, &comps, true);
        let get = |c: &str, p: &str| {
            u.uses
                .iter()
                .find(|(k, _)| k.4 == c && k.5.name == p)
                .map(|(_, a)| (a.executed, a.how))
        };
        assert_eq!(
            get("app", "coreutils"),
            Some((true, PathMatch::MergedUsrAlias))
        );
        assert_eq!(
            get("app", "libc6"),
            Some((false, PathMatch::MergedUsrAlias))
        );
        assert_eq!(
            get("side", "libc6"),
            Some((false, PathMatch::MergedUsrAlias))
        );
        assert_eq!(get("side", "coreutils"), None);
        assert_eq!(u.unowned.len(), 1);
        assert!(u
            .unowned
            .contains_key(&("/usr/local/bin/app".into(), "exec".into())));
        // Without an SBOM nothing is "unowned": there is nothing to own it.
        let u = compute_image_use(&rows, &[], false);
        assert!(u.unowned.is_empty() && u.uses.is_empty());
    }

    #[test]
    fn state_text_parses() {
        assert_eq!(parse_state("executed"), (InUse::Executed, None));
        assert_eq!(
            parse_state("installed_not_observed"),
            (InUse::InstalledNotObserved, None)
        );
        assert_eq!(
            parse_state("unknown:host_network"),
            (InUse::Unknown, Some(UnknownReason::HostNetwork))
        );
        assert_eq!(
            parse_state("unknown:language_package").1,
            Some(UnknownReason::LanguagePackage)
        );
        assert_eq!(
            parse_state("unknown:whatever").1,
            Some(UnknownReason::CaptureGap),
            "an unrecognised reason is still a gap"
        );
        assert_eq!(parse_state("unknown").1, Some(UnknownReason::NoRuntimeData));
        assert_eq!(parse_state("").0, InUse::Unknown);
    }

    fn vex_row(container: &str, state: &str, vuln: &str) -> VexRow {
        VexRow {
            vuln_id: vuln.into(),
            pkg_name: "zlib1g".into(),
            installed_version: "1:1.2.13.dfsg-1".into(),
            pkg_purl: Some("pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1".into()),
            image_digest: format!("sha256:{:064x}", 1),
            repository: Some("docker.io/library/app".into()),
            container_name: container.into(),
            state: state.into(),
            observed_since: Some(t("2026-09-20 00:00")),
            computed_at: Some(t("2026-09-27 00:00")),
            report_digests: "x@trivy-operator".into(),
        }
    }

    fn key() -> crate::workload_profile::Key {
        crate::workload_profile::Key {
            namespace: "prod".into(),
            kind: "Deployment".into(),
            name: "api".into(),
        }
    }

    #[test]
    fn vex_statements_only_where_every_container_is_covered_and_unseen() {
        let rows = vec![
            vex_row("app", "installed_not_observed", "CVE-A"),
            vex_row("side", "installed_not_observed", "CVE-A"),
            vex_row("app", "installed_not_observed", "CVE-B"),
            vex_row("side", "loaded", "CVE-B"),
            vex_row("app", "unknown:capture_gap", "CVE-C"),
            vex_row("app", "unknown:language_package", "CVE-D"),
        ];
        let VexOutcome::Draft(d) = build_openvex(&key(), &rows, 24) else {
            panic!("expected a draft");
        };
        assert_eq!(d.statements, 1);
        let st = &d.doc["statements"][0];
        assert_eq!(st["vulnerability"]["name"], "CVE-A");
        assert_eq!(st["status"], "not_affected");
        assert_eq!(st["justification"], "vulnerable_code_not_in_execute_path");
        assert!(st["status_notes"].as_str().unwrap().contains("DRAFT"));
        assert!(st["status_notes"].as_str().unwrap().contains("168 h"));
        assert_eq!(d.doc["kguardian:draft"], true);
        assert!(d.doc["author"]
            .as_str()
            .unwrap()
            .contains("draft, requires human review"));
        assert_eq!(d.doc["@context"], "https://openvex.dev/ns/v0.2.0");
        assert!(d.doc["@id"]
            .as_str()
            .unwrap()
            .ends_with(d.input_hash.trim_start_matches("fnv1a64:")));
        assert!(st["products"][0]["@id"]
            .as_str()
            .unwrap()
            .starts_with("pkg:oci/app@sha256%3A"));
        assert_eq!(
            st["products"][0]["subcomponents"][0]["@id"],
            "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1"
        );
        // Deterministic.
        let VexOutcome::Draft(again) = build_openvex(&key(), &rows, 24) else {
            panic!()
        };
        assert_eq!(again.doc, d.doc);
        // A changed input changes the hash.
        let mut rows2 = rows.clone();
        rows2[3].state = "installed_not_observed".into();
        let VexOutcome::Draft(d2) = build_openvex(&key(), &rows2, 24) else {
            panic!()
        };
        assert_ne!(d2.input_hash, d.input_hash);
        assert_eq!(d2.statements, 2);
    }

    #[test]
    fn a_finding_cut_by_the_row_cap_is_dropped_whole() {
        // CVE-A has two containers; the cap lands between them, and the
        // missing one ('side') had loaded the package.
        let mut rows = vec![
            vex_row("app", "installed_not_observed", "CVE-0"),
            vex_row("app", "installed_not_observed", "CVE-A"),
            vex_row("side", "loaded", "CVE-A"),
        ];
        drop_partial_group(&mut rows, 2);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].vuln_id, "CVE-0");
        let mut under = vec![vex_row("app", "installed_not_observed", "CVE-0")];
        drop_partial_group(&mut under, 2);
        assert_eq!(under.len(), 1);
    }

    #[test]
    fn vex_is_unavailable_without_a_qualifying_statement() {
        let rows = vec![
            vex_row("app", "unknown:no_runtime_data", "CVE-A"),
            vex_row("app", "executed", "CVE-B"),
        ];
        assert!(matches!(
            build_openvex(&key(), &rows, 24),
            VexOutcome::Unavailable(_)
        ));
    }
}
