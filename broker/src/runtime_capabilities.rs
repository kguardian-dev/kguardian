//! Capability use per workload container (#1533 P2-7) and the evidence
//! behind a minimal `securityContext.capabilities` recommendation.
//!
//! # Ingest
//!
//! `POST /runtime/capabilities` (ingest scope): the controller's per
//! container counts of capability checks, per capability and verdict, as
//! deltas since its previous post. One row per (workload, container,
//! digest, capability, verdict); counts add up across replicas. A running
//! container's rows are re-reported hourly with a zero delta, which keeps
//! `last_reported` fresh: retention prunes by it, so a capability used
//! once at startup is kept while the workload runs.
//!
//! # Recommendation
//!
//! [`build_view`] turns the rows into, per container: what was used
//! (granted), what was asked for and refused, and, only when the evidence
//! is sufficient, `drop: [ALL]` plus `add` = every capability the
//! container was ever seen to use, under any of its digests. Evidence is
//! sufficient when `kg_capability_coverage` says every current digest of
//! the container was watched continuously for the window (probes loaded
//! from start or since a backfill, no lost events, no heartbeat gaps, the
//! capability probe on throughout). Otherwise there is no recommendation
//! and the view says why. A used capability is never recommended for
//! dropping.

use crate::image_inventory::{is_valid_digest, ContainerImages, DEFAULT_CLUSTER_ID};
use crate::read_budget::{cost_kib, ReadBudget};
use crate::runtime_inventory::IngestSummary;
use actix_web::{get, web, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Bool, Integer, Nullable, Text, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tracing::warn;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Entries accepted in one post, counted while parsing.
pub const MAX_CAP_ENTRIES: usize = 5_000;
/// Body limit of the ingest route (an entry is ~350 bytes).
pub const CAP_BODY_LIMIT_BYTES: usize = 4 << 20;
const MAX_NAME_LEN: usize = 253;
const MAX_KIND_LEN: usize = 63;
const MAX_CAP_LEN: usize = 32;
const TOO_MANY: &str = "too many entries";

/// Coverage window for capability evidence, in hours
/// (`CAPABILITY_EVIDENCE_WINDOW_HOURS`, default 168 = 7 days, clamped to
/// [24, 2160]). Long on purpose: a capability used only weekly must have
/// had a chance to show up before "never used" is claimed.
pub fn evidence_window_hours() -> i32 {
    std::env::var("CAPABILITY_EVIDENCE_WINDOW_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(168)
        .clamp(24, 2160)
}

// ---------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------

/// One posted entry (controller `runtime_capabilities::CapPost`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CapEntry {
    pub pod_namespace: String,
    #[serde(default)]
    pub pod_name: Option<String>,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    #[serde(default)]
    pub image_digest: String,
    pub capability: String,
    pub granted: bool,
    /// Checks since the previous post of this entry.
    pub count: u64,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

struct CapBatch(Vec<CapEntry>);

impl<'de> Deserialize<'de> for CapBatch {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CapBatch;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a JSON array of at most {MAX_CAP_ENTRIES} entries")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<CapBatch, A::Error> {
                let mut out = Vec::with_capacity(a.size_hint().unwrap_or(0).min(1024));
                loop {
                    if out.len() == MAX_CAP_ENTRIES {
                        if a.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(TOO_MANY));
                        }
                        return Ok(CapBatch(out));
                    }
                    match a.next_element::<CapEntry>()? {
                        Some(e) => out.push(e),
                        None => return Ok(CapBatch(out)),
                    }
                }
            }
        }
        d.deserialize_seq(V)
    }
}

/// Parse a batch. `Err(None)` = over the cap (413), `Err(Some)` = malformed
/// (400).
pub fn parse_caps(body: &[u8]) -> Result<Vec<CapEntry>, Option<String>> {
    let mut de = serde_json::Deserializer::from_slice(body);
    match CapBatch::deserialize(&mut de).and_then(|b| de.end().map(|_| b)) {
        Ok(b) => Ok(b.0),
        Err(e) if e.to_string().contains(TOO_MANY) => Err(None),
        Err(e) => Err(Some(e.to_string())),
    }
}

fn name_ok(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.contains('\0') && s.trim() == s
}

/// A capability as Kubernetes spells it: upper case, digits and `_`.
pub fn capability_ok(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= MAX_CAP_LEN
        && c.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Validate one entry; `None` = drop it.
pub fn valid(e: CapEntry) -> Option<CapEntry> {
    let ok = name_ok(&e.pod_namespace, MAX_NAME_LEN)
        && name_ok(&e.workload_kind, MAX_KIND_LEN)
        && name_ok(&e.workload_name, MAX_NAME_LEN)
        && name_ok(&e.container_name, MAX_NAME_LEN)
        && e.pod_name
            .as_deref()
            .is_none_or(|p| name_ok(p, MAX_NAME_LEN))
        && (e.image_digest.is_empty() || is_valid_digest(&e.image_digest))
        && capability_ok(&e.capability)
        && e.count <= i64::MAX as u64;
    ok.then_some(e)
}

type CapKey<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, &'a str, bool);

fn key(e: &CapEntry) -> CapKey<'_> {
    (
        &e.pod_namespace,
        &e.workload_kind,
        &e.workload_name,
        &e.container_name,
        &e.image_digest,
        &e.capability,
        e.granted,
    )
}

/// Merge entries for the same row (one INSERT may not touch a row twice):
/// counts add up, times widen.
pub fn merge(mut rows: Vec<CapEntry>) -> Vec<CapEntry> {
    rows.sort_by(|a, b| key(a).cmp(&key(b)));
    let mut out: Vec<CapEntry> = Vec::with_capacity(rows.len());
    for r in rows {
        match out.last_mut() {
            Some(m) if key(m) == key(&r) => {
                m.count = m.count.saturating_add(r.count);
                m.first_seen = m.first_seen.min(r.first_seen);
                if r.last_seen >= m.last_seen {
                    m.last_seen = r.last_seen;
                    if r.pod_name.is_some() {
                        m.pod_name = r.pod_name;
                    }
                }
            }
            _ => out.push(r),
        }
    }
    out
}

pub(crate) const CAP_UPSERT_SQL: &str = "\
INSERT INTO runtime_capabilities AS r (cluster_id, pod_namespace, workload_kind, workload_name, \
    container_name, image_digest, capability, granted, count, last_pod_name, first_seen, \
    last_seen, last_reported) \
SELECT $1, t.ns, t.wk, t.wn, t.cn, t.dg, t.cap, t.gr, t.n, t.lpn, \
    LEAST(t.fs, t.ls, timezone('UTC', NOW())), LEAST(t.ls, timezone('UTC', NOW())), \
    timezone('UTC', NOW()) \
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], \
    $8::bool[], $9::bigint[], $10::text[], $11::timestamp[], $12::timestamp[]) \
    AS t(ns, wk, wn, cn, dg, cap, gr, n, lpn, fs, ls) \
ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name, container_name, \
    image_digest, capability, granted) \
DO UPDATE SET \
    count = r.count + EXCLUDED.count, \
    first_seen = LEAST(r.first_seen, EXCLUDED.first_seen), \
    last_seen = GREATEST(r.last_seen, EXCLUDED.last_seen), \
    last_reported = EXCLUDED.last_reported, \
    last_pod_name = COALESCE(EXCLUDED.last_pod_name, r.last_pod_name)";

/// Upsert a validated, merged batch in one statement.
pub fn upsert(conn: &mut PgConnection, rows: &[CapEntry]) -> Result<usize, DbError> {
    if rows.is_empty() {
        return Ok(0);
    }
    let col = |f: fn(&CapEntry) -> &str| -> Vec<&str> { rows.iter().map(f).collect() };
    Ok(sql_query(CAP_UPSERT_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Array<Text>, _>(col(|r| &r.pod_namespace))
        .bind::<Array<Text>, _>(col(|r| &r.workload_kind))
        .bind::<Array<Text>, _>(col(|r| &r.workload_name))
        .bind::<Array<Text>, _>(col(|r| &r.container_name))
        .bind::<Array<Text>, _>(col(|r| &r.image_digest))
        .bind::<Array<Text>, _>(col(|r| &r.capability))
        .bind::<Array<Bool>, _>(rows.iter().map(|r| r.granted).collect::<Vec<_>>())
        .bind::<Array<BigInt>, _>(rows.iter().map(|r| r.count as i64).collect::<Vec<_>>())
        .bind::<Array<Nullable<Text>>, _>(
            rows.iter()
                .map(|r| r.pod_name.as_deref())
                .collect::<Vec<_>>(),
        )
        .bind::<Array<Timestamp>, _>(rows.iter().map(|r| r.first_seen).collect::<Vec<_>>())
        .bind::<Array<Timestamp>, _>(rows.iter().map(|r| r.last_seen).collect::<Vec<_>>())
        .execute(conn)?)
}

async fn post_capabilities(
    pool: web::Data<DbPool>,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    let entries = match parse_caps(&body) {
        Ok(v) => v,
        Err(None) => {
            return Ok(HttpResponse::PayloadTooLarge().body(format!(
                "at most {MAX_CAP_ENTRIES} entries per post; chunk the batch"
            )))
        }
        Err(Some(e)) => {
            return Ok(HttpResponse::BadRequest().body(format!("invalid capability batch: {e}")))
        }
    };
    drop(body);
    let total = entries.len();
    let valid_rows: Vec<CapEntry> = entries.into_iter().filter_map(valid).collect();
    let dropped = total - valid_rows.len();
    if dropped > 0 {
        warn!(dropped, "/runtime/capabilities entries malformed; dropped");
    }
    let rows = merge(valid_rows);
    let accepted = rows.len();
    let written = web::block(move || {
        let mut conn = pool.get()?;
        upsert(&mut conn, &rows)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(IngestSummary {
        accepted,
        dropped,
        written,
    }))
}

/// `POST /runtime/capabilities` with its own body limit.
pub fn runtime_capabilities_resource() -> impl actix_web::dev::HttpServiceFactory {
    web::resource("/runtime/capabilities")
        .wrap(::actix_web::middleware::from_fn(crate::auth::authorize))
        .app_data(web::PayloadConfig::new(CAP_BODY_LIMIT_BYTES))
        .route(web::post().to(post_capabilities))
}

// ---------------------------------------------------------------------
// Evidence and recommendation
// ---------------------------------------------------------------------

/// Rows read for one workload at most (containers x digests x
/// capabilities x verdict is small in practice).
pub const CAP_ROWS_MAX: i64 = 5_000;

#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct CapRow {
    #[diesel(sql_type = Text)]
    pub container_name: String,
    #[diesel(sql_type = Text)]
    pub image_digest: String,
    #[diesel(sql_type = Text)]
    pub capability: String,
    #[diesel(sql_type = Bool)]
    pub granted: bool,
    #[diesel(sql_type = BigInt)]
    pub count: i64,
    #[diesel(sql_type = Timestamp)]
    pub first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    pub last_seen: NaiveDateTime,
}

/// `kg_capability_coverage` for one (container, digest).
#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct CapCoverageRow {
    #[diesel(sql_type = Text)]
    pub container_name: String,
    #[diesel(sql_type = Text)]
    pub image_digest: String,
    #[diesel(sql_type = Nullable<Bool>)]
    pub covered: Option<bool>,
    #[diesel(sql_type = Nullable<Timestamp>)]
    pub observed_since: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    pub reason: Option<String>,
}

/// What [`build_view`] needs for one workload.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapEvidence {
    pub rows: Vec<CapRow>,
    pub rows_truncated: bool,
    pub coverage: Vec<CapCoverageRow>,
    pub window_hours: i32,
}

/// Read the evidence: every row of the workload, and the capability
/// coverage of each (container, digest) in `current`.
pub fn load_evidence(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
    current: &[(String, String)],
    window_hours: i32,
) -> Result<CapEvidence, DbError> {
    let mut rows: Vec<CapRow> = sql_query(
        "SELECT container_name, image_digest, capability, granted, count, first_seen, last_seen \
         FROM runtime_capabilities \
         WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
         ORDER BY container_name, capability, granted DESC, image_digest LIMIT $5",
    )
    .bind::<Text, _>(DEFAULT_CLUSTER_ID)
    .bind::<Text, _>(ns)
    .bind::<Text, _>(kind)
    .bind::<Text, _>(name)
    .bind::<BigInt, _>(CAP_ROWS_MAX + 1)
    .load(conn)?;
    let rows_truncated = rows.len() as i64 > CAP_ROWS_MAX;
    rows.truncate(CAP_ROWS_MAX as usize);
    let (cn, dg): (Vec<&str>, Vec<&str>) = current
        .iter()
        .map(|(c, d)| (c.as_str(), d.as_str()))
        .unzip();
    let coverage: Vec<CapCoverageRow> = if current.is_empty() {
        Vec::new()
    } else {
        sql_query(
            "SELECT t.cn AS container_name, t.dg AS image_digest, k.covered, k.observed_since, \
                 k.reason \
             FROM unnest($5::text[], $6::text[]) AS t(cn, dg) \
             LEFT JOIN LATERAL kg_capability_coverage($1, $2, $3, $4, t.cn, t.dg, $7) k ON true",
        )
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(ns)
        .bind::<Text, _>(kind)
        .bind::<Text, _>(name)
        .bind::<Array<Text>, _>(cn)
        .bind::<Array<Text>, _>(dg)
        .bind::<Integer, _>(window_hours)
        .load(conn)?
    };
    Ok(CapEvidence {
        rows,
        rows_truncated,
        coverage,
        window_hours,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapUse {
    pub capability: String,
    pub count: i64,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapRecommendation {
    pub drop: Vec<String>,
    pub add: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerCaps {
    pub container: String,
    /// Current digests the evidence must cover.
    pub digests: Vec<String>,
    /// `sufficient`: every current digest was watched for the whole window;
    /// `insufficient`: see `reason`.
    pub evidence: &'static str,
    /// The first coverage reason of an uncovered digest, or
    /// `no_current_digest`, `rows_truncated`.
    pub reason: Option<String>,
    pub observed_since: Option<NaiveDateTime>,
    /// Checks that succeeded, over every digest of the container.
    pub used: Vec<CapUse>,
    /// Checks the container made without holding the capability.
    pub denied: Vec<CapUse>,
    /// Only with sufficient evidence: drop ALL, add every used capability.
    pub recommendation: Option<CapRecommendation>,
    /// Capabilities the current securityContext adds that were never used
    /// (only with sufficient evidence).
    pub unused_added: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesView {
    pub window_hours: i32,
    pub containers: Vec<ContainerCaps>,
}

/// The container's current added capabilities (newest current digest).
fn current_add(c: &ContainerImages) -> Vec<String> {
    c.digests
        .first()
        .and_then(|d| d.security_context.get("capabilitiesAdd").cloned())
        .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
        .unwrap_or_default()
}

/// Build the view. Pure. A used capability is never left out of `add`.
pub fn build_view(containers: &[ContainerImages], ev: &CapEvidence) -> CapabilitiesView {
    let mut out = Vec::new();
    for c in containers {
        let digests: Vec<String> = c.digests.iter().map(|d| d.digest.clone()).collect();
        let mut used: BTreeMap<String, CapUse> = BTreeMap::new();
        let mut denied: BTreeMap<String, CapUse> = BTreeMap::new();
        for r in ev
            .rows
            .iter()
            .filter(|r| r.container_name == c.container_name)
        {
            let m = if r.granted { &mut used } else { &mut denied };
            let e = m.entry(r.capability.clone()).or_insert(CapUse {
                capability: r.capability.clone(),
                count: 0,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
            });
            e.count = e.count.saturating_add(r.count);
            e.first_seen = e.first_seen.min(r.first_seen);
            e.last_seen = e.last_seen.max(r.last_seen);
        }
        let cov: Vec<&CapCoverageRow> = ev
            .coverage
            .iter()
            .filter(|k| k.container_name == c.container_name && digests.contains(&k.image_digest))
            .collect();
        let uncovered =
            digests
                .iter()
                .find_map(|d| match cov.iter().find(|k| &k.image_digest == d) {
                    Some(k) if k.covered == Some(true) => None,
                    Some(k) => Some(k.reason.clone().unwrap_or_else(|| "no_runtime_data".into())),
                    None => Some("no_runtime_data".into()),
                });
        let reason = if digests.is_empty() {
            Some("no_current_digest".to_string())
        } else if ev.rows_truncated {
            Some("rows_truncated".to_string())
        } else {
            uncovered
        };
        let sufficient = reason.is_none();
        let observed_since = cov.iter().filter_map(|k| k.observed_since).max();
        let used_names: BTreeSet<String> = used.keys().cloned().collect();
        let (recommendation, unused_added) = if sufficient {
            let unused: Vec<String> = current_add(c)
                .into_iter()
                .filter(|a| !used_names.contains(a) && a != "ALL")
                .collect();
            (
                Some(CapRecommendation {
                    drop: vec!["ALL".into()],
                    add: used_names.iter().cloned().collect(),
                }),
                unused,
            )
        } else {
            (None, Vec::new())
        };
        out.push(ContainerCaps {
            container: c.container_name.clone(),
            digests,
            evidence: if sufficient {
                "sufficient"
            } else {
                "insufficient"
            },
            reason,
            observed_since,
            used: used.into_values().collect(),
            denied: denied.into_values().collect(),
            recommendation,
            unused_added,
        });
    }
    CapabilitiesView {
        window_hours: ev.window_hours,
        containers: out,
    }
}

/// Current (container, digest) pairs of a workload.
pub fn current_pairs(containers: &[ContainerImages]) -> Vec<(String, String)> {
    containers
        .iter()
        .flat_map(|c| {
            c.digests
                .iter()
                .map(move |d| (c.container_name.clone(), d.digest.clone()))
        })
        .collect()
}

/// Rows charged to the read budget for one capabilities read.
pub const CAP_READ_COST_ROWS: i64 = CAP_ROWS_MAX + 200;
const CAP_ROW_COST_BYTES: u64 = 512;

/// `GET /workloads/{ns}/{kind}/{name}/capabilities`: the same view the
/// profile carries. 200 with no containers when nothing is known.
#[get(
    "/workloads/{namespace}/{kind}/{name}/capabilities",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_capabilities(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    if [&ns, &kind, &name]
        .iter()
        .any(|s| s.trim().is_empty() || s.len() > MAX_NAME_LEN)
    {
        return Ok(HttpResponse::BadRequest().body("namespace, kind and name are required"));
    }
    let _permit = match budget
        .acquire(cost_kib(CAP_READ_COST_ROWS, CAP_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let window = evidence_window_hours();
    let view = web::block(move || {
        let mut conn = pool.get()?;
        let wc = crate::image_inventory::workload_containers(&mut conn, &ns, &kind, &name)?;
        let ev = load_evidence(
            &mut conn,
            &ns,
            &kind,
            &name,
            &current_pairs(&wc.containers),
            window,
        )?;
        Ok::<_, DbError>(build_view(&wc.containers, &ev))
    })
    .await?
    .map_err(|e| {
        warn!(error = %e, "capabilities read failed");
        actix_web::error::ErrorInternalServerError(e)
    })?;
    Ok(HttpResponse::Ok().json(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_inventory::ContainerDigest;
    use serde_json::json;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn t(h: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(1_800_000_000 + h * 3600, 0)
            .unwrap()
            .naive_utc()
    }

    fn entry(cap: &str, granted: bool, n: u64) -> serde_json::Value {
        json!({
            "pod_namespace": "ns", "pod_name": "web-1", "workload_kind": "Deployment",
            "workload_name": "web", "container_name": "app", "image_digest": D,
            "capability": cap, "granted": granted, "count": n,
            "first_seen": "2026-09-26T10:00:00", "last_seen": "2026-09-26T11:00:00"
        })
    }

    #[test]
    fn the_cap_is_enforced_while_parsing_and_bad_entries_are_dropped() {
        let one = entry("NET_RAW", true, 1).to_string();
        let body = |n: usize| format!("[{}]", vec![one.as_str(); n].join(","));
        assert_eq!(
            parse_caps(body(MAX_CAP_ENTRIES).as_bytes()).unwrap().len(),
            MAX_CAP_ENTRIES
        );
        assert_eq!(parse_caps(body(MAX_CAP_ENTRIES + 1).as_bytes()), Err(None));
        assert!(matches!(parse_caps(b"{}"), Err(Some(_))));
        let parsed = parse_caps(
            json!([
                entry("NET_RAW", true, 1),
                entry("net_raw", true, 1),
                entry("CAP_42", true, 1),
                entry("NET_RAW; DROP", true, 1),
                entry(&"X".repeat(40), true, 1),
            ])
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let kept: Vec<String> = parsed
            .into_iter()
            .filter_map(valid)
            .map(|e| e.capability)
            .collect();
        assert_eq!(kept, vec!["NET_RAW", "CAP_42"]);
    }

    #[test]
    fn a_batch_merges_counts_per_row() {
        let rows: Vec<CapEntry> = [
            entry("NET_RAW", true, 2),
            entry("NET_RAW", true, 3),
            entry("NET_RAW", false, 1),
        ]
        .into_iter()
        .map(|v| serde_json::from_value(v).unwrap())
        .collect();
        let m = merge(rows);
        assert_eq!(m.len(), 2, "the verdict is part of the key");
        assert_eq!(m.iter().find(|r| r.granted).unwrap().count, 5);
    }

    fn container(add: &[&str], digests: &[&str]) -> ContainerImages {
        let d = |digest: &str| ContainerDigest {
            digest: digest.into(),
            image_ref: "img".into(),
            security_context: json!({"capabilitiesAdd": add}),
            pod_security: json!({}),
            last_pod_name: None,
            first_seen: t(0),
            last_seen: t(1),
            state: Some("running".into()),
            state_reason: None,
            ran_as_init: false,
        };
        ContainerImages {
            cluster_id: "primary".into(),
            container_name: "app".into(),
            container_kind: "regular".into(),
            mixed_digests: false,
            digests: digests.iter().map(|x| d(x)).collect(),
            previous_digests: vec![],
        }
    }

    fn row(digest: &str, cap: &str, granted: bool, n: i64) -> CapRow {
        CapRow {
            container_name: "app".into(),
            image_digest: digest.into(),
            capability: cap.into(),
            granted,
            count: n,
            first_seen: t(0),
            last_seen: t(1),
        }
    }

    fn cov(digest: &str, covered: bool, reason: Option<&str>) -> CapCoverageRow {
        CapCoverageRow {
            container_name: "app".into(),
            image_digest: digest.into(),
            covered: Some(covered),
            observed_since: Some(t(-200)),
            reason: reason.map(String::from),
        }
    }

    #[test]
    fn sufficient_evidence_recommends_drop_all_plus_every_used_capability() {
        let ev = CapEvidence {
            rows: vec![
                row(D, "NET_BIND_SERVICE", true, 5),
                // Used under an older digest: still never dropped.
                row(D2, "SYS_TIME", true, 1),
                row(D, "SYS_ADMIN", false, 2),
            ],
            coverage: vec![cov(D, true, None)],
            window_hours: 168,
            ..Default::default()
        };
        let v = build_view(&[container(&["NET_ADMIN", "NET_BIND_SERVICE"], &[D])], &ev);
        let c = &v.containers[0];
        assert_eq!(c.evidence, "sufficient");
        assert_eq!(
            c.recommendation,
            Some(CapRecommendation {
                drop: vec!["ALL".into()],
                add: vec!["NET_BIND_SERVICE".into(), "SYS_TIME".into()],
            })
        );
        assert_eq!(c.unused_added, vec!["NET_ADMIN"]);
        assert_eq!(c.denied.len(), 1);
        assert_eq!(c.denied[0].capability, "SYS_ADMIN");
        assert_eq!(
            c.used
                .iter()
                .find(|u| u.capability == "NET_BIND_SERVICE")
                .unwrap()
                .count,
            5
        );
    }

    #[test]
    fn any_uncovered_current_digest_means_no_recommendation() {
        let base = CapEvidence {
            rows: vec![row(D, "NET_BIND_SERVICE", true, 5)],
            coverage: vec![
                cov(D, true, None),
                cov(D2, false, Some("capabilities_not_tracked")),
            ],
            window_hours: 168,
            ..Default::default()
        };
        // Two current digests, one not covered.
        let v = build_view(&[container(&[], &[D, D2])], &base);
        let c = &v.containers[0];
        assert_eq!(
            (c.evidence, c.reason.as_deref()),
            ("insufficient", Some("capabilities_not_tracked"))
        );
        assert!(c.recommendation.is_none() && c.unused_added.is_empty());
        assert_eq!(c.used.len(), 1, "what was seen is still shown");
        // No coverage row at all.
        let v = build_view(
            &[container(&[], &[D])],
            &CapEvidence {
                coverage: vec![],
                ..base.clone()
            },
        );
        assert_eq!(v.containers[0].reason.as_deref(), Some("no_runtime_data"));
        // Truncated rows: the used set may be incomplete.
        let v = build_view(
            &[container(&[], &[D])],
            &CapEvidence {
                rows_truncated: true,
                ..base.clone()
            },
        );
        assert_eq!(v.containers[0].reason.as_deref(), Some("rows_truncated"));
        // No current digest.
        let v = build_view(&[container(&[], &[])], &base);
        assert_eq!(v.containers[0].reason.as_deref(), Some("no_current_digest"));
    }

    // ---- live database -------------------------------------------------

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel_migrations::MigrationHarness;
        let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("migrate");
        conn
    }

    fn beat(
        cid: &str,
        cap_probe: bool,
        tracking_h: i64,
    ) -> crate::runtime_inventory::CoverageEntry {
        let now = chrono::Utc::now().naive_utc();
        crate::runtime_inventory::CoverageEntry {
            pod_namespace: "capns".into(),
            pod_name: format!("{cid}-pod"),
            workload_kind: "Deployment".into(),
            workload_name: "capweb".into(),
            container_name: "app".into(),
            image_digest: D.into(),
            container_id: cid.into(),
            node_name: "n1".into(),
            mode: "full".into(),
            exec_probe: true,
            lib_probe: true,
            start_mode: "start".into(),
            tracking_since: now - chrono::Duration::hours(tracking_h),
            events_dropped: 0,
            unsent: 0,
            incomplete: false,
            cap_probe,
            ended: false,
            heartbeat_at: now,
            heartbeat_secs: 300,
        }
    }

    fn post(conn: &mut PgConnection, cap: &str, granted: bool, n: u64, digest: &str) {
        let mut e = entry(cap, granted, n);
        e["pod_namespace"] = json!("capns");
        e["workload_name"] = json!("capweb");
        e["image_digest"] = json!(digest);
        let rows: Vec<CapEntry> = vec![serde_json::from_value(e).unwrap()];
        upsert(conn, &merge(rows.into_iter().filter_map(valid).collect())).unwrap();
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_evidence_drives_the_profile_and_its_patch() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        let clean = "DELETE FROM runtime_capabilities WHERE pod_namespace = 'capns'; \
             DELETE FROM runtime_coverage WHERE pod_namespace = 'capns'; \
             DELETE FROM runtime_executables WHERE pod_namespace = 'capns'; \
             DELETE FROM workload_containers WHERE pod_namespace = 'capns';";
        conn.batch_execute(clean).unwrap();
        conn.batch_execute(&format!(
            "INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, image_digest, container_kind, image_ref, security_context, \
               pod_security, last_pod_name, state) VALUES \
             ('capns', 'Deployment', 'capweb', 'app', '{D}', 'regular', 'img:1', \
               '{{\"capabilitiesAdd\": [\"NET_ADMIN\", \"NET_BIND_SERVICE\"], \"allowPrivilegeEscalation\": false}}', \
               '{{}}', 'w-1', 'running');"
        ))
        .unwrap();
        let key = crate::workload_profile::Key {
            namespace: "capns".into(),
            kind: "Deployment".into(),
            name: "capweb".into(),
        };
        let profile = |conn: &mut PgConnection| {
            let s = crate::workload_profile::load_sources(conn, &key).unwrap();
            crate::workload_profile::build(&key, &s, chrono::Utc::now())
        };

        // Capability probe on, watched from start 200 h ago.
        crate::runtime_inventory::upsert_coverage(&mut conn, &[beat("c1", true, 200)]).unwrap();
        post(&mut conn, "NET_BIND_SERVICE", true, 3, D);
        post(&mut conn, "NET_BIND_SERVICE", true, 2, D);
        post(&mut conn, "SYS_TIME", true, 1, D2);
        post(&mut conn, "SYS_ADMIN", false, 4, D);

        let p = profile(&mut conn);
        let c = &p.capabilities.containers[0];
        assert_eq!((c.evidence, c.reason.as_deref()), ("sufficient", None));
        assert_eq!(
            c.used
                .iter()
                .map(|u| (u.capability.as_str(), u.count))
                .collect::<Vec<_>>(),
            vec![("NET_BIND_SERVICE", 5), ("SYS_TIME", 1)],
            "counts add up across posts; an older digest's use counts"
        );
        assert_eq!(c.denied[0].capability, "SYS_ADMIN");
        assert_eq!(
            c.recommendation.as_ref().unwrap().add,
            vec!["NET_BIND_SERVICE", "SYS_TIME"]
        );
        assert_eq!(c.unused_added, vec!["NET_ADMIN"]);
        let rec = p
            .dimensions
            .pod_security
            .analysis
            .recommendation
            .as_ref()
            .unwrap();
        eprintln!("{}", rec.yaml);
        assert!(rec.yaml.contains("drop: [\"ALL\"]"));
        assert!(rec
            .yaml
            .contains("add: [\"NET_BIND_SERVICE\", \"SYS_TIME\"]"));
        assert!(
            !rec.yaml.contains("NET_ADMIN\", \""),
            "the unused capability goes"
        );
        assert!(rec.caveats.iter().any(|c| c.contains("used SYS_TIME")));
        // The export bundle's securitycontext artifact carries the same patch.
        let plan = crate::profile_export::plan(&crate::profile_export::ExportQuery {
            artifacts: Some("securitycontext".into()),
            mode: None,
            format: None,
            acknowledge_partial: None,
            record: None,
        })
        .unwrap();
        let docs = crate::profile_export::build_documents(&mut conn, &key, &p, &plan).unwrap();
        let bundle = crate::profile_export::render_bundle_yaml(&key, &p, &plan, &docs, false);
        assert!(
            bundle.contains("add: [\"NET_BIND_SERVICE\", \"SYS_TIME\"]  # observed in use"),
            "{bundle}"
        );
        let v = serde_json::to_value(&p).unwrap();
        eprintln!(
            "CAPABILITIES_JSON {}",
            serde_json::to_string_pretty(&v["capabilities"]).unwrap()
        );
        assert_eq!(v["capabilities"]["windowHours"], json!(168));
        assert_eq!(
            v["capabilities"]["containers"][0]["evidence"],
            json!("sufficient")
        );

        // The capability probe was off for this instance: no evidence, the
        // restricted default, and the profile says why.
        conn.batch_execute("DELETE FROM runtime_coverage WHERE pod_namespace = 'capns'")
            .unwrap();
        crate::runtime_inventory::upsert_coverage(&mut conn, &[beat("c2", false, 200)]).unwrap();
        let p = profile(&mut conn);
        let c = &p.capabilities.containers[0];
        assert_eq!(
            (c.evidence, c.reason.as_deref()),
            ("insufficient", Some("capabilities_not_tracked"))
        );
        assert!(c.recommendation.is_none());
        let rec = p
            .dimensions
            .pod_security
            .analysis
            .recommendation
            .as_ref()
            .unwrap();
        assert!(!rec.yaml.contains("observed in use"));
        assert!(rec
            .caveats
            .iter()
            .any(|c| c.contains("restricted default, not observed evidence")));

        // Retention prunes by last_reported, not by last use.
        conn.batch_execute(
            "UPDATE runtime_capabilities SET last_seen = last_seen - INTERVAL '90 days' \
             WHERE pod_namespace = 'capns' AND capability = 'SYS_TIME'",
        )
        .unwrap();
        let pruned = crate::retention::prune_batch_for_tests(
            &mut conn,
            crate::retention::RUNTIME_CAPABILITIES_PRUNE_SQL,
            30,
            100,
        );
        assert_eq!(
            pruned, 0,
            "a capability still reported is kept however old its use"
        );
        conn.batch_execute(
            "UPDATE runtime_capabilities SET last_reported = last_reported - INTERVAL '40 days' \
             WHERE pod_namespace = 'capns' AND capability = 'SYS_TIME'",
        )
        .unwrap();
        assert_eq!(
            crate::retention::prune_batch_for_tests(
                &mut conn,
                crate::retention::RUNTIME_CAPABILITIES_PRUNE_SQL,
                30,
                100
            ),
            1
        );
        conn.batch_execute(clean).unwrap();
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_capability_coverage_needs_the_probe_throughout() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        conn.batch_execute("DELETE FROM runtime_coverage WHERE pod_namespace = 'capns'")
            .unwrap();
        let ask = |conn: &mut PgConnection| -> CapCoverageRow {
            sql_query(
                "SELECT 'app'::text AS container_name, $1::text AS image_digest, k.covered, \
                   k.observed_since, k.reason \
                 FROM kg_capability_coverage('primary', 'capns', 'Deployment', 'capweb', 'app', $1, 168) k",
            )
            .bind::<Text, _>(D)
            .get_result(conn)
            .unwrap()
        };
        assert_eq!(ask(&mut conn).reason.as_deref(), Some("no_runtime_data"));
        crate::runtime_inventory::upsert_coverage(&mut conn, &[beat("k1", true, 200)]).unwrap();
        assert_eq!(ask(&mut conn).covered, Some(true));
        // The probe went off: a probe change restarts the run, so the window
        // is no longer covered, and the probe is off now.
        let mut off = beat("k1", false, 200);
        off.heartbeat_at += chrono::Duration::seconds(1);
        crate::runtime_inventory::upsert_coverage(&mut conn, &[off]).unwrap();
        let a = ask(&mut conn);
        assert_eq!(a.covered, Some(false));
        assert!(
            ["capture_gap", "capabilities_not_tracked"].contains(&a.reason.as_deref().unwrap()),
            "{a:?}"
        );
        conn.batch_execute("DELETE FROM runtime_coverage WHERE pod_namespace = 'capns'")
            .unwrap();
    }
}
