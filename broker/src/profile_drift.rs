//! Workload profile drift (#1533 P2-5, the parts that need no exec
//! tracking). Pure detection over data the profile already loads, plus the
//! export record that anchors "drift since the last export".
//!
//! Three kinds, each a finding with dimension `drift` and an entry in the
//! profile's `drift.items`:
//!
//! - `tagMoved`: one container's image reference (a tag, not `@digest`)
//!   has resolved to more than one digest in the inventory. The tag was
//!   re-pointed (or nodes resolved it differently); what runs is no longer
//!   what the tag meant when it was first seen.
//! - `imageChangedSinceExport`: a current container runs a digest that the
//!   last exported profile did not contain (or the container is new since
//!   the export). Needs an export record; without one the check is not
//!   evaluated and says so.
//! - `securityContextRegression`: a Pod Security Standards check that
//!   passed in the baseline fails now. The baseline is the last export
//!   when there is one (what the operator accepted), else the newest
//!   stored profile version whose podSecurity content differs from the
//!   live one (the previous state).
//!
//! - `unshippedExecutable`: a current container ran an executable or
//!   loaded a library its image did not ship as it ran: written to the
//!   container's writable layer, run from a memfd, or deleted while
//!   running (the runtime inventory's "unshipped" origins, #1683). Needs
//!   the runtime inventory and its capture coverage: a container with no
//!   inventory or not covered is listed in `notEvaluated`, never read as
//!   "no drift". A row seen is reported whatever the coverage.
//!
//! Drift is not a core posture dimension (it never sets posture status);
//! its findings join `findings` / `attention`, and the snapshotter's list
//! summary carries counts that the `/metrics` gauge is built from.

use crate::image_inventory::{ContainerSecurity, PodSecurity, DEFAULT_CLUSTER_ID};
use crate::pod_security::{self, ContainerInput, Level};
use crate::workload_profile::{mk_finding, utc, Finding, ImageContainerView, Key};
use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Integer, Jsonb, Nullable, Text, Timestamp};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Stored versions read for the securityContext baseline.
pub const RECENT_VERSIONS: i64 = 10;
/// Export records kept per workload (older ones are trimmed on write).
pub const EXPORTS_MAX_PER_WORKLOAD: i64 = 20;

/// Failing PSS checks keyed `(container or "" for pod level, check id)`.
type FailingSet = BTreeMap<(String, String), Level>;

/// One `kguardian_workload_drift` series: namespace, kind, workload, type,
/// value.
pub type DriftSeries = (String, String, String, String, i64);

/// The latest export record of a workload.
#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct ExportBaseline {
    #[diesel(sql_type = BigInt)]
    pub id: i64,
    #[diesel(sql_type = Nullable<Integer>)]
    pub revision: Option<i32>,
    #[diesel(sql_type = Text)]
    pub content_hash: String,
    #[diesel(sql_type = Text)]
    pub mode: String,
    #[diesel(sql_type = Array<Text>)]
    pub artifacts: Vec<String>,
    /// `{ "images": <snapshot.images>, "podSecurity": <snapshot.podSecurity> }`
    /// at export time, so the baseline survives version trimming.
    #[diesel(sql_type = Jsonb)]
    pub baseline: Value,
    #[diesel(sql_type = Timestamp)]
    pub exported_at: NaiveDateTime,
}

/// One stored version's podSecurity part.
#[derive(Debug, Clone, QueryableByName, PartialEq)]
pub struct RecentVersion {
    #[diesel(sql_type = Integer)]
    pub revision: i32,
    #[diesel(sql_type = Timestamp)]
    pub created_at: NaiveDateTime,
    #[diesel(sql_type = Nullable<Text>)]
    pub pod_security_hash: Option<String>,
    #[diesel(sql_type = Jsonb)]
    pub pod_security: Value,
}

const LAST_EXPORT_SQL: &str = "\
SELECT id, revision, content_hash, mode, artifacts, baseline, exported_at \
FROM workload_profile_exports \
WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
ORDER BY exported_at DESC, id DESC LIMIT 1";

const RECENT_VERSIONS_SQL: &str = "\
SELECT revision, created_at, dimension_hashes->>'podSecurity' AS pod_security_hash, \
       coalesce(snapshot->'podSecurity', 'null'::jsonb) AS pod_security \
FROM workload_profile_versions \
WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
ORDER BY revision DESC LIMIT $5";

/// Both baselines for one workload; two bounded, indexed reads.
pub fn load_baselines(
    conn: &mut PgConnection,
    key: &Key,
) -> Result<(Option<ExportBaseline>, Vec<RecentVersion>), DbError> {
    let last: Option<ExportBaseline> = sql_query(LAST_EXPORT_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .get_result(conn)
        .optional()?;
    let recent: Vec<RecentVersion> = sql_query(RECENT_VERSIONS_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<BigInt, _>(RECENT_VERSIONS)
        .load(conn)?;
    Ok((last, recent))
}

/// Record that a bundle was handed out, as the "last exported profile"
/// baseline for drift. Trims the workload's records beyond
/// [`EXPORTS_MAX_PER_WORKLOAD`]; `retention.rs` ages the rest out.
#[allow(clippy::too_many_arguments)]
pub fn record_export(
    conn: &mut PgConnection,
    key: &Key,
    revision: Option<i32>,
    content_hash: &str,
    mode: &str,
    artifacts: &[String],
    snapshot: &Value,
) -> Result<i64, DbError> {
    #[derive(QueryableByName)]
    struct Id {
        #[diesel(sql_type = BigInt)]
        id: i64,
    }
    let baseline = json!({
        "images": snapshot.get("images").cloned().unwrap_or(Value::Null),
        "podSecurity": snapshot.get("podSecurity").cloned().unwrap_or(Value::Null),
    });
    conn.transaction::<_, DbError, _>(|conn| {
        let id: Id = sql_query(
            "INSERT INTO workload_profile_exports \
             (cluster_id, pod_namespace, workload_kind, workload_name, revision, content_hash, \
              mode, artifacts, baseline) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
        )
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<Nullable<Integer>, _>(revision)
        .bind::<Text, _>(content_hash)
        .bind::<Text, _>(mode)
        .bind::<Array<Text>, _>(artifacts)
        .bind::<Jsonb, _>(baseline)
        .get_result(conn)?;
        sql_query(
            "DELETE FROM workload_profile_exports WHERE id IN ( \
               SELECT id FROM workload_profile_exports \
               WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 \
                 AND workload_name = $4 \
               ORDER BY exported_at DESC, id DESC OFFSET $5)",
        )
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<Text, _>(&key.namespace)
        .bind::<Text, _>(&key.kind)
        .bind::<Text, _>(&key.name)
        .bind::<BigInt, _>(EXPORTS_MAX_PER_WORKLOAD)
        .execute(conn)?;
        Ok(id.id)
    })
}

// ---------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExportRef {
    pub revision: Option<i32>,
    pub content_hash: String,
    pub mode: String,
    pub artifacts: Vec<String>,
    pub exported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContextBaseline {
    /// `export` | `previousVersion`.
    pub source: &'static str,
    /// The version revision the baseline came from (`null` for an export
    /// taken before any version was stored).
    pub revision: Option<i32>,
    pub since: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DriftBaselines {
    /// The last export, `null` when this workload was never exported.
    pub export: Option<ExportRef>,
    /// The securityContext baseline, `null` when there is none (no export
    /// and no earlier version with different podSecurity content).
    pub security_context: Option<SecurityContextBaseline>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DriftItem {
    /// `tagMoved` | `imageChangedSinceExport` | `securityContextRegression`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub finding_id: String,
    pub severity: &'static str,
    /// Container name; `null` for a pod-level regression.
    pub container: Option<String>,
    /// Type-specific facts (see the contract, section 2.8).
    pub detail: Value,
}

/// A check that could not be evaluated for one container (or the whole
/// workload), and why. Never "no drift".
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NotEvaluated {
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// `null` = the whole workload.
    pub container: Option<String>,
    /// `no_inventory` | `no_runtime_data` | `capture_gap` | `truncated` |
    /// a reason the runtime coverage reports.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DriftView {
    pub baselines: DriftBaselines,
    /// Which checks ran for the whole workload: `tagMoved` always (when
    /// there is an inventory), `imageChangedSinceExport` only with an
    /// export, `securityContextRegression` only with a baseline, and
    /// `unshippedExecutable` only when every current container's capture
    /// covered it.
    pub evaluated: Vec<&'static str>,
    /// Per container, the checks that could not run and why (v1.6).
    pub not_evaluated: Vec<NotEvaluated>,
    pub items: Vec<DriftItem>,
}

// ---------------------------------------------------------------------
// Runtime input (unshippedExecutable)
// ---------------------------------------------------------------------

/// Unshipped rows read per workload; beyond this the read is truncated.
pub const UNSHIPPED_ROWS_MAX: i64 = 500;
/// Paths listed per drift item.
pub const UNSHIPPED_PATHS_PER_ITEM: usize = 20;

/// What the `unshippedExecutable` check reads from the runtime inventory
/// (#1683): the workload's unshipped rows and its capture coverage.
#[derive(Debug, Clone, Default)]
pub struct RuntimeDriftInput {
    /// The controller has reported any runtime inventory for the workload.
    pub has_inventory: bool,
    pub unshipped: Vec<crate::runtime_inventory::ContainerRuntime>,
    pub unshipped_truncated: bool,
    /// Per (container, digest) coverage over the default window.
    pub coverage: Vec<crate::runtime_inventory::CoverageView>,
}

/// Load the runtime input of one workload (bounded reads).
pub fn load_runtime(conn: &mut PgConnection, key: &Key) -> Result<RuntimeDriftInput, DbError> {
    use crate::runtime_inventory as ri;
    let has_inventory = ri::workload_has_inventory(conn, &key.namespace, &key.kind, &key.name)?;
    let coverage = ri::workload_coverage(
        conn,
        &key.namespace,
        &key.kind,
        &key.name,
        ri::DEFAULT_COVERAGE_WINDOW_HOURS,
    )?;
    let (unshipped, unshipped_truncated) = if has_inventory {
        let w = ri::workload_unshipped_executables(
            conn,
            &key.namespace,
            &key.kind,
            &key.name,
            UNSHIPPED_ROWS_MAX,
        )?;
        (w.containers, w.truncated)
    } else {
        (Vec::new(), false)
    };
    Ok(RuntimeDriftInput {
        has_inventory,
        unshipped,
        unshipped_truncated,
        coverage,
    })
}

/// Read-budget charge of [`load_runtime`].
pub fn runtime_charge_kib() -> u32 {
    crate::read_budget::cost_kib(UNSHIPPED_ROWS_MAX + 1, 1_024).saturating_add(
        crate::read_budget::cost_kib(crate::runtime_inventory::MAX_COVERAGE_GROUPS, 512),
    )
}

/// Severity of an unshipped item: a file written into the container or
/// run from memory is high; a file deleted while running (an in-place
/// upgrade can do that too) is medium.
fn unshipped_severity(origins: &BTreeSet<&str>) -> &'static str {
    if origins.contains("writableLayer") || origins.contains("memfd") {
        "high"
    } else {
        "medium"
    }
}

/// The `unshippedExecutable` check. Items for current containers' running
/// digests; `evaluated` only when every current running container is
/// covered and nothing was cut; otherwise `notEvaluated` entries.
fn unshipped_check(
    containers: &[ImageContainerView],
    rt: Option<&RuntimeDriftInput>,
) -> (bool, Vec<NotEvaluated>, Vec<DriftItem>) {
    const T: &str = "unshippedExecutable";
    let current: Vec<&ImageContainerView> = containers
        .iter()
        .filter(|c| !c.stale && !c.running.is_empty())
        .collect();
    let Some(rt) = rt else {
        return (
            false,
            vec![NotEvaluated {
                kind: T,
                container: None,
                reason: "no_inventory".into(),
            }],
            Vec::new(),
        );
    };
    let mut items = Vec::new();
    let mut not = Vec::new();
    for c in &current {
        let digests: BTreeSet<&str> = c.running.iter().map(|d| d.digest.as_str()).collect();
        // Positive evidence first: rows of this container's running digests.
        let mut entries: Vec<(&str, &crate::runtime_inventory::RuntimeEntry)> = rt
            .unshipped
            .iter()
            .filter(|r| r.container_name == c.name && digests.contains(r.image_digest.as_str()))
            .flat_map(|r| r.entries.iter().map(move |e| (r.image_digest.as_str(), e)))
            .collect();
        entries.sort_by(|a, b| {
            b.1.last_seen
                .cmp(&a.1.last_seen)
                .then(a.1.path.cmp(&b.1.path))
        });
        if !entries.is_empty() {
            let origins: BTreeSet<&str> = entries.iter().map(|(_, e)| e.origin.as_str()).collect();
            let total = entries.len();
            let files: Vec<Value> = entries
                .iter()
                .take(UNSHIPPED_PATHS_PER_ITEM)
                .map(|(d, e)| {
                    json!({
                        "path": e.path, "kind": e.kind, "origin": e.origin, "digest": d,
                        "pathComplete": e.path_complete, "firstSeen": utc(e.first_seen),
                        "lastSeen": utc(e.last_seen),
                    })
                })
                .collect();
            items.push(DriftItem {
                kind: T,
                finding_id: format!("drift.unshippedExecutable/{}", c.name),
                severity: unshipped_severity(&origins),
                container: Some(c.name.clone()),
                detail: json!({
                    "origins": origins,
                    "files": files,
                    "filesTotal": total,
                    "truncated": total > UNSHIPPED_PATHS_PER_ITEM || rt.unshipped_truncated,
                }),
            });
        }
        // Can "nothing unshipped" be claimed for this container?
        let reason = if !rt.has_inventory {
            Some("no_inventory".to_string())
        } else if rt.unshipped_truncated && entries.is_empty() {
            Some("truncated".to_string())
        } else {
            digests.iter().find_map(|d| {
                match rt
                    .coverage
                    .iter()
                    .find(|v| v.container_name == c.name && v.image_digest == *d)
                {
                    Some(v) if v.covered == Some(true) => None,
                    Some(v) => Some(
                        v.reason
                            .clone()
                            .filter(|r| !r.is_empty())
                            .unwrap_or_else(|| "capture_gap".into()),
                    ),
                    None => Some("no_runtime_data".into()),
                }
            })
        };
        if let Some(reason) = reason {
            not.push(NotEvaluated {
                kind: T,
                container: Some(c.name.clone()),
                reason,
            });
        }
    }
    let evaluated = !current.is_empty() && not.is_empty();
    (evaluated, not, items)
}

// ---------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------

/// Failing PSS checks of a stored podSecurity snapshot, keyed
/// `(container or "", check)`, plus its level. `None` when the snapshot has
/// no containers. Re-runs the analyser, so the rules are exactly the live
/// ones.
fn failing_of(kind: &str, ps: &Value) -> Option<(Option<Level>, FailingSet)> {
    let containers = ps.get("containers")?.as_object()?;
    if containers.is_empty() {
        return None;
    }
    let inputs: Vec<ContainerInput> = containers
        .iter()
        .map(|(name, c)| ContainerInput {
            name: name.clone(),
            kind: c
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("regular")
                .to_string(),
            source: "running",
            digest: String::new(),
            observed_capabilities: None,
            probed_capabilities: Vec::new(),
            probed_omitted: Vec::new(),
            security: c
                .get("securityContext")
                .cloned()
                .and_then(|v| serde_json::from_value::<ContainerSecurity>(v).ok())
                .unwrap_or_default(),
        })
        .collect();
    let pod: Option<PodSecurity> = ps
        .get("pod")
        .filter(|p| p.get("known").and_then(Value::as_bool) != Some(false))
        .filter(|p| p.is_object())
        .and_then(|p| serde_json::from_value(p.clone()).ok());
    let a = pod_security::analyse(kind, pod.as_ref(), &inputs);
    let mut out = BTreeMap::new();
    for f in &a.pod.failing {
        out.insert((String::new(), f.check.to_string()), f.level);
    }
    for c in &a.containers {
        for f in &c.failing {
            out.insert((c.name.clone(), f.check.to_string()), f.level);
        }
    }
    Some((a.level, out))
}

fn tag_moved(
    containers: &[ImageContainerView],
) -> Vec<(String, String, Vec<String>, DateTime<Utc>)> {
    let mut out = Vec::new();
    for c in containers.iter().filter(|c| !c.stale) {
        let mut by_ref: BTreeMap<&str, BTreeMap<&str, DateTime<Utc>>> = BTreeMap::new();
        for d in c.running.iter().chain(c.previous.iter()) {
            // Only a tag can move; a digest reference cannot.
            if d.image_ref.contains('@') {
                continue;
            }
            by_ref
                .entry(d.image_ref.as_str())
                .or_default()
                .insert(d.digest.as_str(), d.first_seen);
        }
        for (r, digests) in by_ref {
            if digests.len() > 1 {
                let since = digests.values().max().copied().expect("non-empty");
                out.push((
                    c.name.clone(),
                    r.to_string(),
                    digests.keys().map(|d| d.to_string()).collect(),
                    since,
                ));
            }
        }
    }
    out
}

/// Detect drift for one workload. `containers` are the images dimension's
/// containers; `snapshot` / `hashes` the live snapshot (see
/// `workload_profile::snapshot_of`).
pub fn detect(
    workload_kind: &str,
    containers: &[ImageContainerView],
    snapshot: &Value,
    hashes: &BTreeMap<&'static str, String>,
    s: &crate::workload_profile::Sources,
) -> (DriftView, Vec<Finding>) {
    let mut items: Vec<DriftItem> = Vec::new();
    let mut evaluated: Vec<&'static str> = Vec::new();

    // --- tag moved ---------------------------------------------------
    if !containers.is_empty() {
        evaluated.push("tagMoved");
        for (c, r, digests, since) in tag_moved(containers) {
            items.push(DriftItem {
                kind: "tagMoved",
                finding_id: format!("drift.tagMoved/{c}"),
                severity: "medium",
                container: Some(c),
                detail: json!({ "imageRef": r, "digests": digests, "since": since }),
            });
        }
    }

    // --- unshipped executables (runtime inventory) ---------------------------
    let (unshipped_ok, not_evaluated, unshipped_items) =
        unshipped_check(containers, s.runtime.as_ref());
    if unshipped_ok {
        evaluated.push("unshippedExecutable");
    }
    items.extend(unshipped_items);

    // --- image changed since export ---------------------------------------
    let export = s.last_export.as_ref();
    if let (Some(e), false) = (export, containers.is_empty()) {
        evaluated.push("imageChangedSinceExport");
        let base = e
            .baseline
            .get("images")
            .and_then(|i| i.get("containers"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for c in containers.iter().filter(|c| !c.stale) {
            let exported: BTreeSet<&str> = base
                .get(&c.name)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let running: BTreeSet<&str> = c.running.iter().map(|d| d.digest.as_str()).collect();
            let new: Vec<&str> = running.difference(&exported).copied().collect();
            if new.is_empty() {
                continue;
            }
            items.push(DriftItem {
                kind: "imageChangedSinceExport",
                finding_id: format!("drift.imageChangedSinceExport/{}", c.name),
                severity: "medium",
                container: Some(c.name.clone()),
                detail: json!({
                    "containerInExport": base.contains_key(&c.name),
                    "exportedDigests": exported,
                    "newDigests": new,
                }),
            });
        }
    }

    // --- securityContext regression ------------------------------------------
    let live_ps = snapshot.get("podSecurity").cloned().unwrap_or(Value::Null);
    let live_hash = hashes.get("podSecurity");
    let baseline: Option<(SecurityContextBaseline, Value)> = match export {
        Some(e) => e.baseline.get("podSecurity").map(|ps| {
            (
                SecurityContextBaseline {
                    source: "export",
                    revision: e.revision,
                    since: utc(e.exported_at),
                },
                ps.clone(),
            )
        }),
        None => s
            .recent_versions
            .iter()
            .find(|v| v.pod_security_hash.as_ref() != live_hash)
            .map(|v| {
                (
                    SecurityContextBaseline {
                        source: "previousVersion",
                        revision: Some(v.revision),
                        since: utc(v.created_at),
                    },
                    v.pod_security.clone(),
                )
            }),
    };
    if let Some((_, base_ps)) = &baseline {
        if let (Some((base_level, base_fail)), Some((live_level, live_fail))) = (
            failing_of(workload_kind, base_ps),
            failing_of(workload_kind, &live_ps),
        ) {
            evaluated.push("securityContextRegression");
            let base_containers: BTreeSet<String> = base_ps
                .get("containers")
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            // New failures per container that existed in the baseline
            // (a brand-new container is not a regression of anything).
            let mut per: BTreeMap<String, Vec<(String, Level)>> = BTreeMap::new();
            for ((c, check), lv) in &live_fail {
                let known = c.is_empty() || base_containers.contains(c);
                if known && !base_fail.contains_key(&(c.clone(), check.clone())) {
                    per.entry(c.clone()).or_default().push((check.clone(), *lv));
                }
            }
            for (c, checks) in per {
                let severity = if checks.iter().any(|(_, l)| *l == Level::Baseline) {
                    "high"
                } else {
                    "medium"
                };
                let label = if c.is_empty() {
                    "pod".to_string()
                } else {
                    c.clone()
                };
                items.push(DriftItem {
                    kind: "securityContextRegression",
                    finding_id: format!("drift.securityContextRegression/{label}"),
                    severity,
                    container: (!c.is_empty()).then_some(c),
                    detail: json!({
                        "newlyFailing": checks.iter().map(|(c, _)| c).collect::<Vec<_>>(),
                        "levelFrom": base_level,
                        "levelTo": live_level,
                    }),
                });
            }
        }
    }

    let findings = items
        .iter()
        .map(|i| {
            let who = i.container.as_deref().unwrap_or("pod spec");
            let (title, detail) = match i.kind {
                "tagMoved" => (
                    format!(
                        "Tag {} now resolves to a different digest ({who})",
                        i.detail["imageRef"].as_str().unwrap_or("")
                    ),
                    format!(
                        "Digests seen for this tag: {}. What runs is not what the tag pointed at when first seen; pin the digest.",
                        i.detail["digests"]
                            .as_array()
                            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default()
                    ),
                ),
                "unshippedExecutable" => (
                    format!(
                        "Container {who} ran files its image did not ship ({})",
                        i.detail["origins"]
                            .as_array()
                            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default()
                    ),
                    format!(
                        "{} file(s) executed or loaded from the container's writable layer, a memfd, or after being deleted, e.g. {}. \
                         An image does not change at runtime: find out what wrote them.",
                        i.detail["filesTotal"].as_u64().unwrap_or(0),
                        i.detail["files"]
                            .as_array()
                            .map(|a| a
                                .iter()
                                .take(3)
                                .filter_map(|f| f["path"].as_str())
                                .collect::<Vec<_>>()
                                .join(", "))
                            .unwrap_or_default()
                    ),
                ),
                "imageChangedSinceExport" => (
                    format!("Container {who} runs an image not in the last exported profile"),
                    format!(
                        "New digest(s): {}. Review it; if the change is expected, record a new export (POST .../export) as the baseline.",
                        i.detail["newDigests"]
                            .as_array()
                            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default()
                    ),
                ),
                _ => (
                    format!("securityContext regressed ({who})"),
                    format!(
                        "Now failing: {} (PSS level {} -> {}).",
                        i.detail["newlyFailing"]
                            .as_array()
                            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default(),
                        i.detail["levelFrom"].as_str().unwrap_or("unknown"),
                        i.detail["levelTo"].as_str().unwrap_or("unknown"),
                    ),
                ),
            };
            mk_finding(
                "drift",
                i.finding_id.clone(),
                i.severity,
                i.container.clone(),
                title,
                detail,
            )
        })
        .collect();

    (
        DriftView {
            baselines: DriftBaselines {
                export: export.map(|e| ExportRef {
                    revision: e.revision,
                    content_hash: e.content_hash.clone(),
                    mode: e.mode.clone(),
                    artifacts: e.artifacts.clone(),
                    exported_at: utc(e.exported_at),
                }),
                security_context: baseline.map(|(b, _)| b),
            },
            evaluated,
            not_evaluated,
            items,
        },
        findings,
    )
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

/// Most drift series exposed on `/metrics`.
pub const MAX_DRIFT_SERIES: i64 = 5_000;

/// `kguardian_workload_drift` gauge series, rebuilt from
/// `workload_profile_latest` by [`spawn_metrics_refresh`]. The table is
/// the retention boundary: a workload whose read-model row is pruned drops
/// out of the gauge.
#[derive(Default)]
pub struct DriftMetrics {
    series: std::sync::RwLock<Vec<DriftSeries>>,
}

impl DriftMetrics {
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# HELP kguardian_workload_drift Drift findings per workload and type in the latest profile snapshot (tagMoved, imageChangedSinceExport, securityContextRegression)\n\
             # TYPE kguardian_workload_drift gauge\n",
        );
        let esc = |v: &str| {
            v.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        };
        for (ns, kind, name, ty, n) in self.series.read().expect("drift metrics lock").iter() {
            out.push_str(&format!(
                "kguardian_workload_drift{{workload_namespace=\"{}\",workload_kind=\"{}\",workload=\"{}\",type=\"{}\"}} {n}\n",
                esc(ns),
                esc(kind),
                esc(name),
                esc(ty)
            ));
        }
        out
    }

    fn set(&self, s: Vec<DriftSeries>) {
        *self.series.write().expect("drift metrics lock") = s;
    }
}

#[derive(QueryableByName)]
struct DriftSeriesRow {
    #[diesel(sql_type = Text)]
    ns: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Text)]
    ty: String,
    #[diesel(sql_type = BigInt)]
    n: i64,
}

/// Per-type counts from the stored list summaries. Bounded.
const DRIFT_SERIES_SQL: &str = "\
SELECT l.pod_namespace AS ns, l.workload_kind AS kind, l.workload_name AS name, t.ty, \
       t.n::bigint AS n \
FROM workload_profile_latest l \
CROSS JOIN LATERAL jsonb_each_text(coalesce(l.summary->'drift'->'byType', '{}'::jsonb)) AS t(ty, n) \
WHERE l.cluster_id = $1 \
ORDER BY 1, 2, 3, 4 LIMIT $2";

pub fn load_series(conn: &mut PgConnection) -> Result<Vec<DriftSeries>, DbError> {
    let rows: Vec<DriftSeriesRow> = sql_query(DRIFT_SERIES_SQL)
        .bind::<Text, _>(DEFAULT_CLUSTER_ID)
        .bind::<BigInt, _>(MAX_DRIFT_SERIES)
        .load(conn)?;
    Ok(rows
        .into_iter()
        .map(|r| (r.ns, r.kind, r.name, r.ty, r.n))
        .collect())
}

/// Refresh the gauge every 60 s (the snapshotter's own cadence is slower).
pub fn spawn_metrics_refresh(
    pool: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>,
    metrics: actix_web::web::Data<DriftMetrics>,
) {
    actix_web::rt::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(75)).await;
        loop {
            let p = pool.clone();
            match tokio::task::spawn_blocking(move || {
                let mut conn = p.get().map_err(|e| Box::new(e) as DbError)?;
                load_series(&mut conn)
            })
            .await
            {
                Ok(Ok(s)) => metrics.set(s),
                Ok(Err(e)) => tracing::warn!(error = %e, "drift metrics refresh failed"),
                Err(e) => tracing::warn!(error = %e, "drift metrics refresh panicked"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
mod live_tests {
    use crate::runtime_inventory as ri;
    use crate::workload_profile::{self as wp, Key};
    use diesel::connection::SimpleConnection;
    use diesel::prelude::*;
    use serde_json::json;

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");
    const NS: &str = "drift-live";
    const D: &str = "sha256:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";

    fn live_conn() -> PgConnection {
        use diesel_migrations::MigrationHarness;
        let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("migrations");
        conn.batch_execute(&format!(
            "DELETE FROM runtime_executables WHERE pod_namespace = '{NS}'; \
             DELETE FROM runtime_coverage WHERE pod_namespace = '{NS}'; \
             DELETE FROM workload_containers WHERE pod_namespace = '{NS}'; \
             INSERT INTO images (digest, repository, tags, digest_kind) \
               VALUES ('{D}', 'ghcr.io/example/web', ARRAY['1'], 'repo') ON CONFLICT DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, \
               container_name, container_kind, image_ref, image_digest, state, last_seen) \
             VALUES ('{NS}', 'Deployment', 'web', 'app', 'regular', 'ghcr.io/example/web:1', \
               '{D}', 'running', timezone('UTC', NOW()));"
        ))
        .expect("seed");
        conn
    }

    fn row(path: &str, origin: &str) -> serde_json::Value {
        let now = chrono::Utc::now().naive_utc();
        json!({
            "pod_namespace": NS, "pod_name": "web-1", "workload_kind": "Deployment",
            "workload_name": "web", "container_name": "app", "image_digest": D,
            "kind": "exec", "path": path, "path_complete": true, "source": "ebpf",
            "origin": origin, "first_seen": now - chrono::Duration::seconds(60), "last_seen": now
        })
    }

    fn heartbeat() -> ri::CoverageEntry {
        let now = chrono::Utc::now().naive_utc();
        let body = serde_json::to_vec(&json!([{
            "pod_namespace": NS, "pod_name": "web-1", "workload_kind": "Deployment",
            "workload_name": "web", "container_name": "app", "image_digest": D,
            "container_id": "drift-live-1", "node_name": "n1", "mode": "full",
            "exec_probe": true, "lib_probe": true, "start_mode": "start",
            "tracking_since": now - chrono::Duration::hours(30), "heartbeat_at": now,
            "heartbeat_secs": 300
        }]))
        .unwrap();
        ri::parse_coverage(&body)
            .expect("valid heartbeat")
            .remove(0)
    }

    fn profile(conn: &mut PgConnection) -> wp::Profile {
        let key = Key {
            namespace: NS.into(),
            kind: "Deployment".into(),
            name: "web".into(),
        };
        let s = wp::load_sources(conn, &key).unwrap();
        wp::build(&key, &s, chrono::Utc::now())
    }

    /// Through the real reads: no inventory is not evaluated; an image-only
    /// inventory with coverage is evaluated and clean; a memfd exec is a
    /// high drift item and a drift finding, and posture does not move.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_unshipped_executables_are_drift_through_the_real_reads() {
        let mut conn = live_conn();
        let p = profile(&mut conn);
        assert!(!p.drift.evaluated.contains(&"unshippedExecutable"));
        assert_eq!(p.drift.not_evaluated[0].reason, "no_inventory");

        // Shipped files only, but nothing watching: still not evaluated.
        let ok = ri::prepare(&serde_json::to_vec(&json!([row("/usr/bin/web", "image")])).unwrap())
            .unwrap();
        ri::upsert_rows(&mut conn, &ok.rows).unwrap();
        let p = profile(&mut conn);
        assert_eq!(p.drift.not_evaluated[0].reason, "no_runtime_data");

        // Covered: evaluated, no drift.
        ri::upsert_coverage(&mut conn, &[heartbeat()]).unwrap();
        let clean = profile(&mut conn);
        assert!(
            clean.drift.evaluated.contains(&"unshippedExecutable"),
            "{:?}",
            clean.drift.not_evaluated
        );
        assert!(clean.drift.items.is_empty());

        // A binary run from a memfd.
        let bad =
            ri::prepare(&serde_json::to_vec(&json!([row("/memfd:x (deleted)", "memfd")])).unwrap())
                .unwrap();
        ri::upsert_rows(&mut conn, &bad.rows).unwrap();
        let p = profile(&mut conn);
        let items: Vec<_> = p
            .drift
            .items
            .iter()
            .filter(|i| i.kind == "unshippedExecutable")
            .collect();
        assert_eq!(items.len(), 1);
        assert_eq!(
            (items[0].severity, items[0].container.as_deref()),
            ("high", Some("app"))
        );
        assert_eq!(
            items[0].detail["files"][0]["path"],
            json!("/memfd:x (deleted)")
        );
        assert!(p
            .findings
            .iter()
            .any(|f| f.id == "drift.unshippedExecutable/app" && f.dimension == "drift"));
        assert_eq!(
            serde_json::to_value(&p.posture).unwrap(),
            serde_json::to_value(&clean.posture).unwrap(),
            "drift never sets posture"
        );
        conn.batch_execute(&format!(
            "DELETE FROM runtime_executables WHERE pod_namespace = '{NS}'; \
             DELETE FROM runtime_coverage WHERE pod_namespace = '{NS}'; \
             DELETE FROM workload_containers WHERE pod_namespace = '{NS}';"
        ))
        .unwrap();
    }
}
