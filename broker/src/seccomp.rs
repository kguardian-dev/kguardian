//! Per-workload seccomp profile aggregation and serving.
//!
//! `pod_syscalls` records one row per pod. This module rolls those up to
//! the stable `(namespace, kind, name)` workload identity the controller
//! puts on `pod_details`, keeps a **monotonic** union of the syscalls
//! ever seen (a profile must cover every code path, and must not narrow
//! when a replica goes away), fingerprints the set, and renders it as a
//! `SeccompProfile` document.
//!
//! Aggregation is triggered from the `/pod/syscalls` ingest path
//! (`add::create_pod_syscalls`) for the workloads whose pods appear in
//! the batch. A pod whose `pod_details` row has no `workload_kind` yet
//! (bare pod, or attribution not resolved) contributes to nothing.

use crate::schema;
use actix_web::{get, post, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// A captured CPU architecture (as the controller records it, from
/// Rust's `std::env::consts::ARCH`) mapped to its seccomp arch token.
/// Unknown values are dropped rather than guessed — an invalid
/// `architectures` entry makes the whole profile unloadable.
fn arch_token(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("SCMP_ARCH_X86_64"),
        "aarch64" => Some("SCMP_ARCH_ARM64"),
        _ => None,
    }
}

/// `defaultAction` values the profile endpoint accepts. A too-tight
/// action breaks the workload on its next restart, not immediately, so
/// the default is the audit-only `SCMP_ACT_LOG`; a team opts up to
/// enforcement once they have confirmed the profile is complete.
pub const DEFAULT_SECCOMP_ACTION: &str = "SCMP_ACT_LOG";
const VALID_SECCOMP_ACTIONS: [&str; 3] = ["SCMP_ACT_LOG", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL"];

/// FNV-1a (64-bit) over the canonical `syscalls\x1earches\x1edefault_action`
/// string. A content fingerprint, not a security primitive: the input is
/// broker-generated and never adversarial, and pulling a crypto hash
/// crate into the broker would buy nothing here. Stable across builds
/// by construction, which a crypto hash gives too but `DefaultHasher`
/// (SipHash, unspecified) would not — and the value names a file an app
/// team pins, so it must never move unless the *effective* profile does.
///
/// `default_action` is part of the fingerprint (since Phase 6): a
/// `LOG` profile and the `ERRNO` profile for the same syscall set are
/// genuinely different files, and hashing the action is what lets a
/// distributor tell them apart.
fn fingerprint(
    syscalls: &BTreeSet<String>,
    arches: &BTreeSet<String>,
    default_action: &str,
) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
    };
    // BTreeSet iterates in sorted order — the canonical form.
    for (i, s) in syscalls.iter().enumerate() {
        if i > 0 {
            feed(b",");
        }
        feed(s.as_bytes());
    }
    feed(b"\x1e");
    for (i, a) in arches.iter().enumerate() {
        if i > 0 {
            feed(b",");
        }
        feed(a.as_bytes());
    }
    feed(b"\x1e");
    feed(default_action.as_bytes());
    format!("{h:016x}")
}

/// The seccomp profile document — the shape `kubectl` and the container
/// runtime expect for a `Localhost` profile file. Matches the Go
/// `advisor/pkg/k8s.SeccompProfile` so the two generators agree.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SeccompProfile {
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SeccompRule>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SeccompRule {
    pub names: Vec<String>,
    pub action: String,
}

/// Build a profile that allow-lists exactly `syscalls` and applies
/// `default_action` to everything else. `syscalls` / `arches` come in as
/// the stored comma-joined sorted strings.
fn build_profile(syscalls: &str, arches: &str, default_action: &str) -> SeccompProfile {
    let names: Vec<String> = split_set(syscalls).into_iter().collect();
    let architectures: Vec<String> = split_set(arches)
        .iter()
        .filter_map(|a| arch_token(a))
        .map(String::from)
        .collect();
    SeccompProfile {
        default_action: default_action.to_string(),
        architectures,
        syscalls: if names.is_empty() {
            Vec::new()
        } else {
            vec![SeccompRule {
                names,
                action: "SCMP_ACT_ALLOW".to_string(),
            }]
        },
    }
}

/// Split a comma-joined field into a sorted, de-duplicated set, dropping
/// empties. Tolerant of a leading/trailing/doubled comma.
fn split_set(joined: &str) -> BTreeSet<String> {
    joined
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn join_set(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(",")
}

/// One row of `workload_syscalls`, as stored. `syscalls` / `arches` are
/// the pure observed union; `hash` names the *effective* profile
/// (observed folded with any override — see `effective_sets`).
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = schema::workload_syscalls)]
struct WorkloadSyscallsRow {
    pod_namespace: String,
    workload_kind: String,
    workload_name: String,
    syscalls: String,
    arches: String,
    hash: String,
    updated_at: chrono::NaiveDateTime,
}

/// One row of `workload_seccomp_overrides` (Phase 6).
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::workload_seccomp_overrides)]
struct OverrideRow {
    #[allow(dead_code)]
    pod_namespace: String,
    #[allow(dead_code)]
    workload_kind: String,
    #[allow(dead_code)]
    workload_name: String,
    add_syscalls: String,
    remove_syscalls: String,
    default_action: Option<String>,
    note: Option<String>,
    updated_by: String,
    updated_at: chrono::NaiveDateTime,
    revision: i32,
}

fn load_override(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<Option<OverrideRow>, DbError> {
    use schema::workload_seccomp_overrides::dsl::*;
    Ok(workload_seccomp_overrides
        .find((ns, kind, name))
        .select(OverrideRow::as_select())
        .first(conn)
        .optional()?)
}

/// Fold an observed syscall/arch set with an optional override into the
/// effective `(syscalls, arches, default_action)` the profile renders
/// from. `arches` are not overridable. The single place this fold
/// happens, shared by the ingest recompute and every render path.
fn effective_sets(
    observed_syscalls: &BTreeSet<String>,
    observed_arches: &BTreeSet<String>,
    ovr: Option<&OverrideRow>,
) -> (BTreeSet<String>, BTreeSet<String>, String) {
    let mut syscalls = observed_syscalls.clone();
    let mut action = DEFAULT_SECCOMP_ACTION.to_string();
    if let Some(o) = ovr {
        syscalls.extend(split_set(&o.add_syscalls));
        for r in split_set(&o.remove_syscalls) {
            syscalls.remove(&r);
        }
        if let Some(a) = o.default_action.as_deref().filter(|a| !a.is_empty()) {
            action = a.to_string();
        }
    }
    (syscalls, observed_arches.clone(), action)
}

/// The `(namespace, kind, name)` workloads that own any of `pod_names`.
/// Pods with no resolved workload are skipped.
pub fn affected_workloads(
    conn: &mut PgConnection,
    pod_names: &BTreeSet<String>,
) -> Result<BTreeSet<(String, String, String)>, DbError> {
    use schema::pod_details::dsl as pd;
    if pod_names.is_empty() {
        return Ok(BTreeSet::new());
    }
    let names: Vec<&String> = pod_names.iter().collect();
    let rows: Vec<(Option<String>, Option<String>, Option<String>)> = pd::pod_details
        .filter(pd::pod_name.eq_any(names))
        .select((pd::pod_namespace, pd::workload_kind, pd::workload_name))
        .load(conn)?;
    Ok(rows
        .into_iter()
        .filter_map(|(ns, kind, name)| Some((ns?, kind?, name?)))
        .collect())
}

/// Recompute one workload's aggregate from the current `pod_syscalls`
/// rows of its pods, unioned with whatever the aggregate already holds
/// (monotonic — the set never shrinks). Upserts `workload_syscalls`.
pub fn recompute_workload(
    conn: &mut PgConnection,
    namespace: &str,
    kind: &str,
    name: &str,
) -> Result<(), DbError> {
    use schema::pod_details::dsl as pd;
    use schema::pod_syscalls::dsl as ps;
    use schema::workload_syscalls::dsl as ws;

    let pod_names: Vec<String> = pd::pod_details
        .filter(pd::pod_namespace.eq(namespace))
        .filter(pd::workload_kind.eq(kind))
        .filter(pd::workload_name.eq(name))
        .select(pd::pod_name)
        .load(conn)?;

    let observed: Vec<(String, String)> = if pod_names.is_empty() {
        Vec::new()
    } else {
        ps::pod_syscalls
            .filter(ps::pod_name.eq_any(&pod_names))
            .select((ps::syscalls, ps::arch))
            .load(conn)?
    };

    // Seed from the existing aggregate so the union is monotonic across
    // time even as individual pods come and go.
    let existing: Option<(String, String, String)> = ws::workload_syscalls
        .find((namespace, kind, name))
        .select((ws::syscalls, ws::arches, ws::hash))
        .first(conn)
        .optional()?;

    let mut syscall_set = BTreeSet::new();
    let mut arch_set = BTreeSet::new();
    if let Some((s, a, _)) = &existing {
        syscall_set.extend(split_set(s));
        arch_set.extend(split_set(a));
    }
    for (s, a) in &observed {
        syscall_set.extend(split_set(s));
        if !a.trim().is_empty() {
            arch_set.insert(a.trim().to_string());
        }
    }

    if syscall_set.is_empty() {
        // Nothing observed yet and no prior aggregate — don't create an
        // empty row.
        return Ok(());
    }

    let syscalls_joined = join_set(&syscall_set);
    let arches_joined = join_set(&arch_set);

    // The hash names the EFFECTIVE profile, so an override changes the
    // filename even when the observed union has not moved.
    let ovr = load_override(conn, namespace, kind, name)?;
    let (eff_syscalls, eff_arches, eff_action) =
        effective_sets(&syscall_set, &arch_set, ovr.as_ref());
    let new_hash = fingerprint(&eff_syscalls, &eff_arches, &eff_action);

    if existing
        .as_ref()
        .is_some_and(|(s, a, h)| s == &syscalls_joined && a == &arches_joined && h == &new_hash)
    {
        return Ok(()); // unchanged — leave updated_at alone
    }

    let now = chrono::Utc::now().naive_utc();
    diesel::insert_into(ws::workload_syscalls)
        .values((
            ws::pod_namespace.eq(namespace),
            ws::workload_kind.eq(kind),
            ws::workload_name.eq(name),
            ws::syscalls.eq(&syscalls_joined),
            ws::arches.eq(&arches_joined),
            ws::hash.eq(&new_hash),
            ws::updated_at.eq(now),
        ))
        .on_conflict((ws::pod_namespace, ws::workload_kind, ws::workload_name))
        .do_update()
        .set((
            ws::syscalls.eq(&syscalls_joined),
            ws::arches.eq(&arches_joined),
            ws::hash.eq(&new_hash),
            ws::updated_at.eq(now),
        ))
        .execute(conn)?;

    debug!(
        namespace, kind, name, hash = %new_hash, syscalls = syscall_set.len(),
        "recomputed workload_syscalls aggregate"
    );
    Ok(())
}

/// `kguardian/<ns>/<kind-lowercased>-<name>-<hash>.json` — the path an
/// app team puts in `securityContext.seccompProfile.localhostProfile`,
/// resolved by the kubelet under its seccomp root. `hash` is the
/// effective-profile hash stored on the row.
fn localhost_profile_path(row: &WorkloadSyscallsRow) -> String {
    format!(
        "kguardian/{}/{}-{}-{}.json",
        row.pod_namespace,
        row.workload_kind.to_lowercase(),
        row.workload_name,
        row.hash
    )
}

/// Observed row + the effective set it renders to after any override.
struct Effective {
    row: WorkloadSyscallsRow,
    syscalls: BTreeSet<String>,
    arches: BTreeSet<String>,
    default_action: String,
    ovr: Option<OverrideRow>,
}

/// Load a workload's observed row and fold in its override. `None` when
/// the workload has no observed aggregate yet — an override alone never
/// produces a profile (there would be no architectures).
fn effective_profile(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<Option<Effective>, DbError> {
    let Some(row) = one_row(conn, ns, kind, name)? else {
        return Ok(None);
    };
    let ovr = load_override(conn, ns, kind, name)?;
    let observed_syscalls = split_set(&row.syscalls);
    let observed_arches = split_set(&row.arches);
    let (syscalls, arches, default_action) =
        effective_sets(&observed_syscalls, &observed_arches, ovr.as_ref());
    Ok(Some(Effective {
        row,
        syscalls,
        arches,
        default_action,
        ovr,
    }))
}

#[derive(Serialize)]
struct OverrideBlock {
    add: Vec<String>,
    remove: Vec<String>,
    #[serde(rename = "defaultAction")]
    default_action: Option<String>,
    note: Option<String>,
    #[serde(rename = "updatedBy")]
    updated_by: String,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::NaiveDateTime,
    revision: i32,
}

impl From<&OverrideRow> for OverrideBlock {
    fn from(o: &OverrideRow) -> Self {
        OverrideBlock {
            add: split_set(&o.add_syscalls).into_iter().collect(),
            remove: split_set(&o.remove_syscalls).into_iter().collect(),
            default_action: o.default_action.clone().filter(|a| !a.is_empty()),
            note: o.note.clone(),
            updated_by: o.updated_by.clone(),
            updated_at: o.updated_at,
            revision: o.revision,
        }
    }
}

/// Distribution readiness for one profile: how many live nodes have its
/// current file, out of how many. Referencing a profile before it is
/// `Ready` risks a pod scheduling onto a node that lacks the file
/// (`CreateContainerError`).
#[derive(Serialize)]
struct Distribution {
    ready: i64,
    total: i64,
    /// `Ready` | `Partial` | `Pending`.
    state: &'static str,
}

impl Distribution {
    fn compute(ready: i64, total: i64) -> Self {
        let state = if total == 0 || ready == 0 {
            "Pending"
        } else if ready >= total {
            "Ready"
        } else {
            "Partial"
        };
        Distribution {
            ready,
            total,
            state,
        }
    }
}

#[derive(Serialize)]
struct ProfileSummary {
    namespace: String,
    kind: String,
    name: String,
    hash: String,
    #[serde(rename = "localhostProfile")]
    localhost_profile: String,
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(rename = "syscallCount")]
    syscall_count: usize,
    architectures: Vec<String>,
    distribution: Distribution,
    /// Drop-in for a pod template's `securityContext`.
    #[serde(rename = "recommendedSnippet")]
    recommended_snippet: serde_json::Value,
    /// Operator override in effect, or `null`.
    #[serde(rename = "override")]
    override_block: Option<OverrideBlock>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::NaiveDateTime,
}

impl ProfileSummary {
    /// `syscall_count` / `architectures` / `default_action` reflect the
    /// **effective** profile, not the raw observed row.
    fn build(eff: &Effective, index: &DistributionIndex) -> Self {
        let r = &eff.row;
        let path = localhost_profile_path(r);
        let ready = index.path_counts.get(&path).copied().unwrap_or(0);
        ProfileSummary {
            namespace: r.pod_namespace.clone(),
            kind: r.workload_kind.clone(),
            name: r.workload_name.clone(),
            hash: r.hash.clone(),
            default_action: eff.default_action.clone(),
            syscall_count: eff.syscalls.len(),
            architectures: eff
                .arches
                .iter()
                .filter_map(|a| arch_token(a))
                .map(String::from)
                .collect(),
            distribution: Distribution::compute(ready, index.total_nodes),
            recommended_snippet: serde_json::json!({
                "seccompProfile": { "type": "Localhost", "localhostProfile": path }
            }),
            override_block: eff.ovr.as_ref().map(OverrideBlock::from),
            localhost_profile: path,
            updated_at: r.updated_at,
        }
    }
}

/// Per-path node counts plus the live-node denominator, loaded once per
/// request so building N summaries is O(nodes + profiles), not a query
/// per profile.
struct DistributionIndex {
    path_counts: HashMap<String, i64>,
    total_nodes: i64,
}

fn distribution_index(conn: &mut PgConnection) -> Result<DistributionIndex, DbError> {
    use diesel::sql_query;
    use diesel::sql_types::BigInt;
    use schema::seccomp_node_status::dsl as sns;

    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        n: i64,
    }
    // Same denominator the version check-in uses for install size.
    let total_nodes: i64 =
        sql_query("SELECT COUNT(DISTINCT node_name) AS n FROM pod_details WHERE is_dead = false")
            .get_result::<CountRow>(conn)?
            .n;

    let rows: Vec<serde_json::Value> = sns::seccomp_node_status.select(sns::paths).load(conn)?;
    let mut path_counts: HashMap<String, i64> = HashMap::new();
    for paths in rows {
        if let Some(arr) = paths.as_array() {
            // A node reporting the same path twice still counts once.
            for p in arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<BTreeSet<_>>()
            {
                *path_counts.entry(p.to_string()).or_insert(0) += 1;
            }
        }
    }
    Ok(DistributionIndex {
        path_counts,
        total_nodes,
    })
}

/// Every workload's observed row folded with its override, ordered.
/// Batch-loads overrides so the list endpoint stays O(rows), not a
/// query per row.
fn all_effective(conn: &mut PgConnection) -> Result<Vec<Effective>, DbError> {
    use schema::workload_seccomp_overrides::dsl as o;
    use schema::workload_syscalls::dsl as ws;

    let rows: Vec<WorkloadSyscallsRow> = ws::workload_syscalls
        .select(WorkloadSyscallsRow::as_select())
        .order((
            ws::pod_namespace.asc(),
            ws::workload_kind.asc(),
            ws::workload_name.asc(),
        ))
        .load(conn)?;

    let mut overrides: HashMap<(String, String, String), OverrideRow> =
        o::workload_seccomp_overrides
            .select(OverrideRow::as_select())
            .load(conn)?
            .into_iter()
            .map(|r| {
                (
                    (
                        r.pod_namespace.clone(),
                        r.workload_kind.clone(),
                        r.workload_name.clone(),
                    ),
                    r,
                )
            })
            .collect();

    Ok(rows
        .into_iter()
        .map(|row| {
            let key = (
                row.pod_namespace.clone(),
                row.workload_kind.clone(),
                row.workload_name.clone(),
            );
            let ovr = overrides.remove(&key);
            let observed_syscalls = split_set(&row.syscalls);
            let observed_arches = split_set(&row.arches);
            let (syscalls, arches, default_action) =
                effective_sets(&observed_syscalls, &observed_arches, ovr.as_ref());
            Effective {
                row,
                syscalls,
                arches,
                default_action,
                ovr,
            }
        })
        .collect())
}

fn one_row(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<Option<WorkloadSyscallsRow>, DbError> {
    use schema::workload_syscalls::dsl::*;
    Ok(workload_syscalls
        .find((ns, kind, name))
        .select(WorkloadSyscallsRow::as_select())
        .first(conn)
        .optional()?)
}

fn validated_action(a: &str) -> Result<(), actix_web::Error> {
    if VALID_SECCOMP_ACTIONS.contains(&a) {
        Ok(())
    } else {
        Err(actix_web::error::ErrorBadRequest(format!(
            "invalid defaultAction {a:?}; expected one of {VALID_SECCOMP_ACTIONS:?}"
        )))
    }
}

/// Render the profile document for an `Effective`.
fn render(eff: &Effective) -> SeccompProfile {
    build_profile(
        &join_set(&eff.syscalls),
        &join_set(&eff.arches),
        &eff.default_action,
    )
}

/// `GET /seccomp/profiles` — every workload that has an aggregate, with
/// its effective hash, profile path, distribution readiness, and any
/// override. The list a distributor polls and the UI shows.
#[get("/seccomp/profiles")]
pub async fn list_seccomp_profiles(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    info!("list seccomp profiles");
    let out: Vec<ProfileSummary> = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        let effs = all_effective(&mut conn)?;
        let index = distribution_index(&mut conn)?;
        Ok(effs
            .iter()
            .map(|e| ProfileSummary::build(e, &index))
            .collect())
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(out))
}

#[derive(Serialize)]
struct ProfileDetail {
    #[serde(flatten)]
    summary: ProfileSummary,
    profile: SeccompProfile,
}

/// `GET /seccomp/profiles/{namespace}/{kind}/{name}` — one workload's
/// summary plus the rendered effective profile.
#[get("/seccomp/profiles/{namespace}/{kind}/{name}")]
pub async fn get_seccomp_profile(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name) = path.into_inner();
    info!(%namespace, %kind, %name, "get seccomp profile");

    let result = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        match effective_profile(&mut conn, &namespace, &kind, &name)? {
            Some(eff) => {
                let index = distribution_index(&mut conn)?;
                let profile = render(&eff);
                Ok(Some((ProfileSummary::build(&eff, &index), profile)))
            }
            None => Ok(None),
        }
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match result {
        Some((summary, profile)) => HttpResponse::Ok().json(ProfileDetail { summary, profile }),
        None => HttpResponse::NotFound().body("no seccomp profile for that workload"),
    })
}

/// `GET /seccomp/profile-file/{namespace}/{kind}/{name}/{hash}` — the
/// bare effective `SeccompProfile` JSON, for a distributor to write to a
/// node. Serves only the CURRENT hash; a stale hash is a 404 (the caller
/// should re-read the list).
#[get("/seccomp/profile-file/{namespace}/{kind}/{name}/{hash}")]
pub async fn get_seccomp_profile_file(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name, hash) = path.into_inner();

    let eff = web::block(move || {
        let mut conn = pool.get()?;
        effective_profile(&mut conn, &namespace, &kind, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match eff {
        Some(e) if e.row.hash == hash => HttpResponse::Ok().json(render(&e)),
        Some(_) => HttpResponse::NotFound().body("stale hash; re-read /seccomp/profiles"),
        None => HttpResponse::NotFound().body("no seccomp profile for that workload"),
    })
}

/// Body of `POST /seccomp/node-status`.
#[derive(Deserialize)]
pub struct NodeStatusInput {
    node_name: String,
    /// Every `localhostProfile` path the node currently has on disk.
    #[serde(default)]
    paths: Vec<String>,
}

/// `POST /seccomp/node-status` — the distributor reports, after each
/// pass, the full set of profile files present on its node. Replaces the
/// node's row wholesale.
#[post("/seccomp/node-status")]
pub async fn post_seccomp_node_status(
    pool: web::Data<DbPool>,
    body: web::Json<NodeStatusInput>,
) -> actix_web::Result<impl Responder> {
    let NodeStatusInput { node_name, paths } = body.into_inner();
    if node_name.trim().is_empty() {
        return Err(actix_web::error::ErrorBadRequest("node_name is required"));
    }
    // De-duplicate defensively; the readiness count treats a node once.
    let paths: Vec<String> = paths
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    debug!(node = %node_name, profiles = paths.len(), "seccomp node status");

    web::block(move || -> Result<(), DbError> {
        use schema::seccomp_node_status::dsl as sns;
        let mut conn = pool.get()?;
        let now = chrono::Utc::now().naive_utc();
        let json = serde_json::Value::from(paths);
        diesel::insert_into(sns::seccomp_node_status)
            .values((
                sns::node_name.eq(&node_name),
                sns::paths.eq(&json),
                sns::updated_at.eq(now),
            ))
            .on_conflict(sns::node_name)
            .do_update()
            .set((sns::paths.eq(&json), sns::updated_at.eq(now)))
            .execute(&mut conn)?;
        Ok(())
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(()))
}

// ---------------------------------------------------------------------------
// Phase 6 — operator overrides
// ---------------------------------------------------------------------------

/// The override write endpoints are gated: they 404 unless
/// `SECCOMP_OVERRIDES_ENABLED` is truthy. Editing a profile can take a
/// workload down, so it is an explicit opt-in, not on-by-default.
fn overrides_enabled() -> bool {
    matches!(
        std::env::var("SECCOMP_OVERRIDES_ENABLED")
            .as_deref()
            .map(str::trim),
        Ok("true") | Ok("1") | Ok("yes") | Ok("on")
    )
}

/// A syntactically plausible syscall name: `^[a-z][a-z0-9_]{0,63}$`.
/// This rejects typos like `"OpenAt"`, `"openat "`, `"openat;"` and any
/// injection attempt. It does NOT confirm the name is a real syscall —
/// an unknown-but-well-formed name is a warning (a static name table is
/// a future hardening).
fn valid_syscall_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Actor recorded on an override write. The broker token is a shared
/// secret with no subject, so callers pass `X-Kguardian-Actor`; absent
/// or blank ⇒ `"unknown"`.
fn actor_from(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("X-Kguardian-Actor")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .chars()
        .take(128)
        .collect()
}

/// Body of `PUT /seccomp/profiles/{ns}/{kind}/{name}/override`.
#[derive(Deserialize)]
pub struct OverrideInput {
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
    #[serde(default, rename = "defaultAction")]
    default_action: Option<String>,
    #[serde(default)]
    note: Option<String>,
    /// The `revision` the client last read. Omit (or `null`) to create.
    /// A mismatch with the stored revision is a `409`.
    #[serde(default)]
    revision: Option<i32>,
    /// Validate + render without persisting.
    #[serde(default, rename = "dryRun")]
    dry_run: bool,
}

const MAX_OVERRIDE_LIST: usize = 512;

enum OverrideWrite {
    Ok {
        revision: i32,
        hash: String,
        warnings: Vec<String>,
        profile: SeccompProfile,
    },
    NoObservedProfile,
    RevisionConflict {
        current: Option<i32>,
    },
}

#[allow(clippy::too_many_arguments)]
fn apply_override(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
    add: BTreeSet<String>,
    remove: BTreeSet<String>,
    default_action: Option<String>,
    note: Option<String>,
    client_revision: Option<i32>,
    actor: &str,
    dry_run: bool,
) -> Result<OverrideWrite, DbError> {
    use schema::workload_seccomp_overrides::dsl as o;

    let Some(observed) = one_row(conn, ns, kind, name)? else {
        return Ok(OverrideWrite::NoObservedProfile);
    };
    let existing = load_override(conn, ns, kind, name)?;
    let current_rev = existing.as_ref().map(|e| e.revision);
    if client_revision != current_rev {
        return Ok(OverrideWrite::RevisionConflict {
            current: current_rev,
        });
    }

    let observed_syscalls = split_set(&observed.syscalls);
    let mut warnings = Vec::new();
    if let Some(a) = default_action.as_deref() {
        if a == "SCMP_ACT_ERRNO" || a == "SCMP_ACT_KILL" {
            warnings.push(format!(
                "defaultAction {a} blocks — a syscall the workload makes but kube-guardian \
                 has not yet observed will fail on the pod's next restart"
            ));
        }
    }
    for r in &remove {
        if observed_syscalls.contains(r) {
            warnings.push(format!(
                "removing {r:?}, which the workload was observed to make"
            ));
        }
    }

    let add_joined = join_set(&add);
    let remove_joined = join_set(&remove);
    let synthetic = OverrideRow {
        pod_namespace: ns.to_string(),
        workload_kind: kind.to_string(),
        workload_name: name.to_string(),
        add_syscalls: add_joined.clone(),
        remove_syscalls: remove_joined.clone(),
        default_action: default_action.clone(),
        note: note.clone(),
        updated_by: actor.to_string(),
        updated_at: chrono::Utc::now().naive_utc(),
        revision: current_rev.unwrap_or(0) + 1,
    };
    let (eff_s, eff_a, eff_act) = effective_sets(
        &observed_syscalls,
        &split_set(&observed.arches),
        Some(&synthetic),
    );
    let hash = fingerprint(&eff_s, &eff_a, &eff_act);
    let profile = build_profile(&join_set(&eff_s), &join_set(&eff_a), &eff_act);

    if dry_run {
        return Ok(OverrideWrite::Ok {
            revision: synthetic.revision,
            hash,
            warnings,
            profile,
        });
    }

    let now = synthetic.updated_at;
    diesel::insert_into(o::workload_seccomp_overrides)
        .values((
            o::pod_namespace.eq(ns),
            o::workload_kind.eq(kind),
            o::workload_name.eq(name),
            o::add_syscalls.eq(&add_joined),
            o::remove_syscalls.eq(&remove_joined),
            o::default_action.eq(&default_action),
            o::note.eq(&note),
            o::updated_by.eq(actor),
            o::updated_at.eq(now),
            o::revision.eq(synthetic.revision),
        ))
        .on_conflict((o::pod_namespace, o::workload_kind, o::workload_name))
        .do_update()
        .set((
            o::add_syscalls.eq(&add_joined),
            o::remove_syscalls.eq(&remove_joined),
            o::default_action.eq(&default_action),
            o::note.eq(&note),
            o::updated_by.eq(actor),
            o::updated_at.eq(now),
            o::revision.eq(synthetic.revision),
        ))
        .execute(conn)?;

    audit_override(
        conn,
        ns,
        kind,
        name,
        "put",
        serde_json::json!({
            "add": add, "remove": remove, "defaultAction": default_action, "note": note
        }),
        actor,
    )?;
    rehash_workload(conn, ns, kind, name)?;

    Ok(OverrideWrite::Ok {
        revision: synthetic.revision,
        hash,
        warnings,
        profile,
    })
}

fn audit_override(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
    op: &str,
    diff: serde_json::Value,
    actor: &str,
) -> Result<(), DbError> {
    use schema::seccomp_override_audit::dsl as a;
    diesel::insert_into(a::seccomp_override_audit)
        .values((
            a::pod_namespace.eq(ns),
            a::workload_kind.eq(kind),
            a::workload_name.eq(name),
            a::op.eq(op),
            a::diff.eq(diff),
            a::updated_by.eq(actor),
            a::at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(conn)?;
    Ok(())
}

/// Recompute just the effective hash on `workload_syscalls` (cheaper
/// than `recompute_workload`, which also re-does the pod union query).
/// Called after an override write.
fn rehash_workload(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<(), DbError> {
    use schema::workload_syscalls::dsl as ws;
    let Some(row) = one_row(conn, ns, kind, name)? else {
        return Ok(());
    };
    let ovr = load_override(conn, ns, kind, name)?;
    let (s, a, act) = effective_sets(
        &split_set(&row.syscalls),
        &split_set(&row.arches),
        ovr.as_ref(),
    );
    let h = fingerprint(&s, &a, &act);
    if h != row.hash {
        diesel::update(ws::workload_syscalls.find((ns, kind, name)))
            .set((
                ws::hash.eq(&h),
                ws::updated_at.eq(chrono::Utc::now().naive_utc()),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// `PUT /seccomp/profiles/{namespace}/{kind}/{name}/override` — set (or
/// replace) the operator override for a workload. Gated behind
/// `SECCOMP_OVERRIDES_ENABLED`.
#[actix_web::put("/seccomp/profiles/{namespace}/{kind}/{name}/override")]
pub async fn put_seccomp_override(
    req: actix_web::HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
    body: web::Json<OverrideInput>,
) -> actix_web::Result<impl Responder> {
    if !overrides_enabled() {
        return Ok(HttpResponse::NotFound().body("seccomp overrides are not enabled"));
    }
    let (namespace, kind, name) = path.into_inner();
    let OverrideInput {
        add,
        remove,
        default_action,
        note,
        revision,
        dry_run,
    } = body.into_inner();
    let actor = actor_from(&req);

    // Pure validation, before touching the DB.
    if add.len() > MAX_OVERRIDE_LIST || remove.len() > MAX_OVERRIDE_LIST {
        return Err(actix_web::error::ErrorBadRequest(format!(
            "add/remove lists are capped at {MAX_OVERRIDE_LIST} entries"
        )));
    }
    for s in add.iter().chain(remove.iter()) {
        if !valid_syscall_name(s) {
            return Err(actix_web::error::ErrorBadRequest(format!(
                "{s:?} is not a valid syscall name (expected ^[a-z][a-z0-9_]{{0,63}}$)"
            )));
        }
    }
    let add: BTreeSet<String> = add.into_iter().collect();
    let remove: BTreeSet<String> = remove.into_iter().collect();
    let overlap: Vec<&String> = add.intersection(&remove).collect();
    if !overlap.is_empty() {
        return Err(actix_web::error::ErrorBadRequest(format!(
            "these syscalls are in both add and remove: {overlap:?}"
        )));
    }
    if let Some(a) = default_action.as_deref().filter(|a| !a.is_empty()) {
        validated_action(a)?;
    }
    let default_action = default_action.filter(|a| !a.is_empty());
    if let Some(n) = &note {
        if n.len() > 2000 {
            return Err(actix_web::error::ErrorBadRequest(
                "note is capped at 2000 chars",
            ));
        }
    }

    info!(%namespace, %kind, %name, %actor, dry_run, "put seccomp override");

    let outcome = web::block(move || {
        let mut conn = pool.get()?;
        conn.transaction(|conn| {
            apply_override(
                conn,
                &namespace,
                &kind,
                &name,
                add,
                remove,
                default_action,
                note,
                revision,
                &actor,
                dry_run,
            )
        })
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match outcome {
        OverrideWrite::Ok {
            revision,
            hash,
            warnings,
            profile,
        } => HttpResponse::Ok().json(serde_json::json!({
            "dryRun": dry_run,
            "revision": revision,
            "hash": hash,
            "warnings": warnings,
            "profile": profile,
        })),
        OverrideWrite::NoObservedProfile => HttpResponse::NotFound()
            .body("no observed profile for that workload yet — record syscalls first"),
        OverrideWrite::RevisionConflict { current } => HttpResponse::Conflict()
            .json(serde_json::json!({ "error": "revision conflict", "currentRevision": current })),
    })
}

/// `DELETE /seccomp/profiles/{namespace}/{kind}/{name}/override` — drop
/// the override; the effective profile falls back to the observed set
/// and the hash reverts (the pre-override file, never deleted, is valid
/// again).
#[actix_web::delete("/seccomp/profiles/{namespace}/{kind}/{name}/override")]
pub async fn delete_seccomp_override(
    req: actix_web::HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    if !overrides_enabled() {
        return Ok(HttpResponse::NotFound().body("seccomp overrides are not enabled"));
    }
    let (namespace, kind, name) = path.into_inner();
    let actor = actor_from(&req);
    info!(%namespace, %kind, %name, %actor, "delete seccomp override");

    let deleted = web::block(move || {
        use schema::workload_seccomp_overrides::dsl as o;
        let mut conn = pool.get()?;
        conn.transaction(|conn| -> Result<bool, DbError> {
            let n = diesel::delete(o::workload_seccomp_overrides.find((&namespace, &kind, &name)))
                .execute(conn)?;
            if n > 0 {
                audit_override(
                    conn,
                    &namespace,
                    &kind,
                    &name,
                    "delete",
                    serde_json::json!({}),
                    &actor,
                )?;
                rehash_workload(conn, &namespace, &kind, &name)?;
            }
            Ok(n > 0)
        })
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(if deleted {
        HttpResponse::Ok().json(serde_json::json!({ "deleted": true }))
    } else {
        HttpResponse::NotFound().body("no override for that workload")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// fingerprint with a fixed action, for the set/arch-focused tests.
    fn fp(syscalls: &[&str], arches: &[&str]) -> String {
        fingerprint(&set(syscalls), &set(arches), "SCMP_ACT_LOG")
    }

    #[test]
    fn fingerprint_is_order_independent_and_stable() {
        let a = fp(&["read", "write", "openat"], &["SCMP_ARCH_X86_64"]);
        assert_eq!(a, fp(&["openat", "read", "write"], &["SCMP_ARCH_X86_64"]));
        assert_eq!(a, fp(&["write", "openat", "read"], &["SCMP_ARCH_X86_64"]));
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn fingerprint_changes_when_the_set_grows() {
        assert_ne!(
            fp(&["read", "write"], &["SCMP_ARCH_X86_64"]),
            fp(&["read", "write", "mmap"], &["SCMP_ARCH_X86_64"])
        );
    }

    #[test]
    fn fingerprint_distinguishes_arch() {
        assert_ne!(
            fp(&["read"], &["SCMP_ARCH_X86_64"]),
            fp(&["read"], &["SCMP_ARCH_ARM64"])
        );
    }

    #[test]
    fn fingerprint_distinguishes_default_action() {
        let base = set(&["read", "write"]);
        let arch = set(&["SCMP_ARCH_X86_64"]);
        assert_ne!(
            fingerprint(&base, &arch, "SCMP_ACT_LOG"),
            fingerprint(&base, &arch, "SCMP_ACT_ERRNO")
        );
    }

    #[test]
    fn build_profile_allowlists_observed_syscalls() {
        let p = build_profile("openat,read,write", "x86_64", "SCMP_ACT_ERRNO");
        assert_eq!(p.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(p.architectures, vec!["SCMP_ARCH_X86_64"]);
        assert_eq!(p.syscalls.len(), 1);
        assert_eq!(p.syscalls[0].action, "SCMP_ACT_ALLOW");
        // Stored form is already sorted; the profile preserves it.
        assert_eq!(p.syscalls[0].names, vec!["openat", "read", "write"]);
    }

    #[test]
    fn build_profile_maps_both_arches_and_drops_unknown() {
        let p = build_profile("read", "aarch64,x86_64,riscv64", "SCMP_ACT_LOG");
        assert_eq!(p.architectures, vec!["SCMP_ARCH_ARM64", "SCMP_ARCH_X86_64"]);
    }

    #[test]
    fn build_profile_with_no_syscalls_has_no_rule() {
        let p = build_profile("", "x86_64", "SCMP_ACT_LOG");
        assert!(p.syscalls.is_empty());
    }

    #[test]
    fn split_set_tolerates_messy_joins() {
        assert_eq!(split_set(",read,, write ,read,"), set(&["read", "write"]));
        assert!(split_set("").is_empty());
    }

    #[test]
    fn localhost_path_lowercases_kind_and_carries_hash() {
        let row = WorkloadSyscallsRow {
            pod_namespace: "prod".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            syscalls: "read,write".into(),
            arches: "x86_64".into(),
            hash: "abc123".into(),
            updated_at: chrono::NaiveDateTime::default(),
        };
        assert_eq!(
            localhost_profile_path(&row),
            "kguardian/prod/deployment-web-abc123.json"
        );
    }

    #[test]
    fn validated_action_rejects_garbage() {
        assert!(validated_action("SCMP_ACT_ERRNO").is_ok());
        assert!(validated_action("SCMP_ACT_LOG").is_ok());
        assert!(validated_action("rm -rf").is_err());
    }

    #[test]
    fn valid_syscall_name_rules() {
        for ok in ["read", "openat2", "clock_gettime", "io_uring_enter"] {
            assert!(valid_syscall_name(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            "OpenAt",
            "openat ",
            "openat;",
            "2read",
            "-x",
            "a".repeat(65).as_str(),
        ] {
            assert!(!valid_syscall_name(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn effective_sets_applies_add_remove_and_action() {
        let observed = set(&["read", "write", "openat"]);
        let arches = set(&["x86_64"]);
        let ovr = OverrideRow {
            pod_namespace: "p".into(),
            workload_kind: "Deployment".into(),
            workload_name: "w".into(),
            add_syscalls: "mmap,munmap".into(),
            remove_syscalls: "openat".into(),
            default_action: Some("SCMP_ACT_ERRNO".into()),
            note: None,
            updated_by: "alice".into(),
            updated_at: chrono::NaiveDateTime::default(),
            revision: 1,
        };
        let (s, a, act) = effective_sets(&observed, &arches, Some(&ovr));
        assert_eq!(
            s,
            set(&["read", "write", "mmap", "munmap"]),
            "openat removed, mmap/munmap added"
        );
        assert_eq!(a, arches);
        assert_eq!(act, "SCMP_ACT_ERRNO");
    }

    #[test]
    fn effective_sets_no_override_is_observed_plus_log() {
        let observed = set(&["read"]);
        let (s, _, act) = effective_sets(&observed, &set(&["x86_64"]), None);
        assert_eq!(s, observed);
        assert_eq!(act, "SCMP_ACT_LOG");
    }

    #[test]
    fn override_block_serialises_with_camelcase() {
        let o = OverrideRow {
            pod_namespace: "p".into(),
            workload_kind: "Deployment".into(),
            workload_name: "w".into(),
            add_syscalls: "mmap".into(),
            remove_syscalls: "".into(),
            default_action: Some("SCMP_ACT_ERRNO".into()),
            note: Some("weekly cron".into()),
            updated_by: "alice".into(),
            updated_at: chrono::NaiveDateTime::default(),
            revision: 3,
        };
        let v = serde_json::to_value(OverrideBlock::from(&o)).unwrap();
        assert_eq!(v["add"], serde_json::json!(["mmap"]));
        assert_eq!(v["remove"], serde_json::json!([]));
        assert_eq!(v["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(v["updatedBy"], "alice");
        assert_eq!(v["revision"], 3);
    }

    #[test]
    fn override_input_defaults() {
        let got: OverrideInput = serde_json::from_str("{}").unwrap();
        assert!(got.add.is_empty() && got.remove.is_empty());
        assert!(got.revision.is_none() && !got.dry_run);
    }

    #[test]
    fn profile_json_shape_matches_the_runtime_contract() {
        let p = build_profile("read,write", "x86_64", "SCMP_ACT_LOG");
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["defaultAction"], "SCMP_ACT_LOG");
        assert_eq!(v["architectures"][0], "SCMP_ARCH_X86_64");
        assert_eq!(v["syscalls"][0]["names"][0], "read");
        assert_eq!(v["syscalls"][0]["action"], "SCMP_ACT_ALLOW");
    }

    #[test]
    fn distribution_state_transitions() {
        assert_eq!(Distribution::compute(0, 0).state, "Pending");
        assert_eq!(Distribution::compute(0, 5).state, "Pending");
        assert_eq!(Distribution::compute(2, 5).state, "Partial");
        assert_eq!(Distribution::compute(5, 5).state, "Ready");
        // Defensive: more reporters than the live-node count (a node
        // draining, say) still reads as Ready, never a >100% Partial.
        assert_eq!(Distribution::compute(6, 5).state, "Ready");
    }

    fn effective_fixture(
        syscalls: &str,
        arches: &str,
        hash: &str,
        ovr: Option<OverrideRow>,
    ) -> Effective {
        let row = WorkloadSyscallsRow {
            pod_namespace: "prod".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            syscalls: syscalls.into(),
            arches: arches.into(),
            hash: hash.into(),
            updated_at: chrono::NaiveDateTime::default(),
        };
        let (s, a, act) = effective_sets(&split_set(syscalls), &split_set(arches), ovr.as_ref());
        Effective {
            row,
            syscalls: s,
            arches: a,
            default_action: act,
            ovr,
        }
    }

    #[test]
    fn profile_summary_carries_snippet_and_readiness() {
        let eff = effective_fixture("read,write", "x86_64", "abc123", None);
        let index = DistributionIndex {
            path_counts: HashMap::from([(
                "kguardian/prod/deployment-web-abc123.json".to_string(),
                3,
            )]),
            total_nodes: 3,
        };
        let v = serde_json::to_value(ProfileSummary::build(&eff, &index)).unwrap();
        assert_eq!(v["distribution"]["state"], "Ready");
        assert_eq!(v["distribution"]["ready"], 3);
        assert_eq!(v["defaultAction"], "SCMP_ACT_LOG");
        assert_eq!(v["override"], serde_json::Value::Null);
        assert_eq!(
            v["recommendedSnippet"]["seccompProfile"]["localhostProfile"],
            "kguardian/prod/deployment-web-abc123.json"
        );
        assert_eq!(
            v["recommendedSnippet"]["seccompProfile"]["type"],
            "Localhost"
        );
    }

    #[test]
    fn profile_summary_reflects_the_effective_set_and_override() {
        let ovr = OverrideRow {
            pod_namespace: "prod".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            add_syscalls: "mmap".into(),
            remove_syscalls: "write".into(),
            default_action: Some("SCMP_ACT_ERRNO".into()),
            note: Some("scanner missed mmap".into()),
            updated_by: "alice".into(),
            updated_at: chrono::NaiveDateTime::default(),
            revision: 2,
        };
        let eff = effective_fixture("read,write", "x86_64", "deadbeef", Some(ovr));
        let index = DistributionIndex {
            path_counts: HashMap::new(),
            total_nodes: 4,
        };
        let v = serde_json::to_value(ProfileSummary::build(&eff, &index)).unwrap();
        assert_eq!(v["syscallCount"], 2); // read + mmap (write removed)
        assert_eq!(v["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(v["distribution"]["state"], "Pending");
        assert_eq!(v["override"]["add"], serde_json::json!(["mmap"]));
        assert_eq!(v["override"]["remove"], serde_json::json!(["write"]));
        assert_eq!(v["override"]["revision"], 2);
    }

    #[test]
    fn node_status_input_defaults_paths_to_empty() {
        let got: NodeStatusInput = serde_json::from_str(r#"{"node_name":"node-a"}"#).unwrap();
        assert!(got.paths.is_empty());
    }
}
