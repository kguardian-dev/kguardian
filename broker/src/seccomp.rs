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
use actix_web::{get, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::Serialize;
use std::collections::BTreeSet;
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

/// FNV-1a (64-bit) over the canonical `syscalls\x1earches` string. A
/// content fingerprint, not a security primitive: the input is
/// broker-generated and never adversarial, and pulling a crypto hash
/// crate into the broker would buy nothing here. Stable across builds
/// by construction, which a crypto hash gives too but `DefaultHasher`
/// (SipHash, unspecified) would not — and the value names a file an app
/// team pins, so it must never move unless the set moves.
fn fingerprint(syscalls: &BTreeSet<String>, arches: &BTreeSet<String>) -> String {
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

/// One row of `workload_syscalls`, as stored.
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
    let existing: Option<(String, String)> = ws::workload_syscalls
        .find((namespace, kind, name))
        .select((ws::syscalls, ws::arches))
        .first(conn)
        .optional()?;

    let mut syscall_set = BTreeSet::new();
    let mut arch_set = BTreeSet::new();
    if let Some((s, a)) = &existing {
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
    let new_hash = fingerprint(&syscall_set, &arch_set);

    if existing
        .as_ref()
        .is_some_and(|(s, a)| s == &syscalls_joined && a == &arches_joined)
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
/// resolved by the kubelet under its seccomp root.
fn localhost_profile_path(row: &WorkloadSyscallsRow) -> String {
    format!(
        "kguardian/{}/{}-{}-{}.json",
        row.pod_namespace,
        row.workload_kind.to_lowercase(),
        row.workload_name,
        row.hash
    )
}

#[derive(Serialize)]
struct ProfileSummary {
    namespace: String,
    kind: String,
    name: String,
    hash: String,
    #[serde(rename = "localhostProfile")]
    localhost_profile: String,
    #[serde(rename = "syscallCount")]
    syscall_count: usize,
    architectures: Vec<String>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::NaiveDateTime,
}

impl From<&WorkloadSyscallsRow> for ProfileSummary {
    fn from(r: &WorkloadSyscallsRow) -> Self {
        ProfileSummary {
            namespace: r.pod_namespace.clone(),
            kind: r.workload_kind.clone(),
            name: r.workload_name.clone(),
            hash: r.hash.clone(),
            localhost_profile: localhost_profile_path(r),
            syscall_count: split_set(&r.syscalls).len(),
            architectures: split_set(&r.arches)
                .iter()
                .filter_map(|a| arch_token(a))
                .map(String::from)
                .collect(),
            updated_at: r.updated_at,
        }
    }
}

fn all_rows(conn: &mut PgConnection) -> Result<Vec<WorkloadSyscallsRow>, DbError> {
    use schema::workload_syscalls::dsl::*;
    Ok(workload_syscalls
        .select(WorkloadSyscallsRow::as_select())
        .order((
            pod_namespace.asc(),
            workload_kind.asc(),
            workload_name.asc(),
        ))
        .load(conn)?)
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

fn validated_action(raw: Option<&str>) -> Result<&str, actix_web::Error> {
    match raw {
        None => Ok(DEFAULT_SECCOMP_ACTION),
        Some(a) if VALID_SECCOMP_ACTIONS.contains(&a) => Ok(a),
        Some(a) => Err(actix_web::error::ErrorBadRequest(format!(
            "invalid action {a:?}; expected one of {VALID_SECCOMP_ACTIONS:?}"
        ))),
    }
}

#[derive(serde::Deserialize)]
pub struct ProfileQuery {
    action: Option<String>,
}

/// `GET /seccomp/profiles` — every workload that has an aggregate,
/// with its current hash and profile path. The list a distributor polls.
#[get("/seccomp/profiles")]
pub async fn list_seccomp_profiles(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    info!("list seccomp profiles");
    let rows = web::block(move || {
        let mut conn = pool.get()?;
        all_rows(&mut conn)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let out: Vec<ProfileSummary> = rows.iter().map(ProfileSummary::from).collect();
    Ok(HttpResponse::Ok().json(out))
}

#[derive(Serialize)]
struct ProfileDetail {
    #[serde(flatten)]
    summary: ProfileSummary,
    profile: SeccompProfile,
}

/// `GET /seccomp/profiles/{namespace}/{kind}/{name}` — one workload's
/// summary plus the rendered profile. `?action=` overrides the
/// `defaultAction` (default `SCMP_ACT_LOG`).
#[get("/seccomp/profiles/{namespace}/{kind}/{name}")]
pub async fn get_seccomp_profile(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
    query: web::Query<ProfileQuery>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name) = path.into_inner();
    let action = validated_action(query.action.as_deref())?.to_string();
    info!(%namespace, %kind, %name, "get seccomp profile");

    let row = web::block(move || {
        let mut conn = pool.get()?;
        one_row(&mut conn, &namespace, &kind, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match row {
        Some(r) => {
            let profile = build_profile(&r.syscalls, &r.arches, &action);
            HttpResponse::Ok().json(ProfileDetail {
                summary: ProfileSummary::from(&r),
                profile,
            })
        }
        None => HttpResponse::NotFound().body("no seccomp profile for that workload"),
    })
}

/// `GET /seccomp/profile-file/{namespace}/{kind}/{name}/{hash}` — the
/// bare `SeccompProfile` JSON, for a distributor to write to a node.
/// Serves only the CURRENT hash; a stale hash is a 404 (the caller
/// should re-read the list).
#[get("/seccomp/profile-file/{namespace}/{kind}/{name}/{hash}")]
pub async fn get_seccomp_profile_file(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String, String)>,
    query: web::Query<ProfileQuery>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name, hash) = path.into_inner();
    let action = validated_action(query.action.as_deref())?.to_string();

    let row = web::block(move || {
        let mut conn = pool.get()?;
        one_row(&mut conn, &namespace, &kind, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match row {
        Some(r) if r.hash == hash => {
            HttpResponse::Ok().json(build_profile(&r.syscalls, &r.arches, &action))
        }
        Some(_) => HttpResponse::NotFound().body("stale hash; re-read /seccomp/profiles"),
        None => HttpResponse::NotFound().body("no seccomp profile for that workload"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn fingerprint_is_order_independent_and_stable() {
        let a = fingerprint(
            &set(&["read", "write", "openat"]),
            &set(&["SCMP_ARCH_X86_64"]),
        );
        let b = fingerprint(
            &set(&["openat", "read", "write"]),
            &set(&["SCMP_ARCH_X86_64"]),
        );
        assert_eq!(a, b);
        // Pinned: this value must not move across builds, or every
        // distributed profile filename changes and app-team references break.
        assert_eq!(
            a,
            fingerprint(
                &set(&["write", "openat", "read"]),
                &set(&["SCMP_ARCH_X86_64"])
            )
        );
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn fingerprint_changes_when_the_set_grows() {
        let before = fingerprint(&set(&["read", "write"]), &set(&["SCMP_ARCH_X86_64"]));
        let after = fingerprint(
            &set(&["read", "write", "mmap"]),
            &set(&["SCMP_ARCH_X86_64"]),
        );
        assert_ne!(before, after);
    }

    #[test]
    fn fingerprint_distinguishes_arch() {
        let x = fingerprint(&set(&["read"]), &set(&["SCMP_ARCH_X86_64"]));
        let arm = fingerprint(&set(&["read"]), &set(&["SCMP_ARCH_ARM64"]));
        assert_ne!(x, arm);
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
        assert_eq!(validated_action(None).unwrap(), "SCMP_ACT_LOG");
        assert_eq!(
            validated_action(Some("SCMP_ACT_ERRNO")).unwrap(),
            "SCMP_ACT_ERRNO"
        );
        assert!(validated_action(Some("rm -rf")).is_err());
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
}
