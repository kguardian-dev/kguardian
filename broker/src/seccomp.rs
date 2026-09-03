//! Per-workload seccomp observation, recommendation and reporting.
//!
//! `pod_syscalls` records one row per pod. This module rolls those up to
//! the stable `(namespace, kind, name)` workload identity the controller
//! puts on `pod_details`, keeps a **monotonic** union of the syscalls
//! ever seen (a profile must cover every code path, and must not narrow
//! when a replica goes away), fingerprints the set, and can render it as
//! a `SeccompProfile` document.
//!
//! Aggregation is triggered from the `/pod/syscalls` ingest path
//! (`add::create_pod_syscalls`) for the workloads whose pods appear in
//! the batch. A pod whose `pod_details` row has no `workload_kind` yet
//! (bare pod, or attribution not resolved) contributes to nothing.
//!
//! # Who owns what (CONTRACT v2)
//!
//! The broker is **never** the source of truth for what is deployed.
//! The user owns a `SeccompProfile` CR (`kguardian.dev/v1alpha1`) — in
//! git, typically — the controller reconciles it onto nodes, and the
//! broker only:
//!
//! 1. **observes** syscalls at a capture *tier* (`full | high | medium |
//!    low | custom`, stamped per pod on `pod_details.capture_level`);
//!    only `full` records every syscall, so `capture_summary` folds the
//!    pods that contributed to a workload's union to the LOWEST tier and
//!    `complete` is true only when every contributor is `full`;
//! 2. **recommends**: the `/export` route renders the observed set as a
//!    CR manifest the user can commit, with a loud warning comment when
//!    the capture is partial;
//! 3. **reports**: the controller mirrors every CR it sees into
//!    `seccomp_crs` and every node's on-disk files into
//!    `seccomp_node_status`, and the summary endpoints fold those into a
//!    `cr` block — deployed action, per-node readiness (path + hash
//!    match) and **drift** between the observed set and the CR's
//!    allow-list.
//!
//! The observed union is never edited here; an "override" is an edit to
//! the CR. One file per CR on a node: `kguardian/<namespace>/<cr>.json`.

use crate::schema;
use actix_web::{get, post, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use tracing::{debug, info, warn};

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

/// The action every recommendation is rendered with. A too-tight action
/// breaks the workload on its next restart, not immediately, so the
/// export is audit-only; the user promotes to enforcement by editing
/// `defaultAction` in their CR.
pub const DEFAULT_SECCOMP_ACTION: &str = "SCMP_ACT_LOG";
/// `spec.defaultAction` values the CRD accepts.
const VALID_DEFAULT_ACTIONS: [&str; 4] = [
    "SCMP_ACT_LOG",
    "SCMP_ACT_ERRNO",
    "SCMP_ACT_KILL",
    "SCMP_ACT_KILL_PROCESS",
];

/// FNV-1a (64-bit) over the canonical `syscalls\x1earches\x1edefault_action`
/// string. A content fingerprint, not a security primitive: the input is
/// broker-generated and never adversarial, and pulling a crypto hash
/// crate into the broker would buy nothing here. Stable across builds
/// by construction, which a crypto hash gives too but `DefaultHasher`
/// (SipHash, unspecified) would not.
///
/// This names the OBSERVED set (`workload_syscalls.hash`). It is a
/// different quantity from a CR's `status.hash`, which the controller
/// computes over the rendered file bytes.
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
/// runtime expect for a `Localhost` profile file, and the shape of the
/// CR's `spec` minus `workloadRef`. Matches the Go
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

/// A syntactically plausible syscall name: `^[a-z][a-z0-9_]{0,63}$`.
/// This rejects typos like `"OpenAt"`, `"openat "`, `"openat;"` and any
/// injection attempt. It does NOT confirm the name is a real syscall.
fn valid_syscall_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// A DNS-1123 subdomain, as Kubernetes validates `metadata.name`.
fn valid_k8s_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 253
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
}

fn validated_action(a: &str) -> Result<(), actix_web::Error> {
    if VALID_DEFAULT_ACTIONS.contains(&a) {
        Ok(())
    } else {
        Err(actix_web::error::ErrorBadRequest(format!(
            "invalid defaultAction {a:?}; expected one of {VALID_DEFAULT_ACTIONS:?}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Capture tiers
// ---------------------------------------------------------------------------

/// A pod's syscall capture tier, as stored on `pod_details.capture_level`.
///
/// The derived `Ord` is the "how much did we miss" order used to pick a
/// workload's LOWEST tier: `Full < High < Medium < Low < Unknown <
/// Custom`. `Unknown` (NULL: older controller, or an unrecognised
/// value) sorts after `Low` so that a fleet of `low` pods plus one
/// unknown reports `unknown` — NULL is *treated as* `low` for
/// completeness but *reported* as `unknown`. `Custom` is an
/// operator-supplied list that could be anything, so it is ranked as
/// the least trustworthy and surfaces first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CaptureLevel {
    Full,
    High,
    Medium,
    Low,
    Unknown,
    Custom,
}

impl CaptureLevel {
    fn parse(v: Option<&str>) -> Self {
        match v.map(str::trim) {
            Some("full") => CaptureLevel::Full,
            Some("high") => CaptureLevel::High,
            Some("medium") => CaptureLevel::Medium,
            Some("low") => CaptureLevel::Low,
            Some("custom") => CaptureLevel::Custom,
            _ => CaptureLevel::Unknown,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            CaptureLevel::Full => "full",
            CaptureLevel::High => "high",
            CaptureLevel::Medium => "medium",
            CaptureLevel::Low => "low",
            CaptureLevel::Unknown => "unknown",
            CaptureLevel::Custom => "custom",
        }
    }
}

/// One contributing pod's tier in a workload's capture summary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CapturePod {
    name: String,
    level: &'static str,
}

/// Most contributors listed per summary; the rest are a `more` count.
const MAX_CAPTURE_PODS: usize = 20;

/// The `capture` block of a profile summary: the LOWEST tier across the
/// pods that contributed to the workload's union, whether that makes
/// the profile complete, and the pods themselves so the UI can name
/// the culprits.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CaptureSummary {
    /// `full|high|medium|low|custom|unknown`.
    level: &'static str,
    /// True only when every contributor is `full` (and there is at
    /// least one). The union is complete iff every pod whose syscalls
    /// are in it was captured at `full` — liveness is irrelevant, so a
    /// scaled-to-zero Deployment or a CronJob between runs is still
    /// complete. No contributors at all ⇒ `unknown`/incomplete:
    /// nothing can be verified, and "never assume complete" is the rule.
    complete: bool,
    /// Worst tier first, then by name, capped at `MAX_CAPTURE_PODS` so
    /// the culprits are always the ones shown.
    pods: Vec<CapturePod>,
    /// Contributors not listed in `pods`.
    more: usize,
    /// Contributors that are not `full`, counted over the FULL set
    /// (not the capped list) — what "N pod(s)" means in the warning.
    incomplete: usize,
}

/// Fold `(pod_name, capture_level)` pairs to a `CaptureSummary`. Pure;
/// the DB side is `capture_index`.
fn capture_summary(pods: &[(String, Option<String>)]) -> CaptureSummary {
    let mut parsed: Vec<(String, CaptureLevel)> = pods
        .iter()
        .map(|(n, l)| (n.clone(), CaptureLevel::parse(l.as_deref())))
        .collect();
    parsed.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let lowest = parsed
        .iter()
        .map(|(_, l)| *l)
        .max()
        .unwrap_or(CaptureLevel::Unknown);
    let more = parsed.len().saturating_sub(MAX_CAPTURE_PODS);
    let incomplete = parsed
        .iter()
        .filter(|(_, l)| *l != CaptureLevel::Full)
        .count();
    CaptureSummary {
        level: lowest.as_str(),
        complete: !parsed.is_empty() && lowest == CaptureLevel::Full,
        incomplete,
        pods: parsed
            .into_iter()
            .take(MAX_CAPTURE_PODS)
            .map(|(name, l)| CapturePod {
                name,
                level: l.as_str(),
            })
            .collect(),
        more,
    }
}

impl CaptureSummary {
    /// `"web-2 (low), web-4 (unknown) (+3 more)"` — the non-full
    /// contributors, for the export warning. Counted over the full set
    /// even though only the capped list can be named.
    fn culprits(&self) -> String {
        let listed: Vec<String> = self
            .pods
            .iter()
            .filter(|p| p.level != "full")
            .map(|p| format!("{} ({})", p.name, p.level))
            .collect();
        let unlisted = self.incomplete.saturating_sub(listed.len());
        if unlisted > 0 {
            format!("{} (+{unlisted} more)", listed.join(", "))
        } else {
            listed.join(", ")
        }
    }
}

type WorkloadKey = (String, String, String);

/// Contributing pods per workload — every pod with a `pod_syscalls`
/// row whose `pod_details` row resolves to the workload, dead or alive
/// (the same join `recompute_workload` unions over; `pod_syscalls` is
/// never pruned). Loaded once per request so building N summaries
/// stays O(nodes + profiles + crs). `only` narrows the query to a
/// single workload for the detail endpoints.
struct CaptureIndex {
    pods: HashMap<WorkloadKey, Vec<(String, Option<String>)>>,
}

impl CaptureIndex {
    fn summary_for(&self, key: &WorkloadKey) -> CaptureSummary {
        capture_summary(self.pods.get(key).map(Vec::as_slice).unwrap_or(&[]))
    }
}

fn capture_index(
    conn: &mut PgConnection,
    only: Option<&WorkloadKey>,
) -> Result<CaptureIndex, DbError> {
    use schema::pod_details::dsl as pd;
    use schema::pod_syscalls::dsl as ps;
    let mut q = ps::pod_syscalls
        .inner_join(pd::pod_details.on(pd::pod_name.eq(ps::pod_name)))
        .filter(pd::workload_kind.is_not_null())
        .filter(pd::workload_name.is_not_null())
        .into_boxed();
    if let Some((ns, kind, name)) = only {
        q = q
            .filter(pd::pod_namespace.eq(ns))
            .filter(pd::workload_kind.eq(kind))
            .filter(pd::workload_name.eq(name));
    }
    /// `(namespace, kind, name, pod_name, capture_level)` as selected.
    type ContributorRow = (
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
    );
    let rows: Vec<ContributorRow> = q
        .select((
            pd::pod_namespace,
            pd::workload_kind,
            pd::workload_name,
            pd::pod_name,
            pd::capture_level,
        ))
        .load(conn)?;
    let mut pods: HashMap<WorkloadKey, Vec<(String, Option<String>)>> = HashMap::new();
    for (ns, kind, name, pod, level) in rows {
        let (Some(ns), Some(kind), Some(name)) = (ns, kind, name) else {
            continue;
        };
        pods.entry((ns, kind, name)).or_default().push((pod, level));
    }
    Ok(CaptureIndex { pods })
}

// ---------------------------------------------------------------------------
// Observed aggregate
// ---------------------------------------------------------------------------

/// One row of `workload_syscalls`, as stored. `hash` fingerprints the
/// observed `(syscalls, arches)` rendered with `SCMP_ACT_LOG`.
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
    let new_hash = fingerprint(&syscall_set, &arch_set, DEFAULT_SECCOMP_ACTION);

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

// ---------------------------------------------------------------------------
// CR mirror
// ---------------------------------------------------------------------------

/// One row of `seccomp_crs` — the controller's mirror of a
/// `SeccompProfile` CR. `syscalls` is the sorted csv of the CR's
/// `SCMP_ACT_ALLOW` names; `hash` is the CR's `status.hash`.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::seccomp_crs)]
struct CrRow {
    namespace: String,
    name: String,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    default_action: String,
    syscalls: String,
    architectures: String,
    hash: String,
    ready: i32,
    total: i32,
    dist_state: String,
    updated_at: chrono::NaiveDateTime,
}

/// `kguardian/<namespace>/<cr-name>.json` — the one file a CR produces
/// on every node, and what a pod template's `localhostProfile` points
/// at.
fn cr_profile_path(namespace: &str, cr_name: &str) -> String {
    format!("kguardian/{namespace}/{cr_name}.json")
}

/// `<kind lowercased>-<name>`, coerced to a DNS-1123 subdomain — the
/// `metadata.name` the export suggests. Workload names are already
/// DNS-1123, so this is mostly the lowercase; the coercion is belt and
/// braces for a `ReplicationController` named with odd characters.
fn suggested_cr_name(kind: &str, name: &str) -> String {
    let raw = format!("{}-{}", kind.to_lowercase(), name.to_lowercase());
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    while out.starts_with(['-', '.']) {
        out.remove(0);
    }
    while out.ends_with(['-', '.']) {
        out.pop();
    }
    out.truncate(253);
    if out.is_empty() {
        "seccomp-profile".to_string()
    } else {
        out
    }
}

/// Mirrored CRs keyed by the workload they reference, loaded once per
/// request. CRs without a `workloadRef` are not indexed (nothing to
/// match them to).
struct CrIndex {
    by_workload: HashMap<WorkloadKey, Vec<CrRow>>,
}

impl CrIndex {
    fn from_rows(rows: Vec<CrRow>) -> Self {
        let mut by_workload: HashMap<WorkloadKey, Vec<CrRow>> = HashMap::new();
        for r in rows {
            let (Some(kind), Some(name)) = (r.workload_kind.clone(), r.workload_name.clone())
            else {
                continue;
            };
            by_workload
                .entry((r.namespace.clone(), kind, name))
                .or_default()
                .push(r);
        }
        // Newest first, so `[0]` is the CR a summary reports when a
        // workload is referenced by more than one.
        for v in by_workload.values_mut() {
            v.sort_by(|a, b| {
                b.updated_at
                    .cmp(&a.updated_at)
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
        CrIndex { by_workload }
    }

    fn for_workload(&self, key: &WorkloadKey) -> &[CrRow] {
        self.by_workload.get(key).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn cr_index(conn: &mut PgConnection, only: Option<&WorkloadKey>) -> Result<CrIndex, DbError> {
    use schema::seccomp_crs::dsl as c;
    let mut q = c::seccomp_crs
        .filter(c::workload_kind.is_not_null())
        .filter(c::workload_name.is_not_null())
        .into_boxed();
    if let Some((ns, kind, name)) = only {
        q = q
            .filter(c::namespace.eq(ns))
            .filter(c::workload_kind.eq(kind))
            .filter(c::workload_name.eq(name));
    }
    let rows: Vec<CrRow> = q.select(CrRow::as_select()).load(conn)?;
    Ok(CrIndex::from_rows(rows))
}

/// Observed set vs the CR's allow-list.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Drift {
    /// Observed but not allowed by the CR — the ones that will be
    /// blocked once the CR enforces. Re-export to pick them up.
    missing: Vec<String>,
    /// Allowed by the CR but never observed (hand-added, or stale).
    extra: Vec<String>,
    #[serde(rename = "inSync")]
    in_sync: bool,
}

fn drift(observed: &BTreeSet<String>, cr_allowed: &BTreeSet<String>) -> Drift {
    let missing: Vec<String> = observed.difference(cr_allowed).cloned().collect();
    let extra: Vec<String> = cr_allowed.difference(observed).cloned().collect();
    let in_sync = missing.is_empty() && extra.is_empty();
    Drift {
        missing,
        extra,
        in_sync,
    }
}

// ---------------------------------------------------------------------------
// Node status / readiness
// ---------------------------------------------------------------------------

/// Distribution readiness for one CR: how many live nodes have its file
/// with the CR's current hash, out of how many. Referencing a profile
/// before it is `Ready` risks a pod scheduling onto a node that lacks
/// the file (`CreateContainerError`).
#[derive(Debug, Serialize, PartialEq, Eq)]
struct Distribution {
    /// Nodes reporting the path with a matching hash.
    ready: i64,
    total: i64,
    /// `Ready` | `Partial` | `Pending`.
    state: &'static str,
    /// Nodes reporting the path at all (stale hash, or a legacy
    /// hash-less report).
    present: i64,
}

impl Distribution {
    fn compute(ready: i64, total: i64, present: i64) -> Self {
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
            present,
        }
    }
}

/// Per-file node counts plus the live-node denominator, loaded once per
/// request so building N summaries is O(nodes + profiles + crs), not a
/// query per CR.
struct DistributionIndex {
    /// Nodes reporting `(path, hash)`.
    file_counts: HashMap<(String, String), i64>,
    /// Nodes reporting `path` with any (or no) hash.
    path_counts: HashMap<String, i64>,
    total_nodes: i64,
}

impl DistributionIndex {
    /// Fold one `(path, hash)` list per node into the index. Duplicates
    /// within a node count once.
    fn from_node_files<I, P>(nodes: I, total_nodes: i64) -> Self
    where
        I: IntoIterator<Item = P>,
        P: IntoIterator<Item = (String, Option<String>)>,
    {
        let mut file_counts: HashMap<(String, String), i64> = HashMap::new();
        let mut path_counts: HashMap<String, i64> = HashMap::new();
        for node in nodes {
            let files: BTreeSet<(String, Option<String>)> = node.into_iter().collect();
            let paths: BTreeSet<&String> = files.iter().map(|(p, _)| p).collect();
            for p in paths {
                *path_counts.entry(p.clone()).or_insert(0) += 1;
            }
            for (p, h) in files {
                if let Some(h) = h {
                    *file_counts.entry((p, h)).or_insert(0) += 1;
                }
            }
        }
        DistributionIndex {
            file_counts,
            path_counts,
            total_nodes,
        }
    }

    fn distribution_for(&self, path: &str, hash: &str) -> Distribution {
        let ready = if hash.is_empty() {
            0
        } else {
            self.file_counts
                .get(&(path.to_string(), hash.to_string()))
                .copied()
                .unwrap_or(0)
        };
        let present = self.path_counts.get(path).copied().unwrap_or(0);
        Distribution::compute(ready, self.total_nodes, present)
    }
}

/// Decode one node's stored `paths` JSON: `{path, hash}` objects, or
/// bare strings from a controller that predates hashes.
fn node_files_from_json(v: &serde_json::Value) -> Vec<(String, Option<String>)> {
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|e| {
            if let Some(s) = e.as_str() {
                return Some((s.to_string(), None));
            }
            let path = e.get("path")?.as_str()?.to_string();
            let hash = e
                .get("hash")
                .and_then(|h| h.as_str())
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(String::from);
            Some((path, hash))
        })
        .collect()
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
    Ok(DistributionIndex::from_node_files(
        rows.iter().map(node_files_from_json),
        total_nodes,
    ))
}

// ---------------------------------------------------------------------------
// Summaries
// ---------------------------------------------------------------------------

/// The `cr` block of a summary — the newest mirrored CR referencing the
/// workload, with readiness and drift.
#[derive(Serialize)]
struct CrBlock {
    name: String,
    #[serde(rename = "defaultAction")]
    default_action: String,
    hash: String,
    #[serde(rename = "syscallCount")]
    syscall_count: usize,
    architectures: Vec<String>,
    #[serde(rename = "localhostProfile")]
    localhost_profile: String,
    /// Broker-computed from node-status.
    distribution: Distribution,
    /// Mirrored verbatim from the CR's own `status.distribution`.
    #[serde(rename = "statusDistribution")]
    status_distribution: Option<serde_json::Value>,
    drift: Drift,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::NaiveDateTime,
}

impl CrBlock {
    fn build(cr: &CrRow, observed: &BTreeSet<String>, index: &DistributionIndex) -> Self {
        let path = cr_profile_path(&cr.namespace, &cr.name);
        let allowed = split_set(&cr.syscalls);
        let status_distribution = (cr.total > 0 || cr.ready > 0 || cr.dist_state != "Pending")
            .then(|| {
                serde_json::json!({
                    "ready": cr.ready, "total": cr.total, "state": cr.dist_state
                })
            });
        CrBlock {
            name: cr.name.clone(),
            default_action: cr.default_action.clone(),
            hash: cr.hash.clone(),
            syscall_count: allowed.len(),
            architectures: split_set(&cr.architectures).into_iter().collect(),
            distribution: index.distribution_for(&path, &cr.hash),
            localhost_profile: path,
            status_distribution,
            drift: drift(observed, &allowed),
            updated_at: cr.updated_at,
        }
    }
}

/// Observed row + the sets it decodes to, its capture summary, and the
/// mirrored CRs that reference it.
struct Observed {
    row: WorkloadSyscallsRow,
    syscalls: BTreeSet<String>,
    arches: BTreeSet<String>,
    capture: CaptureSummary,
    crs: Vec<CrRow>,
}

impl Observed {
    fn build(row: WorkloadSyscallsRow, captures: &CaptureIndex, crs: &CrIndex) -> Self {
        let key = (
            row.pod_namespace.clone(),
            row.workload_kind.clone(),
            row.workload_name.clone(),
        );
        let syscalls = split_set(&row.syscalls);
        let arches = split_set(&row.arches);
        Observed {
            capture: captures.summary_for(&key),
            crs: crs.for_workload(&key).to_vec(),
            row,
            syscalls,
            arches,
        }
    }
}

#[derive(Serialize)]
struct ProfileSummary {
    namespace: String,
    kind: String,
    name: String,
    /// Fingerprint of the OBSERVED set — not the CR file hash.
    hash: String,
    #[serde(rename = "syscallCount")]
    syscall_count: usize,
    architectures: Vec<String>,
    #[serde(rename = "updatedAt")]
    updated_at: chrono::NaiveDateTime,
    capture: CaptureSummary,
    #[serde(rename = "captureComplete")]
    capture_complete: bool,
    #[serde(rename = "suggestedName")]
    suggested_name: String,
    /// Drop-in for a pod template's `securityContext`, pointing at the
    /// deployed CR's file when one exists, else the suggested name.
    #[serde(rename = "recommendedSnippet")]
    recommended_snippet: serde_json::Value,
    #[serde(rename = "crCount")]
    cr_count: usize,
    cr: Option<CrBlock>,
}

impl ProfileSummary {
    fn build(obs: &Observed, index: &DistributionIndex) -> Self {
        let r = &obs.row;
        let suggested = suggested_cr_name(&r.workload_kind, &r.workload_name);
        let cr = obs
            .crs
            .first()
            .map(|c| CrBlock::build(c, &obs.syscalls, index));
        let path = cr
            .as_ref()
            .map(|c| c.localhost_profile.clone())
            .unwrap_or_else(|| cr_profile_path(&r.pod_namespace, &suggested));
        ProfileSummary {
            namespace: r.pod_namespace.clone(),
            kind: r.workload_kind.clone(),
            name: r.workload_name.clone(),
            hash: r.hash.clone(),
            syscall_count: obs.syscalls.len(),
            architectures: obs
                .arches
                .iter()
                .filter_map(|a| arch_token(a))
                .map(String::from)
                .collect(),
            updated_at: r.updated_at,
            capture_complete: obs.capture.complete,
            capture: obs.capture.clone(),
            suggested_name: suggested,
            recommended_snippet: serde_json::json!({
                "seccompProfile": { "type": "Localhost", "localhostProfile": path }
            }),
            cr_count: obs.crs.len(),
            cr,
        }
    }
}

/// Every workload's observed row with its capture summary and CRs,
/// ordered. Batch-loads each side table so the list endpoint stays
/// O(rows + contributors + crs), not a query per row.
fn all_observed(conn: &mut PgConnection) -> Result<Vec<Observed>, DbError> {
    use schema::workload_syscalls::dsl as ws;
    let rows: Vec<WorkloadSyscallsRow> = ws::workload_syscalls
        .select(WorkloadSyscallsRow::as_select())
        .order((
            ws::pod_namespace.asc(),
            ws::workload_kind.asc(),
            ws::workload_name.asc(),
        ))
        .load(conn)?;
    let captures = capture_index(conn, None)?;
    let crs = cr_index(conn, None)?;
    Ok(rows
        .into_iter()
        .map(|row| Observed::build(row, &captures, &crs))
        .collect())
}

/// One workload, or `None` when it has no observed aggregate yet.
fn one_observed(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<Option<Observed>, DbError> {
    let Some(row) = one_row(conn, ns, kind, name)? else {
        return Ok(None);
    };
    let key = (ns.to_string(), kind.to_string(), name.to_string());
    let captures = capture_index(conn, Some(&key))?;
    let crs = cr_index(conn, Some(&key))?;
    Ok(Some(Observed::build(row, &captures, &crs)))
}

/// Render the observed set as a profile document (audit action).
fn render(obs: &Observed) -> SeccompProfile {
    build_profile(
        &join_set(&obs.syscalls),
        &join_set(&obs.arches),
        DEFAULT_SECCOMP_ACTION,
    )
}

/// `GET /seccomp/profiles` — every workload that has an observed
/// aggregate, with its capture summary and any deployed CR (readiness +
/// drift). Read-only; the UI lists it, the controller reads the
/// `captureComplete` / `cr.drift` it needs for CR conditions.
#[get("/seccomp/profiles")]
pub async fn list_seccomp_profiles(
    req: actix_web::HttpRequest,
    pool: web::Data<DbPool>,
) -> actix_web::Result<impl Responder> {
    // The v1 `?state=published` filter is gone. Fail loudly rather than
    // return everything: a distributor that predates CR-driven
    // distribution would otherwise write a file for every workload.
    if has_query_param(req.query_string(), "state") {
        return Err(actix_web::error::ErrorBadRequest(
            "the ?state= filter was removed; distribution is driven by SeccompProfile CRs",
        ));
    }
    info!("list seccomp profiles");
    let out: Vec<ProfileSummary> = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        let all = all_observed(&mut conn)?;
        let index = distribution_index(&mut conn)?;
        Ok(all
            .iter()
            .map(|o| ProfileSummary::build(o, &index))
            .collect())
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(out))
}

fn has_query_param(query: &str, key: &str) -> bool {
    query
        .split('&')
        .any(|kv| kv.split('=').next().is_some_and(|k| k == key))
}

#[derive(Serialize)]
struct ProfileDetail {
    #[serde(flatten)]
    summary: ProfileSummary,
    profile: SeccompProfile,
}

/// `GET /seccomp/profiles/{namespace}/{kind}/{name}` — one workload's
/// summary plus the observed set rendered as a profile document.
#[get("/seccomp/profiles/{namespace}/{kind}/{name}")]
pub async fn get_seccomp_profile(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name) = path.into_inner();
    info!(%namespace, %kind, %name, "get seccomp profile");

    let result = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        match one_observed(&mut conn, &namespace, &kind, &name)? {
            Some(obs) => {
                let index = distribution_index(&mut conn)?;
                let profile = render(&obs);
                Ok(Some((ProfileSummary::build(&obs, &index), profile)))
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

/// `GET /seccomp/profile-file/{namespace}/{kind}/{name}/{hash}` — debug
/// render of the observed set as a bare profile document. Kept from v1
/// for `curl`-level inspection; nothing distributes it. `hash` must be
/// the current observed hash (a stale one is a 404).
#[get("/seccomp/profile-file/{namespace}/{kind}/{name}/{hash}")]
pub async fn get_seccomp_profile_file(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name, hash) = path.into_inner();

    let obs = web::block(move || {
        let mut conn = pool.get()?;
        one_observed(&mut conn, &namespace, &kind, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match obs {
        Some(o) if o.row.hash == hash => HttpResponse::Ok().json(render(&o)),
        Some(_) => HttpResponse::NotFound().body("stale hash; re-read /seccomp/profiles"),
        None => HttpResponse::NotFound().body("no seccomp profile for that workload"),
    })
}

// ---------------------------------------------------------------------------
// Export — the recommendation, as a CR manifest
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ExportMeta {
    name: String,
    namespace: String,
}

#[derive(Serialize)]
struct ExportWorkloadRef {
    kind: String,
    name: String,
}

#[derive(Serialize)]
struct ExportSpec {
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    architectures: Vec<String>,
    syscalls: Vec<SeccompRule>,
    #[serde(rename = "workloadRef")]
    workload_ref: ExportWorkloadRef,
}

/// The `SeccompProfile` CR manifest the export produces.
#[derive(Serialize)]
struct ExportDoc {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    metadata: ExportMeta,
    spec: ExportSpec,
}

/// Edits and options an export applies. Query string on GET, JSON body
/// on POST (the POST form carries the frontend's staged add/remove).
#[derive(Debug, Deserialize, Default)]
pub struct ExportOptions {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "defaultAction")]
    default_action: Option<String>,
    /// `yaml` (default) | `json`.
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
}

const MAX_EDIT_LIST: usize = 512;

/// Validated export options.
struct ExportPlan {
    name: Option<String>,
    default_action: String,
    json: bool,
    add: BTreeSet<String>,
    remove: BTreeSet<String>,
}

fn validate_export(opts: ExportOptions) -> Result<ExportPlan, actix_web::Error> {
    let ExportOptions {
        name,
        default_action,
        format,
        add,
        remove,
    } = opts;
    let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if let Some(n) = &name {
        if !valid_k8s_name(n) {
            return Err(actix_web::error::ErrorBadRequest(format!(
                "{n:?} is not a valid metadata.name (DNS-1123 subdomain)"
            )));
        }
    }
    let default_action = default_action
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| DEFAULT_SECCOMP_ACTION.to_string());
    validated_action(&default_action)?;
    let json = match format.as_deref().map(str::trim) {
        None | Some("") | Some("yaml") | Some("yml") => false,
        Some("json") => true,
        Some(other) => {
            return Err(actix_web::error::ErrorBadRequest(format!(
                "invalid format {other:?}; expected yaml or json"
            )))
        }
    };
    if add.len() > MAX_EDIT_LIST || remove.len() > MAX_EDIT_LIST {
        return Err(actix_web::error::ErrorBadRequest(format!(
            "add/remove lists are capped at {MAX_EDIT_LIST} entries"
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
    Ok(ExportPlan {
        name,
        default_action,
        json,
        add,
        remove,
    })
}

/// Build the CR document plus the comment header (YAML only) for an
/// observed workload.
fn export_document(obs: &Observed, plan: &ExportPlan) -> (ExportDoc, Vec<String>) {
    let r = &obs.row;
    let mut names = obs.syscalls.clone();
    names.extend(plan.add.iter().cloned());
    for x in &plan.remove {
        names.remove(x);
    }
    let arches: Vec<String> = obs
        .arches
        .iter()
        .filter_map(|a| arch_token(a))
        .map(String::from)
        .collect();
    let doc = ExportDoc {
        api_version: "kguardian.dev/v1alpha1",
        kind: "SeccompProfile",
        metadata: ExportMeta {
            name: plan
                .name
                .clone()
                .unwrap_or_else(|| suggested_cr_name(&r.workload_kind, &r.workload_name)),
            namespace: r.pod_namespace.clone(),
        },
        spec: ExportSpec {
            default_action: plan.default_action.clone(),
            architectures: arches,
            syscalls: if names.is_empty() {
                Vec::new()
            } else {
                vec![SeccompRule {
                    names: names.into_iter().collect(),
                    action: "SCMP_ACT_ALLOW".to_string(),
                }]
            },
            workload_ref: ExportWorkloadRef {
                kind: r.workload_kind.clone(),
                name: r.workload_name.clone(),
            },
        },
    };

    let c = &obs.capture;
    let contributors = c.pods.len() + c.more;
    let mut header = vec![
        "kguardian SeccompProfile export".to_string(),
        format!(
            "workload: {} {}/{}",
            r.pod_namespace, r.workload_kind, r.workload_name
        ),
        format!(
            "observed syscalls: {} ({})",
            obs.syscalls.len(),
            if obs.arches.is_empty() {
                "no architectures recorded".to_string()
            } else {
                join_set(&obs.arches)
            }
        ),
        if c.complete {
            format!(
                "capture: {} — complete ({contributors} contributing pod(s))",
                c.level
            )
        } else {
            format!(
                "capture: {} — INCOMPLETE ({} of {contributors} contributing pod(s) below full)",
                c.level, c.incomplete
            )
        },
    ];
    if !plan.add.is_empty() || !plan.remove.is_empty() {
        header.push(format!(
            "edits applied: +[{}] -[{}]",
            join_set(&plan.add),
            join_set(&plan.remove)
        ));
    }
    if !c.complete {
        let detail = if contributors == 0 {
            "no pod has contributed syscalls yet".to_string()
        } else {
            format!("{} on {} pod(s): {}", c.level, c.incomplete, c.culprits())
        };
        header.push(format!(
            "WARNING: partial capture ({detail}) — this profile will block"
        ));
        header.push(
            "WARNING: syscalls the workload makes. Raise the tier to \"full\" (kguardian.dev/syscall-capture"
                .to_string(),
        );
        header.push(
            "WARNING: annotation or SYSCALL_CAPTURE_LEVEL) and re-export before enforcing."
                .to_string(),
        );
    }
    (doc, header)
}

/// Quote a YAML scalar unless it is plainly safe. Everything the export
/// emits is DNS-1123 / `[a-z0-9_]` / `SCMP_*`, so this almost never
/// quotes — but a namespace or name is user data and must never be able
/// to break the document.
fn yaml_scalar(s: &str) -> String {
    let plain_safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'/')
        && !s.starts_with(['-', '.'])
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
        )
        && s.parse::<f64>().is_err();
    if plain_safe {
        s.to_string()
    } else {
        let mut out = String::from("\"");
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }
}

/// Hand-rendered YAML for the fixed `ExportDoc` shape. Deterministic and
/// dependency-free; the structure is small enough that a YAML library
/// would only add a transitive crate for the sake of two nested lists.
fn render_yaml(doc: &ExportDoc, header: &[String]) -> String {
    let mut y = String::new();
    for line in header {
        y.push_str("# ");
        y.push_str(line);
        y.push('\n');
    }
    y.push_str(&format!("apiVersion: {}\n", doc.api_version));
    y.push_str(&format!("kind: {}\n", doc.kind));
    y.push_str("metadata:\n");
    y.push_str(&format!("  name: {}\n", yaml_scalar(&doc.metadata.name)));
    y.push_str(&format!(
        "  namespace: {}\n",
        yaml_scalar(&doc.metadata.namespace)
    ));
    y.push_str("spec:\n");
    y.push_str(&format!(
        "  defaultAction: {}\n",
        yaml_scalar(&doc.spec.default_action)
    ));
    if !doc.spec.architectures.is_empty() {
        y.push_str("  architectures:\n");
        for a in &doc.spec.architectures {
            y.push_str(&format!("    - {}\n", yaml_scalar(a)));
        }
    }
    if doc.spec.syscalls.is_empty() {
        y.push_str("  syscalls: []\n");
    } else {
        y.push_str("  syscalls:\n");
        for rule in &doc.spec.syscalls {
            y.push_str("    - names:\n");
            for n in &rule.names {
                y.push_str(&format!("        - {}\n", yaml_scalar(n)));
            }
            y.push_str(&format!("      action: {}\n", yaml_scalar(&rule.action)));
        }
    }
    y.push_str("  workloadRef:\n");
    y.push_str(&format!(
        "    kind: {}\n",
        yaml_scalar(&doc.spec.workload_ref.kind)
    ));
    y.push_str(&format!(
        "    name: {}\n",
        yaml_scalar(&doc.spec.workload_ref.name)
    ));
    y
}

async fn export_impl(
    pool: web::Data<DbPool>,
    (namespace, kind, name): (String, String, String),
    plan: ExportPlan,
) -> actix_web::Result<HttpResponse> {
    info!(%namespace, %kind, %name, json = plan.json, "export seccomp profile CR");
    let obs = web::block(move || {
        let mut conn = pool.get()?;
        one_observed(&mut conn, &namespace, &kind, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let Some(obs) = obs else {
        return Ok(HttpResponse::NotFound().body("no seccomp profile for that workload"));
    };
    let (doc, header) = export_document(&obs, &plan);
    Ok(if plan.json {
        HttpResponse::Ok().json(doc)
    } else {
        HttpResponse::Ok()
            .content_type("application/yaml")
            .body(render_yaml(&doc, &header))
    })
}

/// `GET /seccomp/profiles/{namespace}/{kind}/{name}/export?name=&defaultAction=&format=`
/// — the observed set as a `SeccompProfile` CR manifest (YAML by
/// default; `format=json`). Never writes anything: the user commits
/// and applies it.
#[get("/seccomp/profiles/{namespace}/{kind}/{name}/export")]
pub async fn export_seccomp_profile(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
    query: web::Query<ExportOptions>,
) -> actix_web::Result<impl Responder> {
    let plan = validate_export(query.into_inner())?;
    export_impl(pool, path.into_inner(), plan).await
}

/// `POST /seccomp/profiles/{namespace}/{kind}/{name}/export` — same
/// document, with the options in a JSON body plus `add` / `remove`
/// syscall edits applied to the observed set (the UI's staged edits).
#[post("/seccomp/profiles/{namespace}/{kind}/{name}/export")]
pub async fn export_seccomp_profile_post(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String, String)>,
    body: web::Json<ExportOptions>,
) -> actix_web::Result<impl Responder> {
    let plan = validate_export(body.into_inner())?;
    export_impl(pool, path.into_inner(), plan).await
}

// ---------------------------------------------------------------------------
// Controller → broker: node status and CR mirror
// ---------------------------------------------------------------------------

/// One on-disk file as the distributor reports it.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeFile {
    path: String,
    #[serde(default)]
    hash: Option<String>,
}

/// One `paths[]` entry: `{path, hash}` from the current controller, or
/// a bare string from one that predates hashes.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PathEntry {
    File(NodeFile),
    Path(String),
}

/// Body of `POST /seccomp/node-status`. The controller sends `paths`
/// as `{path, hash}` objects; `files` is accepted as an alias and bare
/// strings are tolerated (present, never Ready).
#[derive(Deserialize)]
pub struct NodeStatusInput {
    node_name: String,
    #[serde(default)]
    paths: Vec<PathEntry>,
    #[serde(default)]
    files: Vec<NodeFile>,
}

impl NodeStatusInput {
    /// Merge both fields into one de-duplicated `{path, hash}` list.
    fn files(self) -> Vec<NodeFile> {
        let mut set: BTreeSet<NodeFile> = self.files.into_iter().collect();
        for p in self.paths {
            set.insert(match p {
                PathEntry::File(f) => f,
                PathEntry::Path(path) => NodeFile { path, hash: None },
            });
        }
        set.into_iter()
            .map(|mut f| {
                f.hash = f
                    .hash
                    .map(|h| h.trim().to_string())
                    .filter(|h| !h.is_empty());
                f
            })
            .collect()
    }
}

/// `POST /seccomp/node-status` — the distributor reports, after each
/// pass, the full set of profile files present on its node. Replaces the
/// node's row wholesale.
#[post("/seccomp/node-status")]
pub async fn post_seccomp_node_status(
    pool: web::Data<DbPool>,
    body: web::Json<NodeStatusInput>,
) -> actix_web::Result<impl Responder> {
    let input = body.into_inner();
    let node_name = input.node_name.clone();
    if node_name.trim().is_empty() {
        return Err(actix_web::error::ErrorBadRequest("node_name is required"));
    }
    let files = input.files();
    debug!(node = %node_name, files = files.len(), "seccomp node status");

    web::block(move || -> Result<(), DbError> {
        use schema::seccomp_node_status::dsl as sns;
        let mut conn = pool.get()?;
        let now = chrono::Utc::now().naive_utc();
        let json = serde_json::to_value(&files)?;
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

#[derive(Debug, Deserialize)]
pub struct CrRuleInput {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    action: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CrWorkloadRefInput {
    kind: String,
    name: String,
}

#[derive(Debug, Deserialize)]
pub struct CrSpecInput {
    #[serde(default, rename = "defaultAction")]
    default_action: Option<String>,
    #[serde(default)]
    architectures: Option<Vec<String>>,
    #[serde(default)]
    syscalls: Vec<CrRuleInput>,
    #[serde(default, rename = "workloadRef")]
    workload_ref: Option<CrWorkloadRefInput>,
}

#[derive(Debug, Deserialize)]
pub struct CrDistributionInput {
    #[serde(default)]
    ready: i32,
    #[serde(default)]
    total: i32,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CrStatusInput {
    #[serde(default)]
    distribution: Option<CrDistributionInput>,
}

/// Body of `PUT /seccomp/crs/{namespace}/{name}` — the CR as the
/// controller sees it. The controller puts `distribution` at the top
/// level; `status.distribution` is accepted too.
#[derive(Debug, Deserialize)]
pub struct CrMirrorInput {
    spec: CrSpecInput,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    distribution: Option<CrDistributionInput>,
    #[serde(default)]
    status: Option<CrStatusInput>,
}

/// What the mirror stores for one CR.
#[derive(Debug, PartialEq, Eq)]
struct CrMirror {
    workload_kind: Option<String>,
    workload_name: Option<String>,
    default_action: String,
    /// Sorted csv of the `SCMP_ACT_ALLOW` names.
    syscalls: String,
    architectures: String,
    hash: String,
    ready: i32,
    total: i32,
    dist_state: String,
}

impl CrMirror {
    fn from_input(input: CrMirrorInput, ns: &str, name: &str) -> Self {
        let CrMirrorInput {
            spec,
            hash,
            distribution,
            status,
        } = input;
        let mut allowed = BTreeSet::new();
        for rule in spec.syscalls {
            let action = rule.action.as_deref().unwrap_or("SCMP_ACT_ALLOW");
            if action != "SCMP_ACT_ALLOW" {
                continue;
            }
            for n in rule.names {
                let n = n.trim().to_string();
                if valid_syscall_name(&n) {
                    allowed.insert(n);
                } else {
                    warn!(namespace = ns, cr = name, syscall = %n, "mirrored CR carries an invalid syscall name; skipped");
                }
            }
        }
        let arches: BTreeSet<String> = spec
            .architectures
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        let (workload_kind, workload_name) = match spec.workload_ref {
            Some(w) if !w.kind.trim().is_empty() && !w.name.trim().is_empty() => (
                Some(w.kind.trim().to_string()),
                Some(w.name.trim().to_string()),
            ),
            _ => (None, None),
        };
        let dist = distribution.or_else(|| status.and_then(|s| s.distribution));
        CrMirror {
            workload_kind,
            workload_name,
            default_action: spec
                .default_action
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .unwrap_or_else(|| DEFAULT_SECCOMP_ACTION.to_string()),
            syscalls: join_set(&allowed),
            architectures: join_set(&arches),
            hash: hash.map(|h| h.trim().to_string()).unwrap_or_default(),
            ready: dist.as_ref().map(|d| d.ready).unwrap_or(0),
            total: dist.as_ref().map(|d| d.total).unwrap_or(0),
            dist_state: dist
                .and_then(|d| d.state)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "Pending".to_string()),
        }
    }
}

/// `PUT /seccomp/crs/{namespace}/{name}` — upsert the mirror of one
/// `SeccompProfile` CR. Idempotent; every controller sends the same
/// thing on every watch event / resync.
#[actix_web::put("/seccomp/crs/{namespace}/{name}")]
pub async fn put_seccomp_cr(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String)>,
    body: web::Json<CrMirrorInput>,
) -> actix_web::Result<impl Responder> {
    let (namespace, name) = path.into_inner();
    if !valid_k8s_name(&namespace) || !valid_k8s_name(&name) {
        return Err(actix_web::error::ErrorBadRequest(
            "namespace and name must be DNS-1123 subdomains",
        ));
    }
    let m = CrMirror::from_input(body.into_inner(), &namespace, &name);
    debug!(%namespace, %name, hash = %m.hash, syscalls = split_set(&m.syscalls).len(), "mirror seccomp CR");

    let out = web::block(move || -> Result<serde_json::Value, DbError> {
        use schema::seccomp_crs::dsl as c;
        let mut conn = pool.get()?;
        let now = chrono::Utc::now().naive_utc();
        diesel::insert_into(c::seccomp_crs)
            .values((
                c::namespace.eq(&namespace),
                c::name.eq(&name),
                c::workload_kind.eq(&m.workload_kind),
                c::workload_name.eq(&m.workload_name),
                c::default_action.eq(&m.default_action),
                c::syscalls.eq(&m.syscalls),
                c::architectures.eq(&m.architectures),
                c::hash.eq(&m.hash),
                c::ready.eq(m.ready),
                c::total.eq(m.total),
                c::dist_state.eq(&m.dist_state),
                c::updated_at.eq(now),
            ))
            .on_conflict((c::namespace, c::name))
            .do_update()
            .set((
                c::workload_kind.eq(&m.workload_kind),
                c::workload_name.eq(&m.workload_name),
                c::default_action.eq(&m.default_action),
                c::syscalls.eq(&m.syscalls),
                c::architectures.eq(&m.architectures),
                c::hash.eq(&m.hash),
                c::ready.eq(m.ready),
                c::total.eq(m.total),
                c::dist_state.eq(&m.dist_state),
                c::updated_at.eq(now),
            ))
            .execute(&mut conn)?;
        Ok(serde_json::json!({
            "namespace": namespace, "name": name, "hash": m.hash,
            "syscallCount": split_set(&m.syscalls).len(),
        }))
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(out))
}

/// `DELETE /seccomp/crs/{namespace}/{name}` — the CR is gone; drop the
/// mirror row. The summaries stop reporting a `cr` for that workload.
#[actix_web::delete("/seccomp/crs/{namespace}/{name}")]
pub async fn delete_seccomp_cr(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<impl Responder> {
    let (namespace, name) = path.into_inner();
    info!(%namespace, %name, "delete seccomp CR mirror");
    let deleted = web::block(move || -> Result<bool, DbError> {
        use schema::seccomp_crs::dsl as c;
        let mut conn = pool.get()?;
        let n = diesel::delete(c::seccomp_crs.find((&namespace, &name))).execute(&mut conn)?;
        Ok(n > 0)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(if deleted {
        HttpResponse::Ok().json(serde_json::json!({ "deleted": true }))
    } else {
        HttpResponse::NotFound().body("no mirrored CR by that name")
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
    fn build_profile_allowlists_observed_syscalls() {
        let p = build_profile("openat,read,write", "x86_64", "SCMP_ACT_ERRNO");
        assert_eq!(p.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(p.architectures, vec!["SCMP_ARCH_X86_64"]);
        assert_eq!(p.syscalls.len(), 1);
        assert_eq!(p.syscalls[0].action, "SCMP_ACT_ALLOW");
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
    fn validated_action_accepts_crd_enum_and_rejects_garbage() {
        for ok in [
            "SCMP_ACT_LOG",
            "SCMP_ACT_ERRNO",
            "SCMP_ACT_KILL",
            "SCMP_ACT_KILL_PROCESS",
        ] {
            assert!(validated_action(ok).is_ok(), "{ok}");
        }
        assert!(validated_action("SCMP_ACT_ALLOW").is_err());
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
    fn valid_k8s_name_rules() {
        for ok in ["web", "deployment-web", "a.b-c", "x1"] {
            assert!(valid_k8s_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-web",
            "web-",
            "Web",
            "a_b",
            "a b",
            "a".repeat(254).as_str(),
        ] {
            assert!(!valid_k8s_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn suggested_cr_name_is_kind_dash_name_dns_safe() {
        assert_eq!(suggested_cr_name("Deployment", "web"), "deployment-web");
        assert_eq!(suggested_cr_name("CronJob", "nightly"), "cronjob-nightly");
        assert_eq!(
            suggested_cr_name("ReplicationController", "Odd_Name!"),
            "replicationcontroller-odd-name"
        );
        assert!(valid_k8s_name(&suggested_cr_name("StatefulSet", "my-db")));
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

    // ---- readiness ---------------------------------------------------

    const PATH: &str = "kguardian/prod/deployment-web.json";
    const HASH: &str = "0123456789abcdef";

    fn files(items: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
        items
            .iter()
            .map(|(p, h)| (p.to_string(), h.map(String::from)))
            .collect()
    }

    fn empty_index() -> DistributionIndex {
        DistributionIndex::from_node_files(Vec::<Vec<(String, Option<String>)>>::new(), 0)
    }

    #[test]
    fn distribution_state_transitions() {
        let st = |ready, total| Distribution::compute(ready, total, ready).state;
        assert_eq!(st(0, 0), "Pending");
        assert_eq!(st(0, 5), "Pending");
        assert_eq!(st(2, 5), "Partial");
        assert_eq!(st(5, 5), "Ready");
        // Defensive: more reporters than the live-node count (a node
        // draining, say) still reads as Ready, never a >100% Partial.
        assert_eq!(st(6, 5), "Ready");
    }

    #[test]
    fn readiness_requires_path_and_matching_hash() {
        // node-a: current hash. node-b: stale hash. node-c: legacy
        // hash-less report. node-d: nothing.
        let index = DistributionIndex::from_node_files(
            vec![
                files(&[(PATH, Some(HASH))]),
                files(&[(PATH, Some("ffffffffffffffff"))]),
                files(&[(PATH, None)]),
                files(&[]),
            ],
            4,
        );
        let d = index.distribution_for(PATH, HASH);
        assert_eq!(d.ready, 1);
        assert_eq!(d.present, 3);
        assert_eq!(d.total, 4);
        assert_eq!(d.state, "Partial");
    }

    #[test]
    fn readiness_is_never_ready_for_an_empty_cr_hash() {
        // The controller has not rendered yet (status.hash absent): a
        // node reporting any hash must not count.
        let index = DistributionIndex::from_node_files(vec![files(&[(PATH, Some(HASH))])], 1);
        let d = index.distribution_for(PATH, "");
        assert_eq!((d.ready, d.present), (0, 1));
        assert_eq!(d.state, "Pending");
    }

    #[test]
    fn readiness_counts_a_node_once_despite_duplicates() {
        let index = DistributionIndex::from_node_files(
            vec![files(&[
                (PATH, Some(HASH)),
                (PATH, Some(HASH)),
                (PATH, None),
            ])],
            1,
        );
        let d = index.distribution_for(PATH, HASH);
        assert_eq!((d.ready, d.present), (1, 1));
        assert_eq!(d.state, "Ready");
    }

    #[test]
    fn node_files_from_json_accepts_objects_and_legacy_strings() {
        let v = serde_json::json!([
            { "path": PATH, "hash": HASH },
            { "path": "kguardian/prod/x.json", "hash": "" },
            "kguardian/prod/legacy.json",
            42
        ]);
        assert_eq!(
            node_files_from_json(&v),
            files(&[
                (PATH, Some(HASH)),
                ("kguardian/prod/x.json", None),
                ("kguardian/prod/legacy.json", None),
            ])
        );
    }

    #[test]
    fn node_status_input_accepts_controller_objects_alias_and_legacy_strings() {
        // The controller's shape: paths[] of {path, hash}.
        let got: NodeStatusInput = serde_json::from_str(
            r#"{"node_name":"node-a","paths":[{"path":"kguardian/p/a.json","hash":" h1 "}]}"#,
        )
        .unwrap();
        let files = got.files();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "kguardian/p/a.json");
        assert_eq!(files[0].hash.as_deref(), Some("h1"));
        // Mixed: `files` alias + legacy bare strings in `paths`.
        let got: NodeStatusInput = serde_json::from_str(
            r#"{"node_name":"node-a","files":[{"path":"kguardian/p/a.json","hash":"h1"}],
                "paths":["kguardian/p/b.json", {"path":"kguardian/p/c.json","hash":""}]}"#,
        )
        .unwrap();
        let files = got.files();
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].hash.as_deref(), Some("h1"));
        assert_eq!(files[1].path, "kguardian/p/b.json");
        assert_eq!(files[1].hash, None);
        assert_eq!(files[2].hash, None, "blank hash normalises to none");
        let got: NodeStatusInput = serde_json::from_str(r#"{"node_name":"node-a"}"#).unwrap();
        assert!(got.files().is_empty());
    }

    // ---- capture tiers -------------------------------------------

    fn pods(items: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
        items
            .iter()
            .map(|(n, l)| (n.to_string(), l.map(String::from)))
            .collect()
    }

    #[test]
    fn capture_all_full_is_complete() {
        let c = capture_summary(&pods(&[("web-1", Some("full")), ("web-2", Some("full"))]));
        assert_eq!(c.level, "full");
        assert!(c.complete);
        assert_eq!(c.incomplete, 0);
    }

    #[test]
    fn capture_lowest_tier_wins() {
        let c = capture_summary(&pods(&[
            ("web-1", Some("full")),
            ("web-2", Some("medium")),
            ("web-3", Some("high")),
        ]));
        assert_eq!(c.level, "medium");
        assert!(!c.complete);
        assert_eq!(c.pods[0].name, "web-2");
        assert_eq!(c.pods[1].name, "web-3");
        assert_eq!(c.pods[2].name, "web-1");
        assert_eq!(c.incomplete, 2);
    }

    #[test]
    fn capture_low_is_below_high_and_medium() {
        let c = capture_summary(&pods(&[("a", Some("low")), ("b", Some("high"))]));
        assert_eq!(c.level, "low");
        assert!(!c.complete);
    }

    #[test]
    fn capture_null_is_unknown_and_never_complete() {
        let c = capture_summary(&pods(&[("web-1", Some("full")), ("web-2", None)]));
        assert_eq!(c.level, "unknown");
        assert!(!c.complete);
        assert_eq!(c.pods[0].level, "unknown");
        let c = capture_summary(&pods(&[("a", Some("low")), ("b", None)]));
        assert_eq!(c.level, "unknown");
        let c = capture_summary(&pods(&[("a", Some("ultra"))]));
        assert_eq!(c.level, "unknown");
    }

    #[test]
    fn capture_custom_is_unordered_and_surfaces_first() {
        let c = capture_summary(&pods(&[("a", Some("custom")), ("b", Some("low"))]));
        assert_eq!(c.level, "custom");
        assert!(!c.complete);
    }

    #[test]
    fn capture_no_contributors_is_unknown_and_incomplete() {
        let c = capture_summary(&[]);
        assert_eq!(c.level, "unknown");
        assert!(!c.complete);
        assert!(c.pods.is_empty());
    }

    #[test]
    fn capture_dead_full_contributors_are_complete_with_zero_live_pods() {
        let c = capture_summary(&pods(&[
            ("nightly-28901234-abcde", Some("full")),
            ("nightly-28902674-fghij", Some("full")),
        ]));
        assert!(c.complete);
    }

    #[test]
    fn capture_one_dead_low_contributor_makes_the_union_incomplete() {
        let c = capture_summary(&pods(&[
            ("nightly-old", Some("low")),
            ("nightly-new", Some("full")),
        ]));
        assert_eq!(c.level, "low");
        assert!(!c.complete);
        assert_eq!(c.culprits(), "nightly-old (low)");
    }

    #[test]
    fn capture_pods_list_is_capped_and_culprits_count_the_full_set() {
        let many: Vec<(String, Option<String>)> = (0..25)
            .map(|i| (format!("web-{i:02}"), Some("low".to_string())))
            .collect();
        let c = capture_summary(&many);
        assert_eq!(c.pods.len(), MAX_CAPTURE_PODS);
        assert_eq!(c.more, 5);
        assert_eq!(c.incomplete, 25);
        let s = c.culprits();
        assert!(s.contains("web-19 (low)") && !s.contains("web-20"), "{s}");
        assert!(s.ends_with("(+5 more)"), "{s}");
    }

    #[test]
    fn capture_summary_serialises_with_the_contract_shape() {
        let c = capture_summary(&pods(&[("web-1", Some("high"))]));
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "level": "high", "complete": false,
                "pods": [{ "name": "web-1", "level": "high" }], "more": 0, "incomplete": 1
            })
        );
    }

    // ---- drift + CR matching -------------------------------------------

    #[test]
    fn drift_set_maths() {
        let d = drift(
            &set(&["read", "write", "mmap"]),
            &set(&["read", "write", "ptrace"]),
        );
        assert_eq!(d.missing, vec!["mmap"]);
        assert_eq!(d.extra, vec!["ptrace"]);
        assert!(!d.in_sync);
        let d = drift(&set(&["read"]), &set(&["read"]));
        assert!(d.in_sync && d.missing.is_empty() && d.extra.is_empty());
        let d = drift(&set(&["read"]), &BTreeSet::new());
        assert_eq!(d.missing, vec!["read"]);
    }

    fn cr_row(name: &str, workload: Option<(&str, &str)>, hash: &str, secs: i64) -> CrRow {
        CrRow {
            namespace: "prod".into(),
            name: name.into(),
            workload_kind: workload.map(|w| w.0.to_string()),
            workload_name: workload.map(|w| w.1.to_string()),
            default_action: "SCMP_ACT_LOG".into(),
            syscalls: "read,write".into(),
            architectures: "SCMP_ARCH_X86_64".into(),
            hash: hash.into(),
            ready: 0,
            total: 0,
            dist_state: "Pending".into(),
            updated_at: chrono::DateTime::from_timestamp(secs, 0)
                .unwrap()
                .naive_utc(),
        }
    }

    fn key(ns: &str, kind: &str, name: &str) -> WorkloadKey {
        (ns.into(), kind.into(), name.into())
    }

    #[test]
    fn cr_index_matches_by_workload_ref_newest_first() {
        let index = CrIndex::from_rows(vec![
            cr_row("old", Some(("Deployment", "web")), "h1", 100),
            cr_row("new", Some(("Deployment", "web")), "h2", 200),
            cr_row("other", Some(("Deployment", "api")), "h3", 300),
            cr_row("noref", None, "h4", 400),
        ]);
        let web = index.for_workload(&key("prod", "Deployment", "web"));
        assert_eq!(web.len(), 2);
        assert_eq!(web[0].name, "new", "newest CR is reported");
        assert_eq!(
            index.for_workload(&key("prod", "Deployment", "api")).len(),
            1
        );
        assert!(index
            .for_workload(&key("prod", "Deployment", "nope"))
            .is_empty());
        assert!(index
            .for_workload(&key("other", "Deployment", "web"))
            .is_empty());
    }

    fn observed_fixture(syscalls: &str, arches: &str, crs: Vec<CrRow>) -> Observed {
        let row = WorkloadSyscallsRow {
            pod_namespace: "prod".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            syscalls: syscalls.into(),
            arches: arches.into(),
            hash: "1c7725691d885dec".into(),
            updated_at: chrono::NaiveDateTime::default(),
        };
        Observed {
            syscalls: split_set(syscalls),
            arches: split_set(arches),
            capture: capture_summary(&pods(&[("web-1", Some("full"))])),
            crs,
            row,
        }
    }

    #[test]
    fn summary_without_cr_points_snippet_at_suggested_name() {
        let obs = observed_fixture("read,write", "x86_64", Vec::new());
        let v = serde_json::to_value(ProfileSummary::build(&obs, &empty_index())).unwrap();
        assert_eq!(v["suggestedName"], "deployment-web");
        assert_eq!(v["cr"], serde_json::Value::Null);
        assert_eq!(v["crCount"], 0);
        assert_eq!(v["captureComplete"], true);
        assert_eq!(v["hash"], "1c7725691d885dec");
        assert_eq!(v["syscallCount"], 2);
        assert_eq!(
            v["recommendedSnippet"]["seccompProfile"]["localhostProfile"],
            "kguardian/prod/deployment-web.json"
        );
        // v1 fields are gone.
        for gone in [
            "state",
            "publishedAt",
            "stableProfile",
            "localhostProfile",
            "defaultAction",
            "override",
            "distribution",
        ] {
            assert!(v.get(gone).is_none(), "{gone} must not be in the summary");
        }
    }

    #[test]
    fn summary_with_cr_reports_drift_readiness_and_count() {
        let mut cr = cr_row("custom-name", Some(("Deployment", "web")), HASH, 200);
        cr.syscalls = "ptrace,read".into();
        cr.default_action = "SCMP_ACT_ERRNO".into();
        cr.ready = 12;
        cr.total = 12;
        cr.dist_state = "Ready".into();
        let older = cr_row("older", Some(("Deployment", "web")), "h0", 100);
        let obs = observed_fixture("read,write", "x86_64", vec![cr, older]);
        let index = DistributionIndex::from_node_files(
            vec![
                files(&[("kguardian/prod/custom-name.json", Some(HASH))]),
                files(&[("kguardian/prod/custom-name.json", Some("stale"))]),
            ],
            2,
        );
        let v = serde_json::to_value(ProfileSummary::build(&obs, &index)).unwrap();
        assert_eq!(v["crCount"], 2);
        let cr = &v["cr"];
        assert_eq!(cr["name"], "custom-name");
        assert_eq!(cr["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(cr["hash"], HASH);
        assert_eq!(cr["syscallCount"], 2);
        assert_eq!(cr["localhostProfile"], "kguardian/prod/custom-name.json");
        assert_eq!(cr["distribution"]["ready"], 1);
        assert_eq!(cr["distribution"]["present"], 2);
        assert_eq!(cr["distribution"]["total"], 2);
        assert_eq!(cr["distribution"]["state"], "Partial");
        assert_eq!(cr["statusDistribution"]["ready"], 12);
        assert_eq!(cr["statusDistribution"]["state"], "Ready");
        assert_eq!(cr["drift"]["missing"], serde_json::json!(["write"]));
        assert_eq!(cr["drift"]["extra"], serde_json::json!(["ptrace"]));
        assert_eq!(cr["drift"]["inSync"], false);
        // Snippet follows the deployed CR's name, not the suggestion.
        assert_eq!(
            v["recommendedSnippet"]["seccompProfile"]["localhostProfile"],
            "kguardian/prod/custom-name.json"
        );
    }

    #[test]
    fn cr_block_omits_status_distribution_when_cr_has_none() {
        let cr = cr_row("x", Some(("Deployment", "web")), HASH, 1);
        let b = CrBlock::build(&cr, &set(&["read"]), &empty_index());
        assert!(b.status_distribution.is_none());
    }

    // ---- CR mirror input ----------------------------------------------

    #[test]
    fn cr_mirror_keeps_allow_names_only_and_normalises() {
        let input: CrMirrorInput = serde_json::from_value(serde_json::json!({
            "spec": {
                "defaultAction": "SCMP_ACT_ERRNO",
                "architectures": ["SCMP_ARCH_X86_64", " SCMP_ARCH_ARM64 "],
                "syscalls": [
                    { "names": ["write", "read", "read"], "action": "SCMP_ACT_ALLOW" },
                    { "names": ["ptrace"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1 },
                    { "names": ["mmap", "Bad Name"] }
                ],
                "workloadRef": { "kind": "Deployment", "name": "web" }
            },
            "hash": " abc ",
            "distribution": { "ready": 3, "total": 4, "state": "Partial" }
        }))
        .unwrap();
        let m = CrMirror::from_input(input, "prod", "deployment-web");
        assert_eq!(
            m.syscalls, "mmap,read,write",
            "ERRNO rule and invalid name excluded"
        );
        assert_eq!(m.architectures, "SCMP_ARCH_ARM64,SCMP_ARCH_X86_64");
        assert_eq!(m.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(m.hash, "abc");
        assert_eq!(m.workload_kind.as_deref(), Some("Deployment"));
        assert_eq!(m.workload_name.as_deref(), Some("web"));
        assert_eq!((m.ready, m.total, m.dist_state.as_str()), (3, 4, "Partial"));
    }

    #[test]
    fn cr_mirror_accepts_distribution_under_status_too() {
        let input: CrMirrorInput = serde_json::from_value(serde_json::json!({
            "spec": { "syscalls": [] },
            "status": { "distribution": { "ready": 1, "total": 1, "state": "Ready" } }
        }))
        .unwrap();
        let m = CrMirror::from_input(input, "prod", "x");
        assert_eq!((m.ready, m.total, m.dist_state.as_str()), (1, 1, "Ready"));
    }

    #[test]
    fn cr_mirror_defaults_without_ref_hash_or_status() {
        let input: CrMirrorInput = serde_json::from_value(serde_json::json!({
            "spec": { "syscalls": [{ "names": ["read"] }] }
        }))
        .unwrap();
        let m = CrMirror::from_input(input, "prod", "x");
        assert_eq!(m.default_action, "SCMP_ACT_LOG");
        assert!(m.workload_kind.is_none() && m.workload_name.is_none());
        assert_eq!(m.hash, "");
        assert_eq!((m.ready, m.total, m.dist_state.as_str()), (0, 0, "Pending"));
        assert_eq!(m.syscalls, "read");
    }

    // ---- export --------------------------------------------------------

    fn plan(opts: serde_json::Value) -> ExportPlan {
        validate_export(serde_json::from_value(opts).unwrap()).expect("valid options")
    }

    #[test]
    fn export_options_validation() {
        assert!(validate_export(
            serde_json::from_value(serde_json::json!({"name": "Bad_Name"})).unwrap()
        )
        .is_err());
        assert!(validate_export(
            serde_json::from_value(serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW"})).unwrap()
        )
        .is_err());
        assert!(validate_export(
            serde_json::from_value(serde_json::json!({"format": "toml"})).unwrap()
        )
        .is_err());
        assert!(validate_export(
            serde_json::from_value(serde_json::json!({"add": ["OpenAt"]})).unwrap()
        )
        .is_err());
        assert!(validate_export(
            serde_json::from_value(serde_json::json!({"add": ["read"], "remove": ["read"]}))
                .unwrap()
        )
        .is_err());
        let p = plan(serde_json::json!({}));
        assert!(p.name.is_none() && !p.json);
        assert_eq!(p.default_action, "SCMP_ACT_LOG");
        let p = plan(
            serde_json::json!({"name": "my-profile", "defaultAction": "SCMP_ACT_ERRNO", "format": "json"}),
        );
        assert_eq!(p.name.as_deref(), Some("my-profile"));
        assert!(p.json);
        // Query-string form parses the same struct.
        let q: ExportOptions =
            serde_urlencoded::from_str("name=x&defaultAction=SCMP_ACT_KILL&format=yaml").unwrap();
        assert_eq!(q.name.as_deref(), Some("x"));
        assert_eq!(q.default_action.as_deref(), Some("SCMP_ACT_KILL"));
    }

    #[test]
    fn export_yaml_golden_complete_capture() {
        let obs = observed_fixture("read,write,accept4", "x86_64", Vec::new());
        let (doc, header) = export_document(&obs, &plan(serde_json::json!({})));
        let yaml = render_yaml(&doc, &header);
        let want = "\
# kguardian SeccompProfile export
# workload: prod Deployment/web
# observed syscalls: 3 (x86_64)
# capture: full — complete (1 contributing pod(s))
apiVersion: kguardian.dev/v1alpha1
kind: SeccompProfile
metadata:
  name: deployment-web
  namespace: prod
spec:
  defaultAction: SCMP_ACT_LOG
  architectures:
    - SCMP_ARCH_X86_64
  syscalls:
    - names:
        - accept4
        - read
        - write
      action: SCMP_ACT_ALLOW
  workloadRef:
    kind: Deployment
    name: web
";
        assert_eq!(yaml, want);
        assert!(!yaml.contains("WARNING"));
    }

    #[test]
    fn export_yaml_golden_partial_capture_carries_warning_and_edits() {
        let mut obs = observed_fixture("read,write", "", Vec::new());
        obs.capture = capture_summary(&pods(&[("web-1", Some("full")), ("web-2", Some("low"))]));
        let p = plan(serde_json::json!({
            "name": "web-audit", "defaultAction": "SCMP_ACT_ERRNO",
            "add": ["mmap"], "remove": ["write"]
        }));
        let (doc, header) = export_document(&obs, &p);
        let yaml = render_yaml(&doc, &header);
        let want = "\
# kguardian SeccompProfile export
# workload: prod Deployment/web
# observed syscalls: 2 (no architectures recorded)
# capture: low — INCOMPLETE (1 of 2 contributing pod(s) below full)
# edits applied: +[mmap] -[write]
# WARNING: partial capture (low on 1 pod(s): web-2 (low)) — this profile will block
# WARNING: syscalls the workload makes. Raise the tier to \"full\" (kguardian.dev/syscall-capture
# WARNING: annotation or SYSCALL_CAPTURE_LEVEL) and re-export before enforcing.
apiVersion: kguardian.dev/v1alpha1
kind: SeccompProfile
metadata:
  name: web-audit
  namespace: prod
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - names:
        - mmap
        - read
      action: SCMP_ACT_ALLOW
  workloadRef:
    kind: Deployment
    name: web
";
        assert_eq!(yaml, want);
    }

    #[test]
    fn export_yaml_no_contributors_warning_and_empty_syscalls() {
        let mut obs = observed_fixture("", "x86_64", Vec::new());
        obs.capture = capture_summary(&[]);
        let (doc, header) = export_document(&obs, &plan(serde_json::json!({})));
        let yaml = render_yaml(&doc, &header);
        assert!(
            yaml.contains("# WARNING: partial capture (no pod has contributed syscalls yet)"),
            "{yaml}"
        );
        assert!(yaml.contains("  syscalls: []\n"), "{yaml}");
    }

    #[test]
    fn export_json_is_the_same_document_without_comments() {
        let obs = observed_fixture("read", "aarch64", Vec::new());
        let (doc, _) = export_document(&obs, &plan(serde_json::json!({"format": "json"})));
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "apiVersion": "kguardian.dev/v1alpha1",
                "kind": "SeccompProfile",
                "metadata": { "name": "deployment-web", "namespace": "prod" },
                "spec": {
                    "defaultAction": "SCMP_ACT_LOG",
                    "architectures": ["SCMP_ARCH_ARM64"],
                    "syscalls": [{ "names": ["read"], "action": "SCMP_ACT_ALLOW" }],
                    "workloadRef": { "kind": "Deployment", "name": "web" }
                }
            })
        );
    }

    #[test]
    fn yaml_scalar_quotes_only_what_could_break_the_document() {
        assert_eq!(yaml_scalar("deployment-web"), "deployment-web");
        assert_eq!(yaml_scalar("SCMP_ACT_LOG"), "SCMP_ACT_LOG");
        assert_eq!(
            yaml_scalar("kguardian/prod/x.json"),
            "kguardian/prod/x.json"
        );
        assert_eq!(yaml_scalar("true"), "\"true\"");
        assert_eq!(yaml_scalar("123"), "\"123\"");
        assert_eq!(yaml_scalar("a: b"), "\"a: b\"");
        assert_eq!(yaml_scalar("-x"), "\"-x\"");
        assert_eq!(yaml_scalar("q\"uote"), "\"q\\\"uote\"");
        assert_eq!(yaml_scalar(""), "\"\"");
    }

    // ---- routing ------------------------------------------------------

    /// A pool that never connects (port 1, 100 ms timeout) so the
    /// `web::Data<DbPool>` extractor succeeds and a handler that does
    /// reach the DB fails fast with a 500 instead of hanging.
    fn dummy_pool() -> DbPool {
        r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(100))
            .build_unchecked(ConnectionManager::<PgConnection>::new(
                "postgres://nobody@127.0.0.1:1/none",
            ))
    }

    /// Every seccomp route registered as main.rs does, against the dummy
    /// pool: a 404 proves the route is gone, a non-404 proves it exists,
    /// and a 400 proves validation ran before the DB was touched.
    async fn status_of(method: actix_web::http::Method, uri: &str) -> u16 {
        status_of_with(method, uri, "{}").await
    }

    async fn status_of_with(method: actix_web::http::Method, uri: &str, body: &str) -> u16 {
        use actix_web::{test, App};
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(dummy_pool()))
                .service(list_seccomp_profiles)
                .service(get_seccomp_profile)
                .service(get_seccomp_profile_file)
                .service(export_seccomp_profile)
                .service(export_seccomp_profile_post)
                .service(post_seccomp_node_status)
                .service(put_seccomp_cr)
                .service(delete_seccomp_cr),
        )
        .await;
        let req = test::TestRequest::default()
            .method(method)
            .uri(uri)
            .insert_header(("content-type", "application/json"))
            .set_payload(body.to_string())
            .to_request();
        test::call_service(&app, req).await.status().as_u16()
    }

    #[actix_web::test]
    async fn v1_lifecycle_and_override_routes_are_gone() {
        use actix_web::http::Method;
        for (m, uri) in [
            (
                Method::POST,
                "/seccomp/profiles/prod/Deployment/web/publish",
            ),
            (
                Method::POST,
                "/seccomp/profiles/prod/Deployment/web/unpublish",
            ),
            (
                Method::POST,
                "/seccomp/profiles/prod/Deployment/web/enforce",
            ),
            (Method::POST, "/seccomp/profiles/prod/Deployment/web/audit"),
            (
                Method::PUT,
                "/seccomp/profiles/prod/Deployment/web/override",
            ),
            (
                Method::DELETE,
                "/seccomp/profiles/prod/Deployment/web/override",
            ),
            (Method::GET, "/seccomp/profile-file/prod/Deployment/web"),
        ] {
            assert_eq!(
                status_of(m.clone(), uri).await,
                404,
                "{m} {uri} must be gone"
            );
        }
        // The list route exists but the v1 filter is refused loudly.
        assert_eq!(
            status_of(Method::GET, "/seccomp/profiles?state=published").await,
            400
        );
        assert!(has_query_param("state=published", "state"));
        assert!(has_query_param("a=1&state=", "state"));
        assert!(!has_query_param("statex=1&name=state", "state"));
        assert!(!has_query_param("", "state"));
    }

    #[actix_web::test]
    async fn v2_routes_exist() {
        use actix_web::http::Method;
        for (m, uri) in [
            (Method::GET, "/seccomp/profiles"),
            (Method::GET, "/seccomp/profiles/prod/Deployment/web"),
            (Method::GET, "/seccomp/profiles/prod/Deployment/web/export"),
            (Method::POST, "/seccomp/profiles/prod/Deployment/web/export"),
            (Method::GET, "/seccomp/profile-file/prod/Deployment/web/abc"),
            (Method::PUT, "/seccomp/crs/prod/deployment-web"),
            (Method::DELETE, "/seccomp/crs/prod/deployment-web"),
            (Method::POST, "/seccomp/node-status"),
        ] {
            assert_ne!(status_of(m.clone(), uri).await, 404, "{m} {uri} must route");
        }
        // Export rejects a bad option before touching the DB.
        assert_eq!(
            status_of(
                Method::GET,
                "/seccomp/profiles/prod/Deployment/web/export?format=toml"
            )
            .await,
            400
        );
        assert_eq!(
            status_of_with(Method::PUT, "/seccomp/crs/Prod/x", r#"{"spec":{}}"#).await,
            400,
            "namespace must be DNS-1123"
        );
        assert_eq!(
            status_of_with(
                Method::POST,
                "/seccomp/profiles/prod/Deployment/web/export",
                r#"{"add":["read"],"remove":["read"]}"#
            )
            .await,
            400,
            "overlapping add/remove is rejected before the DB"
        );
    }
}
