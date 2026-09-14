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
//!    CR manifest the user can commit. Every manifest states its capture
//!    tier in `metadata.annotations` (`kguardian.dev/capture-level` /
//!    `-complete` / `-warning`) and on `X-Kguardian-Capture-*` response
//!    headers, so the partial-capture signal survives `kubectl apply`
//!    and GitOps rendering instead of living only in a YAML comment. An
//!    *enforcing* `defaultAction` on a partial capture is refused with
//!    `409` unless the caller passes `acknowledgePartial=true`;
//!    audit-only (`SCMP_ACT_LOG`) exports are always allowed;
//! 3. **reports**: the controller mirrors every CR it sees into
//!    `seccomp_crs` and every node's on-disk files into
//!    `seccomp_node_status`, and the summary endpoints fold those into a
//!    `cr` block — deployed action, per-node readiness (path + hash
//!    match) and **drift** between the observed set and the CR's
//!    allow-list.
//!
//! The observed union is never edited here; an "override" is an edit to
//! the CR. One file per CR on a node: `kguardian/<namespace>/<cr>.json`.

use crate::read_budget::{
    cost_kib, ReadBudget, SCAN_THRESHOLD_DEN, SCAN_THRESHOLD_NUM, SECCOMP_BLOB_COST_BYTES,
    SECCOMP_DETAIL_ROWS_CHARGED, SECCOMP_WORKLOAD_COST_BYTES,
};
use crate::schema;
use crate::seccomp_denial::{denial_index, denial_index_for, DenialBlock, DenialIndex};
use actix_web::{get, post, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
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

/// Does this `defaultAction` *deny* an unlisted syscall?
///
/// `SCMP_ACT_LOG` records what it would have blocked and lets the call
/// through, so an incomplete profile in log mode is harmless — that is
/// exactly the workflow for tightening a profile safely. Every other
/// action denies, so an incomplete profile is a workload outage on the
/// pod's next restart. The export gate keys off this distinction rather
/// than on the tier alone: the tier only matters once something enforces.
fn action_enforces(action: &str) -> bool {
    action != "SCMP_ACT_LOG"
}

/// Capture provenance stamped onto every exported CR's
/// `metadata.annotations`.
///
/// The warning used to live only in YAML comments, which `kubectl apply`
/// discards and most GitOps renderers strip long before an operator sees
/// them — so a profile built from a partial capture was indistinguishable
/// from a complete one the moment it left this endpoint. Annotations are
/// part of the object: they survive apply, they are visible in
/// `kubectl get -o yaml`, they travel with the manifest in git, and an
/// admission policy can refuse to enforce a profile that is not marked
/// complete. The `true`/`false` values are strings because Kubernetes
/// annotation values always are.
const CAPTURE_LEVEL_ANNOTATION: &str = "kguardian.dev/capture-level";
const CAPTURE_COMPLETE_ANNOTATION: &str = "kguardian.dev/capture-complete";
const CAPTURE_WARNING_ANNOTATION: &str = "kguardian.dev/capture-warning";

/// Query/body flag a caller sets to take a partial profile deliberately.
const ACK_PARTIAL_PARAM: &str = "acknowledgePartial";

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

/// Cardinality of what [`split_set`] would return, without allocating it.
///
/// The list endpoint emits `syscallCount` and nothing else derived from the
/// names, and on a cluster with no mirrored CRs (1696 of 1696 workloads on
/// the dev cluster) that count is the *only* consumer. Building the
/// `BTreeSet<String>` to call `.len()` on it allocated one `String` per
/// syscall name per workload — 113,995 of them cluster-wide, on every 15s
/// UI poll — which is the allocation churn behind the OOMKill this pairs
/// with the read budget to fix.
///
/// Must agree with `split_set(joined).len()` for every input; the property
/// test `count_set_agrees_with_split_set` pins that.
fn count_set(joined: &str) -> usize {
    // Borrowed slices into `joined`, sorted and deduped in one buffer: a
    // single allocation for the whole field, against one per name for the
    // `BTreeSet<String>` this replaces on the list path.
    let mut toks: Vec<&str> = joined
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    toks.sort_unstable();
    toks.dedup();
    toks.len()
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

    /// Contributing pods, listed and unlisted.
    fn contributors(&self) -> usize {
        self.pods.len() + self.more
    }

    /// Why this capture is partial, in one line — the shared wording for
    /// the export's refusal message and the CR's warning annotation, so
    /// an operator meets the same sentence at the API and in the object.
    fn partial_reason(&self) -> String {
        if self.contributors() == 0 {
            "no pod has contributed syscalls yet".to_string()
        } else {
            format!(
                "{} on {} pod(s): {}",
                self.level,
                self.incomplete,
                self.culprits()
            )
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
///
/// Carries the `syscalls` blob, so it is read only by the per-workload
/// endpoints. The list endpoint reads [`WorkloadMeta`] instead — see the
/// note there for why that distinction is load-bearing.
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

/// A `workload_syscalls` row WITHOUT the `syscalls` blob.
///
/// This is the shape the profile list reads, and the reason it exists is
/// the OOMKill in #1514: the list returns one summary per workload and the
/// only thing it derives from the syscall set is its cardinality, but it
/// was selecting every blob to get there. On the dev cluster that is 1696
/// blobs carrying 113,995 syscall names crossing libpq and becoming Rust
/// `String`s on every 15s UI poll.
///
/// `syscall_count` is stored by `recompute_workload`, so the count comes
/// back as a column instead of being derived. `Option` because rows written
/// before that column existed have NULL; the list path fetches the blob for
/// exactly those and counts them the old way, so the number is unchanged
/// while they backfill.
#[derive(Debug, Queryable, Selectable, Clone)]
#[diesel(table_name = schema::workload_syscalls)]
struct WorkloadMeta {
    pod_namespace: String,
    workload_kind: String,
    workload_name: String,
    arches: String,
    hash: String,
    updated_at: chrono::NaiveDateTime,
    syscall_count: Option<i32>,
}

impl WorkloadMeta {
    fn key(&self) -> WorkloadKey {
        (
            self.pod_namespace.clone(),
            self.workload_kind.clone(),
            self.workload_name.clone(),
        )
    }
}

impl From<&WorkloadSyscallsRow> for WorkloadMeta {
    fn from(r: &WorkloadSyscallsRow) -> Self {
        WorkloadMeta {
            pod_namespace: r.pod_namespace.clone(),
            workload_kind: r.workload_kind.clone(),
            workload_name: r.workload_name.clone(),
            arches: r.arches.clone(),
            hash: r.hash.clone(),
            updated_at: r.updated_at,
            // The detail path has the blob in hand, so the count is derived
            // from it rather than trusted from the column.
            syscall_count: None,
        }
    }
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
    // `syscall_count` is selected too, so the unchanged-check below can tell
    // "nothing changed and the count is stored" from "nothing changed but the
    // count is still NULL". Without it a row whose blob never changes again
    // keeps NULL forever and the read path keeps fetching its blob to count
    // it, which is what this column exists to avoid. Reachable during a
    // rolling deploy: the migration runs on the new pod's startup while an old
    // pod is still serving and inserting rows without the column.
    let existing: Option<(String, String, String, Option<i32>)> = ws::workload_syscalls
        .find((namespace, kind, name))
        .select((ws::syscalls, ws::arches, ws::hash, ws::syscall_count))
        .first(conn)
        .optional()?;

    let mut syscall_set = BTreeSet::new();
    let mut arch_set = BTreeSet::new();
    if let Some((s, a, _, _)) = &existing {
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

    if existing.as_ref().is_some_and(|(s, a, h, count)| {
        s == &syscalls_joined && a == &arches_joined && h == &new_hash && count.is_some()
    }) {
        return Ok(()); // unchanged and counted — leave updated_at alone
    }

    // Deliberate consequence of the `count.is_some()` term above: a row that
    // is unchanged but uncounted now falls through to the upsert, which bumps
    // `updated_at` on content that did not change. That contradicts the
    // early return's intent, so it is worth naming rather than leaving to be
    // rediscovered. It is one-time per row, it surfaces only as the summary's
    // `updatedAt`, and no consumer branches on that value. Healing the count
    // is worth more than the timestamp's precision, because a NULL count
    // sends every profile-list call back to reading that row's blob.

    let now = chrono::Utc::now().naive_utc();
    // Stored, not recomputed on read. `syscall_set` is the same set that
    // produces `syscalls_joined`, so this is exact by construction rather
    // than by two implementations agreeing — which is the property that
    // matters, since `syscallCount` is user-visible in the UI.
    let count = syscall_set.len() as i32;
    diesel::insert_into(ws::workload_syscalls)
        .values((
            ws::pod_namespace.eq(namespace),
            ws::workload_kind.eq(kind),
            ws::workload_name.eq(name),
            ws::syscalls.eq(&syscalls_joined),
            ws::arches.eq(&arches_joined),
            ws::hash.eq(&new_hash),
            ws::updated_at.eq(now),
            ws::syscall_count.eq(Some(count)),
        ))
        .on_conflict((ws::pod_namespace, ws::workload_kind, ws::workload_name))
        .do_update()
        .set((
            ws::syscalls.eq(&syscalls_joined),
            ws::arches.eq(&arches_joined),
            ws::hash.eq(&new_hash),
            ws::updated_at.eq(now),
            ws::syscall_count.eq(Some(count)),
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
    meta: WorkloadMeta,
    /// The syscall names, or `None` when they were never read out of the
    /// database.
    ///
    /// `None` and `Some(empty)` are different facts and this type keeps them
    /// apart (#1515). Before it was an `Option`, both were the empty set, and
    /// the distinction lived in a doc comment: the next field added to
    /// [`ProfileSummary`] that read the names would have got an empty set for
    /// every workload without a CR, been silently wrong, and passed any test
    /// written with a CR present.
    ///
    /// The failure that makes this worth a type rather than a convention is
    /// `CrBlock::build`, which diffs these names against the CR's allowed
    /// set. With an empty `observed`, `drift` reports `missing: []` and
    /// `extra: [everything]` — and `missing` is the half that lists what gets
    /// BLOCKED when the CR is enforced. So the silent failure reads as
    /// "nothing will break" for a workload where everything is about to.
    syscalls: Option<BTreeSet<String>>,
    /// Cardinality of the observed set. Always populated, because the list
    /// path gets it from the stored `syscall_count` column without reading
    /// the blob.
    syscall_count: usize,
    arches: BTreeSet<String>,
    capture: CaptureSummary,
    crs: Vec<CrRow>,
}

impl Observed {
    /// The materialised syscall names, for a caller that requires them.
    ///
    /// Only [`Observed::build_for_summary`] can produce an `Observed` without
    /// names, and no list-path caller reaches the render or export paths. So
    /// this is a contract check at the boundary, not a condition expected to
    /// fire — but it returns an error rather than panicking or substituting
    /// an empty set, because an empty set here silently changes what a
    /// generated profile allows.
    fn require_names(&self) -> Result<&BTreeSet<String>, DbError> {
        self.syscalls.as_ref().ok_or_else(|| {
            format!(
                "syscall names were not read for {}/{}/{}; refusing to render a \
                 profile from an unmaterialised set",
                self.meta.pod_namespace, self.meta.workload_kind, self.meta.workload_name
            )
            .into()
        })
    }

    /// Materialises the syscall names. Every caller that renders a profile
    /// document, exports, or diffs against a CR needs this.
    fn build(row: WorkloadSyscallsRow, captures: &CaptureIndex, crs: &CrIndex) -> Self {
        let meta = WorkloadMeta::from(&row);
        let key = meta.key();
        let syscalls = split_set(&row.syscalls);
        let syscall_count = syscalls.len();
        Observed {
            capture: captures.summary_for(&key),
            crs: crs.for_workload(&key).to_vec(),
            arches: split_set(&row.arches),
            meta,
            syscalls: Some(syscalls),
            syscall_count,
        }
    }

    /// List-path build. The blob is never read for a workload that does not
    /// need it, so `names` is `None` for almost every workload.
    ///
    /// `names` must be `Some` when the workload has a mirrored CR, because
    /// `CrBlock::build` diffs them. The caller
    /// ([`workload_summaries`]) is what guarantees that: it fetches blobs
    /// for exactly the CR-referenced workloads plus any row whose stored
    /// `syscall_count` is NULL.
    fn build_for_summary(
        meta: WorkloadMeta,
        names: Option<BTreeSet<String>>,
        captures: &CaptureIndex,
        crs: &CrIndex,
    ) -> Self {
        let key = meta.key();
        let crs_for = crs.for_workload(&key).to_vec();

        // A CR without names would make drift detection report an empty
        // `missing` set, which reads as "nothing will break". Assert the
        // caller's contract rather than trusting it silently.
        debug_assert!(
            crs_for.is_empty() || names.is_some(),
            "workload {key:?} has a mirrored CR but its syscall names were not fetched; \
             drift detection would report an empty `missing` set"
        );

        // Prefer the stored count; fall back to counting the blob for rows
        // written before the column existed.
        let syscall_count = match (meta.syscall_count, &names) {
            (Some(n), _) if n >= 0 => n as usize,
            (_, Some(set)) => set.len(),
            // Neither a stored count nor a blob. Unreachable via
            // `workload_summaries`, which fetches the blob for exactly the
            // NULL-count rows; 0 is the honest answer if it ever happens.
            _ => 0,
        };

        Observed {
            capture: captures.summary_for(&key),
            crs: crs_for,
            arches: split_set(&meta.arches),
            meta,
            syscalls: names,
            syscall_count,
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
    /// The kernel's own verdicts for this workload, or `None` when the
    /// broker cannot tell "nothing denied" from "nothing capturing". See
    /// [`DenialIndex::block_for`] — it follows the same
    /// no-block-rather-than-an-empty-one rule as `cr` above.
    denials: Option<DenialBlock>,
}

impl ProfileSummary {
    fn build(obs: &Observed, index: &DistributionIndex, denials: &DenialIndex) -> Self {
        let r = &obs.meta;
        let suggested = suggested_cr_name(&r.workload_kind, &r.workload_name);
        // Drift needs the real names. `zip` rather than an unwrap: if the
        // names were not fetched for a workload that has a CR, emit no `cr`
        // block at all instead of one whose `missing` list is empty because it
        // diffed against nothing.
        //
        // The decisive argument is what the controller does with each. With
        // the block absent, seccomp_distributor takes its `None` arm and
        // writes Drift status "Unknown"/"NoObservations" - a state it already
        // models, and the right one for "could not compute". With an empty
        // observed set it would instead see missing: [] and extra: [every
        // allowed name], conclude not-in-sync, and write a Drift condition of
        // status "True" naming zero syscalls, which also flaps the transition
        // time. Self-contradicting in the object an operator reads.
        //
        // The cost of omitting it, since this is a trade rather than a free
        // win: with `cr` None the `path` below falls back to
        // `suggested_cr_name`, so `recommendedSnippet` points at the suggested
        // file rather than the deployed CR's. Copying it would reference a
        // file no node has. Acceptable in a branch that should be
        // unreachable, and `crCount` still reports the CR so the omission is
        // visible rather than looking like there is no CR at all.
        //
        // The debug_assert in `build_for_summary` catches the same condition
        // in tests.
        let cr = obs
            .crs
            .first()
            .zip(obs.syscalls.as_ref())
            .map(|(c, names)| CrBlock::build(c, names, index));
        let path = cr
            .as_ref()
            .map(|c| c.localhost_profile.clone())
            .unwrap_or_else(|| cr_profile_path(&r.pod_namespace, &suggested));
        ProfileSummary {
            namespace: r.pod_namespace.clone(),
            kind: r.workload_kind.clone(),
            name: r.workload_name.clone(),
            hash: r.hash.clone(),
            syscall_count: obs.syscall_count,
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
            // Keyed on the same (namespace, kind, name) identity everything
            // else in this summary is grouped on, so a denial and the
            // profile it was measured against always agree on what the
            // workload is.
            denials: denials.block_for(&(
                r.pod_namespace.clone(),
                r.workload_kind.clone(),
                r.workload_name.clone(),
            )),
        }
    }
}

/// Every workload's observed row with its capture summary and CRs,
/// ordered. Batch-loads each side table so the list endpoint stays
/// O(rows + contributors + crs), not a query per row.
/// Every workload's summary, without reading the syscall blobs.
///
/// This is the read path that OOMKilled the broker (#1514). It used to
/// `SELECT *`, which meant every workload's `syscalls` blob crossed libpq
/// and became a Rust `String` per name, on every 15s UI poll, to produce one
/// integer per workload.
///
/// Now the bulk query selects metadata plus the stored `syscall_count` and
/// no blob at all, and blobs are fetched in one follow-up query for exactly
/// the workloads that still need them:
///
///   - workloads with a mirrored CR, because `CrBlock::build` diffs the real
///     names to report drift, and
///   - rows whose `syscall_count` is NULL, i.e. written before that column
///     existed, which are counted from the blob exactly as before and
///     disappear as `recompute_workload` backfills them.
///
/// On a cluster with no CRs and a backfilled table that second query selects
/// nothing. On one where every workload has a CR it degrades to the old
/// behaviour, which is the honest bound: drift detection genuinely needs the
/// names, so the cost is inherent to the feature rather than to this path.
fn workload_summaries(conn: &mut PgConnection) -> Result<Vec<Observed>, DbError> {
    use schema::workload_syscalls::dsl as ws;

    let metas: Vec<WorkloadMeta> = ws::workload_syscalls
        .select(WorkloadMeta::as_select())
        .order((
            ws::pod_namespace.asc(),
            ws::workload_kind.asc(),
            ws::workload_name.asc(),
        ))
        .load(conn)?;

    let captures = capture_index(conn, None)?;
    let crs = cr_index(conn, None)?;

    // Which workloads still need their blob read.
    let need: Vec<&WorkloadMeta> = metas
        .iter()
        .filter(|m| m.syscall_count.is_none() || !crs.for_workload(&m.key()).is_empty())
        .collect();

    // Names, only for workloads whose drift will be computed.
    let mut blobs: HashMap<WorkloadKey, BTreeSet<String>> = HashMap::new();
    // Counts, for legacy rows that have no stored count and no CR. Counting
    // without materialising the names keeps the #1515 invariant intact: a
    // workload with no CR never gets a name set it does not need.
    let mut counts: HashMap<WorkloadKey, usize> = HashMap::new();
    if !need.is_empty() {
        // Exact triples, not three independent `eq_any` filters.
        //
        // Three `eq_any`s describe a cross product: every row where
        // `ns in N and kind in K and name in M`, for the distinct values drawn
        // from `need`. Over-fetch is then roughly |N| x |K| x |M| / |need|,
        // which is quadratic in |need| and WORST when `need` is a diagonal:
        // one distinct namespace and one distinct name per entry.
        //
        // That is the likely early-adoption shape, not an exotic one. A
        // hundred teams each mirroring one workload in their own namespace
        // gives |N| = |M| = 100, so the filter matches up to 10,000 rows,
        // each carrying its blob, to serve 100. At the observed density
        // (~67 names per workload) that is megabytes of blob per call, which
        // is the cost this function exists to remove. Near-total adoption is
        // the SAFE end: N and M cover everything, so the product collapses
        // onto the rows actually wanted.
        //
        // So build an OR of AND-groups, which is exact and index-friendly,
        // chunked so the query text stays bounded on a large cluster.
        //
        // The fallback to an unfiltered scan is RELATIVE to the table, not an
        // absolute row count, and the ratio is derived rather than picked. An
        // unfiltered scan reads every blob, costing 9,318 B (the measured
        // blob-bearing figure) + 944 B (measured JSON) = 10,262 B/workload,
        // while the permit charged `SECCOMP_WORKLOAD_COST_BYTES + f *
        // SECCOMP_BLOB_COST_BYTES` for `need = f * all`. Break-even is
        // `4,096 + 12,288f >= 10,262`, i.e. f >= 0.502.
        //
        // The ratio lives in SCAN_THRESHOLD_NUM/DEN so this condition and the
        // test that checks it cannot drift apart. Do NOT "simplify" it to 1/2:
        // that is what a rounded `9.1 + 0.94 ~= 10 KiB` derivation suggests,
        // it is 22 B/workload short of covering the scan, and
        // `the_unfiltered_scan_threshold_is_covered_by_what_was_charged` fails
        // on it.
        //
        // An absolute cutoff would let the scan read the whole table while the
        // charge billed only the CR-referenced rows, which is the same
        // fail-open this function's own charge was fixed to avoid: at 513
        // needed rows in a 20,000-workload table it under-charges ~2.3x.
        //
        // The cost accepted below the threshold is round trips rather than
        // memory: `need / OR_CHUNK` queries, about 116 at 59,000 needed rows.
        // That is the one place this path can get slow rather than fat, and it
        // is correct, because the scan genuinely is not paid for there.
        const OR_CHUNK: usize = 512;

        let wanted: std::collections::HashSet<WorkloadKey> = need.iter().map(|m| m.key()).collect();
        let scan_is_paid_for = need.len() * SCAN_THRESHOLD_DEN >= metas.len() * SCAN_THRESHOLD_NUM;

        let mut rows: Vec<(String, String, String, String)> = Vec::new();
        if scan_is_paid_for {
            rows = ws::workload_syscalls
                .select((
                    ws::pod_namespace,
                    ws::workload_kind,
                    ws::workload_name,
                    ws::syscalls,
                ))
                .load(conn)?;
        } else {
            for chunk in need.chunks(OR_CHUNK) {
                let (first, rest) = chunk.split_first().expect("chunks are non-empty");
                let mut q = ws::workload_syscalls.into_boxed().filter(
                    ws::pod_namespace
                        .eq(first.pod_namespace.clone())
                        .and(ws::workload_kind.eq(first.workload_kind.clone()))
                        .and(ws::workload_name.eq(first.workload_name.clone())),
                );
                for m in rest {
                    q = q.or_filter(
                        ws::pod_namespace
                            .eq(m.pod_namespace.clone())
                            .and(ws::workload_kind.eq(m.workload_kind.clone()))
                            .and(ws::workload_name.eq(m.workload_name.clone())),
                    );
                }
                rows.extend(
                    q.select((
                        ws::pod_namespace,
                        ws::workload_kind,
                        ws::workload_name,
                        ws::syscalls,
                    ))
                    .load::<(String, String, String, String)>(conn)?,
                );
            }
        }

        for (ns, kind, name, blob) in rows {
            let key = (ns, kind, name);
            if !wanted.contains(&key) {
                continue;
            }
            if crs.for_workload(&key).is_empty() {
                // No CR, so this row is here only because its stored count is
                // NULL. It needs a number, not names.
                counts.insert(key, count_set(&blob));
            } else {
                blobs.insert(key, split_set(&blob));
            }
        }
    }

    Ok(metas
        .into_iter()
        .map(|mut m| {
            let key = m.key();
            let names = blobs.remove(&key);
            if m.syscall_count.is_none() {
                if let Some(n) = counts.remove(&key) {
                    m.syscall_count = Some(n as i32);
                }
            }
            Observed::build_for_summary(m, names, &captures, &crs)
        })
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
///
/// Takes `names` rather than reading `obs.syscalls`, so the `Option` is
/// resolved once by the caller. Every caller is a per-workload endpoint
/// reaching its `Observed` through `one_observed`, which always materialises
/// the names; the list path, which does not, has no route here.
fn render(obs: &Observed, names: &BTreeSet<String>) -> SeccompProfile {
    build_profile(
        &join_set(names),
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
    budget: web::Data<ReadBudget>,
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

    // A whole-result-set read that took no permit — the only one in the
    // broker that did not. This endpoint OOMKilled the broker in the dev
    // cluster: the UI polls it every 15s (frontend useSeccompProfiles) and
    // the container died at steady ingest with zero `/pod/traffic` reads in
    // its log, so the budget that already existed never engaged.
    //
    // BUT THE PERMIT IS NOT WHAT FIXES THAT, and it should not be read as
    // the remedy. Measured on the dev cluster, four SEQUENTIAL calls 25s
    // apart moved RSS 352 -> 366 -> 381 -> 396 -> 411 MiB: ~15 MiB per call,
    // linear, nothing reclaimed in between. A permit is released when the
    // handler returns, so retention that outlives the response is invisible
    // to the budget — it holds no permit and `available_kib` counts it free.
    // A semaphore cannot bound a quantity that persists after the request
    // completes.
    //
    // Nor would it have fired here. Both callers are self-limiting to one
    // in-flight request each: `useSeccompProfiles` holds an `inflight` ref
    // and returns early while a call is outstanding, and the seccomp
    // distributor ticks a single reconciler loop every 30s. Steady state is
    // 2 concurrent against a reservation that admits 4, so in the exact
    // configuration that killed the broker this permit would never have been
    // contended.
    //
    // What attacks the measured growth is `workload_summaries` below, which
    // no longer reads the syscall blobs at all: the count comes from a stored
    // column, and blobs are fetched only for workloads whose drift is
    // actually computed. The permit is a guardrail for a future caller with
    // no in-flight guard, and it closes the structural gap that every read in
    // get.rs is admitted while every read here was not.
    //
    // Charged from the REAL counts on BOTH axes, not a flat assumption.
    //
    // The previous `ASSUMED_MAX_WORKLOADS` reservation under-charged above
    // its assumed count, so it failed open on exactly the clusters big enough
    // to need it. Charging `COUNT(*)` fixes that axis, but on its own it just
    // moves the same failure one axis over: `SECCOMP_WORKLOAD_COST_BYTES` is
    // derived for a workload whose blob is NOT read, and
    // `workload_summaries` still reads the blob for every CR-referenced
    // workload. Charging the no-blob rate for those under-bills them 2-4x,
    // and it does so on the axis this product is trying to grow, since the
    // whole feature exists to get operators committing SeccompProfile CRs.
    //
    // So: two cheap counts, and a charge that tracks what the handler will
    // actually do. `SECCOMP_BLOB_COST_BYTES` is the surcharge for a workload
    // whose names are materialised.
    //
    // Both counts run before the permit, so a request that is ultimately shed
    // still costs two round trips, and the counts can go stale against the
    // load below. Both are accepted: the alternative is charging after doing
    // the work, which is not a bound.
    let count_pool = pool.clone();
    let (workloads, with_crs): (i64, i64) = web::block(move || -> Result<_, DbError> {
        use schema::seccomp_crs::dsl as c;
        use schema::workload_syscalls::dsl as ws;
        let mut conn = count_pool.get()?;
        // Not asserted to be index-only: Postgres uses an index-only path for
        // an unqualified COUNT(*) only when the visibility map allows it. At a
        // few thousand rows the distinction does not matter.
        let all: i64 = ws::workload_syscalls.count().get_result(&mut conn)?;
        let crs: i64 = c::seccomp_crs
            .filter(c::workload_kind.is_not_null())
            .filter(c::workload_name.is_not_null())
            .count()
            .get_result(&mut conn)?;
        Ok((all, crs))
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    // More CRs than workloads is possible (several CRs can reference one
    // workload), and over-charging there is harmless; charging for blobs that
    // will not be read is not the failure mode that matters.
    let blob_bearing = with_crs.min(workloads);
    // The denial rollup below is charged too. Its totals pass is one row per
    // workload and rides inside the per-workload allowance above, but its
    // names pass is per `(syscall, action)` and scales on an axis neither
    // count here measures — so it carries its own bounded reservation. It
    // used to carry none at all, on the argument that the table "is already
    // an aggregate", which was wrong twice: the query grouped by syscall and
    // action as well as workload, and it had no LIMIT.
    let charge = cost_kib(workloads, SECCOMP_WORKLOAD_COST_BYTES)
        .saturating_add(cost_kib(blob_bearing, SECCOMP_BLOB_COST_BYTES))
        .saturating_add(crate::seccomp_denial::denial_index_charge_kib());

    let _permit = match budget.acquire(charge).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };

    let out: Vec<ProfileSummary> = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        let all = workload_summaries(&mut conn)?;
        let index = distribution_index(&mut conn)?;
        // One rollup for the whole call, like the capture and distribution
        // indexes above it, so adding the block keeps this endpoint at
        // O(rows + contributors + crs + denials) rather than a query per
        // workload. Bounded in SQL and charged above.
        let denials = denial_index(&mut conn)?;
        Ok(all
            .iter()
            .map(|o| ProfileSummary::build(o, &index, &denials))
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
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (namespace, kind, name) = path.into_inner();
    info!(%namespace, %kind, %name, "get seccomp profile");

    // One workload, but `distribution_index` below is still a whole-table read
    // of `seccomp_node_status` (one JSON `paths` blob per node). Bounded by
    // node count rather than workload count, so it is charged as a small
    // multiple of one workload rather than the list endpoint's reservation.
    let _permit = match budget
        .acquire(
            cost_kib(SECCOMP_DETAIL_ROWS_CHARGED, SECCOMP_WORKLOAD_COST_BYTES).saturating_add(
                // One workload's denial rollup, capped at its own
                // per-workload pair limit rather than the cluster-wide one.
                crate::seccomp_denial::denial_index_for_charge_kib(),
            ),
        )
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };

    let result = web::block(move || -> Result<_, DbError> {
        let mut conn = pool.get()?;
        match one_observed(&mut conn, &namespace, &kind, &name)? {
            Some(obs) => {
                let index = distribution_index(&mut conn)?;
                let key = (namespace.clone(), kind.clone(), name.clone());
                let denials = denial_index_for(&mut conn, &key)?;
                let profile = render(&obs, obs.require_names()?);
                Ok(Some((
                    ProfileSummary::build(&obs, &index, &denials),
                    profile,
                )))
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
        Some(o) if o.meta.hash == hash => match o.require_names() {
            Ok(names) => HttpResponse::Ok().json(render(&o, names)),
            Err(e) => return Err(actix_web::error::ErrorInternalServerError(e.to_string())),
        },
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
    /// Capture provenance — see the `CAPTURE_*_ANNOTATION` constants.
    /// Always populated, so a complete capture is *positively* marked
    /// rather than merely lacking a warning.
    annotations: BTreeMap<String, String>,
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

/// Accept a flag as a JSON bool (`true`) or as a string (`"true"`, `"1"`,
/// `"yes"`, `"on"`, case- and whitespace-insensitive). One field is read
/// from two places — a hand-typed query string on GET, where everything
/// is a string, and a JSON body on POST, where a client will naturally
/// send a bool — and a 400 on `?acknowledgePartial=1` would be a trap.
/// Anything unrecognised is false: this flag waives a safety check, so it
/// is never granted by accident.
fn de_lenient_bool<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = bool;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str(
                "a boolean or one of \"true\"/\"false\"/\"1\"/\"0\"/\"yes\"/\"no\"/\"on\"/\"off\"",
            )
        }
        fn visit_bool<E>(self, v: bool) -> Result<bool, E> {
            Ok(v)
        }
        fn visit_str<E>(self, v: &str) -> Result<bool, E> {
            Ok(matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            ))
        }
        fn visit_unit<E>(self) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_none<E>(self) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_some<D2>(self, d: D2) -> Result<bool, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            d.deserialize_any(V)
        }
    }
    d.deserialize_any(V)
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
    /// Take a partial-capture profile with an *enforcing* action anyway.
    /// Without it that combination is refused; see `export_impl`.
    #[serde(
        default,
        rename = "acknowledgePartial",
        deserialize_with = "de_lenient_bool"
    )]
    acknowledge_partial: bool,
}

const MAX_EDIT_LIST: usize = 512;

/// Validated export options.
struct ExportPlan {
    name: Option<String>,
    default_action: String,
    json: bool,
    add: BTreeSet<String>,
    remove: BTreeSet<String>,
    acknowledge_partial: bool,
}

fn validate_export(opts: ExportOptions) -> Result<ExportPlan, actix_web::Error> {
    let ExportOptions {
        name,
        default_action,
        format,
        add,
        remove,
        acknowledge_partial,
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
        acknowledge_partial,
    })
}

/// Build the CR document plus the comment header (YAML only) for an
/// observed workload.
fn export_document(
    obs: &Observed,
    observed_names: &BTreeSet<String>,
    plan: &ExportPlan,
) -> (ExportDoc, Vec<String>) {
    let r = &obs.meta;
    let mut names = observed_names.clone();
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
    let c = &obs.capture;
    let mut annotations = BTreeMap::from([
        (CAPTURE_LEVEL_ANNOTATION.to_string(), c.level.to_string()),
        (
            CAPTURE_COMPLETE_ANNOTATION.to_string(),
            c.complete.to_string(),
        ),
    ]);
    if !c.complete {
        annotations.insert(
            CAPTURE_WARNING_ANNOTATION.to_string(),
            format!(
                "partial capture ({}) — this profile omits syscalls the workload makes; \
                 raise the tier to full and re-export before enforcing",
                c.partial_reason()
            ),
        );
    }
    let doc = ExportDoc {
        api_version: "kguardian.dev/v1alpha1",
        kind: "SeccompProfile",
        metadata: ExportMeta {
            name: plan
                .name
                .clone()
                .unwrap_or_else(|| suggested_cr_name(&r.workload_kind, &r.workload_name)),
            namespace: r.pod_namespace.clone(),
            annotations,
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

    let contributors = c.contributors();
    let mut header = vec![
        "kguardian SeccompProfile export".to_string(),
        format!(
            "workload: {} {}/{}",
            r.pod_namespace, r.workload_kind, r.workload_name
        ),
        format!(
            "observed syscalls: {} ({})",
            obs.syscall_count,
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
        let detail = c.partial_reason();
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
    if !doc.metadata.annotations.is_empty() {
        y.push_str("  annotations:\n");
        for (k, v) in &doc.metadata.annotations {
            y.push_str(&format!("    {}: {}\n", yaml_scalar(k), yaml_scalar(v)));
        }
    }
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

/// The gate the tier documentation promises: `Some(message)` when this
/// export must be refused, `None` when it may proceed.
///
/// Only `full` observes every syscall, so a profile built from a lower
/// tier is missing calls the workload really makes. A denying
/// `defaultAction` turns those misses into a workload outage on the pod's
/// next restart — hours after the manifest was applied, and nowhere near
/// it. The comment header this used to rely on is discarded by `kubectl
/// apply` and stripped by most GitOps renderers, so it could never be the
/// safety check; a status code cannot be stripped.
///
/// Scoped to *enforcing* actions on purpose. `SCMP_ACT_LOG` (the default
/// this endpoint renders) only records what it would have blocked, so a
/// partial audit profile breaks nothing and is the normal way to grow a
/// profile safely — refusing it would cost a real workflow and prevent
/// nothing. The opt-out exists for the operator who has decided the gap
/// is acceptable; it is explicit, so it cannot be taken by accident.
fn partial_export_refusal(c: &CaptureSummary, plan: &ExportPlan) -> Option<String> {
    if c.complete || !action_enforces(&plan.default_action) || plan.acknowledge_partial {
        return None;
    }
    Some(format!(
        "refusing to export an enforcing profile ({}) from a partial capture: {}.\n\
         Only the full tier observes every syscall, so this profile would block syscalls \
         the workload makes. Raise the tier to full (the kguardian.dev/syscall-capture pod \
         annotation, or SYSCALL_CAPTURE_LEVEL cluster-wide), let the profile re-accrue, \
         then export again.\n\
         Or export with defaultAction={DEFAULT_SECCOMP_ACTION} for an audit-only profile \
         now, or pass {ACK_PARTIAL_PARAM}=true to take this one as it is.\n",
        plan.default_action,
        c.partial_reason(),
    ))
}

async fn export_impl(
    pool: web::Data<DbPool>,
    (namespace, kind, name): (String, String, String),
    plan: ExportPlan,
) -> actix_web::Result<HttpResponse> {
    info!(%namespace, %kind, %name, json = plan.json, "export seccomp profile CR");
    let (ns, k, n) = (namespace.clone(), kind.clone(), name.clone());
    let obs = web::block(move || {
        let mut conn = pool.get()?;
        one_observed(&mut conn, &ns, &k, &n)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let Some(obs) = obs else {
        return Ok(HttpResponse::NotFound().body("no seccomp profile for that workload"));
    };

    let c = &obs.capture;
    if let Some(msg) = partial_export_refusal(c, &plan) {
        warn!(
            %namespace, %kind, %name,
            level = c.level,
            incomplete = c.incomplete,
            action = %plan.default_action,
            "refused enforcing seccomp export from a partial capture"
        );
        return Ok(capture_headers(HttpResponse::Conflict(), c)
            .content_type("text/plain; charset=utf-8")
            .body(msg));
    }

    let observed_names = obs
        .require_names()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let (doc, header) = export_document(&obs, observed_names, &plan);
    Ok(if plan.json {
        capture_headers(HttpResponse::Ok(), c).json(doc)
    } else {
        capture_headers(HttpResponse::Ok(), c)
            .content_type("application/yaml")
            .body(render_yaml(&doc, &header))
    })
}

/// Stamp the capture verdict on the response itself.
///
/// The document carries the same facts in `metadata.annotations`, but a
/// caller that streams the body straight to a file (`curl -o`, a CI step)
/// can branch on these without parsing YAML — and they are present on the
/// refusal too, so a client can tell *why* it was refused from the
/// headers alone.
fn capture_headers(
    mut builder: actix_web::HttpResponseBuilder,
    c: &CaptureSummary,
) -> actix_web::HttpResponseBuilder {
    builder.insert_header(("X-Kguardian-Capture-Level", c.level));
    builder.insert_header((
        "X-Kguardian-Capture-Complete",
        if c.complete { "true" } else { "false" },
    ));
    builder
}

/// `GET /seccomp/profiles/{namespace}/{kind}/{name}/export?name=&defaultAction=&format=&acknowledgePartial=`
/// — the observed set as a `SeccompProfile` CR manifest (YAML by
/// default; `format=json`). Never writes anything: the user commits
/// and applies it.
///
/// `409` when the capture is partial and `defaultAction` enforces,
/// unless `acknowledgePartial=true`.
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
/// Same partial-capture gate as the GET form.
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

    /// `count_set` exists so the list path can report `syscallCount` without
    /// allocating a `String` per syscall name. It is only safe to substitute
    /// if it agrees with `split_set(..).len()` on every input, including the
    /// messy ones the field is known to carry (leading, trailing and doubled
    /// commas, surrounding whitespace, and repeats).
    #[test]
    fn count_set_agrees_with_split_set() {
        for input in [
            "",
            ",",
            ",,,",
            "read",
            " read ",
            "read,write",
            ",read,, write ,read,",
            "read,read,read",
            "a,b,c,d,e,f,g",
            " , a , a , b , ",
            "openat,close,read,write,mmap,mprotect,futex,epoll_wait",
        ] {
            assert_eq!(
                count_set(input),
                split_set(input).len(),
                "count_set disagreed with split_set on {input:?}"
            );
        }
    }

    fn meta_fixture(count: Option<i32>) -> WorkloadMeta {
        WorkloadMeta {
            pod_namespace: "prod".into(),
            workload_kind: "Deployment".into(),
            workload_name: "web".into(),
            arches: "SCMP_ARCH_X86_64".into(),
            hash: "abc123".into(),
            updated_at: chrono::NaiveDateTime::default(),
            syscall_count: count,
        }
    }

    fn no_captures() -> CaptureIndex {
        CaptureIndex {
            pods: HashMap::new(),
        }
    }

    /// The common case after #1514: a workload with no mirrored CR reports its
    /// count from the stored column and never has its names read at all.
    ///
    /// This is what stops the list endpoint pulling every workload's syscall
    /// blob out of the database. If `syscalls` is ever `Some` here, the blob
    /// is being read again and the OOM regression is back.
    #[test]
    fn summary_uses_the_stored_count_and_reads_no_names_without_a_cr() {
        let obs = Observed::build_for_summary(
            meta_fixture(Some(67)),
            None,
            &no_captures(),
            &CrIndex::from_rows(Vec::new()),
        );

        assert_eq!(obs.syscall_count, 67, "count must come from the column");
        assert!(
            obs.syscalls.is_none(),
            "no CR for this workload, so the names must never be read"
        );
    }

    /// Legacy rows written before `syscall_count` existed have NULL, and the
    /// read path counts them from the blob so the reported number does not
    /// change while they backfill.
    #[test]
    fn summary_falls_back_to_counting_the_blob_when_the_column_is_null() {
        let mut meta = meta_fixture(None);
        // What `workload_summaries` does for a NULL-count row with no CR: it
        // counts the blob without materialising names.
        meta.syscall_count = Some(count_set(",openat,, read , write ,openat,") as i32);

        let obs = Observed::build_for_summary(
            meta,
            None,
            &no_captures(),
            &CrIndex::from_rows(Vec::new()),
        );

        assert_eq!(obs.syscall_count, 3, "openat/read/write, deduped");
        assert!(
            obs.syscalls.is_none(),
            "counting a legacy row must not materialise its names either"
        );
    }

    /// The invariant the optimisation rests on: when a workload HAS a mirrored
    /// CR, the summary path is handed the names, because `CrBlock::build`
    /// diffs them.
    ///
    /// The failure mode if this regresses is silent in the dangerous
    /// direction. `drift(observed, allowed)` with an empty or absent
    /// `observed` yields `missing: []` and `extra: [everything]`. `missing` is
    /// the security-relevant half, the syscalls that get BLOCKED when the CR
    /// is enforced, so a broken gate reports "nothing will break" for a
    /// workload where everything is about to.
    #[test]
    fn summary_with_a_cr_reports_the_same_drift_as_the_full_build() {
        // cr_row's CR allows exactly "read,write"; the observed set adds
        // `openat`, so `openat` is what enforcing the CR would block.
        let crs = CrIndex::from_rows(vec![cr_row(
            "web-profile",
            Some(("Deployment", "web")),
            "h1",
            100,
        )]);
        let names = split_set("openat,read,write");

        let summary = Observed::build_for_summary(
            meta_fixture(Some(3)),
            Some(names.clone()),
            &no_captures(),
            &crs,
        );
        let full = Observed::build(
            WorkloadSyscallsRow {
                pod_namespace: "prod".into(),
                workload_kind: "Deployment".into(),
                workload_name: "web".into(),
                syscalls: "openat,read,write".into(),
                arches: "SCMP_ARCH_X86_64".into(),
                hash: "abc123".into(),
                updated_at: chrono::NaiveDateTime::default(),
            },
            &no_captures(),
            &crs,
        );

        assert_eq!(summary.syscalls.as_ref(), Some(&names));
        assert_eq!(summary.syscall_count, full.syscall_count);

        let idx = empty_index();
        let no_denials = DenialIndex::empty();
        let a = serde_json::to_value(ProfileSummary::build(&summary, &idx, &no_denials)).unwrap();
        let b = serde_json::to_value(ProfileSummary::build(&full, &idx, &no_denials)).unwrap();
        assert_eq!(a["cr"]["drift"], b["cr"]["drift"]);
        assert_eq!(
            a["cr"]["drift"]["missing"],
            serde_json::json!(["openat"]),
            "the CR allows read+write while openat was observed, so openat is \
             what enforcing the CR would block. This is the field that must \
             never be empty by accident."
        );
    }

    /// If the names are ever missing for a workload that has a CR, emit no
    /// `cr` block at all rather than one whose `missing` list is empty because
    /// it diffed against nothing.
    ///
    /// An absent block is visibly incomplete. An empty `missing` reads as
    /// "enforcing this CR breaks nothing", which is the failure that made
    /// #1515 worth a type rather than a convention.
    #[test]
    fn a_cr_without_names_emits_no_drift_rather_than_an_empty_one() {
        let crs = CrIndex::from_rows(vec![cr_row(
            "web-profile",
            Some(("Deployment", "web")),
            "h1",
            100,
        )]);
        // Deliberately violating the caller contract that build_for_summary's
        // debug_assert guards, to pin what the release build does.
        let obs = Observed {
            meta: meta_fixture(Some(3)),
            syscalls: None,
            syscall_count: 3,
            arches: split_set("SCMP_ARCH_X86_64"),
            capture: capture_summary(&pods(&[("web-1", Some("full"))])),
            crs: crs
                .for_workload(&("prod".into(), "Deployment".into(), "web".into()))
                .to_vec(),
        };

        let v = serde_json::to_value(ProfileSummary::build(
            &obs,
            &empty_index(),
            &DenialIndex::empty(),
        ))
        .unwrap();
        assert!(
            v["cr"].is_null(),
            "no names means no drift can be computed, so no cr block"
        );
        assert_eq!(
            v["crCount"], 1,
            "the CR is still counted, so the omission is visible rather than \
             looking like there is no CR at all"
        );
    }

    /// The denial counterpart of
    /// `a_cr_without_names_emits_no_drift_rather_than_an_empty_one`, at the
    /// summary level rather than the index level.
    ///
    /// The two blocks share one rule: an absent block means "could not
    /// determine", and the controller already models that as a condition of
    /// status Unknown. An empty block means "determined, and it is clear" —
    /// so emitting one from data that could not determine anything writes a
    /// false all-clear into an object an operator reads.
    ///
    /// For denials the undeterminable state is the common one: capture needs
    /// CONFIG_AUDIT on the node, the operator can switch it off, and the
    /// probe is skipped on a kernel without the `audit_seccomp` symbol. With
    /// no denial row anywhere, "never denied" and "never watched" are the
    /// same database state.
    #[test]
    fn no_denial_observations_emit_no_block_rather_than_an_empty_one() {
        let obs = observed_fixture("openat,read,write", "x86_64", vec![]);
        let v = serde_json::to_value(ProfileSummary::build(
            &obs,
            &empty_index(),
            &DenialIndex::empty(),
        ))
        .unwrap();
        assert!(
            v["denials"].is_null(),
            "no observations anywhere means unknown, and a total of 0 would              read as an all-clear for a workload nobody is watching"
        );
    }

    /// The other half of the rule, and the shape the controller's
    /// distributor parses. This is a hard contract: the keys, their
    /// spelling, and the fact that `denials` hangs off the same summary the
    /// `cr` block does.
    #[test]
    fn an_observed_workload_carries_the_contract_denials_block() {
        let obs = observed_fixture("openat,read,write", "x86_64", vec![]);
        let denials = DenialIndex::with_rows(vec![(
            "prod".into(),
            "Deployment".into(),
            "web".into(),
            "ptrace".into(),
            "SCMP_ACT_LOG".into(),
            17,
            chrono::DateTime::parse_from_rfc3339("2026-09-14T04:05:14Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )]);
        let v =
            serde_json::to_value(ProfileSummary::build(&obs, &empty_index(), &denials)).unwrap();
        assert_eq!(v["denials"]["total"], 17);
        assert_eq!(v["denials"]["syscalls"], serde_json::json!(["ptrace"]));
        assert_eq!(v["denials"]["actions"], serde_json::json!(["SCMP_ACT_LOG"]));
        assert_eq!(v["denials"]["lastSeen"], "2026-09-14T04:05:14Z");
    }

    /// The block is keyed on the workload, not attached to whatever the
    /// rollup happened to contain. A denial against another workload must
    /// not leak into this one's summary — that would put another team's
    /// kernel verdict into this CR's status.
    #[test]
    fn a_denial_against_another_workload_does_not_leak_into_this_summary() {
        let obs = observed_fixture("openat", "x86_64", vec![]);
        let denials = DenialIndex::with_rows(vec![(
            "prod".into(),
            "Deployment".into(),
            "other".into(),
            "ptrace".into(),
            "SCMP_ACT_LOG".into(),
            17,
            chrono::DateTime::parse_from_rfc3339("2026-09-14T04:05:14Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )]);
        let v =
            serde_json::to_value(ProfileSummary::build(&obs, &empty_index(), &denials)).unwrap();
        assert_eq!(
            v["denials"]["total"], 0,
            "this workload has no denials of its own"
        );
        assert!(
            v["denials"]["lastSeen"].is_null(),
            "and therefore no lastSeen"
        );
        assert!(
            !v["denials"].is_null(),
            "but capture is proven on the cluster, so its zero is a real              all-clear rather than an unknown"
        );
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
        let names = split_set(syscalls);
        Observed {
            syscall_count: names.len(),
            syscalls: Some(names),
            arches: split_set(arches),
            capture: capture_summary(&pods(&[("web-1", Some("full"))])),
            crs,
            meta: WorkloadMeta {
                pod_namespace: "prod".into(),
                workload_kind: "Deployment".into(),
                workload_name: "web".into(),
                arches: arches.into(),
                hash: "1c7725691d885dec".into(),
                updated_at: chrono::NaiveDateTime::default(),
                syscall_count: None,
            },
        }
    }

    #[test]
    fn summary_without_cr_points_snippet_at_suggested_name() {
        let obs = observed_fixture("read,write", "x86_64", Vec::new());
        let v = serde_json::to_value(ProfileSummary::build(
            &obs,
            &empty_index(),
            &DenialIndex::empty(),
        ))
        .unwrap();
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
        let v = serde_json::to_value(ProfileSummary::build(&obs, &index, &DenialIndex::empty()))
            .unwrap();
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
        let (doc, header) = export_document(
            &obs,
            obs.require_names().unwrap(),
            &plan(serde_json::json!({})),
        );
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
  annotations:
    kguardian.dev/capture-complete: \"true\"
    kguardian.dev/capture-level: full
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
        let (doc, header) = export_document(&obs, obs.require_names().unwrap(), &p);
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
  annotations:
    kguardian.dev/capture-complete: \"false\"
    kguardian.dev/capture-level: low
    kguardian.dev/capture-warning: \"partial capture (low on 1 pod(s): web-2 (low)) — this profile omits syscalls the workload makes; raise the tier to full and re-export before enforcing\"
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
        let (doc, header) = export_document(
            &obs,
            obs.require_names().unwrap(),
            &plan(serde_json::json!({})),
        );
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
        let (doc, _) = export_document(
            &obs,
            obs.require_names().unwrap(),
            &plan(serde_json::json!({"format": "json"})),
        );
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "apiVersion": "kguardian.dev/v1alpha1",
                "kind": "SeccompProfile",
                "metadata": {
                    "name": "deployment-web",
                    "namespace": "prod",
                    // JSON drops the comment header entirely, so the
                    // annotations are the ONLY capture signal a
                    // `format=json` consumer ever sees.
                    "annotations": {
                        "kguardian.dev/capture-level": "full",
                        "kguardian.dev/capture-complete": "true"
                    }
                },
                "spec": {
                    "defaultAction": "SCMP_ACT_LOG",
                    "architectures": ["SCMP_ARCH_ARM64"],
                    "syscalls": [{ "names": ["read"], "action": "SCMP_ACT_ALLOW" }],
                    "workloadRef": { "kind": "Deployment", "name": "web" }
                }
            })
        );
    }

    // ---- the partial-capture export gate --------------------------------

    fn partial() -> CaptureSummary {
        capture_summary(&pods(&[("web-1", Some("full")), ("web-2", Some("low"))]))
    }

    fn complete() -> CaptureSummary {
        capture_summary(&pods(&[("web-1", Some("full"))]))
    }

    #[test]
    fn enforcing_export_from_a_partial_capture_is_refused() {
        // The defect this gate closes: every enforcing action would
        // otherwise hand back a profile that blocks syscalls the
        // workload makes.
        for action in ["SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS"] {
            let p = plan(serde_json::json!({ "defaultAction": action }));
            let msg = partial_export_refusal(&partial(), &p)
                .unwrap_or_else(|| panic!("{action} on a partial capture must be refused"));
            // The message must name the action, the tier, the culprit
            // pod and both ways out — it is the only thing a CLI user
            // sees.
            assert!(msg.contains(action), "{msg}");
            assert!(msg.contains("web-2 (low)"), "{msg}");
            assert!(msg.contains("SYSCALL_CAPTURE_LEVEL"), "{msg}");
            assert!(msg.contains("acknowledgePartial=true"), "{msg}");
        }
    }

    #[test]
    fn audit_export_from_a_partial_capture_is_allowed() {
        // SCMP_ACT_LOG cannot break a workload, and growing a profile in
        // log mode is the supported path — gating it would cost a real
        // workflow and prevent nothing.
        let p = plan(serde_json::json!({ "defaultAction": "SCMP_ACT_LOG" }));
        assert!(partial_export_refusal(&partial(), &p).is_none());
        // ...and it is the default, so a plain export still works.
        assert!(partial_export_refusal(&partial(), &plan(serde_json::json!({}))).is_none());
    }

    #[test]
    fn a_complete_capture_is_never_refused() {
        for action in VALID_DEFAULT_ACTIONS {
            let p = plan(serde_json::json!({ "defaultAction": action }));
            assert!(
                partial_export_refusal(&complete(), &p).is_none(),
                "{action}"
            );
        }
    }

    #[test]
    fn acknowledging_the_gap_permits_the_enforcing_export() {
        let p = plan(serde_json::json!({
            "defaultAction": "SCMP_ACT_ERRNO", "acknowledgePartial": true
        }));
        assert!(partial_export_refusal(&partial(), &p).is_none());
        // A workload with no contributors at all is partial too, and the
        // opt-out covers it.
        assert!(partial_export_refusal(&capture_summary(&[]), &p).is_none());
        let p = plan(serde_json::json!({ "defaultAction": "SCMP_ACT_ERRNO" }));
        assert!(partial_export_refusal(&capture_summary(&[]), &p)
            .is_some_and(|m| m.contains("no pod has contributed syscalls yet")));
    }

    #[test]
    fn acknowledge_partial_reads_bools_and_strings_and_defaults_to_false() {
        // GET sends a string, POST sends a JSON bool; a 400 on
        // `?acknowledgePartial=1` would be a trap.
        for v in [
            serde_json::json!(true),
            serde_json::json!("true"),
            serde_json::json!("TRUE"),
            serde_json::json!(" yes "),
            serde_json::json!("1"),
            serde_json::json!("on"),
        ] {
            let p = plan(serde_json::json!({ "acknowledgePartial": v }));
            assert!(p.acknowledge_partial, "{v} must waive the gate");
        }
        // Anything unrecognised leaves the safety check in place: this
        // flag is never granted by accident.
        for v in [
            serde_json::json!(false),
            serde_json::json!("false"),
            serde_json::json!("0"),
            serde_json::json!("off"),
            serde_json::json!("maybe"),
            serde_json::json!(""),
            serde_json::json!(null),
        ] {
            let p = plan(serde_json::json!({ "acknowledgePartial": v }));
            assert!(!p.acknowledge_partial, "{v} must not waive the gate");
        }
        assert!(!plan(serde_json::json!({})).acknowledge_partial);

        // And the query-string form the GET route actually parses.
        let q: ExportOptions =
            serde_urlencoded::from_str("defaultAction=SCMP_ACT_ERRNO&acknowledgePartial=true")
                .unwrap();
        assert!(q.acknowledge_partial);
        let q: ExportOptions = serde_urlencoded::from_str("acknowledgePartial=1").unwrap();
        assert!(q.acknowledge_partial);
        let q: ExportOptions = serde_urlencoded::from_str("name=x").unwrap();
        assert!(!q.acknowledge_partial);
    }

    #[test]
    fn every_export_stamps_its_capture_tier_on_the_object() {
        // The annotations are the point of the fix: a YAML comment is
        // dropped by `kubectl apply` and by GitOps rendering, so the
        // provenance has to live in the object to survive the trip.
        let mut obs = observed_fixture("read", "x86_64", Vec::new());
        let (doc, _) = export_document(
            &obs,
            obs.require_names().unwrap(),
            &plan(serde_json::json!({})),
        );
        assert_eq!(
            doc.metadata.annotations.get(CAPTURE_LEVEL_ANNOTATION),
            Some(&"full".to_string())
        );
        assert_eq!(
            doc.metadata.annotations.get(CAPTURE_COMPLETE_ANNOTATION),
            Some(&"true".to_string())
        );
        // A complete capture is positively marked and carries no warning,
        // so an admission policy can require the positive assertion
        // rather than trusting the absence of a warning.
        assert!(!doc
            .metadata
            .annotations
            .contains_key(CAPTURE_WARNING_ANNOTATION));

        obs.capture = partial();
        let (doc, _) = export_document(
            &obs,
            obs.require_names().unwrap(),
            &plan(serde_json::json!({})),
        );
        assert_eq!(
            doc.metadata.annotations.get(CAPTURE_COMPLETE_ANNOTATION),
            Some(&"false".to_string())
        );
        assert_eq!(
            doc.metadata.annotations.get(CAPTURE_LEVEL_ANNOTATION),
            Some(&"low".to_string())
        );
        let w = doc
            .metadata
            .annotations
            .get(CAPTURE_WARNING_ANNOTATION)
            .expect("partial capture must carry a warning annotation");
        assert!(w.contains("web-2 (low)"), "{w}");
        // One line: a newline here would render as a YAML block scalar
        // and break the manifest.
        assert!(!w.contains('\n'), "{w}");
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
                // The seccomp read handlers take a ReadBudget extractor, so
                // without this every route 500s on a missing app_data before
                // the handler body runs, masking the status each case asserts.
                .app_data(web::Data::new(ReadBudget::with_budget_kib(
                    64 * 1024,
                    std::time::Duration::from_millis(0),
                )))
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
