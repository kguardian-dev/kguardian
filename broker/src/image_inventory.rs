//! Image inventory: which image digests are running, in which workload
//! containers, with what securityContext (#1533 P0-2/P0-3).
//!
//! # Where the data comes from
//!
//! `/pod/spec` has always received the whole Pod as `pod_obj`, and
//! [`crate::get::compact_pod_obj`] has always reduced it to labels and
//! `hostNetwork` before storage — so image references, the digests in
//! `status.containerStatuses[].imageID`, and every securityContext were
//! discarded at ingest. The controller now sends two small typed fields
//! beside the pod, `containers` and `pod_security`, and this module
//! stores them. They never touch `pod_obj`, so compaction cannot drop
//! them, and the manifest is still never stored whole (the 72 MB
//! `/pod/info` lesson in `compact_pod_obj`).
//!
//! # Backwards compatibility
//!
//! A controller that predates the fields simply does not send them:
//! `/pod/spec` behaves exactly as before and no inventory is written for
//! its pods. The fields are parsed leniently — a malformed `containers`
//! value drops the offending entries (or the whole field) with a warning,
//! and never fails the pod upsert, because `/pod/spec` is on the path
//! every other feature depends on.
//!
//! # Shape and bounds
//!
//! - `images`: one row per digest, global (no cluster id: a digest names
//!   the same content everywhere). Growth is O(distinct images run).
//! - `workload_containers`: one row per (cluster, namespace, kind, name,
//!   container, digest). A workload is keyed exactly as
//!   `workload_syscalls` and the SeccompProfile `workloadRef` are — the
//!   controller's owner-ref resolution posted as `workload_kind` /
//!   `workload_name` — and a pod with no owner is keyed
//!   `("Pod", pod_name)`. The digest is in the key because a container
//!   can run several at once (rollout, mixed node images); a row is only
//!   created once a digest is known. "Running" is defined by
//!   [`running_window_secs`].
//! - Retention (`retention.rs`, "Image inventory") prunes digest rows no
//!   running pod has refreshed within `IMAGE_INVENTORY_RETENTION_DAYS`,
//!   then images nothing references.
//! - Re-posts are cheap: the controller re-posts every pod on every
//!   status change and resync, so both upserts carry a `WHERE` that skips
//!   the write unless something changed or the row is more than
//!   [`REFRESH_SECS`] old.

use crate::read_budget::{cost_kib, ReadBudget};
use crate::schema;
use actix_web::{get, web, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::{Array, BigInt, Bool, Double, Jsonb, Nullable, Text, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Every row is written for this cluster until multi-cluster ingest
/// carries a real id.
pub const DEFAULT_CLUSTER_ID: &str = "primary";

/// A row is rewritten at most this often when nothing about it changed;
/// the retention window is days, so minute-level `last_seen` precision
/// buys nothing and would cost one write per pod per resync.
pub const REFRESH_SECS: i64 = 300;

/// Default for [`running_window_secs`]: three refresh periods.
pub const DEFAULT_RUNNING_WINDOW_SECS: i64 = 3 * REFRESH_SECS;
/// Floor for the window: shorter than one refresh period plus a resync
/// and a live digest would flicker out between refreshes.
pub const MIN_RUNNING_WINDOW_SECS: i64 = REFRESH_SECS + 60;
/// Ceiling: a week. Beyond that "running" stops meaning anything.
pub const MAX_RUNNING_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// Parse `IMAGE_INVENTORY_RUNNING_WINDOW_SECS` (chart:
/// `broker.imageInventory.runningWindowSeconds`). Pure for testing.
pub(crate) fn parse_running_window(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n.clamp(MIN_RUNNING_WINDOW_SECS, MAX_RUNNING_WINDOW_SECS))
        .unwrap_or(DEFAULT_RUNNING_WINDOW_SECS)
}

/// A (workload, container, digest) row counts as RUNNING when its latest
/// report says the container is active — `state = running`, or `waiting`
/// with reason `CrashLoopBackOff` (it has run from this digest and will
/// again) — AND EITHER:
///
/// 1. its `last_seen` is within this window, or
/// 2. the pod that last reported it (`last_pod_name`) is still live — in
///    `pod_details`, same namespace, not marked dead.
///
/// The state term keeps a completed init container (`terminated`, exposed
/// as `ranAsInit`) and a digest that never started (`waiting` in
/// `ContainerCreating` / `ImagePullBackOff`, e.g. a spec pin) out of the
/// running set. A NULL state comes from a controller that predates the
/// field and falls back to (1)/(2) alone.
///
/// (1) is the primary signal. The controller re-posts every live,
/// non-terminal pod on its node at least every 60 s, ready or not, and a
/// re-post refreshes `last_seen` whenever it is older than
/// [`REFRESH_SECS`], so a running digest is never more than ~6 minutes
/// stale; the default of three refresh periods leaves room for a missed
/// resync or a controller restart. Its cost: a digest keeps reading as
/// running for up to the window after its last pod goes.
///
/// (2) is the backstop for a pod whose re-posts stop while it lives (an
/// older controller that only re-posts Ready pods, a controller down on
/// that node). It is one indexed lookup on `pod_details`' primary key.
/// When a pod reports a DIFFERENT digest for the same container (an
/// in-place image update), the old row's `last_pod_name` is cleared at
/// ingest so the backstop cannot keep a replaced digest alive.
///
/// Read once from the environment.
pub fn running_window_secs() -> i64 {
    static WINDOW: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *WINDOW.get_or_init(|| {
        parse_running_window(
            std::env::var("IMAGE_INVENTORY_RUNNING_WINDOW_SECS")
                .ok()
                .as_deref(),
        )
    })
}

/// SQL for "this `workload_containers` row (aliased `wc`) is running";
/// `$W` is replaced by the bind parameter carrying the window in seconds.
/// One definition so the three read queries cannot disagree.
macro_rules! running_sql {
    ($w:literal) => {
        concat!(
            "((wc.state IS NULL OR wc.state = 'running' \
             OR (wc.state = 'waiting' AND wc.state_reason = 'CrashLoopBackOff')) \
             AND (wc.last_seen >= timezone('UTC', NOW()) - make_interval(secs => ",
            $w,
            ") OR EXISTS (SELECT 1 FROM pod_details pd WHERE pd.pod_name = wc.last_pod_name \
             AND pd.pod_namespace = wc.pod_namespace AND NOT pd.is_dead)))"
        )
    };
}
// The supply-chain GC and reads use the same predicate.
pub(crate) use running_sql;

/// Containers accepted per pod. Matches the controller's own cap.
pub const MAX_CONTAINERS_PER_POD: usize = 64;
/// Tags kept per image. A digest is normally reached through one or two
/// tags; the cap stops a CI that re-tags one digest per build from
/// growing a row without bound.
pub const MAX_TAGS_PER_IMAGE: i32 = 32;
/// Capability names kept per add/drop list.
const MAX_CAPABILITIES: usize = 64;
/// Longest Kubernetes object name (DNS subdomain).
const MAX_NAME_LEN: usize = 253;
/// Longest image reference accepted.
const MAX_IMAGE_REF_LEN: usize = 1024;
/// Longest repository accepted.
const MAX_REPOSITORY_LEN: usize = 512;
/// Docker's tag limit.
const MAX_TAG_LEN: usize = 128;
/// Short enum-like strings (seccomp type, capability names).
const MAX_SHORT_LEN: usize = 64;

// ---------------------------------------------------------------------
// Ingest types
// ---------------------------------------------------------------------

/// Container-level securityContext subset, stored as `jsonb`. Parsed
/// into this type (not stored as posted) so unknown or oversized keys
/// cannot reach the column.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSecurity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities_add: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities_drop: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile_type: Option<String>,
}

/// Pod securityContext subset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_group: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile_type: Option<String>,
}

/// Pod-level posture fields, stored as `jsonb` on every container row of
/// the workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automount_service_account_token: Option<bool>,
    #[serde(default, rename = "hostPID", skip_serializing_if = "Option::is_none")]
    pub host_pid: Option<bool>,
    #[serde(default, rename = "hostIPC", skip_serializing_if = "Option::is_none")]
    pub host_ipc: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_users: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<PodSecurityFields>,
}

/// One entry of the posted `containers` list (controller
/// `image_inventory::ContainerInventory`).
#[derive(Debug, Clone, Deserialize)]
pub struct ContainerInput {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub digest_kind: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub security_context: Option<ContainerSecurity>,
    /// `running` | `waiting` | `terminated`; absent from older controllers.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub state_reason: Option<String>,
}

const CONTAINER_STATES: [&str; 3] = ["running", "waiting", "terminated"];

/// The `/pod/spec` body: the existing `PodDetail` plus the two inventory
/// fields, which are not `pod_details` columns and so cannot live on
/// that (positional, diesel-derived) struct.
///
/// Both are `serde_json::Value` on purpose: they are parsed leniently in
/// [`inventory_from_post`], so a malformed value costs its own inventory
/// and never the pod upsert.
#[derive(Debug, Deserialize)]
pub struct PodSpecIngest {
    #[serde(flatten)]
    pub pod: crate::PodDetail,
    #[serde(default)]
    pub containers: Option<serde_json::Value>,
    #[serde(default)]
    pub pod_security: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

/// `algo:hex` with a known algorithm and the right hex length.
pub fn is_valid_digest(s: &str) -> bool {
    let Some((algo, hex)) = s.split_once(':') else {
        return false;
    };
    let want = match algo {
        "sha256" => 64,
        "sha512" => 128,
        _ => return false,
    };
    hex.len() == want
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

const CONTAINER_KINDS: [&str; 3] = ["init", "regular", "ephemeral"];
const DIGEST_KINDS: [&str; 3] = ["repo", "config", "pinned"];

fn bounded(s: Option<String>, max: usize) -> Option<String> {
    s.map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= max)
}

/// [`bounded`] for an image reference, repository or tag: also refused
/// when it holds a control character or a Unicode line/paragraph separator
/// (U+2028/U+2029). No valid reference has one, and these values are
/// written into generated YAML, where a line break would start a new line.
fn bounded_ref(s: Option<String>, max: usize) -> Option<String> {
    bounded(s, max).filter(|v| {
        !v.chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
    })
}

/// What a container's image reference is stored as when the controller
/// reported one that is not a valid reference (a control character or line
/// separator, or too long). The container is kept, so it is never missing
/// from the inventory, profiles or generated policies; everything
/// downstream treats it as an image that cannot be judged.
pub const MALFORMED_REFERENCE: &str = "malformed_reference";

static MALFORMED_IMAGE_REF: AtomicU64 = AtomicU64::new(0);
static MALFORMED_REPOSITORY: AtomicU64 = AtomicU64::new(0);
static MALFORMED_TAG: AtomicU64 = AtomicU64::new(0);

/// Validates an image field that was reported. `Ok(None)`: absent;
/// `Err(())`: reported but malformed (logged and counted; the raw value is
/// only ever logged escaped and cut short).
fn checked_ref(
    s: Option<String>,
    max: usize,
    field: &'static str,
    pod: &str,
    container: &str,
) -> Result<Option<String>, ()> {
    let reported = s.as_deref().is_some_and(|v| !v.trim().is_empty());
    match bounded_ref(s.clone(), max) {
        Some(v) => Ok(Some(v)),
        None if !reported => Ok(None),
        None => {
            let counter = match field {
                "image_ref" => &MALFORMED_IMAGE_REF,
                "repository" => &MALFORMED_REPOSITORY,
                _ => &MALFORMED_TAG,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let preview: String = s.unwrap_or_default().chars().take(64).collect();
            warn!(pod, container, field, value = ?preview,
                "malformed image reference from the controller (control character, line separator or too long); kept as malformed_reference");
            Err(())
        }
    }
}

/// Prometheus text for malformed image references seen at ingest.
pub fn render_malformed_metrics() -> String {
    let mut out = String::from(
        "# HELP kguardian_image_inventory_malformed_total Image references reported by the controller that were not valid (control character, line separator or too long), by field\n\
         # TYPE kguardian_image_inventory_malformed_total counter\n",
    );
    for (field, c) in [
        ("image_ref", &MALFORMED_IMAGE_REF),
        ("repository", &MALFORMED_REPOSITORY),
        ("tag", &MALFORMED_TAG),
    ] {
        out.push_str(&format!(
            "kguardian_image_inventory_malformed_total{{field=\"{field}\"}} {}\n",
            c.load(Ordering::Relaxed)
        ));
    }
    out
}

fn bounded_list(v: Option<Vec<String>>) -> Option<Vec<String>> {
    let mut out: Vec<String> = v?
        .into_iter()
        .filter_map(|s| bounded(Some(s), MAX_SHORT_LEN))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    out.truncate(MAX_CAPABILITIES);
    (!out.is_empty()).then_some(out)
}

fn sanitise_container_security(sc: ContainerSecurity) -> ContainerSecurity {
    ContainerSecurity {
        capabilities_add: bounded_list(sc.capabilities_add),
        capabilities_drop: bounded_list(sc.capabilities_drop),
        seccomp_profile_type: bounded(sc.seccomp_profile_type, MAX_SHORT_LEN),
        ..sc
    }
}

fn sanitise_pod_security(ps: PodSecurity) -> PodSecurity {
    PodSecurity {
        service_account_name: bounded(ps.service_account_name, MAX_NAME_LEN),
        security_context: ps.security_context.map(|sc| PodSecurityFields {
            seccomp_profile_type: bounded(sc.seccomp_profile_type, MAX_SHORT_LEN),
            ..sc
        }),
        ..ps
    }
}

/// One validated `workload_containers` row, ready to upsert.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerRow {
    pub cluster_id: String,
    pub namespace: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub container_kind: String,
    pub image_ref: String,
    pub image_digest: Option<String>,
    pub security_context: serde_json::Value,
    pub pod_security: serde_json::Value,
    pub last_pod_name: String,
    /// Validated `running|waiting|terminated`, or `None` (older controller
    /// or an unknown value).
    pub state: Option<String>,
    pub state_reason: Option<String>,
}

/// One validated `images` upsert, merged across every container of the
/// post that runs the digest.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageRow {
    pub digest: String,
    pub repository: Option<String>,
    pub tags: Vec<String>,
    pub digest_kind: String,
}

/// Everything one `/pod/spec` post contributes to the inventory.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Inventory {
    pub containers: Vec<ContainerRow>,
    pub images: Vec<ImageRow>,
}

/// Rank for merging two sightings of one digest: a registry-resolvable
/// repo digest beats a config digest beats a spec pin.
fn digest_kind_rank(k: &str) -> u8 {
    match k {
        "repo" => 2,
        "config" => 1,
        _ => 0,
    }
}

/// Turn a post's typed inventory fields into rows. Pure: no database.
///
/// Returns an empty inventory (and writes nothing) when the controller
/// did not send `containers` (an older controller), when the pod has no
/// namespace to key it on, or when nothing in the list is valid.
pub fn inventory_from_post(
    pod: &crate::PodDetail,
    containers: Option<&serde_json::Value>,
    pod_security: Option<&serde_json::Value>,
) -> Inventory {
    let Some(serde_json::Value::Array(entries)) = containers else {
        if containers.is_some_and(|v| !v.is_null()) {
            warn!(pod = %pod.pod_name, "/pod/spec containers is not a list; inventory skipped");
        }
        return Inventory::default();
    };
    let Some(namespace) = pod
        .pod_namespace
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Inventory::default();
    };
    let (workload_kind, workload_name) = match (
        pod.workload_kind.as_deref().map(str::trim),
        pod.workload_name.as_deref().map(str::trim),
    ) {
        (Some(k), Some(n)) if !k.is_empty() && !n.is_empty() => (k.to_string(), n.to_string()),
        _ => ("Pod".to_string(), pod.pod_name.trim().to_string()),
    };

    let pod_sec = pod_security
        .filter(|v| !v.is_null())
        .and_then(|v| match serde_json::from_value::<PodSecurity>(v.clone()) {
            Ok(p) => Some(p),
            Err(e) => {
                warn!(pod = %pod.pod_name, error = %e, "/pod/spec pod_security malformed; stored empty");
                None
            }
        })
        .map(sanitise_pod_security)
        .unwrap_or_default();
    let pod_sec_json = serde_json::to_value(&pod_sec).unwrap_or_else(|_| serde_json::json!({}));

    let mut out = Inventory::default();
    let mut seen_names = BTreeSet::new();
    let mut images: BTreeMap<String, ImageRow> = BTreeMap::new();
    for raw in entries.iter().take(MAX_CONTAINERS_PER_POD) {
        let c: ContainerInput = match serde_json::from_value(raw.clone()) {
            Ok(c) => c,
            Err(e) => {
                warn!(pod = %pod.pod_name, error = %e, "/pod/spec container entry malformed; skipped");
                continue;
            }
        };
        let Some(name) = bounded(Some(c.name), MAX_NAME_LEN) else {
            continue;
        };
        let kind = c.kind.trim().to_ascii_lowercase();
        if !CONTAINER_KINDS.contains(&kind.as_str()) {
            warn!(pod = %pod.pod_name, container = %name, kind = %c.kind, "unknown container kind; skipped");
            continue;
        }
        // A malformed reference keeps the container (as
        // malformed_reference): an image that cannot be read is an image
        // that cannot be judged, never a container that is not there.
        let image_ref = match checked_ref(
            c.image,
            MAX_IMAGE_REF_LEN,
            "image_ref",
            &pod.pod_name,
            &name,
        ) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(()) => MALFORMED_REFERENCE.to_string(),
        };
        if !seen_names.insert(name.clone()) {
            continue;
        }
        // A digest is only kept with a kind we understand; the images row
        // cannot be written without one.
        let digest_kind = c
            .digest_kind
            .map(|k| k.trim().to_ascii_lowercase())
            .filter(|k| DIGEST_KINDS.contains(&k.as_str()));
        let digest = c
            .digest
            .map(|d| d.trim().to_string())
            .filter(|d| is_valid_digest(d));
        let digest = match (digest, digest_kind) {
            (Some(d), Some(k)) => {
                // A malformed repository or tag is dropped, counted and
                // logged. Not stored as a marker: supplychain and the
                // registry SBOM source look repositories up in registries.
                let repository = checked_ref(
                    c.repository,
                    MAX_REPOSITORY_LEN,
                    "repository",
                    &pod.pod_name,
                    &name,
                )
                .unwrap_or(None);
                let tag =
                    checked_ref(c.tag, MAX_TAG_LEN, "tag", &pod.pod_name, &name).unwrap_or(None);
                let entry = images.entry(d.clone()).or_insert_with(|| ImageRow {
                    digest: d.clone(),
                    repository: None,
                    tags: Vec::new(),
                    digest_kind: k.clone(),
                });
                if entry.repository.is_none() {
                    entry.repository = repository;
                }
                if let Some(t) = tag {
                    if !entry.tags.contains(&t) && entry.tags.len() < MAX_TAGS_PER_IMAGE as usize {
                        entry.tags.push(t);
                        entry.tags.sort();
                    }
                }
                if digest_kind_rank(&k) > digest_kind_rank(&entry.digest_kind) {
                    entry.digest_kind = k;
                }
                Some(d)
            }
            _ => None,
        };
        let sc = sanitise_container_security(c.security_context.unwrap_or_default());
        let state = c
            .state
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| CONTAINER_STATES.contains(&s.as_str()));
        // A reason only means something next to a known state.
        let state_reason = state
            .as_ref()
            .and_then(|_| bounded(c.state_reason, MAX_SHORT_LEN));
        out.containers.push(ContainerRow {
            state,
            state_reason,
            cluster_id: DEFAULT_CLUSTER_ID.to_string(),
            namespace: namespace.to_string(),
            workload_kind: workload_kind.clone(),
            workload_name: workload_name.clone(),
            container_name: name,
            container_kind: kind,
            image_ref,
            image_digest: digest,
            security_context: serde_json::to_value(&sc).unwrap_or_else(|_| serde_json::json!({})),
            pod_security: pod_sec_json.clone(),
            last_pod_name: pod.pod_name.clone(),
        });
    }
    out.images = images.into_values().collect();
    out
}

// ---------------------------------------------------------------------
// Upsert
// ---------------------------------------------------------------------

/// Upsert one image. `last_seen` is the DATABASE clock (not the posted
/// timestamp) so retention compares like with like.
///
/// The `WHERE` skips the write when nothing would change and the row was
/// refreshed within [`REFRESH_SECS`]: tags only grow (until the cap),
/// repository only fills in, and `digest_kind` only moves towards `repo`.
pub(crate) const IMAGE_UPSERT_SQL: &str = "\
INSERT INTO images (digest, repository, tags, digest_kind, first_seen, last_seen) \
VALUES ($1, $2, $3, $4, timezone('UTC', NOW()), timezone('UTC', NOW())) \
ON CONFLICT (digest) DO UPDATE SET \
    repository = COALESCE(images.repository, EXCLUDED.repository), \
    tags = (SELECT COALESCE(array_agg(t ORDER BY t), '{}'::text[]) FROM ( \
        SELECT t FROM (SELECT DISTINCT unnest(images.tags || EXCLUDED.tags) AS t) d \
        ORDER BY (t = ANY(images.tags)) DESC, t LIMIT $5) s), \
    digest_kind = CASE \
        WHEN EXCLUDED.digest_kind = 'repo' OR images.digest_kind = 'repo' THEN 'repo' \
        WHEN EXCLUDED.digest_kind = 'config' OR images.digest_kind = 'config' THEN 'config' \
        ELSE images.digest_kind END, \
    last_seen = GREATEST(images.last_seen, EXCLUDED.last_seen) \
WHERE images.last_seen < EXCLUDED.last_seen - make_interval(secs => $6) \
   OR (NOT (EXCLUDED.tags <@ images.tags) AND cardinality(images.tags) < $5) \
   OR (images.repository IS NULL AND EXCLUDED.repository IS NOT NULL) \
   OR (images.digest_kind <> 'repo' AND EXCLUDED.digest_kind = 'repo') \
   OR (images.digest_kind = 'pinned' AND EXCLUDED.digest_kind = 'config')";

/// Upsert one (workload, container, digest) sighting.
///
/// The digest is part of the key, so a workload running several digests
/// for one container at once — mid-rollout, or a DaemonSet whose nodes
/// resolved a tag differently — keeps one row per digest, each refreshed
/// by the pods that run it. `state` / `state_reason` record the latest
/// report for that digest. The `WHERE` skips the write unless something
/// about the row changed or it is more than [`REFRESH_SECS`] old;
/// `last_pod_name` alone never forces a write, so replicas sharing a
/// digest do not take turns rewriting it.
pub(crate) const CONTAINER_UPSERT_SQL: &str = "\
INSERT INTO workload_containers (cluster_id, pod_namespace, workload_kind, workload_name, \
    container_name, image_digest, container_kind, image_ref, security_context, pod_security, \
    last_pod_name, state, state_reason, first_seen, last_seen) \
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $13, $14, \
    timezone('UTC', NOW()), timezone('UTC', NOW())) \
ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest) \
DO UPDATE SET \
    container_kind = EXCLUDED.container_kind, \
    image_ref = EXCLUDED.image_ref, \
    security_context = EXCLUDED.security_context, \
    pod_security = EXCLUDED.pod_security, \
    last_pod_name = EXCLUDED.last_pod_name, \
    state = EXCLUDED.state, \
    state_reason = EXCLUDED.state_reason, \
    last_seen = EXCLUDED.last_seen \
WHERE workload_containers.last_seen < EXCLUDED.last_seen - make_interval(secs => $12) \
   OR workload_containers.container_kind IS DISTINCT FROM EXCLUDED.container_kind \
   OR workload_containers.image_ref IS DISTINCT FROM EXCLUDED.image_ref \
   OR workload_containers.security_context IS DISTINCT FROM EXCLUDED.security_context \
   OR workload_containers.pod_security IS DISTINCT FROM EXCLUDED.pod_security \
   OR workload_containers.state IS DISTINCT FROM EXCLUDED.state \
   OR workload_containers.state_reason IS DISTINCT FROM EXCLUDED.state_reason";

/// When a pod reports digest D for a container, it no longer runs any
/// other digest there: drop its name from those rows so the live-pod
/// backstop in [`running_window_secs`] cannot keep a replaced digest
/// running (in-place image update, a StatefulSet pod recreated under the
/// same name on a new image). Matches nothing in the steady state, so it
/// writes nothing.
pub(crate) const CONTAINER_RELEASE_SQL: &str = "\
UPDATE workload_containers SET last_pod_name = NULL \
WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
  AND container_name = $5 AND image_digest <> $6 AND last_pod_name = $7";

/// The digest-less twin of [`CONTAINER_RELEASE_SQL`]: a pod that reports
/// a container with NO digest (recreated under the same name and stuck
/// pulling, or an in-place image patch that fails to pull) runs nothing
/// there, so its name comes off every digest row of that container.
/// Otherwise a StatefulSet pod `web-0` stuck in `ImagePullBackOff` would
/// keep its previous digest reading as running through the live-pod
/// backstop for as long as it stayed stuck. Matches nothing in the
/// steady state.
pub(crate) const CONTAINER_RELEASE_ALL_SQL: &str = "\
UPDATE workload_containers SET last_pod_name = NULL \
WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
  AND container_name = $5 AND last_pod_name = $6";

/// A container reported with an image ref but no digest yet — the pod is
/// (re)starting or stuck pulling (`ContainerCreating`, `ImagePullBackOff`).
/// It never creates a row (no digest is known to run) and it never makes
/// one read as running: it touches only `ref_seen_at`, which retention
/// honours and the running predicate ignores, and only on the single most
/// recent digest row for that ref. With a mutable tag (`app:latest`)
/// several historical digests share the ref; bumping all of them, or
/// setting `last_pod_name` on them (the live-pod backstop), would make
/// every one of them read as running for as long as the pod stayed stuck.
pub(crate) const CONTAINER_REFRESH_SQL: &str = "\
UPDATE workload_containers SET ref_seen_at = timezone('UTC', NOW()) \
WHERE (cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest) = ( \
    SELECT cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest \
    FROM workload_containers \
    WHERE cluster_id = $1 AND pod_namespace = $2 AND workload_kind = $3 AND workload_name = $4 \
      AND container_name = $5 AND image_ref = $6 \
    ORDER BY last_seen DESC, image_digest LIMIT 1) \
  AND (ref_seen_at IS NULL OR ref_seen_at < timezone('UTC', NOW()) - make_interval(secs => $7))";

/// Write one post's inventory in a single transaction. Returns the number
/// of rows actually written (inserted or changed); a steady-state re-post
/// writes 0.
pub fn upsert_inventory(conn: &mut PgConnection, inv: &Inventory) -> Result<usize, DbError> {
    if inv.containers.is_empty() && inv.images.is_empty() {
        return Ok(0);
    }
    let written = conn.transaction::<usize, diesel::result::Error, _>(|conn| {
        let mut n = 0;
        for img in &inv.images {
            n += sql_query(IMAGE_UPSERT_SQL)
                .bind::<Text, _>(&img.digest)
                .bind::<Nullable<Text>, _>(img.repository.as_deref())
                .bind::<Array<Text>, _>(&img.tags)
                .bind::<Text, _>(&img.digest_kind)
                .bind::<diesel::sql_types::Integer, _>(MAX_TAGS_PER_IMAGE)
                .bind::<diesel::sql_types::Double, _>(REFRESH_SECS as f64)
                .execute(conn)?;
        }
        for c in &inv.containers {
            if c.image_digest.is_none() {
                n += sql_query(CONTAINER_RELEASE_ALL_SQL)
                    .bind::<Text, _>(&c.cluster_id)
                    .bind::<Text, _>(&c.namespace)
                    .bind::<Text, _>(&c.workload_kind)
                    .bind::<Text, _>(&c.workload_name)
                    .bind::<Text, _>(&c.container_name)
                    .bind::<Text, _>(&c.last_pod_name)
                    .execute(conn)?;
            }
            if let Some(digest) = c.image_digest.as_deref() {
                n += sql_query(CONTAINER_RELEASE_SQL)
                    .bind::<Text, _>(&c.cluster_id)
                    .bind::<Text, _>(&c.namespace)
                    .bind::<Text, _>(&c.workload_kind)
                    .bind::<Text, _>(&c.workload_name)
                    .bind::<Text, _>(&c.container_name)
                    .bind::<Text, _>(digest)
                    .bind::<Text, _>(&c.last_pod_name)
                    .execute(conn)?;
            }
            n += match c.image_digest.as_deref() {
                Some(digest) => sql_query(CONTAINER_UPSERT_SQL)
                    .bind::<Text, _>(&c.cluster_id)
                    .bind::<Text, _>(&c.namespace)
                    .bind::<Text, _>(&c.workload_kind)
                    .bind::<Text, _>(&c.workload_name)
                    .bind::<Text, _>(&c.container_name)
                    .bind::<Text, _>(digest)
                    .bind::<Text, _>(&c.container_kind)
                    .bind::<Text, _>(&c.image_ref)
                    .bind::<Jsonb, _>(&c.security_context)
                    .bind::<Jsonb, _>(&c.pod_security)
                    .bind::<Text, _>(&c.last_pod_name)
                    .bind::<diesel::sql_types::Double, _>(REFRESH_SECS as f64)
                    .bind::<Nullable<Text>, _>(c.state.as_deref())
                    .bind::<Nullable<Text>, _>(c.state_reason.as_deref())
                    .execute(conn)?,
                None => sql_query(CONTAINER_REFRESH_SQL)
                    .bind::<Text, _>(&c.cluster_id)
                    .bind::<Text, _>(&c.namespace)
                    .bind::<Text, _>(&c.workload_kind)
                    .bind::<Text, _>(&c.workload_name)
                    .bind::<Text, _>(&c.container_name)
                    .bind::<Text, _>(&c.image_ref)
                    .bind::<diesel::sql_types::Double, _>(REFRESH_SECS as f64)
                    .execute(conn)?,
            };
        }
        Ok(n)
    })?;
    debug!(
        containers = inv.containers.len(),
        images = inv.images.len(),
        written,
        "image inventory upserted"
    );
    Ok(written)
}

// ---------------------------------------------------------------------
// Read side
// ---------------------------------------------------------------------

/// Peak in-flight bytes charged per `images` row on a list read. The row
/// is a digest, a repository, a handful of tags and two timestamps —
/// well under 1 KiB serialised; charged at 1 KiB, the same figure as
/// the similarly narrow audit rows (`read_budget::AUDIT_ROW_COST_BYTES`).
pub const IMAGE_ROW_COST_BYTES: u64 = 1_024;
/// Per `workload_containers` row: the two jsonb subsets are bounded by
/// the sanitisers above (a few hundred bytes each in practice), so 2 KiB
/// covers the row, its serialised form and the doubling transient.
pub const WORKLOAD_CONTAINER_ROW_COST_BYTES: u64 = 2_048;

/// `GET /images` page size: default and hard cap.
pub const IMAGES_DEFAULT_LIMIT: i64 = 100;
pub const IMAGES_MAX_LIMIT: i64 = 500;
/// Workloads listed under one image in `GET /images/{digest}`.
pub const IMAGE_WORKLOADS_MAX: i64 = 500;
/// Containers listed for one workload.
pub const WORKLOAD_CONTAINERS_MAX: i64 = 256;

pub(crate) fn clamp_images_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(IMAGES_DEFAULT_LIMIT)
        .clamp(1, IMAGES_MAX_LIMIT)
}

fn empty_to_none(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[derive(Debug, Deserialize)]
pub struct ImagesQuery {
    /// Only images some workload in this namespace runs.
    pub namespace: Option<String>,
    /// Exact normalised repository, e.g. `docker.io/library/nginx`.
    pub repository: Option<String>,
    /// Page size; default 100, max 500.
    pub limit: Option<i64>,
    /// Cursor: the `nextAfter` of the previous page (a digest).
    pub after: Option<String>,
}

#[derive(Debug, Clone, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageSummary {
    #[diesel(sql_type = Text)]
    pub digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub repository: Option<String>,
    #[diesel(sql_type = Array<Text>)]
    pub tags: Vec<String>,
    #[diesel(sql_type = Text)]
    pub digest_kind: String,
    #[diesel(sql_type = Timestamp)]
    pub first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    pub last_seen: NaiveDateTime,
    /// Workload containers running this digest now (refreshed within
    /// [`running_window_secs`]). 0 = no longer running; kept until
    /// retention prunes it.
    #[diesel(sql_type = BigInt)]
    pub running_containers: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImagePage {
    pub items: Vec<ImageSummary>,
    /// Pass as `?after=` for the next page; `null` on the last page.
    pub next_after: Option<String>,
}

const IMAGES_LIST_SQL: &str = concat!(
    "SELECT i.digest, i.repository, i.tags, i.digest_kind, i.first_seen, i.last_seen, \
    (SELECT count(*) FROM workload_containers wc WHERE wc.image_digest = i.digest AND ",
    running_sql!("$5"),
    ") AS running_containers \
FROM images i \
WHERE ($1::text IS NULL OR i.digest > $1) \
  AND ($2::text IS NULL OR EXISTS (SELECT 1 FROM workload_containers wc \
        WHERE wc.image_digest = i.digest AND wc.pod_namespace = $2)) \
  AND ($3::text IS NULL OR i.repository = $3) \
ORDER BY i.digest \
LIMIT $4"
);

pub fn list_images(
    conn: &mut PgConnection,
    namespace: Option<&str>,
    repository: Option<&str>,
    after: Option<&str>,
    limit: i64,
) -> Result<ImagePage, DbError> {
    let mut items: Vec<ImageSummary> = sql_query(IMAGES_LIST_SQL)
        .bind::<Nullable<Text>, _>(after)
        .bind::<Nullable<Text>, _>(namespace)
        .bind::<Nullable<Text>, _>(repository)
        .bind::<BigInt, _>(limit + 1)
        .bind::<Double, _>(running_window_secs() as f64)
        .load(conn)?;
    let next_after = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(|i| i.digest.clone())
    } else {
        None
    };
    Ok(ImagePage { items, next_after })
}

#[get(
    "/images",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_images(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ImagesQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let limit = clamp_images_limit(q.limit);
    let after = empty_to_none(q.after);
    if let Some(a) = after.as_deref() {
        if !is_valid_digest(a) {
            return Ok(HttpResponse::BadRequest().body("after must be a digest (sha256:<hex>)"));
        }
    }
    let namespace = empty_to_none(q.namespace);
    let repository = empty_to_none(q.repository);
    // +1: the look-ahead row that decides `nextAfter`.
    let _permit = match budget
        .acquire(cost_kib(limit + 1, IMAGE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let page = web::block(move || {
        let mut conn = pool.get()?;
        list_images(
            &mut conn,
            namespace.as_deref(),
            repository.as_deref(),
            after.as_deref(),
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(page))
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = schema::images)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub digest: String,
    pub repository: Option<String>,
    pub tags: Vec<String>,
    pub digest_kind: String,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

/// A workload container that runs (or ran) an image, without the posture
/// blobs (those are on `GET /workloads/.../containers`).
#[derive(Debug, Clone, QueryableByName, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageUser {
    #[diesel(sql_type = Text)]
    pub cluster_id: String,
    #[diesel(sql_type = Text)]
    pub namespace: String,
    #[diesel(sql_type = Text)]
    pub workload_kind: String,
    #[diesel(sql_type = Text)]
    pub workload_name: String,
    #[diesel(sql_type = Text)]
    pub container_name: String,
    #[diesel(sql_type = Text)]
    pub container_kind: String,
    #[diesel(sql_type = Text)]
    pub image_ref: String,
    #[diesel(sql_type = Timestamp)]
    pub first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    pub last_seen: NaiveDateTime,
    /// Container state in the latest report for this digest (`running` |
    /// `waiting` | `terminated`); `null` from an older controller.
    #[diesel(sql_type = Nullable<Text>)]
    pub state: Option<String>,
    /// Kubelet reason for `waiting` / `terminated` (e.g. `CrashLoopBackOff`,
    /// `ImagePullBackOff`, `Completed`).
    #[diesel(sql_type = Nullable<Text>)]
    pub state_reason: Option<String>,
    /// An init container that ran from this digest and completed. Kept in
    /// the inventory, never counted as running.
    #[diesel(sql_type = Bool)]
    pub ran_as_init: bool,
    /// See [`running_window_secs`] for the definition.
    #[diesel(sql_type = Bool)]
    pub running: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageDetail {
    #[serde(flatten)]
    pub image: Image,
    /// Running rows first, then most recently seen.
    pub workloads: Vec<ImageUser>,
    /// More than [`IMAGE_WORKLOADS_MAX`] workload containers reference it.
    pub truncated: bool,
}

const IMAGE_USERS_SQL: &str = concat!(
    "SELECT wc.cluster_id, wc.pod_namespace AS namespace, wc.workload_kind, wc.workload_name, \
    wc.container_name, wc.container_kind, wc.image_ref, wc.first_seen, wc.last_seen, \
    wc.state, wc.state_reason, \
    (wc.container_kind = 'init' AND wc.state IS NOT DISTINCT FROM 'terminated') AS ran_as_init, ",
    running_sql!("$2"),
    " AS running \
FROM workload_containers wc WHERE wc.image_digest = $1 \
ORDER BY running DESC, wc.pod_namespace, wc.workload_kind, wc.workload_name, wc.container_name \
LIMIT $3"
);

pub fn image_detail(conn: &mut PgConnection, d: &str) -> Result<Option<ImageDetail>, DbError> {
    use schema::images::dsl as im;
    let Some(image) = im::images
        .find(d)
        .select(Image::as_select())
        .first(conn)
        .optional()?
    else {
        return Ok(None);
    };
    let mut workloads: Vec<ImageUser> = sql_query(IMAGE_USERS_SQL)
        .bind::<Text, _>(d)
        .bind::<Double, _>(running_window_secs() as f64)
        .bind::<BigInt, _>(IMAGE_WORKLOADS_MAX + 1)
        .load(conn)?;
    let truncated = workloads.len() as i64 > IMAGE_WORKLOADS_MAX;
    workloads.truncate(IMAGE_WORKLOADS_MAX as usize);
    Ok(Some(ImageDetail {
        image,
        workloads,
        truncated,
    }))
}

#[get(
    "/images/{digest}",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_image(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let digest = path.into_inner();
    if !is_valid_digest(&digest) {
        return Ok(
            HttpResponse::BadRequest().body("digest must be sha256:<64 hex> or sha512:<128 hex>")
        );
    }
    let _permit = match budget
        .acquire(cost_kib(
            IMAGE_WORKLOADS_MAX + 2,
            WORKLOAD_CONTAINER_ROW_COST_BYTES,
        ))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let detail = web::block(move || {
        let mut conn = pool.get()?;
        image_detail(&mut conn, &digest)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match detail {
        Some(d) => HttpResponse::Ok().json(d),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

/// One `workload_containers` row as read for the workload view.
#[derive(Debug, Clone, QueryableByName)]
struct ContainerDigestRow {
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Text)]
    container_name: String,
    #[diesel(sql_type = Text)]
    container_kind: String,
    #[diesel(sql_type = Text)]
    image_digest: String,
    #[diesel(sql_type = Text)]
    image_ref: String,
    #[diesel(sql_type = Jsonb)]
    security_context: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    pod_security: serde_json::Value,
    #[diesel(sql_type = Nullable<Text>)]
    last_pod_name: Option<String>,
    #[diesel(sql_type = Timestamp)]
    first_seen: NaiveDateTime,
    #[diesel(sql_type = Timestamp)]
    last_seen: NaiveDateTime,
    #[diesel(sql_type = Nullable<Text>)]
    state: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    state_reason: Option<String>,
    #[diesel(sql_type = Bool)]
    ran_as_init: bool,
    #[diesel(sql_type = Bool)]
    running: bool,
}

/// One digest a container runs (or ran).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerDigest {
    pub digest: String,
    pub image_ref: String,
    pub security_context: serde_json::Value,
    pub pod_security: serde_json::Value,
    pub last_pod_name: Option<String>,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
    /// `running` | `waiting` | `terminated` in the latest report for this
    /// digest; `null` from an older controller.
    pub state: Option<String>,
    /// e.g. `CrashLoopBackOff`, `ImagePullBackOff`, `Completed`.
    pub state_reason: Option<String>,
    /// A completed init container: it ran from this digest, it is not
    /// running now.
    pub ran_as_init: bool,
}

/// One container of a workload, with every digest it runs.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerImages {
    pub cluster_id: String,
    pub container_name: String,
    pub container_kind: String,
    /// More than one digest running at once: a rollout in progress, or
    /// nodes that resolved the same tag to different images.
    pub mixed_digests: bool,
    /// Digests running now (see [`running_window_secs`]), newest first.
    pub digests: Vec<ContainerDigest>,
    /// Digests known for this container but not running now: no pod has
    /// reported them within the window, they never started (`waiting` in
    /// `ContainerCreating` / `ImagePullBackOff`), or a completed init
    /// container (`ranAsInit`). Each carries its `state` for labelling;
    /// kept until retention prunes them (`IMAGE_INVENTORY_RETENTION_DAYS`).
    pub previous_digests: Vec<ContainerDigest>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadContainers {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    /// The freshness window that defines "running", in seconds.
    pub running_window_seconds: i64,
    pub containers: Vec<ContainerImages>,
    /// More than [`WORKLOAD_CONTAINERS_MAX`] (container, digest) rows.
    pub truncated: bool,
}

const WORKLOAD_CONTAINERS_SQL: &str = concat!(
    "SELECT wc.cluster_id, wc.container_name, wc.container_kind, wc.image_digest, wc.image_ref, \
    wc.security_context, wc.pod_security, wc.last_pod_name, wc.first_seen, wc.last_seen, \
    wc.state, wc.state_reason, \
    (wc.container_kind = 'init' AND wc.state IS NOT DISTINCT FROM 'terminated') AS ran_as_init, ",
    running_sql!("$4"),
    " AS running \
FROM workload_containers wc \
WHERE wc.pod_namespace = $1 AND wc.workload_kind = $2 AND wc.workload_name = $3 \
ORDER BY wc.cluster_id, wc.container_name, wc.last_seen DESC, wc.image_digest \
LIMIT $5"
);

/// Group rows (already ordered by cluster, container, newest first) per
/// container. Pure, so the grouping is unit-tested without a database.
fn group_containers(rows: Vec<ContainerDigestRow>) -> Vec<ContainerImages> {
    let mut out: Vec<ContainerImages> = Vec::new();
    for r in rows {
        let d = ContainerDigest {
            digest: r.image_digest,
            image_ref: r.image_ref,
            security_context: r.security_context,
            pod_security: r.pod_security,
            last_pod_name: r.last_pod_name,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            state: r.state,
            state_reason: r.state_reason,
            ran_as_init: r.ran_as_init,
        };
        let same = out
            .last()
            .is_some_and(|c| c.cluster_id == r.cluster_id && c.container_name == r.container_name);
        if !same {
            out.push(ContainerImages {
                cluster_id: r.cluster_id,
                container_name: r.container_name,
                // Newest row first, so this is the current kind.
                container_kind: r.container_kind,
                mixed_digests: false,
                digests: Vec::new(),
                previous_digests: Vec::new(),
            });
        }
        let c = out.last_mut().expect("pushed above");
        if r.running {
            c.digests.push(d);
        } else {
            c.previous_digests.push(d);
        }
        c.mixed_digests = c.digests.len() > 1;
    }
    out
}

pub fn workload_containers(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<WorkloadContainers, DbError> {
    let mut rows: Vec<ContainerDigestRow> = sql_query(WORKLOAD_CONTAINERS_SQL)
        .bind::<Text, _>(ns)
        .bind::<Text, _>(kind)
        .bind::<Text, _>(name)
        .bind::<Double, _>(running_window_secs() as f64)
        .bind::<BigInt, _>(WORKLOAD_CONTAINERS_MAX + 1)
        .load(conn)?;
    let truncated = rows.len() as i64 > WORKLOAD_CONTAINERS_MAX;
    rows.truncate(WORKLOAD_CONTAINERS_MAX as usize);
    Ok(WorkloadContainers {
        namespace: ns.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
        running_window_seconds: running_window_secs(),
        containers: group_containers(rows),
        truncated,
    })
}

#[get(
    "/workloads/{namespace}/{kind}/{name}/containers",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_containers(
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
        .acquire(cost_kib(
            WORKLOAD_CONTAINERS_MAX + 1,
            WORKLOAD_CONTAINER_ROW_COST_BYTES,
        ))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let out = web::block(move || {
        let mut conn = pool.get()?;
        workload_containers(&mut conn, &ns, &kind, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(if out.containers.is_empty() {
        HttpResponse::NotFound().body("No data found")
    } else {
        HttpResponse::Ok().json(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn pod(ns: Option<&str>, kind: Option<&str>, name: Option<&str>) -> crate::PodDetail {
        crate::PodDetail {
            pod_name: "web-7d9f-abcde".into(),
            pod_ip: "10.0.0.1".into(),
            pod_namespace: ns.map(String::from),
            node_name: "node-a".into(),
            workload_kind: kind.map(String::from),
            workload_name: name.map(String::from),
            ..Default::default()
        }
    }

    fn containers() -> serde_json::Value {
        json!([
            {"name": "migrate", "kind": "init", "image": "ghcr.io/org/migrate:v2",
             "digest": D2, "digest_kind": "config", "repository": "ghcr.io/org/migrate", "tag": "v2"},
            {"name": "app", "kind": "regular", "image": "nginx:1.27",
             "image_id": format!("docker.io/library/nginx@{D}"),
             "digest": D, "digest_kind": "repo", "repository": "docker.io/library/nginx", "tag": "1.27",
             "security_context": {"runAsNonRoot": true, "capabilitiesDrop": ["ALL", "ALL"],
                "unknownKey": "dropped"}},
            {"name": "sidecar", "kind": "regular", "image": "nginx:stable",
             "digest": D, "digest_kind": "pinned", "tag": "stable"},
            {"name": "debug", "kind": "ephemeral", "image": "busybox"}
        ])
    }

    /// Line breaks (the five YAML/Unicode ones) and other control
    /// characters never enter an image reference, repository or tag: these
    /// are written into generated policy YAML.
    #[test]
    fn image_fields_with_line_breaks_are_refused() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let before = MALFORMED_IMAGE_REF.load(Ordering::Relaxed);
        for sep in ["\n", "\r", "\u{0085}", "\u{2028}", "\u{2029}", "\t"] {
            let inj = format!("evil{sep}---{sep}apiVersion: v1{sep}kind: Secret");
            let list = json!([
                {"name": "a", "kind": "regular", "image": inj.clone(), "digest": D, "digest_kind": "repo"},
                {"name": "b", "kind": "regular", "image": "nginx:1.27", "digest": D2, "digest_kind": "repo",
                 "repository": inj.clone(), "tag": inj.clone()}
            ]);
            let inv = inventory_from_post(&p, Some(&list), None);
            // The container with the bad reference is kept, marked; never
            // missing.
            assert_eq!(inv.containers.len(), 2, "{sep:?}: container dropped");
            let a = inv
                .containers
                .iter()
                .find(|c| c.container_name == "a")
                .unwrap();
            assert_eq!(a.image_ref, MALFORMED_REFERENCE, "{sep:?}");
            assert_eq!(a.image_digest.as_deref(), Some(D));
            // A bad repository or tag is not stored (never looked up).
            let img = inv.images.iter().find(|i| i.digest == D2).unwrap();
            assert!(
                img.repository.is_none() && img.tags.is_empty(),
                "{sep:?}: {img:?}"
            );
        }
        assert!(MALFORMED_IMAGE_REF.load(Ordering::Relaxed) >= before + 6);
        let m = render_malformed_metrics();
        assert!(m.contains("kguardian_image_inventory_malformed_total{field=\"image_ref\"}"));
        assert!(m.contains("kguardian_image_inventory_malformed_total{field=\"repository\"}"));
        // A reference that is only too long is malformed too; one that is
        // absent is not a container image at all.
        let long = json!([{"name": "c", "kind": "regular", "image": "r/".repeat(MAX_IMAGE_REF_LEN), "digest": D, "digest_kind": "repo"},
                          {"name": "d", "kind": "regular", "image": "   ", "digest": D2, "digest_kind": "repo"}]);
        let inv = inventory_from_post(&p, Some(&long), None);
        assert_eq!(inv.containers.len(), 1);
        assert_eq!(inv.containers[0].image_ref, MALFORMED_REFERENCE);
    }

    #[test]
    fn older_controller_without_the_field_writes_nothing() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        assert_eq!(inventory_from_post(&p, None, None), Inventory::default());
        assert_eq!(
            inventory_from_post(&p, Some(&serde_json::Value::Null), None),
            Inventory::default()
        );
    }

    #[test]
    fn pod_spec_body_parses_with_and_without_the_new_fields() {
        let base = json!({"pod_name": "web-1", "pod_ip": "10.0.0.1", "pod_namespace": "prod",
            "pod_obj": null, "time_stamp": "2026-09-26T00:00:00", "node_name": "n",
            "is_dead": false, "pod_identity": null, "workload_selector_labels": null});
        let old: PodSpecIngest = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(old.pod.pod_name, "web-1");
        assert!(old.containers.is_none() && old.pod_security.is_none());

        let mut new = base;
        new["containers"] = containers();
        new["pod_security"] = json!({"serviceAccountName": "web", "hostPID": true});
        new["host_network"] = json!(false);
        let new: PodSpecIngest = serde_json::from_value(new).unwrap();
        assert_eq!(new.pod.host_network, Some(false));
        assert!(new.containers.is_some());

        // A malformed field must not fail the body: it is a Value here.
        let mut bad: serde_json::Value = serde_json::to_value(json!({"pod_name": "w",
            "pod_ip": "10.0.0.1", "time_stamp": "2026-09-26T00:00:00", "node_name": "n",
            "is_dead": false}))
        .unwrap();
        bad["containers"] = json!("not a list");
        bad["pod_security"] = json!(42);
        let bad: PodSpecIngest = serde_json::from_value(bad).unwrap();
        let inv = inventory_from_post(&bad.pod, bad.containers.as_ref(), bad.pod_security.as_ref());
        assert_eq!(inv, Inventory::default());
    }

    #[test]
    fn rows_are_keyed_on_the_resolved_workload() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let ps = json!({"serviceAccountName": "web", "automountServiceAccountToken": false,
            "hostPID": false, "securityContext": {"runAsNonRoot": true, "extra": 1}});
        let inv = inventory_from_post(&p, Some(&containers()), Some(&ps));
        assert_eq!(inv.containers.len(), 4);
        for c in &inv.containers {
            assert_eq!(
                (
                    c.namespace.as_str(),
                    c.workload_kind.as_str(),
                    c.workload_name.as_str()
                ),
                ("prod", "Deployment", "web")
            );
            assert_eq!(c.cluster_id, "primary");
            assert_eq!(c.last_pod_name, "web-7d9f-abcde");
            assert_eq!(
                c.pod_security,
                json!({"serviceAccountName": "web", "automountServiceAccountToken": false,
                    "hostPID": false, "securityContext": {"runAsNonRoot": true}})
            );
        }
        let app = &inv.containers[1];
        assert_eq!(app.container_kind, "regular");
        assert_eq!(app.image_digest.as_deref(), Some(D));
        // Typed, deduplicated, unknown keys gone.
        assert_eq!(
            app.security_context,
            json!({"runAsNonRoot": true, "capabilitiesDrop": ["ALL"]})
        );
        let dbg = &inv.containers[3];
        assert_eq!(dbg.container_kind, "ephemeral");
        assert_eq!(dbg.image_digest, None);
        assert_eq!(dbg.security_context, json!({}));
    }

    #[test]
    fn images_merge_per_digest_and_prefer_the_repo_kind() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let inv = inventory_from_post(&p, Some(&containers()), None);
        assert_eq!(inv.images.len(), 2);
        let nginx = inv.images.iter().find(|i| i.digest == D).unwrap();
        assert_eq!(nginx.digest_kind, "repo");
        assert_eq!(nginx.repository.as_deref(), Some("docker.io/library/nginx"));
        assert_eq!(nginx.tags, vec!["1.27".to_string(), "stable".to_string()]);
        let migrate = inv.images.iter().find(|i| i.digest == D2).unwrap();
        assert_eq!(migrate.digest_kind, "config");
    }

    #[test]
    fn bare_pod_is_keyed_as_pod_and_no_namespace_writes_nothing() {
        let p = pod(Some("prod"), None, None);
        let inv = inventory_from_post(&p, Some(&containers()), None);
        assert_eq!(inv.containers[0].workload_kind, "Pod");
        assert_eq!(inv.containers[0].workload_name, "web-7d9f-abcde");

        let p = pod(None, Some("Deployment"), Some("web"));
        assert_eq!(
            inventory_from_post(&p, Some(&containers()), None),
            Inventory::default()
        );
    }

    #[test]
    fn invalid_entries_are_dropped_not_fatal() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let list = json!([
            {"name": "ok", "kind": "regular", "image": "a", "digest": D, "digest_kind": "repo"},
            {"name": "", "kind": "regular", "image": "a"},
            {"name": "k", "kind": "sidecar", "image": "a"},
            {"name": "noimg", "kind": "regular"},
            {"name": "baddigest", "kind": "regular", "image": "a",
             "digest": "sha256:XYZ", "digest_kind": "repo"},
            {"name": "badkind", "kind": "regular", "image": "a",
             "digest": D2, "digest_kind": "mystery"},
            {"name": "ok", "kind": "regular", "image": "duplicate-name"},
            {"name": "x".repeat(300), "kind": "regular", "image": "a"},
            "not an object",
            {"name": "caps", "kind": "regular", "image": "a",
             "security_context": {"capabilitiesAdd": ["NET_ADMIN", "", "Y".repeat(200)]}}
        ]);
        let inv = inventory_from_post(&p, Some(&list), Some(&json!("garbage")));
        let names: Vec<_> = inv
            .containers
            .iter()
            .map(|c| c.container_name.as_str())
            .collect();
        assert_eq!(names, vec!["ok", "baddigest", "badkind", "caps"]);
        assert_eq!(inv.containers[1].image_digest, None);
        assert_eq!(inv.containers[2].image_digest, None);
        assert_eq!(inv.images.len(), 1);
        assert_eq!(
            inv.containers[3].security_context,
            json!({"capabilitiesAdd": ["NET_ADMIN"]})
        );
        assert_eq!(inv.containers[0].pod_security, json!({}));
    }

    #[test]
    fn container_count_is_capped() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let list: Vec<_> = (0..200)
            .map(|i| json!({"name": format!("c{i}"), "kind": "regular", "image": "a"}))
            .collect();
        let inv = inventory_from_post(&p, Some(&json!(list)), None);
        assert_eq!(inv.containers.len(), MAX_CONTAINERS_PER_POD);
    }

    #[test]
    fn tags_are_capped_per_post() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let list: Vec<_> = (0..100)
            .map(|i| {
                json!({"name": format!("c{i}"), "kind": "regular", "image": "a",
                    "digest": D, "digest_kind": "repo", "tag": format!("t{i:03}")})
            })
            .collect();
        let inv = inventory_from_post(&p, Some(&json!(list)), None);
        assert_eq!(inv.images[0].tags.len(), MAX_TAGS_PER_IMAGE as usize);
    }

    #[test]
    fn digest_validation() {
        assert!(is_valid_digest(D));
        assert!(!is_valid_digest("sha256:abc"));
        assert!(!is_valid_digest(&D.to_uppercase()));
        assert!(!is_valid_digest("latest"));
    }

    #[test]
    fn images_limit_is_clamped() {
        assert_eq!(clamp_images_limit(None), IMAGES_DEFAULT_LIMIT);
        assert_eq!(clamp_images_limit(Some(0)), 1);
        assert_eq!(clamp_images_limit(Some(-3)), 1);
        assert_eq!(clamp_images_limit(Some(10_000)), IMAGES_MAX_LIMIT);
        assert_eq!(clamp_images_limit(Some(42)), 42);
    }

    #[test]
    fn container_state_is_validated() {
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let list = json!([
            {"name": "a", "kind": "regular", "image": "a", "state": " Running "},
            {"name": "b", "kind": "regular", "image": "b", "state": "exploded",
             "state_reason": "Boom"},
            {"name": "c", "kind": "regular", "image": "c", "state": "waiting",
             "state_reason": "x".repeat(300)},
            {"name": "d", "kind": "regular", "image": "d"}
        ]);
        let inv = inventory_from_post(&p, Some(&list), None);
        let st: Vec<_> = inv
            .containers
            .iter()
            .map(|c| (c.state.as_deref(), c.state_reason.as_deref()))
            .collect();
        assert_eq!(
            st,
            vec![
                (Some("running"), None),
                // Unknown state: dropped, and its reason with it.
                (None, None),
                // Oversized reason: dropped, state kept.
                (Some("waiting"), None),
                // Older controller: no state.
                (None, None),
            ]
        );
    }

    #[test]
    fn running_window_parses_and_clamps() {
        assert_eq!(parse_running_window(None), DEFAULT_RUNNING_WINDOW_SECS);
        assert_eq!(parse_running_window(Some("900")), 900);
        assert_eq!(parse_running_window(Some(" 1800 ")), 1800);
        assert_eq!(parse_running_window(Some("10")), MIN_RUNNING_WINDOW_SECS);
        assert_eq!(parse_running_window(Some("0")), MIN_RUNNING_WINDOW_SECS);
        assert_eq!(
            parse_running_window(Some("99999999")),
            MAX_RUNNING_WINDOW_SECS
        );
        assert_eq!(
            parse_running_window(Some("soon")),
            DEFAULT_RUNNING_WINDOW_SECS
        );
    }

    #[test]
    fn every_read_uses_the_same_running_predicate() {
        let pred = running_sql!("$N");
        assert!(pred.contains("NOT pd.is_dead"));
        for (sql, w) in [
            (IMAGES_LIST_SQL, "$5"),
            (IMAGE_USERS_SQL, "$2"),
            (WORKLOAD_CONTAINERS_SQL, "$4"),
        ] {
            assert!(sql.contains(&pred.replace("$N", w)), "{sql}");
        }
    }

    fn digest_row(container: &str, digest: &str, running: bool) -> ContainerDigestRow {
        ContainerDigestRow {
            cluster_id: "primary".into(),
            container_name: container.into(),
            container_kind: "regular".into(),
            image_digest: digest.into(),
            image_ref: "r:1".into(),
            security_context: json!({}),
            pod_security: json!({}),
            last_pod_name: None,
            first_seen: NaiveDateTime::default(),
            last_seen: NaiveDateTime::default(),
            state: Some("running".into()),
            state_reason: None,
            ran_as_init: false,
            running,
        }
    }

    #[test]
    fn grouping_flags_mixed_digests_and_splits_previous() {
        let groups = group_containers(vec![
            digest_row("app", D, true),
            digest_row("app", D2, true),
            digest_row("app", "sha256:old", false),
            digest_row("side", D, true),
            digest_row("gone", D2, false),
        ]);
        assert_eq!(groups.len(), 3);
        assert!(groups[0].mixed_digests);
        assert_eq!(groups[0].digests.len(), 2);
        assert_eq!(groups[0].previous_digests.len(), 1);
        assert!(!groups[1].mixed_digests);
        assert_eq!(groups[1].digests.len(), 1);
        // A container nothing runs any more: no current digests, not mixed.
        assert!(!groups[2].mixed_digests);
        assert!(groups[2].digests.is_empty());
        assert_eq!(groups[2].previous_digests.len(), 1);
    }

    // ---- live database ------------------------------------------------
    //
    // Same gate as the other live tests: ignored by default, run by CI's
    // `cargo test -- --ignored` step against a real Postgres with the
    // shipped migrations applied.

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel::connection::SimpleConnection;
        use diesel_migrations::MigrationHarness;
        let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
            panic!("set KG_TEST_DATABASE_URL to run this test");
        };
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("apply the shipped migrations");
        conn.batch_execute("TRUNCATE images, workload_containers")
            .expect("reset the inventory tables");
        conn
    }

    fn age(conn: &mut PgConnection, table: &str, col: &str, secs: i64) {
        use diesel::connection::SimpleConnection;
        conn.batch_execute(&format!(
            "UPDATE {table} SET {col} = timezone('UTC', NOW()) - INTERVAL '{secs} seconds'"
        ))
        .expect("age rows");
    }

    fn app_group(conn: &mut PgConnection) -> ContainerImages {
        workload_containers(conn, "prod", "Deployment", "web")
            .unwrap()
            .containers
            .into_iter()
            .find(|c| c.container_name == "app")
            .expect("app container")
    }

    fn row_count(conn: &mut PgConnection) -> i64 {
        use schema::workload_containers::dsl as wc;
        wc::workload_containers
            .count()
            .get_result(conn)
            .expect("count")
    }

    /// A container whose reference was malformed is stored and listed
    /// with its workload (as malformed_reference), never missing.
    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_keeps_malformed_reference_containers() {
        let mut conn = live_conn();
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let list = json!([{"name": "app", "kind": "regular", "image": "evil\n---\nkind: Secret",
            "digest": D, "digest_kind": "repo", "state": "running"}]);
        let inv = inventory_from_post(&p, Some(&list), None);
        assert!(upsert_inventory(&mut conn, &inv).unwrap() > 0);
        let group = workload_containers(&mut conn, "prod", "Deployment", "web").unwrap();
        let app = group
            .containers
            .iter()
            .find(|c| c.container_name == "app")
            .expect("container missing");
        assert_eq!(app.digests[0].digest, D);
        let raw = serde_json::to_string(&group).unwrap();
        assert!(
            raw.contains(MALFORMED_REFERENCE) && !raw.contains("kind: Secret"),
            "{raw}"
        );
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_upsert_is_idempotent_and_merges() {
        let mut conn = live_conn();
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let inv = inventory_from_post(&p, Some(&containers()), None);

        // First post writes 2 images + 3 container rows. `debug` has no
        // digest, so it creates no row.
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 5);
        assert_eq!(row_count(&mut conn), 3);
        // The identical re-post (every resync does this) writes nothing.
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 0);
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 0);

        let page = list_images(&mut conn, None, None, None, 10).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next_after, None);
        let nginx = page.items.iter().find(|i| i.digest == D).unwrap();
        assert_eq!(nginx.running_containers, 2);
        assert_eq!(nginx.tags, vec!["1.27", "stable"]);
        assert_eq!(nginx.digest_kind, "repo");

        // A new tag for a known digest merges into the image row; the
        // container row for (app, D) is updated in place (new ref).
        let more = json!([{"name": "app", "kind": "regular", "image": "nginx:mainline",
            "digest": D, "digest_kind": "repo", "tag": "mainline"}]);
        let inv2 = inventory_from_post(&p, Some(&more), None);
        assert_eq!(upsert_inventory(&mut conn, &inv2).unwrap(), 2);
        let d = image_detail(&mut conn, D).unwrap().unwrap();
        assert_eq!(d.image.tags, vec!["1.27", "mainline", "stable"]);
        assert_eq!(row_count(&mut conn), 3);

        // A restart with no digest yet creates no phantom row and keeps
        // the known digest for the same ref alive...
        age(
            &mut conn,
            "workload_containers",
            "last_seen",
            REFRESH_SECS * 2,
        );
        let pending = json!([{"name": "app", "kind": "regular", "image": "nginx:mainline"}]);
        let inv3 = inventory_from_post(&p, Some(&pending), None);
        // 2 = the pod's name released from its digest row (a digest-less
        // report means it runs nothing there right now) + ref_seen_at on
        // the most recent digest row for the ref.
        assert_eq!(upsert_inventory(&mut conn, &inv3).unwrap(), 2);
        assert_eq!(row_count(&mut conn), 3);
        let app = app_group(&mut conn);
        assert_eq!(app.digests.len(), 1);
        assert_eq!(app.digests[0].digest, D);
        // ...while a new ref with no digest yet writes nothing at all.
        let rollout = json!([{"name": "app", "kind": "regular", "image": "nginx:1.28"}]);
        let inv4 = inventory_from_post(&p, Some(&rollout), None);
        assert_eq!(upsert_inventory(&mut conn, &inv4).unwrap(), 0);
        assert_eq!(row_count(&mut conn), 3);

        // A stale row is refreshed even when nothing changed.
        age(
            &mut conn,
            "workload_containers",
            "last_seen",
            REFRESH_SECS * 2,
        );
        age(&mut conn, "images", "last_seen", REFRESH_SECS * 2);
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 5);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_mixed_digest_rollout() {
        let mut conn = live_conn();
        let post = |conn: &mut PgConnection, pod_name: &str, image: &str, digest: &str| {
            let mut p = pod(Some("prod"), Some("Deployment"), Some("web"));
            p.pod_name = pod_name.to_string();
            let list = json!([{"name": "app", "kind": "regular", "image": image,
                "digest": digest, "digest_kind": "repo", "repository": "docker.io/library/nginx"}]);
            upsert_inventory(conn, &inventory_from_post(&p, Some(&list), None)).unwrap()
        };

        // Steady state on D.
        post(&mut conn, "web-old-1", "nginx:1.27", D);
        let app = app_group(&mut conn);
        assert!(!app.mixed_digests);
        assert_eq!(app.digests.len(), 1);

        // Rollout: a new pod on D2 while old pods still run D. Old and new
        // posts interleave; neither overwrites the other.
        post(&mut conn, "web-new-1", "nginx:1.28", D2);
        post(&mut conn, "web-old-2", "nginx:1.27", D);
        post(&mut conn, "web-new-2", "nginx:1.28", D2);
        assert_eq!(row_count(&mut conn), 2);
        let app = app_group(&mut conn);
        assert!(app.mixed_digests, "two digests running at once");
        let mut running: Vec<_> = app.digests.iter().map(|d| d.digest.as_str()).collect();
        running.sort();
        assert_eq!(running, vec![D, D2]);
        let refs: BTreeSet<_> = app.digests.iter().map(|d| d.image_ref.as_str()).collect();
        assert_eq!(refs, BTreeSet::from(["nginx:1.27", "nginx:1.28"]));
        // Both images read as in use.
        for d in [D, D2] {
            let detail = image_detail(&mut conn, d).unwrap().unwrap();
            assert_eq!(detail.workloads.len(), 1);
            assert!(detail.workloads[0].running);
        }

        // Rollout done: the old pods are gone, so nothing refreshes D.
        // Once its row falls out of the running window it moves to
        // previousDigests and the container is no longer mixed.
        use diesel::connection::SimpleConnection;
        conn.batch_execute(&format!(
            "UPDATE workload_containers SET last_seen = timezone('UTC', NOW()) \
               - INTERVAL '{} seconds' WHERE image_digest = '{D}'",
            running_window_secs() + 60
        ))
        .unwrap();
        post(&mut conn, "web-new-1", "nginx:1.28", D2);
        let app = app_group(&mut conn);
        assert!(!app.mixed_digests);
        assert_eq!(app.digests.len(), 1);
        assert_eq!(app.digests[0].digest, D2);
        assert_eq!(app.previous_digests.len(), 1);
        assert_eq!(app.previous_digests[0].digest, D);
        let old = list_images(&mut conn, None, None, None, 10)
            .unwrap()
            .items
            .into_iter()
            .find(|i| i.digest == D)
            .unwrap();
        assert_eq!(old.running_containers, 0);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_live_pod_keeps_its_digest_running_and_dead_pod_drops_out() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        let reset = "DELETE FROM pod_details WHERE pod_name LIKE 'inv-test-%'";
        conn.batch_execute(reset).unwrap();
        // A CrashLoopBackOff pod: live in pod_details, not dead.
        conn.batch_execute(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead) \
             VALUES ('inv-test-crash', '10.9.9.9', 'prod', timezone('UTC', NOW()), 'n', false)",
        )
        .unwrap();
        let post = |conn: &mut PgConnection, digest: &str, image: &str| {
            let mut p = pod(Some("prod"), Some("Deployment"), Some("web"));
            p.pod_name = "inv-test-crash".into();
            let list = json!([{"name": "app", "kind": "regular", "image": image,
                "digest": digest, "digest_kind": "repo"}]);
            upsert_inventory(conn, &inventory_from_post(&p, Some(&list), None)).unwrap()
        };
        let age_past_window = |conn: &mut PgConnection| {
            conn.batch_execute(&format!(
                "UPDATE workload_containers SET last_seen = timezone('UTC', NOW()) \
                   - INTERVAL '{} seconds'",
                running_window_secs() + 60
            ))
            .unwrap();
        };
        let running_count = |conn: &mut PgConnection, d: &str| {
            list_images(conn, None, None, None, 10)
                .unwrap()
                .items
                .into_iter()
                .find(|i| i.digest == d)
                .map(|i| i.running_containers)
                .unwrap_or(0)
        };

        post(&mut conn, D, "nginx:1.27");
        // Its re-posts stopped (say an older controller that only re-posts
        // Ready pods), so the row is well past the freshness window...
        age_past_window(&mut conn);
        // ...but the pod is live, so the digest still reads as running.
        let app = app_group(&mut conn);
        assert_eq!(app.digests.len(), 1, "live pod keeps its digest running");
        assert_eq!(app.digests[0].digest, D);
        assert_eq!(running_count(&mut conn, D), 1);
        assert!(image_detail(&mut conn, D).unwrap().unwrap().workloads[0].running);

        // Marked dead: it drops out.
        conn.batch_execute(
            "UPDATE pod_details SET is_dead = true WHERE pod_name = 'inv-test-crash'",
        )
        .unwrap();
        let app = app_group(&mut conn);
        assert!(app.digests.is_empty());
        assert_eq!(app.previous_digests[0].digest, D);
        assert_eq!(running_count(&mut conn, D), 0);
        assert!(!image_detail(&mut conn, D).unwrap().unwrap().workloads[0].running);

        // Revived, then updated in place to D2: the backstop must not keep
        // the replaced digest running once the pod reports the new one.
        conn.batch_execute(
            "UPDATE pod_details SET is_dead = false WHERE pod_name = 'inv-test-crash'",
        )
        .unwrap();
        post(&mut conn, D2, "nginx:1.28");
        let app = app_group(&mut conn);
        assert_eq!(
            app.digests
                .iter()
                .map(|d| d.digest.as_str())
                .collect::<Vec<_>>(),
            vec![D2]
        );
        assert_eq!(app.previous_digests[0].digest, D);
        assert_eq!(app.previous_digests[0].last_pod_name, None);

        conn.batch_execute(reset).unwrap();
    }

    fn post_state(conn: &mut PgConnection, pod_name: &str, containers: serde_json::Value) -> usize {
        let mut p = pod(Some("prod"), Some("Deployment"), Some("web"));
        p.pod_name = pod_name.to_string();
        upsert_inventory(conn, &inventory_from_post(&p, Some(&containers), None)).unwrap()
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_image_pull_backoff_never_revives_old_digests() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        let reset = "DELETE FROM pod_details WHERE pod_name LIKE 'inv-test-%'";
        conn.batch_execute(reset).unwrap();
        // Three historical digests of app:latest, each run by a pod long gone.
        let digests: Vec<String> = (1..=3u8).map(|i| format!("sha256:{:064x}", i)).collect();
        for (i, d) in digests.iter().enumerate() {
            post_state(
                &mut conn,
                &format!("web-old-{i}"),
                json!([{"name": "app", "kind": "regular", "image": "app:latest",
                    "digest": d, "digest_kind": "repo", "state": "running"}]),
            );
            // Age each one, oldest first, past the window.
            conn.batch_execute(&format!(
                "UPDATE workload_containers SET last_seen = timezone('UTC', NOW()) \
                   - INTERVAL '{} seconds' WHERE image_digest = '{d}'",
                running_window_secs() + 600 - (i as i64) * 60
            ))
            .unwrap();
        }
        // A live pod stuck in ImagePullBackOff on the same mutable tag: ref
        // only, no digest.
        conn.batch_execute(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead) \
             VALUES ('inv-test-pull', '10.9.9.8', 'prod', timezone('UTC', NOW()), 'n', false)",
        )
        .unwrap();
        let pulling = json!([{"name": "app", "kind": "regular", "image": "app:latest",
            "state": "waiting", "state_reason": "ImagePullBackOff"}]);
        // Touches exactly one row (the most recent digest's ref_seen_at)...
        assert_eq!(post_state(&mut conn, "inv-test-pull", pulling.clone()), 1);
        // ...and a repeat inside the refresh period touches none.
        assert_eq!(post_state(&mut conn, "inv-test-pull", pulling), 0);

        let app = app_group(&mut conn);
        assert!(app.digests.is_empty(), "no old digest may read as running");
        assert_eq!(app.previous_digests.len(), 3);
        for d in &digests {
            assert_eq!(running_count_of(&mut conn, d), 0, "{d}");
        }
        // The stuck pod never lends its name to the live-pod backstop.
        assert!(app
            .previous_digests
            .iter()
            .all(|d| d.last_pod_name.as_deref() != Some("inv-test-pull")));
        // Only the most recent digest is kept alive for retention.
        #[derive(QueryableByName)]
        struct R {
            #[diesel(sql_type = Text)]
            image_digest: String,
        }
        let kept: Vec<R> =
            sql_query("SELECT image_digest FROM workload_containers WHERE ref_seen_at IS NOT NULL")
                .load(&mut conn)
                .unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].image_digest, digests[2]);
        conn.batch_execute(reset).unwrap();
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_same_name_pod_stuck_pulling_releases_its_old_digest() {
        use diesel::connection::SimpleConnection;
        let mut conn = live_conn();
        let reset = "DELETE FROM pod_details WHERE pod_name LIKE 'inv-test-%'";
        conn.batch_execute(reset).unwrap();
        // StatefulSet pod web-0, live throughout (same name before and after).
        conn.batch_execute(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, time_stamp, node_name, is_dead) \
             VALUES ('inv-test-web-0', '10.9.9.7', 'prod', timezone('UTC', NOW()), 'n', false)",
        )
        .unwrap();
        let d = |i: u8| format!("sha256:{:064x}", i);
        // web-0 runs D1 in `app` (StatefulSet recreate case), D2 in `side`
        // (in-place patch case) and D3 under a mutable tag in `tagged`.
        post_state(
            &mut conn,
            "inv-test-web-0",
            json!([
                {"name": "app", "kind": "regular", "image": "app:1", "digest": d(1),
                 "digest_kind": "repo", "state": "running"},
                {"name": "side", "kind": "regular", "image": "side:1", "digest": d(2),
                 "digest_kind": "repo", "state": "running"},
                {"name": "tagged", "kind": "regular", "image": "t:latest", "digest": d(3),
                 "digest_kind": "repo", "state": "running"}
            ]),
        );
        conn.batch_execute(&format!(
            "UPDATE workload_containers SET last_seen = timezone('UTC', NOW()) \
               - INTERVAL '{} seconds'",
            running_window_secs() + 60
        ))
        .unwrap();
        // Past the window, the live pod still holds all three running.
        for i in 1..=3 {
            assert_eq!(running_count_of(&mut conn, &d(i)), 1);
        }

        // Same name, no digests any more:
        // - app: web-0 recreated on a new ref, stuck in ImagePullBackOff;
        // - side: an in-place image patch to a ref that fails to pull;
        // - tagged: recreated on the SAME mutable ref, stuck pulling.
        post_state(
            &mut conn,
            "inv-test-web-0",
            json!([
                {"name": "app", "kind": "regular", "image": "app:2",
                 "state": "waiting", "state_reason": "ImagePullBackOff"},
                {"name": "side", "kind": "regular", "image": "side:broken",
                 "state": "waiting", "state_reason": "ErrImagePull"},
                {"name": "tagged", "kind": "regular", "image": "t:latest",
                 "state": "waiting", "state_reason": "ImagePullBackOff"}
            ]),
        );
        for i in 1..=3 {
            assert_eq!(
                running_count_of(&mut conn, &d(i)),
                0,
                "digest {i} must stop reading as running"
            );
        }
        let wc = workload_containers(&mut conn, "prod", "Deployment", "web").unwrap();
        for c in &wc.containers {
            assert!(c.digests.is_empty(), "{}", c.container_name);
            assert!(c.previous_digests.iter().all(|d| d.last_pod_name.is_none()));
        }
        // A repeat of the stuck report writes nothing.
        assert_eq!(
            post_state(
                &mut conn,
                "inv-test-web-0",
                json!([{"name": "app", "kind": "regular", "image": "app:2",
                    "state": "waiting", "state_reason": "ImagePullBackOff"}]),
            ),
            0
        );
        conn.batch_execute(reset).unwrap();
    }

    fn running_count_of(conn: &mut PgConnection, d: &str) -> i64 {
        list_images(conn, None, None, None, 100)
            .unwrap()
            .items
            .into_iter()
            .find(|i| i.digest == d)
            .map(|i| i.running_containers)
            .unwrap_or(0)
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_container_state_decides_running() {
        let mut conn = live_conn();
        let d = |i: u8| format!("sha256:{:064x}", i);
        post_state(
            &mut conn,
            "web-1",
            json!([
                {"name": "migrate", "kind": "init", "image": "m:1", "digest": d(1),
                 "digest_kind": "repo", "state": "terminated", "state_reason": "Completed"},
                {"name": "app", "kind": "regular", "image": "a:1", "digest": d(2),
                 "digest_kind": "repo", "state": "running"},
                {"name": "crash", "kind": "regular", "image": "c:1", "digest": d(3),
                 "digest_kind": "repo", "state": "waiting", "state_reason": "CrashLoopBackOff"},
                {"name": "pinned", "kind": "regular", "image": format!("p@{}", d(4)),
                 "digest": d(4), "digest_kind": "pinned", "state": "waiting",
                 "state_reason": "ContainerCreating"}
            ]),
        );
        let wc = workload_containers(&mut conn, "prod", "Deployment", "web").unwrap();
        let by = |n: &str| {
            wc.containers
                .iter()
                .find(|c| c.container_name == n)
                .unwrap()
                .clone()
        };
        let migrate = by("migrate");
        assert!(
            migrate.digests.is_empty(),
            "a completed init container is not running"
        );
        assert!(migrate.previous_digests[0].ran_as_init);
        assert_eq!(
            migrate.previous_digests[0].state.as_deref(),
            Some("terminated")
        );
        assert_eq!(
            migrate.previous_digests[0].state_reason.as_deref(),
            Some("Completed")
        );
        assert_eq!(by("app").digests[0].state.as_deref(), Some("running"));
        let crash = by("crash");
        assert_eq!(crash.digests.len(), 1, "crash-looping counts as running");
        assert_eq!(
            crash.digests[0].state_reason.as_deref(),
            Some("CrashLoopBackOff")
        );
        let pinned = by("pinned");
        assert!(
            pinned.digests.is_empty(),
            "a digest that never started is not running"
        );
        assert_eq!(
            pinned.previous_digests[0].state_reason.as_deref(),
            Some("ContainerCreating")
        );
        assert_eq!(running_count_of(&mut conn, &d(1)), 0);
        assert_eq!(running_count_of(&mut conn, &d(2)), 1);
        assert_eq!(running_count_of(&mut conn, &d(3)), 1);
        assert_eq!(running_count_of(&mut conn, &d(4)), 0);
        let init_user = &image_detail(&mut conn, &d(1)).unwrap().unwrap().workloads[0];
        assert!(init_user.ran_as_init && !init_user.running);

        // The pinned container starts: the same digest row flips to running.
        assert_eq!(
            post_state(
                &mut conn,
                "web-1",
                json!([{"name": "pinned", "kind": "regular", "image": format!("p@{}", d(4)),
                    "digest": d(4), "digest_kind": "repo", "state": "running"}]),
            ),
            2 // image row (pinned -> repo) + container row (state changed)
        );
        assert_eq!(running_count_of(&mut conn, &d(4)), 1);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_reads_are_bounded_and_paginated() {
        let mut conn = live_conn();
        // 5 distinct digests across two namespaces.
        for i in 0..5u8 {
            let digest = format!("sha256:{:064x}", i as u128 + 1);
            let ns = if i % 2 == 0 { "even" } else { "odd" };
            let p = pod(Some(ns), Some("Deployment"), Some(&format!("w{i}")));
            let list = json!([{"name": "c", "kind": "regular", "image": format!("r/i{i}:1"),
                "digest": digest, "digest_kind": "repo", "repository": format!("docker.io/r/i{i}"),
                "tag": "1"}]);
            upsert_inventory(&mut conn, &inventory_from_post(&p, Some(&list), None)).unwrap();
        }
        let p1 = list_images(&mut conn, None, None, None, 2).unwrap();
        assert_eq!(p1.items.len(), 2);
        let after = p1.next_after.clone().unwrap();
        assert_eq!(after, p1.items[1].digest);
        let p2 = list_images(&mut conn, None, None, Some(&after), 2).unwrap();
        assert_eq!(p2.items.len(), 2);
        assert!(p2.items[0].digest > after);
        let p3 = list_images(&mut conn, None, None, p2.next_after.as_deref(), 2).unwrap();
        assert_eq!(p3.items.len(), 1);
        assert_eq!(p3.next_after, None);

        let even = list_images(&mut conn, Some("even"), None, None, 100).unwrap();
        assert_eq!(even.items.len(), 3);
        let repo = list_images(&mut conn, None, Some("docker.io/r/i1"), None, 100).unwrap();
        assert_eq!(repo.items.len(), 1);

        assert!(image_detail(&mut conn, D).unwrap().is_none());
        let d = image_detail(&mut conn, &format!("sha256:{:064x}", 1))
            .unwrap()
            .unwrap();
        assert_eq!(d.workloads.len(), 1);
        assert!(!d.truncated);
        assert_eq!(d.workloads[0].workload_name, "w0");

        let none = workload_containers(&mut conn, "prod", "Deployment", "missing").unwrap();
        assert!(none.containers.is_empty());
    }
}
