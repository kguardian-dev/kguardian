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
//! - `images`: one row per digest. Growth is O(distinct running images).
//! - `workload_containers`: one row per (cluster, namespace, kind, name,
//!   container). A workload is keyed exactly as `workload_syscalls` and
//!   the SeccompProfile `workloadRef` are — the controller's owner-ref
//!   resolution posted as `workload_kind` / `workload_name` — and a pod
//!   with no owner is keyed `("Pod", pod_name)`.
//! - Retention (`retention.rs`, "Image inventory") prunes rows not
//!   refreshed within `IMAGE_INVENTORY_RETENTION_DAYS`.
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
use diesel::sql_types::{Array, BigInt, Jsonb, Nullable, Text, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
}

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
        let Some(image_ref) = bounded(c.image, MAX_IMAGE_REF_LEN) else {
            continue;
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
                let repository = bounded(c.repository, MAX_REPOSITORY_LEN);
                let tag = bounded(c.tag, MAX_TAG_LEN);
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
        out.containers.push(ContainerRow {
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
INSERT INTO images (digest, cluster_id, repository, tags, digest_kind, first_seen, last_seen) \
VALUES ($1, $2, $3, $4, $5, timezone('UTC', NOW()), timezone('UTC', NOW())) \
ON CONFLICT (digest) DO UPDATE SET \
    cluster_id = EXCLUDED.cluster_id, \
    repository = COALESCE(images.repository, EXCLUDED.repository), \
    tags = (SELECT COALESCE(array_agg(t ORDER BY t), '{}'::text[]) FROM ( \
        SELECT t FROM (SELECT DISTINCT unnest(images.tags || EXCLUDED.tags) AS t) d \
        ORDER BY (t = ANY(images.tags)) DESC, t LIMIT $6) s), \
    digest_kind = CASE \
        WHEN EXCLUDED.digest_kind = 'repo' OR images.digest_kind = 'repo' THEN 'repo' \
        WHEN EXCLUDED.digest_kind = 'config' OR images.digest_kind = 'config' THEN 'config' \
        ELSE images.digest_kind END, \
    last_seen = GREATEST(images.last_seen, EXCLUDED.last_seen) \
WHERE images.last_seen < EXCLUDED.last_seen - make_interval(secs => $7) \
   OR (NOT (EXCLUDED.tags <@ images.tags) AND cardinality(images.tags) < $6) \
   OR (images.repository IS NULL AND EXCLUDED.repository IS NOT NULL) \
   OR (images.digest_kind <> 'repo' AND EXCLUDED.digest_kind = 'repo') \
   OR (images.digest_kind = 'pinned' AND EXCLUDED.digest_kind = 'config')";

/// Upsert one workload container.
///
/// `image_digest`: a re-post with no digest (the replacement pod is still
/// pulling) keeps the stored digest as long as the image reference is
/// unchanged, so a restart does not blank a known digest. A changed
/// reference takes the new value, NULL included — the old digest no
/// longer describes the container.
///
/// Last writer wins across replicas. Mid-rollout, old and new pods of one
/// workload both post, so the row follows whichever posted last until
/// the rollout completes; that is the cost of the one-row-per-container
/// key.
pub(crate) const CONTAINER_UPSERT_SQL: &str = "\
INSERT INTO workload_containers (cluster_id, pod_namespace, workload_kind, workload_name, \
    container_name, container_kind, image_ref, image_digest, security_context, pod_security, \
    last_pod_name, first_seen, updated_at) \
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
    timezone('UTC', NOW()), timezone('UTC', NOW())) \
ON CONFLICT (cluster_id, pod_namespace, workload_kind, workload_name, container_name) \
DO UPDATE SET \
    container_kind = EXCLUDED.container_kind, \
    image_ref = EXCLUDED.image_ref, \
    image_digest = CASE \
        WHEN EXCLUDED.image_digest IS NULL AND EXCLUDED.image_ref = workload_containers.image_ref \
        THEN workload_containers.image_digest \
        ELSE EXCLUDED.image_digest END, \
    security_context = EXCLUDED.security_context, \
    pod_security = EXCLUDED.pod_security, \
    last_pod_name = EXCLUDED.last_pod_name, \
    updated_at = EXCLUDED.updated_at \
WHERE workload_containers.updated_at < EXCLUDED.updated_at - make_interval(secs => $12) \
   OR workload_containers.container_kind IS DISTINCT FROM EXCLUDED.container_kind \
   OR workload_containers.image_ref IS DISTINCT FROM EXCLUDED.image_ref \
   OR (EXCLUDED.image_digest IS NOT NULL \
       AND workload_containers.image_digest IS DISTINCT FROM EXCLUDED.image_digest) \
   OR workload_containers.security_context IS DISTINCT FROM EXCLUDED.security_context \
   OR workload_containers.pod_security IS DISTINCT FROM EXCLUDED.pod_security";

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
                .bind::<Text, _>(DEFAULT_CLUSTER_ID)
                .bind::<Nullable<Text>, _>(img.repository.as_deref())
                .bind::<Array<Text>, _>(&img.tags)
                .bind::<Text, _>(&img.digest_kind)
                .bind::<diesel::sql_types::Integer, _>(MAX_TAGS_PER_IMAGE)
                .bind::<diesel::sql_types::Double, _>(REFRESH_SECS as f64)
                .execute(conn)?;
        }
        for c in &inv.containers {
            n += sql_query(CONTAINER_UPSERT_SQL)
                .bind::<Text, _>(&c.cluster_id)
                .bind::<Text, _>(&c.namespace)
                .bind::<Text, _>(&c.workload_kind)
                .bind::<Text, _>(&c.workload_name)
                .bind::<Text, _>(&c.container_name)
                .bind::<Text, _>(&c.container_kind)
                .bind::<Text, _>(&c.image_ref)
                .bind::<Nullable<Text>, _>(c.image_digest.as_deref())
                .bind::<Jsonb, _>(&c.security_context)
                .bind::<Jsonb, _>(&c.pod_security)
                .bind::<Text, _>(&c.last_pod_name)
                .bind::<diesel::sql_types::Double, _>(REFRESH_SECS as f64)
                .execute(conn)?;
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
    #[diesel(sql_type = Text)]
    pub cluster_id: String,
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
    /// Workload containers currently recorded as running this digest.
    #[diesel(sql_type = BigInt)]
    pub workload_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImagePage {
    pub items: Vec<ImageSummary>,
    /// Pass as `?after=` for the next page; `null` on the last page.
    pub next_after: Option<String>,
}

const IMAGES_LIST_SQL: &str = "\
SELECT i.digest, i.cluster_id, i.repository, i.tags, i.digest_kind, i.first_seen, i.last_seen, \
    (SELECT count(*) FROM workload_containers wc WHERE wc.image_digest = i.digest) AS workload_count \
FROM images i \
WHERE ($1::text IS NULL OR i.digest > $1) \
  AND ($2::text IS NULL OR EXISTS (SELECT 1 FROM workload_containers wc \
        WHERE wc.image_digest = i.digest AND wc.pod_namespace = $2)) \
  AND ($3::text IS NULL OR i.repository = $3) \
ORDER BY i.digest \
LIMIT $4";

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
        .load(conn)?;
    let next_after = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(|i| i.digest.clone())
    } else {
        None
    };
    Ok(ImagePage { items, next_after })
}

#[get("/images")]
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
#[diesel(table_name = schema::workload_containers)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadContainer {
    pub cluster_id: String,
    #[serde(rename = "namespace")]
    pub pod_namespace: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub container_kind: String,
    pub image_ref: String,
    pub image_digest: Option<String>,
    pub security_context: serde_json::Value,
    pub pod_security: serde_json::Value,
    pub last_pod_name: Option<String>,
    pub first_seen: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = schema::images)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub digest: String,
    pub cluster_id: String,
    pub repository: Option<String>,
    pub tags: Vec<String>,
    pub digest_kind: String,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

/// A workload container that runs an image, without the posture blobs
/// (those are on `GET /workloads/.../containers`).
#[derive(Debug, Clone, Queryable, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageUser {
    pub cluster_id: String,
    pub namespace: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub container_kind: String,
    pub image_ref: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageDetail {
    #[serde(flatten)]
    pub image: Image,
    pub workloads: Vec<ImageUser>,
    /// More than [`IMAGE_WORKLOADS_MAX`] workload containers run it.
    pub truncated: bool,
}

pub fn image_detail(conn: &mut PgConnection, d: &str) -> Result<Option<ImageDetail>, DbError> {
    use schema::images::dsl as im;
    use schema::workload_containers::dsl as wc;
    let Some(image) = im::images
        .find(d)
        .select(Image::as_select())
        .first(conn)
        .optional()?
    else {
        return Ok(None);
    };
    let mut workloads: Vec<ImageUser> = wc::workload_containers
        .filter(wc::image_digest.eq(d))
        .order((
            wc::pod_namespace.asc(),
            wc::workload_kind.asc(),
            wc::workload_name.asc(),
            wc::container_name.asc(),
        ))
        .select((
            wc::cluster_id,
            wc::pod_namespace,
            wc::workload_kind,
            wc::workload_name,
            wc::container_name,
            wc::container_kind,
            wc::image_ref,
            wc::updated_at,
        ))
        .limit(IMAGE_WORKLOADS_MAX + 1)
        .load(conn)?;
    let truncated = workloads.len() as i64 > IMAGE_WORKLOADS_MAX;
    workloads.truncate(IMAGE_WORKLOADS_MAX as usize);
    Ok(Some(ImageDetail {
        image,
        workloads,
        truncated,
    }))
}

#[get("/images/{digest}")]
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadContainers {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub containers: Vec<WorkloadContainer>,
    /// More than [`WORKLOAD_CONTAINERS_MAX`] rows (container names that
    /// changed across versions linger until retention prunes them).
    pub truncated: bool,
}

pub fn workload_containers(
    conn: &mut PgConnection,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<WorkloadContainers, DbError> {
    use schema::workload_containers::dsl as wc;
    let mut rows: Vec<WorkloadContainer> = wc::workload_containers
        .filter(wc::pod_namespace.eq(ns))
        .filter(wc::workload_kind.eq(kind))
        .filter(wc::workload_name.eq(name))
        .order((
            wc::cluster_id.asc(),
            wc::container_kind.asc(),
            wc::container_name.asc(),
        ))
        .select(WorkloadContainer::as_select())
        .limit(WORKLOAD_CONTAINERS_MAX + 1)
        .load(conn)?;
    let truncated = rows.len() as i64 > WORKLOAD_CONTAINERS_MAX;
    rows.truncate(WORKLOAD_CONTAINERS_MAX as usize);
    Ok(WorkloadContainers {
        namespace: ns.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
        containers: rows,
        truncated,
    })
}

#[get("/workloads/{namespace}/{kind}/{name}/containers")]
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

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_database_upsert_is_idempotent_and_merges() {
        let mut conn = live_conn();
        let p = pod(Some("prod"), Some("Deployment"), Some("web"));
        let inv = inventory_from_post(&p, Some(&containers()), None);

        // First post writes 2 images + 4 containers.
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 6);
        // The identical re-post (every resync does this) writes nothing.
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 0);
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 0);

        let page = list_images(&mut conn, None, None, None, 10).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next_after, None);
        let nginx = page.items.iter().find(|i| i.digest == D).unwrap();
        assert_eq!(nginx.workload_count, 2);
        assert_eq!(nginx.tags, vec!["1.27", "stable"]);
        assert_eq!(nginx.digest_kind, "repo");

        // A new tag for a known digest merges into the row.
        let more = json!([{"name": "app", "kind": "regular", "image": "nginx:mainline",
            "digest": D, "digest_kind": "repo", "tag": "mainline"}]);
        let inv2 = inventory_from_post(&p, Some(&more), None);
        assert_eq!(upsert_inventory(&mut conn, &inv2).unwrap(), 2);
        let d = image_detail(&mut conn, D).unwrap().unwrap();
        assert_eq!(d.image.tags, vec!["1.27", "mainline", "stable"]);

        // A restart with no digest yet keeps the known digest when the ref
        // is unchanged...
        let pending = json!([{"name": "app", "kind": "regular", "image": "nginx:mainline"}]);
        let inv3 = inventory_from_post(&p, Some(&pending), None);
        assert_eq!(upsert_inventory(&mut conn, &inv3).unwrap(), 0);
        let wc = workload_containers(&mut conn, "prod", "Deployment", "web").unwrap();
        let app = wc
            .containers
            .iter()
            .find(|c| c.container_name == "app")
            .unwrap();
        assert_eq!(app.image_digest.as_deref(), Some(D));
        // ...and a changed ref with no digest clears it.
        let rollout = json!([{"name": "app", "kind": "regular", "image": "nginx:1.28"}]);
        let inv4 = inventory_from_post(&p, Some(&rollout), None);
        assert_eq!(upsert_inventory(&mut conn, &inv4).unwrap(), 1);
        let wc = workload_containers(&mut conn, "prod", "Deployment", "web").unwrap();
        let app = wc
            .containers
            .iter()
            .find(|c| c.container_name == "app")
            .unwrap();
        assert_eq!(app.image_digest, None);
        assert_eq!(app.image_ref, "nginx:1.28");

        // A stale row is refreshed even when nothing changed.
        age(
            &mut conn,
            "workload_containers",
            "updated_at",
            REFRESH_SECS * 2,
        );
        age(&mut conn, "images", "last_seen", REFRESH_SECS * 2);
        assert_eq!(upsert_inventory(&mut conn, &inv).unwrap(), 6);
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
