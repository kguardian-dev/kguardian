use crate::ip::canonical_ip;
use crate::{schema, PodDetail, PodSyscalls, PodTraffic, SvcDetail};
use actix_web::{get, web, HttpResponse, Responder};
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_types::{Bool, Jsonb};
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

#[get("/pod/traffic")]
pub async fn get_pod_traffic(
    pool: web::Data<DbPool>,
    query: web::Query<PodTrafficQuery>,
) -> actix_web::Result<impl Responder> {
    debug!("select pod traffic table");
    let row_limit = clamp_pod_traffic_limit(query.limit);
    let pod_traffic = web::block(move || {
        let mut conn = pool.get()?;
        pod_traffic(&mut conn, row_limit)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_traffic {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

/// Query params for the cluster-wide `GET /pod/traffic` endpoint.
#[derive(serde::Deserialize)]
pub struct PodTrafficQuery {
    /// Cap rows returned (most-recent-first). Defaults to 5000, hard cap 20000.
    pub limit: Option<i64>,
}

/// Clamp the caller-supplied row limit into [1, 20000] with a default of
/// 5000 when unset. Extracted so the policy can be unit-tested without a
/// live DB, mirroring `clamp_audit_limit`.
///
/// The bound is not cosmetic: `pod_traffic` is a high-insert, never-pruned
/// table that grows into the millions of rows (observed at 6.7M rows / 2 GB
/// in production). The pre-bound query was an unbounded
/// `SELECT * ... ORDER BY time_stamp DESC` — a parallel seq-scan + sort of
/// the whole table that took tens of seconds and serialised a multi-hundred-MB
/// body. That stalled the broker, spiked its memory, and overran the
/// mcp-server's 10 MB response cap, so the client failed to decode the
/// truncated body with "unexpected EOF" (i.e. cluster-traffic was broken).
/// At ~350 B/row of JSON, the 20000-row cap is ~7 MB — safely under that cap —
/// and the default 5000 is ~1.7 MB. The sole cluster-wide consumer
/// (mcp-server's get_cluster_traffic) only aggregates the rows into per-pod
/// counts, so a most-recent-first window is the right shape; its counts now
/// describe the recent window rather than all history.
pub(crate) fn clamp_pod_traffic_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(5_000).clamp(1, 20_000)
}

pub fn pod_traffic(
    conn: &mut PgConnection,
    row_limit: i64,
) -> Result<Option<Vec<PodTraffic>>, DbError> {
    use schema::pod_traffic::dsl::*;

    // Stable display order — most recent first with uuid (the PK) as
    // the tiebreak. Same UX-stability class as the audit_verdicts
    // ORDER BY (observed_at DESC, id DESC) — without this, the
    // frontend's "all pod traffic" panel reshuffled between reads as
    // Postgres heap state changed (any insert/delete shifts row
    // positions). uuid DESC is deterministic for ties in time_stamp
    // (which the broker stamps from chrono::Utc::now().naive_utc(),
    // and microsecond-level ties are common inside a batch ingest).
    //
    // The .limit() bounds the whole-table read (see clamp_pod_traffic_limit);
    // the idx_pod_traffic_time_stamp index (time_stamp DESC, uuid DESC) lets
    // this ORDER BY ... LIMIT run as an index scan of `row_limit` rows instead
    // of a full seq-scan + sort of the millions-of-rows table.
    let pod = pod_traffic
        .order((time_stamp.desc(), uuid.desc()))
        .limit(row_limit)
        .load::<PodTraffic>(conn)
        .optional()?;

    Ok(pod)
}

#[get("/pod/info")]
pub async fn get_pod_details(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    debug!("select pod details table");
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_details(&mut conn)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        Some(mut p) => {
            // Strip the bulky parts of each stored Pod manifest before
            // returning the whole table. /pod/info is polled by the
            // frontend, and the full pod_obj (spec + status +
            // metadata.managedFields) is ~12 KB/pod — at a few hundred
            // pods that's multi-MB per poll, which spikes the broker's
            // serialise + memory enough to blip /health and (pre-fix)
            // death-spiral it. The frontend only reads
            // pod_obj.metadata.labels, so keep metadata (sans
            // managedFields) and drop the rest.
            for pod in &mut p {
                if let Some(obj) = pod.pod_obj.as_mut() {
                    compact_pod_obj(obj);
                }
            }
            HttpResponse::Ok().json(p)
        }
        None => HttpResponse::NotFound().body("No data found"),
    })
}

/// Reduce a stored Pod manifest to just the fields consumers need: labels
/// (under metadata — advisor uses them for the policy podSelector, the frontend
/// for the same) and `spec.hostNetwork` (the advisor's Cilium generator reads it
/// to skip host-networked / node-IP pods). Everything else in spec, all of
/// status, and the verbose metadata.managedFields are dropped. Operates in
/// place; non-object values are left untouched. Applied at write time (add.rs)
/// so the bulk never reaches storage, and kept here as a defensive read-time
/// pass for rows written before that.
pub(crate) fn compact_pod_obj(v: &mut serde_json::Value) {
    if let Some(obj) = v.as_object_mut() {
        // Preserve only spec.hostNetwork, dropping the rest of spec. When the
        // manifest has no spec.hostNetwork (the common, non-host-networked
        // case — the field is omitempty), drop spec entirely; the advisor then
        // deserializes HostNetwork=false, which is correct.
        let host_network = obj
            .get("spec")
            .and_then(|s| s.get("hostNetwork"))
            .filter(|hn| !hn.is_null())
            .cloned();
        match host_network {
            Some(hn) => {
                obj.insert("spec".to_string(), serde_json::json!({ "hostNetwork": hn }));
            }
            None => {
                obj.remove("spec");
            }
        }
        obj.remove("status");
        if let Some(meta) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            meta.remove("managedFields");
        }
    }
}

/// Reduce a stored Service manifest to the fields consumers read — `spec`
/// carries the selector (advisor/frontend) and ports (mcp-server/frontend) —
/// dropping status (loadBalancer, etc.) and metadata.managedFields. Operates in
/// place; non-object values are left untouched. Applied at write time so the
/// bulk never reaches storage.
pub(crate) fn compact_svc_spec(v: &mut serde_json::Value) {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("status");
        if let Some(meta) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            meta.remove("managedFields");
        }
    }
}

pub fn pod_details(conn: &mut PgConnection) -> Result<Option<Vec<PodDetail>>, DbError> {
    use schema::pod_details::dsl::*;
    // Stable display order so the frontend's pod-info table doesn't
    // reshuffle between reads. pod_namespace is Nullable — Postgres
    // sorts NULLs LAST for ASC by default, which lands cluster-wide
    // (namespaceless) entries at the bottom. pod_name is the PK so
    // ties are impossible within a namespace.
    let pod = pod_details
        .order((pod_namespace.asc(), pod_name.asc()))
        .load::<PodDetail>(conn)
        .optional()?;
    Ok(pod)
}

// New API: Get all pods for a specific node
#[get("/pod/list/{node}")]
pub async fn get_pods_by_node(
    pool: web::Data<DbPool>,
    node: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    debug!("Getting pods for node: {}", node);
    let node_name = node.into_inner();
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        pods_by_node(&mut conn, &node_name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(pods))
}

pub fn pods_by_node(conn: &mut PgConnection, node: &str) -> Result<Vec<PodDetail>, DbError> {
    use schema::pod_details::dsl::*;
    // Sorted output matches /pod/info — same (namespace, name) order.
    // The reconciler uses a HashSet lookup so this doesn't affect its
    // logic, but ordered output makes the reconciler's own "marking
    // X as dead" log sequence deterministic and easier to read.
    let pods = pod_details
        .filter(node_name.eq(node))
        .filter(is_dead.eq(false))
        .order((pod_namespace.asc(), pod_name.asc()))
        .load::<PodDetail>(conn)?;
    Ok(pods)
}

#[get("/svc/info")]
pub async fn get_svc_details(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    debug!("select svc details table");
    let svc_detail = web::block(move || {
        let mut conn = pool.get()?;
        svc_details_all(&mut conn)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match svc_detail {
        Some(s) => HttpResponse::Ok().json(s),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn svc_details_all(conn: &mut PgConnection) -> Result<Option<Vec<SvcDetail>>, DbError> {
    use schema::svc_details::dsl::*;
    // Stable display order — same rationale as pod_details. svc_ip
    // (the PK) is the final tiebreak so the order is fully
    // deterministic even when two Services share name/namespace via
    // an out-of-band insert (shouldn't happen in practice — k8s
    // doesn't reuse cluster IPs — but a deterministic third sort
    // key costs nothing and saves head-scratching if it ever does).
    let svcs = svc_details
        .order((svc_namespace.asc(), svc_name.asc(), svc_ip.asc()))
        .load::<SvcDetail>(conn)
        .optional()?;
    Ok(svcs)
}

#[get("/svc/ip/{ip}")]
pub async fn get_svc_by_ip(
    pool: web::Data<DbPool>,
    ip: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select svc details by ip");
    let ip = ip.into_inner();
    let svc_detail = web::block(move || {
        let mut conn = pool.get()?;
        svc_ip(&mut conn, &ip)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match svc_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

/// The service-by-IP query for a raw inbound `ip`, canonicalisation
/// included.
///
/// Split out from [`svc_ip`] so the whole behaviour — the normalisation
/// and the resulting SQL — can be asserted in a unit test. Every test
/// in this crate runs without a database, so the generated SQL is the
/// only thing there is to pin.
///
/// svc_ip is the table PK, a VARCHAR, so this is a string match: an
/// IPv6 ClusterIP written "FD00::1" by the caller does not match the
/// "fd00::1" the write path stored, and the Service silently resolves
/// to nothing. See [`crate::ip`] for the canonical form itself (it is
/// a cross-component contract, not a local choice) and for why non-IP
/// input — notably the headless "None" sentinel — passes through
/// rather than erroring.
fn svc_by_ip_query(ip: &str) -> schema::svc_details::BoxedQuery<'static, diesel::pg::Pg> {
    use schema::svc_details::dsl::*;
    svc_details.filter(svc_ip.eq(canonical_ip(ip))).into_boxed()
}

pub fn svc_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<SvcDetail>, DbError> {
    let svc = svc_by_ip_query(ip).first::<SvcDetail>(conn).optional()?;
    Ok(svc)
}

// POD BY NAME
#[get("/pod/name/{name}")]
pub async fn get_pod_by_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod details by name");
    let name = name.into_inner();
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_name(&mut conn, &name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_name(conn: &mut PgConnection, name: &str) -> Result<Option<PodDetail>, DbError> {
    use schema::pod_details::dsl::*;
    // pod_details PK is pod_name (per the iteration-86 schema fix and
    // confirmed in schema.rs), so this filter matches AT MOST one row.
    // The upsert on /pod/spec uses on_conflict(pod_name).do_update(),
    // so a StatefulSet pod restarting reusing the same name replaces
    // the old row in place — the dead entry never survives alongside
    // the new live entry.
    //
    // The (is_dead ASC, time_stamp DESC) ordering is now defense-in-
    // depth: it's a no-op for a single-row result, but if a future
    // schema migration ever permits multiple rows per pod_name (e.g.,
    // a join with a workload_revisions side-table), this query would
    // still surface the alive-and-current row first — falling back to
    // the most-recent dead entry only when nothing is alive. Cheap
    // insurance against a schema regression.
    let pod = pod_details
        .filter(pod_name.eq(name.to_string()))
        .order((is_dead.asc(), time_stamp.desc()))
        .first::<PodDetail>(conn)
        .optional()?;
    Ok(pod)
}

// POD BY IP
#[get("/pod/ip/{ip}")]
pub async fn get_pod_by_ip(
    pool: web::Data<DbPool>,
    ip: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod details by ip");
    let ip = ip.into_inner();
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_ip(&mut conn, &ip)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

/// The pod-by-IP query for a raw inbound `ip`, canonicalisation
/// included.
///
/// Split out from [`pod_ip`] for the same reason as
/// [`svc_by_ip_query`]: the crate has no database-backed tests, so the
/// generated SQL is what the unit tests assert against.
///
/// The inbound address is canonicalised first. These are VARCHAR
/// columns matched as strings, and one IPv6 address has many spellings
/// ("FD00::1", "fd00:0:0:0:0:0:0:1", "fd00::1"); whichever form the
/// caller happens to hold has to be reduced to the same form the write
/// path stored. See [`crate::ip`].
///
/// The predicate matches EITHER the legacy scalar `pod_ip` column or
/// membership in the `pod_ips` array. `pod_details.pod_ip` holds a
/// single address — for a dual-stack pod, whichever family kubelet
/// reports as primary — so a peer observed on the other family never
/// resolved to a pod at all. That failure is invisible rather than
/// loud: a `None` here is also how the advisor learns a peer is
/// genuinely external, so instead of erroring, policy generation
/// quietly degrades the flow from a podSelector to a raw ipBlock.
///
/// Matching the scalar as well as the array (rather than reading
/// `pod_ips` alone) is what keeps an older controller working — one
/// that posts only `pod_ip`, against rows this broker has not
/// re-upserted since the migration backfilled them. Broker and
/// controller ship independently (RELEASES.md).
///
/// The containment probe is a raw fragment because diesel has no typed
/// operator for jsonb `@>`; it is parameterised, not interpolated, and
/// idx_pod_details_pod_ips (GIN jsonb_path_ops) serves it. The column
/// is qualified because `pod_ips` is also in scope as a diesel dsl
/// item.
fn pod_by_ip_query(ip: &str) -> schema::pod_details::BoxedQuery<'static, diesel::pg::Pg> {
    use schema::pod_details::dsl::*;
    let wanted = canonical_ip(ip);
    let contains_wanted =
        sql::<Bool>("pod_details.pod_ips @> ").bind::<Jsonb, _>(serde_json::json!([wanted]));
    // Deterministic pick when more than one row matches. pod_details is
    // keyed by pod_name, so a pod that died holding an address and a
    // live pod that later reused it are two rows — and widening the
    // predicate makes an overlap likelier than it was with a single
    // exact column. Same (is_dead ASC, time_stamp DESC) rule as
    // pod_name(): prefer the live pod, fall back to the most recently
    // seen dead one, never let the planner decide.
    pod_details
        .filter(pod_ip.eq(wanted).or(contains_wanted))
        .order((is_dead.asc(), time_stamp.desc()))
        .into_boxed()
}

/// Resolve a pod by any of its addresses.
pub fn pod_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<PodDetail>, DbError> {
    let pod = pod_by_ip_query(ip).first::<PodDetail>(conn).optional()?;
    Ok(pod)
}

// POD TRAFFIC BY PODNAME
#[get("/pod/traffic/{name}")]
pub async fn get_pod_traffic_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod traffic for the pod name");
    let pod_name = name.into_inner();
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_traffic_by_name(&mut conn, &pod_name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_traffic_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<Vec<PodTraffic>>, DbError> {
    use schema::pod_traffic::dsl::*;
    // See pod_traffic() for the (time_stamp DESC, uuid DESC) rationale.
    // This is also what the advisor's policy generator reads via
    // /pod/traffic/{name}; the dedup-then-sort on the advisor side
    // (deduplicatePorts) already produces deterministic YAML, but
    // stable input here means simpler reasoning + fewer surprises if
    // a future generator change becomes input-order sensitive.
    // Bounded like the cluster-wide endpoint (clamp_pod_traffic_limit's
    // ceiling): a pathological pod — the direction-heuristic artifact
    // accumulated tens of thousands of one-port rows per peer — must
    // not turn this into an unbounded whole-partition read. Newest
    // rows win via the DESC order above.
    let pod_tr = pod_traffic
        .filter(pod_name.eq(name.to_string()))
        .order((time_stamp.desc(), uuid.desc()))
        .limit(clamp_pod_traffic_limit(Some(20_000)))
        .load::<PodTraffic>(conn)
        .optional()?;
    Ok(pod_tr)
}

// POD SYS CALLS BY PODNAME
#[get("/pod/syscalls/{name}")]
pub async fn get_pod_syscall_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod syscall for the pod name");
    let pod_name = name.into_inner();
    let pod_syscalls = web::block(move || {
        let mut conn = pool.get()?;
        pod_syscalls_by_name(&mut conn, &pod_name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_syscalls {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_syscalls_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<Vec<PodSyscalls>>, DbError> {
    use schema::pod_syscalls::dsl::*;
    let pod_tr = pod_syscalls
        .filter(pod_name.eq(name.to_string()))
        .load::<PodSyscalls>(conn)
        .optional()?;
    Ok(pod_tr)
}

#[derive(serde::Deserialize)]
pub struct AuditVerdictsQuery {
    /// Filter to a single policy by name. Combine with a concrete `namespace`
    /// for an AuditNetworkPolicy; for cluster-scoped verdicts send `namespace=`
    /// (empty value present), which matches `policy_namespace = ''`. An absent
    /// `namespace` param spans all namespaces (cluster-scoped included).
    pub policy: Option<String>,
    pub namespace: Option<String>,
    /// Filter rows by verdict — "Allow" or "WouldDeny". The DB has the
    /// (verdict, observed_at) composite index from the audit_verdict_column
    /// migration, so server-side filtering is index-backed; without this
    /// filter the frontends Would-Deny view has to pull both verdicts
    /// then drop Allow client-side, burning the row limit.
    pub verdict: Option<String>,
    /// Filter rows by direction — "Ingress" or "Egress". Pairs with the
    /// frontend tabs that split each direction.
    pub direction: Option<String>,
    /// Cap rows returned. Defaults to 100, hard cap 500.
    pub limit: Option<i64>,
}

/// Clamp the caller-supplied row limit into the [1, 500] window with a
/// default of 100 when unset. Extracted so the policy can be unit-tested
/// without a live DB.
pub(crate) fn clamp_audit_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(100).clamp(1, 500)
}

/// Normalise an empty-string filter to `None` for /audit/verdicts.
///
/// - `None` or `Some("")` → `None` (no filter applied; return everything
///   subject to other filters).
/// - `Some(non-empty)` → unchanged.
///
/// Applied to `?policy=`, `?verdict=`, and `?direction=`. The empty
/// case happens when a caller submits a form with the field blank,
/// or an MCP tool passes through an unset parameter — they want the
/// filter to NOT be applied. Without this normaliser the broker
/// would either filter to `WHERE policy_name = ''` (zero rows; policy
/// names are CRD-non-empty) or reject the request with a 400 from
/// the enum validator. The frontend already gates each filter with
/// `if (opts.X) params.X = ...`, so this is mainly a defense for
/// direct API callers (curl, mcp-server, future SDK consumers).
///
/// Asymmetry with `?namespace=` is deliberate: empty-namespace IS a
/// meaningful filter (cluster-scoped policy verdicts are stored with
/// `policy_namespace = ''`), so empty-namespace stays as an explicit
/// filter. See the doc comment on `policy_ns` in the handler.
pub(crate) fn normalise_empty_to_none(raw: Option<String>) -> Option<String> {
    raw.filter(|s| !s.is_empty())
}

/// Whitelist of valid verdict values. Anything else is rejected with
/// 400 — silently ignoring an unknown value (the previous behavior of
/// "no filter parameter" was no-op) would mask client bugs.
const VALID_VERDICTS: &[&str] = &["Allow", "WouldDeny"];
/// Whitelist of valid direction values. See VALID_VERDICTS above.
const VALID_DIRECTIONS: &[&str] = &["Ingress", "Egress"];

pub(crate) fn validate_enum_filter(
    field: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "invalid {field}={value:?}; must be one of {allowed:?}"
        ))
    }
}

#[get("/audit/verdicts")]
pub async fn get_audit_verdicts(
    pool: web::Data<DbPool>,
    query: web::Query<AuditVerdictsQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let limit = clamp_audit_limit(q.limit);
    let policy_name = normalise_empty_to_none(q.policy.clone());
    // namespace is NOT normalised the same way. `namespace=` (empty)
    // IS a legitimate filter: cluster-scoped policy verdicts are
    // stored with `policy_namespace = ''` (the evaluator emits "" for
    // cluster-scoped), so `?namespace=` correctly returns only
    // cluster-scoped verdicts. This is the documented contract
    // pinned by `query_parses_full_filter`.
    let policy_ns = q.namespace.clone();

    // Empty-string verdict/direction → no filter (form fields left
    // blank). The validator then catches actual typos (Maybe / Both
    // / lowercase variants) — a 400 for genuinely-bad input but a
    // no-op for "filter not selected". Symmetric with policy
    // normalisation so a caller posting an empty form doesn't get
    // arbitrary 400 vs 200-empty depending on which fields they
    // happen to skip.
    let verdict_filter = normalise_empty_to_none(q.verdict.clone());
    let direction_filter = normalise_empty_to_none(q.direction.clone());
    if let Some(v) = verdict_filter.as_deref() {
        if let Err(msg) = validate_enum_filter("verdict", v, VALID_VERDICTS) {
            return Ok(HttpResponse::BadRequest().body(msg));
        }
    }
    if let Some(d) = direction_filter.as_deref() {
        if let Err(msg) = validate_enum_filter("direction", d, VALID_DIRECTIONS) {
            return Ok(HttpResponse::BadRequest().body(msg));
        }
    }
    let rows = web::block(move || {
        let mut conn = pool.get()?;
        audit_verdicts_query(
            &mut conn,
            policy_name,
            policy_ns,
            verdict_filter,
            direction_filter,
            limit,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(rows))
}

pub fn audit_verdicts_query(
    conn: &mut PgConnection,
    by_policy: Option<String>,
    by_namespace: Option<String>,
    by_verdict: Option<String>,
    by_direction: Option<String>,
    row_limit: i64,
) -> Result<Vec<crate::AuditVerdict>, DbError> {
    use schema::audit_verdicts::dsl::*;
    let mut q = audit_verdicts.into_boxed();
    if let Some(name) = by_policy {
        q = q.filter(policy_name.eq(name));
    }
    if let Some(ns) = by_namespace {
        q = q.filter(policy_namespace.eq(ns));
    }
    if let Some(v) = by_verdict {
        q = q.filter(verdict.eq(v));
    }
    if let Some(d) = by_direction {
        q = q.filter(direction.eq(d));
    }
    // Tie-break by id DESC. Without it, multiple rows that share the
    // same observed_at (the broker stamps with Utc::now().naive_utc()
    // and microsecond-level ties are common when a single ingest
    // batch produces N verdicts) come back in arbitrary order from
    // postgres — every repeat of the same request reshuffles the
    // top-N visible to the frontend's Would-Deny view. id is the
    // BIGSERIAL PK (monotonic), so id DESC is a deterministic stand-
    // in for "most recently inserted" within the same observed_at.
    let rows = q
        .order((observed_at.desc(), id.desc()))
        .limit(row_limit)
        .load::<crate::AuditVerdict>(conn)?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pod/svc by-IP lookup -------------------------------------
    //
    // There is no database in this test suite (nothing in the crate
    // takes a live PgConnection), so these assert on the SQL diesel
    // generates and the values it binds. That is enough to pin the two
    // things that actually broke for dual-stack pods: which columns the
    // predicate consults, and what form the address is in by the time
    // it reaches a bind.

    fn pod_sql(ip: &str) -> String {
        diesel::debug_query::<diesel::pg::Pg, _>(&pod_by_ip_query(ip)).to_string()
    }

    fn svc_sql(ip: &str) -> String {
        diesel::debug_query::<diesel::pg::Pg, _>(&svc_by_ip_query(ip)).to_string()
    }

    #[test]
    fn pod_by_ip_matches_either_column() {
        // The regression this whole change exists for: a dual-stack pod
        // stores only its primary address in pod_details.pod_ip, so the
        // lookup has to also consult pod_ips. Both halves must be
        // present, OR'd — checking only pod_ips would break older
        // controllers, checking only pod_ip is the original bug.
        let sql = pod_sql("fd00::1");
        assert!(
            sql.contains(r#""pod_details"."pod_ip" = $1"#),
            "legacy scalar column must still be matched: {sql}"
        );
        assert!(
            sql.contains("pod_details.pod_ips @> $2"),
            "pod_ips membership must be matched: {sql}"
        );
        assert!(
            sql.contains(r#"(("pod_details"."pod_ip" = $1) OR pod_details.pod_ips @> $2)"#),
            "the two must be OR'd, not AND'd: {sql}"
        );
    }

    #[test]
    fn pod_by_ip_binds_the_same_canonical_address_to_both_halves() {
        // A mismatch between the two binds would make the OR match on
        // one family's spelling and miss on the other's — the exact
        // failure mode, just moved one layer down.
        let sql = pod_sql("FD00:0:0:0:0:0:0:1");
        assert!(
            sql.contains(r#"binds: ["fd00::1", Array [String("fd00::1")]]"#),
            "both halves must bind the same canonical form: {sql}"
        );
    }

    #[test]
    fn pod_by_ip_canonicalises_every_ipv6_spelling_to_one_query() {
        // Four ways of writing one address must produce byte-identical
        // SQL *and* binds, or the lookup depends on how the caller
        // happened to format the peer it observed.
        let expected = pod_sql("fd00::1");
        for spelling in [
            "FD00::1",
            "fd00:0:0:0:0:0:0:1",
            "fd00:0000:0000:0000:0000:0000:0000:0001",
            "FD00:0000:0000:0000:0000:0000:0000:0001",
        ] {
            assert_eq!(
                pod_sql(spelling),
                expected,
                "{spelling} must produce the same query as fd00::1"
            );
        }
    }

    #[test]
    fn pod_by_ip_leaves_ipv4_alone() {
        // Canonicalisation must not disturb the IPv4 path: every row
        // written before this change holds a plain dotted quad.
        let sql = pod_sql("10.42.3.5");
        assert!(
            sql.contains(r#"binds: ["10.42.3.5", Array [String("10.42.3.5")]]"#),
            "IPv4 must bind unchanged: {sql}"
        );
    }

    #[test]
    fn pod_by_ip_passes_non_ip_input_through_unchanged() {
        // A lookup for something that isn't an address should behave as
        // it did before canonicalisation existed — bind the string,
        // match nothing, return None. Not an error.
        let sql = pod_sql("not-an-ip");
        assert!(
            sql.contains(r#"binds: ["not-an-ip", Array [String("not-an-ip")]]"#),
            "unparseable input must reach the bind untouched: {sql}"
        );
    }

    #[test]
    fn pod_by_ip_prefers_the_live_pod() {
        // Widening the predicate makes multi-row matches likelier (a
        // dead pod's row keeps its address; a later pod can reuse it),
        // so the row we return must not be the planner's choice.
        let sql = pod_sql("fd00::1");
        assert!(
            sql.contains(
                r#"ORDER BY "pod_details"."is_dead" ASC, "pod_details"."time_stamp" DESC"#
            ),
            "alive-first, newest-first ordering must be explicit: {sql}"
        );
    }

    #[test]
    fn pod_by_ip_selects_workload_columns_last() {
        // PodDetail derives Queryable, which is positional: if the
        // struct field order and schema.rs column order ever drift, the
        // load silently deserialises the wrong column into the wrong
        // field. Pin the tail of the select list — the last columns
        // added by a migration.
        let sql = pod_sql("10.0.0.1");
        assert!(
            sql.contains(
                r#""pod_details"."pod_ips", "pod_details"."workload_kind", "pod_details"."workload_name" FROM"#
            ),
            "workload_kind/workload_name must be the last selected columns: {sql}"
        );
    }

    #[test]
    fn svc_by_ip_canonicalises_ipv6_variants() {
        let expected = svc_sql("fd00::1");
        for spelling in ["FD00::1", "fd00:0:0:0:0:0:0:1"] {
            assert_eq!(
                svc_sql(spelling),
                expected,
                "{spelling} must produce the same query as fd00::1"
            );
        }
        assert!(
            expected.contains(r#"binds: ["fd00::1"]"#),
            "svc lookup must bind the canonical form: {expected}"
        );
    }

    #[test]
    fn svc_by_ip_leaves_headless_sentinel_and_ipv4_alone() {
        // "None" is the headless-Service sentinel the routability guard
        // rejects on the write path; it must not be mangled here either.
        assert!(svc_sql("None").contains(r#"binds: ["None"]"#));
        assert!(svc_sql("10.96.0.1").contains(r#"binds: ["10.96.0.1"]"#));
    }

    #[test]
    fn compact_pod_obj_drops_bulk_keeps_labels() {
        // Guards the /pod/info weight fix: the response must drop the
        // heavy spec/status/managedFields but keep metadata.labels (the
        // only part the frontend reads), so /pod/info can't balloon back
        // to multi-MB and overload the broker.
        let mut v = serde_json::json!({
            "metadata": {
                "name": "web-1",
                "namespace": "prod",
                "labels": {"app": "web"},
                "managedFields": [{"manager": "kubelet", "big": "x".repeat(1000)}]
            },
            "spec": {"hostNetwork": true, "containers": [{"name": "c", "image": "nginx"}]},
            "status": {"phase": "Running", "conditions": [{"type": "Ready"}]}
        });
        compact_pod_obj(&mut v);
        assert!(v.get("status").is_none(), "status must be dropped");
        let meta = v.get("metadata").expect("metadata kept");
        assert!(
            meta.get("managedFields").is_none(),
            "managedFields must be dropped"
        );
        assert_eq!(
            meta.pointer("/labels/app").and_then(|x| x.as_str()),
            Some("web"),
            "metadata.labels must be preserved"
        );
        assert_eq!(meta.get("name").and_then(|x| x.as_str()), Some("web-1"));
        // spec.hostNetwork must survive (the Cilium generator reads it) but the
        // rest of spec (containers, etc.) must be dropped.
        assert_eq!(
            v.pointer("/spec/hostNetwork").and_then(|x| x.as_bool()),
            Some(true),
            "spec.hostNetwork must be preserved"
        );
        assert!(
            v.pointer("/spec/containers").is_none(),
            "the rest of spec must be dropped"
        );
    }

    #[test]
    fn compact_pod_obj_drops_spec_when_no_host_network() {
        // Non-host-networked pods omit spec.hostNetwork; spec is dropped wholesale.
        let mut v = serde_json::json!({
            "metadata": {"labels": {"app": "db"}},
            "spec": {"containers": [{"name": "c"}]}
        });
        compact_pod_obj(&mut v);
        assert!(
            v.get("spec").is_none(),
            "spec must be dropped when no hostNetwork"
        );
        assert_eq!(
            v.pointer("/metadata/labels/app").and_then(|x| x.as_str()),
            Some("db")
        );
    }

    #[test]
    fn compact_svc_spec_keeps_spec_drops_status() {
        // The Service slim must keep spec (selector + ports — read by advisor,
        // mcp-server, and the frontend) while dropping status and managedFields.
        let mut v = serde_json::json!({
            "metadata": {
                "name": "web",
                "namespace": "prod",
                "managedFields": [{"manager": "kube-controller", "big": "y".repeat(1000)}]
            },
            "spec": {
                "selector": {"app": "web"},
                "ports": [{"port": 80, "protocol": "TCP"}],
                "type": "ClusterIP"
            },
            "status": {"loadBalancer": {"ingress": [{"ip": "1.2.3.4"}]}}
        });
        compact_svc_spec(&mut v);
        assert!(v.get("status").is_none(), "status must be dropped");
        let meta = v.get("metadata").expect("metadata kept");
        assert!(
            meta.get("managedFields").is_none(),
            "managedFields must be dropped"
        );
        // spec.selector and spec.ports must survive for policy generation.
        assert_eq!(
            v.pointer("/spec/selector/app").and_then(|x| x.as_str()),
            Some("web"),
            "spec.selector must be preserved"
        );
        assert_eq!(
            v.pointer("/spec/ports/0/port").and_then(|x| x.as_u64()),
            Some(80),
            "spec.ports must be preserved"
        );
    }

    #[test]
    fn compact_svc_spec_tolerates_non_object() {
        let mut v = serde_json::Value::Null;
        compact_svc_spec(&mut v); // must not panic
        assert!(v.is_null());
    }

    #[test]
    fn compact_pod_obj_tolerates_non_object() {
        let mut v = serde_json::Value::Null;
        compact_pod_obj(&mut v); // must not panic
        assert!(v.is_null());
    }

    #[test]
    fn clamp_default_when_unset() {
        assert_eq!(clamp_audit_limit(None), 100);
    }

    #[test]
    fn clamp_passes_through_in_range() {
        for n in [1, 50, 100, 250, 499, 500] {
            assert_eq!(
                clamp_audit_limit(Some(n)),
                n,
                "in-range {n} must be unchanged"
            );
        }
    }

    #[test]
    fn clamp_caps_oversized_request() {
        // The frontend should never request 10,000 rows — but if it did,
        // we don't want to OOM the broker. Hard cap is 500.
        assert_eq!(clamp_audit_limit(Some(10_000)), 500);
        assert_eq!(clamp_audit_limit(Some(i64::MAX)), 500);
    }

    #[test]
    fn clamp_floors_zero_and_negative() {
        // Zero or negative would make the SQL `LIMIT 0` (no rows) or
        // a query error; both surprising for a caller that probably
        // forgot to set the field. Clamp to 1 row.
        assert_eq!(clamp_audit_limit(Some(0)), 1);
        assert_eq!(clamp_audit_limit(Some(-5)), 1);
        assert_eq!(clamp_audit_limit(Some(i64::MIN)), 1);
    }

    // AuditVerdictsQuery deserialisation — exercised through actix's
    // web::Query in production, but we can drive the same serde path
    // directly via serde_urlencoded which web::Query uses internally.

    fn parse_query(qs: &str) -> AuditVerdictsQuery {
        serde_urlencoded::from_str(qs).expect("must parse")
    }

    #[test]
    fn query_all_fields_optional() {
        // No filters at all — all three fields are Option<_> with None.
        let q = parse_query("");
        assert!(q.policy.is_none());
        assert!(q.namespace.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn query_parses_full_filter() {
        let q = parse_query("policy=cluster-baseline-audit&namespace=&limit=42");
        assert_eq!(q.policy.as_deref(), Some("cluster-baseline-audit"));
        // Empty namespace is meaningful (cluster-scoped policy filter).
        assert_eq!(q.namespace.as_deref(), Some(""));
        assert_eq!(q.limit, Some(42));
    }

    #[test]
    fn query_partial_filter() {
        let q = parse_query("policy=web-deny");
        assert_eq!(q.policy.as_deref(), Some("web-deny"));
        assert!(q.namespace.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn query_rejects_non_numeric_limit() {
        // Better to return a clear 400 than to silently coerce.
        let r: Result<AuditVerdictsQuery, _> = serde_urlencoded::from_str("limit=abc");
        assert!(r.is_err(), "non-numeric limit must fail to parse");
    }

    // ---- /pod/traffic limit clamping + query parsing ----

    #[test]
    fn pod_traffic_clamp_default_when_unset() {
        // The mcp-server's get_cluster_traffic sends no limit, so the
        // default governs the whole cluster-traffic path.
        assert_eq!(clamp_pod_traffic_limit(None), 5_000);
    }

    #[test]
    fn pod_traffic_clamp_passes_through_in_range() {
        for n in [1, 100, 5_000, 10_000, 19_999, 20_000] {
            assert_eq!(
                clamp_pod_traffic_limit(Some(n)),
                n,
                "in-range {n} must be unchanged"
            );
        }
    }

    #[test]
    fn pod_traffic_clamp_caps_oversized_request() {
        // Above the cap the unbounded whole-table serialise returns to
        // overrunning the mcp-server's 10 MB body cap; hard cap is 20000
        // (~7 MB at ~350 B/row).
        assert_eq!(clamp_pod_traffic_limit(Some(1_000_000)), 20_000);
        assert_eq!(clamp_pod_traffic_limit(Some(i64::MAX)), 20_000);
    }

    #[test]
    fn pod_traffic_clamp_floors_zero_and_negative() {
        // LIMIT 0 returns no rows; negative errors in SQL. Both are almost
        // certainly a caller mistake — clamp to 1 row.
        assert_eq!(clamp_pod_traffic_limit(Some(0)), 1);
        assert_eq!(clamp_pod_traffic_limit(Some(-5)), 1);
        assert_eq!(clamp_pod_traffic_limit(Some(i64::MIN)), 1);
    }

    #[test]
    fn pod_traffic_query_limit_optional() {
        let q: PodTrafficQuery = serde_urlencoded::from_str("").expect("must parse");
        assert!(q.limit.is_none());
    }

    #[test]
    fn pod_traffic_query_parses_limit() {
        let q: PodTrafficQuery = serde_urlencoded::from_str("limit=1234").expect("must parse");
        assert_eq!(q.limit, Some(1234));
    }

    #[test]
    fn pod_traffic_query_rejects_non_numeric_limit() {
        let r: Result<PodTrafficQuery, _> = serde_urlencoded::from_str("limit=abc");
        assert!(r.is_err(), "non-numeric limit must fail to parse");
    }

    #[test]
    fn normalise_empty_to_none_empty_string_becomes_none() {
        // `?policy=` on the wire serdes to Some("") via web::Query
        // because the parameter is present with no value. Without the
        // normaliser, the query function would apply
        // `WHERE policy_name = ''` and return zero rows — a confusing
        // "asked for everything, got nothing" UX. Policy names are
        // CRD-validated non-empty so this filter is never useful.
        assert_eq!(normalise_empty_to_none(Some(String::new())), None);
    }

    #[test]
    fn normalise_empty_to_none_none_stays_none() {
        // No `?policy=` query string at all → Option::None passes through.
        assert_eq!(normalise_empty_to_none(None), None);
    }

    #[test]
    fn normalise_empty_to_none_preserves_non_empty() {
        // Real policy names must pass through unchanged.
        assert_eq!(
            normalise_empty_to_none(Some("web-deny".to_string())),
            Some("web-deny".to_string()),
        );
        assert_eq!(
            normalise_empty_to_none(Some("cluster-baseline-audit".to_string())),
            Some("cluster-baseline-audit".to_string()),
        );
    }

    #[test]
    fn normalise_empty_to_none_preserves_whitespace_string() {
        // Whitespace-only names aren't CRD-valid either, but trimming
        // here would be too eager — if an operator types `policy= foo`
        // they probably mean " foo" literal and the server should
        // either match it exactly (which it will) or return zero rows
        // (revealing the typo). We only collapse the truly-empty case,
        // matching the "no value supplied" wire shape that the frontend
        // sometimes accidentally produces.
        assert_eq!(
            normalise_empty_to_none(Some(" ".to_string())),
            Some(" ".to_string()),
        );
    }

    #[test]
    fn query_parses_verdict_and_direction() {
        // The new filters arrive on the wire alongside policy/limit.
        // Both populate the Option fields at the parse layer; semantic
        // validation (allowed values) happens later in the handler.
        let q = parse_query("verdict=WouldDeny&direction=Egress&limit=50");
        assert_eq!(q.verdict.as_deref(), Some("WouldDeny"));
        assert_eq!(q.direction.as_deref(), Some("Egress"));
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn query_verdict_and_direction_optional() {
        let q = parse_query("policy=p1");
        assert!(q.verdict.is_none(), "verdict must be optional");
        assert!(q.direction.is_none(), "direction must be optional");
    }

    #[test]
    fn validate_enum_filter_accepts_allowed_values() {
        // Both whitelists are tiny; pin every value to catch a typo
        // (Allow vs allow, Ingress vs ingress) at compile-test time.
        for v in ["Allow", "WouldDeny"] {
            assert!(
                validate_enum_filter("verdict", v, VALID_VERDICTS).is_ok(),
                "verdict={v} must be accepted",
            );
        }
        for d in ["Ingress", "Egress"] {
            assert!(
                validate_enum_filter("direction", d, VALID_DIRECTIONS).is_ok(),
                "direction={d} must be accepted",
            );
        }
    }

    #[test]
    fn validate_enum_filter_rejects_case_variants() {
        // Verdicts are case-sensitive on the wire to match the
        // evaluator's wire format ("WouldDeny", "Allow"). Lowercase or
        // mixed-case must produce a 400 — silently lower-casing would
        // mask a frontend bug and the SQL filter would still miss because
        // the DB column stores mixed-case verbatim.
        for bad in ["allow", "ALLOW", "wouldDeny", "wouldDENY", "would_deny"] {
            assert!(
                validate_enum_filter("verdict", bad, VALID_VERDICTS).is_err(),
                "case variant {bad:?} must be rejected",
            );
        }
        for bad in ["ingress", "egress", "INGRESS", "Both"] {
            assert!(
                validate_enum_filter("direction", bad, VALID_DIRECTIONS).is_err(),
                "case variant {bad:?} must be rejected",
            );
        }
    }

    #[test]
    fn validate_enum_filter_rejects_garbage() {
        assert!(validate_enum_filter("verdict", "", VALID_VERDICTS).is_err());
        assert!(validate_enum_filter("verdict", "Maybe", VALID_VERDICTS).is_err());
        assert!(validate_enum_filter("direction", "<script>", VALID_DIRECTIONS).is_err());
    }

    #[test]
    fn validate_enum_filter_error_includes_field_and_value() {
        // The 400 body is what frontend devs see — make sure it names
        // the offending field AND the bad value so the bug is debuggable
        // without running the broker locally.
        let err = validate_enum_filter("verdict", "Maybe", VALID_VERDICTS).unwrap_err();
        assert!(err.contains("verdict"), "error must name field: {err}");
        assert!(err.contains("Maybe"), "error must name value: {err}");
    }
}
