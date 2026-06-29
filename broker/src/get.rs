use crate::{schema, HttpPodTraffic, PodDetail, PodSyscalls, PodTraffic, SvcDetail};
use actix_web::{get, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

#[get("/pod/traffic")]
pub async fn get_pod_traffic(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    debug!("select pod traffic table");
    let pod_traffic = web::block(move || {
        let mut conn = pool.get()?;
        pod_traffic(&mut conn)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_traffic {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_traffic(conn: &mut PgConnection) -> Result<Option<Vec<PodTraffic>>, DbError> {
    use schema::pod_traffic::dsl::*;

    // Stable display order — most recent first with uuid (the PK) as
    // the tiebreak. Same UX-stability class as the audit_verdicts
    // ORDER BY (observed_at DESC, id DESC) — without this, the
    // frontend's "all pod traffic" panel reshuffled between reads as
    // Postgres heap state changed (any insert/delete shifts row
    // positions). uuid DESC is deterministic for ties in time_stamp
    // (which the broker stamps from chrono::Utc::now().naive_utc(),
    // and microsecond-level ties are common inside a batch ingest).
    let pod = pod_traffic
        .order((time_stamp.desc(), uuid.desc()))
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

pub fn svc_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<SvcDetail>, DbError> {
    use schema::svc_details::dsl::*;
    let svc = svc_details
        .filter(svc_ip.eq(ip.to_string()))
        .first::<SvcDetail>(conn)
        .optional()?;
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

pub fn pod_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<PodDetail>, DbError> {
    use schema::pod_details::dsl::*;
    let pod = pod_details
        .filter(pod_ip.eq(ip.to_string()))
        .first::<PodDetail>(conn)
        .optional()?;
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
    let pod_tr = pod_traffic
        .filter(pod_name.eq(name.to_string()))
        .order((time_stamp.desc(), uuid.desc()))
        .load::<PodTraffic>(conn)
        .optional()?;
    Ok(pod_tr)
}

// L7 HTTP TRAFFIC — ALL
#[get("/pod/l7traffic")]
pub async fn get_pod_l7traffic(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    debug!("select pod_http_traffic table");
    let traffic = web::block(move || {
        let mut conn = pool.get()?;
        pod_l7traffic(&mut conn)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match traffic {
        Some(t) => HttpResponse::Ok().json(t),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_l7traffic(conn: &mut PgConnection) -> Result<Option<Vec<HttpPodTraffic>>, DbError> {
    use schema::pod_http_traffic::dsl::*;
    let rows = pod_http_traffic.load::<HttpPodTraffic>(conn).optional()?;
    Ok(rows)
}

// L7 HTTP TRAFFIC BY POD NAME
#[get("/pod/l7traffic/{name}")]
pub async fn get_pod_l7traffic_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod_http_traffic for pod name");
    let pod_name = name.into_inner();
    let traffic = web::block(move || {
        let mut conn = pool.get()?;
        pod_l7traffic_by_name(&mut conn, &pod_name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match traffic {
        Some(t) => HttpResponse::Ok().json(t),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_l7traffic_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<Vec<HttpPodTraffic>>, DbError> {
    use schema::pod_http_traffic::dsl::*;
    let rows = pod_http_traffic
        .filter(pod_name.eq(name))
        .load::<HttpPodTraffic>(conn)
        .optional()?;
    Ok(rows)
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
    raw.and_then(|s| if s.is_empty() { None } else { Some(s) })
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
