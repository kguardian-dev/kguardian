use crate::{
    schema, AuditClient, HttpPodTraffic, PodDetail, PodInputSyscalls, PodSyscalls, PodTraffic,
    SvcDetail,
};
use actix_web::{post, web, Error, HttpResponse};
use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use std::clone::Clone;

use diesel::prelude::*;
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

#[post("/pod/traffic/batch")]
pub async fn add_pods_batch(
    pool: web::Data<DbPool>,
    audit: web::Data<AuditClient>,
    form: web::Json<Vec<PodTraffic>>,
) -> Result<HttpResponse, Error> {
    let received = form.len();
    debug!("Received batch of {} network traffic events", received);

    // Run the dedup-and-insert in the blocking pool. The returned vec
    // is the subset of `form` that was actually new (not already in
    // pod_traffic). Pre-fix we cloned the full batch for the audit
    // forwarder before filtering — so a batch where 90/100 events
    // were duplicates fired 100 evaluator round-trips for 10 actually-
    // new flows. eBPF reports the same flow on every cycle, so most
    // batches are >90% duplicate; the wasted audit traffic was
    // pinning the evaluator semaphore and starving real audit work.
    let pool_for_insert = pool.clone();
    let inserted: Vec<PodTraffic> = web::block(move || {
        let mut conn = pool_for_insert.get()?;
        create_pod_traffic_batch(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    info!(
        "Inserted {} new network traffic events ({} duplicates filtered)",
        inserted.len(),
        received - inserted.len()
    );

    // Enqueue new flows for best-effort audit eval. try_enqueue never blocks
    // the ingest hot path and never back-pressures capture: a backed-up
    // evaluator sheds load (the bounded queue drops the overflow and counts it)
    // instead of accumulating unbounded waiting tasks. The dispatcher drains the
    // queue under a concurrency cap.
    if audit.enabled() {
        for event in inserted.iter().cloned() {
            audit.try_enqueue(event);
        }
    }

    // Wire format unchanged: respond with the count of newly-inserted
    // rows (a usize JSON-encoded as a number). The controllers caller
    // discards the body, so we could return more — but tightening the
    // wire is a separate concern.
    Ok(HttpResponse::Ok().json(inserted.len()))
}

/// The content columns that identify a duplicate `PodTraffic` event —
/// the same set `get_row` dedups on. `uuid` and `time_stamp` differ on
/// every eBPF emit by design and are intentionally excluded so that
/// repeated emits of the same flow collapse to one row.
type TrafficContentKey = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn traffic_content_key(e: &PodTraffic) -> TrafficContentKey {
    (
        e.pod_ip.clone(),
        e.pod_port.clone(),
        e.ip_protocol.clone(),
        e.traffic_type.clone(),
        e.traffic_in_out_ip.clone(),
        e.traffic_in_out_port.clone(),
        e.decision.clone(),
    )
}

fn create_pod_traffic_batch(
    conn: &mut PgConnection,
    batch: web::Json<Vec<PodTraffic>>,
) -> Result<Vec<PodTraffic>, DbError> {
    use schema::pod_traffic::dsl::*;

    if batch.is_empty() {
        return Ok(Vec::new());
    }

    debug!("Processing batch of {} network traffic events", batch.len());

    // Filter out duplicates by checking each event against existing records.
    // The returned vec is what the HTTP handler uses to drive audit
    // forwarding — only events that were genuinely new should hit the
    // evaluator, so the dedup decision lives here as the single source
    // of truth.
    let mut events_to_insert = Vec::new();
    // Collapse byte-identical events within THIS batch before the
    // per-event DB check. eBPF re-emits the same flow every cycle and a
    // batch accumulates over BATCH_TIMEOUT, so identical events commonly
    // arrive together. Without this, both pass get_row (neither is
    // committed yet), double-insert into pod_traffic, AND double-fire
    // the audit evaluator — inflating verdict/flow counts. Key on the
    // same content columns get_row dedups on; uuid/time_stamp differ per
    // event by design and are excluded.
    let mut seen_in_batch = std::collections::HashSet::new();
    for event in batch.iter() {
        if !seen_in_batch.insert(traffic_content_key(event)) {
            debug!(
                "Skipping in-batch duplicate traffic event for pod: {:?}",
                event.pod_name
            );
            continue;
        }
        if event.get_row(conn)?.is_none() {
            events_to_insert.push(event.clone());
        } else {
            debug!(
                "Skipping duplicate traffic event for pod: {:?}",
                event.pod_name
            );
        }
    }

    if events_to_insert.is_empty() {
        debug!("All events in batch were duplicates, nothing to insert");
        return Ok(events_to_insert);
    }

    debug!(
        "Inserting {} new network traffic events (filtered {} duplicates)",
        events_to_insert.len(),
        batch.len() - events_to_insert.len()
    );

    // Bulk insert only the new events
    diesel::insert_into(pod_traffic)
        .values(&events_to_insert)
        .execute(conn)?;

    debug!(
        "Successfully inserted {} network traffic events",
        events_to_insert.len()
    );
    Ok(events_to_insert)
}

#[post("/pod/traffic")]
pub async fn add_pods(
    pool: web::Data<DbPool>,
    audit: web::Data<AuditClient>,
    form: web::Json<PodTraffic>,
) -> Result<HttpResponse, Error> {
    let pool_for_insert = pool.clone();
    let inserted = web::block(move || {
        let mut conn = pool_for_insert.get()?;
        create_pod_traffic(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    // Enqueue ONLY new events for best-effort audit eval (deduped flows are
    // skipped). try_enqueue is non-blocking and sheds load when the evaluator
    // is backed up — same bounded-queue path as the batch endpoint.
    if audit.enabled() {
        if let Some(event) = inserted.clone() {
            audit.try_enqueue(event);
        }
    }

    // Wire format preserved: echo the input form back to the
    // controller (it ignores the body but a behavior change here
    // would be observable in API contract tests). When the row was a
    // duplicate, the input is echoed via the None-path fallback.
    Ok(HttpResponse::Ok().json(inserted))
}

fn create_pod_traffic(
    conn: &mut PgConnection,
    w: web::Json<PodTraffic>,
) -> Result<Option<PodTraffic>, DbError> {
    use schema::pod_traffic::dsl::*;
    debug!("storing pod_traffic event {:?} (uuid)", w.uuid);
    if w.get_row(conn)?.is_none() {
        // debug not info — pod_traffic inserts happen at the rate of
        // new flows in the cluster (potentially thousands per minute
        // on a busy cluster). Reserving INFO for the rare events
        // operators care about (startup, shutdown, config, errors)
        // keeps the default-info log scannable.
        debug!("Insert pod {:?}, in pod_traffic table", w.uuid);
        diesel::insert_into(pod_traffic).values(&*w).execute(conn)?;
        debug!("Success: pod {:?} inserted in pod_traffic table", w.uuid);
        Ok(Some(w.0))
    } else {
        debug!("Data already exists");
        Ok(None)
    }
}

impl PodTraffic {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<PodTraffic>, DbError> {
        use schema::pod_traffic::dsl::*;
        if self.ip_protocol.eq(&Some("UDP".to_string())) {
            let out: Option<PodTraffic> = pod_traffic
                .filter(pod_ip.eq(&self.pod_ip))
                .filter(traffic_type.eq(&self.traffic_type))
                .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
                .filter(traffic_in_out_port.eq(&self.traffic_in_out_port))
                .filter(decision.eq(&self.decision))
                .first::<PodTraffic>(conn)
                .optional()?;
            if out.is_none() {
                let second: Option<PodTraffic> = pod_traffic
                    .filter(pod_ip.eq(&self.pod_ip))
                    .filter(pod_port.eq(&self.pod_port))
                    .filter(traffic_type.eq(&self.traffic_type))
                    .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
                    .filter(decision.eq(&self.decision))
                    .first::<PodTraffic>(conn)
                    .optional()?;
                return Ok(second);
            }
            return Ok(out);
        }

        // Single-line structured log — the previous "\n"-joined
        // multi-line format broke log-aggregator parsing (each line
        // looked like a separate logger emit) and the field name
        // "pod_trafic_type" was a typo. Use tracing's structured
        // fields so operators querying by pod_ip / decision get
        // clean filters in their log backend.
        debug!(
            pod_ip = ?self.pod_ip,
            pod_port = ?self.pod_port,
            traffic_type = ?self.traffic_type,
            traffic_in_out_ip = ?self.traffic_in_out_ip,
            traffic_in_out_port = ?self.traffic_in_out_port,
            decision = ?self.decision,
            "checking pod_traffic for existing row",
        );
        let row = pod_traffic
            .filter(pod_ip.eq(&self.pod_ip))
            .filter(pod_port.eq(&self.pod_port))
            .filter(traffic_type.eq(&self.traffic_type))
            .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
            .filter(traffic_in_out_port.eq(&self.traffic_in_out_port))
            .filter(decision.eq(&self.decision))
            .first::<PodTraffic>(conn)
            .optional()?;
        Ok(row)
    }
}

#[post("/pod/spec")]
pub async fn add_pod_details(
    pool: web::Data<DbPool>,
    form: web::Json<PodDetail>,
) -> Result<HttpResponse, Error> {
    // Defense-in-depth: reject empty/whitespace-only pod_name before
    // it reaches the diesel upsert. pod_name is the table PK and the
    // CRD validator would never produce an empty value, but the
    // broker accepts external POSTs (future tool, hand-rolled curl,
    // misbehaving controller) and an empty PK row creates a sentinel
    // entry that subsequent /pod/name/ lookups can surface as a
    // fake pod. Mirrors the is_routable_svc_ip guard on /svc/spec.
    if form.pod_name.trim().is_empty() {
        tracing::warn!(
            pod_ip = %form.pod_ip,
            pod_namespace = ?form.pod_namespace,
            "skipping pod_details upsert for empty/whitespace pod_name"
        );
        return Ok(HttpResponse::Ok().json(form.0));
    }
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        upsert_pod_details(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(pods))
}

pub fn upsert_pod_details(
    conn: &mut PgConnection,
    mut w: web::Json<PodDetail>,
) -> Result<PodDetail, DbError> {
    use schema::pod_details::dsl::*;
    // Slim the Pod manifest before it ever hits storage: consumers read only
    // metadata.labels and spec.hostNetwork, so dropping the rest of
    // spec/status/managedFields here (rather than recompacting on every read)
    // shrinks the row and the serialise cost.
    if let Some(obj) = w.pod_obj.as_mut() {
        crate::get::compact_pod_obj(obj);
    }
    debug!(
        "storing the pod details {:?} into pod_details table",
        w.pod_name,
    );
    diesel::insert_into(pod_details)
        .values(&*w)
        .on_conflict(pod_name)
        .do_update()
        .set(&*w)
        .execute(conn)?;
    // debug not info — every controller pod-watcher event upserts here
    // (creates, updates, status transitions). On a cluster with rolling
    // deployments this fires at high rate; same INFO-reservation
    // discipline as create_pod_traffic above.
    debug!("Success: pod {:?} inserted in pod_details table", w.pod_ip);
    Ok(w.0)
}

/// Mark-dead request body. `pod_name` is required for backward
/// compatibility with controllers that haven't been updated yet;
/// `pod_ip` is preferred when set because it acts as a sanity check
/// against the row's current pod_ip.
///
/// pod_details PK is pod_name (one row per pod_name), but a pod that
/// restarts updates the SAME row with a new pod_ip via on_conflict
/// upsert. If the reconciler holds a stale view of the row
/// (pod_ip=old) and posts mark_dead during the race window between
/// restart and reconciler refresh, the precise (name, ip) filter
/// won't match the broker's current (name, new_ip) row → no
/// mark-dead, the live restarted pod stays alive. Without pod_ip the
/// name-only filter would mark the live row dead, requiring an
/// upsert from the watcher to restore is_dead=false.
#[derive(Debug, serde::Deserialize)]
pub struct MarkDeadRequest {
    pub pod_name: String,
    #[serde(default)]
    pub pod_ip: Option<String>,
}

#[post("/pod/mark_dead")]
pub async fn mark_pod_dead(
    pool: web::Data<DbPool>,
    form: web::Json<MarkDeadRequest>,
) -> Result<HttpResponse, Error> {
    debug!("Marking pod {} as dead", form.pod_name);
    let MarkDeadRequest { pod_name, pod_ip } = form.into_inner();
    let result = web::block(move || {
        let mut conn = pool.get()?;
        mark_pod_as_dead(&mut conn, &pod_name, pod_ip.as_deref())
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(result))
}

/// Mark the pod_details row(s) dead. Prefer the precise (pod_ip)
/// filter; fall back to name-only for legacy callers.
///
/// pod_details PK is pod_name (one row per pod_name). The precise
/// (pod_name, pod_ip) filter acts as a sanity check — if the
/// reconciler holds a stale view, the precise filter won't match
/// the broker's current row, leaving the (now-restarted, live)
/// pod alone. The legacy name-only fallback unconditionally marks
/// the (single) row dead, which is fine for actually-gone pods but
/// briefly mis-flags a restart during the race window between the
/// new instance's upsert and the reconciler refresh — until the
/// next watcher upsert restores is_dead=false.
fn mark_pod_as_dead(
    conn: &mut PgConnection,
    pod: &str,
    ip: Option<&str>,
) -> Result<usize, DbError> {
    use schema::pod_details::dsl::*;

    // Symmetric defense for pod_name. A degenerate caller sending
    // `{"pod_name": ""}` or whitespace-only would otherwise issue
    // `WHERE pod_name = ''` and silently match zero rows — the broker
    // logs "Marked pod row(s) as dead, rows=0" giving the caller a
    // false-success signal that diverges from the actual update count.
    // Bail early with a warn log so operators can spot the bad call;
    // return Ok(0) to keep the wire-shape idempotent (controllers
    // retry mark_dead, and a 400 would change their failure-handling
    // behavior — pod stays alive in the DB across the retry budget).
    let pod = pod.trim();
    if pod.is_empty() {
        tracing::warn!("mark_pod_dead called with empty pod_name; no-op");
        return Ok(0);
    }

    // Normalise the pod_ip arg: trim whitespace, then treat empty as
    // None. A degenerate caller (a future tool sending pod_ip="") would
    // otherwise hit the precise-filter path with `WHERE pod_ip = ''`
    // — silently matches no rows, returns 0, gives the caller a
    // false success. Falling back to the legacy name-only path is
    // less precise but visible (it logs the warn) and at least
    // marks the matched-by-name rows dead.
    let ip = ip.map(str::trim).filter(|s| !s.is_empty());

    let updated = match ip {
        Some(precise_ip) => {
            // Filter by (pod_name, pod_ip). pod_name is the PK so the
            // row is unique; adding pod_ip is a sanity check that
            // prevents marking the wrong row dead when the reconciler
            // and broker have racing views of the pod's current IP.
            diesel::update(pod_details)
                .filter(pod_name.eq(pod))
                .filter(pod_ip.eq(precise_ip))
                .set(is_dead.eq(true))
                .execute(conn)?
        }
        None => {
            // Legacy path. Logged at warn so operators can see when a
            // controller hasn't been updated to send pod_ip yet. With
            // pod_name as PK this still updates only one row — but
            // without the pod_ip sanity check we risk marking a
            // racing-restart's live row dead until the next watcher
            // upsert refreshes is_dead.
            tracing::warn!(
                pod = %pod,
                "mark_pod_dead called without pod_ip — falling back to name-only filter; no IP sanity check against a racing restart"
            );
            diesel::update(pod_details)
                .filter(pod_name.eq(pod))
                .set(is_dead.eq(true))
                .execute(conn)?
        }
    };

    info!(pod = %pod, ip = ?ip, rows = updated, "Marked pod row(s) as dead");
    Ok(updated)
}

/// Defense-in-depth predicate matching the controllers
/// is_routable_cluster_ip. Headless services use the literal string
/// "None" for clusterIP, which is API-valid but business-invalid for
/// the brokers svc_ip-keyed table — every headless service would
/// collide on the same PK row. The controller already filters these
/// out at the source; this is the brokers backstop for any other
/// writer (a future tool, a hand-rolled curl, an out-of-band
/// migration script) that bypasses the controller path.
pub(crate) fn is_routable_svc_ip(s: &str) -> bool {
    !s.is_empty() && s != "None"
}

#[post("/svc/spec")]
pub async fn add_svc_details(
    pool: web::Data<DbPool>,
    form: web::Json<SvcDetail>,
) -> Result<HttpResponse, Error> {
    // debug not info — fires once per Service event from the
    // controller's watcher. Same INFO-reservation discipline as the
    // pod_traffic / pod_details / svc_details upsert logs below.
    debug!("Insert Service details table");
    if !is_routable_svc_ip(&form.svc_ip) {
        // Log at warn so the case is greppable in broker logs but
        // dont 400 — keeping the response shape preserves caller
        // idempotency. The controller filters these out at source;
        // this branch should be unreachable in normal operation.
        tracing::warn!(
            svc_ip = %form.svc_ip,
            svc_name = ?form.svc_name,
            "skipping svc_details upsert for non-routable cluster IP (headless/ExternalName)"
        );
        return Ok(HttpResponse::Ok().json(form.0));
    }
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        upsert_svc_details(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(pods))
}

pub fn upsert_svc_details(
    conn: &mut PgConnection,
    mut w: web::Json<SvcDetail>,
) -> Result<SvcDetail, DbError> {
    use schema::svc_details::dsl::*;
    // Slim the Service manifest before storage: consumers read spec.selector
    // and spec.ports, so keep spec and drop status/managedFields here.
    if let Some(obj) = w.service_spec.as_mut() {
        crate::get::compact_svc_spec(obj);
    }
    debug!(
        "storing the service details {:?} into svc_details table",
        w.svc_ip,
    );
    diesel::insert_into(svc_details)
        .values(&*w)
        .on_conflict(svc_ip)
        .do_update()
        .set(&*w)
        .execute(conn)?;
    // debug not info — same per-event rate concern as the pod_details
    // upsert above. Service watch events drive this on every Service
    // create / update / status change.
    debug!("Success: svc {:?} inserted in svc_details table", w.svc_ip);
    Ok(w.0)
}

impl PodInputSyscalls {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<PodSyscalls>, DbError> {
        use schema::pod_syscalls::dsl::*;

        debug!(
            "pod_name: {:?}, pod_namespace: {:?}, syscalls: {:?}, arch: {:?}",
            &self.pod_name, &self.pod_namespace, &self.syscalls, &self.arch
        );

        let row = pod_syscalls
            .filter(pod_name.eq(&self.pod_name))
            .filter(pod_namespace.eq(&self.pod_namespace))
            .filter(arch.eq(&self.arch))
            .first::<PodSyscalls>(conn)
            .optional()?;

        Ok(row)
    }
}

#[post("/pod/syscalls")]
pub async fn add_pods_syscalls(
    pool: web::Data<DbPool>,
    form: web::Json<Vec<PodInputSyscalls>>,
) -> Result<HttpResponse, Error> {
    debug!("processing /pod/syscalls batch");
    web::block(move || {
        let mut conn = pool.get()?;
        create_pod_syscalls(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(()))
}

pub fn create_pod_syscalls(
    conn: &mut PgConnection,
    w: web::Json<Vec<PodInputSyscalls>>,
) -> Result<(), DbError> {
    use schema::pod_syscalls::dsl::*;

    conn.transaction(|conn| {
        for pod_syscall in w.iter() {
            // Skip entries with empty/whitespace pod_name — same
            // defense as the /pod/spec guard (commit 66090aed) and
            // the symmetric one in mark_pod_as_dead (7eb9bf00).
            // pod_name is the table PK; an empty value would create
            // a sentinel row that subsequent batches' "is there
            // already a syscall row for X?" lookups could collide
            // with. Skip per-entry rather than failing the whole
            // batch — controllers send these in batches and one bad
            // entry shouldn't lose the rest.
            if pod_syscall.pod_name.trim().is_empty() {
                tracing::warn!(
                    pod_namespace = %pod_syscall.pod_namespace,
                    "skipping syscall entry with empty/whitespace pod_name"
                );
                continue;
            }
            debug!("storing pod_syscalls entry for {:?}", pod_syscall.pod_name);

            let existing_row = pod_syscall.get_row(conn)?;
            let new_syscall_number = pod_syscall.syscalls.join(",");

            if let Some(mut row) = existing_row {
                row.syscalls = new_syscall_number;

                diesel::update(pod_syscalls.filter(pod_name.eq(&row.pod_name)))
                    .set(syscalls.eq(row.syscalls.clone()))
                    .execute(conn)?;
            } else {
                let new_pod_syscall = PodSyscalls {
                    syscalls: new_syscall_number,
                    pod_name: pod_syscall.pod_name.clone(),
                    pod_namespace: pod_syscall.pod_namespace.clone(),
                    arch: pod_syscall.arch.clone(),
                    time_stamp: pod_syscall.time_stamp,
                };

                diesel::insert_into(pod_syscalls)
                    .values(&new_pod_syscall)
                    .execute(conn)?;
            }

            debug!(
                "Success: pod {:?} processed in pod_syscalls table",
                pod_syscall.pod_name
            );
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // MarkDeadRequest deserialization is the wire-format contract
    // between the controllers reconciler and the brokers
    // /pod/mark_dead endpoint. Pin both shapes — pre-fix
    // (pod_name only) and post-fix (pod_name + pod_ip) — so a future
    // refactor that renames the field, or changes the pod_ip flag
    // from optional to required, shows up as a test failure rather
    // than a silent regression on a fleet of mixed-version controllers.

    #[test]
    fn mark_dead_request_legacy_shape_pod_name_only() {
        // Pre-fix wire: controllers running an old version send only
        // pod_name. Must still deserialise cleanly.
        let json = r#"{"pod_name":"web-1"}"#;
        let got: MarkDeadRequest = serde_json::from_str(json).expect("decode");
        assert_eq!(got.pod_name, "web-1");
        assert_eq!(got.pod_ip, None);
    }

    #[test]
    fn mark_dead_request_new_shape_with_pod_ip() {
        // Post-fix wire: controllers post-iteration-66 include pod_ip.
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5"}"#;
        let got: MarkDeadRequest = serde_json::from_str(json).expect("decode");
        assert_eq!(got.pod_name, "web-1");
        assert_eq!(got.pod_ip.as_deref(), Some("10.42.3.5"));
    }

    #[test]
    fn mark_dead_request_pod_ip_explicit_null_treated_as_none() {
        // A JSON `null` for pod_ip should also produce None.
        // serde's Option<String> with default handles both
        // missing and explicit null this way.
        let json = r#"{"pod_name":"web-1","pod_ip":null}"#;
        let got: MarkDeadRequest = serde_json::from_str(json).expect("decode");
        assert_eq!(got.pod_ip, None);
    }

    #[test]
    fn mark_dead_request_rejects_missing_pod_name() {
        // pod_name is REQUIRED — without it the broker has nothing
        // to filter on at all (neither the precise path nor the
        // legacy fallback can run). Must reject at parse time.
        let json = r#"{"pod_ip":"10.42.3.5"}"#;
        let got: Result<MarkDeadRequest, _> = serde_json::from_str(json);
        assert!(
            got.is_err(),
            "missing pod_name must fail to decode, got {:?}",
            got
        );
    }

    // is_routable_svc_ip mirrors the controllers
    // is_routable_cluster_ip — defence-in-depth at the broker for any
    // writer that bypasses the controller path. Mirroring the test
    // shape too so a future divergence between the two predicates
    // shows up loudly.

    #[test]
    fn routable_svc_ip_accepts_real_ips() {
        assert!(is_routable_svc_ip("10.96.0.1"));
        assert!(is_routable_svc_ip("192.168.1.100"));
        assert!(is_routable_svc_ip("172.20.0.10"));
        assert!(is_routable_svc_ip("fd00::1"));
    }

    #[test]
    fn routable_svc_ip_rejects_headless_sentinel() {
        // The bug case: headless services use the literal string
        // "None" for clusterIP. Without this filter every headless
        // service would collide on svc_ip="None" in svc_details.
        assert!(!is_routable_svc_ip("None"));
    }

    #[test]
    fn routable_svc_ip_rejects_empty() {
        // ExternalName services + pre-allocation state.
        assert!(!is_routable_svc_ip(""));
    }

    #[test]
    fn routable_svc_ip_is_case_sensitive_on_none() {
        // Lowercase variants are malformed input, not the headless
        // sentinel — let them through here so subsequent validation
        // (e.g. an inet parse on the postgres side) can flag them.
        assert!(is_routable_svc_ip("none"));
        assert!(is_routable_svc_ip("NONE"));
    }

    // traffic_content_key drives the in-batch dedup in
    // create_pod_traffic_batch. The DB path itself needs a live
    // PostgreSQL (not available in unit tests), but the key is the part
    // most prone to regression: include the wrong column and the dedup
    // either over-merges distinct flows or fails to collapse repeats.
    fn sample_traffic(uuid: &str) -> PodTraffic {
        PodTraffic {
            uuid: uuid.to_string(),
            pod_name: Some("web-1".to_string()),
            pod_namespace: Some("prod".to_string()),
            pod_ip: Some("10.0.0.1".to_string()),
            pod_port: Some("8080".to_string()),
            ip_protocol: Some("TCP".to_string()),
            traffic_type: Some("EGRESS".to_string()),
            traffic_in_out_ip: Some("10.0.0.2".to_string()),
            traffic_in_out_port: Some("443".to_string()),
            decision: Some("ALLOW".to_string()),
            time_stamp: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        }
    }

    #[test]
    fn content_key_ignores_uuid_and_timestamp() {
        // eBPF re-emits the same flow every cycle with a fresh uuid and
        // timestamp; those repeats must share a content key so the
        // in-batch dedup collapses them to one insert + one audit eval.
        let a = sample_traffic("uuid-a");
        let mut b = sample_traffic("uuid-b");
        b.time_stamp = chrono::NaiveDate::from_ymd_opt(2026, 6, 30)
            .unwrap()
            .and_hms_opt(12, 34, 56)
            .unwrap();
        assert_eq!(traffic_content_key(&a), traffic_content_key(&b));
    }

    #[test]
    fn content_key_distinguishes_real_flow_differences() {
        // A different peer port is a genuinely distinct flow and must
        // NOT be collapsed — guards against an over-broad key.
        let a = sample_traffic("x");
        let mut b = sample_traffic("y");
        b.traffic_in_out_port = Some("8443".to_string());
        assert_ne!(traffic_content_key(&a), traffic_content_key(&b));
    }
}

// ── L7 HTTP traffic ──────────────────────────────────────────────────────────

#[post("/pod/l7traffic/batch")]
pub async fn add_pod_l7traffic_batch(
    pool: web::Data<DbPool>,
    form: web::Json<Vec<HttpPodTraffic>>,
) -> Result<HttpResponse, Error> {
    let count = form.len();
    debug!("Received batch of {} HTTP traffic events", count);

    let result = web::block(move || {
        let mut conn = pool.get()?;
        create_http_traffic_batch(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    info!("Successfully inserted {} HTTP traffic events", result);
    Ok(HttpResponse::Ok().json(result))
}

fn create_http_traffic_batch(
    conn: &mut PgConnection,
    batch: web::Json<Vec<HttpPodTraffic>>,
) -> Result<usize, DbError> {
    use schema::pod_http_traffic::dsl::*;

    if batch.is_empty() {
        return Ok(0);
    }

    // Dedup is enforced by the pod_http_traffic_content_uidx unique index on the
    // content columns. ON CONFLICT DO NOTHING collapses duplicates atomically —
    // within this batch and across concurrent batches / controller restarts —
    // so we no longer need the racy check-then-insert (SELECT exists then
    // INSERT) that let two concurrent batches both insert the same flow.
    let inserted = diesel::insert_into(pod_http_traffic)
        .values(batch.as_slice())
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Inserted {} HTTP traffic events (skipped {} duplicates)",
        inserted,
        batch.len() - inserted,
    );
    Ok(inserted)
}
