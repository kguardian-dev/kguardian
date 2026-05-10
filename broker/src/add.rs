use crate::{schema, AuditClient, PodDetail, PodInputSyscalls, PodSyscalls, PodTraffic, SvcDetail};
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

    // Fire-and-forget audit eval ONLY for events that were actually new.
    // Each evaluation runs on its own tokio task so a busy batch doesn't
    // serialise 100 sequential 500ms HTTP round-trips on one worker.
    if audit.enabled() {
        for event in inserted.iter().cloned() {
            let audit_client = audit.get_ref().clone();
            let pool_for_audit = pool.get_ref().clone();
            actix_web::rt::spawn(async move {
                audit_client.evaluate_and_persist(pool_for_audit, event).await;
            });
        }
    }

    // Wire format unchanged: respond with the count of newly-inserted
    // rows (a usize JSON-encoded as a number). The controllers caller
    // discards the body, so we could return more — but tightening the
    // wire is a separate concern.
    Ok(HttpResponse::Ok().json(inserted.len()))
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
    for event in batch.iter() {
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

    // Fire audit eval ONLY for new events. The pre-fix code cloned
    // the form unconditionally and spawned the audit task even when
    // create_pod_traffic deduped — wasting evaluator capacity on
    // already-seen flows. Same class of fix as the batch endpoint.
    if audit.enabled() {
        if let Some(event) = inserted.clone() {
            let audit_client = audit.get_ref().clone();
            let pool_for_audit = pool.get_ref().clone();
            actix_web::rt::spawn(async move {
                audit_client.evaluate_and_persist(pool_for_audit, event).await;
            });
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
    debug!(
        "storing the pod details {:?} into pod_traffic table",
        w.uuid
    );
    if w.get_row(conn)?.is_none() {
        info!("Insert pod {:?}, in pod_traffic table", w.uuid);
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

        debug!("pod_ip {:?}\n pod_port {:?}\n pod_trafic_type {:?}\n traffic_in_out_ip {:?}\n traffic_in_out_port {:?}\n decision {:?}\n_", &self.pod_ip, &self.pod_port,&self.traffic_type,&self.traffic_in_out_ip,&self.traffic_in_out_port,&self.decision);
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
    w: web::Json<PodDetail>,
) -> Result<PodDetail, DbError> {
    use schema::pod_details::dsl::*;
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
    info!("Success: pod {:?} inserted in pod_details table", w.pod_ip);
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
    info!("Insert Service details table");
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
    w: web::Json<SvcDetail>,
) -> Result<SvcDetail, DbError> {
    use schema::svc_details::dsl::*;
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
    info!("Success: svc {:?} inserted in svc_details table", w.svc_ip);
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
    debug!("Insert pod syscall details table");
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        create_pod_syscalls(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(pods))
}

pub fn create_pod_syscalls(
    conn: &mut PgConnection,
    w: web::Json<Vec<PodInputSyscalls>>,
) -> Result<(), DbError> {
    use schema::pod_syscalls::dsl::*;

    conn.transaction(|conn| {
        for pod_syscall in w.iter() {
            debug!(
                "Storing pod details {:?} into pod_syscalls table",
                pod_syscall.pod_name
            );

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
        assert!(got.is_err(), "missing pod_name must fail to decode, got {:?}", got);
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
}
