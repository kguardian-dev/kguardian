use crate::ip::{canonical_ip, canonicalise_opt};
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

/// Canonicalise the two IP columns of every event in an ingest batch,
/// in place.
///
/// This has to run ahead of the dedup, not just ahead of the insert.
/// `traffic_content_key` and `PodTraffic::get_row` both compare these
/// strings, so the same IPv6 flow rendered "FD00::1" on one eBPF emit
/// and "fd00::1" on the next looks like two distinct flows — duplicate
/// rows in pod_traffic AND a duplicate evaluator round-trip for each.
///
/// It also has to happen on the way IN rather than at read time:
/// `traffic_in_out_ip` is the value the advisor feeds back to
/// /pod/ip/<ip> and /svc/ip/<ip> to resolve a peer, so the stored form
/// and the looked-up form have to agree. IPv4 is unaffected —
/// canonicalisation is a no-op for it — so rows written before this
/// existed still match.
fn canonicalise_traffic_ips(batch: &mut [PodTraffic]) {
    for event in batch.iter_mut() {
        canonicalise_opt(&mut event.pod_ip);
        canonicalise_opt(&mut event.traffic_in_out_ip);
    }
}

fn create_pod_traffic_batch(
    conn: &mut PgConnection,
    mut batch: web::Json<Vec<PodTraffic>>,
) -> Result<Vec<PodTraffic>, DbError> {
    use schema::pod_traffic::dsl::*;

    if batch.is_empty() {
        return Ok(Vec::new());
    }

    debug!("Processing batch of {} network traffic events", batch.len());

    canonicalise_traffic_ips(&mut batch);

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

/// Build the `pod_ips` array stored alongside the scalar `pod_ip`.
///
/// `posted` is the optional array the controller sent; `primary` is
/// the already-canonicalised `pod_ip` for the same row. Every entry is
/// canonicalised, duplicates are collapsed, and `primary` is forced to
/// the front so the scalar column and the array can never disagree
/// about which address is the pod's primary. Non-string and blank
/// entries are dropped rather than stored — they could only ever match
/// nothing, and keeping them out means the GIN index holds addresses
/// only.
///
/// A `None` (or non-array) `posted` is the backward-compatibility
/// case, not an error: a controller predating dual-stack support posts
/// `pod_ip` alone, and the broker ships independently of it
/// (RELEASES.md). Such a pod gets `[pod_ip]`, which is exactly what
/// the migration backfilled for rows written before this column
/// existed, so the row is never left in a shape the lookup cannot
/// find.
///
/// Be clear about the cost, because this is NOT a no-op on the update
/// path. `upsert_pod_details` recomputes this column unconditionally
/// and feeds it to `on_conflict(pod_name).do_update()`, so an old
/// controller posting without the field does not merely decline to add
/// addresses — it REPLACES an existing `["10.0.0.5","fd00::5"]` with
/// `["10.0.0.5"]`, destroying a second-family address a newer
/// controller already wrote. `/pod/ip/fd00::5` then 404s and that peer
/// degrades back to an ipBlock: precisely the regression this column
/// exists to prevent.
///
/// Accepted rather than fixed, because the blast radius is bounded.
/// `update_pods_details` is driven by each node's own pod watcher, so
/// a given pod's row is only ever written by the controller on its
/// node, and the full list is restored on that controller's next watch
/// event. The window is therefore "pods on not-yet-upgraded nodes are
/// single-stack in the DB during a DaemonSet rollout", and it
/// self-heals as the rollout completes.
///
/// The alternative — treat `None` as "leave the column alone" — trades
/// away the invariant that `pod_ip` is always present in `pod_ips`,
/// which every lookup relies on. That is a design change, not an
/// obvious win, so it is deliberately not made here.
fn canonical_pod_ips(posted: Option<&serde_json::Value>, primary: &str) -> serde_json::Value {
    let mut out: Vec<String> = Vec::new();
    let mut push = |ip: &str| {
        let ip = ip.trim();
        if ip.is_empty() {
            return;
        }
        let canonical = canonical_ip(ip);
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    };
    push(primary);
    if let Some(serde_json::Value::Array(items)) = posted {
        for item in items {
            if let Some(ip) = item.as_str() {
                push(ip);
            }
        }
    }
    serde_json::Value::Array(out.into_iter().map(serde_json::Value::String).collect())
}

/// Reduce a posted `capture_level` to one of the five tier names, or
/// `None`. Trimmed and lower-cased so a chart typo in case does not
/// register as "unknown"; anything else is logged and dropped. `None`
/// is the honest answer for an unrecognised value — capture
/// completeness (which feeds the CR's `CaptureComplete` condition, the
/// export warning and drift) treats it as `low`, never as complete,
/// which is the safe direction. Because `AsChangeset` skips `None`, a
/// dropped value leaves
/// whatever the column already held rather than overwriting it.
fn normalise_capture_level(posted: Option<String>, pod: &str) -> Option<String> {
    let raw = posted?;
    let level = raw.trim().to_ascii_lowercase();
    if level.is_empty() {
        return None;
    }
    if crate::CAPTURE_LEVELS.contains(&level.as_str()) {
        Some(level)
    } else {
        tracing::warn!(
            pod,
            value = %raw,
            "unrecognised capture_level on /pod/spec; storing NULL (treated as low)"
        );
        None
    }
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
    // Canonicalise before storage so the stored spelling is the one
    // pod_ip()/svc_ip() will look up. Order matters: pod_ip has to be
    // canonical before canonical_pod_ips folds it into the array, or
    // the scalar and the array would carry different spellings of the
    // same address and the OR in the lookup would only half-work.
    w.pod_ip = canonical_ip(&w.pod_ip);
    w.pod_ips = Some(canonical_pod_ips(w.pod_ips.as_ref(), &w.pod_ip));
    w.capture_level = normalise_capture_level(w.capture_level.take(), &w.pod_name);
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
    // discipline as create_pod_traffic_batch.
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
    //
    // Canonicalise once empty is ruled out: the sanity check below is a
    // string comparison against the stored pod_ip, which the upsert
    // path writes in canonical form. An IPv6 pod whose mark_dead call
    // spelled the address differently would fail that comparison,
    // match zero rows, and leave a terminated pod marked alive —
    // resurfacing later as a phantom peer in generated policy.
    let ip = ip
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(canonical_ip);

    let updated = match ip.as_deref() {
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
    // svc_ip is the table PK and svc_ip() matches it as a string, so an
    // IPv6 ClusterIP must be stored in the same canonical form the
    // lookup normalises to. The non-routable guard in the handler above
    // has already rejected the "None" sentinel by this point; anything
    // else that fails to parse is stored verbatim, as before.
    w.svc_ip = canonical_ip(&w.svc_ip);
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
        // pod_names touched by this batch — used after the loop to
        // recompute the affected workloads' seccomp aggregates.
        let mut touched: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
            touched.insert(pod_syscall.pod_name.clone());
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

        // Roll the new syscalls up into the per-workload aggregates that
        // seccomp profiles are generated from. Same transaction as the
        // ingest so a reader never sees pod_syscalls updated without the
        // matching workload_syscalls. A pod whose pod_details row has no
        // resolved workload yet contributes to nothing here; its next
        // batch (every ~10s from the controller) will pick it up once
        // attribution lands.
        for (ns, kind, name) in crate::seccomp::affected_workloads(conn, &touched)? {
            crate::seccomp::recompute_workload(conn, &ns, &kind, &name)?;
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pod_ips (dual-stack) -------------------------------------
    //
    // canonical_pod_ips is the write half of the dual-stack fix; the
    // read half is get::pod_by_ip_query. The invariant tying them
    // together is that pod_ip is always present in pod_ips and both
    // are canonical, so the OR in the lookup can never match one and
    // miss the other.

    fn ips(v: &serde_json::Value) -> Vec<String> {
        v.as_array()
            .expect("pod_ips must be a JSON array")
            .iter()
            .map(|x| x.as_str().expect("entries must be strings").to_string())
            .collect()
    }

    #[test]
    fn pod_ips_absent_falls_back_to_pod_ip() {
        // The backward-compatibility case: a controller predating
        // dual-stack support posts pod_ip alone. It must keep working
        // against this broker, and the row it writes must be
        // indistinguishable from what the migration backfilled.
        let got = canonical_pod_ips(None, "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5"]);
    }

    #[test]
    fn pod_ips_non_array_falls_back_to_pod_ip() {
        // A malformed payload should degrade to the single-stack
        // behaviour rather than store something the lookup can't match.
        for junk in [
            serde_json::Value::Null,
            serde_json::json!("10.42.3.5"),
            serde_json::json!({"v4": "10.42.3.5"}),
        ] {
            let got = canonical_pod_ips(Some(&junk), "10.42.3.5");
            assert_eq!(ips(&got), vec!["10.42.3.5"], "junk payload {junk:?}");
        }
    }

    #[test]
    fn pod_ips_empty_array_falls_back_to_pod_ip() {
        let got = canonical_pod_ips(Some(&serde_json::json!([])), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5"]);
    }

    #[test]
    fn pod_ips_keeps_both_families_for_a_dual_stack_pod() {
        // The case the whole change exists for.
        let posted = serde_json::json!(["10.42.3.5", "fd00::5"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fd00::5"]);
    }

    #[test]
    fn pod_ips_canonicalises_every_entry() {
        // Entries arrive as whatever the source rendered. They are
        // matched by JSONB containment against a canonicalised probe,
        // so a non-canonical entry in the array is an entry that can
        // never be found.
        let posted = serde_json::json!(["10.42.3.5", "FD00:0:0:0:0:0:0:5", "2001:0DB8::0:1"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fd00::5", "2001:db8::1"]);
    }

    #[test]
    fn pod_ips_always_leads_with_the_primary_address() {
        // pod_ip and pod_ips[0] must agree on the primary, so the two
        // halves of the lookup's OR can't disagree about which pod an
        // address belongs to. Even if the controller orders podIPs
        // differently, or omits the primary entirely.
        let posted = serde_json::json!(["fd00::5", "10.42.3.5"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fd00::5"]);

        let posted = serde_json::json!(["fd00::5"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fd00::5"]);
    }

    #[test]
    fn pod_ips_collapses_duplicates_including_spelling_variants() {
        // Two spellings of one address are one address; storing both
        // would bloat the GIN index with entries that can never match
        // independently.
        let posted = serde_json::json!(["10.42.3.5", "FD00::5", "fd00:0:0:0:0:0:0:5", "fd00::5"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fd00::5"]);
    }

    #[test]
    fn pod_ips_drops_blank_and_non_string_entries() {
        // Keep the index holding addresses only — these could match
        // nothing anyway.
        let posted = serde_json::json!(["", "   ", 42, null, {"ip": "x"}, "fd00::5"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fd00::5"]);
    }

    #[test]
    fn pod_ips_keeps_unparseable_entries_verbatim() {
        // Same passthrough rule as everywhere else: don't error, don't
        // rewrite. An entry that isn't an address just never matches.
        let posted = serde_json::json!(["10.42.3.5", "fe80::1%eth0"]);
        let got = canonical_pod_ips(Some(&posted), "10.42.3.5");
        assert_eq!(ips(&got), vec!["10.42.3.5", "fe80::1%eth0"]);
    }

    #[test]
    fn pod_ips_tolerates_a_blank_primary() {
        // PodDetail::default() and degenerate callers produce an empty
        // pod_ip; it must not become an empty-string array entry.
        let posted = serde_json::json!(["fd00::5"]);
        let got = canonical_pod_ips(Some(&posted), "");
        assert_eq!(ips(&got), vec!["fd00::5"]);
        assert_eq!(ips(&canonical_pod_ips(None, "")), Vec::<String>::new());
    }

    // ---- pod_traffic ingest canonicalisation ----------------------

    fn traffic(pod_ip: &str, peer_ip: &str) -> PodTraffic {
        PodTraffic {
            uuid: "u".to_string(),
            pod_ip: Some(pod_ip.to_string()),
            traffic_in_out_ip: Some(peer_ip.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn traffic_ingest_canonicalises_both_ip_columns() {
        let mut batch = vec![traffic("FD00::1", "FD00:0:0:0:0:0:0:2")];
        canonicalise_traffic_ips(&mut batch);
        assert_eq!(batch[0].pod_ip.as_deref(), Some("fd00::1"));
        assert_eq!(batch[0].traffic_in_out_ip.as_deref(), Some("fd00::2"));
    }

    #[test]
    fn traffic_ingest_leaves_ipv4_and_nulls_alone() {
        let mut batch = vec![
            traffic("10.0.0.1", "10.0.0.2"),
            PodTraffic {
                uuid: "u2".to_string(),
                ..Default::default()
            },
        ];
        canonicalise_traffic_ips(&mut batch);
        assert_eq!(batch[0].pod_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(batch[0].traffic_in_out_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(batch[1].pod_ip, None);
        assert_eq!(batch[1].traffic_in_out_ip, None);
    }

    #[test]
    fn traffic_ingest_makes_ipv6_spelling_variants_dedup_together() {
        // The point of canonicalising BEFORE the dedup: two emits of
        // one flow, spelled differently, must collapse to a single
        // content key — otherwise they double-insert and double-fire
        // the audit evaluator.
        let mut batch = vec![
            traffic("FD00::1", "fd00:0:0:0:0:0:0:2"),
            traffic("fd00:0000:0000:0000:0000:0000:0000:0001", "FD00::2"),
        ];
        assert_ne!(
            traffic_content_key(&batch[0]),
            traffic_content_key(&batch[1]),
            "precondition: raw spellings look like different flows"
        );
        canonicalise_traffic_ips(&mut batch);
        assert_eq!(
            traffic_content_key(&batch[0]),
            traffic_content_key(&batch[1]),
            "after canonicalisation the two emits must be one flow"
        );
    }

    // PodDetail wire compatibility. Broker and controller are released
    // independently (RELEASES.md), so the /pod/spec payload must
    // deserialise with and without the new field.

    #[test]
    fn pod_detail_accepts_payload_without_pod_ips() {
        // Pre-dual-stack controller. Must not 400.
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":"prod",
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null}"#;
        let got: PodDetail = serde_json::from_str(json).expect("must parse without pod_ips");
        assert_eq!(got.pod_ip, "10.42.3.5");
        assert!(
            got.pod_ips.is_none(),
            "missing field must deserialise to None"
        );
    }

    #[test]
    fn pod_detail_accepts_payload_with_workload() {
        // Controller new enough to resolve the owning workload.
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":"prod",
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null,
            "workload_kind":"Deployment","workload_name":"web"}"#;
        let got: PodDetail = serde_json::from_str(json).expect("must parse with workload fields");
        assert_eq!(got.workload_kind.as_deref(), Some("Deployment"));
        assert_eq!(got.workload_name.as_deref(), Some("web"));
    }

    #[test]
    fn pod_detail_accepts_payload_without_workload() {
        // Controller predating workload attribution, or a bare pod.
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":"prod",
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null}"#;
        let got: PodDetail =
            serde_json::from_str(json).expect("must parse without workload fields");
        assert!(got.workload_kind.is_none() && got.workload_name.is_none());
    }

    #[test]
    fn pod_detail_accepts_payload_with_capture_level() {
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":"prod",
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null,
            "workload_kind":"Deployment","workload_name":"web","capture_level":"high"}"#;
        let got: PodDetail = serde_json::from_str(json).expect("must parse with capture_level");
        assert_eq!(got.capture_level.as_deref(), Some("high"));
    }

    #[test]
    fn pod_detail_capture_level_defaults_to_none_for_older_controllers() {
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":"prod",
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null}"#;
        let got: PodDetail = serde_json::from_str(json).unwrap();
        assert!(got.capture_level.is_none());
    }

    #[test]
    fn normalise_capture_level_accepts_the_five_tiers_case_insensitively() {
        for (input, want) in [
            ("full", "full"),
            ("High", "high"),
            (" medium ", "medium"),
            ("LOW", "low"),
            ("custom", "custom"),
        ] {
            assert_eq!(
                normalise_capture_level(Some(input.to_string()), "p").as_deref(),
                Some(want),
                "{input:?}"
            );
        }
    }

    #[test]
    fn normalise_capture_level_drops_unknown_and_blank() {
        assert!(normalise_capture_level(None, "p").is_none());
        assert!(normalise_capture_level(Some("".into()), "p").is_none());
        assert!(normalise_capture_level(Some("   ".into()), "p").is_none());
        assert!(normalise_capture_level(Some("ultra".into()), "p").is_none());
        assert!(normalise_capture_level(Some("full;drop".into()), "p").is_none());
    }

    #[test]
    fn pod_detail_accepts_payload_with_pod_ips() {
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":"prod",
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null,
            "pod_ips":["10.42.3.5","fd00::5"]}"#;
        let got: PodDetail = serde_json::from_str(json).expect("must parse with pod_ips");
        assert_eq!(
            ips(&got.pod_ips.expect("pod_ips present")),
            vec!["10.42.3.5", "fd00::5"]
        );
    }

    #[test]
    fn pod_detail_accepts_explicit_null_pod_ips() {
        let json = r#"{"pod_name":"web-1","pod_ip":"10.42.3.5","pod_namespace":null,
            "pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a",
            "is_dead":false,"pod_identity":null,"workload_selector_labels":null,
            "pod_ips":null}"#;
        let got: PodDetail = serde_json::from_str(json).expect("must parse with null pod_ips");
        assert!(got.pod_ips.is_none());
    }

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

/// Upsert one node's coarse environment facts (see NodeFact). Called by
/// the controller once per start; the telemetry check-in aggregates the
/// table. Light validation only — the version service re-whitelists
/// every value before anything is recorded upstream.
#[post("/node/facts")]
pub async fn add_node_facts(
    pool: web::Data<DbPool>,
    form: web::Json<crate::NodeFact>,
) -> Result<HttpResponse, Error> {
    let fact = form.into_inner();
    if fact.node_name.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().body("node_name must not be empty"));
    }
    // Enum fields are short fixed strings; anything oversized is junk
    // (the broker API is in-cluster but unauthenticated by default).
    let fields = [
        &fact.node_name,
        &fact.provider,
        &fact.distro,
        &fact.cni,
        &fact.ip_family,
        &fact.node_os,
    ];
    if fields.iter().any(|f| f.len() > 253) {
        return Ok(HttpResponse::BadRequest().body("field too long"));
    }
    web::block(move || -> Result<(), DbError> {
        use schema::node_facts::dsl::*;
        let mut conn = pool.get()?;
        diesel::insert_into(node_facts)
            .values(&fact)
            .on_conflict(node_name)
            .do_update()
            .set(&fact)
            .execute(&mut conn)?;
        Ok(())
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    debug!("node facts upserted");
    Ok(HttpResponse::Ok().json(()))
}
