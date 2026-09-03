//! Peer identity: who was behind `traffic_in_out_ip` when the flow was
//! observed.
//!
//! `pod_traffic` used to store only the peer's IP, and every consumer
//! resolved IP → pod at READ time against `pod_details` — a table keyed
//! by pod_name and upserted, so it only ever knows who holds an address
//! NOW. Pod IPs are recycled constantly (hourly volsync Jobs, migration
//! Jobs; one address on cluster-00 had 50+ dead owners), so a flow from
//! July resolved to whichever pod holds the address in September: the
//! map drew `autobrr → cmangos-database` for rows that predate autobrr
//! by weeks, and Job labels (`job-name`, `controller-uid`) leaked into
//! generated policies.
//!
//! The fix is the one Cilium Hubble uses: stamp the peer's identity on
//! the flow when it is captured and never recompute it from the IP.
//! Three pieces, all here:
//!
//! 1. **Resolve at ingest.** `create_pod_traffic_batch` calls
//!    [`resolve_batch`] before the insert: one candidate lookup per
//!    DISTINCT peer IP in the batch (not per row), then a pure
//!    per-row choice under the start-time guard.
//! 2. **Late-resolve pass.** [`spawn`] re-resolves rows whose peer is
//!    still NULL and whose `time_stamp` is inside a short window
//!    (`PEER_LATE_RESOLVE_WINDOW_SECS`, default 600) every
//!    `PEER_LATE_RESOLVE_INTERVAL_SECS` (default 60). This covers the
//!    race where the flow arrives before the peer pod's `/pod/spec`.
//!    Rows that age out unresolved stay NULL forever.
//! 3. **Start-time guard.** [`choose_pod`] never picks a pod whose
//!    `started_at` is later than the flow's `time_stamp`, nor one whose
//!    start is unknown (NULL = never re-posted since the upgrade, i.e.
//!    a ghost, or Pending). The same function backs
//!    `GET /pod/ip/{ip}?at=`, so the by-IP fallback for rows with no
//!    stored peer applies the identical rule.
//! 4. **Stale-alive sweep.** The controller re-posts every live pod on
//!    each 60 s resync; a row still `is_dead=false` but untouched for
//!    `PEER_STALE_ALIVE_SECS` (default 900) is a ghost from a controller
//!    restart and gets marked dead, so it stops being a "live" by-IP
//!    candidate for a recycled address.
//!
//! Precedence, given the guard: a live pod holding the IP > the dead
//! pod with the newest start ≤ the flow time > a Service ClusterIP >
//! nothing (NULL). A host-network pod resolves as `peer_kind = "node"`
//! (its address is the node's), carrying the pod's identity.
//!
//! What is deliberately NOT written: `external`. An unmatched peer is
//! left NULL rather than stamped external, because "no match in the
//! window" and "external" are indistinguishable from inside the broker
//! (a controller restart on the peer's node can delay its spec past
//! any window), and a NULL row keeps the guarded by-IP fallback while
//! a stamped `external` would take it away for good.

use crate::{schema, PodDetail, PodTraffic, SvcDetail};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// `peer_kind` for a pod-network pod.
pub const PEER_KIND_POD: &str = "pod";
/// `peer_kind` for a host-network pod: the IP is a node IP.
pub const PEER_KIND_NODE: &str = "node";
/// `peer_kind` for a Service ClusterIP.
pub const PEER_KIND_SERVICE: &str = "service";

/// Default late-resolve window: rows younger than this with a NULL
/// peer are retried. 10 minutes comfortably covers a pod-watcher event
/// racing an eBPF flow, plus a controller restart.
const DEFAULT_WINDOW_SECS: u64 = 600;
/// Default cadence of the late-resolve pass.
const DEFAULT_INTERVAL_SECS: u64 = 60;
/// Floor for the interval — below this the pass is pure DB churn.
const MIN_INTERVAL_SECS: u64 = 5;
/// Rows re-resolved per pass. Unresolved rows in the window are mostly
/// genuinely external peers (DNS, internet) that never resolve; the cap
/// bounds one pass regardless of how many there are. Generous, and
/// paired with OLDEST-first ordering so the pass drains FIFO: a
/// resolvable row can only be deferred, never starved out of the
/// window by newer noise (see `pending_rows_query`).
const MAX_ROWS_PER_PASS: i64 = 20_000;

/// The identity stamped on a `pod_traffic` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub kind: String,
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub uid: Option<String>,
    pub workload_kind: Option<String>,
    pub workload_name: Option<String>,
}

impl PeerIdentity {
    fn from_pod(pod: &PodDetail) -> Self {
        let kind = if pod.host_network == Some(true) {
            PEER_KIND_NODE
        } else {
            PEER_KIND_POD
        };
        PeerIdentity {
            kind: kind.to_string(),
            namespace: pod.pod_namespace.clone(),
            name: Some(pod.pod_name.clone()),
            uid: manifest_uid(pod.pod_obj.as_ref()),
            workload_kind: pod.workload_kind.clone(),
            workload_name: pod.workload_name.clone(),
        }
    }

    fn from_service(svc: &SvcDetail) -> Self {
        PeerIdentity {
            kind: PEER_KIND_SERVICE.to_string(),
            namespace: svc.svc_namespace.clone(),
            name: svc.svc_name.clone(),
            uid: manifest_uid(svc.service_spec.as_ref()),
            workload_kind: None,
            workload_name: None,
        }
    }

    /// Write this identity onto a traffic row (or clear it when `None`).
    /// Always overwrites: the broker is the authority for these columns,
    /// whatever a client put in the POST body.
    pub fn apply(this: Option<&PeerIdentity>, row: &mut PodTraffic, resolved_at: NaiveDateTime) {
        match this {
            Some(p) => {
                row.peer_kind = Some(p.kind.clone());
                row.peer_namespace = p.namespace.clone();
                row.peer_name = p.name.clone();
                row.peer_uid = p.uid.clone();
                row.peer_workload_kind = p.workload_kind.clone();
                row.peer_workload_name = p.workload_name.clone();
                row.peer_resolved_at = Some(resolved_at);
            }
            None => {
                row.peer_kind = None;
                row.peer_namespace = None;
                row.peer_name = None;
                row.peer_uid = None;
                row.peer_workload_kind = None;
                row.peer_workload_name = None;
                row.peer_resolved_at = None;
            }
        }
    }
}

/// `metadata.uid` from a stored Pod or Service manifest. `compact_pod_obj`
/// / `compact_svc_spec` keep `metadata` (minus managedFields), so the uid
/// survives to storage whenever the controller posted a real manifest.
fn manifest_uid(obj: Option<&serde_json::Value>) -> Option<String> {
    obj?.pointer("/metadata/uid")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Everything that currently claims one IP, fetched once per distinct
/// address and then reused for every row in the batch that names it.
#[derive(Debug, Default)]
pub struct Candidates {
    pub pods: Vec<PodDetail>,
    pub service: Option<SvcDetail>,
}

/// Load every `pod_details` row holding `ip` (scalar `pod_ip` OR
/// `pod_ips` membership — the same predicate as `GET /pod/ip/{ip}`) and
/// the Service with that ClusterIP, if any.
pub fn load_candidates(conn: &mut PgConnection, ip: &str) -> Result<Candidates, DbError> {
    let pods = crate::get::pod_candidates_by_ip(conn, ip)?;
    let service = crate::get::svc_ip(conn, ip)?;
    Ok(Candidates { pods, service })
}

/// The start-time guard: `pod` may be the peer of a flow observed at
/// `at` only if it is KNOWN to have started by then.
///
/// An unknown start (`None`) is excluded, not merely ranked last. The
/// broker derives `started_at` from the `status.startTime` the
/// controller posts, and the controller re-posts every live pod within
/// 60 s of a resync, so after the upgrade every genuinely live pod has
/// one. A row still NULL is therefore a ghost — a pod that no longer
/// exists but was never marked dead (seen live on cluster-00: 33
/// `is_dead=false` rows from a July controller restart, one of which
/// kept absorbing old flows under the earlier "rank last" rule) — or a
/// Pending pod that has no address to be a peer with yet. Neither may
/// attribute a flow.
pub fn passes_guard(pod: &PodDetail, at: NaiveDateTime) -> bool {
    pod.started_at.is_some_and(|s| s <= at)
}

/// Pick the pod that held the address at `at`, from all rows that hold
/// it now or held it once.
///
/// Order: live pods first (an address a live pod holds now has been its
/// since it started, so if it started before `at` it was the holder at
/// `at`), then dead pods by newest `started_at` — IP owners are
/// sequential in time, so the pod that started most recently before
/// the flow is the most likely holder — then newest `time_stamp`, then
/// name for determinism. Anything that fails the guard (started after
/// `at`, or start unknown) is skipped outright; `None` when nothing
/// survives it.
pub fn choose_pod(pods: &[PodDetail], at: NaiveDateTime) -> Option<&PodDetail> {
    let mut eligible: Vec<&PodDetail> = pods.iter().filter(|p| passes_guard(p, at)).collect();
    eligible.sort_by(|a, b| {
        a.is_dead
            .cmp(&b.is_dead)
            .then_with(|| b.started_at.cmp(&a.started_at))
            .then_with(|| b.time_stamp.cmp(&a.time_stamp))
            .then_with(|| a.pod_name.cmp(&b.pod_name))
    });
    eligible.into_iter().next()
}

/// Full precedence for one flow: pod (live > dead, under the guard) →
/// Service → nothing.
pub fn choose(cands: &Candidates, at: NaiveDateTime) -> Option<PeerIdentity> {
    if let Some(pod) = choose_pod(&cands.pods, at) {
        return Some(PeerIdentity::from_pod(pod));
    }
    cands.service.as_ref().map(PeerIdentity::from_service)
}

/// Resolve the peer of every row in `rows`, in place. One candidate
/// lookup per distinct `traffic_in_out_ip`; the per-row choice is pure.
/// Rows with no peer IP, or whose IP matches nothing, get every
/// `peer_*` column cleared (NULL), never a client-supplied value.
pub fn resolve_batch(conn: &mut PgConnection, rows: &mut [PodTraffic]) -> Result<(), DbError> {
    let now = chrono::Utc::now().naive_utc();
    let mut by_ip: HashMap<String, Candidates> = HashMap::new();
    for row in rows.iter() {
        if let Some(ip) = row.traffic_in_out_ip.as_deref() {
            if !by_ip.contains_key(ip) {
                by_ip.insert(ip.to_string(), load_candidates(conn, ip)?);
            }
        }
    }
    for row in rows.iter_mut() {
        let identity = row
            .traffic_in_out_ip
            .as_deref()
            .and_then(|ip| by_ip.get(ip))
            .and_then(|c| choose(c, row.time_stamp));
        PeerIdentity::apply(identity.as_ref(), row, now);
    }
    Ok(())
}

/// Late-resolve window (seconds); `0` disables the task entirely.
fn window_secs() -> u64 {
    std::env::var("PEER_LATE_RESOLVE_WINDOW_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS)
}

/// Late-resolve cadence, floored so a typo cannot turn it into a busy
/// loop against the table.
fn interval() -> Duration {
    let secs = std::env::var("PEER_LATE_RESOLVE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs.max(MIN_INTERVAL_SECS))
}

/// The oldest `time_stamp` the late-resolve pass still retries as of
/// `now`. Pure so the boundary is unit-testable: exactly `window` old
/// is still in; anything older is out.
pub fn window_cutoff(now: NaiveDateTime, window: Duration) -> NaiveDateTime {
    now - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::zero())
}

/// Stale-alive threshold (seconds): an `is_dead=false` pod_details row
/// whose `time_stamp` is older than this is marked dead. `0` disables
/// the sweep. Default 15 min = fifteen missed 60 s controller resyncs.
const DEFAULT_STALE_ALIVE_SECS: u64 = 900;

fn stale_alive_secs() -> u64 {
    std::env::var("PEER_STALE_ALIVE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_STALE_ALIVE_SECS)
}

/// The stale-alive sweep as a statement: every row still flagged alive
/// that the controller has not re-posted since `cutoff` is marked dead.
/// The controller re-posts every live pod on each 60 s resync (updating
/// `time_stamp`), so a row untouched for the threshold cannot be live —
/// it is a ghost left behind by a controller restart, and a ghost
/// holding a recycled address would otherwise be a live-pod candidate
/// for every flow to that address (`choose_pod` prefers live pods).
/// If the controller itself is down long enough to trip this, its next
/// resync re-posts `is_dead=false` and the rows come straight back.
/// A constant (and pinned by a unit test) rather than a diesel DSL
/// expression only because naming the DSL's return type is unwieldy;
/// `$1` is the cutoff, bound as a parameter.
const STALE_ALIVE_SQL: &str = "UPDATE pod_details SET is_dead = true \
     WHERE is_dead = false AND time_stamp < $1";

/// One stale-alive sweep: rows marked dead.
pub fn run_stale_alive_sweep(
    conn: &mut PgConnection,
    threshold: Duration,
) -> Result<usize, DbError> {
    let cutoff = window_cutoff(chrono::Utc::now().naive_utc(), threshold);
    Ok(diesel::sql_query(STALE_ALIVE_SQL)
        .bind::<diesel::sql_types::Timestamp, _>(cutoff)
        .execute(conn)?)
}

/// Spawn the peer maintenance loop: the late-resolve pass
/// (`PEER_LATE_RESOLVE_WINDOW_SECS`, `0` disables) and the stale-alive
/// sweep (`PEER_STALE_ALIVE_SECS`, `0` disables), both on the
/// `PEER_LATE_RESOLVE_INTERVAL_SECS` cadence. Returns immediately; the
/// task lives for the broker's lifetime. Ingest-time resolution runs
/// regardless.
pub fn spawn(pool: DbPool) {
    let window = window_secs();
    let stale = stale_alive_secs();
    if window == 0 {
        info!("peer late-resolve disabled (PEER_LATE_RESOLVE_WINDOW_SECS=0)");
    }
    if stale == 0 {
        info!("peer stale-alive sweep disabled (PEER_STALE_ALIVE_SECS=0)");
    }
    if window == 0 && stale == 0 {
        return;
    }
    let every = interval();
    info!(
        window_secs = window,
        stale_alive_secs = stale,
        interval_secs = every.as_secs(),
        "peer late-resolve / stale-alive loop scheduled"
    );
    actix_web::rt::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            if window > 0 {
                let pool = pool.clone();
                let result =
                    tokio::task::spawn_blocking(move || -> Result<(usize, usize), DbError> {
                        let mut conn = pool.get()?;
                        run_pass(&mut conn, Duration::from_secs(window))
                    })
                    .await;
                match result {
                    Ok(Ok((0, 0))) => debug!("peer late-resolve: nothing pending"),
                    Ok(Ok((scanned, resolved))) => {
                        info!(scanned, resolved, "peer late-resolve pass")
                    }
                    Ok(Err(e)) => warn!(error = %e, "peer late-resolve pass failed"),
                    Err(e) => warn!(error = %e, "peer late-resolve task panicked"),
                }
            }
            if stale > 0 {
                let pool = pool.clone();
                let result = tokio::task::spawn_blocking(move || -> Result<usize, DbError> {
                    let mut conn = pool.get()?;
                    run_stale_alive_sweep(&mut conn, Duration::from_secs(stale))
                })
                .await;
                match result {
                    Ok(Ok(0)) => debug!("peer stale-alive sweep: nothing stale"),
                    Ok(Ok(marked_dead)) => info!(
                        marked_dead,
                        stale_alive_secs = stale,
                        "peer stale-alive sweep marked ghost pods dead"
                    ),
                    Ok(Err(e)) => warn!(error = %e, "peer stale-alive sweep failed"),
                    Err(e) => warn!(error = %e, "peer stale-alive sweep panicked"),
                }
            }
        }
    });
}

/// One late-resolve pass: (rows scanned, rows resolved).
/// The rows one late-resolve pass considers: unresolved, inside the
/// window, OLDEST first. Oldest-first matters: a row nearest the cutoff
/// is the one about to age out, so under sustained unresolvable noise
/// (external IPs re-emitted every cycle) it must be tried before the
/// newer rows, or a resolvable older row could be pushed past the LIMIT
/// on every pass and leave the window NULL. With ASC + LIMIT the pass
/// drains FIFO; the cutoff bounds the set, the LIMIT bounds one pass.
/// Split out so the SQL can be pinned without a database.
fn pending_rows_query(
    cutoff: NaiveDateTime,
) -> schema::pod_traffic::BoxedQuery<'static, diesel::pg::Pg> {
    use schema::pod_traffic::dsl::*;
    pod_traffic
        .filter(peer_kind.is_null())
        .filter(traffic_in_out_ip.is_not_null())
        .filter(time_stamp.ge(cutoff))
        .order((time_stamp.asc(), uuid.asc()))
        .limit(MAX_ROWS_PER_PASS)
        .into_boxed()
}

pub fn run_pass(conn: &mut PgConnection, window: Duration) -> Result<(usize, usize), DbError> {
    use schema::pod_traffic::dsl::*;
    let cutoff = window_cutoff(chrono::Utc::now().naive_utc(), window);
    // Bounded range scan on idx_pod_traffic_time_stamp (walked backwards
    // for ASC), oldest first — see pending_rows_query.
    let mut pending: Vec<PodTraffic> = pending_rows_query(cutoff).load::<PodTraffic>(conn)?;
    if pending.is_empty() {
        return Ok((0, 0));
    }
    let scanned = pending.len();
    resolve_batch(conn, &mut pending)?;
    let mut resolved = 0usize;
    for row in pending.iter().filter(|r| r.peer_kind.is_some()) {
        // `peer_kind IS NULL` in the predicate keeps this idempotent
        // against a concurrent ingest of the same uuid (impossible today,
        // but free).
        resolved += diesel::update(
            pod_traffic
                .filter(uuid.eq(&row.uuid))
                .filter(peer_kind.is_null()),
        )
        .set((
            peer_kind.eq(&row.peer_kind),
            peer_namespace.eq(&row.peer_namespace),
            peer_name.eq(&row.peer_name),
            peer_uid.eq(&row.peer_uid),
            peer_workload_kind.eq(&row.peer_workload_kind),
            peer_workload_name.eq(&row.peer_workload_name),
            peer_resolved_at.eq(&row.peer_resolved_at),
        ))
        .execute(conn)?;
    }
    Ok((scanned, resolved))
}

/// Parse the `?at=` query value: RFC3339 (any offset, converted to UTC)
/// or the broker's own naive form (`2026-07-23T10:00:00[.ffffff]`).
pub fn parse_at(raw: &str) -> Result<NaiveDateTime, String> {
    let s = raw.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.naive_utc());
    }
    if let Ok(dt) = s.parse::<NaiveDateTime>() {
        return Ok(dt);
    }
    Err(format!(
        "invalid at={raw:?}; expected RFC3339 (2026-07-23T10:00:00Z) or naive UTC (2026-07-23T10:00:00)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> NaiveDateTime {
        s.parse().expect("test timestamp")
    }

    fn pod(name: &str, dead: bool, started: Option<&str>, seen: &str) -> PodDetail {
        PodDetail {
            pod_name: name.to_string(),
            pod_ip: "10.244.12.199".to_string(),
            pod_namespace: Some("ns".to_string()),
            pod_obj: Some(serde_json::json!({"metadata": {"uid": format!("uid-{name}")}})),
            time_stamp: ts(seen),
            node_name: "node-a".to_string(),
            is_dead: dead,
            workload_kind: Some("Deployment".to_string()),
            workload_name: Some(name.trim_end_matches(char::is_numeric).to_string()),
            started_at: started.map(ts),
            ..Default::default()
        }
    }

    fn svc() -> SvcDetail {
        SvcDetail {
            svc_ip: "10.96.0.10".to_string(),
            svc_name: Some("kube-dns".to_string()),
            svc_namespace: Some("kube-system".to_string()),
            service_spec: Some(serde_json::json!({"metadata": {"uid": "svc-uid"}})),
            time_stamp: ts("2026-01-01T00:00:00"),
        }
    }

    // ---- guard ----------------------------------------------------

    #[test]
    fn guard_rejects_a_pod_started_after_the_flow() {
        // The autobrr/cmangos case: the row is from July, autobrr
        // started in August and holds the IP now. It must never be
        // chosen for that row.
        let autobrr = pod(
            "autobrr-1",
            false,
            Some("2026-08-04T09:12:41"),
            "2026-09-03T00:00:00",
        );
        assert!(!passes_guard(&autobrr, ts("2026-07-23T10:00:00")));
        assert!(passes_guard(&autobrr, ts("2026-08-04T09:12:41")));
        assert!(passes_guard(&autobrr, ts("2026-09-01T00:00:00")));
    }

    #[test]
    fn guard_excludes_an_unknown_start_even_when_alive() {
        // The cluster-00 ghost: is_dead=false, never re-posted since the
        // upgrade (started_at NULL), IP since recycled. It must not be a
        // candidate for any flow, at any time — dead or "alive".
        let ghost = pod(
            "autobrr-6b6cb9f9dd-vc9rf",
            false,
            None,
            "2026-07-23T19:31:00",
        );
        assert!(!passes_guard(&ghost, ts("2026-09-03T00:00:00")));
        assert!(!passes_guard(&ghost, ts("2020-01-01T00:00:00")));
        let legacy_dead = pod("legacy-1", true, None, "2026-05-01T00:00:00");
        assert!(!passes_guard(&legacy_dead, ts("2026-09-03T00:00:00")));
        // choose_pod inherits it: a ghost alone resolves to nothing, and
        // a ghost never outranks a dead pod with a known start.
        assert!(choose_pod(std::slice::from_ref(&ghost), ts("2026-09-03T00:00:00")).is_none());
        let real = pod(
            "job-b",
            true,
            Some("2026-07-23T09:00:00"),
            "2026-07-23T09:30:00",
        );
        assert_eq!(
            choose_pod(&[ghost, real], ts("2026-09-03T00:00:00")).map(|p| p.pod_name.as_str()),
            Some("job-b")
        );
    }

    #[test]
    fn choose_pod_returns_none_when_only_candidate_started_after_the_flow() {
        let pods = vec![pod(
            "autobrr-1",
            false,
            Some("2026-08-04T09:12:41"),
            "2026-09-03T00:00:00",
        )];
        assert!(choose_pod(&pods, ts("2026-07-23T10:00:00")).is_none());
        // A row from after the start resolves normally.
        assert_eq!(
            choose_pod(&pods, ts("2026-08-10T00:00:00")).map(|p| p.pod_name.as_str()),
            Some("autobrr-1")
        );
    }

    // ---- precedence -----------------------------------------------

    #[test]
    fn alive_pod_beats_dead_pod() {
        let pods = vec![
            pod(
                "job-9",
                true,
                Some("2026-09-02T00:00:00"),
                "2026-09-02T01:00:00",
            ),
            pod(
                "web-1",
                false,
                Some("2026-08-01T00:00:00"),
                "2026-09-03T00:00:00",
            ),
        ];
        assert_eq!(
            choose_pod(&pods, ts("2026-09-03T00:00:00")).map(|p| p.pod_name.as_str()),
            Some("web-1")
        );
    }

    #[test]
    fn guarded_out_alive_pod_falls_back_to_the_dead_holder_with_the_newest_start() {
        // Three former holders plus today's owner; the row predates the
        // owner. The dead pod that started most recently BEFORE the row
        // is the best guess, not the most recently seen one.
        let pods = vec![
            pod(
                "autobrr-1",
                false,
                Some("2026-08-04T09:12:41"),
                "2026-09-03T00:00:00",
            ),
            pod(
                "job-a",
                true,
                Some("2026-07-01T00:00:00"),
                "2026-07-01T01:00:00",
            ),
            pod(
                "job-b",
                true,
                Some("2026-07-23T09:00:00"),
                "2026-07-23T09:30:00",
            ),
            pod(
                "job-c",
                true,
                Some("2026-07-30T00:00:00"),
                "2026-07-30T01:00:00",
            ),
        ];
        assert_eq!(
            choose_pod(&pods, ts("2026-07-23T10:00:00")).map(|p| p.pod_name.as_str()),
            Some("job-b")
        );
    }

    #[test]
    fn unknown_start_is_never_a_candidate_regardless_of_recency() {
        let pods = vec![
            pod("legacy", true, None, "2026-08-30T00:00:00"),
            pod(
                "job-b",
                true,
                Some("2026-07-23T09:00:00"),
                "2026-07-23T09:30:00",
            ),
        ];
        assert_eq!(
            choose_pod(&pods, ts("2026-08-31T00:00:00")).map(|p| p.pod_name.as_str()),
            Some("job-b")
        );
        // Only unknown starts left: nothing, not "the newest seen".
        let pods = vec![
            pod("old", true, None, "2026-05-01T00:00:00"),
            pod("newer", false, None, "2026-08-30T00:00:00"),
        ];
        assert!(choose_pod(&pods, ts("2026-08-31T00:00:00")).is_none());
    }

    #[test]
    fn pod_beats_service_and_service_beats_nothing() {
        let at = ts("2026-09-03T00:00:00");
        let both = Candidates {
            pods: vec![pod(
                "web-1",
                false,
                Some("2026-08-01T00:00:00"),
                "2026-09-03T00:00:00",
            )],
            service: Some(svc()),
        };
        assert_eq!(choose(&both, at).unwrap().kind, PEER_KIND_POD);
        let dead_and_svc = Candidates {
            pods: vec![pod(
                "job-a",
                true,
                Some("2026-08-01T00:00:00"),
                "2026-08-01T01:00:00",
            )],
            service: Some(svc()),
        };
        let got = choose(&dead_and_svc, at).unwrap();
        assert_eq!(got.kind, PEER_KIND_POD);
        assert_eq!(got.name.as_deref(), Some("job-a"));
        let svc_only = Candidates {
            pods: vec![],
            service: Some(svc()),
        };
        let got = choose(&svc_only, at).unwrap();
        assert_eq!(got.kind, PEER_KIND_SERVICE);
        assert_eq!(got.namespace.as_deref(), Some("kube-system"));
        assert_eq!(got.name.as_deref(), Some("kube-dns"));
        assert_eq!(got.uid.as_deref(), Some("svc-uid"));
        assert!(got.workload_kind.is_none() && got.workload_name.is_none());
        assert!(choose(&Candidates::default(), at).is_none());
    }

    #[test]
    fn guarded_out_pod_falls_through_to_the_service() {
        // The guard applies before the Service fallback: a pod that
        // started after the flow does not block a ClusterIP match.
        let cands = Candidates {
            pods: vec![pod(
                "late",
                false,
                Some("2026-09-02T00:00:00"),
                "2026-09-03T00:00:00",
            )],
            service: Some(svc()),
        };
        assert_eq!(
            choose(&cands, ts("2026-09-01T00:00:00")).unwrap().kind,
            PEER_KIND_SERVICE
        );
    }

    #[test]
    fn host_network_pod_resolves_as_node() {
        let mut p = pod(
            "node-exporter-x",
            false,
            Some("2026-08-01T00:00:00"),
            "2026-09-03T00:00:00",
        );
        p.host_network = Some(true);
        p.workload_kind = Some("DaemonSet".to_string());
        let got = PeerIdentity::from_pod(&p);
        assert_eq!(got.kind, PEER_KIND_NODE);
        assert_eq!(got.name.as_deref(), Some("node-exporter-x"));
        assert_eq!(got.uid.as_deref(), Some("uid-node-exporter-x"));
        assert_eq!(got.workload_kind.as_deref(), Some("DaemonSet"));
    }

    #[test]
    fn identity_carries_uid_and_workload_or_none() {
        let p = pod(
            "web-1",
            false,
            Some("2026-08-01T00:00:00"),
            "2026-09-03T00:00:00",
        );
        let got = PeerIdentity::from_pod(&p);
        assert_eq!(got.kind, PEER_KIND_POD);
        assert_eq!(got.namespace.as_deref(), Some("ns"));
        assert_eq!(got.uid.as_deref(), Some("uid-web-1"));
        assert_eq!(got.workload_kind.as_deref(), Some("Deployment"));
        assert_eq!(got.workload_name.as_deref(), Some("web-"));
        // No manifest, bare pod.
        let bare = PodDetail {
            pod_name: "bare".to_string(),
            ..Default::default()
        };
        let got = PeerIdentity::from_pod(&bare);
        assert!(got.uid.is_none() && got.workload_kind.is_none());
        assert!(manifest_uid(Some(&serde_json::json!({"metadata": {"uid": ""}}))).is_none());
    }

    // ---- apply / overwrite -----------------------------------------

    #[test]
    fn apply_overwrites_client_supplied_peer_fields() {
        // A client cannot pre-stamp an identity: ingest always writes
        // the broker's own answer, including clearing to NULL.
        let mut row = PodTraffic {
            uuid: "u".to_string(),
            peer_kind: Some("pod".to_string()),
            peer_name: Some("forged".to_string()),
            peer_resolved_at: Some(ts("2020-01-01T00:00:00")),
            ..Default::default()
        };
        PeerIdentity::apply(None, &mut row, ts("2026-09-03T00:00:00"));
        assert!(row.peer_kind.is_none() && row.peer_name.is_none());
        assert!(row.peer_resolved_at.is_none());

        let id = PeerIdentity::from_service(&svc());
        PeerIdentity::apply(Some(&id), &mut row, ts("2026-09-03T00:00:00"));
        assert_eq!(row.peer_kind.as_deref(), Some("service"));
        assert_eq!(row.peer_name.as_deref(), Some("kube-dns"));
        assert_eq!(row.peer_resolved_at, Some(ts("2026-09-03T00:00:00")));
    }

    // ---- window edge ----------------------------------------------

    #[test]
    fn window_edge_is_inclusive_at_exactly_window_old() {
        // run_pass filters `time_stamp >= cutoff`: a row exactly
        // `window` old is still retried; one second older is not.
        let now = ts("2026-09-03T00:10:00");
        let cutoff = window_cutoff(now, Duration::from_secs(600));
        assert_eq!(cutoff, ts("2026-09-03T00:00:00"));
        assert!(ts("2026-09-03T00:00:00") >= cutoff);
        assert!(ts("2026-09-03T00:09:59") >= cutoff);
        assert!(ts("2026-09-02T23:59:59") < cutoff);
    }

    #[test]
    fn late_resolve_pass_takes_the_oldest_unresolved_row_first() {
        // Starvation guard: a resolvable row near the cutoff must be
        // picked before newer unresolvable noise, so it is never pushed
        // past the LIMIT on every pass until it ages out. Pin the SQL:
        // ascending on time_stamp (FIFO within the window), bounded by
        // the cutoff and a generous LIMIT.
        let cutoff = ts("2026-09-03T00:00:00");
        let sql = diesel::debug_query::<diesel::pg::Pg, _>(&pending_rows_query(cutoff)).to_string();
        assert!(
            sql.contains(r#"ORDER BY "pod_traffic"."time_stamp" ASC, "pod_traffic"."uuid" ASC"#),
            "must be oldest-first: {sql}"
        );
        assert!(
            !sql.contains("DESC"),
            "no newest-first ordering anywhere: {sql}"
        );
        assert!(
            sql.contains(r#""pod_traffic"."peer_kind" IS NULL"#)
                && sql.contains(r#""pod_traffic"."traffic_in_out_ip" IS NOT NULL"#)
                && sql.contains(r#""pod_traffic"."time_stamp" >= $1"#),
            "window + unresolved predicates: {sql}"
        );
        assert!(
            sql.contains("LIMIT $2") && sql.contains(&format!("{MAX_ROWS_PER_PASS}")),
            "generous LIMIT bound: {sql}"
        );
        // Simulate a window holding one old resolvable row plus more
        // noise than one pass admits: under the pinned ASC order the old
        // row is the FIRST row of the pass, not one pushed past the LIMIT.
        let old = ts("2026-09-03T00:00:01");
        let mut times: Vec<NaiveDateTime> = (2..(MAX_ROWS_PER_PASS + 10))
            .map(|i| ts("2026-09-03T00:00:00") + chrono::Duration::seconds(i))
            .collect();
        times.push(old);
        times.sort(); // what ORDER BY time_stamp ASC yields
        let first_pass: Vec<_> = times.iter().take(MAX_ROWS_PER_PASS as usize).collect();
        assert_eq!(first_pass[0], &old, "oldest row leads the pass");
        let newest_first: Vec<_> = times
            .iter()
            .rev()
            .take(MAX_ROWS_PER_PASS as usize)
            .collect();
        assert!(
            !newest_first.contains(&&old),
            "the old DESC order would have starved it"
        );
    }

    // ---- ?at= parsing ----------------------------------------------

    #[test]
    fn parse_at_accepts_rfc3339_and_naive() {
        assert_eq!(
            parse_at("2026-07-23T10:00:00Z").unwrap(),
            ts("2026-07-23T10:00:00")
        );
        // An offset is converted to UTC, matching the stored naive-UTC form.
        assert_eq!(
            parse_at("2026-07-23T12:00:00+02:00").unwrap(),
            ts("2026-07-23T10:00:00")
        );
        assert_eq!(
            parse_at("2026-07-23T10:00:00.123456").unwrap(),
            ts("2026-07-23T10:00:00.123456")
        );
        assert_eq!(
            parse_at("  2026-07-23T10:00:00 ").unwrap(),
            ts("2026-07-23T10:00:00")
        );
    }

    #[test]
    fn parse_at_rejects_garbage() {
        for bad in [
            "",
            "yesterday",
            "2026-07-23",
            "1690000000",
            "2026-13-01T00:00:00Z",
        ] {
            assert!(parse_at(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    // ---- env readers ----------------------------------------------

    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        let _guard = crate::test_support::env_lock();
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn stale_alive_sweep_marks_only_untouched_alive_rows_dead() {
        // Pin the statement: UPDATE pod_details SET is_dead = true only
        // where is_dead = false AND time_stamp < cutoff. Dead rows and
        // recently re-posted live rows are untouched, and nothing is
        // deleted (retention prunes dead rows on its own schedule).
        let cutoff = ts("2026-09-03T00:00:00");
        let sql = STALE_ALIVE_SQL;
        assert!(
            sql.starts_with("UPDATE pod_details SET is_dead = true"),
            "{sql}"
        );
        assert!(
            sql.ends_with("WHERE is_dead = false AND time_stamp < $1"),
            "{sql}"
        );
        assert!(!sql.contains("DELETE"), "{sql}");
        // The cutoff is bound as a parameter, never interpolated.
        let bound = diesel::debug_query::<diesel::pg::Pg, _>(
            &diesel::sql_query(STALE_ALIVE_SQL).bind::<diesel::sql_types::Timestamp, _>(cutoff),
        )
        .to_string();
        assert!(bound.contains("binds: [2026-09-03T00:00:00]"), "{bound}");
        // The cutoff is the same arithmetic as the late-resolve window:
        // a 15-min threshold at 00:15 marks rows last written before 00:00.
        assert_eq!(
            window_cutoff(ts("2026-09-03T00:15:00"), Duration::from_secs(900)),
            cutoff
        );
    }

    #[test]
    fn stale_alive_env_default_override_zero_and_garbage() {
        with_env("PEER_STALE_ALIVE_SECS", None, || {
            assert_eq!(stale_alive_secs(), DEFAULT_STALE_ALIVE_SECS);
        });
        with_env("PEER_STALE_ALIVE_SECS", Some(" 1800\n"), || {
            assert_eq!(stale_alive_secs(), 1800);
        });
        with_env("PEER_STALE_ALIVE_SECS", Some("0"), || {
            assert_eq!(stale_alive_secs(), 0);
        });
        with_env("PEER_STALE_ALIVE_SECS", Some("never"), || {
            assert_eq!(stale_alive_secs(), DEFAULT_STALE_ALIVE_SECS);
        });
    }

    #[test]
    fn window_env_default_override_zero_and_garbage() {
        with_env("PEER_LATE_RESOLVE_WINDOW_SECS", None, || {
            assert_eq!(window_secs(), DEFAULT_WINDOW_SECS);
        });
        with_env("PEER_LATE_RESOLVE_WINDOW_SECS", Some(" 120\n"), || {
            assert_eq!(window_secs(), 120);
        });
        with_env("PEER_LATE_RESOLVE_WINDOW_SECS", Some("0"), || {
            assert_eq!(window_secs(), 0);
        });
        with_env("PEER_LATE_RESOLVE_WINDOW_SECS", Some("soon"), || {
            assert_eq!(window_secs(), DEFAULT_WINDOW_SECS);
        });
    }

    #[test]
    fn interval_env_default_override_and_floor() {
        with_env("PEER_LATE_RESOLVE_INTERVAL_SECS", None, || {
            assert_eq!(interval(), Duration::from_secs(DEFAULT_INTERVAL_SECS));
        });
        with_env("PEER_LATE_RESOLVE_INTERVAL_SECS", Some("30"), || {
            assert_eq!(interval(), Duration::from_secs(30));
        });
        with_env("PEER_LATE_RESOLVE_INTERVAL_SECS", Some("1"), || {
            assert_eq!(interval(), Duration::from_secs(MIN_INTERVAL_SECS));
        });
    }
}
