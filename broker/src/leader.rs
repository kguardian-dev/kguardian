//! Leader election for the broker's cluster-singleton background work.
//!
//! With `broker.replicaCount > 1` every replica used to run every
//! background loop, so two replicas could fold the same compute range at
//! once (duplicate five-minute rows), write the same workload profile
//! version twice, and race each other's prunes. The loops that derive or
//! delete shared data now run only on the replica holding a
//! `coordination.k8s.io/v1` Lease; everything else still runs everywhere.
//!
//! # Background tasks
//!
//! | Task | Where | Runs on |
//! |---|---|---|
//! | Audit verdict + dead-pod prune | `retention::spawn` | leader |
//! | Compute downsample, history prune, stale latest rows | `retention::spawn_compute` | leader |
//! | Compute minute-index ensure | `retention::spawn_minute_index` | leader (plus its session advisory lock) |
//! | Seccomp denial attribution backfill + prune, stale denial nodes | `retention::spawn_seccomp_denials` | leader |
//! | Pod traffic prune and per-pod cap | `retention::spawn_pod_traffic` | leader |
//! | Image inventory prune | `retention::spawn_image_inventory` | leader |
//! | Runtime inventory prune | `retention::spawn_runtime_inventory` | leader |
//! | Workload profile version prune | `retention::spawn_workload_profiles` | leader |
//! | Supply-chain relink, in-use, CVE summary, page expiry, GC | `retention::spawn_supplychain` | leader |
//! | Image attestation prune | `attestation::spawn_retention` | leader |
//! | Peer late-resolve + stale-alive (dead-node) sweep | `peer::spawn` | leader |
//! | Workload profile snapshotter | `workload_profile::spawn` | leader |
//! | Seccomp denial workload gauge | `seccomp_denial::spawn_metrics_refresh` | every replica (feeds its own /metrics; read-only) |
//! | Drift gauge | `profile_drift::spawn_metrics_refresh` | every replica (feeds its own /metrics; read-only) |
//! | Version check-in | `version_check::spawn` | every replica (fills its own GET /version) |
//! | Audit dispatcher | `audit::spawn_audit_dispatcher` | every replica (request path) |
//! | Supply-chain ingest worker | `supplychain::ingest_worker` | every replica (request path) |
//! | Seccomp profiles cache rebuild | `seccomp_profiles_cache` | every replica (request path) |
//!
//! A leader-only loop checks [`is_leader`] before each pass, and a pass
//! that loses leadership stops at its next batch boundary
//! ([`still_leader`]); a batch already in its transaction finishes. A
//! replica that becomes the leader runs each loop's pass promptly when the
//! last pass any replica completed is an interval old ([`Cadence`]),
//! instead of waiting out its own timer.
//!
//! # Election
//!
//! The client-go algorithm, over three calls on one Lease (get, create,
//! update with `resourceVersion`, so a lost race is a 409 and never an
//! overwrite). A lease held by another replica is taken only once its
//! record has not changed for `leaseDurationSeconds` of THIS replica's
//! monotonic clock, so wall-clock skew between nodes cannot shorten it.
//! The leader renews every retry period and stops leader-only work once
//! it has gone `renewDeadline` without a successful renew, which is
//! shorter than the lease duration a successor waits out. On graceful
//! shutdown the holder is cleared so a successor takes over on its next
//! retry instead of waiting the lease out.
//!
//! The API is spoken directly over the broker's existing reqwest client
//! rather than through kube-rs, which the broker does not otherwise
//! depend on and would add a large dependency tree for three requests.
//!
//! # Configuration
//!
//! - `LEADER_ELECTION_ENABLED`: `true`, `false`, or unset/`auto` (on
//!   when running in a pod: `KUBERNETES_SERVICE_HOST` set and a service
//!   account token mounted). Off means this replica is always the leader,
//!   the behaviour before election existed.
//! - `LEADER_ELECTION_LEASE_NAME` (default `kguardian-broker-leader`;
//!   the chart sets `<fullname>-broker-leader`).
//! - `LEADER_ELECTION_NAMESPACE` (default `POD_NAMESPACE`, then the
//!   service account's namespace file).
//! - `LEADER_ELECTION_LEASE_DURATION_SECS` (15),
//!   `LEADER_ELECTION_RENEW_DEADLINE_SECS` (10),
//!   `LEADER_ELECTION_RETRY_PERIOD_SECS` (2); the client-go defaults.
//! - Identity: `POD_NAME`, then `HOSTNAME`.
//!
//! # When the Lease API does not cooperate
//!
//! - **Unreachable, timing out or failing (5xx)**, at startup or later:
//!   the replica stays a follower and keeps retrying. The singleton jobs
//!   pause until some replica can hold the lease, as with client-go. It
//!   never assumes leadership it cannot prove: another replica may hold
//!   the lease, and two leaders is the failure this module exists for.
//! - **Refused (401/403) for [`STARTUP_ATTEMPTS`] tries in a row before
//!   first contact**: RBAC is missing (a Deployment without the chart's
//!   Role). Every replica shares the service account, so all are refused
//!   alike; they fall back to always-leader, the pre-election behaviour,
//!   warn every five minutes, and keep retrying every 30 s. Once the API
//!   accepts them they close the gate and elect normally, so a RoleBinding
//!   that was only slow to propagate never leaves two leaders.
//!   `broker_leader_election_active{mode="fallback_forbidden"}` reads 0.
//! - **Refused after first contact** (RBAC removed mid-life): as
//!   unreachable, zero leaders rather than two.
//! - **Election asked for but impossible to start** (no namespace or CA):
//!   always-leader with a warning every five minutes
//!   (`mode="fallback_misconfigured"`).
//!
//! `broker_leader_election_errors_total` rising on every replica means no
//! replica can hold the lease and the jobs are paused.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

const DEFAULT_LEASE_NAME: &str = "kguardian-broker-leader";
const DEFAULT_LEASE_DURATION_SECS: u64 = 15;
const DEFAULT_RENEW_DEADLINE_SECS: u64 = 10;
const DEFAULT_RETRY_PERIOD_SECS: u64 = 2;
/// Consecutive 401/403s at startup before falling back to always-leader:
/// about 20 s at the default retry period, so a RoleBinding still
/// propagating on a fresh install is not mistaken for missing RBAC.
pub(crate) const STARTUP_ATTEMPTS: u32 = 10;
/// How long [`shutdown`] waits for the release to reach the API server.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
/// Retry cadence while in the 401/403 fallback, and how many refused
/// retries between warnings (every 5 minutes).
const FALLBACK_RETRY: Duration = Duration::from_secs(30);
const FALLBACK_WARN_EVERY: u32 = 10;
/// Failed attempts between repeated warnings while the API is failing
/// (about a minute at the default retry period).
const FAILURE_WARN_EVERY: u32 = 30;
/// How often a replica left always-leader by a static misconfiguration
/// repeats its warning.
const MISCONFIGURED_WARN_EVERY: Duration = Duration::from_secs(300);

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

// ---------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------

/// How this replica decides leadership. Everything but `Elected` means
/// "always the leader".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Mode {
    /// Election off (not in a cluster, or `LEADER_ELECTION_ENABLED=false`).
    Disabled = 0,
    /// Contending for the Lease.
    Elected = 1,
    /// The Lease API refused us at startup (missing RBAC). Still retried.
    FallbackDenied = 2,
    /// Election was asked for but cannot start (no namespace, no CA).
    FallbackMisconfigured = 3,
}

impl Mode {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Mode::Elected,
            2 => Mode::FallbackDenied,
            3 => Mode::FallbackMisconfigured,
            _ => Mode::Disabled,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Mode::Disabled => "disabled",
            Mode::Elected => "elected",
            Mode::FallbackDenied => "fallback_forbidden",
            Mode::FallbackMisconfigured => "fallback_misconfigured",
        }
    }
}

/// Whether this replica may run leader-only work right now. Two atomic
/// loads, so the loops can ask before every batch.
///
/// Leadership is a deadline on the process's monotonic clock rather than
/// a flag: if the elector stalls (a hung request, a panic) the gate
/// closes by itself once the last successful renew is `renewDeadline`
/// old, without anyone having to notice.
pub struct LeaderGate {
    mode: AtomicU8,
    /// Leading until this many ms after [`mono_now`]'s anchor; 0 = not.
    until_ms: AtomicU64,
    transitions: AtomicU64,
    /// Bumped each time this replica acquires the lease, after the gate
    /// opens; [`Cadence`] watches it to run a new leader's passes promptly.
    acquisitions: AtomicU64,
    /// Failed Lease requests, for `broker_leader_election_errors_total`.
    errors: AtomicU64,
    /// Set on shutdown: closed for good, whatever the mode or deadline.
    stopped: AtomicBool,
}

impl LeaderGate {
    /// Election disabled: always the leader.
    pub const fn new() -> Self {
        Self {
            mode: AtomicU8::new(Mode::Disabled as u8),
            until_ms: AtomicU64::new(0),
            transitions: AtomicU64::new(0),
            acquisitions: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        }
    }

    pub fn is_leader(&self) -> bool {
        self.is_leader_at(mono_now())
    }

    pub(crate) fn is_leader_at(&self, now: Duration) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        match self.mode() {
            Mode::Elected => (now.as_millis() as u64) < self.until_ms.load(Ordering::Acquire),
            _ => true,
        }
    }

    pub(crate) fn mode(&self) -> Mode {
        Mode::from_u8(self.mode.load(Ordering::Acquire))
    }

    pub(crate) fn set_mode(&self, mode: Mode) {
        self.mode.store(mode as u8, Ordering::Release);
    }

    fn hold_until(&self, deadline: Duration) {
        self.until_ms
            .store(deadline.as_millis() as u64, Ordering::Release);
    }

    fn clear(&self) {
        self.until_ms.store(0, Ordering::Release);
    }

    fn transitioned(&self) {
        self.transitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Close the gate for the rest of the process (shutdown).
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.clear();
    }

    fn errored(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn acquired(&self) {
        self.acquisitions.fetch_add(1, Ordering::Release);
    }

    fn acquisitions(&self) -> u64 {
        self.acquisitions.load(Ordering::Acquire)
    }

    /// Batch-boundary check for a pass in progress: `false` (and one info
    /// line) once leadership is gone, so the pass stops before starting
    /// another batch.
    pub fn still_leader(&self, task: &str) -> bool {
        let leading = self.is_leader();
        if !leading {
            info!(
                task,
                "leadership lost; stopping the pass at a batch boundary"
            );
        }
        leading
    }

    /// Run one pass of a leader-only loop, or skip it (`None`) when this
    /// replica is not the leader. `pass` is not polled when skipped.
    pub async fn run<F: Future>(&self, task: &str, pass: F) -> Option<F::Output> {
        if self.is_leader() {
            Some(pass.await)
        } else {
            debug!(task, "not the leader; skipping this pass");
            None
        }
    }
}

impl Default for LeaderGate {
    fn default() -> Self {
        Self::new()
    }
}

static GATE: LeaderGate = LeaderGate::new();

/// The process-wide gate the background loops consult.
pub fn gate() -> &'static LeaderGate {
    &GATE
}

/// Whether this replica may run leader-only work.
pub fn is_leader() -> bool {
    GATE.is_leader()
}

/// [`LeaderGate::still_leader`] on the process-wide gate.
pub fn still_leader(task: &str) -> bool {
    GATE.still_leader(task)
}

/// [`LeaderGate::run`] on the process-wide gate.
pub async fn singleton<F: Future>(task: &str, pass: F) -> Option<F::Output> {
    GATE.run(task, pass).await
}

fn mono_now() -> Duration {
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    ANCHOR.get_or_init(Instant::now).elapsed()
}

/// Leadership lines for `/metrics`.
pub fn render_metrics() -> String {
    render_metrics_for(&GATE)
}

fn render_metrics_for(gate: &LeaderGate) -> String {
    let mode = gate.mode();
    format!(
        concat!(
            "# HELP broker_leader 1 while this replica runs the cluster-singleton background jobs (retention, rollups, snapshotter, sweeps)\n",
            "# TYPE broker_leader gauge\n",
            "broker_leader {leader}\n",
            "# HELP broker_leader_election_active 1 when this replica contends for the leader Lease; 0 when election is disabled or fell back to always-leader (mode says why)\n",
            "# TYPE broker_leader_election_active gauge\n",
            "broker_leader_election_active{{mode=\"{mode}\"}} {active}\n",
            "# HELP broker_leader_transitions_total Leadership changes on this replica (each acquire and each loss counts one)\n",
            "# TYPE broker_leader_transitions_total counter\n",
            "broker_leader_transitions_total {transitions}\n",
            "# HELP broker_leader_election_errors_total Failed Lease API requests on this replica; rising on every replica means no replica can hold the lease and the cluster-singleton jobs are paused\n",
            "# TYPE broker_leader_election_errors_total counter\n",
            "broker_leader_election_errors_total {errors}\n",
        ),
        leader = u8::from(gate.is_leader()),
        mode = mode.label(),
        active = u8::from(mode == Mode::Elected),
        transitions = gate.transitions.load(Ordering::Relaxed),
        errors = gate.errors.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------
// Cadence: pacing a leader-only loop across hand-offs
// ---------------------------------------------------------------------

type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::PgConnection>>;

/// Most a new leader delays its first pass of a loop, so the dozen loops
/// do not all start in the same second.
const MAX_TAKEOVER_JITTER: Duration = Duration::from_secs(30);

/// Paces one leader-only loop: a pass, then [`Cadence::wait`] for the next.
///
/// Waiting is the loop's interval, except that a replica which becomes the
/// leader mid-wait does not sit out the rest of it (up to an hour for some
/// loops): after a short random delay it runs the pass as soon as the last
/// pass ANY replica completed (`leader_task_runs`) is an interval old. A
/// pass the previous leader finished recently is not repeated: the wait is
/// cut to when it falls due, so the cluster keeps one schedule and a
/// replica flapping leadership cannot run passes back to back.
pub struct Cadence {
    task: &'static str,
    interval: Duration,
    jitter_max: Duration,
    /// How often a waiting loop looks for an acquisition.
    poll: Duration,
    seen_acquisitions: u64,
}

impl Cadence {
    pub fn new(task: &'static str, interval: Duration) -> Self {
        Self {
            task,
            interval,
            jitter_max: (interval / 10).min(MAX_TAKEOVER_JITTER),
            poll: Duration::from_secs(1),
            seen_acquisitions: 0,
        }
    }

    /// Run `pass` if this replica is the leader, and record it as the
    /// cluster's last completed pass when it finished still leading.
    pub async fn pass<F: Future>(&mut self, pool: &DbPool, pass: F) -> Option<F::Output> {
        let out = GATE.run(self.task, pass).await;
        if out.is_some() {
            self.completed(pool).await;
        }
        out
    }

    /// Record a pass run outside [`Cadence::pass`], if still leading. A pass
    /// cut short by losing leadership is not recorded, so the new leader
    /// runs its own promptly.
    pub async fn completed(&mut self, pool: &DbPool) {
        if !GATE.is_leader() {
            return;
        }
        let (pool, task) = (pool.clone(), self.task);
        let r = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|e| e.to_string())?;
            record_pass(&mut conn, task).map_err(|e| e.to_string())
        })
        .await;
        if let Ok(Err(e)) | Err(e) = r.map_err(|e| e.to_string()) {
            debug!(task, error = %e, "could not record the completed pass");
        }
    }

    /// Wait for the next pass (see the type docs).
    pub async fn wait(&mut self, pool: &DbPool) {
        let task = self.task;
        self.wait_with(&GATE, || {
            let pool = pool.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    let mut conn = pool.get().ok()?;
                    last_pass_age(&mut conn, task).ok().flatten()
                })
                .await
                .ok()
                .flatten()
            }
        })
        .await
    }

    /// [`Cadence::wait`] against `gate`, with `last_pass_age` telling how
    /// long ago the cluster last completed this pass (`None`: never, or
    /// unknown, which runs it).
    pub(crate) async fn wait_with<F, Fut>(&mut self, gate: &LeaderGate, last_pass_age: F)
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Option<Duration>>,
    {
        let mut deadline = Instant::now() + self.interval;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            tokio::time::sleep(self.poll.min(deadline - now)).await;
            let acquisitions = gate.acquisitions();
            if acquisitions == self.seen_acquisitions {
                continue;
            }
            self.seen_acquisitions = acquisitions;
            if !gate.is_leader() {
                continue;
            }
            tokio::time::sleep(random_up_to(self.jitter_max)).await;
            match last_pass_age().await {
                Some(age) if age < self.interval => {
                    // Keep the cluster's schedule: due an interval after the
                    // last pass, wherever it ran.
                    deadline = deadline.min(Instant::now() + (self.interval - age));
                    debug!(
                        task = self.task,
                        age_secs = age.as_secs(),
                        "became leader; this pass ran recently, keeping its schedule"
                    );
                }
                _ => {
                    info!(task = self.task, "became leader; running this pass now");
                    return;
                }
            }
        }
    }
}

fn random_up_to(max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    let r = u64::from_le_bytes(
        uuid::Uuid::new_v4().as_bytes()[..8]
            .try_into()
            .unwrap_or([0; 8]),
    );
    Duration::from_millis(r % (max.as_millis() as u64 + 1))
}

/// Note that `task` just completed a pass (`leader_task_runs`).
pub(crate) fn record_pass(conn: &mut diesel::PgConnection, task: &str) -> diesel::QueryResult<()> {
    use diesel::RunQueryDsl;
    diesel::sql_query(
        "INSERT INTO leader_task_runs (task, finished_at) VALUES ($1, timezone('UTC', NOW())) \
         ON CONFLICT (task) DO UPDATE SET finished_at = EXCLUDED.finished_at",
    )
    .bind::<diesel::sql_types::Text, _>(task)
    .execute(conn)
    .map(|_| ())
}

#[derive(diesel::QueryableByName)]
struct PassAge {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Double>)]
    secs: Option<f64>,
}

/// How long ago any replica completed `task`, by the database's clock
/// (so replicas' clocks never enter it). `None` when it never has.
pub(crate) fn last_pass_age(
    conn: &mut diesel::PgConnection,
    task: &str,
) -> diesel::QueryResult<Option<Duration>> {
    use diesel::RunQueryDsl;
    let row = diesel::sql_query(
        "SELECT (SELECT EXTRACT(EPOCH FROM timezone('UTC', NOW()) - finished_at)::float8 \
                 FROM leader_task_runs WHERE task = $1) AS secs",
    )
    .bind::<diesel::sql_types::Text, _>(task)
    .get_result::<PassAge>(conn)?;
    Ok(row.secs.map(|s| Duration::from_secs_f64(s.max(0.0))))
}

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Timings {
    pub lease_duration: Duration,
    pub renew_deadline: Duration,
    pub retry_period: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            lease_duration: Duration::from_secs(DEFAULT_LEASE_DURATION_SECS),
            renew_deadline: Duration::from_secs(DEFAULT_RENEW_DEADLINE_SECS),
            retry_period: Duration::from_secs(DEFAULT_RETRY_PERIOD_SECS),
        }
    }
}

impl Timings {
    /// The configured timings, or the defaults when they break client-go's
    /// ordering `lease > renew deadline > retry period` (with room for the
    /// follower's retry jitter). Out of order, a leader could keep working
    /// after a successor was allowed to start, which is the bug this
    /// module exists to prevent, so a bad combination is never used.
    fn from_secs(lease: Option<u64>, renew: Option<u64>, retry: Option<u64>) -> Self {
        let d = Self::default();
        let t = Self {
            lease_duration: lease.map(Duration::from_secs).unwrap_or(d.lease_duration),
            renew_deadline: renew.map(Duration::from_secs).unwrap_or(d.renew_deadline),
            retry_period: retry.map(Duration::from_secs).unwrap_or(d.retry_period),
        };
        let jittered_retry = t.retry_period.mul_f64(1.2);
        if t.retry_period.is_zero()
            || t.lease_duration <= t.renew_deadline
            || t.renew_deadline <= jittered_retry
        {
            warn!(
                lease_duration_secs = t.lease_duration.as_secs(),
                renew_deadline_secs = t.renew_deadline.as_secs(),
                retry_period_secs = t.retry_period.as_secs(),
                "leader election timings must satisfy lease duration > renew deadline > \
                 1.2 x retry period; using the defaults (15/10/2)"
            );
            return d;
        }
        t
    }

    fn from_env() -> Self {
        Self::from_secs(
            env_u64("LEADER_ELECTION_LEASE_DURATION_SECS"),
            env_u64("LEADER_ELECTION_RENEW_DEADLINE_SECS"),
            env_u64("LEADER_ELECTION_RETRY_PERIOD_SECS"),
        )
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_u64(key: &str) -> Option<u64> {
    env_str(key).and_then(|v| v.parse().ok())
}

/// `LEADER_ELECTION_ENABLED`: explicit true/false wins; unset, `auto` or
/// garbage follow `in_cluster`.
fn election_enabled(setting: Option<&str>, in_cluster: bool) -> bool {
    match setting.map(|s| s.to_ascii_lowercase()) {
        Some(s) if matches!(s.as_str(), "true" | "1" | "yes" | "on") => true,
        Some(s) if matches!(s.as_str(), "false" | "0" | "no" | "off") => false,
        _ => in_cluster,
    }
}

fn in_cluster() -> bool {
    env_str("KUBERNETES_SERVICE_HOST").is_some()
        && std::path::Path::new(SA_DIR).join("token").exists()
}

/// This replica's holder identity: the pod name (downward API), then the
/// hostname, which is the pod name in a pod anyway.
fn identity() -> String {
    env_str("POD_NAME")
        .or_else(|| env_str("HOSTNAME"))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| format!("broker-{}", uuid::Uuid::new_v4()))
}

fn namespace() -> Option<String> {
    env_str("LEADER_ELECTION_NAMESPACE")
        .or_else(|| env_str("POD_NAMESPACE"))
        .or_else(|| {
            std::fs::read_to_string(std::path::Path::new(SA_DIR).join("namespace"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

/// `https://host:port` for the in-cluster API server, bracketing an IPv6
/// host the way client-go's InClusterConfig does.
fn api_server_url(host: &str, port: Option<&str>) -> String {
    let port = port.unwrap_or("443");
    if host.contains(':') && !host.starts_with('[') {
        format!("https://[{host}]:{port}")
    } else {
        format!("https://{host}:{port}")
    }
}

// ---------------------------------------------------------------------
// Lease object and API
// ---------------------------------------------------------------------

/// The subset of `coordination.k8s.io/v1` Lease the election uses. Fields
/// it does not know are kept (`extra`) so an update never strips them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Lease {
    pub api_version: String,
    pub kind: String,
    pub metadata: LeaseMeta,
    pub spec: LeaseSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct LeaseMeta {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct LeaseSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_duration_seconds: Option<i32>,
    /// MicroTime strings; only ever written, never compared (see the
    /// module docs on skew).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquire_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_transitions: Option<i32>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Lease {
    fn named(name: &str) -> Self {
        Self {
            api_version: "coordination.k8s.io/v1".into(),
            kind: "Lease".into(),
            metadata: LeaseMeta {
                name: name.into(),
                ..Default::default()
            },
            spec: LeaseSpec::default(),
        }
    }

    /// The holder, with an empty string (a released lease) read as none.
    pub fn holder(&self) -> Option<&str> {
        self.spec
            .holder_identity
            .as_deref()
            .filter(|h| !h.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LeaseError {
    /// 409 on update: someone wrote the lease since we read it. Also a
    /// 409 on create (someone created it first).
    Conflict,
    /// 401/403: not allowed to use the Lease (RBAC, token).
    Denied(String),
    /// Anything else: network failure, timeout, 5xx, unexpected status.
    Unavailable(String),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseError::Conflict => f.write_str("lease was modified concurrently (409)"),
            LeaseError::Denied(m) => write!(f, "lease access denied: {m}"),
            LeaseError::Unavailable(m) => write!(f, "lease API unavailable: {m}"),
        }
    }
}

/// The three Lease calls the election makes. `replace` must send the
/// lease's `resourceVersion` and fail with [`LeaseError::Conflict`] when
/// it is stale.
pub(crate) trait LeaseApi {
    async fn get(&self) -> Result<Option<Lease>, LeaseError>;
    async fn create(&self, lease: &Lease) -> Result<Lease, LeaseError>;
    async fn replace(&self, lease: &Lease) -> Result<Lease, LeaseError>;
}

pub(crate) trait Clock {
    /// Monotonic time; all expiry decisions use this.
    fn mono(&self) -> Duration;
    /// Wall time, only written into the lease for humans and tools.
    fn wall(&self) -> DateTime<Utc>;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn mono(&self) -> Duration {
        mono_now()
    }
    fn wall(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

fn micro_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Map a Lease API response status that is not a success.
fn classify(status: u16, body: &str) -> LeaseError {
    let detail = || {
        let msg = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
            .unwrap_or_else(|| body.chars().take(200).collect());
        format!("HTTP {status}: {msg}")
    };
    match status {
        409 => LeaseError::Conflict,
        401 | 403 => LeaseError::Denied(detail()),
        _ => LeaseError::Unavailable(detail()),
    }
}

/// [`LeaseApi`] against a real API server.
pub(crate) struct KubeLeaseApi {
    client: reqwest::Client,
    collection_url: String,
    item_url: String,
    /// Re-read on every request: projected service account tokens rotate.
    token_path: Option<PathBuf>,
}

impl KubeLeaseApi {
    pub fn new(
        client: reqwest::Client,
        base_url: &str,
        namespace: &str,
        name: &str,
        token_path: Option<PathBuf>,
    ) -> Self {
        let collection_url = format!(
            "{}/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases",
            base_url.trim_end_matches('/')
        );
        let item_url = format!("{collection_url}/{name}");
        Self {
            client,
            collection_url,
            item_url,
            token_path,
        }
    }

    /// The in-cluster client: API server from the service env, the
    /// service account CA as the only trust root.
    fn in_cluster(namespace: &str, name: &str, timeout: Duration) -> Result<Self, String> {
        let host = env_str("KUBERNETES_SERVICE_HOST")
            .ok_or_else(|| "KUBERNETES_SERVICE_HOST is not set".to_string())?;
        let port = env_str("KUBERNETES_SERVICE_PORT");
        let sa = std::path::Path::new(SA_DIR);
        let ca = std::fs::read(sa.join("ca.crt")).map_err(|e| format!("read ca.crt: {e}"))?;
        let ca = reqwest::Certificate::from_pem(&ca).map_err(|e| format!("parse ca.crt: {e}"))?;
        let client = reqwest::Client::builder()
            .tls_certs_only([ca])
            .timeout(timeout)
            .build()
            .map_err(|e| format!("build HTTP client: {e}"))?;
        Ok(Self::new(
            client,
            &api_server_url(&host, port.as_deref()),
            namespace,
            name,
            Some(sa.join("token")),
        ))
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder, LeaseError> {
        match &self.token_path {
            None => Ok(req),
            Some(p) => {
                let token = std::fs::read_to_string(p)
                    .map_err(|e| LeaseError::Unavailable(format!("read token: {e}")))?;
                Ok(req.bearer_auth(token.trim()))
            }
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<(u16, String), LeaseError> {
        let resp = self
            .authed(req)?
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| LeaseError::Unavailable(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| LeaseError::Unavailable(e.to_string()))?;
        Ok((status, body))
    }

    fn parse(body: &str) -> Result<Lease, LeaseError> {
        serde_json::from_str(body)
            .map_err(|e| LeaseError::Unavailable(format!("decode lease: {e}")))
    }
}

impl LeaseApi for KubeLeaseApi {
    async fn get(&self) -> Result<Option<Lease>, LeaseError> {
        match self.send(self.client.get(&self.item_url)).await? {
            (200, body) => Self::parse(&body).map(Some),
            (404, _) => Ok(None),
            (status, body) => Err(classify(status, &body)),
        }
    }

    async fn create(&self, lease: &Lease) -> Result<Lease, LeaseError> {
        // The API server refuses (500, not 409) a create that carries one.
        let mut lease = lease.clone();
        lease.metadata.resource_version = None;
        match self
            .send(self.client.post(&self.collection_url).json(&lease))
            .await?
        {
            (200 | 201, body) => Self::parse(&body),
            (status, body) => Err(classify(status, &body)),
        }
    }

    async fn replace(&self, lease: &Lease) -> Result<Lease, LeaseError> {
        match self
            .send(self.client.put(&self.item_url).json(lease))
            .await?
        {
            (200 | 201, body) => Self::parse(&body),
            // Deleted since we read it: our resourceVersion is as stale
            // as it would be after a concurrent update.
            (404, _) => Err(LeaseError::Conflict),
            (status, body) => Err(classify(status, &body)),
        }
    }
}

// ---------------------------------------------------------------------
// Elector
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Attempt {
    Leading,
    Following { holder: String },
}

/// The last lease record seen, and when (monotonic) it was first seen.
struct Observed {
    resource_version: Option<String>,
    duration: Duration,
    at: Duration,
}

/// One replica's view of the Lease: the client-go `tryAcquireOrRenew`.
pub(crate) struct Elector<A, C> {
    api: A,
    clock: C,
    identity: String,
    lease_name: String,
    lease_duration: Duration,
    observed: Option<Observed>,
    /// The lease as we last wrote it while holding it, for release.
    held: Option<Lease>,
}

impl<A: LeaseApi, C: Clock> Elector<A, C> {
    pub fn new(
        api: A,
        clock: C,
        identity: &str,
        lease_name: &str,
        lease_duration: Duration,
    ) -> Self {
        Self {
            api,
            clock,
            identity: identity.into(),
            lease_name: lease_name.into(),
            lease_duration,
            observed: None,
            held: None,
        }
    }

    fn duration_secs(&self) -> i32 {
        i32::try_from(self.lease_duration.as_secs()).unwrap_or(i32::MAX)
    }

    /// Note `lease` as seen now if its record changed since last time.
    /// Only a CHANGE restarts the clock: a record that sits unchanged for
    /// its lease duration of our own monotonic time has expired, whatever
    /// its renewTime says, which is what makes this skew-proof.
    fn observe(&mut self, lease: &Lease) {
        let rv = lease.metadata.resource_version.clone();
        let changed = self
            .observed
            .as_ref()
            .is_none_or(|o| o.resource_version != rv || rv.is_none());
        if changed {
            let secs = lease
                .spec
                .lease_duration_seconds
                .filter(|s| *s > 0)
                .map(|s| s as u64)
                .unwrap_or(self.lease_duration.as_secs());
            self.observed = Some(Observed {
                resource_version: rv,
                duration: Duration::from_secs(secs),
                at: self.clock.mono(),
            });
        }
    }

    fn observed_expired(&self) -> bool {
        self.observed
            .as_ref()
            .is_none_or(|o| self.clock.mono() >= o.at + o.duration)
    }

    pub async fn try_acquire_or_renew(&mut self) -> Result<Attempt, LeaseError> {
        let now = micro_time(self.clock.wall());
        let Some(existing) = self.api.get().await? else {
            let mut lease = Lease::named(&self.lease_name);
            lease.spec = LeaseSpec {
                holder_identity: Some(self.identity.clone()),
                lease_duration_seconds: Some(self.duration_secs()),
                acquire_time: Some(now.clone()),
                renew_time: Some(now),
                lease_transitions: Some(0),
                extra: Default::default(),
            };
            let created = self.api.create(&lease).await?;
            self.observe(&created);
            self.held = Some(created);
            return Ok(Attempt::Leading);
        };
        self.observe(&existing);
        let mine = existing.holder() == Some(self.identity.as_str());
        if let Some(holder) = existing.holder() {
            if !mine && !self.observed_expired() {
                self.held = None;
                return Ok(Attempt::Following {
                    holder: holder.to_string(),
                });
            }
        }
        let mut next = existing.clone();
        next.spec.holder_identity = Some(self.identity.clone());
        next.spec.lease_duration_seconds = Some(self.duration_secs());
        next.spec.renew_time = Some(now.clone());
        if !mine {
            next.spec.acquire_time = Some(now);
            next.spec.lease_transitions = Some(
                existing
                    .spec
                    .lease_transitions
                    .unwrap_or(0)
                    .saturating_add(1),
            );
        }
        match self.api.replace(&next).await {
            Ok(written) => {
                self.observe(&written);
                self.held = Some(written);
                Ok(Attempt::Leading)
            }
            Err(e) => {
                if e == LeaseError::Conflict {
                    self.held = None;
                }
                Err(e)
            }
        }
    }

    /// Give the lease up: clear the holder (and shorten the duration, as
    /// client-go does) so a follower acquires on its next retry. `false`
    /// when there was nothing of ours to release. A conflict means someone
    /// else already wrote it, so it is not ours to clear.
    ///
    /// Uses the lease as last written when it is still current; otherwise
    /// (an attempt abandoned mid-flight may have renewed it, or none ever
    /// returned) it re-reads, and clears the holder only if it is this
    /// replica, with the fresh resourceVersion.
    pub async fn release(&mut self) -> Result<bool, LeaseError> {
        if let Some(lease) = self.held.take() {
            match self.clear_holder(lease).await {
                Err(LeaseError::Conflict) => {}
                other => return other,
            }
        }
        match self.api.get().await? {
            Some(lease) => self.clear_holder(lease).await,
            None => Ok(false),
        }
    }

    async fn clear_holder(&mut self, mut lease: Lease) -> Result<bool, LeaseError> {
        if lease.holder() != Some(self.identity.as_str()) {
            return Ok(false);
        }
        let now = micro_time(self.clock.wall());
        lease.spec.holder_identity = None;
        lease.spec.lease_duration_seconds = Some(1);
        lease.spec.acquire_time = Some(now.clone());
        lease.spec.renew_time = Some(now);
        self.api.replace(&lease).await.map(|_| true)
    }
}

// ---------------------------------------------------------------------
// Driver: turns attempt results into gate updates
// ---------------------------------------------------------------------

pub(crate) struct Driver {
    renew_deadline: Duration,
    pub leading: bool,
    last_renew: Duration,
    /// The API has answered at least once with something other than a
    /// refusal.
    contacted: bool,
    /// Consecutive 401/403s before first contact.
    denials: u32,
    /// Consecutive failed attempts (any error), for periodic warnings.
    failing: u32,
    last_holder: Option<String>,
}

impl Driver {
    pub fn new(renew_deadline: Duration) -> Self {
        Self {
            renew_deadline,
            leading: false,
            last_renew: Duration::ZERO,
            contacted: false,
            denials: 0,
            failing: 0,
            last_holder: None,
        }
    }

    fn lose(&mut self, gate: &LeaderGate) {
        self.leading = false;
        gate.clear();
        gate.transitioned();
    }

    /// Apply one attempt's result. `started` is when the attempt began and
    /// `now` when it returned, both on the elector's monotonic clock.
    ///
    /// Leadership runs from `started`, not from the response: a renewal
    /// the API server committed at some instant in between keeps the gate
    /// open for at most `renewDeadline` after it, so a slow response never
    /// eats into the `leaseDuration - renewDeadline` margin a successor
    /// waits out.
    pub fn on_attempt(
        &mut self,
        result: &Result<Attempt, LeaseError>,
        started: Duration,
        now: Duration,
        gate: &LeaderGate,
    ) {
        if gate.mode() == Mode::FallbackDenied {
            match result {
                Ok(_) | Err(LeaseError::Conflict) => {
                    // RBAC arrived (or was slow to propagate at install):
                    // stop acting as leader, then compete like everyone else.
                    gate.clear();
                    gate.set_mode(Mode::Elected);
                    info!("leader election: the Lease API now accepts this broker; leaving the always-leader fallback and electing");
                }
                Err(e) => {
                    self.failing += 1;
                    gate.errored();
                    if self.failing.is_multiple_of(FALLBACK_WARN_EVERY) {
                        warn!(error = %e, "leader election still refused; this replica keeps running every cluster-singleton job (see broker_leader_election_active)");
                    }
                    return;
                }
            }
        }
        match result {
            Ok(_) | Err(LeaseError::Conflict) => {
                if self.failing > 0 {
                    info!(
                        failed_attempts = self.failing,
                        "leader election: lease requests recovered"
                    );
                }
                self.failing = 0;
                self.denials = 0;
            }
            Err(_) => gate.errored(),
        }
        match result {
            Ok(Attempt::Leading) => {
                self.contacted = true;
                self.last_renew = started;
                self.last_holder = None;
                gate.hold_until(started + self.renew_deadline);
                if !self.leading {
                    self.leading = true;
                    gate.transitioned();
                    // After the gate opens, so a Cadence that sees the new
                    // acquisition also sees this replica leading.
                    gate.acquired();
                    info!("leader election: acquired the lease; running cluster-singleton jobs");
                }
            }
            Ok(Attempt::Following { holder }) => {
                self.contacted = true;
                if self.leading {
                    info!(holder, "leader election: lost the lease to another replica");
                    self.lose(gate);
                }
                if self.last_holder.as_deref() != Some(holder.as_str()) {
                    info!(
                        holder,
                        "leader election: following; cluster-singleton jobs run on the holder"
                    );
                    self.last_holder = Some(holder.clone());
                }
            }
            Err(LeaseError::Conflict) => {
                // The API answered; the next read decides who holds it.
                self.contacted = true;
                debug!("leader election: lease update conflicted; re-reading");
            }
            Err(LeaseError::Denied(msg)) if !self.contacted => {
                self.denials += 1;
                if self.denials >= STARTUP_ATTEMPTS {
                    warn!(
                        error = %msg,
                        attempts = self.denials,
                        "leader election: the Lease API refuses this broker (is the chart's \
                         leader election Role installed?). Falling back to running every \
                         cluster-singleton job on this replica, as before leader election \
                         existed, and retrying every 30 s. With more than one replica they \
                         duplicate work until the RBAC exists; or set \
                         LEADER_ELECTION_ENABLED=false"
                    );
                    self.failing = 0;
                    gate.set_mode(Mode::FallbackDenied);
                    return;
                }
                debug!(error = %msg, attempt = self.denials, "leader election: refused; retrying (RBAC may still be propagating)");
            }
            Err(e) => {
                // Unreachable, timing out, 5xx, or refused after first
                // contact: stay a follower and keep trying. The singleton
                // jobs pause rather than risk a second leader.
                self.failing += 1;
                if self.failing == 1 || self.failing.is_multiple_of(FAILURE_WARN_EVERY) {
                    warn!(error = %e, leading = self.leading, attempts = self.failing,
                        "leader election: lease request failed; retrying (cluster-singleton jobs pause while no replica can hold the lease)");
                } else {
                    debug!(error = %e, attempt = self.failing, "leader election: lease request failed");
                }
            }
        }
        if self.leading && now >= self.last_renew + self.renew_deadline {
            info!(
                renew_deadline_secs = self.renew_deadline.as_secs(),
                "leader election: could not renew the lease in time; stopping cluster-singleton jobs"
            );
            self.lose(gate);
        }
    }
}

// ---------------------------------------------------------------------
// Process wiring
// ---------------------------------------------------------------------

struct Shutdown {
    request: tokio::sync::watch::Sender<bool>,
    done: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

static SHUTDOWN: OnceLock<Shutdown> = OnceLock::new();

/// Up to 20% extra on the follower's retry, from the clock's sub-second
/// noise, so replicas started together do not poll in lockstep.
fn jittered(period: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    period + period.mul_f64(f64::from(nanos % 1000) / 5000.0)
}

/// The elector loop. Shutdown is raced against the attempt in flight as
/// well as the sleep: an attempt is abandoned, never applied to the gate
/// once shutdown is requested, and the lease is released straight away.
async fn run<A: LeaseApi, C: Clock>(
    mut elector: Elector<A, C>,
    gate: &LeaderGate,
    timings: Timings,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    done: tokio::sync::oneshot::Sender<()>,
) {
    let mut driver = Driver::new(timings.renew_deadline);
    loop {
        let started = elector.clock.mono();
        let result = tokio::select! {
            r = elector.try_acquire_or_renew() => Some(r),
            _ = shutdown.changed() => None,
        };
        let Some(result) = result.filter(|_| !*shutdown.borrow()) else {
            break;
        };
        driver.on_attempt(&result, started, elector.clock.mono(), gate);
        let wait = if gate.mode() == Mode::FallbackDenied {
            FALLBACK_RETRY
        } else if driver.leading {
            timings.retry_period
        } else {
            jittered(timings.retry_period)
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
    }
    // Stop leader-only work before giving the lease away.
    gate.stop();
    match elector.release().await {
        Ok(true) => info!("leader election: released the lease for a successor"),
        Ok(false) => {}
        Err(e) => {
            warn!(error = %e, "leader election: could not release the lease; a successor takes over once it expires")
        }
    }
    let _ = done.send(());
}

/// Start leader election, or leave this replica as the permanent leader
/// when it is off. Call before spawning the leader-only loops: when
/// election is on, the gate is closed on return and opens only once the
/// lease is held.
pub fn spawn() {
    let setting = env_str("LEADER_ELECTION_ENABLED");
    let in_cluster = in_cluster();
    if !election_enabled(setting.as_deref(), in_cluster) {
        info!(
            in_cluster,
            "leader election disabled; this replica runs every cluster-singleton job"
        );
        return;
    }
    let timings = Timings::from_env();
    let lease_name =
        env_str("LEADER_ELECTION_LEASE_NAME").unwrap_or_else(|| DEFAULT_LEASE_NAME.into());
    let identity = identity();
    let Some(namespace) = namespace() else {
        misconfigured("no namespace (set POD_NAMESPACE or LEADER_ELECTION_NAMESPACE)".into());
        return;
    };
    let timeout = (timings.renew_deadline / 2).max(Duration::from_secs(1));
    let api = match KubeLeaseApi::in_cluster(&namespace, &lease_name, timeout) {
        Ok(api) => api,
        Err(e) => {
            misconfigured(format!("cannot build the in-cluster API client: {e}"));
            return;
        }
    };
    info!(
        lease = %lease_name,
        namespace = %namespace,
        identity = %identity,
        lease_duration_secs = timings.lease_duration.as_secs(),
        renew_deadline_secs = timings.renew_deadline.as_secs(),
        retry_period_secs = timings.retry_period.as_secs(),
        "leader election enabled; cluster-singleton jobs wait for the lease"
    );
    GATE.set_mode(Mode::Elected);
    let (request, rx) = tokio::sync::watch::channel(false);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let _ = SHUTDOWN.set(Shutdown {
        request,
        done: Mutex::new(Some(done_rx)),
    });
    let elector = Elector::new(
        api,
        SystemClock,
        &identity,
        &lease_name,
        timings.lease_duration,
    );
    actix_web::rt::spawn(run(elector, &GATE, timings, rx, done_tx));
}

/// Election was asked for but cannot start: act as the permanent leader,
/// as before election existed (every replica shares this configuration, so
/// they all do), and repeat the warning so it is not lost in startup logs.
fn misconfigured(why: String) {
    GATE.set_mode(Mode::FallbackMisconfigured);
    actix_web::rt::spawn(async move {
        loop {
            warn!(
                reason = %why,
                "leader election cannot start; this replica runs every cluster-singleton job \
                 (duplicated with more than one replica; see broker_leader_election_active)"
            );
            tokio::time::sleep(MISCONFIGURED_WARN_EVERY).await;
        }
    });
}

/// Stop leader-only work and release the lease, if held. Call when the
/// shutdown signal arrives, before draining HTTP. Bounded by
/// [`RELEASE_TIMEOUT`].
pub async fn shutdown() {
    GATE.stop();
    let Some(s) = SHUTDOWN.get() else {
        return;
    };
    let _ = s.request.send(true);
    let done = s.done.lock().ok().and_then(|mut d| d.take());
    if let Some(done) = done {
        if tokio::time::timeout(RELEASE_TIMEOUT, done).await.is_err() {
            warn!("leader election: lease release timed out");
        }
    }
}

#[cfg(test)]
#[path = "leader_tests.rs"]
mod tests;
