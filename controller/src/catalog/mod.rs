//! Node catalog (design: node SBOMs, in-house cataloging; PR 3).
//!
//! The Controller's privileged half: offer this node's running image
//! digests to the Broker, and for the one it is granted, open a running
//! container's root as a directory handle, hand it to the `cataloger`
//! sidecar over a Unix socket, and post the package list it returns.
//!
//! ```text
//!  pod watcher --try_send--> feed (Inventory) <--snapshot-- claim loop
//!                                                     |  POST /catalog/claims
//!                                                     v
//!                containerd pid + snapshot -> /proc/<pid> handle -> identity
//!                -> mountinfo -> mount id + snapshot check -> drift
//!                -> root fd -> checked worker.sock
//!                                                     |  PUT renew / fail / skip
//!                                                     v  POST /catalog/images/{d}/sbom
//! ```
//!
//! Gated by `NODE_CATALOG` (default off). Off, [`start`] returns before
//! reading any other variable: no task, no channel, no socket, no HTTP
//! call, and the pod watcher hooks are one failed `OnceLock` read each.
//!
//! On, it never touches the capture paths: ordinary tasks, the pod
//! watcher feeding them through a bounded channel it never waits on, and
//! every blocking step (`/proc`, PSI, the fork for the read-only clone,
//! the worker socket) on `spawn_blocking`. It is deliberately not a
//! supervised subsystem: like node facts, a catalog failure must never
//! end the Controller. A panic in the claim loop is logged and the loop
//! restarts after a minute ([`supervise`]).
//!
//! Memory is bounded so the catalog cannot OOM the Controller (which
//! would take capture down): one scan at a time, a response of at most
//! `NODE_CATALOG_MAX_RESPONSE_BYTES` (16 MiB default, 64 MiB cap) parsed
//! into bounded types with the raw buffer freed straight after, and the
//! upload built page by page by moving components (see `worker` and
//! `post` for the arithmetic). Worst case extra memory at the default is
//! about 16 MiB (raw) + 40 MiB (parsed) during parsing, then the parsed
//! SBOM plus one 7 MiB page and its HTTP body during upload.

pub mod api;
pub mod claim;
pub mod feed;
pub mod mountinfo;
pub mod post;
pub mod root;
pub mod scan;
pub mod worker;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use api::{ClaimRequest, ClaimUpdate, FailReason};
use claim::{Answer, Backoff, Broker, GrantCtx, GrantOutcome, HttpBroker, Scan};
use feed::{Cooldown, Inventory, Pacer, RunningContainer};
use worker::{PeerMode, PeerPolicy};

pub use scan::MAX_CANDIDATES;

pub const DEFAULT_SOCKET: &str = "/run/kguardian/catalog/worker.sock";
/// Default and ceiling for the worker response size.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// How often the loop looks at its inventory.
const TICK: Duration = Duration::from_secs(10);
/// How often counters are logged.
const SUMMARY_EVERY: Duration = Duration::from_secs(600);
/// Ceilings for operator-set waits (L7).
const MAX_STARTUP_JITTER: Duration = Duration::from_secs(3600);
const MAX_PRESSURE_DEFER: Duration = Duration::from_secs(24 * 3600);
/// Backoff on a 503 from the claim route: from 60 s, doubling, to 30 min.
const UNAVAILABLE_BASE: Duration = Duration::from_secs(60);
const UNAVAILABLE_CAP: Duration = Duration::from_secs(1800);
/// Wait after a claim loop panic before restarting it.
const RESTART_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// `NODE_CATALOG` (`on`/`true`/`1`); default off.
    pub enabled: bool,
    /// `NODE_CATALOG_SOCKET`.
    pub socket: PathBuf,
    /// `NODE_CATALOG_EPOCH` (default 1), bumped to re-catalog every digest.
    pub epoch: i64,
    /// `NODE_CATALOG_RO_CLONE`: pass a read-only `open_tree` clone of the
    /// root instead of the plain `O_PATH` fd, falling back when refused.
    pub ro_clone: bool,
    /// `NODE_CATALOG_HOST_PROC`, else `COMPUTE_HOST_PROC`, else `/proc`
    /// (the host procfs mount).
    pub host_proc: PathBuf,
    /// `NODE_CATALOG_SCAN_TIMEOUT_SECS` (600).
    pub scan_timeout: Duration,
    /// `NODE_CATALOG_MAX_FILES` (2 000 000).
    pub max_files: u64,
    /// `NODE_CATALOG_MAX_COMPONENTS` (50 000).
    pub max_components: u64,
    /// `NODE_CATALOG_MAX_RESPONSE_BYTES` (16 MiB, at most 64 MiB).
    pub max_response_bytes: u64,
    /// `NODE_CATALOG_MIN_SCAN_INTERVAL_SECS` (30): gap between claims.
    pub min_scan_interval: Duration,
    /// `NODE_CATALOG_IDLE_SECS` (600): an unchanged offer that got no
    /// grant is re-sent after this.
    pub idle: Duration,
    /// `NODE_CATALOG_STARTUP_JITTER_SECS` (120, at most 3600): first
    /// claim is delayed by a uniform draw from this.
    pub startup_jitter: Duration,
    /// `NODE_CATALOG_PRESSURE_THRESHOLD` (40): PSI `some avg10` percent
    /// above which scans are deferred.
    pub pressure_threshold: f64,
    /// `NODE_CATALOG_MAX_PRESSURE_DEFER_SECS` (1800, at most 86400):
    /// defer at most this long, then scan anyway.
    pub max_pressure_defer: Duration,
    /// `NODE_CATALOG_PEER_UIDS` (`0`): uids the worker may run as.
    pub peer_uids: Vec<u32>,
    /// `POD_UID` (downward API `metadata.uid`): the Controller's own pod,
    /// never offered. Found from mountinfo or the cgroup when unset.
    pub pod_uid: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: PathBuf::from(DEFAULT_SOCKET),
            epoch: 1,
            ro_clone: false,
            host_proc: PathBuf::from("/proc"),
            scan_timeout: Duration::from_secs(600),
            max_files: 2_000_000,
            max_components: 50_000,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            min_scan_interval: Duration::from_secs(30),
            idle: Duration::from_secs(600),
            startup_jitter: Duration::from_secs(120),
            pressure_threshold: 40.0,
            max_pressure_defer: Duration::from_secs(1800),
            peer_uids: vec![0],
            pod_uid: None,
        }
    }
}

fn num<T: std::str::FromStr>(name: &str, raw: Option<String>, default: T) -> T {
    match raw.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => default,
        Some(s) => s.parse().unwrap_or_else(|_| {
            warn!(env = name, value = s, "not a number; using the default");
            default
        }),
    }
}

fn capped(name: &str, v: Duration, max: Duration) -> Duration {
    if v > max {
        warn!(
            env = name,
            secs = v.as_secs(),
            max_secs = max.as_secs(),
            "over the maximum; clamped"
        );
        max
    } else {
        v
    }
}

impl Config {
    /// Pure parser over a variable lookup. With `NODE_CATALOG` off it
    /// returns without looking up anything else.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let d = Self::default();
        let enabled = crate::pod_watcher::parse_lenient_bool(
            get("NODE_CATALOG").as_deref().unwrap_or_default(),
            false,
        );
        if !enabled {
            return d;
        }
        let secs = |k: &str, def: Duration| Duration::from_secs(num(k, get(k), def.as_secs()));
        let text = |k: &str| {
            get(k)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let peer_uids: Vec<u32> = get("NODE_CATALOG_PEER_UIDS")
            .map(|s| s.split(',').filter_map(|u| u.trim().parse().ok()).collect())
            .filter(|v: &Vec<u32>| !v.is_empty())
            .unwrap_or(d.peer_uids.clone());
        Self {
            enabled,
            socket: text("NODE_CATALOG_SOCKET").map_or(d.socket, PathBuf::from),
            epoch: num("NODE_CATALOG_EPOCH", get("NODE_CATALOG_EPOCH"), d.epoch).max(0),
            ro_clone: crate::pod_watcher::parse_lenient_bool(
                get("NODE_CATALOG_RO_CLONE").as_deref().unwrap_or_default(),
                false,
            ),
            host_proc: text("NODE_CATALOG_HOST_PROC")
                .or_else(|| text("COMPUTE_HOST_PROC"))
                .map_or(d.host_proc, PathBuf::from),
            scan_timeout: secs("NODE_CATALOG_SCAN_TIMEOUT_SECS", d.scan_timeout)
                .clamp(Duration::from_secs(10), Duration::from_secs(1800)),
            max_files: num(
                "NODE_CATALOG_MAX_FILES",
                get("NODE_CATALOG_MAX_FILES"),
                d.max_files,
            ),
            max_components: num(
                "NODE_CATALOG_MAX_COMPONENTS",
                get("NODE_CATALOG_MAX_COMPONENTS"),
                d.max_components,
            )
            .min(post::MAX_COMPONENTS as u64),
            max_response_bytes: num(
                "NODE_CATALOG_MAX_RESPONSE_BYTES",
                get("NODE_CATALOG_MAX_RESPONSE_BYTES"),
                d.max_response_bytes,
            )
            .clamp(1 << 20, worker::MAX_RESPONSE_CEILING as u64),
            min_scan_interval: secs("NODE_CATALOG_MIN_SCAN_INTERVAL_SECS", d.min_scan_interval)
                .max(Duration::from_secs(30)),
            idle: secs("NODE_CATALOG_IDLE_SECS", d.idle).max(Duration::from_secs(60)),
            startup_jitter: capped(
                "NODE_CATALOG_STARTUP_JITTER_SECS",
                secs("NODE_CATALOG_STARTUP_JITTER_SECS", d.startup_jitter),
                MAX_STARTUP_JITTER,
            ),
            pressure_threshold: num(
                "NODE_CATALOG_PRESSURE_THRESHOLD",
                get("NODE_CATALOG_PRESSURE_THRESHOLD"),
                d.pressure_threshold,
            ),
            max_pressure_defer: capped(
                "NODE_CATALOG_MAX_PRESSURE_DEFER_SECS",
                secs("NODE_CATALOG_MAX_PRESSURE_DEFER_SECS", d.max_pressure_defer),
                MAX_PRESSURE_DEFER,
            ),
            peer_uids,
            pod_uid: text("POD_UID"),
        }
    }

    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn budgets(&self) -> worker::Budgets {
        worker::Budgets {
            max_files: self.max_files,
            max_components: self.max_components,
            max_depth: 4096,
            scan_timeout_ms: self.scan_timeout.as_millis() as u64,
            max_paths_per_package: api::MAX_PATHS_PER_COMPONENT as u64,
            max_response_bytes: self.max_response_bytes,
        }
    }
}

/// The catalog token, read like `BROKER_AUTH_TOKEN`: trimmed, empty is
/// unset.
fn catalog_token() -> Option<String> {
    std::env::var("BROKER_TOKEN_CATALOG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Start the node catalog, if it is on. `None` means nothing was
/// started: the feature is off, or it cannot run on this node (no
/// catalog token, an unmappable platform), which is logged once.
pub fn start(config: Config, node: String, broker_url: String) -> Option<JoinHandle<()>> {
    if !config.enabled {
        return None;
    }
    let Some(token) = catalog_token() else {
        warn!(
            "node catalog: NODE_CATALOG is on but BROKER_TOKEN_CATALOG is not set; \
             idle (token_missing). Set broker.auth.keys.catalog in the auth secret."
        );
        return None;
    };
    let Some(platform) = feed::node_platform() else {
        warn!(
            arch = std::env::consts::ARCH,
            "node catalog: no platform name for this architecture; idle"
        );
        return None;
    };
    let rx = feed::open()?;
    // Decided once: a socketpair and one getsockopt (M2).
    let mode = worker::probe_peer_mode();
    info!(
        socket = %config.socket.display(),
        epoch = config.epoch,
        platform,
        ro_clone = config.ro_clone,
        peer_check = mode.as_str(),
        "node catalog: on"
    );
    if mode == PeerMode::PathCheck {
        info!(
            "node catalog: this kernel has no SO_PEERPIDFD (Linux < 6.5); the worker is \
             verified by its socket file (uid 0, 0600, in a uid-0 0700 directory) and \
             SO_PEERCRED uid, without the cgroup check"
        );
    }
    let inventory = Arc::new(Mutex::new(Inventory::default()));
    let broker = Arc::new(HttpBroker::new(broker_url, &token));
    let policy = Arc::new(PeerPolicy {
        mode,
        allowed_uids: config.peer_uids.clone(),
        socket_owner: 0,
        host_proc: config.host_proc.clone(),
    });
    let ctx = Arc::new(LoopCtx {
        config,
        node,
        platform,
    });
    Some(tokio::spawn(async move {
        // Procfs reads off the runtime (L5): the own pod, and whether
        // trusted.* xattrs are readable (N3), both once.
        let cfg = ctx.config.clone();
        let (own, trusted_xattrs) = tokio::task::spawn_blocking(move || {
            let status = std::fs::read_to_string(cfg.host_proc.join("self/status"));
            (own_pod(&cfg), status.is_ok_and(|s| root::cap_sys_admin(&s)))
        })
        .await
        .unwrap_or((None, false));
        if !trusted_xattrs {
            warn!(
                "node catalog: no CAP_SYS_ADMIN in the Controller's effective set, so \
                 trusted.overlay.* xattrs cannot be read and an opaque directory in a \
                 container's upperdir would go unseen; every SBOM from this node is partial \
                 (drift_unknown)"
            );
        }
        lock(&inventory).set_own_pod(own);
        tokio::spawn(drain_feed(rx, Arc::clone(&inventory)));
        let env = Arc::new(NodeEnv {
            policy,
            runtime: Arc::new(scan::Containerd),
            platform: ctx.platform.clone(),
            config: ctx.config.clone(),
            trusted_xattrs,
        });
        supervise(
            move || {
                claim_loop(
                    Arc::clone(&ctx),
                    Arc::clone(&broker),
                    Arc::clone(&env),
                    Arc::clone(&inventory),
                )
            },
            RESTART_AFTER,
        )
        .await;
    }))
}

/// Run `make()`'s future as a task until it returns; restart it after
/// `restart_after` when it panics. A panic is logged, never propagated.
pub async fn supervise<F, Fut>(make: F, restart_after: Duration)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        match tokio::spawn(make()).await {
            Ok(()) => return,
            Err(e) => {
                error!(
                    error = %e,
                    restart_secs = restart_after.as_secs(),
                    "node catalog: claim loop crashed; restarting"
                );
                tokio::time::sleep(restart_after).await;
            }
        }
    }
}

/// The Controller's own pod UID, so its digests are never offered.
fn own_pod(config: &Config) -> Option<String> {
    let read = |f: &str| std::fs::read_to_string(config.host_proc.join("self").join(f)).ok();
    match feed::own_pod_uid(
        config.pod_uid.as_deref(),
        read("mountinfo").as_deref(),
        read("cgroup").as_deref(),
    ) {
        Some((uid, source)) => {
            info!(
                pod_uid = uid,
                ?source,
                "node catalog: excluding the Controller's own pod"
            );
            Some(uid)
        }
        None => {
            warn!(
                "node catalog: cannot tell the Controller's own pod (set POD_UID from \
                 metadata.uid); its images may be offered and fail pid_gone"
            );
            None
        }
    }
}

fn lock(inv: &Mutex<Inventory>) -> std::sync::MutexGuard<'_, Inventory> {
    inv.lock().unwrap_or_else(|p| p.into_inner())
}

async fn drain_feed(
    mut rx: tokio::sync::mpsc::Receiver<feed::FeedMsg>,
    inv: Arc<Mutex<Inventory>>,
) {
    while let Some(m) = rx.recv().await {
        lock(&inv).apply(m);
    }
}

pub struct LoopCtx {
    pub config: Config,
    pub node: String,
    pub platform: String,
}

/// Counters, logged every [`SUMMARY_EVERY`] (the Controller exports no
/// Prometheus endpoint; the Broker's `kguardian_node_catalog_*` metrics
/// are the fleet view, these are this node's).
#[derive(Debug, Default)]
struct Stats {
    claims: u64,
    granted: u64,
    stored: u64,
    lost_leases: u64,
    abandoned: u64,
    worker_unavailable: u64,
    deferred_pressure: u64,
    failed: BTreeMap<&'static str, u64>,
}

impl Stats {
    fn log(&self, containers: usize) {
        info!(
            containers,
            claims = self.claims,
            granted = self.granted,
            stored = self.stored,
            lost_leases = self.lost_leases,
            abandoned = self.abandoned,
            worker_unavailable = self.worker_unavailable,
            deferred_pressure = self.deferred_pressure,
            failed = ?self.failed,
            "node catalog: summary"
        );
    }
}

/// PSI `some avg10` from a pressure file body.
pub fn psi_some_avg10(body: &str) -> Option<f64> {
    body.lines()
        .find(|l| l.starts_with("some "))?
        .split_whitespace()
        .find_map(|f| f.strip_prefix("avg10="))?
        .parse()
        .ok()
}

/// The highest of cpu/io/memory `some avg10` on the host, if any is
/// readable (no PSI means no deferral).
fn host_pressure(host_proc: &Path) -> Option<f64> {
    ["cpu", "io", "memory"]
        .iter()
        .filter_map(|r| std::fs::read_to_string(host_proc.join("pressure").join(r)).ok())
        .filter_map(|b| psi_some_avg10(&b))
        .reduce(f64::max)
}

/// What the claim loop needs from the node, so it runs in tests against
/// scripted answers.
pub trait LoopEnv: Send + Sync + 'static {
    type Scanner: Scan;
    /// Is the worker there and answering?
    fn ping(&self) -> impl Future<Output = Result<(), String>> + Send;
    /// Host pressure (PSI `some avg10`, percent), if known.
    fn pressure(&self) -> impl Future<Output = Option<f64>> + Send;
    /// A scanner for one grant over these candidates.
    fn scanner(&self, candidates: Vec<RunningContainer>) -> Self::Scanner;
}

/// The real node.
pub struct NodeEnv {
    pub config: Config,
    pub platform: String,
    pub policy: Arc<PeerPolicy>,
    pub runtime: Arc<scan::Containerd>,
    /// CAP_SYS_ADMIN is effective (see `scan::ScanConfig`).
    pub trusted_xattrs: bool,
}

impl LoopEnv for NodeEnv {
    type Scanner = scan::NodeScanner<scan::Containerd>;

    /// `ping` before claiming, so a missing sidecar never holds a lease
    /// (PROTOCOL.md 3.3). The same socket and peer checks as a scan.
    async fn ping(&self) -> Result<(), String> {
        let path = self.config.socket.clone();
        let policy = Arc::clone(&self.policy);
        tokio::task::spawn_blocking(move || {
            let id = format!("ping-{}", uuid::Uuid::new_v4().simple());
            let r = worker::call(
                &path,
                &policy,
                &worker::ping_request(id.clone()),
                None,
                worker::Limits {
                    response_bytes: 1 << 20,
                    read_timeout: worker::PING_TIMEOUT,
                },
                &AtomicBool::new(false),
            )
            .map_err(|e| e.to_string())?;
            if r.status.as_str() == "ok" && r.scan_id.as_str() == id {
                Ok(())
            } else {
                Err(format!(
                    "ping answered {} {}",
                    r.status.as_str(),
                    r.reason.as_str()
                ))
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    async fn pressure(&self) -> Option<f64> {
        let host_proc = self.config.host_proc.clone();
        tokio::task::spawn_blocking(move || host_pressure(&host_proc))
            .await
            .ok()
            .flatten()
    }

    fn scanner(&self, candidates: Vec<RunningContainer>) -> Self::Scanner {
        scan::NodeScanner {
            config: scan::ScanConfig {
                host_proc: self.config.host_proc.clone(),
                socket: self.config.socket.clone(),
                epoch: self.config.epoch,
                ro_clone: self.config.ro_clone,
                budgets: self.config.budgets(),
                read_timeout: self.config.scan_timeout + worker::READ_GRACE,
                platform: self.platform.clone(),
                trusted_xattrs: self.trusted_xattrs,
            },
            policy: Arc::clone(&self.policy),
            runtime: Arc::clone(&self.runtime),
            candidates,
        }
    }
}

/// At most one event per `every`.
#[derive(Debug)]
pub struct RateLimit {
    every: Duration,
    last: Option<Instant>,
}

impl RateLimit {
    pub fn new(every: Duration) -> Self {
        Self { every, last: None }
    }

    /// Starts as if an event had just happened (the first `allow` is one
    /// period away).
    pub fn starting(every: Duration, now: Instant) -> Self {
        Self {
            every,
            last: Some(now),
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        match self.last {
            Some(l) if now.saturating_duration_since(l) < self.every => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

/// How often degraded mode repeats its warning.
const DEGRADED_WARN_EVERY: Duration = Duration::from_secs(3600);

/// How often degraded mode asks again under the real epoch.
const DEGRADED_PROBE_EVERY: Duration = Duration::from_secs(3600);

/// Claiming cannot work on this node (the Broker refuses this
/// Controller's claims as a contract violation, 422, e.g. an epoch above
/// its `NODE_CATALOG_MAX_EPOCH`). Stop claiming, visibly, until the
/// Broker accepts the real epoch again:
///
/// * one `error` line naming the cause (logged by the caller);
/// * an empty offer every `every`, under epoch 0 (an empty offer can be
///   granted nothing, and 0 is valid on any Broker): the Broker records
///   the node and its platform, with no claims;
/// * once an hour, an empty offer under the configured epoch instead: a
///   200 means the Broker takes it now (its limit was raised), and the
///   caller resumes claiming;
/// * a `warn` at most once an hour.
///
/// Returns only on that 200; never retries hot.
async fn degraded<B: Broker>(ctx: &LoopCtx, broker: &B, why: &str, every: Duration) {
    let now = Instant::now();
    let mut warn_limit = RateLimit::starting(DEGRADED_WARN_EVERY, now);
    let mut probe = RateLimit::starting(DEGRADED_PROBE_EVERY, now);
    loop {
        tokio::time::sleep(every).await;
        let real = probe.allow(Instant::now());
        let req = ClaimRequest {
            node: ctx.node.clone(),
            platform: ctx.platform.clone(),
            epoch: if real { ctx.config.epoch } else { 0 },
            offer: Vec::new(),
        };
        let answer = broker.claim(&req).await;
        if let Answer::Ok(api::ClaimResponse { grant: Some(g), .. }) = &answer {
            // An empty offer cannot be granted anything; never scan here.
            warn!(
                digest = g.digest,
                "node catalog: ignoring a grant in degraded mode"
            );
        }
        if real && matches!(answer, Answer::Ok(_)) {
            info!(
                epoch = ctx.config.epoch,
                "node catalog: the Broker accepts this epoch again; resuming claims"
            );
            return;
        }
        if warn_limit.allow(Instant::now()) {
            warn!(cause = why, "node catalog: still not claiming on this node");
        }
    }
}

/// How long a digest stays out of this node's offers after a grant.
fn cooldown_for(outcome: &GrantOutcome) -> Duration {
    const H: u64 = 3600;
    Duration::from_secs(match outcome {
        GrantOutcome::Stored { .. } => 24 * H,
        GrantOutcome::Reported(r) => match r {
            FailReason::NoPackagesFound => 24 * H,
            r if r.action() == api::Action::Skip => 24 * H,
            FailReason::Timeout | FailReason::Oom | FailReason::Error => H,
            _ => 600,
        },
        GrantOutcome::LostLease | GrantOutcome::Abandoned(_) => 900,
    })
}

async fn claim_loop<B: Broker + 'static, E: LoopEnv>(
    ctx: Arc<LoopCtx>,
    broker: Arc<B>,
    env: Arc<E>,
    inv: Arc<Mutex<Inventory>>,
) {
    let cfg = &ctx.config;
    let first = feed::jitter(cfg.startup_jitter);
    debug!(
        delay_secs = first.as_secs(),
        "node catalog: first claim delayed"
    );
    tokio::time::sleep(first).await;

    let mut pacer = Pacer::new(cfg.min_scan_interval, cfg.idle);
    let mut cooldown = Cooldown::default();
    let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(300));
    let mut unavailable = Backoff::new(UNAVAILABLE_BASE, UNAVAILABLE_CAP);
    let mut unavailable_logged = false;
    let mut stats = Stats::default();
    let mut last_summary = Instant::now();
    let mut deferred_since: Option<Instant> = None;
    let mut worker_down_logged = false;
    let mut grants_off_logged = false;

    loop {
        tokio::time::sleep(TICK).await;
        let now = Instant::now();
        // Pacer and cooldown keep std instants; tokio's converts (and
        // follows the paused clock in tests).
        let now_std = now.into_std();
        if now.duration_since(last_summary) >= SUMMARY_EVERY {
            stats.log(lock(&inv).containers());
            last_summary = now;
        }
        cooldown.prune(now_std);
        let offer = feed::offer(&lock(&inv), &cooldown, now_std);
        if !pacer.due(&offer, now_std) {
            continue;
        }

        // Node pressure: defer, but not forever.
        match env.pressure().await {
            Some(p) if p > cfg.pressure_threshold => {
                let since = *deferred_since.get_or_insert(now);
                if now.duration_since(since) < cfg.max_pressure_defer {
                    stats.deferred_pressure += 1;
                    debug!(pressure = p, "node catalog: node under pressure; deferring");
                    continue;
                }
                info!(
                    pressure = p,
                    "node catalog: deferred for the maximum; scanning anyway"
                );
            }
            _ => {}
        }
        deferred_since = None;

        if let Err(e) = env.ping().await {
            stats.worker_unavailable += 1;
            if !worker_down_logged {
                warn!(error = e, "node catalog: worker unavailable; not claiming");
                worker_down_logged = true;
            }
            // Counted as a no-grant: retried after `idle`, or sooner on
            // a changed offer.
            pacer.sent(&offer, false, now_std);
            continue;
        }
        if worker_down_logged {
            info!("node catalog: worker available again");
            worker_down_logged = false;
        }

        stats.claims += 1;
        let req = ClaimRequest {
            node: ctx.node.clone(),
            platform: ctx.platform.clone(),
            epoch: cfg.epoch,
            offer: offer.clone(),
        };
        let grant = match broker.claim(&req).await {
            Answer::Ok(r) => {
                backoff.reset();
                unavailable.reset();
                unavailable_logged = false;
                if !r.grants_enabled && !grants_off_logged {
                    info!("node catalog: grants are switched off on the Broker");
                }
                grants_off_logged = !r.grants_enabled;
                pacer.sent(&offer, r.grant.is_some(), now_std);
                r.grant
            }
            Answer::Unavailable(hint) => {
                let d = unavailable.next(Some(hint));
                if !unavailable_logged {
                    warn!(
                        wait_secs = d.as_secs(),
                        "node catalog: Broker catalog unavailable (503); backing off up to 30 min"
                    );
                    unavailable_logged = true;
                }
                tokio::time::sleep(d).await;
                continue;
            }
            Answer::Missing => {
                warn!("node catalog: the Broker has no catalog routes (404); idle for 30 min");
                tokio::time::sleep(UNAVAILABLE_CAP).await;
                continue;
            }
            Answer::Retry(hint) => {
                let d = backoff.next(hint);
                debug!(
                    wait_secs = d.as_secs(),
                    "node catalog: claim failed; backing off"
                );
                tokio::time::sleep(d).await;
                continue;
            }
            Answer::Refused(422, body) => {
                error!(
                    epoch = cfg.epoch,
                    body,
                    "node catalog: the Broker refuses this node's claims (422). Check \
                     NODE_CATALOG_EPOCH on the Controller against the Broker's \
                     NODE_CATALOG_MAX_EPOCH. Not claiming; asking again under this \
                     epoch once an hour"
                );
                degraded(&ctx, broker.as_ref(), &body, cfg.idle).await;
                pacer = Pacer::new(cfg.min_scan_interval, cfg.idle);
                continue;
            }
            other => {
                warn!(answer = ?other, "node catalog: claim refused");
                pacer.sent(&offer, false, now_std);
                continue;
            }
        };
        let Some(grant) = grant else { continue };
        if !offer.contains(&grant.digest) {
            // Not ours to scan: hand it straight back (L2).
            warn!(
                digest = grant.digest,
                "node catalog: granted a digest that was not offered; failing it"
            );
            let u = ClaimUpdate {
                action: api::Action::Fail,
                node: ctx.node.clone(),
                reason: Some(FailReason::Error.as_str().to_string()),
            };
            let _ = broker.update(&grant.digest, &grant.claim_token, &u).await;
            continue;
        }
        stats.granted += 1;
        let candidates = lock(&inv).candidates(&grant.digest);
        info!(
            digest = grant.digest,
            candidates = candidates.len(),
            lease_expires_at = grant.lease_expires_at.as_deref().unwrap_or(""),
            "node catalog: granted"
        );
        let scanner = env.scanner(candidates);
        let gctx = GrantCtx {
            broker: broker.as_ref(),
            node: &ctx.node,
            digest: &grant.digest,
            token: &grant.claim_token,
            renew_every: claim::RENEW_EVERY,
            busy_wait: claim::BUSY_WAIT,
            retry_base: Duration::from_secs(2),
        };
        // The scan and upload use `cfg.epoch`, the epoch this claim was
        // just made under: the Broker grants under the request's epoch,
        // so by construction the upload's epoch is the grant's (L1).
        let started = Instant::now();
        let outcome = claim::run_grant(&gctx, &scanner).await;
        match &outcome {
            GrantOutcome::Stored { pages, status } => {
                stats.stored += 1;
                info!(
                    digest = grant.digest,
                    pages,
                    status,
                    secs = started.elapsed().as_secs(),
                    "node catalog: SBOM posted"
                );
            }
            GrantOutcome::Reported(r) => *stats.failed.entry(r.as_str()).or_default() += 1,
            GrantOutcome::LostLease => stats.lost_leases += 1,
            GrantOutcome::Abandoned(why) => {
                stats.abandoned += 1;
                warn!(
                    digest = grant.digest,
                    why, "node catalog: grant abandoned; the lease will expire"
                );
            }
        }
        cooldown.hold(
            &grant.digest,
            Instant::now().into_std(),
            cooldown_for(&outcome),
        );
    }
}

#[cfg(test)]
mod tests;
