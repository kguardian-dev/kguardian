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
//!                        containerd pid -> /proc/<pid> handle -> identity
//!                        -> mountinfo -> drift -> root fd -> worker.sock
//!                                                     |  PUT renew / fail / skip
//!                                                     v  POST /catalog/images/{d}/sbom
//! ```
//!
//! Gated by `NODE_CATALOG` (default off). Off, [`start`] returns before
//! reading any other variable: no task, no channel, no socket, no HTTP
//! call, and the pod watcher hooks are one failed `OnceLock` read each.
//!
//! On, it never touches the capture paths: two ordinary tasks, the
//! pod watcher feeding them through a bounded channel it never waits
//! on, and every blocking step (`/proc`, the fork for the read-only
//! clone, the worker socket) on `spawn_blocking`. It is deliberately
//! not a supervised subsystem: like node facts, a catalog failure must
//! never end the Controller. A panic in the claim loop is logged and the
//! loop restarts after a minute.

pub mod api;
pub mod claim;
pub mod feed;
pub mod mountinfo;
pub mod post;
pub mod root;
pub mod worker;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use api::{ClaimRequest, FailReason};
use claim::{Answer, Backoff, Broker, GrantCtx, GrantOutcome, HttpBroker, Scan, ScanResult};
use feed::{Cooldown, Inventory, Pacer, RunningContainer};

pub const DEFAULT_SOCKET: &str = "/run/kguardian/catalog/worker.sock";

/// Candidates (replicas) tried for one grant before reporting
/// drift / pid_gone (design section 2 retry caps are the Broker's; this
/// bounds the local work per grant).
pub const MAX_CANDIDATES: usize = 3;
/// How often the loop looks at its inventory.
const TICK: Duration = Duration::from_secs(10);
/// How often counters are logged.
const SUMMARY_EVERY: Duration = Duration::from_secs(600);

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
    /// `NODE_CATALOG_HOST_PROC` (default `/proc`, the host procfs mount).
    pub host_proc: PathBuf,
    /// `NODE_CATALOG_SCAN_TIMEOUT_SECS` (600).
    pub scan_timeout: Duration,
    /// `NODE_CATALOG_MAX_FILES` (2 000 000).
    pub max_files: u64,
    /// `NODE_CATALOG_MAX_COMPONENTS` (50 000).
    pub max_components: u64,
    /// `NODE_CATALOG_MAX_RESPONSE_BYTES` (32 MiB, at most 64 MiB).
    pub max_response_bytes: u64,
    /// `NODE_CATALOG_MIN_SCAN_INTERVAL_SECS` (30): gap between claims.
    pub min_scan_interval: Duration,
    /// `NODE_CATALOG_IDLE_SECS` (600): an unchanged offer that got no
    /// grant is re-sent after this.
    pub idle: Duration,
    /// `NODE_CATALOG_STARTUP_JITTER_SECS` (120): first claim is delayed
    /// by a uniform draw from this, so a fleet restart does not stampede.
    pub startup_jitter: Duration,
    /// `NODE_CATALOG_PRESSURE_THRESHOLD` (40): PSI `some avg10` percent
    /// above which scans are deferred.
    pub pressure_threshold: f64,
    /// `NODE_CATALOG_MAX_PRESSURE_DEFER_SECS` (1800): defer at most this
    /// long, then scan anyway (the worker runs at nice 19, idle I/O).
    pub max_pressure_defer: Duration,
    /// `NODE_CATALOG_PEER_UIDS` (`0`): uids the worker may run as.
    pub peer_uids: Vec<u32>,
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
            max_response_bytes: 32 * 1024 * 1024,
            min_scan_interval: Duration::from_secs(30),
            idle: Duration::from_secs(600),
            startup_jitter: Duration::from_secs(120),
            pressure_threshold: 40.0,
            max_pressure_defer: Duration::from_secs(1800),
            peer_uids: vec![0],
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
        let path = |k: &str, def: &Path| {
            get(k)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map_or_else(|| def.to_path_buf(), PathBuf::from)
        };
        let peer_uids: Vec<u32> = get("NODE_CATALOG_PEER_UIDS")
            .map(|s| s.split(',').filter_map(|u| u.trim().parse().ok()).collect())
            .filter(|v: &Vec<u32>| !v.is_empty())
            .unwrap_or(d.peer_uids.clone());
        Self {
            enabled,
            socket: path("NODE_CATALOG_SOCKET", &d.socket),
            epoch: num("NODE_CATALOG_EPOCH", get("NODE_CATALOG_EPOCH"), d.epoch).max(0),
            ro_clone: crate::pod_watcher::parse_lenient_bool(
                get("NODE_CATALOG_RO_CLONE").as_deref().unwrap_or_default(),
                false,
            ),
            host_proc: path("NODE_CATALOG_HOST_PROC", &d.host_proc),
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
            .min(worker::MAX_RESPONSE_CEILING as u64),
            min_scan_interval: secs("NODE_CATALOG_MIN_SCAN_INTERVAL_SECS", d.min_scan_interval)
                .max(Duration::from_secs(30)),
            idle: secs("NODE_CATALOG_IDLE_SECS", d.idle).max(Duration::from_secs(60)),
            startup_jitter: secs("NODE_CATALOG_STARTUP_JITTER_SECS", d.startup_jitter),
            pressure_threshold: num(
                "NODE_CATALOG_PRESSURE_THRESHOLD",
                get("NODE_CATALOG_PRESSURE_THRESHOLD"),
                d.pressure_threshold,
            ),
            max_pressure_defer: secs("NODE_CATALOG_MAX_PRESSURE_DEFER_SECS", d.max_pressure_defer),
            peer_uids,
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
    info!(
        socket = %config.socket.display(),
        epoch = config.epoch,
        platform,
        ro_clone = config.ro_clone,
        "node catalog: on"
    );
    let inventory = Arc::new(Mutex::new(Inventory::default()));
    tokio::spawn(drain_feed(rx, Arc::clone(&inventory)));
    let broker = Arc::new(HttpBroker::new(broker_url, &token));
    let ctx = Arc::new(LoopCtx {
        config,
        node,
        platform,
    });
    Some(tokio::spawn(async move {
        loop {
            let run = tokio::spawn(claim_loop(
                Arc::clone(&ctx),
                Arc::clone(&broker),
                Arc::clone(&inventory),
            ));
            match run.await {
                Ok(()) => return,
                Err(e) => {
                    error!(error = %e, "node catalog: claim loop crashed; restarting in 60s");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        }
    }))
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

struct LoopCtx {
    config: Config,
    node: String,
    platform: String,
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

/// Is the worker there and answering? `ping` before claiming, so a
/// missing sidecar never holds a lease (PROTOCOL.md 3.3).
async fn ping(cfg: &Config) -> Result<(), String> {
    let path = cfg.socket.clone();
    let uids = cfg.peer_uids.clone();
    let host_proc = cfg.host_proc.clone();
    tokio::task::spawn_blocking(move || {
        let id = format!("ping-{}", uuid::Uuid::new_v4().simple());
        let r = worker::call(
            &path,
            &uids,
            &worker::HostPeerProc { host_proc },
            &worker::ping_request(id.clone()),
            None,
            1 << 20,
            worker::PING_TIMEOUT,
            &AtomicBool::new(false),
        )
        .map_err(|e| e.to_string())?;
        if r.status == "ok" && r.scan_id == id {
            Ok(())
        } else {
            Err(format!("ping answered {} {}", r.status, r.reason))
        }
    })
    .await
    .map_err(|e| e.to_string())?
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

async fn claim_loop<B: Broker + 'static>(
    ctx: Arc<LoopCtx>,
    broker: Arc<B>,
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
    let mut stats = Stats::default();
    let mut last_summary = Instant::now();
    let mut deferred_since: Option<Instant> = None;
    let mut worker_down_logged = false;
    let mut grants_off_logged = false;

    loop {
        tokio::time::sleep(TICK).await;
        let now = Instant::now();
        if now.duration_since(last_summary) >= SUMMARY_EVERY {
            stats.log(lock(&inv).containers());
            last_summary = now;
        }
        cooldown.prune(now);
        let offer = feed::offer(&lock(&inv), &cooldown, now);
        if !pacer.due(&offer, now) {
            continue;
        }

        // Node pressure: defer, but not forever.
        match host_pressure(&cfg.host_proc) {
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

        if let Err(e) = ping(cfg).await {
            stats.worker_unavailable += 1;
            if !worker_down_logged {
                warn!(error = e, "node catalog: worker unavailable; not claiming");
                worker_down_logged = true;
            }
            // Counted as a no-grant: retried after `idle`, or sooner on
            // a changed offer.
            pacer.sent(&offer, false, now);
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
                if !r.grants_enabled && !grants_off_logged {
                    info!("node catalog: grants are switched off on the Broker");
                }
                grants_off_logged = !r.grants_enabled;
                pacer.sent(&offer, r.grant.is_some(), now);
                r.grant
            }
            Answer::Unavailable(d) => {
                warn!(
                    wait_secs = d.as_secs(),
                    "node catalog: Broker catalog unavailable (503)"
                );
                tokio::time::sleep(d.max(Duration::from_secs(60))).await;
                continue;
            }
            Answer::Missing => {
                warn!("node catalog: the Broker has no catalog routes (404); idle for 30 min");
                tokio::time::sleep(Duration::from_secs(1800)).await;
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
            other => {
                warn!(answer = ?other, "node catalog: claim refused");
                pacer.sent(&offer, false, now);
                continue;
            }
        };
        let Some(grant) = grant else { continue };
        if !offer.contains(&grant.digest) {
            warn!(
                digest = grant.digest,
                "node catalog: granted a digest that was not offered"
            );
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
        let scanner = NodeScanner {
            config: cfg.clone(),
            platform: ctx.platform.clone(),
            candidates,
        };
        let gctx = GrantCtx {
            broker: broker.as_ref(),
            node: &ctx.node,
            digest: &grant.digest,
            token: &grant.claim_token,
            renew_every: claim::RENEW_EVERY,
            busy_wait: claim::BUSY_WAIT,
            retry_base: Duration::from_secs(2),
        };
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
        cooldown.hold(&grant.digest, Instant::now(), cooldown_for(&outcome));
    }
}

// ---- The real scan -----------------------------------------------------

/// One grant's scan over this node's candidates for the digest.
struct NodeScanner {
    config: Config,
    platform: String,
    candidates: Vec<RunningContainer>,
}

/// One candidate's result (see [`ScanResult`] on its size).
#[allow(clippy::large_enum_variant)]
enum Attempt {
    Done(ScanResult),
    Drift(&'static str),
    PidGone(String),
}

/// The container's task pid from containerd, with the existing bounds.
async fn task_pid(container_id: &str) -> Option<u32> {
    let sock = crate::container::containerd_sock();
    let ch = crate::container::connect_containerd(&sock, crate::container::CONNECT_TIMEOUT).await?;
    crate::PodInspect {
        container_id: Some(container_id.to_string()),
        ..Default::default()
    }
    .get_pid(ch)
    .await
    .pid
}

fn failed(reason: FailReason, detail: impl Into<String>) -> Attempt {
    Attempt::Done(ScanResult::Failed {
        reason,
        detail: detail.into(),
    })
}

/// Everything blocking for one candidate, on a `spawn_blocking` thread.
fn scan_one(
    cfg: &Config,
    platform: &str,
    c: &RunningContainer,
    pid: u32,
    cancel: &AtomicBool,
) -> Attempt {
    use root::{AcquireError, Drift, ProcDir};

    let dir = match ProcDir::open(&cfg.host_proc, pid) {
        Ok(d) => d,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) => {
            return Attempt::PidGone(format!("pid {pid} gone"))
        }
        Err(e) => return failed(FailReason::Error, format!("open /proc/{pid}: {e}")),
    };
    let want = root::Expected {
        pod_uid: c.pod_uid.clone(),
        container_id: c.container_id.clone(),
    };
    let acq = match root::acquire(&dir, &want) {
        Ok(a) => a,
        Err(AcquireError::PidGone(why)) => return Attempt::PidGone(why.to_string()),
        Err(AcquireError::Io(e)) => return failed(FailReason::Error, format!("acquire: {e}")),
    };
    let info = match mountinfo::root_info(&mountinfo::parse(&acq.mountinfo)) {
        Ok(i) => i,
        Err(mountinfo::RootRefusal::LazySnapshotter) => {
            return failed(FailReason::LazySnapshotter, "lazily pulled root")
        }
        Err(mountinfo::RootRefusal::UnsupportedRootfs) => {
            return failed(FailReason::UnsupportedRootfs, "root is not overlayfs")
        }
    };
    if info.submounts_dropped > 0 {
        debug!(
            dropped = info.submounts_dropped,
            "node catalog: submounts left out of the request"
        );
    }
    let drift = match root::open_host_root(&cfg.host_proc) {
        Ok(h) => root::drift_check(std::os::fd::AsRawFd::as_raw_fd(&h), &info.upperdir),
        Err(e) => Drift::Unknown(format!("open /proc/1/root: {e}")),
    };
    let drift_unknown = match drift {
        Drift::Drifted(db) => return Attempt::Drift(db),
        Drift::Unknown(why) => {
            info!(
                container = c.container_id,
                why, "node catalog: drift unknown; SBOM will be partial"
            );
            true
        }
        Drift::Clean => false,
    };
    let root_fd = if cfg.ro_clone {
        match root::readonly_clone(&dir) {
            Ok(clone) => clone,
            Err(e) => {
                debug!(error = %e, "node catalog: read-only clone unavailable; passing the O_PATH root");
                acq.root
            }
        }
    } else {
        acq.root
    };

    let scan_id = uuid::Uuid::new_v4().to_string();
    let req = worker::Request {
        protocol_version: worker::PROTOCOL_VERSION,
        op: "scan",
        scan_id: scan_id.clone(),
        epoch: Some(cfg.epoch),
        container_start_unix_nanos: Some(root::start_unix_nanos(acq.start_ticks)),
        submounts: info.submounts,
        profile: Some("full"),
        budgets: Some(cfg.budgets()),
    };
    let resp = worker::call(
        &cfg.socket,
        &cfg.peer_uids,
        &worker::HostPeerProc {
            host_proc: cfg.host_proc.clone(),
        },
        &req,
        Some(root_fd),
        cfg.max_response_bytes as usize,
        cfg.scan_timeout + worker::READ_GRACE,
        cancel,
    );
    let resp = match resp {
        Ok(r) => r,
        Err(worker::WorkerError::Cancelled) => return Attempt::Done(ScanResult::Cancelled),
        Err(worker::WorkerError::Timeout) => {
            return failed(FailReason::Timeout, "no answer in time")
        }
        Err(e @ worker::WorkerError::Unavailable(_))
        | Err(e @ worker::WorkerError::PeerRejected(_)) => {
            error!(error = %e, "node catalog: cannot hand off to the worker");
            return failed(FailReason::WorkerUnavailable, e.to_string());
        }
        Err(e) => return failed(FailReason::Error, e.to_string()),
    };
    match post::validate(resp, &scan_id, cfg.epoch, drift_unknown) {
        Ok(post::Outcome::Sbom(sbom)) => Attempt::Done(ScanResult::Sbom {
            subject: post::Subject {
                digest: c.digest.clone(),
                // The Broker's digest_kind is index | manifest, which the
                // pod status cannot tell apart (a repo digest is either);
                // left out, it is stored as unknown.
                digest_kind: None,
                repository: c.repository.clone(),
                platform: platform.to_string(),
                epoch: cfg.epoch,
            },
            sbom,
        }),
        Ok(post::Outcome::Failed { reason, .. }) if reason == "busy" => {
            Attempt::Done(ScanResult::Busy)
        }
        Ok(post::Outcome::Failed { reason, message }) => failed(
            FailReason::from_worker(&reason),
            format!("{reason}: {message}"),
        ),
        Err(post::Invalid(why)) => {
            warn!(why, "node catalog: worker response refused");
            failed(FailReason::Error, why)
        }
    }
}

impl Scan for NodeScanner {
    async fn scan(&self, digest: &str, cancel: Arc<AtomicBool>) -> ScanResult {
        let mut tried = 0usize;
        let mut sandboxed = false;
        let mut drift: Option<&'static str> = None;
        let mut pid_gone = false;
        for c in self.candidates.iter().filter(|c| c.digest == digest) {
            if cancel.load(Ordering::Relaxed) {
                return ScanResult::Cancelled;
            }
            if c.sandboxed {
                sandboxed = true;
                continue;
            }
            if tried == MAX_CANDIDATES {
                break;
            }
            tried += 1;
            let Some(pid) = task_pid(&c.container_id).await else {
                continue;
            };
            let (cfg, platform, cand, cancel) = (
                self.config.clone(),
                self.platform.clone(),
                c.clone(),
                Arc::clone(&cancel),
            );
            let attempt =
                tokio::task::spawn_blocking(move || scan_one(&cfg, &platform, &cand, pid, &cancel))
                    .await;
            match attempt {
                Ok(Attempt::Done(r)) => return r,
                Ok(Attempt::Drift(db)) => {
                    info!(
                        container = c.container_id,
                        db, "node catalog: container drifted; trying another"
                    );
                    drift = Some(db);
                }
                Ok(Attempt::PidGone(why)) => {
                    debug!(
                        container = c.container_id,
                        why, "node catalog: pid gone; trying another"
                    );
                    pid_gone = true;
                }
                Err(e) => {
                    return ScanResult::Failed {
                        reason: FailReason::Error,
                        detail: format!("scan thread: {e}"),
                    }
                }
            }
        }
        let (reason, detail) = if let Some(db) = drift {
            (FailReason::Drift, format!("{db} changed at runtime"))
        } else if pid_gone {
            (
                FailReason::PidGone,
                "every candidate's process changed".to_string(),
            )
        } else if sandboxed && tried == 0 {
            (
                FailReason::Sandboxed,
                "only sandboxed containers run it here".to_string(),
            )
        } else {
            (
                FailReason::ExitedBeforeCatalog,
                "no running container left".to_string(),
            )
        };
        ScanResult::Failed { reason, detail }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn off_by_default_and_off_reads_nothing_else() {
        let seen = Mutex::new(Vec::<String>::new());
        let c = Config::from_lookup(|k| {
            seen.lock().unwrap().push(k.to_string());
            None
        });
        assert!(!c.enabled);
        assert_eq!(c, Config::default());
        assert_eq!(*seen.lock().unwrap(), vec!["NODE_CATALOG"]);

        for off in ["off", "false", "0", "", "banana"] {
            let c = Config::from_lookup(|k| (k == "NODE_CATALOG").then(|| off.to_string()));
            assert!(!c.enabled, "{off:?}");
        }
    }

    /// The off path starts nothing: no task, no feed, and the pod
    /// watcher hooks do nothing.
    #[tokio::test]
    async fn start_with_the_gate_off_does_nothing() {
        assert!(start(Config::default(), "n".into(), "http://127.0.0.1:1".into()).is_none());
        assert!(!feed::is_open(), "no channel was opened");
        // The hooks are inert with no feed.
        let pod = k8s_openapi::api::core::v1::Pod::default();
        feed::note_pod(&pod);
        feed::forget_pod(&pod);
        feed::retain_pods(&Default::default());
        assert!(!feed::is_open());
    }

    #[test]
    fn values_parse_and_clamp() {
        let env: HashMap<&str, &str> = [
            ("NODE_CATALOG", "on"),
            ("NODE_CATALOG_SOCKET", " /tmp/w.sock "),
            ("NODE_CATALOG_EPOCH", "7"),
            ("NODE_CATALOG_RO_CLONE", "true"),
            ("NODE_CATALOG_SCAN_TIMEOUT_SECS", "99999"),
            ("NODE_CATALOG_MAX_COMPONENTS", "900000"),
            ("NODE_CATALOG_MAX_RESPONSE_BYTES", "999999999999"),
            ("NODE_CATALOG_MIN_SCAN_INTERVAL_SECS", "1"),
            ("NODE_CATALOG_PEER_UIDS", "0, 2000000000"),
            ("NODE_CATALOG_MAX_FILES", "not-a-number"),
        ]
        .into();
        let c = Config::from_lookup(|k| env.get(k).map(|v| v.to_string()));
        assert!(c.enabled);
        assert_eq!(c.socket, PathBuf::from("/tmp/w.sock"));
        assert_eq!(c.epoch, 7);
        assert!(c.ro_clone);
        assert_eq!(c.scan_timeout, Duration::from_secs(1800));
        assert_eq!(c.max_components, 50_000);
        assert_eq!(c.max_response_bytes, 64 * 1024 * 1024);
        assert_eq!(c.min_scan_interval, Duration::from_secs(30));
        assert_eq!(c.peer_uids, vec![0, 2_000_000_000]);
        assert_eq!(c.max_files, 2_000_000);
        assert_eq!(c.budgets().scan_timeout_ms, 1_800_000);
    }

    #[test]
    fn psi_parses_some_avg10() {
        let body = "some avg10=41.50 avg60=10.00 avg300=2.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(psi_some_avg10(body), Some(41.5));
        assert_eq!(psi_some_avg10("full avg10=3.0\n"), None);
        assert_eq!(psi_some_avg10(""), None);
    }

    #[test]
    fn cooldowns_follow_the_retry_class() {
        let h = Duration::from_secs(3600);
        assert_eq!(
            cooldown_for(&GrantOutcome::Stored {
                pages: 1,
                status: String::new()
            }),
            24 * h
        );
        assert_eq!(
            cooldown_for(&GrantOutcome::Reported(FailReason::LazySnapshotter)),
            24 * h
        );
        assert_eq!(cooldown_for(&GrantOutcome::Reported(FailReason::Oom)), h);
        assert_eq!(
            cooldown_for(&GrantOutcome::Reported(FailReason::Drift)),
            Duration::from_secs(600)
        );
        assert_eq!(
            cooldown_for(&GrantOutcome::LostLease),
            Duration::from_secs(900)
        );
    }

    fn cand(sandboxed: bool) -> RunningContainer {
        RunningContainer {
            pod_uid: "u".into(),
            namespace: "n".into(),
            pod: "p".into(),
            container: "c".into(),
            container_id: "c".repeat(64),
            digest: "sha256:x".into(),
            digest_kind: crate::image_inventory::DigestKind::Repo,
            repository: None,
            started_unix: None,
            sandboxed,
        }
    }

    #[tokio::test]
    async fn only_sandboxed_candidates_are_sandboxed_and_none_is_exited() {
        let s = NodeScanner {
            config: Config::default(),
            platform: "linux/amd64".into(),
            candidates: vec![cand(true)],
        };
        assert!(matches!(
            s.scan("sha256:x", Arc::default()).await,
            ScanResult::Failed {
                reason: FailReason::Sandboxed,
                ..
            }
        ));
        let s = NodeScanner {
            config: Config::default(),
            platform: "linux/amd64".into(),
            candidates: vec![],
        };
        assert!(matches!(
            s.scan("sha256:x", Arc::default()).await,
            ScanResult::Failed {
                reason: FailReason::ExitedBeforeCatalog,
                ..
            }
        ));
    }
}
