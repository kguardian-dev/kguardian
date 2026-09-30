//! Tests for the catalog's top level: config, the gate, and the claim
//! loop driven on virtual time against a scripted Broker and node.

use super::*;
use crate::catalog::api::{ClaimResponse, ClaimUpdateResponse, Grant, SbomPage, Scanner};
use crate::catalog::claim::ScanResult;
use crate::catalog::feed::FeedMsg;
use crate::image_inventory::DigestKind;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// The off path starts nothing: no task, no feed, and the pod watcher
/// hooks do nothing.
#[tokio::test]
async fn start_with_the_gate_off_does_nothing() {
    assert!(start(Config::default(), "n".into(), "http://127.0.0.1:1".into()).is_none());
    assert!(!feed::is_open(), "no channel was opened");
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
        ("NODE_CATALOG_STARTUP_JITTER_SECS", "999999"),
        ("NODE_CATALOG_MAX_PRESSURE_DEFER_SECS", "9999999"),
        ("COMPUTE_HOST_PROC", "/host/proc"),
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
    // L7 clamps and L6 fallback.
    assert_eq!(c.startup_jitter, Duration::from_secs(3600));
    assert_eq!(c.max_pressure_defer, Duration::from_secs(86_400));
    assert_eq!(c.host_proc, PathBuf::from("/host/proc"));
}

#[test]
fn defaults_are_lean_and_host_proc_prefers_its_own_variable() {
    let on = Config::from_lookup(|k| (k == "NODE_CATALOG").then(|| "on".to_string()));
    assert_eq!(on.max_response_bytes, 16 * 1024 * 1024);
    assert_eq!(on.host_proc, PathBuf::from("/proc"));
    let both = Config::from_lookup(|k| match k {
        "NODE_CATALOG" => Some("on".into()),
        "NODE_CATALOG_HOST_PROC" => Some("/a".into()),
        "COMPUTE_HOST_PROC" => Some("/b".into()),
        _ => None,
    });
    assert_eq!(both.host_proc, PathBuf::from("/a"));
}

#[test]
fn pod_uid_is_read_only_when_on() {
    let c = Config::from_lookup(|k| match k {
        "NODE_CATALOG" => Some("on".into()),
        "POD_UID" => Some(" 5d7c1c2e-1f2a-4b3c-9d8e-0a1b2c3d4e5f ".into()),
        _ => None,
    });
    assert_eq!(
        c.pod_uid.as_deref(),
        Some("5d7c1c2e-1f2a-4b3c-9d8e-0a1b2c3d4e5f")
    );
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

#[test]
fn rate_limit_allows_one_per_period() {
    let t0 = Instant::now();
    let mut r = RateLimit::new(Duration::from_secs(3600));
    assert!(r.allow(t0));
    assert!(!r.allow(t0 + Duration::from_secs(10)));
    assert!(r.allow(t0 + Duration::from_secs(3600)));
    let mut s = RateLimit::starting(Duration::from_secs(60), t0);
    assert!(!s.allow(t0));
    assert!(s.allow(t0 + Duration::from_secs(60)));
}

// ---- The claim loop on virtual time ---------------------------------------

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

/// What the scripted Broker was asked.
#[derive(Debug, Clone, PartialEq)]
enum Call {
    Claim {
        offer: Vec<String>,
        epoch: i64,
    },
    Update {
        digest: String,
        action: String,
        reason: Option<String>,
    },
    Upload {
        digest: String,
    },
}

/// A Broker answering claims from a script (then "no grant").
#[derive(Default)]
struct ScriptBroker {
    claims: Mutex<VecDeque<Answer<ClaimResponse>>>,
    calls: Mutex<Vec<(Instant, Call)>>,
}

impl ScriptBroker {
    fn with(claims: Vec<Answer<ClaimResponse>>) -> Self {
        Self {
            claims: Mutex::new(claims.into()),
            calls: Mutex::default(),
        }
    }
    fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, c)| c.clone())
            .collect()
    }
    fn claim_times(&self) -> Vec<Instant> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, c)| matches!(c, Call::Claim { .. }))
            .map(|(t, _)| *t)
            .collect()
    }
    fn offers(&self) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Claim { offer, .. } => Some(offer),
                _ => None,
            })
            .collect()
    }
}

fn grant(d: &str) -> Answer<ClaimResponse> {
    Answer::Ok(ClaimResponse {
        grants_enabled: true,
        grant: Some(Grant {
            digest: d.into(),
            claim_token: "tok".into(),
            lease_expires_at: None,
            lease_seconds: Some(900),
        }),
    })
}

impl Broker for ScriptBroker {
    async fn claim(&self, r: &ClaimRequest) -> Answer<ClaimResponse> {
        self.calls.lock().unwrap().push((
            Instant::now(),
            Call::Claim {
                offer: r.offer.clone(),
                epoch: r.epoch,
            },
        ));
        self.claims
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Answer::Ok(ClaimResponse {
                grants_enabled: true,
                grant: None,
            }))
    }
    async fn update(&self, d: &str, _: &str, u: &ClaimUpdate) -> Answer<ClaimUpdateResponse> {
        let v = serde_json::to_value(u).unwrap();
        self.calls.lock().unwrap().push((
            Instant::now(),
            Call::Update {
                digest: d.into(),
                action: v["action"].as_str().unwrap().into(),
                reason: v.get("reason").and_then(|r| r.as_str()).map(String::from),
            },
        ));
        Answer::Ok(ClaimUpdateResponse {
            state: None,
            lease_expires_at: None,
            next_attempt_at: None,
        })
    }
    async fn upload(&self, d: &str, _: &str, _: &SbomPage) -> Answer<serde_json::Value> {
        self.calls
            .lock()
            .unwrap()
            .push((Instant::now(), Call::Upload { digest: d.into() }));
        Answer::Ok(serde_json::json!({"status": "stored"}))
    }
}

/// A scan that answers at once with a fixed result.
struct InstantScan(ScanResult);

impl Scan for InstantScan {
    async fn scan(&self, _: &str, _: Arc<AtomicBool>) -> ScanResult {
        self.0.clone()
    }
}

/// A node with scripted ping and pressure answers.
struct FakeEnv {
    ping_ok: Mutex<VecDeque<bool>>,
    pressure: Mutex<VecDeque<Option<f64>>>,
    pings: AtomicUsize,
    result: ScanResult,
}

impl FakeEnv {
    fn new(result: ScanResult) -> Self {
        Self {
            ping_ok: Mutex::default(),
            pressure: Mutex::default(),
            pings: AtomicUsize::new(0),
            result,
        }
    }
}

impl LoopEnv for FakeEnv {
    type Scanner = InstantScan;
    async fn ping(&self) -> Result<(), String> {
        self.pings.fetch_add(1, Ordering::Relaxed);
        match self.ping_ok.lock().unwrap().pop_front().unwrap_or(true) {
            true => Ok(()),
            false => Err("no worker".into()),
        }
    }
    async fn pressure(&self) -> Option<f64> {
        self.pressure.lock().unwrap().pop_front().flatten()
    }
    fn scanner(&self, _: Vec<RunningContainer>) -> InstantScan {
        InstantScan(self.result.clone())
    }
}

fn stored() -> ScanResult {
    ScanResult::Sbom {
        subject: post::Subject {
            digest: digest('a'),
            digest_kind: None,
            repository: None,
            platform: "linux/amd64".into(),
            epoch: 1,
        },
        sbom: post::Sbom {
            completeness: "full".into(),
            partial_reasons: vec![],
            scanner: Scanner::default(),
            stats: serde_json::json!({}),
            components: vec![api::Component {
                name: "p".into(),
                ..Default::default()
            }],
        },
    }
}

fn inventory(digests: &[char]) -> Arc<Mutex<Inventory>> {
    let mut inv = Inventory::default();
    let containers = digests
        .iter()
        .enumerate()
        .map(|(i, d)| RunningContainer {
            pod_uid: "u".into(),
            namespace: "n".into(),
            pod: "p".into(),
            container: format!("c{i}"),
            container_id: format!("id{i}"),
            digest: digest(*d),
            digest_kind: DigestKind::Repo,
            repository: None,
            started_unix: None,
            sandboxed: false,
        })
        .collect();
    inv.apply(FeedMsg::Pod {
        uid: "u".into(),
        containers,
    });
    Arc::new(Mutex::new(inv))
}

fn ctx() -> Arc<LoopCtx> {
    Arc::new(LoopCtx {
        config: Config {
            enabled: true,
            startup_jitter: Duration::ZERO,
            ..Config::default()
        },
        node: "n1".into(),
        platform: "linux/amd64".into(),
    })
}

async fn run_for(
    d: Duration,
    ctx: Arc<LoopCtx>,
    broker: Arc<ScriptBroker>,
    env: Arc<FakeEnv>,
    inv: Arc<Mutex<Inventory>>,
) {
    let _ = tokio::time::timeout(d, claim_loop(ctx, broker, env, inv)).await;
}

/// A grant is scanned and stored; the stored digest then cools down and
/// leaves the offer, and an unchanged no-grant offer waits for `idle`.
#[tokio::test(start_paused = true)]
async fn grants_are_scanned_then_cool_down_and_offers_are_paced() {
    let b = Arc::new(ScriptBroker::with(vec![grant(&digest('a'))]));
    let env = Arc::new(FakeEnv::new(stored()));
    run_for(
        Duration::from_secs(1300),
        ctx(),
        Arc::clone(&b),
        env,
        inventory(&['a', 'b']),
    )
    .await;
    let offers = b.offers();
    assert_eq!(offers[0], vec![digest('a'), digest('b')]);
    assert!(b.calls().contains(&Call::Upload {
        digest: digest('a')
    }));
    // After the grant: 'a' cools down; 'b' alone is offered, then only
    // every `idle` (600 s) while nothing changes.
    assert_eq!(offers[1], vec![digest('b')]);
    assert!(offers.len() <= 4, "paced, not every tick: {offers:?}");
    let t = b.claim_times();
    assert!(t[2] - t[1] >= Duration::from_secs(600));
}

#[tokio::test(start_paused = true)]
async fn pressure_defers_claims_up_to_the_maximum() {
    let b = Arc::new(ScriptBroker::default());
    let env = Arc::new(FakeEnv::new(stored()));
    // High pressure on every check.
    *env.pressure.lock().unwrap() = (0..1000).map(|_| Some(90.0)).collect();
    let mut c = Config {
        enabled: true,
        startup_jitter: Duration::ZERO,
        ..Config::default()
    };
    c.max_pressure_defer = Duration::from_secs(120);
    let ctx = Arc::new(LoopCtx {
        config: c,
        node: "n1".into(),
        platform: "linux/amd64".into(),
    });
    let started = Instant::now();
    run_for(
        Duration::from_secs(300),
        ctx,
        Arc::clone(&b),
        env,
        inventory(&['a']),
    )
    .await;
    let t = b.claim_times();
    assert!(!t.is_empty(), "claims after the maximum defer");
    assert!(t[0] - started >= Duration::from_secs(120), "deferred first");
}

#[tokio::test(start_paused = true)]
async fn a_worker_ping_failure_means_no_claim_and_a_paced_retry() {
    let b = Arc::new(ScriptBroker::default());
    let env = Arc::new(FakeEnv::new(stored()));
    *env.ping_ok.lock().unwrap() = VecDeque::from([false, false, false]);
    run_for(
        Duration::from_secs(700),
        ctx(),
        Arc::clone(&b),
        Arc::clone(&env),
        inventory(&['a']),
    )
    .await;
    // First ping at ~10 s fails, the next is after idle (600 s): two
    // pings in 700 s, never one per tick, and no claim while down.
    assert_eq!(env.pings.load(Ordering::Relaxed), 2);
    assert!(b.claim_times().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_grant_for_a_digest_not_offered_is_failed_back() {
    let b = Arc::new(ScriptBroker::with(vec![grant(&digest('z'))]));
    let env = Arc::new(FakeEnv::new(stored()));
    run_for(
        Duration::from_secs(60),
        ctx(),
        Arc::clone(&b),
        env,
        inventory(&['a']),
    )
    .await;
    assert!(b.calls().contains(&Call::Update {
        digest: digest('z'),
        action: "fail".into(),
        reason: Some("error".into()),
    }));
    assert!(!b.calls().iter().any(|c| matches!(c, Call::Upload { .. })));
}

/// M4: 503s back off exponentially from 60 s to 30 min; no hot loop.
#[tokio::test(start_paused = true)]
async fn claim_503s_back_off_exponentially_to_thirty_minutes() {
    let b = Arc::new(ScriptBroker::with(
        (0..50)
            .map(|_| Answer::Unavailable(Duration::from_secs(60)))
            .collect(),
    ));
    let env = Arc::new(FakeEnv::new(stored()));
    run_for(
        Duration::from_secs(4 * 3600),
        ctx(),
        Arc::clone(&b),
        env,
        inventory(&['a']),
    )
    .await;
    let t = b.claim_times();
    let gaps: Vec<u64> = t.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
    assert!(gaps.windows(2).take(4).all(|g| g[1] >= g[0]), "{gaps:?}");
    assert!(gaps.iter().all(|g| *g >= 60), "{gaps:?}");
    assert!(gaps.iter().all(|g| *g <= 1800 * 12 / 10 + 20), "{gaps:?}");
    assert!(t.len() < 15, "{} claims in 4 h", t.len());
}

/// L1: a 422 stops claiming; empty offers under epoch 0 follow at the
/// idle cadence.
#[tokio::test(start_paused = true)]
async fn a_422_switches_to_empty_offers() {
    let b = Arc::new(ScriptBroker::with(vec![Answer::Refused(
        422,
        "epoch 7 is above this broker's NODE_CATALOG_MAX_EPOCH (5)".into(),
    )]));
    let env = Arc::new(FakeEnv::new(stored()));
    run_for(
        Duration::from_secs(1300),
        ctx(),
        Arc::clone(&b),
        env,
        inventory(&['a']),
    )
    .await;
    let calls = b.calls();
    assert_eq!(
        calls[0],
        Call::Claim {
            offer: vec![digest('a')],
            epoch: 1
        }
    );
    let rest: Vec<&Call> = calls[1..].iter().collect();
    assert_eq!(rest.len(), 3, "t+0, +600, +1200: {rest:?}");
    assert!(rest.iter().all(|c| **c
        == Call::Claim {
            offer: vec![],
            epoch: 0
        }));
}

#[tokio::test(start_paused = true)]
async fn a_panicking_loop_is_restarted_and_a_clean_one_ends() {
    let runs = Arc::new(AtomicUsize::new(0));
    let r = Arc::clone(&runs);
    supervise(
        move || {
            let n = r.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    panic!("boom {n}");
                }
            }
        },
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(runs.load(Ordering::SeqCst), 3);
}
