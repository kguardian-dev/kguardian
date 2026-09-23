//! Distributes user-owned `SeccompProfile` CRs to this node.
//!
//! Policy-as-code: the user commits and applies a `SeccompProfile`
//! (`kguardian.dev/v1alpha1`, see `seccomp_crd.rs`); this task watches
//! them cluster-wide and keeps `<root>/kguardian/<namespace>/<name>.json`
//! under the kubelet seccomp root equal to the profile rendered from the
//! CR spec. The broker never decides what reaches a node — it only
//! observes, recommends, and reports.
//!
//! Off by default. Enable with `SECCOMP_DISTRIBUTE=true` (Helm:
//! `seccomp.distribute=true`), which also adds the hostPath mount of the
//! kubelet seccomp directory to the controller pod and the RBAC for
//! `seccompprofiles` (get/list/watch), `seccompprofiles/status` (patch)
//! and `nodes` (list).
//!
//! Every pass lists the nodes once (the `total` in `distribution`) and
//! asks the broker about each workload a CR references — one
//! `GET /seccomp/profiles/{ns}/{kind}/{name}` per distinct `workloadRef`,
//! however many CRs share it. A pass over an empty store asks for
//! neither and only posts this node's (empty) file list. It used to pull
//! the cluster-wide `GET /seccomp/profiles` on every pass, CRs or not:
//! megabytes of JSON per node per resync on a large cluster, against a
//! handler that retains memory per call (see `list_seccomp_profiles` in
//! the broker) — enough to OOMKill the broker when distribution was
//! switched on for a fleet that had no CRs at all.
//!
//! What a resync now costs the broker is distinct `workloadRef`s × nodes
//! requests, each detail call a handful of queries. That is the right
//! trade from zero to tens of CRs, which is where every fleet starts and
//! where the list was pure waste. Once CR counts grow past that, the
//! follow-up is a batched lookup by key — one request carrying every
//! referenced workload — not a return to the cluster-wide list.
//!
//! Per CR, every pass:
//!  1. render the file from spec, write it atomically only when the bytes
//!     on disk differ;
//!  2. server-side-apply this node's `status.nodes[name=<node>]` entry
//!     (field manager `kguardian-controller/<node>`);
//!  3. compute the summary (`distribution`, `Ready`, and — from the
//!     broker's observations — `CaptureComplete`, `Drift`, and
//!     `DenialsObserved` with its `denials` block) and apply it under the
//!     shared manager `kguardian-summary`. Both applies are skipped when
//!     nothing changed. The parts computed from the CR itself are the
//!     same on every node, so last-writer-wins settles on its own; the
//!     denial block is not — each node polls the broker separately and a
//!     denial count never stops moving — so `settled_denials` has to
//!     make that one converge explicitly;
//!  4. mirror `{spec, hash, distribution}` to the broker so the UI can show
//!     CR state without an API-server round trip.
//!
//! **A deleted CR deletes its file** — that is the user's explicit intent,
//! and the only deletion this code ever performs. A CR deleted while the
//! controller is down leaves its file behind until the next delete event
//! it does see; nothing prunes unmatched files.
//!
//! Deliberately best-effort: a failed step logs and retries next pass, and
//! a missing seccomp root, a missing CRD, or a broker outage never
//! propagates an error that would restart the controller and interrupt
//! tracing. If the watch stream ever ends it is rebuilt after a capped
//! backoff (`rebuild_delay`); the task itself never returns once active.

use crate::client::{api_delete_call, api_get_bytes, api_post_call, api_put_call};
use crate::pod_watcher::parse_lenient_bool;
use crate::seccomp_crd::{
    fingerprint, localhost_profile_path, render_profile, Condition, DenialSummary, Distribution,
    DistributionState, NodeStatus, SeccompProfile, SeccompProfileSpec, SeccompProfileStatus,
    WorkloadRef,
};
use crate::Error;
use chrono::{DateTime, SecondsFormat, Utc};
use futures::future::BoxFuture;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Node;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{watcher, WatchStreamExt};
use kube::{Api, Client, ResourceExt};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default kubelet seccomp root. Overridable because it is not
/// `/var/lib/kubelet` everywhere (k3s, kubeadm custom, OpenShift) — the
/// same portability concern the containerd socket path already has.
const DEFAULT_SECCOMP_ROOT: &str = "/var/lib/kubelet/seccomp";
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Shared field manager for the computed summary. Every node applies
/// the same value under it; last writer wins and the result converges.
const MANAGER_SUMMARY: &str = "kguardian-summary";
/// Kubernetes caps field manager names at 128 bytes.
const MANAGER_MAX_LEN: usize = 128;

pub const COND_READY: &str = "Ready";
pub const COND_CAPTURE_COMPLETE: &str = "CaptureComplete";
pub const COND_DRIFT: &str = "Drift";
pub const COND_DENIALS_OBSERVED: &str = "DenialsObserved";

/// The three conditions computed from broker observations rather than
/// from this node's own files. They share a fate: all three are decided
/// together in `observation_conditions`, and all three are carried
/// forward untouched when the broker cannot be reached.
const OBSERVED_CONDITIONS: [&str; 3] = [COND_CAPTURE_COMPLETE, COND_DRIFT, COND_DENIALS_OBSERVED];

struct Config {
    root: PathBuf,
    interval: Duration,
    /// This node's name: the `status.nodes` key and the `node-status`
    /// report. Empty disables both (the files still get written).
    node_name: String,
}

fn enabled_config() -> Option<Config> {
    let enabled = parse_lenient_bool(
        &std::env::var("SECCOMP_DISTRIBUTE").unwrap_or_default(),
        false,
    );
    if !enabled {
        return None;
    }
    let root = std::env::var("SECCOMP_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SECCOMP_ROOT.to_string());
    let interval = std::env::var("SECCOMP_DISTRIBUTE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_INTERVAL);
    let node_name = std::env::var("CURRENT_NODE")
        .unwrap_or_default()
        .trim()
        .to_string();
    Some(Config {
        root: PathBuf::from(root),
        interval,
        node_name,
    })
}

/// Field manager for this node's `status.nodes` entry.
fn node_manager(node: &str) -> String {
    let mut m = format!("kguardian-controller/{node}");
    if m.len() > MANAGER_MAX_LEN {
        m.truncate(MANAGER_MAX_LEN);
    }
    m
}

/// Task entrypoint. Returns `Ok(())` immediately when disabled or
/// misconfigured — the caller joins this alongside the eBPF tasks, and a
/// distribution problem must never take the controller down.
pub async fn run() -> Result<(), Error> {
    let Some(cfg) = enabled_config() else {
        info!("seccomp profile distribution disabled (set SECCOMP_DISTRIBUTE=true to enable)");
        return Ok(());
    };

    if !cfg.root.is_dir() {
        error!(
            root = %cfg.root.display(),
            "SECCOMP_ROOT is not a directory; seccomp profile distribution is inactive. \
             Set seccomp.kubeletRoot to this node's kubelet root if it is not /var/lib/kubelet."
        );
        return Ok(());
    }

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            error!("seccomp profile distribution inactive: cannot build a kube client: {e}");
            return Ok(());
        }
    };

    info!(
        root = %cfg.root.display(),
        interval_secs = cfg.interval.as_secs(),
        node = %cfg.node_name,
        "seccomp profile distribution active (SeccompProfile CRs)"
    );

    let (store, mut stream) = build_watch(&client);
    let mut rec = Reconciler {
        cfg,
        client,
        store,
        cluster: None,
        fetch: |key| Box::pin(fetch_workload(key)),
        last_total_nodes: 0,
    };

    let mut ticker = tokio::time::interval(rec.cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consecutive stream ends since the last successful event; drives
    // the rebuild backoff.
    let mut stream_ends: u32 = 0;
    loop {
        tokio::select! {
            ev = stream.next() => match ev {
                // The backoff watcher is meant to be endless, but if it
                // does end we must NOT return. This subsystem is
                // supervised as `MayRetire` — it is allowed to return
                // `Ok(())`, because it does exactly that when
                // SECCOMP_DISTRIBUTE is unset — so a return here is
                // taken as a deliberate retirement and CR reconciliation
                // would be silently dead until the pod restarted for
                // some other reason. And we must not Err either — a
                // distributor failure never interrupts tracing. So: back
                // off, rebuild the reflector + watcher, carry on. The
                // ticker keeps firing meanwhile (against the last known
                // store contents).
                None => {
                    let delay = rebuild_delay(stream_ends);
                    stream_ends = stream_ends.saturating_add(1);
                    warn!(
                        attempt = stream_ends,
                        delay_secs = delay.as_secs(),
                        "SeccompProfile watch stream ended; rebuilding the watcher after backoff"
                    );
                    let sleep = tokio::time::sleep(delay);
                    tokio::pin!(sleep);
                    loop {
                        tokio::select! {
                            _ = &mut sleep => break,
                            _ = ticker.tick() => rec.full_pass().await,
                        }
                    }
                    let (store, new_stream) = build_watch(&rec.client);
                    rec.store = store;
                    stream = new_stream;
                }
                // A missing CRD, RBAC gap or apiserver blip: the backoff
                // watcher retries by itself; say why at warn so an
                // operator who forgot `seccomp.installCRDs` sees it.
                Some(Err(e)) => warn!("SeccompProfile watch error (will retry): {e}"),
                Some(Ok(event)) => {
                    stream_ends = 0;
                    match event {
                        watcher::Event::Apply(cr) | watcher::Event::InitApply(cr) => {
                            // Cluster inputs are refreshed once per
                            // resync, not once per event. Another node's
                            // status write arrives here as an Apply, so
                            // refreshing per event would have every node
                            // list nodes and re-read the broker once per
                            // node per write. Instead the node count is
                            // taken here only when no pass has one yet,
                            // and a workload's broker reading is taken
                            // the first time a CR naming it is reconciled
                            // after a refresh and reused until the next —
                            // so a replayed Apply costs the broker
                            // nothing and a brand-new CR costs it one
                            // read. The reading this path uses is
                            // therefore up to `interval` old, which
                            // `settled_denials` is built to tolerate: a
                            // stale reading can only lose the ratchet,
                            // never overwrite a fresher one.
                            if rec.cluster.is_none() {
                                rec.refresh_cluster().await;
                            }
                            if let Err(e) = rec.reconcile_cr(&cr).await {
                                warn!(cr = %cr_id(&cr), "seccomp profile reconcile failed (will retry): {e}");
                            }
                        }
                        watcher::Event::Delete(cr) => rec.on_delete(&cr).await,
                        watcher::Event::InitDone => rec.full_pass().await,
                        watcher::Event::Init => {}
                    }
                }
            },
            _ = ticker.tick() => rec.full_pass().await,
        }
    }
}

type WatchStream =
    futures::stream::BoxStream<'static, Result<watcher::Event<SeccompProfile>, watcher::Error>>;

/// A fresh reflector store + backoff watcher over every SeccompProfile.
/// Called at start and again whenever the stream ends (see `run`).
fn build_watch(client: &Client) -> (Store<SeccompProfile>, WatchStream) {
    let api: Api<SeccompProfile> = Api::all(client.clone());
    let (store, writer) = reflector::store();
    let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()))
        .default_backoff()
        .boxed();
    (store, stream)
}

/// How long to wait before rebuilding the watcher after its `n`th
/// consecutive end: 1s, 2s, 4s, … capped at `REBUILD_BACKOFF_MAX`.
/// Pure so the schedule is unit-testable.
fn rebuild_delay(consecutive_ends: u32) -> Duration {
    let secs = 1u64 << consecutive_ends.min(6);
    Duration::from_secs(secs).min(REBUILD_BACKOFF_MAX)
}

const REBUILD_BACKOFF_MAX: Duration = Duration::from_secs(60);

fn cr_id(cr: &SeccompProfile) -> String {
    format!("{}/{}", cr.namespace().unwrap_or_default(), cr.name_any())
}

/// Cluster-wide inputs refreshed once per pass: how many nodes exist
/// (the `total` in `distribution`) and what the broker has said about
/// each workload a CR references (for `CaptureComplete` / `Drift` /
/// `DenialsObserved`). Held only while there is a CR to spend them on —
/// `None` after a pass over an empty store — so the first CR to arrive
/// after a quiet spell gets a node count taken now, not one from
/// whenever CRs last existed (or, if that list fails, the last count a
/// list did return; see `Reconciler::last_total_nodes`).
struct ClusterData {
    total_nodes: u32,
    readings: BrokerReadings,
}

/// `(namespace, kind, name)` of a CR's workload: the key the broker's
/// rows carry, and the path `GET /seccomp/profiles/{ns}/{kind}/{name}`
/// takes. The namespace is the CR's own — a `workloadRef` names only a
/// kind and a name, because a CR speaks for its own namespace and no
/// other.
type WorkloadKey = (String, String, String);

fn workload_key(ns: &str, wr: &WorkloadRef) -> WorkloadKey {
    (
        ns.to_string(),
        wr.kind.as_str().to_string(),
        wr.name.clone(),
    )
}

/// `Deployment prod/web`, the spelling the condition messages use.
fn workload_id((ns, kind, name): &WorkloadKey) -> String {
    format!("{kind} {ns}/{name}")
}

/// One workload, as the broker answered when this pass asked.
///
/// Three answers, because the CR's conditions have three outcomes and
/// the outcomes must not blur into each other: a row decides them; a 404
/// means the broker has no observed set for the workload, which is
/// `NoObservations`; anything else means the broker could not be asked,
/// and the conditions are carried forward as they are. The same three
/// used to fall out of one cluster-wide list — a row present, a row
/// absent, no list at all — and `observation_conditions` still reads
/// that shape, so `summaries` renders each answer as the zero-or-one-row
/// list it would have found there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BrokerReading {
    /// Boxed because a row is a few hundred bytes and the other two
    /// answers carry nothing; the cache holds one of these per workload.
    Observed(Box<BrokerSummary>),
    Unobserved,
    Unavailable,
}

impl BrokerReading {
    /// From the raw answer to `GET /seccomp/profiles/{ns}/{kind}/{name}`.
    ///
    /// A body that does not parse is `Unavailable`, not `Unobserved`: the
    /// broker plainly knows the workload, this controller just cannot
    /// read what it said, and flipping three conditions to `Unknown` over
    /// that would be the flap a parse failure of the cluster list was
    /// already kept from causing.
    fn from_response(key: &WorkloadKey, response: Result<Option<Vec<u8>>, Error>) -> Self {
        match response {
            Ok(Some(body)) => match serde_json::from_slice::<BrokerSummary>(&body) {
                Ok(row) => Self::Observed(Box::new(row)),
                Err(e) => {
                    warn!(workload = %workload_id(key), "parsing the broker's seccomp profile: {e}");
                    Self::Unavailable
                }
            },
            Ok(None) => Self::Unobserved,
            Err(e) => {
                debug!(
                    workload = %workload_id(key),
                    "broker seccomp profile unavailable (conditions kept as-is): {e}"
                );
                Self::Unavailable
            }
        }
    }

    /// The reading as the list `observation_conditions` finds a row in:
    /// one row, no row, or no list.
    fn summaries(&self) -> Option<&[BrokerSummary]> {
        match self {
            Self::Observed(row) => Some(std::slice::from_ref(row.as_ref())),
            Self::Unobserved => Some(&[]),
            Self::Unavailable => None,
        }
    }
}

/// What this pass has asked the broker so far, one entry per distinct
/// workload. Emptied when the node count is refreshed, so a reading is
/// at most one resync old — the age the cluster list used to be — and is
/// taken at most once per resync however many CRs reference the workload
/// and however many watch events replay them.
#[derive(Debug, Default)]
struct BrokerReadings {
    by_workload: BTreeMap<WorkloadKey, BrokerReading>,
    /// Set by the first fetch this pass that fails outright. From then on
    /// every workload not already read answers `Unavailable` without a
    /// request; see `get_or_fetch`.
    broker_down: bool,
}

/// What the latch hands out. A `static` rather than a `const` because
/// `BrokerReading` owns a `Box` in one arm, so a borrowed `const` would
/// be a temporary and not promote to `'static`.
static UNAVAILABLE: BrokerReading = BrokerReading::Unavailable;

impl BrokerReadings {
    /// The reading for `key`, asking the broker through `fetch` only when
    /// this pass has not asked yet. A 404 is kept like a row: a workload
    /// nobody has observed is not re-asked per CR.
    ///
    /// A failure is not retried within the pass either, and it does more
    /// than cache: it latches `broker_down`, and every workload not yet
    /// read this pass then answers `Unavailable` without a request. The
    /// reason is the timeout. Fetches run one after another inside the
    /// per-CR loop, and `run` handles no watch events while a pass is in
    /// progress, so against a broker that accepts and never answers each
    /// fetch costs a whole `REQUEST_TIMEOUT`: twenty distinct workloads
    /// would hold the pass, and every new CR waiting behind it, for ten
    /// minutes. The cluster list cost one timeout per pass, and the latch
    /// keeps that bound. The skipped workloads get the outcome a failed
    /// fetch gives anyway — conditions carried forward — and the next
    /// pass starts clean and asks again.
    ///
    /// A body that does not parse does not latch: the broker answered.
    ///
    /// `fetch` is a parameter rather than `fetch_workload` itself so a
    /// test can count what a pass actually asks for.
    async fn get_or_fetch<F, Fut>(&mut self, key: WorkloadKey, fetch: F) -> &BrokerReading
    where
        F: FnOnce(WorkloadKey) -> Fut,
        Fut: std::future::Future<Output = Result<Option<Vec<u8>>, Error>>,
    {
        if self.by_workload.contains_key(&key) {
            return &self.by_workload[&key];
        }
        if self.broker_down {
            debug!(
                workload = %workload_id(&key),
                "broker already failed this pass; not asked (conditions kept as-is)"
            );
            return &UNAVAILABLE;
        }
        let response = fetch(key.clone()).await;
        if response.is_err() {
            self.broker_down = true;
        }
        let reading = BrokerReading::from_response(&key, response);
        self.by_workload.insert(key.clone(), reading);
        &self.by_workload[&key]
    }

    /// Requests this pass sent, latched answers excluded.
    fn len(&self) -> usize {
        self.by_workload.len()
    }
}

/// Everything outside RFC 3986's unreserved set is escaped in a path
/// segment. `workloadRef.name` is a bare string in the CRD — the schema
/// puts no pattern on it — so a `/` or `?` in a name must reach the
/// broker as data inside one segment, not as another route or a query.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// `seccomp/profiles/{ns}/{kind}/{name}`, each component escaped.
fn workload_path((ns, kind, name): &WorkloadKey) -> String {
    let seg = |s: &str| utf8_percent_encode(s, PATH_SEGMENT).to_string();
    format!("seccomp/profiles/{}/{}/{}", seg(ns), seg(kind), seg(name))
}

/// `GET /seccomp/profiles/{ns}/{kind}/{name}`: one workload's row, as the
/// cluster-wide list would carry it, plus a rendered `profile` the
/// controller ignores.
async fn fetch_workload(key: WorkloadKey) -> Result<Option<Vec<u8>>, Error> {
    api_get_bytes(&workload_path(&key)).await
}

/// The reconciler's one outbound broker read: `fetch_workload` in
/// production. Injectable so a test can stand in a broker that answers
/// — or one that never does — without a listener or `API_ENDPOINT`,
/// which is process-wide.
type WorkloadFetch = fn(WorkloadKey) -> BoxFuture<'static, Result<Option<Vec<u8>>, Error>>;

struct Reconciler {
    cfg: Config,
    client: Client,
    store: Store<SeccompProfile>,
    cluster: Option<ClusterData>,
    fetch: WorkloadFetch,
    /// The last node count a list returned, standing in when the next
    /// list fails. Kept here rather than read back from `ClusterData`
    /// because that is dropped after a pass over an empty store, and a
    /// failed list on the pass after would otherwise fall back to zero:
    /// `distribution` reading `n/0` and `Ready` flipping to `False` for
    /// a pass, both mirrored to the broker.
    last_total_nodes: u32,
}

/// One row of the broker's `GET /seccomp/profiles`, which is also the
/// body of `GET /seccomp/profiles/{ns}/{kind}/{name}` — the same fields
/// plus a rendered `profile` this controller has no use for. Only what
/// the conditions need; everything is lenient so an older or newer
/// broker still parses, and fields not named here fall away.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct BrokerSummary {
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub capture: Option<BrokerCapture>,
    #[serde(default)]
    pub cr: Option<BrokerCr>,
    /// Kernel seccomp verdicts for this workload. `None` from a broker
    /// that predates denial capture, and from one holding no denial rows
    /// at all — never "zero denials"; see `BrokerDenials`.
    #[serde(default)]
    pub denials: Option<BrokerDenials>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct BrokerCapture {
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub pods: Vec<BrokerPod>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct BrokerPod {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub level: String,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct BrokerCr {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub drift: Option<BrokerDrift>,
}

/// The `denials` block of one `GET /seccomp/profiles` row: what the
/// kernel's seccomp filter actually acted on for this workload, as the
/// broker has aggregated it over its retention window.
///
/// The block being absent and the block saying zero are different
/// answers and stay different all the way into the CR. Absent means the
/// broker did not tell us. Zero means it told us the workload is clean.
/// Collapsing them would hand an operator a clean bill of health for a
/// workload nobody has looked at — the same failure the broker's own
/// `a_cr_without_names_emits_no_drift_rather_than_an_empty_one` guards
/// on the other side of the wire.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct BrokerDenials {
    /// Denial events across every syscall and action.
    ///
    /// Signed on the wire even though a count cannot be negative: the
    /// whole `Vec<BrokerSummary>` is parsed in one go, so a broker that
    /// ever emitted `-1` here would fail the parse and take
    /// `CaptureComplete` and `Drift` down with it for every CR in the
    /// cluster. It clamps to zero instead.
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub syscalls: Vec<String>,
    /// The `SCMP_ACT_*` spellings seen. Mirrored into `status.denials`
    /// alongside the count and the syscalls, because the
    /// `DenialsObserved` message names them and that message may only
    /// render the published block — see `denials_condition`.
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, rename = "lastSeen")]
    pub last_seen: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct BrokerDrift {
    /// Observed by kguardian but not allowed by the CR.
    #[serde(default)]
    pub missing: Vec<String>,
    /// Allowed by the CR but never observed.
    #[serde(default)]
    pub extra: Vec<String>,
    #[serde(default, rename = "inSync")]
    pub in_sync: bool,
}

impl Reconciler {
    /// Take a fresh node count and forget this pass's broker readings.
    /// The readings are not fetched here: `reconcile_cr` asks for each
    /// CR's workload as it gets to it, so a pass reads exactly the
    /// workloads its CRs name, and nothing when they name none.
    async fn refresh_cluster(&mut self) {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let total_nodes = match nodes.list_metadata(&ListParams::default()).await {
            Ok(list) => {
                self.last_total_nodes = list.items.len() as u32;
                self.last_total_nodes
            }
            Err(e) => {
                warn!("cannot list nodes for seccomp distribution totals: {e}");
                self.last_total_nodes
            }
        };
        self.cluster = Some(ClusterData {
            total_nodes,
            readings: BrokerReadings::default(),
        });
    }

    /// Resync: reconcile every CR in the reflector store, then report
    /// this node's files to the broker.
    ///
    /// Cluster inputs are refreshed only when there is a CR to use them
    /// on. Nothing else in the pass needs them — `report_node_status`
    /// posts this node's file list and nothing more — and on a fleet with
    /// distribution enabled and no CRs yet, which is every fleet for a
    /// while, they used to be the entire cost of the feature: one node
    /// list and one cluster-wide profile list per node per resync, for
    /// nobody.
    async fn full_pass(&mut self) {
        let crs = self.store.state();
        if crs.is_empty() {
            self.cluster = None;
        } else {
            self.refresh_cluster().await;
        }
        let mut present: Vec<(String, String)> = Vec::new();
        let mut failed = 0usize;
        for cr in &crs {
            match self.reconcile_cr(cr).await {
                Ok(Some(pair)) => present.push(pair),
                Ok(None) => {}
                Err(e) => {
                    failed += 1;
                    warn!(cr = %cr_id(cr), "seccomp profile reconcile failed (will retry): {e}");
                }
            }
        }
        debug!(
            crs = crs.len(),
            present = present.len(),
            failed,
            broker_reads = self.cluster.as_ref().map_or(0, |c| c.readings.len()),
            "seccomp profile distribution pass"
        );
        self.report_node_status(&present).await;
    }

    /// Bring one CR's file, status and broker mirror up to date. Returns
    /// the `(localhostProfile, hash)` now on disk.
    async fn reconcile_cr(
        &mut self,
        cr: &SeccompProfile,
    ) -> Result<Option<(String, String)>, Error> {
        let Some(ns) = cr.namespace() else {
            warn!(name = %cr.name_any(), "SeccompProfile without a namespace; skipped");
            return Ok(None);
        };
        let name = cr.name_any();
        let localhost = localhost_profile_path(&ns, &name);
        let Some(rel) = safe_relative_path(&localhost) else {
            warn!(path = %localhost, "SeccompProfile resolves to an unsafe path; skipped");
            return Ok(None);
        };

        // 1. The file.
        let bytes = render_profile(&cr.spec);
        let hash = fingerprint(&bytes);
        let dest = self.cfg.root.join(&rel);
        let on_disk = match std::fs::read(&dest) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let status = cr.status.clone().unwrap_or_default();
        let my_entry = status.nodes.iter().find(|n| n.name == self.cfg.node_name);
        let mut last_written = my_entry.and_then(|n| n.last_written.clone());
        if on_disk.as_deref() != Some(bytes.as_slice()) {
            write_atomic(&dest, &bytes)?;
            last_written = Some(now_rfc3339());
            info!(dest = %dest.display(), hash = %hash, "wrote seccomp profile from SeccompProfile CR");
        }

        // 2. This node's status entry (only when it changed).
        let mut nodes_view = status.nodes.clone();
        if !self.cfg.node_name.is_empty() {
            let desired = NodeStatus {
                name: self.cfg.node_name.clone(),
                hash: hash.clone(),
                last_written,
            };
            if my_entry != Some(&desired) {
                self.apply_node_entry(&ns, &name, &desired).await?;
            }
            nodes_view.retain(|n| n.name != desired.name);
            nodes_view.push(desired);
        }

        // 3. The summary (only when it changed). The broker is asked about
        // this CR's workload here, through the pass's cache, so the first
        // CR naming a workload pays for the read and the rest of the pass
        // reuses it. Without a `workloadRef` there is nothing to ask and
        // `observation_conditions` says so on its own; without cluster
        // inputs at all — not a path either caller takes — the broker
        // counts as unreachable and the conditions carry forward.
        let total = self.cluster.as_ref().map(|c| c.total_nodes).unwrap_or(0);
        let fetch = self.fetch;
        let summaries = match (cr.spec.workload_ref.as_ref(), self.cluster.as_mut()) {
            (Some(wr), Some(cluster)) => cluster
                .readings
                .get_or_fetch(workload_key(&ns, wr), fetch)
                .await
                .summaries(),
            _ => None,
        };
        let desired = desired_summary(
            cr,
            &status,
            &nodes_view,
            &hash,
            &localhost,
            total,
            summaries,
        );
        if !summary_equal(&status, &desired) {
            self.apply_summary(&ns, &name, &desired).await?;
        }

        // 4. Mirror to the broker. Best-effort: the file and status are
        // already right; the UI just lags until the next pass.
        if let Err(e) = mirror_cr(&ns, &name, &cr.spec, &hash, desired.distribution.as_ref()).await
        {
            debug!(cr = %cr_id(cr), "seccomp CR mirror failed (will retry next pass): {e}");
        }

        Ok(Some((localhost, hash)))
    }

    async fn apply_node_entry(
        &self,
        ns: &str,
        name: &str,
        entry: &NodeStatus,
    ) -> Result<(), Error> {
        let api: Api<SeccompProfile> = Api::namespaced(self.client.clone(), ns);
        let patch = node_entry_patch(ns, name, entry);
        api.patch_status(
            name,
            &PatchParams::apply(&node_manager(&self.cfg.node_name)).force(),
            &Patch::Apply(patch),
        )
        .await?;
        debug!(cr = %format!("{ns}/{name}"), "applied status.nodes entry");
        Ok(())
    }

    async fn apply_summary(
        &self,
        ns: &str,
        name: &str,
        summary: &SeccompProfileStatus,
    ) -> Result<(), Error> {
        let api: Api<SeccompProfile> = Api::namespaced(self.client.clone(), ns);
        let patch = summary_patch(ns, name, summary);
        api.patch_status(
            name,
            &PatchParams::apply(MANAGER_SUMMARY).force(),
            &Patch::Apply(patch),
        )
        .await?;
        debug!(cr = %format!("{ns}/{name}"), "applied status summary");
        Ok(())
    }

    /// The user deleted the CR: remove its file and the broker mirror.
    async fn on_delete(&self, cr: &SeccompProfile) {
        let Some(ns) = cr.namespace() else { return };
        let name = cr.name_any();
        let localhost = localhost_profile_path(&ns, &name);
        match safe_relative_path(&localhost) {
            Some(rel) => match delete_profile_file(&self.cfg.root.join(rel)) {
                Ok(true) => {
                    info!(cr = %cr_id(cr), path = %localhost, "removed seccomp profile: SeccompProfile CR deleted")
                }
                Ok(false) => {
                    debug!(cr = %cr_id(cr), "SeccompProfile CR deleted; no file to remove")
                }
                Err(e) => warn!(cr = %cr_id(cr), "failed to remove seccomp profile file: {e}"),
            },
            None => {
                warn!(path = %localhost, "deleted SeccompProfile resolves to an unsafe path; nothing removed")
            }
        }
        if let Err(e) = api_delete_call(&format!("seccomp/crs/{ns}/{name}")).await {
            debug!(cr = %cr_id(cr), "seccomp CR mirror delete failed: {e}");
        }
    }

    /// Best-effort report of which profile files this node now has (and
    /// their hashes), so the broker can show readiness without touching
    /// the API server. A failure is logged and forgotten — the next pass
    /// re-reports.
    async fn report_node_status(&self, present: &[(String, String)]) {
        if self.cfg.node_name.is_empty() {
            return;
        }
        let body = node_status_body(&self.cfg.node_name, present);
        if let Err(e) = api_post_call(body, "seccomp/node-status").await {
            debug!("seccomp node-status report failed (will retry next pass): {e}");
        }
    }
}

/// `POST /seccomp/node-status` body. `files` carries `{path, hash}` pairs
/// (readiness = path AND hash match the mirrored CR); `paths` is the
/// legacy string list an older broker still understands.
pub fn node_status_body(node_name: &str, present: &[(String, String)]) -> serde_json::Value {
    let files: Vec<serde_json::Value> = present
        .iter()
        .map(|(path, hash)| json!({ "path": path, "hash": hash }))
        .collect();
    let paths: Vec<&str> = present.iter().map(|(p, _)| p.as_str()).collect();
    json!({ "node_name": node_name, "files": files, "paths": paths })
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Remove the file if present. `Ok(true)` when something was removed.
fn delete_profile_file(dest: &Path) -> Result<bool, Error> {
    match std::fs::remove_file(dest) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// `PUT /seccomp/crs/{ns}/{name}` body: the spec verbatim, the file hash,
/// and the distribution as this node computed it.
async fn mirror_cr(
    ns: &str,
    name: &str,
    spec: &SeccompProfileSpec,
    hash: &str,
    distribution: Option<&Distribution>,
) -> Result<(), Error> {
    api_put_call(
        mirror_body(spec, hash, distribution),
        &format!("seccomp/crs/{ns}/{name}"),
    )
    .await
}

pub fn mirror_body(
    spec: &SeccompProfileSpec,
    hash: &str,
    distribution: Option<&Distribution>,
) -> serde_json::Value {
    json!({ "spec": spec, "hash": hash, "status": { "distribution": distribution } })
}

/// Server-side-apply document for one node's `status.nodes` entry. The
/// list is `x-kubernetes-list-type: map` keyed on `name`, so this touches
/// only that entry.
pub fn node_entry_patch(ns: &str, name: &str, entry: &NodeStatus) -> serde_json::Value {
    json!({
        "apiVersion": "kguardian.dev/v1alpha1",
        "kind": "SeccompProfile",
        "metadata": { "name": name, "namespace": ns },
        "status": { "nodes": [entry] }
    })
}

/// Server-side-apply document for the shared summary: everything in
/// `status` except `nodes`.
pub fn summary_patch(ns: &str, name: &str, s: &SeccompProfileStatus) -> serde_json::Value {
    // Serialise the struct rather than spelling the fields out in `json!`:
    // the macro writes an absent `Option` as an explicit `null`, and the
    // apiserver keeps a `null` on a nullable field, so `status.denials`
    // would read as `null` instead of absent. The CRD contract is that the
    // block is present exactly when the Broker answered, and server-side
    // apply removes a field its manager stops sending. `nodes` is owned per
    // node and is never part of the summary.
    let status = serde_json::to_value(SeccompProfileStatus {
        nodes: Vec::new(),
        ..s.clone()
    })
    .expect("status serialises");
    json!({
        "apiVersion": "kguardian.dev/v1alpha1",
        "kind": "SeccompProfile",
        "metadata": { "name": name, "namespace": ns },
        "status": status,
    })
}

/// `distribution` from the per-node entries: a node is ready when its
/// entry carries the current hash.
pub fn compute_distribution(nodes: &[NodeStatus], hash: &str, total: u32) -> Distribution {
    let ready = nodes.iter().filter(|n| n.hash == hash).count() as u32;
    let ready = ready.min(total.max(ready));
    let state = if total > 0 && ready >= total {
        DistributionState::Ready
    } else if ready > 0 {
        DistributionState::Partial
    } else {
        DistributionState::Pending
    };
    Distribution {
        ready,
        total,
        state,
        summary: Some(format!("{ready}/{total}")),
    }
}

/// What a condition should say, before transition-time bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    pub type_: &'static str,
    pub status: &'static str,
    pub reason: &'static str,
    pub message: String,
}

pub fn ready_condition(d: &Distribution) -> Desired {
    let (status, reason) = match d.state {
        DistributionState::Ready => ("True", "AllNodes"),
        DistributionState::Partial => ("False", "SomeNodes"),
        DistributionState::Pending => ("False", "NoNodes"),
    };
    Desired {
        type_: COND_READY,
        status,
        reason,
        message: format!("{}/{} nodes", d.ready, d.total),
    }
}

/// What one pass concluded about the three broker-derived conditions,
/// and the `status.denials` block that belongs with the last of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observations {
    pub capture: Desired,
    pub drift: Desired,
    pub denials: Desired,
    /// `Some` exactly when `denials` is `True` or `False`, `None` when it
    /// is `Unknown`. The block and the condition are two readings of one
    /// answer and must never disagree: a count beside an `Unknown`
    /// condition reads as current, and an absent block beside a `False`
    /// would put a blank in the `Denials` column for a workload the
    /// broker affirmatively cleared.
    pub denial_summary: Option<DenialSummary>,
}

/// All three observation conditions `Unknown` for one reason. They are
/// decided from a single broker row, so when there is no row to decide
/// from they are unknown together.
fn all_unknown(reason: &'static str, message: String) -> Observations {
    Observations {
        capture: Desired {
            type_: COND_CAPTURE_COMPLETE,
            status: "Unknown",
            reason,
            message: message.clone(),
        },
        drift: Desired {
            type_: COND_DRIFT,
            status: "Unknown",
            reason,
            message: message.clone(),
        },
        denials: Desired {
            type_: COND_DENIALS_OBSERVED,
            status: "Unknown",
            reason,
            message,
        },
        denial_summary: None,
    }
}

/// `CaptureComplete`, `Drift` and `DenialsObserved` from the broker's
/// view of the CR's workload. `None` summaries (broker unreachable) ⇒
/// `None` here, and the caller keeps whatever the conditions already say.
///
/// `published` is the `status.denials` block already on the CR, and
/// `now` is this pass's RFC 3339 timestamp. Both are inputs because a
/// denial count and its timestamp keep moving while a workload keeps
/// denying, and because each node reads them from its own poll of the
/// broker — republishing every reading would re-apply the CR forever and
/// have nodes overwrite each other while doing it. See
/// `settled_denials`.
pub fn observation_conditions(
    namespace: &str,
    cr_name: &str,
    workload_ref: Option<&WorkloadRef>,
    summaries: Option<&[BrokerSummary]>,
    published: Option<&DenialSummary>,
    now: &str,
) -> Option<Observations> {
    let Some(wr) = workload_ref else {
        return Some(all_unknown(
            "NoWorkloadRef",
            "spec.workloadRef is not set".into(),
        ));
    };
    let summaries = summaries?;
    let row = summaries
        .iter()
        .find(|s| s.namespace == namespace && s.kind == wr.kind.as_str() && s.name == wr.name);
    let Some(row) = row else {
        return Some(all_unknown(
            "NoObservations",
            format!(
                "no observations yet for {} {}/{}",
                wr.kind.as_str(),
                namespace,
                wr.name
            ),
        ));
    };

    let capture = match &row.capture {
        Some(c) if c.complete => Desired {
            type_: COND_CAPTURE_COMPLETE,
            status: "True",
            reason: "Full",
            message: format!("full capture on {} pod(s)", c.pods.len()),
        },
        Some(c) => {
            let partial: Vec<String> = c
                .pods
                .iter()
                .filter(|p| p.level != "full")
                .map(|p| format!("{} ({})", p.name, p.level))
                .collect();
            Desired {
                type_: COND_CAPTURE_COMPLETE,
                status: "False",
                reason: "PartialCapture",
                message: format!(
                    "{} tier on {} pod(s): {}; the profile is incomplete and will block syscalls the workload uses",
                    c.level,
                    partial.len(),
                    partial.join(", ")
                ),
            }
        }
        None => Desired {
            type_: COND_CAPTURE_COMPLETE,
            status: "Unknown",
            reason: "NoObservations",
            message: "broker returned no capture summary".into(),
        },
    };

    let drift = match &row.cr {
        Some(cr) if cr.name == cr_name => match &cr.drift {
            Some(d) if d.in_sync => Desired {
                type_: COND_DRIFT,
                status: "False",
                reason: "InSync",
                message: "every observed syscall is in spec".into(),
            },
            Some(d) => Desired {
                type_: COND_DRIFT,
                status: "True",
                reason: "ObservedNotInSpec",
                message: format!(
                    "{} observed syscalls not in spec: {}",
                    d.missing.len(),
                    d.missing.join(", ")
                ),
            },
            None => Desired {
                type_: COND_DRIFT,
                status: "Unknown",
                reason: "NoObservations",
                message: "broker returned no drift summary".into(),
            },
        },
        Some(other) => Desired {
            type_: COND_DRIFT,
            status: "Unknown",
            reason: "NoObservations",
            message: format!(
                "broker matched this workload to SeccompProfile {:?}, not {:?}",
                other.name, cr_name
            ),
        },
        None => Desired {
            type_: COND_DRIFT,
            status: "Unknown",
            reason: "NoObservations",
            message: "broker has not seen this SeccompProfile yet".into(),
        },
    };

    let (denials, denial_summary) = match &row.denials {
        Some(d) => {
            // Zero is an answer, so it gets written out as one.
            //
            // The `Denials` printer column is bound to
            // `.status.denials.observed`, and that table is the surface
            // operators actually read. Leave the block unset for a zero
            // and the column goes blank for a workload the broker
            // affirmatively cleared — the same blank it shows for a
            // workload nothing is watching. Two opposite meanings in one
            // cell is precisely what the three-valued condition exists to
            // prevent, and it would be reintroduced one layer down where
            // nobody reading the table can see the condition at all. `0`
            // for clean and blank for unknown makes the column stand on
            // its own.
            //
            // The cost, since this is a trade: every clean CR carries an
            // all-zero `denials` block in `-o yaml`. That is noise, but
            // it is honest noise — it is the difference between "checked,
            // nothing" and "not checked", and it is the cheaper of the
            // two.
            let block = settled_denials(published, denial_block(d), now);
            let condition = denials_condition(&block);
            (condition, Some(block))
        }
        // No block at all. NOT zero denials — this is the whole point of
        // the condition being three-valued. `False` here would tell an
        // operator, and any alert reading the CR, that the kernel has
        // never acted on this profile, on no evidence whatsoever.
        //
        // The broker omits the block when it holds no denial rows for
        // anything, because at that point "this workload was never
        // denied" and "nothing on this cluster is capturing denials" are
        // the same database state — capture needs CONFIG_AUDIT on the
        // node and can be switched off. An older broker omits it because
        // the field did not exist. Both are genuinely "we do not know",
        // and the message names both because the fix differs.
        None => (
            Desired {
                type_: COND_DENIALS_OBSERVED,
                status: "Unknown",
                reason: "NoDenialData",
                message: "broker reported no denials data; either it predates denial \
                          capture or no node is capturing"
                    .into(),
            },
            None,
        ),
    };

    Some(Observations {
        capture,
        drift,
        denials,
        denial_summary,
    })
}

/// This pass's reading of one broker block, before `settled_denials`
/// decides whether it is the one to publish.
///
/// Sorts and de-duplicates the names rather than mirroring the broker's
/// order, because the sorted form is what `denial_rank` compares and
/// what `summary_equal` compares. A broker that returned them in an
/// unstable order (a `HashSet` drained on the other side, say) would
/// otherwise have two nodes rank identical readings differently and take
/// turns overwriting each other. `render_profile` sorts for the same
/// reason. Sorting closes that door; the count and the timestamp move on
/// their own even when the content does not, and `settled_denials`
/// closes theirs.
fn denial_block(d: &BrokerDenials) -> DenialSummary {
    DenialSummary {
        // Clamped rather than trusted: `observed` is a `u64` in the CR
        // and the apiserver would reject a negative one outright.
        observed: d.total.max(0) as u64,
        syscalls: sorted_unique(&d.syscalls),
        actions: sorted_unique(&d.actions),
        last_seen: normalised_last_seen(d.last_seen.as_deref()),
        // Stamped by `settled_denials`, and only if this reading is the
        // one that ends up published.
        refreshed_at: None,
    }
}

/// The `DenialsObserved` condition for the block that is being
/// published.
///
/// Rendered from that block and from nothing else, for two reasons that
/// are really one reason. `settled_denials` may keep a block this pass
/// did not compute, so anything fresh mixed into the message would
/// narrate two different readings in one sentence — the count in
/// `kubectl describe` must be the count in the `Denials` column. And the
/// message is part of the condition, which `summary_equal` compares:
/// anything in it that differs between two nodes' polls is a field the
/// whole fleet would overwrite for each other on every pass. That is why
/// the `SCMP_ACT_*` verdicts live on the block rather than being passed
/// in beside it.
fn denials_condition(block: &DenialSummary) -> Desired {
    // "Are there denials" is the count, except that a count of zero
    // alongside named syscalls can only be a broker bug — and of the two
    // ways to be wrong about it, saying "denials, go look" beats handing
    // out a clean bill of health. The printer column still shows the
    // count the broker sent, so the contradiction stays visible rather
    // than being papered over with a number kguardian made up.
    if block.observed == 0 && block.syscalls.is_empty() {
        return Desired {
            type_: COND_DENIALS_OBSERVED,
            status: "False",
            reason: "NoDenials",
            message: "no denials in the retention window".into(),
        };
    }
    let actions = if block.actions.is_empty() {
        String::new()
    } else {
        format!(" ({})", block.actions.join(", "))
    };
    let last_seen = match &block.last_seen {
        Some(ts) => format!("; last seen {ts}"),
        None => String::new(),
    };
    Desired {
        type_: COND_DENIALS_OBSERVED,
        status: "True",
        reason: "KernelDenied",
        message: format!(
            "{} seccomp denial(s){actions} on {} syscall(s): {}{last_seen}",
            block.observed,
            block.syscalls.len(),
            block.syscalls.join(", "),
        ),
    }
}

/// How stale the published reading may get before the next node to
/// reconcile replaces it outright. Thirty resyncs: long enough that a
/// workload denying non-stop costs one apply a quarter of an hour rather
/// than one per node per pass, short enough that an operator reading the
/// `Denials` column is never behind by more than a coffee break.
const DENIAL_REFRESH_SECS: i64 = 15 * 60;

/// Which denial block to publish: the reading this pass computed, or the
/// one the CR already carries.
///
/// `observed` climbs and `lastSeen` advances for as long as a workload
/// keeps tripping its filter, and `summary_equal` compares the whole
/// block — so publishing every reading would have every node
/// server-side-apply the CR on every resync for the entire time the
/// denials continue, each apply bumping `resourceVersion` and fanning a
/// watch event back to every other node's reflector. On a sixty-node
/// cluster that is 120 writes a minute per CR, forever, on a cluster
/// that has otherwise converged.
///
/// Slowing that down is not enough, and this is the part that is easy to
/// get wrong. Each node polls the broker on its own schedule and
/// compares the CR against *its own* poll, so any symmetric "has this
/// moved enough to be worth republishing" test has two nodes whose polls
/// straddle the threshold each finding the other's published value worth
/// overwriting — and they alternate for as long as both keep
/// reconciling. A rate limit makes that slower, not finite. So the test
/// here is one-directional in both of its halves:
///
///  * `denial_rank` is a fixed total order over readings, and a node
///    republishes only when its own reading ranks strictly above the
///    published one. Of any two nodes at most one can then ever want to
///    overwrite the other, so the block settles on the highest-ranked
///    reading the fleet has taken — a function of the readings, not of
///    which node reconciled first.
///  * A ratchet only climbs, so on its own it would never let a weaker
///    reading through: not a retention prune, not a burst ending, not a
///    count returning to zero. `refreshedAt` is the release. Once the
///    published reading is `DENIAL_REFRESH_SECS` old the next node to
///    reconcile replaces it wholesale, whatever it says, and stamps it
///    afresh. That decision reads the CR and the clock and nothing else,
///    so every node agrees on when it is due; the few that reconcile in
///    the same instant may each write once, and then the whole fleet is
///    quiet again for another quarter of an hour.
///
/// The cost, since this is a trade: `status.denials` is a reading taken
/// up to `DENIAL_REFRESH_SECS` ago, biased towards the loudest reading
/// any node took in that window. A count climbing inside one order of
/// magnitude, a count falling, and a workload going quiet all take up to
/// that long to surface; a cleared workload is cleared late rather than
/// early, which is the safe direction for a field an operator promotes a
/// profile on. `GET /seccomp/denials` is the live view, and `refreshedAt`
/// on the block says how old the published one is — both of which the
/// CRD schema description says out loud, because a CRD consumer never
/// sees this comment.
fn settled_denials(
    published: Option<&DenialSummary>,
    mut fresh: DenialSummary,
    now: &str,
) -> DenialSummary {
    if let Some(prev) = published {
        if !refresh_due(prev, now) && denial_rank(&fresh) <= denial_rank(prev) {
            return prev.clone();
        }
    }
    fresh.refreshed_at = Some(now.to_string());
    fresh
}

/// The fixed total order two readings of one workload are compared
/// under. Breadth first — a syscall the kernel had not acted on before,
/// or a verdict it had not returned before, is the strongest thing a
/// reading can say, at any count — then the order of magnitude of the
/// count. The names themselves are the last tie-break and their ordering
/// is arbitrary: they are in the key so that two readings which are
/// equally broad and equally loud still compare, which is what makes the
/// order total and so the ratchet asymmetric.
///
/// The exact count is deliberately not in the key. It moves on every
/// single denial, and a key that moved with it would be the patch loop
/// again, one magnitude finer.
///
/// A reading that ranks lower is not lost, only late: it reaches the CR
/// on the next `refresh_due`. In practice the case that matters most
/// arrives early anyway — a profile going from logging to returning
/// errors shows up as `[SCMP_ACT_ERRNO, SCMP_ACT_LOG]` for as long as
/// the broker's retention window still holds both, which outranks
/// `[SCMP_ACT_LOG]` on length.
fn denial_rank(b: &DenialSummary) -> (usize, usize, u32, &[String], &[String]) {
    (
        b.syscalls.len(),
        b.actions.len(),
        count_magnitude(b.observed),
        &b.syscalls,
        &b.actions,
    )
}

/// Digits in the count, with zero in a bucket of its own: 0, 1-9, 10-99,
/// and so on. Zero is separate because "cleared" and "denied once" are
/// opposite answers, and `observed: 0` is what clears a profile for
/// promotion to an enforcing action.
///
/// Worth being exact about how much that carries, because it is less
/// than it looks. In `denial_rank` the count is reached only when the
/// two breadth terms tie, so on the common path — a first denial
/// arriving with a syscall name on it — the name is what republishes and
/// this never gets a vote. The zero bucket is the backstop for a reading
/// carrying no names at all, which is what a denial the broker cannot
/// put a syscall name to looks like once `sorted_unique` has dropped the
/// empty one.
fn count_magnitude(observed: u64) -> u32 {
    observed.checked_ilog10().map_or(0, |n| n + 1)
}

/// Whether the published reading is old enough that the next node to
/// reconcile should replace it outright. Reads the CR and the clock and
/// nothing else — no node's own poll — so the whole fleet reaches the
/// same answer at the same moment instead of each deciding from what it
/// happens to have seen.
///
/// A block with no `refreshedAt` is due at once: it was written by a
/// controller from before the field existed, or edited by hand. Writing
/// it stamps one and puts it back under the floor.
///
/// Deliberately not an absolute difference. A node whose clock runs fast
/// stamps a `refreshedAt` in the future; the rest of the fleet then
/// waits out the skew, rather than reading the future stamp as overdue
/// and racing to correct it on every pass — which is the same alternation
/// this function exists to avoid, moved onto the clock.
fn refresh_due(published: &DenialSummary, now: &str) -> bool {
    let (Some(stamp), Ok(now)) = (
        published.refreshed_at.as_deref(),
        DateTime::parse_from_rfc3339(now),
    ) else {
        return true;
    };
    match DateTime::parse_from_rfc3339(stamp) {
        Ok(taken) => (now - taken).num_seconds() >= DENIAL_REFRESH_SECS,
        // Not a timestamp at all: hand edited. Replace the block once,
        // and the pass after that has two instants to compare.
        Err(_) => true,
    }
}

/// Sorted, de-duplicated, empties dropped.
fn sorted_unique(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Re-spell the broker's `lastSeen` the way `now_rfc3339` spells a
/// timestamp, or drop it if it is not a timestamp at all.
///
/// Not what keeps a re-spelling out of the patch loop — `lastSeen` is
/// not in `denial_rank`, so on its own it can never win a republish. It
/// is what keeps `status.denials.lastSeen` a single spelling of a time
/// across a mixed-version fleet, and dropping an unparseable value keeps
/// it a field an operator can read as a time at all.
fn normalised_last_seen(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let parsed = DateTime::parse_from_rfc3339(raw).ok()?;
    Some(
        parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

/// Merge desired conditions over the existing ones: the transition time
/// is kept when `status` is unchanged and set to `now` otherwise, so an
/// unchanged summary compares equal and is not re-applied.
pub fn merge_conditions(existing: &[Condition], desired: &[Desired], now: &str) -> Vec<Condition> {
    desired
        .iter()
        .map(|d| {
            let prev = existing.iter().find(|c| c.type_ == d.type_);
            let last_transition_time = match prev {
                Some(p) if p.status == d.status => p.last_transition_time.clone(),
                _ => Some(now.to_string()),
            };
            Condition {
                type_: d.type_.to_string(),
                status: d.status.to_string(),
                reason: d.reason.to_string(),
                message: d.message.clone(),
                last_transition_time,
            }
        })
        .collect()
}

/// The summary this node wants `status` to carry. `nodes` is the CR's
/// current entries with this node's own entry already updated.
#[allow(clippy::too_many_arguments)]
pub fn desired_summary(
    cr: &SeccompProfile,
    existing: &SeccompProfileStatus,
    nodes: &[NodeStatus],
    hash: &str,
    localhost: &str,
    total_nodes: u32,
    summaries: Option<&[BrokerSummary]>,
) -> SeccompProfileStatus {
    let distribution = compute_distribution(nodes, hash, total_nodes);
    let ready = ready_condition(&distribution);
    let now = now_rfc3339();

    let mut desired: Vec<Desired> = vec![ready];
    let denials = match observation_conditions(
        cr.namespace().as_deref().unwrap_or_default(),
        &cr.name_any(),
        cr.spec.workload_ref.as_ref(),
        summaries,
        existing.denials.as_ref(),
        &now,
    ) {
        Some(o) => {
            desired.push(o.capture);
            desired.push(o.drift);
            desired.push(o.denials);
            o.denial_summary
        }
        // Broker unreachable: carry the existing three forward untouched,
        // and with them whatever `status.denials` already said. Dropping
        // the block here would blank the `Denials` printer column on every
        // broker blip, and a blank column is how this status spells "no
        // data" — an outage would keep announcing that kguardian had
        // forgotten what it already knew.
        None => {
            for t in OBSERVED_CONDITIONS {
                if let Some(c) = existing.conditions.iter().find(|c| c.type_ == t) {
                    desired.push(Desired {
                        type_: t,
                        status: match c.status.as_str() {
                            "True" => "True",
                            "False" => "False",
                            _ => "Unknown",
                        },
                        reason: leak_reason(&c.reason),
                        message: c.message.clone(),
                    });
                }
            }
            existing.denials.clone()
        }
    };
    let conditions = merge_conditions(&existing.conditions, &desired, &now);
    let drift = conditions
        .iter()
        .find(|c| c.type_ == COND_DRIFT)
        .map(|c| c.status.clone());

    SeccompProfileStatus {
        observed_generation: cr.metadata.generation,
        hash: Some(hash.to_string()),
        localhost_profile: Some(localhost.to_string()),
        distribution: Some(distribution),
        drift,
        denials,
        nodes: Vec::new(),
        conditions,
    }
}

/// Map a stored reason back onto the static set. Anything unrecognised
/// falls back to `NoObservations`, which is a valid `Unknown` reason for
/// every one of these conditions.
fn leak_reason(reason: &str) -> &'static str {
    match reason {
        "Full" => "Full",
        "PartialCapture" => "PartialCapture",
        "NoWorkloadRef" => "NoWorkloadRef",
        "InSync" => "InSync",
        "ObservedNotInSpec" => "ObservedNotInSpec",
        "KernelDenied" => "KernelDenied",
        "NoDenials" => "NoDenials",
        "NoDenialData" => "NoDenialData",
        _ => "NoObservations",
    }
}

/// True when the summary fields (everything but `nodes`) already match.
pub fn summary_equal(existing: &SeccompProfileStatus, desired: &SeccompProfileStatus) -> bool {
    existing.observed_generation == desired.observed_generation
        && existing.hash == desired.hash
        && existing.localhost_profile == desired.localhost_profile
        && existing.distribution == desired.distribution
        && existing.drift == desired.drift
        && existing.denials == desired.denials
        && existing.conditions == desired.conditions
}

/// Reduce a `kguardian/<ns>/<name>.json` path to a relative path that is
/// safe to join onto the seccomp root: no absolute prefix, no `..`, no
/// `.` or empty components. Namespace and name are DNS-1123 so this
/// cannot fail for a real CR, but the distributor writes to (and deletes
/// from) the host filesystem — so it is validated rather than trusted.
fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut out = PathBuf::new();
    let mut components = 0;
    for comp in Path::new(raw).components() {
        match comp {
            std::path::Component::Normal(c) => {
                let s = c.to_str()?;
                if s == ".." || s.is_empty() {
                    return None;
                }
                out.push(s);
                components += 1;
            }
            // RootDir, Prefix, CurDir, ParentDir are all disallowed.
            _ => return None,
        }
    }
    if components == 0 {
        return None;
    }
    Some(out)
}

/// Write `data` to `dest` atomically: create the parent directory, write
/// to a sibling temp file, then rename over `dest`. A concurrent reader
/// (the kubelet loading the profile) never sees a partial file.
fn write_atomic(dest: &Path, data: &[u8]) -> Result<(), Error> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::Custom(format!("{} has no parent directory", dest.display())))?;
    std::fs::create_dir_all(parent)?;

    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Custom(format!("{} has no file name", dest.display())))?;
    let tmp = parent.join(format!(".{}.{}.tmp", file_name, std::process::id()));

    // Scope the handle so it is flushed and closed before the rename.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp_crd::{
        Architecture, DefaultAction, RuleAction, SyscallName, SyscallRule, WorkloadKind,
    };

    fn node(name: &str, hash: &str) -> NodeStatus {
        NodeStatus {
            name: name.into(),
            hash: hash.into(),
            last_written: Some("2026-09-03T00:00:00Z".into()),
        }
    }

    fn cr(ns: &str, name: &str, workload: Option<&str>) -> SeccompProfile {
        let mut c = SeccompProfile::new(
            name,
            SeccompProfileSpec {
                default_action: DefaultAction::Log,
                architectures: Some(vec![Architecture::X8664]),
                syscalls: vec![SyscallRule {
                    names: vec![SyscallName("read".into()), SyscallName("write".into())],
                    action: RuleAction::Allow,
                    errno_ret: None,
                }],
                workload_ref: workload.map(|w| WorkloadRef {
                    kind: WorkloadKind::Deployment,
                    name: w.into(),
                }),
            },
        );
        c.metadata.namespace = Some(ns.into());
        c.metadata.generation = Some(3);
        c
    }

    fn summary_row(ns: &str, name: &str, complete: bool, cr: Option<BrokerCr>) -> BrokerSummary {
        BrokerSummary {
            namespace: ns.into(),
            kind: "Deployment".into(),
            name: name.into(),
            capture: Some(BrokerCapture {
                level: if complete {
                    "full".into()
                } else {
                    "low".into()
                },
                complete,
                pods: vec![
                    BrokerPod {
                        name: "web-1".into(),
                        level: if complete {
                            "full".into()
                        } else {
                            "low".into()
                        },
                    },
                    BrokerPod {
                        name: "web-2".into(),
                        level: "full".into(),
                    },
                ],
            }),
            cr,
            // A broker that predates denial capture: the field is simply
            // not in the JSON. Every test that wants denials opts in
            // with `with_denials`, so the default row keeps proving the
            // older-broker path stays `Unknown`.
            denials: None,
        }
    }

    fn with_denials(row: BrokerSummary, denials: BrokerDenials) -> BrokerSummary {
        BrokerSummary {
            denials: Some(denials),
            ..row
        }
    }

    /// `secs` past a fixed instant, spelled the way the broker spells
    /// `lastSeen`. Lets a test walk a workload's denials forward in time.
    fn at(secs: u64) -> String {
        let base = DateTime::parse_from_rfc3339("2026-09-14T04:00:00Z").expect("fixed base");
        (base + chrono::Duration::seconds(secs as i64)).to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    /// A fixed `now` for tests that call `observation_conditions`
    /// directly, so the stamp `settled_denials` writes is assertable.
    const NOW: &str = "2026-09-14T05:00:00Z";

    /// Push a published block's `refreshedAt` `secs` into the past, so a
    /// test can reach the refresh floor without waiting for it. Relative
    /// to the real clock because `desired_summary` reads the real clock.
    fn backdate(s: &SeccompProfileStatus, secs: i64) -> SeccompProfileStatus {
        let mut s = s.clone();
        let then = Utc::now() - chrono::Duration::seconds(secs);
        if let Some(d) = s.denials.as_mut() {
            d.refreshed_at = Some(then.to_rfc3339_opts(SecondsFormat::Secs, true));
        }
        s
    }

    fn denials(total: i64, syscalls: &[&str]) -> BrokerDenials {
        BrokerDenials {
            total,
            syscalls: syscalls.iter().map(|s| (*s).to_string()).collect(),
            actions: vec!["SCMP_ACT_LOG".into()],
            last_seen: Some("2026-09-14T04:05:14Z".into()),
        }
    }

    fn key(ns: &str, name: &str) -> WorkloadKey {
        (ns.into(), "Deployment".into(), name.into())
    }

    fn web_ref() -> WorkloadRef {
        WorkloadRef {
            kind: WorkloadKind::Deployment,
            name: "web".into(),
        }
    }

    /// A fresh directory under the system temp dir for a `Reconciler` to
    /// write profiles into. Callers remove it.
    fn test_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kg-seccomp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A `Reconciler` whose kube client points at a closed loopback port,
    /// so every API-server call fails fast, whose node name is empty, so
    /// no per-node status is applied before the broker is consulted, and
    /// whose broker is `fetch`. Enough to run `full_pass` and see what it
    /// decides to ask for.
    async fn offline_reconciler(
        root: PathBuf,
        fetch: WorkloadFetch,
    ) -> (Reconciler, reflector::store::Writer<SeccompProfile>) {
        // What `main` does at startup; kube's client construction needs a
        // rustls provider even for a plain-http server. `Err` means another
        // test got there first.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let kubeconfig = kube::config::Kubeconfig::from_yaml(
            "apiVersion: v1\nkind: Config\ncurrent-context: dead\n\
             clusters:\n- name: dead\n  cluster:\n    server: http://127.0.0.1:1\n\
             contexts:\n- name: dead\n  context:\n    cluster: dead\n    user: nobody\n\
             users:\n- name: nobody\n  user: {}\n",
        )
        .expect("kubeconfig");
        let config = kube::Config::from_custom_kubeconfig(
            kubeconfig,
            &kube::config::KubeConfigOptions::default(),
        )
        .await
        .expect("config");
        let client = Client::try_from(config).expect("client");
        let (store, writer) = reflector::store();
        let rec = Reconciler {
            cfg: Config {
                root,
                interval: DEFAULT_INTERVAL,
                node_name: String::new(),
            },
            client,
            store,
            cluster: None,
            fetch,
            last_total_nodes: 0,
        };
        (rec, writer)
    }

    #[test]
    fn rebuild_backoff_doubles_and_caps_at_sixty_seconds() {
        // A watch stream that ends must be rebuilt, not abandoned: the
        // schedule is 1,2,4,…,60s and never grows past the cap or
        // overflows on a long streak.
        let secs: Vec<u64> = (0..8).map(|n| rebuild_delay(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(rebuild_delay(u32::MAX), REBUILD_BACKOFF_MAX);
        assert!(rebuild_delay(0) >= Duration::from_secs(1));
    }

    #[test]
    fn distribution_ready_partial_pending() {
        let h = "aaaa";
        let d = compute_distribution(&[node("a", h), node("b", h)], h, 2);
        assert_eq!(d.state, DistributionState::Ready);
        assert_eq!((d.ready, d.total), (2, 2));
        assert_eq!(d.summary.as_deref(), Some("2/2"));

        let d = compute_distribution(&[node("a", h), node("b", "stale")], h, 3);
        assert_eq!(d.state, DistributionState::Partial);
        assert_eq!((d.ready, d.total), (1, 3));

        let d = compute_distribution(&[node("a", "stale")], h, 3);
        assert_eq!(d.state, DistributionState::Pending);
        assert_eq!((d.ready, d.total), (0, 3));

        // No nodes known at all is never "Ready".
        let d = compute_distribution(&[], h, 0);
        assert_eq!(d.state, DistributionState::Pending);

        // Ready condition follows the state.
        assert_eq!(
            ready_condition(&compute_distribution(&[node("a", h)], h, 1)).reason,
            "AllNodes"
        );
        assert_eq!(
            ready_condition(&compute_distribution(&[node("a", h)], h, 2)).reason,
            "SomeNodes"
        );
        assert_eq!(
            ready_condition(&compute_distribution(&[], h, 2)).reason,
            "NoNodes"
        );
    }

    #[test]
    fn observation_conditions_cover_every_branch() {
        // No workloadRef ⇒ all three Unknown/NoWorkloadRef, even without
        // a broker.
        let o = observation_conditions("prod", "deployment-web", None, None, None, NOW).unwrap();
        let (c, d) = (&o.capture, &o.drift);
        assert_eq!((c.status, c.reason), ("Unknown", "NoWorkloadRef"));
        assert_eq!((d.status, d.reason), ("Unknown", "NoWorkloadRef"));
        assert_eq!(
            (o.denials.status, o.denials.reason),
            ("Unknown", "NoWorkloadRef")
        );
        assert!(o.denial_summary.is_none());

        let wr = WorkloadRef {
            kind: WorkloadKind::Deployment,
            name: "web".into(),
        };
        // Broker unreachable ⇒ None (caller keeps existing conditions).
        assert!(
            observation_conditions("prod", "deployment-web", Some(&wr), None, None, NOW).is_none()
        );

        // No row for the workload ⇒ Unknown/NoObservations.
        let o = observation_conditions("prod", "deployment-web", Some(&wr), Some(&[]), None, NOW)
            .unwrap();
        let (c, d) = (&o.capture, &o.drift);
        assert_eq!((c.status, c.reason), ("Unknown", "NoObservations"));
        assert_eq!((d.status, d.reason), ("Unknown", "NoObservations"));
        assert_eq!(
            (o.denials.status, o.denials.reason),
            ("Unknown", "NoObservations")
        );
        assert!(o.denial_summary.is_none());

        // Complete capture + in-sync CR.
        let rows = [summary_row(
            "prod",
            "web",
            true,
            Some(BrokerCr {
                name: "deployment-web".into(),
                drift: Some(BrokerDrift {
                    missing: vec![],
                    extra: vec![],
                    in_sync: true,
                }),
            }),
        )];
        let o = observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows), None, NOW)
            .unwrap();
        let (c, d) = (&o.capture, &o.drift);
        assert_eq!((c.status, c.reason), ("True", "Full"));
        assert_eq!((d.status, d.reason), ("False", "InSync"));

        // Partial capture + drift, message names tier, pods and syscalls.
        let rows = [summary_row(
            "prod",
            "web",
            false,
            Some(BrokerCr {
                name: "deployment-web".into(),
                drift: Some(BrokerDrift {
                    missing: vec!["clock_adjtime".into(), "ptrace".into()],
                    extra: vec![],
                    in_sync: false,
                }),
            }),
        )];
        let o = observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows), None, NOW)
            .unwrap();
        let (c, d) = (&o.capture, &o.drift);
        assert_eq!((c.status, c.reason), ("False", "PartialCapture"));
        assert!(
            c.message.contains("low tier on 1 pod(s): web-1 (low)"),
            "{}",
            c.message
        );
        assert_eq!((d.status, d.reason), ("True", "ObservedNotInSpec"));
        assert_eq!(
            d.message,
            "2 observed syscalls not in spec: clock_adjtime, ptrace"
        );

        // Broker matched the workload to a different CR ⇒ Drift Unknown.
        let rows = [summary_row(
            "prod",
            "web",
            true,
            Some(BrokerCr {
                name: "other".into(),
                drift: None,
            }),
        )];
        let d = observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows), None, NOW)
            .unwrap()
            .drift;
        assert_eq!((d.status, d.reason), ("Unknown", "NoObservations"));
        assert!(d.message.contains("\"other\""));

        // Namespace must match, not just the workload name.
        let rows = [summary_row("staging", "web", true, None)];
        let c = observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows), None, NOW)
            .unwrap()
            .capture;
        assert_eq!(c.reason, "NoObservations");
    }

    /// The distinction this feature exists to preserve: a row whose
    /// `denials` block is absent is not a row that says zero.
    ///
    /// Absent is what a broker sends when it predates denial capture, and
    /// when it holds no denial rows at all — at which point "this workload
    /// was never denied" and "nothing on this cluster is capturing" are
    /// the same database state. Zero is an answer: the broker looked, and
    /// nothing has fired.
    ///
    /// Collapsing them costs an operator the difference between
    /// "kguardian checked and this profile has never fired" and "nothing
    /// checked". Only the first is grounds for promoting a profile to an
    /// enforcing action, and it is exactly the reading `False` invites.
    /// Both the condition and `status.denials` carry the distinction, so
    /// neither a `kubectl get` nor a JSONPath gate can land on the wrong
    /// one. The broker guards the other end of the same wire — see
    /// `a_cr_without_names_emits_no_drift_rather_than_an_empty_one`.
    #[test]
    fn an_absent_denials_block_is_unknown_rather_than_zero() {
        let wr = WorkloadRef {
            kind: WorkloadKind::Deployment,
            name: "web".into(),
        };
        let c = cr("prod", "deployment-web", Some("web"));
        let path = "kguardian/prod/deployment-web.json";
        let nodes = [node("a", "h1")];
        let summarise = |rows: &[BrokerSummary]| {
            desired_summary(
                &c,
                &SeccompProfileStatus::default(),
                &nodes,
                "h1",
                path,
                1,
                Some(rows),
            )
        };
        let denials_of = |s: &SeccompProfileStatus| {
            s.conditions
                .iter()
                .find(|c| c.type_ == COND_DENIALS_OBSERVED)
                .cloned()
                .expect("DenialsObserved is always emitted")
        };

        // A broker that reports on the workload but says nothing about
        // denials.
        let silent_rows = [summary_row("prod", "web", true, None)];
        let o = observation_conditions(
            "prod",
            "deployment-web",
            Some(&wr),
            Some(&silent_rows),
            None,
            NOW,
        )
        .unwrap();
        assert_eq!(
            (o.denials.status, o.denials.reason),
            ("Unknown", "NoDenialData"),
            "silence from the broker is not a clean bill of health"
        );
        assert!(
            o.denial_summary.is_none(),
            "no block may be published beside an Unknown condition"
        );

        // The same broker, explicitly reporting zero for this workload.
        let clean_rows = [with_denials(
            summary_row("prod", "web", true, None),
            BrokerDenials::default(),
        )];
        let o = observation_conditions(
            "prod",
            "deployment-web",
            Some(&wr),
            Some(&clean_rows),
            None,
            NOW,
        )
        .unwrap();
        assert_eq!((o.denials.status, o.denials.reason), ("False", "NoDenials"));
        assert_eq!(
            o.denial_summary,
            Some(DenialSummary {
                refreshed_at: Some(NOW.to_string()),
                ..Default::default()
            }),
            "zero is a block with an explicit count, not an absent block"
        );

        // Both readings of the CR keep them apart: the status block and
        // the condition.
        let unknown = summarise(&silent_rows);
        let clean = summarise(&clean_rows);
        assert!(unknown.denials.is_none());
        assert_eq!(clean.denials.as_ref().unwrap().observed, 0);
        assert!(
            summary_patch("prod", "deployment-web", &unknown)["status"]
                .get("denials")
                .is_none(),
            "an unknown block is absent from the applied status, not an explicit null: \
             the apiserver keeps a null on a nullable field and the Denials column \
             contract is present-exactly-when-answered"
        );
        assert_eq!(
            summary_patch("prod", "deployment-web", &clean)["status"]["denials"]["observed"],
            0,
            "the Denials column shows a real 0 for a cleared workload"
        );
        assert_eq!(denials_of(&clean).status, "False");
        assert_eq!(denials_of(&unknown).status, "Unknown");
    }

    /// One rule ties the block to the condition across every branch:
    /// `status.denials` is present exactly when `DenialsObserved` has
    /// decided something — `True` or `False` — and absent exactly when it
    /// is `Unknown`. The two are readings of one answer, so a stale count
    /// can never sit beside an `Unknown`, and a `False` can never leave
    /// the `Denials` column blank.
    ///
    /// This holds across a broker outage too, where the condition and the
    /// block are carried forward together rather than recomputed.
    #[test]
    fn a_denials_block_is_present_exactly_when_the_condition_is_decided() {
        let c = cr("prod", "deployment-web", Some("web"));
        let path = "kguardian/prod/deployment-web.json";
        let nodes = [node("a", "h1")];
        let row = |d: Option<BrokerDenials>| match d {
            Some(d) => with_denials(summary_row("prod", "web", true, None), d),
            None => summary_row("prod", "web", true, None),
        };
        let cases = [
            // (rows for this pass, what it is)
            (vec![row(Some(denials(17, &["ptrace"])))], "denials present"),
            (
                vec![row(Some(BrokerDenials::default()))],
                "broker reports zero",
            ),
            (vec![row(None)], "broker sent no denials block"),
            (vec![], "no row for the workload at all"),
        ];
        let mut status = SeccompProfileStatus::default();
        for (rows, what) in cases {
            status = desired_summary(&c, &status, &nodes, "h1", path, 1, Some(&rows));
            let decided = status
                .conditions
                .iter()
                .find(|c| c.type_ == COND_DENIALS_OBSERVED)
                .map(|c| c.status != "Unknown")
                .unwrap_or(false);
            assert_eq!(
                status.denials.is_some(),
                decided,
                "{what}: block presence must track a decided DenialsObserved"
            );
        }

        // And the same holds through an outage, which carries both
        // forward rather than recomputing either.
        let seen = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &nodes,
            "h1",
            path,
            1,
            Some(&[row(Some(denials(17, &["ptrace"])))]),
        );
        let outage = desired_summary(&c, &seen, &nodes, "h1", path, 1, None);
        assert!(outage.denials.is_some());
        assert_eq!(
            outage
                .conditions
                .iter()
                .find(|c| c.type_ == COND_DENIALS_OBSERVED)
                .unwrap()
                .status,
            "True"
        );
    }

    #[test]
    fn denials_set_the_condition_the_block_and_the_message() {
        let wr = WorkloadRef {
            kind: WorkloadKind::Deployment,
            name: "web".into(),
        };
        let rows = [with_denials(
            summary_row("prod", "web", true, None),
            BrokerDenials {
                total: 17,
                // Unsorted, duplicated, and with an empty name: whatever
                // the broker's aggregation happened to emit.
                syscalls: vec![
                    "ptrace".into(),
                    "mount".into(),
                    "ptrace".into(),
                    String::new(),
                ],
                actions: vec!["SCMP_ACT_LOG".into(), "SCMP_ACT_LOG".into()],
                last_seen: Some("2026-09-14T04:05:14Z".into()),
            },
        )];
        let o = observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows), None, NOW)
            .unwrap();
        assert_eq!(
            (o.denials.status, o.denials.reason),
            ("True", "KernelDenied")
        );
        assert_eq!(
            o.denials.message,
            "17 seccomp denial(s) (SCMP_ACT_LOG) on 2 syscall(s): mount, ptrace; \
             last seen 2026-09-14T04:05:14Z"
        );
        let block = o.denial_summary.unwrap();
        assert_eq!(block.observed, 17);
        assert_eq!(block.syscalls, ["mount", "ptrace"]);
        assert_eq!(block.last_seen.as_deref(), Some("2026-09-14T04:05:14Z"));
        assert_eq!(
            block.actions,
            ["SCMP_ACT_LOG"],
            "the verdicts the message names are on the block it renders"
        );
        assert_eq!(block.refreshed_at.as_deref(), Some(NOW));

        // A count of zero next to named syscalls can only be a broker
        // bug. Of the two ways to be wrong about it, "there are denials,
        // go look" beats handing out a clean bill of health.
        let rows = [with_denials(
            summary_row("prod", "web", true, None),
            BrokerDenials {
                total: 0,
                syscalls: vec!["ptrace".into()],
                ..Default::default()
            },
        )];
        let o = observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows), None, NOW)
            .unwrap();
        assert_eq!(o.denials.status, "True");
        assert_eq!(
            o.denial_summary.unwrap().observed,
            0,
            "the column still shows the count the broker sent, so the \
             contradiction stays visible instead of being papered over"
        );
    }

    /// Every node computes this block and applies it under the shared
    /// `kguardian-summary` manager, and the apply is skipped only when it
    /// compares equal to what is already on the CR. So the block has to be
    /// a function of the broker's content, not of the order or spelling
    /// the broker happened to use — otherwise an idle cluster re-patches
    /// every CR on every pass, forever, for no change at all.
    #[test]
    fn the_denials_block_is_a_function_of_content_not_spelling() {
        let a = denial_block(&BrokerDenials {
            total: 3,
            syscalls: vec!["ptrace".into(), "mount".into()],
            actions: vec!["SCMP_ACT_LOG".into(), "SCMP_ACT_ERRNO".into()],
            last_seen: Some("2026-09-14T04:05:14Z".into()),
        });
        let b = denial_block(&BrokerDenials {
            total: 3,
            syscalls: vec!["mount".into(), "ptrace".into(), "mount".into()],
            actions: vec![
                "SCMP_ACT_ERRNO".into(),
                "SCMP_ACT_LOG".into(),
                "SCMP_ACT_ERRNO".into(),
                String::new(),
            ],
            last_seen: Some("2026-09-14T06:05:14+02:00".into()),
        });
        assert_eq!(a, b, "same denials, different spelling ⇒ same block");
        assert_eq!(a.actions, ["SCMP_ACT_ERRNO", "SCMP_ACT_LOG"]);

        // A count that cannot exist clamps here rather than reaching the
        // CR, where the field is unsigned and the apiserver would reject
        // it outright.
        assert_eq!(
            denial_block(&BrokerDenials {
                total: -1,
                ..Default::default()
            })
            .observed,
            0
        );
        // A lastSeen that is not a time is dropped rather than mirrored
        // into a status field an operator reads as a time.
        assert_eq!(
            denial_block(&BrokerDenials {
                total: 1,
                last_seen: Some("whenever".into()),
                ..Default::default()
            })
            .last_seen,
            None
        );
    }

    /// A broker outage must not look like an answer. The three
    /// observation conditions keep whatever they last said, and so does
    /// `status.denials`: blanking the block would drop the `Denials`
    /// column back to the blank that means "no data", so every blip would
    /// announce that kguardian had forgotten a count it still has.
    #[test]
    fn a_broker_outage_leaves_the_denials_condition_and_block_alone() {
        let c = cr("prod", "deployment-web", Some("web"));
        let path = "kguardian/prod/deployment-web.json";
        let nodes = [node("a", "h1")];
        let rows = [with_denials(
            summary_row("prod", "web", true, None),
            denials(17, &["ptrace"]),
        )];
        let cond = |s: &SeccompProfileStatus| {
            s.conditions
                .iter()
                .find(|c| c.type_ == COND_DENIALS_OBSERVED)
                .cloned()
                .expect("DenialsObserved is always emitted")
        };

        let first = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &nodes,
            "h1",
            path,
            1,
            Some(&rows),
        );
        assert_eq!(first.denials.as_ref().unwrap().observed, 17);
        assert_eq!(cond(&first).status, "True");

        let during = desired_summary(&c, &first, &nodes, "h1", path, 1, None);
        assert!(
            summary_equal(&first, &during),
            "an outage changes nothing, so nothing is applied"
        );
        assert_eq!(during.denials, first.denials);
        let (was, now) = (cond(&first), cond(&during));
        assert_eq!(
            (now.status, now.reason),
            (was.status.clone(), was.reason.clone())
        );
        assert_eq!(
            now.last_transition_time, was.last_transition_time,
            "carrying a condition forward is not a transition"
        );
    }

    #[test]
    fn merge_conditions_keeps_transition_time_when_status_unchanged() {
        let existing = vec![Condition {
            type_: COND_READY.into(),
            status: "True".into(),
            reason: "AllNodes".into(),
            message: "1/1 nodes".into(),
            last_transition_time: Some("2026-01-01T00:00:00Z".into()),
        }];
        let same = Desired {
            type_: COND_READY,
            status: "True",
            reason: "AllNodes",
            message: "2/2 nodes".into(),
        };
        let out = merge_conditions(&existing, &[same], "2026-09-03T00:00:00Z");
        assert_eq!(
            out[0].last_transition_time.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(out[0].message, "2/2 nodes");

        let flipped = Desired {
            type_: COND_READY,
            status: "False",
            reason: "SomeNodes",
            message: "1/2 nodes".into(),
        };
        let out = merge_conditions(&existing, &[flipped], "2026-09-03T00:00:00Z");
        assert_eq!(
            out[0].last_transition_time.as_deref(),
            Some("2026-09-03T00:00:00Z")
        );
        // A brand-new condition gets `now`.
        let out = merge_conditions(
            &[],
            &[Desired {
                type_: COND_DRIFT,
                status: "Unknown",
                reason: "NoWorkloadRef",
                message: String::new(),
            }],
            "now",
        );
        assert_eq!(out[0].last_transition_time.as_deref(), Some("now"));
    }

    /// The steady state this file is built for: a cluster where nothing
    /// has changed applies nothing.
    ///
    /// The workload here is denying continuously — one Deployment
    /// tripping one syscall under `SCMP_ACT_LOG` — so `observed` climbs
    /// and `lastSeen` advances on every pass. `summary_equal` compares
    /// both, and the `DenialsObserved` message quotes the count, so a
    /// summary that tracks them exactly is a server-side apply per node
    /// per resync for as long as the denials last, each one bumping
    /// `resourceVersion` and fanning a watch event back to every other
    /// node's reflector.
    ///
    /// This test passed `Some(&[])` before — no row for the workload, so
    /// no denials and nothing that could move between passes. It proved
    /// idempotence for the one input that could not break it.
    #[test]
    fn desired_summary_is_idempotent_so_it_is_only_applied_once() {
        let c = cr("prod", "deployment-web", Some("web"));
        let nodes = [node("a", "h1")];
        let path = "kguardian/prod/deployment-web.json";
        // Pass n, half a minute apart, one more denial each time.
        let pass = |n: u64| {
            [with_denials(
                summary_row("prod", "web", true, None),
                BrokerDenials {
                    total: 400 + n as i64,
                    syscalls: vec!["ptrace".into()],
                    actions: vec!["SCMP_ACT_LOG".into()],
                    last_seen: Some(at(30 * n)),
                },
            )]
        };

        let first = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &nodes,
            "h1",
            path,
            1,
            Some(&pass(0)),
        );
        assert_eq!(first.observed_generation, Some(3));
        assert_eq!(first.hash.as_deref(), Some("h1"));
        assert_eq!(first.localhost_profile.as_deref(), Some(path));
        assert_eq!(
            first.distribution.as_ref().unwrap().state,
            DistributionState::Ready
        );
        assert_eq!(first.drift.as_deref(), Some("Unknown"));
        assert_eq!(first.conditions.len(), 4);
        assert_eq!(first.denials.as_ref().unwrap().observed, 400);
        assert!(first.nodes.is_empty(), "summary never carries nodes");
        assert!(!summary_equal(&SeccompProfileStatus::default(), &first));

        // Ten minutes of steady denials. The count and the timestamp
        // move on every one of these passes and not one of them is worth
        // a write.
        let mut status = first.clone();
        for n in 1..=20 {
            let next = desired_summary(&c, &status, &nodes, "h1", path, 1, Some(&pass(n)));
            assert!(
                summary_equal(&status, &next),
                "pass {n} re-applies the CR: {:?} then {:?}",
                status.denials,
                next.denials
            );
            status = next;
        }

        // Broker outage keeps CaptureComplete/Drift exactly as they were.
        let outage = desired_summary(&c, &status, &nodes, "h1", path, 1, None);
        assert!(summary_equal(&status, &outage));

        // A new hash flips Ready and changes the summary.
        let rehashed = desired_summary(&c, &status, &nodes, "h2", path, 1, Some(&pass(21)));
        assert!(!summary_equal(&status, &rehashed));
        assert_eq!(
            rehashed.distribution.as_ref().unwrap().state,
            DistributionState::Pending
        );
        // …and it carries the settled count, not a fresher one. The
        // floor decides when the denial view is refreshed; it does not
        // ride along on whatever else happens to be applied, so the
        // count in the column is always one a pass deliberately chose.
        assert_eq!(rehashed.denials.as_ref().unwrap().observed, 400);
    }

    /// The ratchet is a ratchet, not a mute: a reading that says
    /// something stronger than the one on the CR reaches it at once, and
    /// one that says something weaker waits for the refresh floor and no
    /// longer.
    ///
    /// Both costs are asserted here so they stay decisions rather than
    /// surprises. Between writes the `Denials` column trails the live
    /// count, and a workload that has been cleared stays dirty in the
    /// column for up to `DENIAL_REFRESH_SECS` — late rather than early,
    /// which is the safe direction for the number a profile gets
    /// promoted on. What the status may never do is disagree with
    /// itself: the condition message renders the block that was actually
    /// published, verdicts included, so `kubectl get` and `kubectl
    /// describe` cannot name two different readings.
    #[test]
    fn a_climbing_denial_count_is_republished_only_when_it_says_something_new() {
        let c = cr("prod", "deployment-web", Some("web"));
        let nodes = [node("a", "h1")];
        let path = "kguardian/prod/deployment-web.json";
        let rows = |total: i64, syscalls: &[&str], secs: u64| {
            [with_denials(
                summary_row("prod", "web", true, None),
                BrokerDenials {
                    total,
                    syscalls: syscalls.iter().map(|s| (*s).to_string()).collect(),
                    actions: vec!["SCMP_ACT_LOG".into()],
                    last_seen: Some(at(secs)),
                },
            )]
        };
        let block = |s: &SeccompProfileStatus| s.denials.clone().expect("a block is published");
        let message = |s: &SeccompProfileStatus| {
            s.conditions
                .iter()
                .find(|c| c.type_ == COND_DENIALS_OBSERVED)
                .expect("DenialsObserved is always emitted")
                .message
                .clone()
        };
        let base = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &nodes,
            "h1",
            path,
            1,
            Some(&rows(400, &["ptrace"], 0)),
        );
        let step = |prev: &SeccompProfileStatus, rows: &[BrokerSummary]| {
            desired_summary(&c, prev, &nodes, "h1", path, 1, Some(rows))
        };

        // A denial a second for four minutes: same syscall, same order
        // of magnitude, well inside the floor. Nothing is applied, and
        // the message still names the count that was.
        let quiet = step(&base, &rows(640, &["ptrace"], 240));
        assert!(summary_equal(&base, &quiet));
        assert_eq!(block(&quiet).observed, 400);
        assert!(
            message(&quiet).starts_with("400 seccomp denial(s)"),
            "the message must render the published block: {}",
            message(&quiet)
        );

        // An order of magnitude is news …
        let louder = step(&base, &rows(4_000, &["ptrace"], 240));
        assert!(!summary_equal(&base, &louder));
        assert_eq!(block(&louder).observed, 4_000);

        // … so is a syscall the kernel had not acted on before, at any
        // count …
        let wider = step(&base, &rows(401, &["mount", "ptrace"], 240));
        assert!(!summary_equal(&base, &wider));
        assert_eq!(block(&wider).syscalls, ["mount", "ptrace"]);
        assert_eq!(
            block(&wider).observed,
            401,
            "a write carries the fresh count"
        );

        // … and so is a verdict the kernel had not returned before: the
        // profile has gone from logging to breaking the workload, which
        // is the one thing here an operator is paged for.
        let zero_rows = [with_denials(
            summary_row("prod", "web", true, None),
            BrokerDenials::default(),
        )];
        let harsher = step(
            &base,
            &[with_denials(
                summary_row("prod", "web", true, None),
                BrokerDenials {
                    total: 401,
                    syscalls: vec!["ptrace".into()],
                    actions: vec!["SCMP_ACT_LOG".into(), "SCMP_ACT_ERRNO".into()],
                    last_seen: Some(at(240)),
                },
            )],
        );
        assert!(!summary_equal(&base, &harsher));
        assert_eq!(block(&harsher).actions, ["SCMP_ACT_ERRNO", "SCMP_ACT_LOG"]);
        assert!(
            message(&harsher).contains("(SCMP_ACT_ERRNO, SCMP_ACT_LOG)"),
            "the verdicts in the message come from the published block: {}",
            message(&harsher)
        );

        // What is never news is a reading that says *less* than the one
        // on the CR, however fresh it is. That is the half of this that
        // stops two nodes overwriting each other: a retention prune, a
        // finished burst and a count back to zero all wait.
        let pruned = step(&base, &rows(40, &["ptrace"], 600));
        assert!(summary_equal(&base, &pruned));
        assert_eq!(block(&pruned).observed, 400);
        assert!(summary_equal(&base, &step(&base, &zero_rows)));

        // They wait for the refresh floor, and no longer. Once the
        // published reading is a quarter of an hour old the next node to
        // reconcile replaces it with its own, weaker or not — the only
        // way a cleared workload ever reaches `observed: 0` and
        // `False`/`NoDenials`.
        let stale = backdate(&base, DENIAL_REFRESH_SECS + 1);
        let cleared = step(&stale, &zero_rows);
        assert!(!summary_equal(&stale, &cleared));
        assert_eq!(block(&cleared).observed, 0);
        assert_eq!(message(&cleared), "no denials in the retention window");
        // …and the replacement is stamped, so the floor starts again
        // instead of every remaining node piling in behind the first.
        assert!(block(&cleared).refreshed_at.is_some());
        assert!(summary_equal(&cleared, &step(&cleared, &zero_rows)));

        // The broker going quiet about denials altogether is not a
        // reading at all, so neither half applies — the block goes away
        // with the condition, floor or no floor.
        let silent = step(&base, &[summary_row("prod", "web", true, None)]);
        assert!(!summary_equal(&base, &silent));
        assert!(silent.denials.is_none());
    }

    /// The bug the ratchet exists for, and the one a refresh floor on its
    /// own does not fix.
    ///
    /// Sixty nodes each poll the broker on their own schedule and each
    /// compare the CR against their own poll, so at any moment two of
    /// them hold readings taken seconds apart that straddle a threshold.
    /// A symmetric "has this moved enough to republish" test then has
    /// both of them find the other's published value worth overwriting,
    /// and they alternate for as long as both keep reconciling — a write
    /// per node per watch event, forever, on a cluster where nothing is
    /// actually changing. Rate-limiting makes that slower, not finite.
    ///
    /// Two nodes, two snapshots taken moments apart, alternating passes.
    /// The sequence has to stop writing; and it has to stop on the same
    /// block whichever node reconciles first, because the published
    /// value is decided by the readings and not by who got there first.
    #[test]
    fn two_nodes_with_different_snapshots_converge_instead_of_alternating() {
        let c = cr("prod", "deployment-web", Some("web"));
        let nodes = [node("a", "h1"), node("b", "h1")];
        let path = "kguardian/prod/deployment-web.json";

        // Node A polled just before the count crossed a thousand and
        // just before the kernel first denied `mount`; node B polled
        // just after. Nothing else about the cluster differs, and
        // neither reading is wrong.
        let a = [with_denials(
            summary_row("prod", "web", true, None),
            BrokerDenials {
                total: 900,
                syscalls: vec!["ptrace".into()],
                actions: vec!["SCMP_ACT_LOG".into()],
                last_seen: Some(at(0)),
            },
        )];
        let b = [with_denials(
            summary_row("prod", "web", true, None),
            BrokerDenials {
                total: 1_200,
                syscalls: vec!["mount".into(), "ptrace".into()],
                actions: vec!["SCMP_ACT_ERRNO".into(), "SCMP_ACT_LOG".into()],
                last_seen: Some(at(4_000)),
            },
        )];

        // Alternate the two over the shared CR and count the applies.
        // Twenty passes is ten minutes of resyncs, well inside the
        // refresh floor, so every write in here is the ratchet's doing.
        let run = |first: &[BrokerSummary], second: &[BrokerSummary]| {
            let mut status = SeccompProfileStatus::default();
            let mut writes = 0usize;
            for pass in 0..20 {
                let rows = if pass % 2 == 0 { first } else { second };
                let next = desired_summary(&c, &status, &nodes, "h1", path, 2, Some(rows));
                if !summary_equal(&status, &next) {
                    writes += 1;
                    status = next;
                }
            }
            (writes, status)
        };
        let (a_first_writes, a_first) = run(&a, &b);
        let (b_first_writes, b_first) = run(&b, &a);

        for (writes, who) in [
            (a_first_writes, "node a first"),
            (b_first_writes, "node b first"),
        ] {
            assert!(
                writes <= 2,
                "{who}: the fleet is still applying after it should have settled \
                 — {writes} applies in 20 passes"
            );
        }

        // The stamp is wall-clock, so compare the reading itself.
        let reading = |s: &SeccompProfileStatus| {
            s.denials.clone().map(|mut d| {
                d.refreshed_at = None;
                d
            })
        };
        assert_eq!(
            reading(&a_first),
            reading(&b_first),
            "the published reading must be a function of the readings, not of \
             which node reconciled first"
        );

        // And it settles on B's: broader, and the kernel is returning
        // errors rather than only logging.
        let settled = a_first.denials.as_ref().expect("a block is published");
        assert_eq!(settled.observed, 1_200);
        assert_eq!(settled.syscalls, ["mount", "ptrace"]);
        assert_eq!(settled.actions, ["SCMP_ACT_ERRNO", "SCMP_ACT_LOG"]);
    }

    /// The two halves of `settled_denials`, isolated from the wall clock
    /// and from everything `desired_summary` wraps around them.
    #[test]
    fn the_denial_ratchet_only_climbs_and_the_refresh_floor_releases_it() {
        let block = |observed: u64, syscalls: &[&str], actions: &[&str]| DenialSummary {
            observed,
            syscalls: syscalls.iter().map(|x| (*x).to_string()).collect(),
            actions: actions.iter().map(|x| (*x).to_string()).collect(),
            last_seen: Some(at(0)),
            refreshed_at: Some(at(0)),
        };
        let quiet = block(900, &["ptrace"], &["SCMP_ACT_LOG"]);
        let loud = block(
            1_200,
            &["mount", "ptrace"],
            &["SCMP_ACT_ERRNO", "SCMP_ACT_LOG"],
        );
        let inside = at(60);
        let past = at(DENIAL_REFRESH_SECS as u64 + 1);

        // Inside the floor the ratchet only climbs. The louder reading
        // replaces the quieter one; the quieter one never replaces the
        // louder. That asymmetry is the fix — two nodes holding these
        // two readings cannot both want to overwrite the other, so there
        // is no sequence of passes in which they alternate.
        assert_eq!(
            settled_denials(Some(&quiet), loud.clone(), &inside).observed,
            1_200
        );
        assert_eq!(
            settled_denials(Some(&loud), quiet.clone(), &inside),
            loud,
            "a node holding a weaker reading must defer, stamp and all"
        );
        assert_eq!(
            settled_denials(Some(&loud), DenialSummary::default(), &inside),
            loud,
            "including when the weaker reading is a real zero"
        );

        // A reading that wins is stamped with when it was taken, so the
        // floor measures the age of the reading rather than the time
        // since anything last changed.
        assert_eq!(
            settled_denials(Some(&quiet), loud.clone(), &inside).refreshed_at,
            Some(inside.clone())
        );

        // Past the floor the next node to reconcile replaces the block
        // outright, however much quieter its reading is. Without this
        // the ratchet would never come down and a cleared workload would
        // read as denied for the life of the CR.
        let rolled = settled_denials(Some(&loud), DenialSummary::default(), &past);
        assert_eq!(rolled.observed, 0);
        assert_eq!(rolled.refreshed_at, Some(past.clone()));
        assert_eq!(
            settled_denials(Some(&rolled), DenialSummary::default(), &past),
            rolled,
            "the replacement resets the floor, so the rest of the fleet stays quiet"
        );

        // A block from before `refreshedAt` existed, or one an operator
        // edited: due at once, which stamps it and puts it back under
        // the floor rather than leaving it stuck outside forever.
        let unstamped = DenialSummary {
            refreshed_at: None,
            ..loud.clone()
        };
        assert_eq!(
            settled_denials(Some(&unstamped), quiet.clone(), &inside).observed,
            900
        );

        // A clock that runs ahead delays the fleet's next refresh; it
        // must not make every node think the stamp is overdue, which
        // would be the alternation again with the clock as the disagreeing
        // input.
        let future = DenialSummary {
            refreshed_at: Some(at(7_200)),
            ..loud.clone()
        };
        assert_eq!(
            settled_denials(Some(&future), DenialSummary::default(), &inside),
            future
        );
    }

    /// The zero bucket in `count_magnitude`, on the one input where it
    /// is the only thing that can decide.
    ///
    /// It is easy to believe this bucket is what makes a first denial
    /// reach a CR that reads `observed: 0`, and to test it with an input
    /// where a syscall name arrives alongside the count — in which case
    /// `denial_rank`'s breadth term has already decided and collapsing
    /// 0 into 1-9 changes nothing. The count is only reached when both
    /// breadth terms tie, so the reading has to carry no names on either
    /// side of the transition. The broker produces exactly that when the
    /// names it holds are empty: `sorted_unique` drops them, which is
    /// what a denial on a syscall number its table cannot resolve, or a
    /// row from a broker predating the `actions` field, looks like by
    /// the time it reaches `denial_block`.
    ///
    /// Sabotage to confirm this goes red: `count_magnitude`'s
    /// `map_or(0, |n| n + 1)` becomes `unwrap_or(0)`, which merges 0 and
    /// 1-9 into one bucket and leaves every other bucket distinct.
    #[test]
    fn a_first_denial_escapes_a_cleared_block_on_the_zero_bucket_alone() {
        // The buckets themselves. 0 and 1 must not share one: a CR at
        // `observed: 0` reads as clear to promote.
        assert_eq!(count_magnitude(0), 0);
        assert_eq!(count_magnitude(1), 1);
        assert_eq!(count_magnitude(9), 1);
        assert_eq!(count_magnitude(10), 2);
        assert_eq!(count_magnitude(u64::MAX), 20);
        assert!(
            count_magnitude(0) < count_magnitude(1),
            "\"cleared\" and \"denied once\" are opposite answers, not one bucket"
        );

        // And the decision that rests on it. Syscalls, verdicts and
        // `lastSeen` are identical across the transition, so the count
        // is the only clause left that can fire, and the floor is
        // nowhere near — a stale `0` here is the one direction that
        // matters, because it is the reading an operator promotes on.
        let inside = at(60);
        let cleared = DenialSummary {
            observed: 0,
            syscalls: Vec::new(),
            actions: Vec::new(),
            last_seen: None,
            refreshed_at: Some(at(0)),
        };
        let denied = DenialSummary {
            observed: 4,
            ..cleared.clone()
        };
        assert_eq!(
            settled_denials(Some(&cleared), denied.clone(), &inside).observed,
            4,
            "a workload that has started denying must not keep reading `0` \
             until the refresh floor"
        );
        // The other direction stays deferred, as everything weaker does:
        // a count falling back is not news, it waits for the floor.
        assert_eq!(
            settled_denials(Some(&denied), cleared, &inside),
            denied,
            "the ratchet still only climbs"
        );
    }

    /// The transition a promotion gate exists for: a profile promoted
    /// from logging to killing, inside the refresh floor and inside one
    /// magnitude bucket. An operator must not be left reading
    /// `SCMP_ACT_LOG` while the kernel is killing the workload.
    ///
    /// This is why the verdicts live on the published block. Before that
    /// they were rendered into the condition message straight from the
    /// broker row, which forced an apply — and had every node whose poll
    /// showed a different verdict set fight over the summary on every
    /// pass. On the block they are ranked instead, and the ranking has
    /// to carry the same guarantee.
    #[test]
    fn a_profile_that_starts_killing_republishes_inside_the_floor() {
        let inside = at(60);
        let logging = DenialSummary {
            observed: 400,
            syscalls: vec!["ptrace".into()],
            actions: vec!["SCMP_ACT_LOG".into()],
            last_seen: Some(at(0)),
            refreshed_at: Some(at(0)),
        };
        // The broker's window holds both verdicts for as long as the
        // pre-promotion rows live, so the reading is two verdicts wide
        // against a published one verdict wide and outranks it at once.
        let killing = DenialSummary {
            observed: 402,
            actions: vec!["SCMP_ACT_KILL_PROCESS".into(), "SCMP_ACT_LOG".into()],
            ..logging.clone()
        };
        assert_eq!(
            settled_denials(Some(&logging), killing.clone(), &inside).actions,
            ["SCMP_ACT_KILL_PROCESS", "SCMP_ACT_LOG"],
            "the kernel killing the workload cannot wait for the refresh floor"
        );

        // Once retention has rolled the logging rows out the reading
        // narrows again, and a narrower reading waits for the floor.
        // That costs nothing: the block it waits behind already names
        // SCMP_ACT_KILL_PROCESS. The window is days and the floor is
        // fifteen minutes, so there is no order of events in which the
        // narrowing happens before the widening was published.
        let killing_only = DenialSummary {
            actions: vec!["SCMP_ACT_KILL_PROCESS".into()],
            ..killing.clone()
        };
        assert_eq!(
            settled_denials(Some(&killing), killing_only, &inside),
            killing
        );
    }

    #[test]
    fn ssa_payloads_have_the_expected_shape() {
        let p = node_entry_patch("prod", "deployment-web", &node("node-a", "h1"));
        assert_eq!(p["apiVersion"], "kguardian.dev/v1alpha1");
        assert_eq!(p["kind"], "SeccompProfile");
        assert_eq!(p["metadata"]["name"], "deployment-web");
        assert_eq!(p["metadata"]["namespace"], "prod");
        assert_eq!(p["status"]["nodes"][0]["name"], "node-a");
        assert_eq!(p["status"]["nodes"][0]["hash"], "h1");
        assert_eq!(
            p["status"]["nodes"][0]["lastWritten"],
            "2026-09-03T00:00:00Z"
        );
        // Only nodes — the summary fields belong to the other manager.
        assert_eq!(p["status"].as_object().unwrap().len(), 1);

        let c = cr("prod", "deployment-web", None);
        let s = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &[],
            "h1",
            "kguardian/prod/deployment-web.json",
            2,
            None,
        );
        let p = summary_patch("prod", "deployment-web", &s);
        assert_eq!(p["status"]["hash"], "h1");
        assert_eq!(p["status"]["observedGeneration"], 3);
        assert_eq!(
            p["status"]["localhostProfile"],
            "kguardian/prod/deployment-web.json"
        );
        assert_eq!(p["status"]["distribution"]["state"], "Pending");
        assert_eq!(p["status"]["distribution"]["summary"], "0/2");
        assert_eq!(p["status"]["drift"], "Unknown");
        assert!(
            p["status"].get("nodes").is_none(),
            "summary must not own nodes"
        );
        let types: Vec<&str> = p["status"]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            ["Ready", "CaptureComplete", "Drift", "DenialsObserved"]
        );
        assert_eq!(p["status"]["conditions"][1]["reason"], "NoWorkloadRef");
        assert_eq!(p["status"]["conditions"][3]["reason"], "NoWorkloadRef");
        assert!(
            p["status"]["denials"].is_null(),
            "no workloadRef means no workload to attribute denials to"
        );

        // Field managers.
        assert_eq!(node_manager("node-a"), "kguardian-controller/node-a");
        assert!(node_manager(&"x".repeat(300)).len() <= MANAGER_MAX_LEN);
    }

    #[test]
    fn mirror_body_carries_spec_hash_and_distribution() {
        let c = cr("prod", "deployment-web", Some("web"));
        let d = compute_distribution(&[node("a", "h1")], "h1", 1);
        let b = mirror_body(&c.spec, "h1", Some(&d));
        assert_eq!(b["hash"], "h1");
        assert_eq!(b["status"]["distribution"]["ready"], 1);
        assert_eq!(b["status"]["distribution"]["state"], "Ready");
        assert!(
            b.get("distribution").is_none(),
            "distribution lives under status"
        );

        let ns = node_status_body(
            "node-a",
            &[(
                "kguardian/prod/deployment-web.json".to_string(),
                "h1".to_string(),
            )],
        );
        assert_eq!(ns["node_name"], "node-a");
        assert_eq!(ns["files"][0]["path"], "kguardian/prod/deployment-web.json");
        assert_eq!(ns["files"][0]["hash"], "h1");
        assert_eq!(ns["paths"][0], "kguardian/prod/deployment-web.json");
        assert_eq!(b["spec"]["defaultAction"], "SCMP_ACT_LOG");
        assert_eq!(b["spec"]["workloadRef"]["kind"], "Deployment");
        assert_eq!(b["spec"]["workloadRef"]["name"], "web");
        assert_eq!(b["spec"]["syscalls"][0]["names"][0], "read");
        assert_eq!(b["spec"]["architectures"][0], "SCMP_ARCH_X86_64");
    }

    #[test]
    fn broker_summary_parses_leniently() {
        let json = r#"[{"namespace":"prod","kind":"Deployment","name":"web","hash":"x",
            "syscallCount":3,"capture":{"level":"full","complete":true,"pods":[{"name":"w","level":"full"}],"more":0},
            "cr":{"name":"deployment-web","defaultAction":"SCMP_ACT_LOG","hash":"y","syscallCount":2,
                  "distribution":{"ready":1,"total":1,"state":"Ready"},
                  "drift":{"missing":["a"],"extra":[],"inSync":false}},
            "denials":{"total":17,"syscalls":["ptrace"],"actions":["SCMP_ACT_LOG"],
                       "lastSeen":"2026-09-14T04:05:14Z","perNode":{"n1":17}},
            "captureComplete":true,"recommendedSnippet":{}},
            {"namespace":"prod","kind":"Deployment","name":"api","cr":null,"denials":null}]"#;
        let v: Vec<BrokerSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(
            v[0].cr.as_ref().unwrap().drift.as_ref().unwrap().missing,
            ["a"]
        );
        let d = v[0].denials.as_ref().unwrap();
        assert_eq!(d.total, 17);
        assert_eq!(d.syscalls, ["ptrace"]);
        assert_eq!(d.actions, ["SCMP_ACT_LOG"]);
        assert_eq!(d.last_seen.as_deref(), Some("2026-09-14T04:05:14Z"));
        assert!(v[1].cr.is_none());
        assert!(v[1].capture.is_none());
        assert!(
            v[1].denials.is_none(),
            "an explicit null is as absent as a missing key"
        );

        // An older broker sends no `denials` key at all. That must parse,
        // and must not become a zero: the whole list failing here would
        // also take CaptureComplete and Drift down for every CR.
        let old = r#"[{"namespace":"prod","kind":"Deployment","name":"web"}]"#;
        let v: Vec<BrokerSummary> = serde_json::from_str(old).unwrap();
        assert!(v[0].denials.is_none());
    }

    /// The body of `GET /seccomp/profiles/{ns}/{kind}/{name}` is a list
    /// row plus a rendered `profile`. It must parse into the same
    /// `BrokerSummary` the row does, with the extra field falling away,
    /// or moving from the list to per-workload reads would blind every
    /// condition at once.
    #[test]
    fn a_per_workload_body_reads_as_the_row_it_contains() {
        let body = br#"{"namespace":"prod","kind":"Deployment","name":"web","hash":"x",
            "syscallCount":3,"architectures":["SCMP_ARCH_X86_64"],
            "capture":{"level":"full","complete":true,"pods":[{"name":"w","level":"full"}],"more":0},
            "captureComplete":true,"suggestedName":"deployment-web","crCount":1,
            "cr":{"name":"deployment-web","drift":{"missing":[],"extra":[],"inSync":true}},
            "denials":{"total":0,"syscalls":[],"actions":[],"lastSeen":null},
            "recommendedSnippet":{},
            "profile":{"defaultAction":"SCMP_ACT_LOG","architectures":["SCMP_ARCH_X86_64"],
                       "syscalls":[{"names":["read","write"],"action":"SCMP_ACT_ALLOW"}]}}"#;
        let reading = BrokerReading::from_response(&key("prod", "web"), Ok(Some(body.to_vec())));
        let BrokerReading::Observed(row) = &reading else {
            panic!("a 200 with a row is an observation, got {reading:?}");
        };
        assert_eq!(
            (row.namespace.as_str(), row.kind.as_str(), row.name.as_str()),
            ("prod", "Deployment", "web")
        );

        let o = observation_conditions(
            "prod",
            "deployment-web",
            Some(&web_ref()),
            reading.summaries(),
            None,
            NOW,
        )
        .expect("a row decides the conditions");
        assert_eq!((o.capture.status, o.capture.reason), ("True", "Full"));
        assert_eq!((o.drift.status, o.drift.reason), ("False", "InSync"));
        assert_eq!((o.denials.status, o.denials.reason), ("False", "NoDenials"));
    }

    /// A 404 is the broker saying it has never observed the workload.
    /// That is exactly what a row missing from the cluster-wide list
    /// meant, and it must land on the same conditions — `Unknown` /
    /// `NoObservations` on all three — rather than be carried forward as
    /// if the broker were down, which would freeze a CR's conditions for
    /// as long as its workload stays unobserved.
    #[test]
    fn an_unknown_workload_is_no_observations_not_an_outage() {
        let reading = BrokerReading::from_response(&key("prod", "web"), Ok(None));
        assert_eq!(reading, BrokerReading::Unobserved);

        let wr = web_ref();
        let from_404 = observation_conditions(
            "prod",
            "deployment-web",
            Some(&wr),
            reading.summaries(),
            None,
            NOW,
        )
        .expect("a 404 decides the conditions");
        let from_absent_row = observation_conditions(
            "prod",
            "deployment-web",
            Some(&wr),
            Some(&[summary_row("prod", "api", true, None)]),
            None,
            NOW,
        )
        .expect("an absent row decides the conditions");
        assert_eq!(from_404, from_absent_row);
        for c in [&from_404.capture, &from_404.drift, &from_404.denials] {
            assert_eq!((c.status, c.reason), ("Unknown", "NoObservations"));
        }
        assert!(from_404.denial_summary.is_none());
    }

    /// Anything else — the broker down, a 5xx, a body this controller
    /// cannot read — is the broker not answering, and the three
    /// observation conditions and `status.denials` are carried forward
    /// untouched, as an outage of the cluster list always was.
    #[test]
    fn a_failed_or_unreadable_read_leaves_the_conditions_alone() {
        let k = key("prod", "web");
        let down = BrokerReading::from_response(&k, Err(Error::ApiError("refused".into())));
        let garbage =
            BrokerReading::from_response(&k, Ok(Some(b"<html>bad gateway</html>".to_vec())));
        assert_eq!(down, BrokerReading::Unavailable);
        assert_eq!(garbage, BrokerReading::Unavailable);
        assert!(down.summaries().is_none());

        let c = cr("prod", "deployment-web", Some("web"));
        let path = "kguardian/prod/deployment-web.json";
        let nodes = [node("a", "h1")];
        let rows = [with_denials(
            summary_row("prod", "web", true, None),
            denials(17, &["ptrace"]),
        )];
        let first = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &nodes,
            "h1",
            path,
            1,
            Some(&rows),
        );
        let during = desired_summary(&c, &first, &nodes, "h1", path, 1, down.summaries());
        assert!(
            summary_equal(&first, &during),
            "an outage changes nothing, so nothing is applied"
        );
        assert_eq!(during.denials.as_ref().map(|d| d.observed), Some(17));
    }

    /// One read per distinct workload per pass. Several CRs naming the
    /// same workload, and the watch replaying a CR after another node's
    /// status write, all land on the cached reading — and a 404 or a
    /// failure is cached too, so neither is retried for the next CR.
    #[tokio::test]
    async fn a_pass_asks_the_broker_once_per_workload() {
        let asked = std::cell::RefCell::new(Vec::<WorkloadKey>::new());
        let record = |k: WorkloadKey, answer: Result<Option<Vec<u8>>, Error>| {
            asked.borrow_mut().push(k);
            async move { answer }
        };
        let body = serde_json::to_vec(&json!({
            "namespace": "prod", "kind": "Deployment", "name": "web",
            "capture": {"level": "full", "complete": true, "pods": []},
            "profile": {}
        }))
        .unwrap();
        let (web, api, db) = (key("prod", "web"), key("prod", "api"), key("prod", "db"));
        let mut readings = BrokerReadings::default();

        // Two CRs name `web`: one read, and both see the row.
        let first = readings
            .get_or_fetch(web.clone(), |k| record(k, Ok(Some(body.clone()))))
            .await
            .clone();
        let again = readings
            .get_or_fetch(web.clone(), |k| {
                record(k, Err(Error::ApiError("must not be asked".into())))
            })
            .await
            .clone();
        assert!(matches!(first, BrokerReading::Observed(_)), "{first:?}");
        assert_eq!(again, first, "the second CR reuses the first CR's reading");
        assert_eq!(asked.borrow().as_slice(), std::slice::from_ref(&web));

        // A 404 is kept: the next CR naming `api` does not ask again.
        let r = readings
            .get_or_fetch(api.clone(), |k| record(k, Ok(None)))
            .await
            .clone();
        assert_eq!(r, BrokerReading::Unobserved);
        let r = readings
            .get_or_fetch(api.clone(), |k| record(k, Ok(Some(body.clone()))))
            .await
            .clone();
        assert_eq!(r, BrokerReading::Unobserved);
        assert_eq!(asked.borrow().as_slice(), [web.clone(), api.clone()]);

        // So is a failure (which also latches the pass; next test).
        let r = readings
            .get_or_fetch(db.clone(), |k| {
                record(k, Err(Error::ApiError("down".into())))
            })
            .await
            .clone();
        assert_eq!(r, BrokerReading::Unavailable);
        let r = readings
            .get_or_fetch(db.clone(), |k| record(k, Ok(None)))
            .await
            .clone();
        assert_eq!(r, BrokerReading::Unavailable);
        assert_eq!(asked.borrow().len(), 3);
        assert_eq!(readings.len(), 3);

        // A refresh starts the pass over, and the next CR asks again.
        let mut readings = BrokerReadings::default();
        readings
            .get_or_fetch(web.clone(), |k| record(k, Ok(None)))
            .await;
        assert_eq!(asked.borrow().len(), 4);
    }

    /// The latch. Against a broker that accepts and never answers, every
    /// fetch costs a full request timeout and fetches run one after
    /// another inside the pass — so after the first failure the rest of
    /// the pass's workloads answer `Unavailable` without a request: the
    /// outcome a failed fetch gives them anyway, at one timeout per pass
    /// instead of one per workload. An answer of any kind does not latch,
    /// and a fresh pass asks again.
    #[tokio::test]
    async fn one_failure_stops_a_pass_asking_the_broker_again() {
        let asked = std::cell::RefCell::new(Vec::<WorkloadKey>::new());
        let record = |k: WorkloadKey, answer: Result<Option<Vec<u8>>, Error>| {
            asked.borrow_mut().push(k);
            async move { answer }
        };
        let keys: Vec<WorkloadKey> = (0..20).map(|i| key("prod", &format!("w{i}"))).collect();

        let mut readings = BrokerReadings::default();
        for k in &keys {
            let r = readings
                .get_or_fetch(k.clone(), |k| {
                    record(k, Err(Error::ApiError("timed out".into())))
                })
                .await
                .clone();
            assert_eq!(r, BrokerReading::Unavailable);
        }
        assert_eq!(
            asked.borrow().as_slice(),
            std::slice::from_ref(&keys[0]),
            "one attempt, then the latch"
        );
        assert_eq!(readings.len(), 1);

        // A 404, a row, or a body that does not parse is the broker
        // answering: no latch, the next workload is asked.
        let mut readings = BrokerReadings::default();
        readings
            .get_or_fetch(keys[0].clone(), |k| record(k, Ok(None)))
            .await;
        readings
            .get_or_fetch(keys[1].clone(), |k| {
                record(k, Ok(Some(b"not json".to_vec())))
            })
            .await;
        readings
            .get_or_fetch(keys[2].clone(), |k| record(k, Ok(None)))
            .await;
        assert_eq!(asked.borrow().len(), 4);

        // A new pass starts clean.
        let mut readings = BrokerReadings::default();
        readings
            .get_or_fetch(keys[0].clone(), |k| {
                record(k, Err(Error::ApiError("still down".into())))
            })
            .await;
        assert_eq!(asked.borrow().len(), 5);
    }

    /// `workloadRef.name` is a bare string in the CRD. A name with a `/`
    /// or `?` in it must reach the broker as one escaped path segment,
    /// not as a different route or a query string; a plain name passes
    /// through untouched.
    #[test]
    fn a_workload_path_escapes_anything_that_is_not_a_plain_segment() {
        assert_eq!(
            workload_path(&key("prod", "web-api.v2_x")),
            "seccomp/profiles/prod/Deployment/web-api.v2_x"
        );
        assert_eq!(
            workload_path(&(
                "prod".into(),
                "Deployment".into(),
                "web/../admin?x=1&y".into()
            )),
            "seccomp/profiles/prod/Deployment/web%2F..%2Fadmin%3Fx%3D1%26y"
        );
    }

    /// The pass every node runs every resync on a fleet with distribution
    /// enabled and no CRs. It used to list the nodes and pull the
    /// cluster-wide profile list each time — the list the broker OOMKilled
    /// on — for CRs that did not exist. Now it takes no cluster inputs at
    /// all: `cluster` stays `None`, which it could not if the node list
    /// had run, because even a failed list records a count.
    #[tokio::test]
    async fn an_empty_store_takes_no_cluster_inputs() {
        let root = test_root("empty-store");
        let (mut rec, _writer) = offline_reconciler(root.clone(), |_| {
            Box::pin(async { panic!("an empty store asks the broker for nothing") })
        })
        .await;
        rec.full_pass().await;
        assert!(
            rec.cluster.is_none(),
            "an empty store must not list nodes or read the broker"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The CRs behind the next two tests: two naming `web`, one naming
    /// `api`, one naming nothing.
    fn four_crs(writer: &mut reflector::store::Writer<SeccompProfile>) {
        for c in [
            cr("prod", "deployment-web", Some("web")),
            cr("prod", "deployment-web-canary", Some("web")),
            cr("prod", "deployment-api", Some("api")),
            cr("prod", "unbound", None),
        ] {
            writer.apply_watcher_event(&watcher::Event::Apply(c));
        }
    }

    /// With CRs in the store the pass takes its inputs per CR: the node
    /// count once, and one broker read per distinct workload — two CRs
    /// naming `web` share one, and a CR without a `workloadRef` asks for
    /// nothing. The broker here answers 404 to everything, so each
    /// reading is `Unobserved` and none of them latches.
    #[tokio::test]
    async fn a_pass_reads_one_workload_per_distinct_workload_ref() {
        let root = test_root("per-cr");
        let (mut rec, mut writer) =
            offline_reconciler(root.clone(), |_| Box::pin(async { Ok(None) })).await;
        four_crs(&mut writer);
        rec.full_pass().await;
        let cluster = rec
            .cluster
            .as_ref()
            .expect("a store with CRs takes cluster inputs");
        let asked: Vec<(&WorkloadKey, &BrokerReading)> =
            cluster.readings.by_workload.iter().collect();
        assert_eq!(
            asked,
            [
                (&key("prod", "api"), &BrokerReading::Unobserved),
                (&key("prod", "web"), &BrokerReading::Unobserved),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The same store against a broker that fails every read: the pass
    /// sends one request, the latch answers the rest, and the pass still
    /// completes with every CR reconciled as far as the API server allows.
    #[tokio::test]
    async fn a_failing_broker_costs_a_pass_one_request() {
        let root = test_root("latched");
        let (mut rec, mut writer) = offline_reconciler(root.clone(), |_| {
            Box::pin(async { Err(Error::ApiError("timed out".into())) })
        })
        .await;
        four_crs(&mut writer);
        rec.full_pass().await;
        let cluster = rec
            .cluster
            .as_ref()
            .expect("a store with CRs takes cluster inputs");
        assert_eq!(cluster.readings.len(), 1, "{:?}", cluster.readings);
        assert!(cluster.readings.broker_down);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delete_removes_the_file_and_tolerates_absence() {
        let dir = std::env::temp_dir().join(format!("kg-seccomp-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dest = dir.join("kguardian/prod/deployment-web.json");
        write_atomic(&dest, b"{}").unwrap();
        assert!(dest.exists());
        assert!(delete_profile_file(&dest).unwrap());
        assert!(!dest.exists());
        // Second delete (another node raced us, or the CR was deleted
        // while we were down): not an error.
        assert!(!delete_profile_file(&dest).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn safe_relative_path_accepts_a_normal_profile_path() {
        let p = safe_relative_path("kguardian/prod/deployment-web.json").unwrap();
        assert_eq!(p, PathBuf::from("kguardian/prod/deployment-web.json"));
        assert_eq!(
            safe_relative_path(&localhost_profile_path("prod", "deployment-web")).unwrap(),
            PathBuf::from("kguardian/prod/deployment-web.json")
        );
    }

    #[test]
    fn safe_relative_path_rejects_traversal_and_absolute() {
        for bad in [
            "",
            "   ",
            "/etc/passwd",
            "../../../etc/passwd",
            "kguardian/../../../etc/cron.d/x",
            "./kguardian/x.json",
            "kguardian/../x.json",
            "kguardian/prod/../../../../etc/shadow",
        ] {
            assert!(
                safe_relative_path(bad).is_none(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn safe_relative_path_normalises_a_harmless_dot_component() {
        assert_eq!(
            safe_relative_path("kguardian/./prod/x.json").unwrap(),
            PathBuf::from("kguardian/prod/x.json")
        );
    }

    #[test]
    fn write_atomic_creates_parents_and_file() {
        let dir = std::env::temp_dir().join(format!("kg-seccomp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dest = dir.join("kguardian/prod/deployment-web.json");
        write_atomic(&dest, br#"{"defaultAction":"SCMP_ACT_LOG"}"#).unwrap();
        let got = std::fs::read(&dest).unwrap();
        assert_eq!(got, br#"{"defaultAction":"SCMP_ACT_LOG"}"#);
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file not cleaned up");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_atomic_overwrites_existing() {
        let dir = std::env::temp_dir().join(format!("kg-seccomp-test-ow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dest = dir.join("x.json");
        write_atomic(&dest, b"one").unwrap();
        write_atomic(&dest, b"two").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"two");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
