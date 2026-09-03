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
//! Per CR, every pass:
//!  1. render the file from spec, write it atomically only when the bytes
//!     on disk differ;
//!  2. server-side-apply this node's `status.nodes[name=<node>]` entry
//!     (field manager `kguardian-controller/<node>`);
//!  3. compute the summary (`distribution`, `Ready`, and — from the
//!     broker's observations — `CaptureComplete` and `Drift`) and apply it
//!     under the shared manager `kguardian-summary`; every node writes the
//!     same value, so it converges. Both applies are skipped when nothing
//!     changed;
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
    fingerprint, localhost_profile_path, render_profile, Condition, Distribution,
    DistributionState, NodeStatus, SeccompProfile, SeccompProfileSpec, SeccompProfileStatus,
    WorkloadRef,
};
use crate::Error;
use chrono::{SecondsFormat, Utc};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Node;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{watcher, WatchStreamExt};
use kube::{Api, Client, ResourceExt};
use serde::Deserialize;
use serde_json::json;
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
                // does end we must NOT return: try_join! would never
                // notice, and CR reconciliation would be silently dead
                // until the pod restarted for some other reason. And we
                // must not Err either — a distributor failure never
                // interrupts tracing. So: back off, rebuild the reflector
                // + watcher, carry on. The ticker keeps firing meanwhile
                // (against the last known store contents).
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
/// (the `total` in `distribution`) and what the broker has observed
/// (for `CaptureComplete` / `Drift`). `summaries` is `None` when the
/// broker could not be reached, in which case those two conditions are
/// left as they are rather than flapping to `Unknown`.
struct ClusterData {
    total_nodes: u32,
    summaries: Option<Vec<BrokerSummary>>,
}

struct Reconciler {
    cfg: Config,
    client: Client,
    store: Store<SeccompProfile>,
    cluster: Option<ClusterData>,
}

/// One row of the broker's `GET /seccomp/profiles`. Only what the
/// conditions need; everything is lenient so an older or newer broker
/// still parses.
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
    async fn refresh_cluster(&mut self) {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let total_nodes = match nodes.list_metadata(&ListParams::default()).await {
            Ok(list) => list.items.len() as u32,
            Err(e) => {
                warn!("cannot list nodes for seccomp distribution totals: {e}");
                self.cluster.as_ref().map(|c| c.total_nodes).unwrap_or(0)
            }
        };
        let summaries = match api_get_bytes("seccomp/profiles").await {
            Ok(body) => match serde_json::from_slice::<Vec<BrokerSummary>>(&body) {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!("parsing /seccomp/profiles: {e}");
                    None
                }
            },
            Err(e) => {
                debug!("broker /seccomp/profiles unavailable (conditions kept as-is): {e}");
                None
            }
        };
        self.cluster = Some(ClusterData {
            total_nodes,
            summaries,
        });
    }

    /// Resync: refresh cluster inputs, reconcile every CR in the
    /// reflector store, then report this node's files to the broker.
    async fn full_pass(&mut self) {
        self.refresh_cluster().await;
        let crs = self.store.state();
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
            "seccomp profile distribution pass"
        );
        self.report_node_status(&present).await;
    }

    /// Bring one CR's file, status and broker mirror up to date. Returns
    /// the `(localhostProfile, hash)` now on disk.
    async fn reconcile_cr(&self, cr: &SeccompProfile) -> Result<Option<(String, String)>, Error> {
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

        // 3. The summary (only when it changed).
        let total = self.cluster.as_ref().map(|c| c.total_nodes).unwrap_or(0);
        let summaries = self.cluster.as_ref().and_then(|c| c.summaries.as_deref());
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
    json!({
        "apiVersion": "kguardian.dev/v1alpha1",
        "kind": "SeccompProfile",
        "metadata": { "name": name, "namespace": ns },
        "status": {
            "observedGeneration": s.observed_generation,
            "hash": s.hash,
            "localhostProfile": s.localhost_profile,
            "distribution": s.distribution,
            "drift": s.drift,
            "conditions": s.conditions,
        }
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

/// `CaptureComplete` and `Drift` from the broker's view of the CR's
/// workload. `None` summaries (broker unreachable) ⇒ `None` here, and the
/// caller keeps whatever the conditions already say.
pub fn observation_conditions(
    namespace: &str,
    cr_name: &str,
    workload_ref: Option<&WorkloadRef>,
    summaries: Option<&[BrokerSummary]>,
) -> Option<(Desired, Desired)> {
    let Some(wr) = workload_ref else {
        return Some((
            Desired {
                type_: COND_CAPTURE_COMPLETE,
                status: "Unknown",
                reason: "NoWorkloadRef",
                message: "spec.workloadRef is not set".into(),
            },
            Desired {
                type_: COND_DRIFT,
                status: "Unknown",
                reason: "NoWorkloadRef",
                message: "spec.workloadRef is not set".into(),
            },
        ));
    };
    let summaries = summaries?;
    let row = summaries
        .iter()
        .find(|s| s.namespace == namespace && s.kind == wr.kind.as_str() && s.name == wr.name);
    let Some(row) = row else {
        let msg = format!(
            "no observations yet for {} {}/{}",
            wr.kind.as_str(),
            namespace,
            wr.name
        );
        return Some((
            Desired {
                type_: COND_CAPTURE_COMPLETE,
                status: "Unknown",
                reason: "NoObservations",
                message: msg.clone(),
            },
            Desired {
                type_: COND_DRIFT,
                status: "Unknown",
                reason: "NoObservations",
                message: msg,
            },
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
    Some((capture, drift))
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
    match observation_conditions(
        cr.namespace().as_deref().unwrap_or_default(),
        &cr.name_any(),
        cr.spec.workload_ref.as_ref(),
        summaries,
    ) {
        Some((capture, drift)) => {
            desired.push(capture);
            desired.push(drift);
        }
        // Broker unreachable: carry the existing two forward untouched.
        None => {
            for t in [COND_CAPTURE_COMPLETE, COND_DRIFT] {
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
        }
    }
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
        nodes: Vec::new(),
        conditions,
    }
}

/// Map a stored reason back onto the static set (unknown ⇒ kept as
/// `NoObservations`, the only reason a stale broker row can have).
fn leak_reason(reason: &str) -> &'static str {
    match reason {
        "Full" => "Full",
        "PartialCapture" => "PartialCapture",
        "NoWorkloadRef" => "NoWorkloadRef",
        "InSync" => "InSync",
        "ObservedNotInSpec" => "ObservedNotInSpec",
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
        }
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
        // No workloadRef ⇒ both Unknown/NoWorkloadRef, even without a broker.
        let (c, d) = observation_conditions("prod", "deployment-web", None, None).unwrap();
        assert_eq!((c.status, c.reason), ("Unknown", "NoWorkloadRef"));
        assert_eq!((d.status, d.reason), ("Unknown", "NoWorkloadRef"));

        let wr = WorkloadRef {
            kind: WorkloadKind::Deployment,
            name: "web".into(),
        };
        // Broker unreachable ⇒ None (caller keeps existing conditions).
        assert!(observation_conditions("prod", "deployment-web", Some(&wr), None).is_none());

        // No row for the workload ⇒ Unknown/NoObservations.
        let (c, d) =
            observation_conditions("prod", "deployment-web", Some(&wr), Some(&[])).unwrap();
        assert_eq!((c.status, c.reason), ("Unknown", "NoObservations"));
        assert_eq!((d.status, d.reason), ("Unknown", "NoObservations"));

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
        let (c, d) =
            observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows)).unwrap();
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
        let (c, d) =
            observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows)).unwrap();
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
        let (_, d) =
            observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows)).unwrap();
        assert_eq!((d.status, d.reason), ("Unknown", "NoObservations"));
        assert!(d.message.contains("\"other\""));

        // Namespace must match, not just the workload name.
        let rows = [summary_row("staging", "web", true, None)];
        let (c, _) =
            observation_conditions("prod", "deployment-web", Some(&wr), Some(&rows)).unwrap();
        assert_eq!(c.reason, "NoObservations");
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

    #[test]
    fn desired_summary_is_idempotent_so_it_is_only_applied_once() {
        let c = cr("prod", "deployment-web", Some("web"));
        let nodes = [node("a", "h1")];
        let first = desired_summary(
            &c,
            &SeccompProfileStatus::default(),
            &nodes,
            "h1",
            "kguardian/prod/deployment-web.json",
            1,
            Some(&[]),
        );
        assert_eq!(first.observed_generation, Some(3));
        assert_eq!(first.hash.as_deref(), Some("h1"));
        assert_eq!(
            first.localhost_profile.as_deref(),
            Some("kguardian/prod/deployment-web.json")
        );
        assert_eq!(
            first.distribution.as_ref().unwrap().state,
            DistributionState::Ready
        );
        assert_eq!(first.drift.as_deref(), Some("Unknown"));
        assert_eq!(first.conditions.len(), 3);
        assert!(first.nodes.is_empty(), "summary never carries nodes");
        assert!(!summary_equal(&SeccompProfileStatus::default(), &first));

        // Recomputed against itself ⇒ equal ⇒ no patch.
        let second = desired_summary(
            &c,
            &first,
            &nodes,
            "h1",
            "kguardian/prod/deployment-web.json",
            1,
            Some(&[]),
        );
        assert!(summary_equal(&first, &second));

        // Broker outage keeps CaptureComplete/Drift exactly as they were.
        let third = desired_summary(
            &c,
            &first,
            &nodes,
            "h1",
            "kguardian/prod/deployment-web.json",
            1,
            None,
        );
        assert!(summary_equal(&first, &third));

        // A new hash flips Ready and changes the summary.
        let fourth = desired_summary(
            &c,
            &first,
            &nodes,
            "h2",
            "kguardian/prod/deployment-web.json",
            1,
            Some(&[]),
        );
        assert!(!summary_equal(&first, &fourth));
        assert_eq!(
            fourth.distribution.as_ref().unwrap().state,
            DistributionState::Pending
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
        assert_eq!(types, ["Ready", "CaptureComplete", "Drift"]);
        assert_eq!(p["status"]["conditions"][1]["reason"], "NoWorkloadRef");

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
            "captureComplete":true,"recommendedSnippet":{}},
            {"namespace":"prod","kind":"Deployment","name":"api","cr":null}]"#;
        let v: Vec<BrokerSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(
            v[0].cr.as_ref().unwrap().drift.as_ref().unwrap().missing,
            ["a"]
        );
        assert!(v[1].cr.is_none());
        assert!(v[1].capture.is_none());
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
