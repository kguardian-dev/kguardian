use crate::capture_tiers::CaptureLevel;
use crate::compute_config::COMPUTE_ANNOTATION;
use crate::compute_registry::{
    cgroup_id_for_path, parse_cpu_millis, parse_memory_bytes, resolve_container_cgroup,
    resolve_pid_and_cgroups_path, ComputeMap, ContainerCompute, ResourceSpec, Tier,
};
use crate::models::{pod_flags, Config, ContainerMap, Info, Metadata, PodRegistration};
use crate::network::canonicalize_ip;
use crate::supervisor::{Draining, Subsystem, Supervisor};
use crate::watch_loop::run_watch;
use crate::{api_post_call, Error, PodDetail, PodInfo, PodInspect};
use chrono::Utc;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Pod, PodIP, ResourceRequirements};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{
    api::ListParams,
    runtime::{reflector::Lookup, watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use tokio::sync::mpsc;

/// Watch this node's pods and keep the netns-inode → pod map current.
///
/// Takes `excluded_namespaces` **by value**. It used to be a
/// `&[String]` borrowed from `main`'s stack, which made the returned
/// future non-`'static` and therefore impossible to `tokio::spawn` —
/// which is why every subsystem ended up fused into one task by
/// `try_join!` in the first place (#1346). An `Arc<[String]>` inside
/// gives the two halves below a cheap shared handle without cloning
/// the list per pod event.
/// What the pod watcher needs to keep the per-container compute
/// registry (design D1) in step with the pods on this node. `None` in
/// `watch_pods` means the feature is off: no containerd lookups beyond
/// the one the netns path already makes, nothing registered.
#[derive(Clone)]
pub struct ComputeContext {
    pub map: ComputeMap,
    pub cgroup_root: PathBuf,
    pub host_proc: PathBuf,
    pub node: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn watch_pods(
    node_name: String,
    tx: mpsc::Sender<PodRegistration>,
    container_map: ContainerMap,
    excluded_namespaces: Vec<String>,
    sender_ip: mpsc::Sender<String>,
    ignore_daemonset_traffic: bool,
    cluster_capture_level: CaptureLevel,
    compute: Option<ComputeContext>,
) -> Result<(), Error> {
    let excluded_namespaces: Arc<[String]> = excluded_namespaces.into();
    let c = Client::try_default().await?;
    let pods: Api<Pod> = Api::all(c.clone());
    #[cfg(not(debug_assertions))]
    let wc = watcher::Config::default().fields(&format!("spec.nodeName={}", node_name));
    #[cfg(debug_assertions)]
    let wc = watcher::Config::default();

    // The streaming watch gives low-latency capture as pods appear, but a
    // `spec.nodeName` field-selector watch does NOT reliably deliver the
    // unscheduled->scheduled transition — a pod that schedules onto this
    // node AFTER the watch starts can be missed entirely, so it would
    // never be captured until the controller restarts (and re-runs its
    // initial LIST). Run a periodic re-list alongside the watch as a
    // safety net: a field-selector LIST *is* reliable, and process_pod is
    // idempotent, so re-walking on-node pods only ever fills gaps the
    // watch left. See resync_pods.
    let resync = resync_pods(
        pods.clone(),
        node_name.clone(),
        tx.clone(),
        Arc::clone(&container_map),
        Arc::clone(&excluded_namespaces),
        sender_ip.clone(),
        ignore_daemonset_traffic,
        c.clone(),
        cluster_capture_level,
        compute.clone(),
    );

    // `.default_backoff()` wraps the RAW watcher stream, BEFORE
    // `.applied_objects()`. That is the order kube-rs's own examples
    // use (see kube_runtime::controller's docs), and it matters:
    // `applied_objects` decodes the Init/InitDone markers away, so with
    // the backoff on the outside a successful re-list of a node whose
    // field selector matches nothing yields no `Ok` at all and the
    // backoff never resets. It was the other way round here, which is
    // part of how this chain came to read as "retries, with backoff"
    // when it did neither.
    //
    // Cloned rather than moved because `run_watch` rebuilds the stream
    // if it ever ends; an Api handle and a Config are cheap to clone.
    let watch_api = pods;
    let watch_cfg = wc;

    // `run_watch` never returns: an apiserver outage degrades the watch
    // and nothing else. See watch_loop's module docs for the 2026-09-04
    // incident that made that non-negotiable — in short, `try_for_each`
    // dropped this stream on its first `Err` (backoff sleep included,
    // so not one retry happened) and the `?` took main's try_join! down
    // with it, eBPF handle and all. 26 of 42 nodes lost kernel capture
    // state that nothing backfills.
    let watch = async move {
        run_watch(
            "pod",
            move || {
                watcher(watch_api.clone(), watch_cfg.clone())
                    .default_backoff()
                    .applied_objects()
            },
            move |p| {
                let t = tx.clone();
                let sender_ip = sender_ip.clone();
                let container_map = Arc::clone(&container_map);
                let excluded_namespaces = Arc::clone(&excluded_namespaces);
                let node_name = node_name.clone();
                let c = c.clone();
                let compute = compute.clone();
                async move {
                    if let Some(reg) = process_pod(
                        &p,
                        container_map,
                        &excluded_namespaces,
                        sender_ip,
                        ignore_daemonset_traffic,
                        &node_name,
                        &c,
                        cluster_capture_level,
                        compute.as_ref(),
                    )
                    .await
                    {
                        if let Err(e) = t.send(reg).await {
                            tracing::error!("Failed to send pod registration: {:?}", e);
                        }
                        // debug not info — fires on every pod event that
                        // passes the per-node + namespace-exclusion filter,
                        // including the full re-sync on controller startup
                        // AND every pod-status transition (rolling deploys
                        // generate hundreds per minute on busy nodes). The
                        // inode-to-pod mapping is debug-relevant only when
                        // chasing eBPF event correlation issues; operators
                        // under default RUST_LOG=info don't need it.
                        debug!(
                            "Pod {:?}, inode num {:?}, flags {:#x}",
                            p.name(),
                            reg.netns_inode,
                            reg.flags
                        );
                    }
                }
            },
        )
        .await;
        // Unreachable: `run_watch` loops forever. Present only to give
        // this block the `Result` the supervisor expects.
        Ok::<(), Error>(())
    };

    // Two halves, two tasks, supervised.
    //
    // They used to be `try_join!`ed here, which put both on the task
    // that ran them — so a containerd RPC stalling inside the watch's
    // `process_pod` also stalled the resync loop. That is precisely
    // backwards: the resync exists BECAUSE the streaming watch is not
    // reliable (a `spec.nodeName` field-selector watch drops the
    // unscheduled→scheduled transition), so the safety net must not
    // share a fate with the thing it is a net for.
    //
    // Either half stopping is still fatal, exactly as `try_join!`
    // made it — but now a clean `Ok` return is caught too, not just
    // an `Err`. Both are infinite by construction, so either one
    // returning means pod ingestion has silently stopped.
    let mut subsystems = Supervisor::new();
    subsystems.spawn(Subsystem::PodWatchStream, watch);
    subsystems.spawn(Subsystem::PodResync, resync);
    let fault = subsystems.watch().await;
    // Logs any fault the other half had already queued, so a stall in
    // one is not reported without the error that caused it.
    let _ = subsystems.shutdown(Draining::AfterFault).await;
    Err(fault.into())
}

/// Periodic re-list of this node's pods, registering any the streaming
/// watch missed. The watch is best-effort (field-selector watches drop
/// scheduled-onto-node transitions); this LIST-based pass is the
/// reliable backstop so new workloads are captured within one interval.
#[allow(clippy::too_many_arguments)]
async fn resync_pods(
    pods: Api<Pod>,
    node_name: String,
    tx: mpsc::Sender<PodRegistration>,
    container_map: ContainerMap,
    excluded_namespaces: Arc<[String]>,
    sender_ip: mpsc::Sender<String>,
    ignore_daemonset_traffic: bool,
    client: Client,
    cluster_capture_level: CaptureLevel,
    compute: Option<ComputeContext>,
) -> Result<(), Error> {
    const RESYNC_INTERVAL: Duration = Duration::from_secs(60);
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node_name));
    info!(
        "Pod resync safety-net active: re-listing on-node pods every {}s",
        RESYNC_INTERVAL.as_secs()
    );
    loop {
        tokio::time::sleep(RESYNC_INTERVAL).await;
        // Taken BEFORE the LIST: only pods registered before this
        // instant may be pruned on its evidence. The per-container walk
        // below is serial and containerd-bound, and the streaming watch
        // keeps registering pods meanwhile; those are newer than the
        // list and must not be retired by it.
        let listed_at = Instant::now();
        match pods.list(&lp).await {
            Ok(list) => {
                let mut processed = 0u32;
                for pod in &list.items {
                    if let Some(reg) = process_pod(
                        pod,
                        Arc::clone(&container_map),
                        &excluded_namespaces,
                        sender_ip.clone(),
                        ignore_daemonset_traffic,
                        &node_name,
                        &client,
                        cluster_capture_level,
                        compute.as_ref(),
                    )
                    .await
                    {
                        if let Err(e) = tx.send(reg).await {
                            error!("resync: failed to send pod registration: {:?}", e);
                        }
                        processed += 1;
                    }
                }
                debug!("Pod resync pass processed {} on-node pods", processed);
                // The streaming watch decodes deletions away
                // (`applied_objects`), so a pod that vanished between
                // resyncs is retired here: the compute registry must
                // not keep sampling a cgroup that no longer exists, and
                // the contention probe must stop tracking its id.
                if let Some(ctx) = compute.as_ref() {
                    let live: std::collections::HashSet<String> = list
                        .items
                        .iter()
                        .filter_map(|p| p.metadata.uid.clone())
                        .collect();
                    let stale = prune_compute_registry(&ctx.map, &live, listed_at);
                    if stale > 0 {
                        debug!(
                            stale,
                            "compute registry: retired pods absent from the resync list"
                        );
                    }
                }
            }
            // Transient list failures (apiserver blip) are non-fatal —
            // the next tick retries. Only the watch task failing restarts.
            Err(e) => warn!("Pod resync list failed (will retry next tick): {}", e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_pod(
    pod: &Pod,
    container_map: ContainerMap,
    excluded_namespaces: &[String],
    sender_ip: mpsc::Sender<String>,
    ignore_daemonset_traffic: bool,
    node_name: &str,
    client: &Client,
    cluster_capture_level: CaptureLevel,
    compute: Option<&ComputeContext>,
) -> Option<PodRegistration> {
    // A Succeeded/Failed or deleting pod no longer owns its IP, but its
    // object lingers in the API server and shows up in every resync.
    // Re-posting it kept its broker row alive (and flapping against the
    // reconciler, which marks it dead), so flows on its recycled IP were
    // attributed to a Job that finished weeks earlier. Skip it entirely;
    // the reconciler marks the row dead.
    if !crate::pod_reconciler::pod_holds_an_ip(pod) {
        debug!(
            "skipping terminal/deleting pod {}/{}",
            pod.metadata.namespace.as_deref().unwrap_or(""),
            pod.name_any()
        );
        // Its cgroups are going or gone: stop sampling them. This is
        // the deletion path the watch does deliver (a deletionTimestamp
        // is a modification); the resync prune covers the rest.
        if let (Some(ctx), Some(uid)) = (compute, pod.metadata.uid.as_deref()) {
            ctx.map.remove_pod(uid);
        }
        return None;
    }
    if let Some(con_ids) = pod_unready(pod) {
        // Computed once here so the broker payload and the eBPF
        // registration can never disagree about a pod's tier.
        let capture_level = effective_capture_level(pod, cluster_capture_level);
        let pod_ip = update_pods_details(pod, node_name, client, capture_level).await;
        if let Ok(Some(pod_ip)) = pod_ip {
            match ignore_map_action(pod, &pod_ip, ignore_daemonset_traffic, excluded_namespaces) {
                IgnoreMapAction::Ignore(ips) => {
                    // debug not info — fires per daemonset pod event,
                    // including the full re-sync (kube-proxy, calico-node,
                    // and the kguardian-controller itself on every node).
                    // Operators set IGNORE_DAEMONSET_TRAFFIC=true to NOT
                    // see this stream by default.
                    debug!("Ignoring daemonset pod: {}, {}", pod.name_any(), pod_ip);
                    for ip in ips {
                        if let Err(e) = sender_ip.send(ip).await {
                            error!("Failed to send pod ip: {}", e);
                        }
                    }
                }
                IgnoreMapAction::HostNetwork => log_host_network_skip_once(pod, &pod_ip),
                IgnoreMapAction::None => {}
            }
            let plan = registration_plan(
                should_process_pod(&pod.metadata.namespace, excluded_namespaces),
                compute.is_some(),
            );
            if plan.netns {
                return process_container_ids(
                    &con_ids,
                    pod,
                    &pod_ip,
                    container_map,
                    capture_level,
                    compute,
                )
                .await;
            }
            if plan.compute {
                // Excluded namespace: no traffic or syscall tracking (those
                // feed policies the operator chose not to generate here),
                // but compute gauges are observation only, and every pod on
                // the node matters as a possible victim or culprit — the
                // kguardian namespace itself included.
                if let Some(ctx) = compute {
                    register_compute(pod, ctx).await;
                }
            }
        }
    }

    None
}

/// What `process_pod` does to the eBPF `ignore_ips` map for a pod.
#[derive(Debug, PartialEq, Eq)]
enum IgnoreMapAction {
    /// Not a DaemonSet pod, ignoring is off, or the namespace is
    /// excluded: leave the map alone.
    None,
    /// A DaemonSet pod whose address is the node's: leave the map alone
    /// (see `ignore_map_action`) — the caller logs, once.
    HostNetwork,
    /// Push these addresses into the map.
    Ignore(Vec<String>),
}

/// Decide whether a pod's addresses go into the eBPF ignore map.
///
/// `IGNORE_DAEMONSET_TRAFFIC` means "don't capture DaemonSet pods". For
/// a pod-network DaemonSet that is two things: don't register its
/// netns (handled by never reaching `process_container_ids`) AND drop
/// flows to/from its IPs in BPF, so its peers' recordings aren't
/// flooded with kube-proxy / CNI chatter.
///
/// A host-network DaemonSet pod (node-exporter, Cilium, this controller)
/// has `podIP == node IP`. Putting that in the map ignored every flow to
/// or from the NODE — Prometheus → node-exporter:9100, anything →
/// kubelet:10250, etcd:2381, the apiserver on a control-plane node —
/// for every pod on the cluster, and `helper.h` drops on src OR dst.
/// That traffic was simply never recorded, so generated policies
/// omitted it. Such a pod is still not registered (unchanged); only the
/// map insertion is withheld.
///
/// The excluded-namespace gate applies here too: it used to run only
/// AFTER the insertion, so excluding `kguardian` did not stop the
/// controller's own DaemonSet from ignoring its node IP.
///
/// `Ignore` carries EVERY address the pod holds, not just the primary:
/// on a dual-stack node the map otherwise never learns the
/// secondary-family address, and the daemonset's traffic over that
/// family is still recorded — the exact half-working state the IpAddr
/// parse in bpf.rs exists to prevent.
fn ignore_map_action(
    pod: &Pod,
    pod_ip: &str,
    ignore_daemonset_traffic: bool,
    excluded_namespaces: &[String],
) -> IgnoreMapAction {
    if !ignore_daemonset_traffic
        || !is_backed_by_daemonset(pod)
        || !should_process_pod(&pod.metadata.namespace, excluded_namespaces)
    {
        return IgnoreMapAction::None;
    }
    if is_host_network(pod) {
        return IgnoreMapAction::HostNetwork;
    }
    IgnoreMapAction::Ignore(collect_pod_ips(
        pod.status.as_ref().and_then(|s| s.pod_ips.as_deref()),
        pod_ip,
    ))
}

/// `spec.hostNetwork`, absent ⇒ false.
fn is_host_network(pod: &Pod) -> bool {
    pod.spec
        .as_ref()
        .and_then(|s| s.host_network)
        .unwrap_or(false)
}

/// Info once per pod, not per event: `process_pod` re-runs for every
/// watch event and on the 60s resync, and there are several
/// host-network DaemonSet pods on every node.
fn log_host_network_skip_once(pod: &Pod, pod_ip: &str) {
    static LOGGED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let key = format!(
        "{}/{}",
        pod.metadata.namespace.as_deref().unwrap_or_default(),
        pod.name_any()
    );
    let mut logged = LOGGED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if logged.insert(key) {
        info!(
            pod = %pod.name_any(),
            namespace = pod.metadata.namespace.as_deref().unwrap_or_default(),
            ip = pod_ip,
            "host-network daemonset pod shares the node IP; not ignoring node traffic"
        );
    }
}

/// Which registrations a ready pod gets. `EXCLUDED_NAMESPACES` switches
/// off the netns registration (traffic + syscalls, the policy inputs)
/// only; compute sampling follows `COMPUTE_ENABLED` alone, so an excluded
/// namespace still shows CPU/memory gauges and takes part in noisy-
/// neighbour attribution. The per-pod opt-out for compute is the
/// `kguardian.dev/compute: "off"` annotation, handled in `register_compute`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RegistrationPlan {
    pub netns: bool,
    pub compute: bool,
}

pub fn registration_plan(namespace_tracked: bool, compute_enabled: bool) -> RegistrationPlan {
    RegistrationPlan {
        netns: namespace_tracked,
        compute: compute_enabled,
    }
}

fn should_process_pod(namespace: &Option<String>, excluded_namespaces: &[String]) -> bool {
    !namespace
        .as_ref()
        .is_some_and(|ns| excluded_namespaces.contains(ns))
}

/// Parse the `EXCLUDED_NAMESPACES` env var into a Vec<String>.
///
/// Splits on `,`, trims whitespace from each entry, drops empties.
/// Without this, the natural human formatting `"kube-system, monitoring,
/// ingress-nginx"` silently produced `["kube-system", " monitoring",
/// " ingress-nginx"]` — and `should_process_pod` does an exact-match
/// `Vec::contains`, so the spaced entries never matched any real
/// namespace name. Operators thought they had three namespaces excluded
/// but were processing pods from two of them.
pub fn parse_excluded_namespaces(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// Lenient bool parser for env-var values.
///
/// Rust's `bool::from_str` only accepts the literal strings "true" and
/// "false" (lowercase, exact). Operators routinely write "True",
/// "FALSE", or copy-paste artefacts like " false\n" — all of which
/// the strict parser rejects, silently falling back to the default.
/// For a flag like IGNORE_DAEMONSET_TRAFFIC where the default is
/// `true`, an operator setting `IGNORE_DAEMONSET_TRAFFIC=False`
/// (intending to disable) gets the opposite of their intent and
/// never gets a warning about the typo.
///
/// Accepts (case-insensitive, surrounding-whitespace tolerant):
///   - true:  "true", "1", "yes", "on"
///   - false: "false", "0", "no", "off"
///
/// Anything else returns `default`. Pure function, no env access —
/// caller does the env::var lookup and passes the raw string here.
pub fn parse_lenient_bool(s: &str, default: bool) -> bool {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => default,
    }
}

fn pod_unready(p: &Pod) -> Option<Vec<String>> {
    let status = p.status.as_ref()?;
    if let Some(conds) = &status.conditions {
        let failed = conds
            .iter()
            .filter(|c| c.type_ == "Ready" && c.status == "False")
            .map(|c| c.message.clone().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",");
        if !failed.is_empty() {
            debug!("Unready pod {}: {}", p.name_any(), failed);
            return None;
        }
    }

    if let Some(con_status) = &status.container_statuses {
        let mut container_ids: Vec<String> = vec![];
        for container in con_status {
            if let Some(container_id) = container.container_id.to_owned() {
                container_ids.push(container_id)
            }
        }
        return Some(container_ids);
    }

    None
}

/// Build the full set of addresses for a pod, canonicalised and
/// de-duplicated, with `primary` (from `status.podIP`) guaranteed first.
///
/// `status.podIPs` is authoritative for dual-stack and, per the API
/// contract, its first entry equals `status.podIP` — but that is only a
/// contract, and the list is absent entirely on older/simpler clusters.
/// Seeding from `primary` means a missing or reordered `podIPs` can
/// never lose the address the rest of the controller keys on.
fn collect_pod_ips(pod_ips: Option<&[PodIP]>, primary: &str) -> Vec<String> {
    let mut out = vec![primary.to_string()];
    for entry in pod_ips.unwrap_or_default() {
        let ip = canonicalize_ip(&entry.ip);
        if !ip.is_empty() && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

async fn update_pods_details(
    pod: &Pod,
    node_name: &str,
    client: &Client,
    capture_level: CaptureLevel,
) -> Result<Option<String>, Error> {
    let pod_name = pod.name_any();
    let pod_namespace = pod.metadata.namespace.to_owned();
    let pod_status = match pod.status.as_ref() {
        Some(status) => status,
        None => return Ok(None),
    };
    let mut pod_ip_address: Option<String> = None;
    if let Some(pod_ip) = pod_status.pod_ip.as_ref() {
        // Canonicalise: everything downstream (the broker's IP-keyed
        // lookups, the TrafficKey cache, the eBPF address comparison in
        // network.rs) matches these as strings, so the controller must
        // emit exactly one spelling per address. See
        // network::canonicalize_ip.
        let pod_ip = canonicalize_ip(pod_ip);

        // A dual-stack pod has both an IPv4 and an IPv6 address, but
        // `status.podIP` reports only the first (the cluster's primary
        // family). Reading it alone meant the secondary-family address
        // was never registered, so eBPF flows to or from it correlated
        // to no pod at all. `status.podIPs` carries the full set; post
        // all of them and keep podIP as the primary for compatibility.
        let pod_ips = collect_pod_ips(pod_status.pod_ips.as_deref(), &pod_ip);

        // Extract pod identity and workload selector labels
        let (pod_identity, workload_selector_labels) =
            extract_pod_identity_and_selectors(pod, client).await;

        // Top-level owning controller as (kind, name) — the key the
        // broker groups syscalls on for per-workload seccomp profiles.
        let (workload_kind, workload_name) = match resolve_workload(pod, client).await {
            Some((k, n)) => (Some(k), Some(n)),
            None => (None, None),
        };

        // debug not info — fires for every pod-watcher event with a
        // pod_ip (i.e. essentially every status transition during a
        // rollout). The identity / workload-selector inference is
        // debug-relevant when validating what kguardian inferred from
        // a pod's labels + owner refs, not steady-state operator info.
        debug!(
            "Pod {}: identity={:?}, workload={:?}/{:?}, workload_selector_labels={:?}",
            pod_name, pod_identity, workload_kind, workload_name, workload_selector_labels
        );

        let z = PodDetail {
            pod_ip: pod_ip.to_string(),
            pod_ips,
            pod_name: pod_name.clone(),
            pod_namespace,
            pod_obj: Some(json!(pod)),
            time_stamp: Utc::now().naive_utc(),
            node_name: node_name.to_string(),
            is_dead: false,
            pod_identity,
            workload_selector_labels,
            workload_kind,
            workload_name,
            capture_level: Some(capture_level.as_str().to_string()),
            host_network: is_host_network(pod),
        };

        if let Err(e) = api_post_call(json!(z), "pod/spec").await {
            error!("Failed to post Pod details: {}", e);
        }
        pod_ip_address = Some(pod_ip.to_string());
        return Ok(pod_ip_address);
    }
    Ok(pod_ip_address)
}

/// Annotation a workload sets on its pod template to raise its syscall
/// capture tier above the cluster default: one of `full|high|medium|low`.
/// It can only RAISE capture (the cluster default is a floor); `custom`
/// is cluster-only and an unknown value warns and is ignored. Kubernetes
/// propagates `spec.template.metadata.annotations` onto the pods, so this
/// needs no extra owner lookup.
pub const SYSCALL_CAPTURE_ANNOTATION: &str = "kguardian.dev/syscall-capture";

/// Legacy opt-in for complete, unfiltered capture — kept as an alias for
/// `kguardian.dev/syscall-capture: full`. Any value the lenient bool
/// parser reads as true counts. See
/// docs/design/per-workload-seccomp-distribution.md.
pub const SECCOMP_RECORD_ANNOTATION: &str = "kguardian.dev/seccomp-record";

/// The tier a pod is captured at: the cluster default, raised by the
/// pod's annotations if they ask for more.
///
/// Precedence: `seccomp-record: "true"` ⇒ `full`, unconditionally.
/// Otherwise `syscall-capture` is parsed and applied through
/// `CaptureLevel::raise` (never lowers). Invalid values and `custom`
/// warn and leave the cluster default in place.
pub fn effective_capture_level(pod: &Pod, cluster: CaptureLevel) -> CaptureLevel {
    let annotations = pod.metadata.annotations.as_ref();

    let legacy_full = annotations
        .and_then(|a| a.get(SECCOMP_RECORD_ANNOTATION))
        .is_some_and(|v| parse_lenient_bool(v, false));
    if legacy_full {
        return CaptureLevel::Full;
    }

    let Some(raw) = annotations.and_then(|a| a.get(SYSCALL_CAPTURE_ANNOTATION)) else {
        return cluster;
    };
    match CaptureLevel::parse(raw) {
        Some(CaptureLevel::Custom) => {
            warn!(
                pod = %pod.name_any(),
                "{SYSCALL_CAPTURE_ANNOTATION}=custom is cluster-only (SYSCALL_CUSTOM_LIST); \
                 using cluster default {cluster}"
            );
            cluster
        }
        Some(requested) => {
            let effective = CaptureLevel::raise(cluster, requested);
            if effective != requested {
                debug!(
                    pod = %pod.name_any(),
                    "{SYSCALL_CAPTURE_ANNOTATION}={requested} does not raise the cluster \
                     default {cluster}; keeping {effective}"
                );
            }
            effective
        }
        None => {
            warn!(
                pod = %pod.name_any(),
                value = raw.as_str(),
                "{SYSCALL_CAPTURE_ANNOTATION} is not one of full|high|medium|low; \
                 using cluster default {cluster}"
            );
            cluster
        }
    }
}

/// The `inode_num` map value for a pod: tracked, at `level`, with a
/// generation derived from the pod UID (see `pod_flags::GEN_SHIFT`).
fn pod_registration_flags(pod: &Pod, level: CaptureLevel) -> u32 {
    pod_flags::pack(
        level,
        pod_flags::generation_for_uid(pod.metadata.uid.as_deref()),
    )
}

/// Register a pod's netns (unchanged behaviour, see [`register_netns`])
/// and then, when compute is on, every one of its containers in the
/// compute registry. The compute walk runs *after* the netns
/// registration and never alters its result: a pod the netns path
/// could not resolve is still not registered for traffic, whatever the
/// compute walk finds.
async fn process_container_ids(
    con_ids: &[String],
    pod: &Pod,
    pod_ip: &str,
    container_map: ContainerMap,
    capture_level: CaptureLevel,
    compute: Option<&ComputeContext>,
) -> Option<PodRegistration> {
    let reg = register_netns(con_ids, pod, pod_ip, container_map, capture_level).await;
    if let Some(ctx) = compute {
        register_compute(pod, ctx).await;
    }
    reg
}

/// The netns registration: the first container whose network namespace
/// resolves registers the pod, and the loop stops there.
async fn register_netns(
    con_ids: &[String],
    pod: &Pod,
    pod_ip: &str,
    container_map: ContainerMap,
    capture_level: CaptureLevel,
) -> Option<PodRegistration> {
    let flags = pod_registration_flags(pod, capture_level);
    let identity = pod_identity_metadata(pod);
    for con_id in con_ids {
        let pod_info = create_pod_info(pod, pod_ip);
        let pod_inspect = PodInspect {
            status: pod_info,
            info: Info {
                config: Config {
                    metadata: identity.clone(),
                },
            },
            ..Default::default()
        };
        // debug not info — these two log lines fire inside the
        // per-container loop, per pod-event. Same per-event rate as
        // the upstream pod-watcher info logs already dropped to debug.
        // Operators see the consolidated per-pod inode line at the
        // watch-loop level (also at debug); this inner trace is BPF
        // debug detail.
        debug!("pod name {}", pod.name_any());
        if let Some(pod_inspect) = pod_inspect.get_pod_inspect(con_id).await {
            if let Some(inode_num) = pod_inspect.inode_num {
                debug!(
                    "inode_num of pod {} is {} (flags {:#x})",
                    pod_inspect.status.pod_name, inode_num, flags
                );
                // Takes a write lock on this key's shard. It is only safe to
                // block here because no reader holds a guard across an await
                // any more — see ContainerMap and lookup_pod in models.rs.
                container_map.insert(inode_num, Arc::new(pod_inspect));
                return Some(PodRegistration {
                    netns_inode: inode_num,
                    flags,
                });
            }
        }
    }
    None
}

/// `kguardian.dev/compute: "off"` on the pod opts it out of sampling
/// and of `tracked_cgroups`. Any other value, or no annotation, is on;
/// there is no opt-in mode (design D9).
pub fn compute_opted_out(pod: &Pod) -> bool {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(COMPUTE_ANNOTATION))
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("off"))
}

/// Requests and limits from a `resources:` block, normalised to
/// millicores and bytes. An unparseable quantity is treated as unset —
/// a wrong denominator is worse than none.
pub fn resource_spec_from(r: Option<&ResourceRequirements>) -> ResourceSpec {
    type Quantities = BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>;
    let Some(r) = r else {
        return ResourceSpec::default();
    };
    let get = |m: &Option<Quantities>, k: &str| -> Option<String> {
        m.as_ref().and_then(|m| m.get(k)).map(|q| q.0.clone())
    };
    ResourceSpec {
        cpu_request_millis: get(&r.requests, "cpu").and_then(|q| parse_cpu_millis(&q)),
        cpu_limit_millis: get(&r.limits, "cpu").and_then(|q| parse_cpu_millis(&q)),
        memory_request_bytes: get(&r.requests, "memory").and_then(|q| parse_memory_bytes(&q)),
        memory_limit_bytes: get(&r.limits, "memory").and_then(|q| parse_memory_bytes(&q)),
    }
}

/// The effective resources of one container: the status' `resources`
/// when the kubelet reports them (in-place resize, 1.27+), else the
/// spec's.
pub fn container_resources(pod: &Pod, container_name: &str) -> ResourceSpec {
    let from_status = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.name == container_name))
        .and_then(|c| c.resources.as_ref());
    if from_status.is_some() {
        return resource_spec_from(from_status);
    }
    let from_spec = pod
        .spec
        .as_ref()
        .and_then(|s| s.containers.iter().find(|c| c.name == container_name))
        .and_then(|c| c.resources.as_ref());
    resource_spec_from(from_spec)
}

/// Retire every pod registered before `listed_at` whose uid is not in
/// `live` (the LIST taken at `listed_at`). Pods registered after the
/// list was taken are newer than its evidence and are left alone; the
/// next resync judges them. Returns how many were removed.
pub fn prune_compute_registry(
    map: &ComputeMap,
    live: &std::collections::HashSet<String>,
    listed_at: Instant,
) -> usize {
    let mut removed = 0;
    for uid in map.pod_uids_registered_before(listed_at) {
        if !live.contains(&uid) {
            map.remove_pod(&uid);
            removed += 1;
        }
    }
    removed
}

/// Walk EVERY container of the pod (not just the first that resolves),
/// resolve its host pid through the existing containerd path, read its
/// cgroup v2 path and id, and record it with its requests and limits.
///
/// A pod annotated `kguardian.dev/compute: "off"` is walked the same
/// way but lands in the registry's identity-only tier (design D9): it
/// is never sampled or tracked, yet blame can still name it
/// `ns/pod/container` when it is the bully.
///
/// Containers already registered under the same containerd id and tier
/// are skipped, so the 60 s resync costs no containerd RPC for a steady
/// pod. Every failure is per container and logged at debug: a pod that
/// cannot be sampled must not stop its neighbours from being.
async fn register_compute(pod: &Pod, ctx: &ComputeContext) {
    let Some(uid) = pod.metadata.uid.clone() else {
        return;
    };
    ctx.map.note_eligible_pod();
    let tier = if compute_opted_out(pod) {
        Tier::IdentityOnly
    } else {
        Tier::Sampled
    };
    let namespace = pod.metadata.namespace.clone().unwrap_or_default();
    let pod_name = pod.name_any();
    let Some(statuses) = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
    else {
        return;
    };
    for status in statuses {
        let Some(raw_id) = status.container_id.as_deref() else {
            continue;
        };
        let existing = ctx.map.container_for(&uid, &status.name);
        let entry = match existing {
            Some((e, t)) if e.container_id == raw_id => {
                if t == tier {
                    continue;
                }
                // Same container, the annotation changed: move tiers
                // without another containerd round trip.
                (*e).clone()
            }
            _ => {
                // One containerd channel per container: Tasks.Get (the
                // same call and ceilings the netns registration uses)
                // then Containers.Get for the OCI cgroupsPath. The
                // controller's own cgroup namespace makes
                // /proc/<pid>/cgroup useless for other pods (it renders
                // `../..` paths); see `resolve_container_cgroup`.
                let cid = crate::container::parse_container_id(raw_id).unwrap_or_default();
                let Some((pid, spec_path)) = resolve_pid_and_cgroups_path(&cid).await else {
                    continue;
                };
                let resolved = match resolve_container_cgroup(
                    &ctx.cgroup_root,
                    &ctx.host_proc,
                    pid,
                    &cid,
                    spec_path.as_deref(),
                ) {
                    Ok(r) => r,
                    Err(failure) => {
                        // WARN, not debug: every route failed, and if
                        // this happens for every container the feature
                        // is silently dead. The sampler's startup
                        // self-check escalates that case to ERROR.
                        warn!(
                            pod = %pod_name,
                            container = %status.name,
                            pid,
                            container_id = %cid,
                            attempts = %failure,
                            "compute: could not resolve container cgroup; container not sampled"
                        );
                        continue;
                    }
                };
                let cgroup_path = resolved.path;
                let via = resolved.via;
                let cgroup_id = match cgroup_id_for_path(&ctx.cgroup_root, &cgroup_path) {
                    Ok(id) => id,
                    Err(e) => {
                        debug!(pod = %pod_name, container = %status.name, cgroup = %cgroup_path, error = %e, "cgroup id lookup failed");
                        continue;
                    }
                };
                debug!(
                    pod = %pod_name,
                    container = %status.name,
                    pid,
                    cgroup = %cgroup_path,
                    cgroup_id,
                    via,
                    ?tier,
                    "compute: registered container cgroup"
                );
                ContainerCompute {
                    pod_uid: uid.clone(),
                    namespace: namespace.clone(),
                    pod_name: pod_name.clone(),
                    container_name: status.name.clone(),
                    container_id: raw_id.to_string(),
                    pid,
                    cgroup_path,
                    cgroup_id,
                    resources: container_resources(pod, &status.name),
                    node: ctx.node.clone(),
                }
            }
        };
        match tier {
            Tier::Sampled => ctx.map.insert_container(entry),
            Tier::IdentityOnly => ctx.map.insert_identity_only(entry),
        }
    }
}

fn create_pod_info(pod: &Pod, pod_ip: &str) -> PodInfo {
    PodInfo {
        pod_name: pod.name_any(),
        pod_namespace: pod.metadata.namespace.to_owned(),
        pod_ip: pod_ip.to_string(),
    }
}

/// The pod's Kubernetes identity for its `ContainerMap` entry.
///
/// `register_netns` used to fill `PodInspect.status` and nothing else, so
/// `info.config.metadata` was `Default` on every node — name, namespace
/// AND uid all empty strings. That went unnoticed for as long as nothing
/// read them. Seccomp denial capture does: it reports the pod UID to the
/// broker, whose storage key is `(pod_uid, syscall, action)`. An empty
/// UID there is not a cosmetically missing field, it is every pod on the
/// cluster collapsing into a single row per syscall/action pair, so the
/// broker rejects such rows outright rather than merge them
/// (`broker/src/seccomp_denial.rs`, `reject_reason`) — and the entire
/// feature stored nothing while looking healthy from both ends.
///
/// All three fields are filled, not just the uid that prompted this.
/// Leaving two of three empty next to one that is populated is exactly
/// the shape that made the gap invisible the first time.
///
/// A pod with no `metadata.uid` cannot arise from a real apiserver — it
/// assigns one at admission — so this is the hand-built-object case. It
/// is deliberately NOT a reason to skip registration: this entry is what
/// makes traffic and syscall capture work at all, and refusing it would
/// trade a missing UID for a pod no probe can see. Register it, say so
/// once per event so the condition is never silent, and let the broker
/// reject the denial rows that carry no UID rather than invent an
/// identity for them here.
fn pod_identity_metadata(pod: &Pod) -> Metadata {
    let uid = pod.metadata.uid.clone().unwrap_or_default();
    if uid.is_empty() {
        warn!(
            pod = %pod.name_any(),
            namespace = %pod.metadata.namespace.as_deref().unwrap_or("?"),
            "pod has no metadata.uid; it is still tracked for traffic and syscall capture, \
             but the broker will reject its seccomp denial rows because they cannot be \
             attributed to a stable pod identity"
        );
    }
    Metadata {
        name: pod.name_any(),
        namespace: pod.metadata.namespace.clone().unwrap_or_default(),
        uid,
    }
}

fn is_backed_by_daemonset(pod: &Pod) -> bool {
    if let Some(owner_references) = &pod.metadata.owner_references {
        for owner in owner_references {
            if owner.kind == "DaemonSet" {
                return true;
            }
        }
    }
    false
}

/// Extracts pod identity and workload selector labels from labels or owner references
/// Returns (identity, selector_labels)
/// Priority: app.kubernetes.io/name > app.kubernetes.io/component > k8s-app > owner references
async fn extract_pod_identity_and_selectors(
    pod: &Pod,
    client: &Client,
) -> (Option<String>, Option<BTreeMap<String, String>>) {
    // Check labels first in priority order
    if let Some(labels) = &pod.metadata.labels {
        // 1. Check for app.kubernetes.io/name
        if let Some(name) = labels.get("app.kubernetes.io/name") {
            // Also try to get workload selector labels
            let selectors = trace_owner_to_workload_with_selectors(pod, client).await;
            return (Some(name.clone()), selectors);
        }

        // 2. Check for app.kubernetes.io/component
        if let Some(component) = labels.get("app.kubernetes.io/component") {
            let selectors = trace_owner_to_workload_with_selectors(pod, client).await;
            return (Some(component.clone()), selectors);
        }

        // 3. Check for k8s-app
        if let Some(k8s_app) = labels.get("k8s-app") {
            let selectors = trace_owner_to_workload_with_selectors(pod, client).await;
            return (Some(k8s_app.clone()), selectors);
        }
        // 4. Check for app
        if let Some(k8s_app) = labels.get("app") {
            let selectors = trace_owner_to_workload_with_selectors(pod, client).await;
            return (Some(k8s_app.clone()), selectors);
        }
    }

    // 5. If no labels found, trace back through owner references
    let (identity, selectors) = trace_owner_to_workload_with_selectors_and_name(pod, client).await;
    (identity, selectors)
}

/// Traces pod's owner references to get workload selector labels only
async fn trace_owner_to_workload_with_selectors(
    pod: &Pod,
    client: &Client,
) -> Option<BTreeMap<String, String>> {
    let owner_references = pod.metadata.owner_references.as_ref()?;
    let namespace = pod.metadata.namespace.as_ref()?;

    debug!(
        "Tracing owner references for pod {} to get selector labels",
        pod.name_any()
    );

    for owner in owner_references {
        debug!("Processing owner: kind={}, name={}", owner.kind, owner.name);
        match owner.kind.as_str() {
            "ReplicaSet" => {
                // Trace ReplicaSet to Deployment and get selector
                if let Some(selectors) =
                    get_deployment_selector_from_replicaset(&owner.name, namespace, client).await
                {
                    return Some(selectors);
                }
            }
            "Deployment" => {
                if let Some(selectors) =
                    get_deployment_selector(&owner.name, namespace, client).await
                {
                    return Some(selectors);
                }
            }
            "StatefulSet" => {
                if let Some(selectors) =
                    get_statefulset_selector(&owner.name, namespace, client).await
                {
                    return Some(selectors);
                }
            }
            "DaemonSet" => {
                debug!("Found DaemonSet owner: {}", owner.name);
                if let Some(selectors) =
                    get_daemonset_selector(&owner.name, namespace, client).await
                {
                    return Some(selectors);
                }
            }
            _ => {
                debug!("Unknown owner kind for selector extraction: {}", owner.kind);
            }
        }
    }

    debug!("No selector labels found for pod {}", pod.name_any());
    None
}

/// Traces pod's owner references to get both workload name and selector labels
async fn trace_owner_to_workload_with_selectors_and_name(
    pod: &Pod,
    client: &Client,
) -> (Option<String>, Option<BTreeMap<String, String>>) {
    let owner_references = match pod.metadata.owner_references.as_ref() {
        Some(refs) => refs,
        None => return (None, None),
    };
    let namespace = match pod.metadata.namespace.as_ref() {
        Some(ns) => ns,
        None => return (None, None),
    };

    for owner in owner_references {
        match owner.kind.as_str() {
            "ReplicaSet" => {
                // Trace ReplicaSet to Deployment
                if let Some((name, selectors)) =
                    get_deployment_name_and_selector_from_replicaset(&owner.name, namespace, client)
                        .await
                {
                    return (Some(name), Some(selectors));
                }
            }
            "Deployment" => {
                let selectors = get_deployment_selector(&owner.name, namespace, client).await;
                return (Some(owner.name.clone()), selectors);
            }
            "StatefulSet" => {
                let selectors = get_statefulset_selector(&owner.name, namespace, client).await;
                return (Some(owner.name.clone()), selectors);
            }
            "DaemonSet" => {
                let selectors = get_daemonset_selector(&owner.name, namespace, client).await;
                return (Some(owner.name.clone()), selectors);
            }
            _ => {
                debug!("Unknown owner kind: {}", owner.kind);
            }
        }
    }

    (None, None)
}

/// Kinds taken as a workload identity directly from a pod's owner
/// reference — no further tracing needed. `ReplicaSet` and `Job` are
/// deliberately absent: they are collapsed to their parent by
/// `resolve_workload`.
const DIRECT_WORKLOAD_KINDS: [&str; 4] = [
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicationController",
];

/// What a pod's owner references say about its workload, before any
/// apiserver round-trip. Split out from `resolve_workload` so the
/// owner-walking logic is unit-testable without a `Client`.
#[derive(Debug, PartialEq, Eq)]
enum OwnerClass {
    /// Owner is itself the top-level workload.
    Direct(String, String),
    /// Owner is a ReplicaSet — trace it to its Deployment.
    ViaReplicaSet(String),
    /// Owner is a Job — trace it to its CronJob.
    ViaJob(String),
    /// No controller owner reference — a bare or static pod.
    None,
}

/// Classify a pod's owner references. Only the reference with
/// `controller: true` identifies the workload.
fn classify_owner(owners: Option<&[OwnerReference]>) -> OwnerClass {
    let Some(owners) = owners else {
        return OwnerClass::None;
    };
    for owner in owners {
        if owner.controller != Some(true) {
            continue;
        }
        return match owner.kind.as_str() {
            "ReplicaSet" => OwnerClass::ViaReplicaSet(owner.name.clone()),
            "Job" => OwnerClass::ViaJob(owner.name.clone()),
            kind if DIRECT_WORKLOAD_KINDS.contains(&kind) => {
                OwnerClass::Direct(kind.to_string(), owner.name.clone())
            }
            other => {
                debug!("classify_owner: unhandled controller kind {other}");
                OwnerClass::None
            }
        };
    }
    OwnerClass::None
}

/// Resolve a pod to the top-level controller that owns it, as a
/// `(kind, name)` pair — the stable key a per-workload seccomp profile
/// is grouped on.
///
/// Transient layers are collapsed: a `ReplicaSet` resolves to its
/// `Deployment` (each rollout creates a fresh ReplicaSet, so keying on
/// it would fragment the profile), and a `Job` to its `CronJob` (Jobs
/// created by a CronJob carry a generated name per scheduled run). A
/// ReplicaSet or Job that has no controller of its own is kept as-is.
/// A pod with no controller owner reference — a bare or static pod —
/// returns `None`.
async fn resolve_workload(pod: &Pod, client: &Client) -> Option<(String, String)> {
    let namespace = pod.metadata.namespace.as_deref()?;
    match classify_owner(pod.metadata.owner_references.as_deref()) {
        OwnerClass::Direct(kind, name) => Some((kind, name)),
        OwnerClass::ViaReplicaSet(rs) => Some(
            replicaset_deployment(&rs, namespace, client)
                .await
                .unwrap_or(("ReplicaSet".to_string(), rs)),
        ),
        OwnerClass::ViaJob(job) => Some(
            job_cronjob(&job, namespace, client)
                .await
                .unwrap_or(("Job".to_string(), job)),
        ),
        OwnerClass::None => None,
    }
}

/// `("Deployment", name)` when the ReplicaSet is owned by one, else `None`
/// (a directly-created ReplicaSet).
async fn replicaset_deployment(
    name: &str,
    namespace: &str,
    client: &Client,
) -> Option<(String, String)> {
    let api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
    match api.get(name).await {
        Ok(rs) => rs
            .metadata
            .owner_references?
            .into_iter()
            .find(|o| o.kind == "Deployment" && o.controller == Some(true))
            .map(|o| ("Deployment".to_string(), o.name)),
        Err(e) => {
            warn!("resolve_workload: failed to get ReplicaSet {name}: {e}");
            None
        }
    }
}

/// `("CronJob", name)` when the Job is owned by one, else `None` (a
/// standalone Job).
async fn job_cronjob(name: &str, namespace: &str, client: &Client) -> Option<(String, String)> {
    let api: Api<Job> = Api::namespaced(client.clone(), namespace);
    match api.get(name).await {
        Ok(job) => job
            .metadata
            .owner_references?
            .into_iter()
            .find(|o| o.kind == "CronJob" && o.controller == Some(true))
            .map(|o| ("CronJob".to_string(), o.name)),
        Err(e) => {
            warn!("resolve_workload: failed to get Job {name}: {e}");
            None
        }
    }
}

/// Gets selector labels from a Deployment
async fn get_deployment_selector(
    deployment_name: &str,
    namespace: &str,
    client: &Client,
) -> Option<BTreeMap<String, String>> {
    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    match deploy_api.get(deployment_name).await {
        Ok(deployment) => {
            let selectors = deployment.spec.and_then(|spec| spec.selector.match_labels);
            if selectors.is_none() {
                debug!(
                    "Deployment {} has no match_labels in selector",
                    deployment_name
                );
            } else {
                debug!(
                    "Deployment {} selector labels: {:?}",
                    deployment_name, selectors
                );
            }
            selectors
        }
        Err(e) => {
            warn!("Failed to get Deployment {}: {}", deployment_name, e);
            None
        }
    }
}

/// Gets selector labels from a StatefulSet
async fn get_statefulset_selector(
    statefulset_name: &str,
    namespace: &str,
    client: &Client,
) -> Option<BTreeMap<String, String>> {
    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);

    match sts_api.get(statefulset_name).await {
        Ok(statefulset) => {
            let selectors = statefulset.spec.and_then(|spec| spec.selector.match_labels);
            if selectors.is_none() {
                debug!(
                    "StatefulSet {} has no match_labels in selector",
                    statefulset_name
                );
            } else {
                debug!(
                    "StatefulSet {} selector labels: {:?}",
                    statefulset_name, selectors
                );
            }
            selectors
        }
        Err(e) => {
            warn!("Failed to get StatefulSet {}: {}", statefulset_name, e);
            None
        }
    }
}

/// Gets selector labels from a DaemonSet
async fn get_daemonset_selector(
    daemonset_name: &str,
    namespace: &str,
    client: &Client,
) -> Option<BTreeMap<String, String>> {
    let ds_api: Api<DaemonSet> = Api::namespaced(client.clone(), namespace);

    match ds_api.get(daemonset_name).await {
        Ok(daemonset) => {
            let selectors = daemonset.spec.and_then(|spec| spec.selector.match_labels);
            if selectors.is_none() {
                debug!(
                    "DaemonSet {} has no match_labels in selector",
                    daemonset_name
                );
            } else {
                debug!(
                    "DaemonSet {} selector labels: {:?}",
                    daemonset_name, selectors
                );
            }
            selectors
        }
        Err(e) => {
            warn!("Failed to get DaemonSet {}: {}", daemonset_name, e);
            None
        }
    }
}

/// Traces a ReplicaSet to its Deployment and gets the selector
async fn get_deployment_selector_from_replicaset(
    replicaset_name: &str,
    namespace: &str,
    client: &Client,
) -> Option<BTreeMap<String, String>> {
    let rs_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);

    match rs_api.get(replicaset_name).await {
        Ok(replicaset) => {
            if let Some(owner_references) = &replicaset.metadata.owner_references {
                for owner in owner_references {
                    if owner.kind == "Deployment" {
                        return get_deployment_selector(&owner.name, namespace, client).await;
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to get ReplicaSet {}: {}", replicaset_name, e);
        }
    }

    None
}

/// Traces a ReplicaSet to its Deployment and gets both name and selector
async fn get_deployment_name_and_selector_from_replicaset(
    replicaset_name: &str,
    namespace: &str,
    client: &Client,
) -> Option<(String, BTreeMap<String, String>)> {
    let rs_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);

    match rs_api.get(replicaset_name).await {
        Ok(replicaset) => {
            if let Some(owner_references) = &replicaset.metadata.owner_references {
                for owner in owner_references {
                    if owner.kind == "Deployment" {
                        if let Some(selectors) =
                            get_deployment_selector(&owner.name, namespace, client).await
                        {
                            return Some((owner.name.clone(), selectors));
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to get ReplicaSet {}: {}", replicaset_name, e);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_ip(ip: &str) -> PodIP {
        PodIP { ip: ip.to_string() }
    }

    #[test]
    fn collect_pod_ips_single_stack() {
        assert_eq!(
            collect_pod_ips(Some(&[pod_ip("10.244.1.5")]), "10.244.1.5"),
            vec!["10.244.1.5".to_string()]
        );
    }

    #[test]
    fn collect_pod_ips_dual_stack_keeps_both_primary_first() {
        // The regression this guards: reading only status.podIP dropped
        // the IPv6 address, so eBPF flows on it matched no pod and their
        // generated rules degraded to ipBlocks.
        assert_eq!(
            collect_pod_ips(
                Some(&[pod_ip("10.244.1.5"), pod_ip("fd00:10:244::5")]),
                "10.244.1.5"
            ),
            vec!["10.244.1.5".to_string(), "fd00:10:244::5".to_string()]
        );
    }

    #[test]
    fn collect_pod_ips_falls_back_when_pod_ips_absent() {
        assert_eq!(
            collect_pod_ips(None, "10.244.1.5"),
            vec!["10.244.1.5".to_string()]
        );
    }

    #[test]
    fn collect_pod_ips_never_loses_the_primary() {
        // podIPs[0] is contractually podIP, but the contract is not the
        // implementation. Even a list that omits or reorders it must
        // leave the address the rest of the controller keys on first.
        assert_eq!(
            collect_pod_ips(Some(&[pod_ip("fd00::5")]), "10.244.1.5"),
            vec!["10.244.1.5".to_string(), "fd00::5".to_string()]
        );
    }

    #[test]
    fn collect_pod_ips_canonicalises_and_dedupes() {
        assert_eq!(
            collect_pod_ips(
                Some(&[pod_ip("FD00:0:0:0:0:0:0:5"), pod_ip("fd00::5")]),
                "fd00::5"
            ),
            vec!["fd00::5".to_string()]
        );
    }

    // should_process_pod is the namespace-exclusion gate the watcher
    // uses to ignore (for example) the kguardian and kube-system
    // namespaces. A regression here would either miss intended
    // exclusions (leak self-traffic into observations) or over-exclude
    // (drop traffic operators cared about).

    // parse_excluded_namespaces is the EXCLUDED_NAMESPACES env-var
    // parser. Pre-fix it was just `s.split(',').map(to_string)` —
    // operators who wrote `"kube-system, kguardian"` (the natural
    // human format with spaces after commas) got `[" kguardian"]`
    // which never matched any real namespace.

    #[test]
    fn parse_excluded_namespaces_handles_no_whitespace() {
        let got = parse_excluded_namespaces("kube-system,kguardian");
        assert_eq!(got, vec!["kube-system", "kguardian"]);
    }

    #[test]
    fn parse_excluded_namespaces_trims_whitespace_around_entries() {
        // Regression: this was the bug case. "kube-system, kguardian"
        // (with the space after the comma) silently produced
        // [" kguardian"] which never matched any real namespace.
        let got = parse_excluded_namespaces("kube-system, kguardian, monitoring");
        assert_eq!(got, vec!["kube-system", "kguardian", "monitoring"]);
    }

    #[test]
    fn parse_excluded_namespaces_filters_empty_segments() {
        // Operators sometimes leave a trailing comma or double-comma
        // by accident; both should produce no empty-string entries
        // that would match the empty namespace (which itself is
        // already filtered upstream, but defense in depth).
        let got = parse_excluded_namespaces("kube-system,,kguardian,");
        assert_eq!(got, vec!["kube-system", "kguardian"]);
    }

    #[test]
    fn parse_excluded_namespaces_empty_input_yields_empty() {
        let got = parse_excluded_namespaces("");
        assert!(
            got.is_empty(),
            "empty input must yield no entries; got {:?}",
            got
        );
    }

    #[test]
    fn parse_excluded_namespaces_only_whitespace_yields_empty() {
        let got = parse_excluded_namespaces("  ,  ,   ");
        assert!(
            got.is_empty(),
            "all-whitespace input must yield no entries; got {:?}",
            got
        );
    }

    #[test]
    fn parse_excluded_namespaces_preserves_internal_dashes_and_dots() {
        // Namespace names commonly contain dashes; one cluster I've
        // seen has dotted names too. The parser only splits on commas.
        let got = parse_excluded_namespaces("ingress-nginx, cert-manager.io , kube-public");
        assert_eq!(got, vec!["ingress-nginx", "cert-manager.io", "kube-public"]);
    }

    #[test]
    fn parse_lenient_bool_accepts_true_variants() {
        // bool::from_str rejects all of these; parse_lenient_bool must
        // accept them so an operator typing "True" or "YES" doesn't
        // silently flip their intent to the default.
        for v in [
            "true", "True", "TRUE", "tRuE", "1", "yes", "YES", "on", "ON",
        ] {
            assert!(parse_lenient_bool(v, false), "{v:?} must parse as true");
        }
    }

    #[test]
    fn parse_lenient_bool_accepts_false_variants() {
        for v in [
            "false", "False", "FALSE", "fAlSe", "0", "no", "NO", "off", "OFF",
        ] {
            assert!(!parse_lenient_bool(v, true), "{v:?} must parse as false");
        }
    }

    #[test]
    fn parse_lenient_bool_trims_surrounding_whitespace() {
        // Copy-paste artefacts (trailing newline from a multi-line
        // env value, leading space from a quoted YAML literal) must
        // not defeat parsing. Same defense applied across other env
        // reads in this controller.
        assert!(parse_lenient_bool(" true\n", false));
        assert!(!parse_lenient_bool("\tFALSE  ", true));
        assert!(parse_lenient_bool("  YES  ", false));
    }

    #[test]
    fn parse_lenient_bool_unknown_returns_default() {
        // Typo'd or unrecognised values fall back to the caller's
        // default. The IGNORE_DAEMONSET_TRAFFIC site uses true as the
        // default, so an operator typo at least gets the safe-default
        // behaviour (filter ON) rather than crashing or no-op'ing.
        assert!(parse_lenient_bool("maybe", true));
        assert!(!parse_lenient_bool("maybe", false));
        assert!(parse_lenient_bool("", true));
        assert!(!parse_lenient_bool("   ", false));
        assert!(parse_lenient_bool("2", true));
    }

    #[test]
    fn excluded_namespaces_skip_netns_but_keep_compute() {
        // Tracked namespace, compute on: both.
        assert_eq!(
            registration_plan(true, true),
            RegistrationPlan {
                netns: true,
                compute: true
            }
        );
        // Excluded namespace (e.g. kguardian itself): no traffic/syscalls,
        // but gauges and blame still work.
        assert_eq!(
            registration_plan(false, true),
            RegistrationPlan {
                netns: false,
                compute: true
            }
        );
        // Compute off: excluded namespaces register nothing at all.
        assert_eq!(
            registration_plan(false, false),
            RegistrationPlan {
                netns: false,
                compute: false
            }
        );
        assert_eq!(
            registration_plan(true, false),
            RegistrationPlan {
                netns: true,
                compute: false
            }
        );
    }

    #[test]
    fn should_process_pod_includes_when_no_namespace() {
        let excluded = vec!["kguardian".into(), "kube-system".into()];
        assert!(should_process_pod(&None, &excluded));
    }

    #[test]
    fn should_process_pod_includes_when_excluded_list_empty() {
        let excluded: Vec<String> = vec![];
        assert!(should_process_pod(&Some("any".into()), &excluded));
    }

    #[test]
    fn should_process_pod_excludes_listed_namespace() {
        let excluded = vec!["kguardian".into(), "kube-system".into()];
        assert!(!should_process_pod(&Some("kguardian".into()), &excluded));
        assert!(!should_process_pod(&Some("kube-system".into()), &excluded));
    }

    #[test]
    fn should_process_pod_includes_unlisted_namespace() {
        let excluded = vec!["kguardian".into()];
        assert!(should_process_pod(&Some("prod".into()), &excluded));
        assert!(should_process_pod(&Some("default".into()), &excluded));
    }

    #[test]
    fn should_process_pod_namespace_match_is_exact() {
        // "kguardian-test" must NOT match "kguardian"; otherwise
        // exclusion would over-broadly skip namespaces sharing a prefix.
        let excluded = vec!["kguardian".into()];
        assert!(should_process_pod(
            &Some("kguardian-test".into()),
            &excluded
        ));
        assert!(should_process_pod(
            &Some("kguardian-staging".into()),
            &excluded
        ));
    }

    fn pod_with_annotation(key: &str, value: &str) -> Pod {
        let mut pod = Pod::default();
        pod.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(key.to_string(), value.to_string());
        pod
    }

    use CaptureLevel::*;

    #[test]
    fn effective_level_without_annotations_is_the_cluster_default() {
        for cluster in CaptureLevel::ALL {
            assert_eq!(effective_capture_level(&Pod::default(), cluster), cluster);
        }
    }

    #[test]
    fn effective_level_annotation_raises_above_cluster_default() {
        // cluster low + annotation high ⇒ high
        let pod = pod_with_annotation(SYSCALL_CAPTURE_ANNOTATION, "high");
        assert_eq!(effective_capture_level(&pod, Low), High);
        // and the string form is case/whitespace tolerant
        let pod = pod_with_annotation(SYSCALL_CAPTURE_ANNOTATION, " Full ");
        assert_eq!(effective_capture_level(&pod, Medium), Full);
    }

    #[test]
    fn effective_level_annotation_never_lowers() {
        // cluster full + annotation low ⇒ full
        let pod = pod_with_annotation(SYSCALL_CAPTURE_ANNOTATION, "low");
        assert_eq!(effective_capture_level(&pod, Full), Full);
        let pod = pod_with_annotation(SYSCALL_CAPTURE_ANNOTATION, "medium");
        assert_eq!(effective_capture_level(&pod, High), High);
        assert_eq!(effective_capture_level(&pod, Medium), Medium);
    }

    #[test]
    fn effective_level_invalid_annotation_uses_cluster_default() {
        for v in ["", "maximum", "true", "FULL!", "custom"] {
            let pod = pod_with_annotation(SYSCALL_CAPTURE_ANNOTATION, v);
            assert_eq!(effective_capture_level(&pod, Low), Low, "value {v:?}");
            assert_eq!(effective_capture_level(&pod, Full), Full, "value {v:?}");
        }
    }

    #[test]
    fn effective_level_legacy_seccomp_record_means_full() {
        for v in ["true", "1", "yes", "on", "True"] {
            let pod = pod_with_annotation(SECCOMP_RECORD_ANNOTATION, v);
            assert_eq!(effective_capture_level(&pod, Low), Full, "value {v:?}");
            assert_eq!(effective_capture_level(&pod, Custom), Full, "value {v:?}");
        }
        for v in ["false", "0", "no", "off", "", "maybe"] {
            let pod = pod_with_annotation(SECCOMP_RECORD_ANNOTATION, v);
            assert_eq!(effective_capture_level(&pod, Low), Low, "value {v:?}");
        }
        // The legacy alias wins over a lower syscall-capture value.
        let mut pod = pod_with_annotation(SECCOMP_RECORD_ANNOTATION, "true");
        pod.metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(SYSCALL_CAPTURE_ANNOTATION.into(), "low".into());
        assert_eq!(effective_capture_level(&pod, Low), Full);
    }

    #[test]
    fn effective_level_ignores_unrelated_annotations() {
        let pod = pod_with_annotation("example.com/other", "full");
        assert_eq!(effective_capture_level(&pod, Low), Low);
    }

    #[test]
    fn registration_flags_carry_tier_and_uid_generation() {
        let mut pod = Pod::default();
        pod.metadata.uid = Some("11111111-2222-3333-4444-555555555555".into());
        let f = pod_registration_flags(&pod, Medium);
        assert_eq!(f & pod_flags::POD_TRACKED, pod_flags::POD_TRACKED);
        assert_eq!(pod_flags::level(f), Some(Medium));
        assert_eq!(
            pod_flags::generation(f),
            pod_flags::generation_for_uid(pod.metadata.uid.as_deref())
        );
        // Same pod, resync ⇒ identical value (no spurious dedup reset);
        // a different pod on a reused inode ⇒ different generation.
        assert_eq!(f, pod_registration_flags(&pod, Medium));
        let mut other = Pod::default();
        other.metadata.uid = Some("11111111-2222-3333-4444-555555555556".into());
        assert_ne!(
            pod_flags::generation(f),
            pod_flags::generation(pod_registration_flags(&other, Medium))
        );
        // No UID (a hand-built test pod) still yields a tracked, tiered value.
        let f = pod_registration_flags(&Pod::default(), Full);
        assert_eq!(f, pod_flags::POD_TRACKED);
    }

    /// The `ContainerMap` entry has to carry the pod's Kubernetes
    /// identity, not just its status.
    ///
    /// This is the fix for a gap that made seccomp denial capture store
    /// nothing at all: `register_netns` filled `status` and left
    /// `info.config.metadata` at `Default`, so the UID the denial
    /// reporter sends to the broker was `""` on every node. The broker's
    /// storage key is `(pod_uid, syscall, action)`, so it rejects an
    /// empty UID rather than collapse every pod on the cluster into one
    /// row per syscall/action pair — correct of it, and invisible from
    /// both ends except for a warning about "unusable entries".
    ///
    /// Asserting all three fields, not just the uid: two empty fields
    /// sitting beside one populated one is how this was missed before.
    #[test]
    fn the_container_map_entry_carries_the_pods_uid_name_and_namespace() {
        let mut pod = Pod::default();
        pod.metadata.uid = Some("11111111-2222-3333-4444-555555555555".into());
        pod.metadata.name = Some("media-transform-7d9c8-abc12".into());
        pod.metadata.namespace = Some("media".into());

        let identity = pod_identity_metadata(&pod);

        assert_eq!(identity.uid, "11111111-2222-3333-4444-555555555555");
        assert_eq!(identity.name, "media-transform-7d9c8-abc12");
        assert_eq!(identity.namespace, "media");
    }

    /// A pod with no UID stays tracked.
    ///
    /// It cannot happen against a real apiserver, which assigns one at
    /// admission. If it somehow does, dropping the registration would
    /// trade a missing pod UID for a pod invisible to every probe —
    /// traffic and syscall capture both key off this entry. The row is
    /// registered, the condition is logged, and only its denial rows are
    /// refused downstream.
    #[test]
    fn a_pod_without_a_uid_is_still_registered_rather_than_dropped() {
        let mut pod = Pod::default();
        pod.metadata.name = Some("hand-built".into());

        let identity = pod_identity_metadata(&pod);

        assert_eq!(identity.name, "hand-built");
        assert!(
            identity.uid.is_empty(),
            "an absent UID must stay absent; inventing one here would hand the broker a \
             stable-looking identity that is not stable, which is worse than a rejected row"
        );
    }

    fn pod_with_owners(owners: Vec<OwnerReference>) -> Pod {
        let mut pod = Pod::default();
        pod.metadata.owner_references = if owners.is_empty() {
            None
        } else {
            Some(owners)
        };
        pod
    }

    fn owner(kind: &str) -> OwnerReference {
        OwnerReference {
            kind: kind.into(),
            api_version: "apps/v1".into(),
            name: "x".into(),
            uid: "u".into(),
            ..Default::default()
        }
    }

    /// A ready DaemonSet pod in `ns` with `hostNetwork` set as given and
    /// (dual-stack) `status.podIPs`.
    fn daemonset_pod(ns: &str, host_network: bool) -> Pod {
        use k8s_openapi::api::core::v1::{PodSpec, PodStatus};
        let mut pod = pod_with_owners(vec![owner("DaemonSet")]);
        pod.metadata.name = Some("ds-x".into());
        pod.metadata.namespace = Some(ns.into());
        pod.spec = Some(PodSpec {
            host_network: Some(host_network),
            ..Default::default()
        });
        pod.status = Some(PodStatus {
            pod_ip: Some("10.0.0.5".into()),
            pod_ips: Some(vec![
                PodIP {
                    ip: "10.0.0.5".into(),
                },
                PodIP {
                    ip: "fd00::5".into(),
                },
            ]),
            ..Default::default()
        });
        pod
    }

    fn excluded() -> Vec<String> {
        vec!["kguardian".to_string()]
    }

    #[test]
    fn ignore_map_host_network_daemonset_pod_is_never_ignored() {
        // The blind spot: a host-network DS pod's IP is the node IP, so
        // ignoring it ignored every pod's flows to any node address
        // (node-exporter, kubelet, etcd, apiserver).
        let pod = daemonset_pod("monitoring", true);
        assert_eq!(
            ignore_map_action(&pod, "10.0.0.5", true, &excluded()),
            IgnoreMapAction::HostNetwork
        );
    }

    #[test]
    fn ignore_map_pod_network_daemonset_pod_is_ignored_with_every_address() {
        let pod = daemonset_pod("kube-system", false);
        assert_eq!(
            ignore_map_action(&pod, "10.0.0.5", true, &excluded()),
            IgnoreMapAction::Ignore(vec!["10.0.0.5".into(), "fd00::5".into()])
        );
        // hostNetwork absent from the spec is the same as false.
        let mut pod = daemonset_pod("kube-system", false);
        pod.spec = None;
        assert!(matches!(
            ignore_map_action(&pod, "10.0.0.5", true, &excluded()),
            IgnoreMapAction::Ignore(_)
        ));
    }

    #[test]
    fn ignore_map_excluded_namespace_daemonset_pod_is_not_ignored() {
        // The gate used to run only AFTER the insertion, so excluding
        // kguardian did not keep the controller's own node IP out.
        for hn in [true, false] {
            let pod = daemonset_pod("kguardian", hn);
            assert_eq!(
                ignore_map_action(&pod, "10.0.0.5", true, &excluded()),
                IgnoreMapAction::None,
                "hostNetwork={hn}"
            );
        }
    }

    #[test]
    fn ignore_map_is_untouched_when_disabled_or_not_a_daemonset() {
        let pod = daemonset_pod("kube-system", false);
        assert_eq!(
            ignore_map_action(&pod, "10.0.0.5", false, &excluded()),
            IgnoreMapAction::None
        );
        let mut pod = daemonset_pod("kube-system", true);
        pod.metadata.owner_references = Some(vec![owner("ReplicaSet")]);
        assert_eq!(
            ignore_map_action(&pod, "10.0.0.5", true, &excluded()),
            IgnoreMapAction::None
        );
    }

    #[test]
    fn is_host_network_reads_spec_and_defaults_false() {
        assert!(!is_host_network(&Pod::default()));
        assert!(!is_host_network(&daemonset_pod("a", false)));
        assert!(is_host_network(&daemonset_pod("a", true)));
    }

    #[test]
    fn is_backed_by_daemonset_no_owner_refs() {
        let pod = pod_with_owners(vec![]);
        assert!(!is_backed_by_daemonset(&pod));
    }

    #[test]
    fn is_backed_by_daemonset_replicaset_only() {
        let pod = pod_with_owners(vec![owner("ReplicaSet")]);
        assert!(!is_backed_by_daemonset(&pod));
    }

    #[test]
    fn is_backed_by_daemonset_direct() {
        let pod = pod_with_owners(vec![owner("DaemonSet")]);
        assert!(is_backed_by_daemonset(&pod));
    }

    #[test]
    fn is_backed_by_daemonset_among_multiple_owners() {
        let pod = pod_with_owners(vec![owner("ReplicaSet"), owner("DaemonSet")]);
        assert!(is_backed_by_daemonset(&pod));
    }

    fn controller_owner(kind: &str, name: &str) -> OwnerReference {
        OwnerReference {
            kind: kind.into(),
            api_version: "apps/v1".into(),
            name: name.into(),
            uid: "u".into(),
            controller: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn classify_owner_none_without_refs() {
        assert_eq!(classify_owner(None), OwnerClass::None);
        assert_eq!(classify_owner(Some(&[])), OwnerClass::None);
    }

    #[test]
    fn classify_owner_direct_kinds() {
        for kind in [
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "ReplicationController",
        ] {
            assert_eq!(
                classify_owner(Some(&[controller_owner(kind, "app")])),
                OwnerClass::Direct(kind.to_string(), "app".to_string())
            );
        }
    }

    #[test]
    fn classify_owner_replicaset_and_job_need_tracing() {
        assert_eq!(
            classify_owner(Some(&[controller_owner("ReplicaSet", "app-7d9f")])),
            OwnerClass::ViaReplicaSet("app-7d9f".to_string())
        );
        assert_eq!(
            classify_owner(Some(&[controller_owner("Job", "nightly-28919")])),
            OwnerClass::ViaJob("nightly-28919".to_string())
        );
    }

    #[test]
    fn classify_owner_ignores_non_controller_refs() {
        // A plain (non-controller) ownerReference does not identify the
        // workload — e.g. a pod that a custom operator merely labels as
        // owned. Only `controller: true` counts.
        let mut plain = controller_owner("Deployment", "app");
        plain.controller = None;
        assert_eq!(classify_owner(Some(&[plain])), OwnerClass::None);
    }

    #[test]
    fn classify_owner_unknown_controller_kind_is_none() {
        // A CRD-based controller we don't model (e.g. Rollout, CloneSet):
        // better to leave the workload unattributed than to key a
        // profile on something we can't reason about.
        assert_eq!(
            classify_owner(Some(&[controller_owner("Rollout", "app")])),
            OwnerClass::None
        );
    }

    // pod_unready is mis-named: it returns Some(container_ids) when
    // the pod IS ready and None when unready / status missing.
    // Renaming would be churn; document and pin the contract instead.
    use k8s_openapi::api::core::v1::{ContainerStatus, PodCondition, PodStatus};

    fn pod_with_status(status: PodStatus) -> Pod {
        Pod {
            status: Some(status),
            ..Pod::default()
        }
    }

    #[test]
    fn compute_opt_out_annotation_is_off_only() {
        let mut p = Pod::default();
        assert!(!compute_opted_out(&p));
        p.metadata.annotations = Some(
            [(COMPUTE_ANNOTATION.to_string(), " OFF ".to_string())]
                .into_iter()
                .collect(),
        );
        assert!(compute_opted_out(&p));
        p.metadata.annotations = Some(
            [(COMPUTE_ANNOTATION.to_string(), "on".to_string())]
                .into_iter()
                .collect(),
        );
        assert!(!compute_opted_out(&p));
    }

    #[test]
    fn container_resources_come_from_status_then_spec() {
        use k8s_openapi::api::core::v1::{Container, PodSpec};
        use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
        let q = |s: &str| Quantity(s.to_string());
        let spec_res = ResourceRequirements {
            requests: Some(
                [
                    ("cpu".to_string(), q("250m")),
                    ("memory".to_string(), q("128Mi")),
                ]
                .into_iter()
                .collect(),
            ),
            limits: Some(
                [
                    ("cpu".to_string(), q("1")),
                    ("memory".to_string(), q("1Gi")),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let mut pod = Pod {
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "api".into(),
                    resources: Some(spec_res),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    name: "api".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Pod::default()
        };
        assert_eq!(
            container_resources(&pod, "api"),
            ResourceSpec {
                cpu_request_millis: Some(250),
                cpu_limit_millis: Some(1000),
                memory_request_bytes: Some(128 << 20),
                memory_limit_bytes: Some(1 << 30),
            }
        );
        // Unknown container: nothing set.
        assert_eq!(container_resources(&pod, "nope"), ResourceSpec::default());
        // An in-place resize shows up in status.resources and wins.
        pod.status
            .as_mut()
            .unwrap()
            .container_statuses
            .as_mut()
            .unwrap()[0]
            .resources = Some(ResourceRequirements {
            limits: Some([("cpu".to_string(), q("2"))].into_iter().collect()),
            ..Default::default()
        });
        let r = container_resources(&pod, "api");
        assert_eq!(r.cpu_limit_millis, Some(2000));
        assert_eq!(r.cpu_request_millis, None);
        // Garbage quantities are unset, not zero.
        let bad = ResourceRequirements {
            requests: Some([("cpu".to_string(), q("lots"))].into_iter().collect()),
            ..Default::default()
        };
        assert_eq!(resource_spec_from(Some(&bad)), ResourceSpec::default());
    }

    #[test]
    fn prune_retires_only_pods_registered_before_the_list_and_missing_from_it() {
        use crate::compute_registry::ComputeRegistry;
        let map: ComputeMap = Arc::new(ComputeRegistry::new());
        let mk = |uid: &str, id: u64| ContainerCompute {
            pod_uid: uid.into(),
            namespace: "n".into(),
            pod_name: "p".into(),
            container_name: "c".into(),
            container_id: "x".into(),
            pid: 1,
            cgroup_path: "x".into(),
            cgroup_id: id,
            resources: ResourceSpec::default(),
            node: "n".into(),
        };
        map.insert_container(mk("a", 1));
        map.insert_container(mk("b", 2));
        let listed_at = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        // Registered by the watch while the resync walk was running:
        // absent from the list, but newer than it.
        map.insert_container(mk("c", 3));
        let live = ["b".to_string()].into_iter().collect();
        assert_eq!(prune_compute_registry(&map, &live, listed_at), 1);
        assert!(map.lookup_cgroup(1).is_none(), "a: old and absent → pruned");
        assert!(map.lookup_cgroup(2).is_some(), "b: listed → kept");
        assert!(
            map.lookup_cgroup(3).is_some(),
            "c: newer than the list → kept"
        );
        assert_eq!(prune_compute_registry(&map, &live, listed_at), 0);
    }

    #[test]
    fn pod_unready_no_status_returns_none() {
        assert_eq!(pod_unready(&Pod::default()), None);
    }

    #[test]
    fn pod_unready_ready_false_returns_none() {
        let cond = PodCondition {
            type_: "Ready".into(),
            status: "False".into(),
            message: Some("crashloop".into()),
            ..Default::default()
        };
        let st = PodStatus {
            conditions: Some(vec![cond]),
            container_statuses: Some(vec![ContainerStatus {
                container_id: Some("docker://abc".into()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert_eq!(pod_unready(&pod_with_status(st)), None);
    }

    #[test]
    fn pod_unready_ready_true_returns_container_ids() {
        let cond = PodCondition {
            type_: "Ready".into(),
            status: "True".into(),
            ..Default::default()
        };
        let st = PodStatus {
            conditions: Some(vec![cond]),
            container_statuses: Some(vec![ContainerStatus {
                container_id: Some("containerd://hash1".into()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert_eq!(
            pod_unready(&pod_with_status(st)),
            Some(vec!["containerd://hash1".to_string()])
        );
    }

    #[test]
    fn pod_unready_skips_containers_without_id() {
        // Mid-startup containers have no containerID populated yet.
        // Those entries are silently skipped — only fully realised
        // containers contribute IDs.
        let st = PodStatus {
            container_statuses: Some(vec![
                ContainerStatus {
                    container_id: Some("ok-1".into()),
                    ..Default::default()
                },
                ContainerStatus {
                    container_id: None,
                    ..Default::default()
                },
                ContainerStatus {
                    container_id: Some("ok-2".into()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        assert_eq!(
            pod_unready(&pod_with_status(st)),
            Some(vec!["ok-1".to_string(), "ok-2".to_string()])
        );
    }

    #[test]
    fn pod_unready_no_containers_returns_none() {
        let st = PodStatus {
            container_statuses: None,
            ..Default::default()
        };
        assert_eq!(pod_unready(&pod_with_status(st)), None);
    }
}
