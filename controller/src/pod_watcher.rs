use crate::{api_post_call, Error, PodDetail, PodInfo, PodInspect};
use chrono::Utc;
use dashmap::DashMap;
use futures::TryStreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::ListParams,
    runtime::{reflector::Lookup, watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use tokio::sync::mpsc;
pub async fn watch_pods(
    node_name: String,
    tx: mpsc::Sender<u64>,
    container_map: Arc<DashMap<u64, PodInspect>>,
    excluded_namespaces: &[String],
    sender_ip: mpsc::Sender<String>,
    ignore_daemonset_traffic: bool,
) -> Result<(), Error> {
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
        excluded_namespaces.to_vec(),
        sender_ip.clone(),
        ignore_daemonset_traffic,
        c.clone(),
    );

    let watch = watcher(pods, wc)
        .applied_objects()
        .default_backoff()
        .try_for_each(|p| {
            let t = tx.clone();
            let sender_ip = sender_ip.clone();
            let container_map = Arc::clone(&container_map);
            let node_name = node_name.clone();
            let c = c.clone();
            async move {
                if let Some(inum) = process_pod(
                    &p,
                    container_map,
                    excluded_namespaces,
                    sender_ip,
                    ignore_daemonset_traffic,
                    &node_name,
                    &c,
                )
                .await
                {
                    if let Err(e) = t.send(inum).await {
                        tracing::error!("Failed to send inode number: {:?}", e);
                    }
                    // debug not info — fires on every pod event that
                    // passes the per-node + namespace-exclusion filter,
                    // including the full re-sync on controller startup
                    // AND every pod-status transition (rolling deploys
                    // generate hundreds per minute on busy nodes). The
                    // inode-to-pod mapping is debug-relevant only when
                    // chasing eBPF event correlation issues; operators
                    // under default RUST_LOG=info don't need it.
                    debug!("Pod {:?}, inode num {:?}", p.name(), inum);
                }
                Ok(())
            }
        });

    // Run both concurrently. If either ends (watch stream error, or the
    // resync list fails fatally), propagate so main's try_join! exits and
    // the kubelet restarts the controller for a clean re-sync.
    tokio::try_join!(async move { watch.await.map_err(Error::from) }, resync)?;
    Ok(())
}

/// Periodic re-list of this node's pods, registering any the streaming
/// watch missed. The watch is best-effort (field-selector watches drop
/// scheduled-onto-node transitions); this LIST-based pass is the
/// reliable backstop so new workloads are captured within one interval.
#[allow(clippy::too_many_arguments)]
async fn resync_pods(
    pods: Api<Pod>,
    node_name: String,
    tx: mpsc::Sender<u64>,
    container_map: Arc<DashMap<u64, PodInspect>>,
    excluded_namespaces: Vec<String>,
    sender_ip: mpsc::Sender<String>,
    ignore_daemonset_traffic: bool,
    client: Client,
) -> Result<(), Error> {
    const RESYNC_INTERVAL: Duration = Duration::from_secs(60);
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node_name));
    info!(
        "Pod resync safety-net active: re-listing on-node pods every {}s",
        RESYNC_INTERVAL.as_secs()
    );
    loop {
        tokio::time::sleep(RESYNC_INTERVAL).await;
        match pods.list(&lp).await {
            Ok(list) => {
                let mut processed = 0u32;
                for pod in &list.items {
                    if let Some(inum) = process_pod(
                        pod,
                        Arc::clone(&container_map),
                        &excluded_namespaces,
                        sender_ip.clone(),
                        ignore_daemonset_traffic,
                        &node_name,
                        &client,
                    )
                    .await
                    {
                        if let Err(e) = tx.send(inum).await {
                            error!("resync: failed to send inode number: {:?}", e);
                        }
                        processed += 1;
                    }
                }
                debug!("Pod resync pass processed {} on-node pods", processed);
            }
            // Transient list failures (apiserver blip) are non-fatal —
            // the next tick retries. Only the watch task failing restarts.
            Err(e) => warn!("Pod resync list failed (will retry next tick): {}", e),
        }
    }
}

async fn process_pod(
    pod: &Pod,
    container_map: Arc<DashMap<u64, PodInspect>>,
    excluded_namespaces: &[String],
    sender_ip: mpsc::Sender<String>,
    ignore_daemonset_traffic: bool,
    node_name: &str,
    client: &Client,
) -> Option<u64> {
    if let Some(con_ids) = pod_unready(pod) {
        let pod_ip = update_pods_details(pod, node_name, client).await;
        if let Ok(Some(pod_ip)) = pod_ip {
            if ignore_daemonset_traffic && is_backed_by_daemonset(pod) {
                // debug not info — fires per daemonset pod event,
                // including the full re-sync (kube-proxy, calico-node,
                // and the kguardian-controller itself on every node).
                // Operators set IGNORE_DAEMONSET_TRAFFIC=true to NOT
                // see this stream by default.
                debug!("Ignoring daemonset pod: {}, {}", pod.name_any(), pod_ip);

                if let Err(e) = sender_ip.send(pod_ip.clone()).await {
                    error!("Failed to send pod ip: {}", e);
                }
            }
            if should_process_pod(&pod.metadata.namespace, excluded_namespaces) {
                return process_container_ids(&con_ids, pod, &pod_ip, container_map).await;
            }
        }
    }

    None
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

async fn update_pods_details(
    pod: &Pod,
    node_name: &str,
    client: &Client,
) -> Result<Option<String>, Error> {
    let pod_name = pod.name_any();
    let pod_namespace = pod.metadata.namespace.to_owned();
    let pod_status = match pod.status.as_ref() {
        Some(status) => status,
        None => return Ok(None),
    };
    let mut pod_ip_address: Option<String> = None;
    if let Some(pod_ip) = pod_status.pod_ip.as_ref() {
        // Extract pod identity and workload selector labels
        let (pod_identity, workload_selector_labels) =
            extract_pod_identity_and_selectors(pod, client).await;

        // debug not info — fires for every pod-watcher event with a
        // pod_ip (i.e. essentially every status transition during a
        // rollout). The identity / workload-selector inference is
        // debug-relevant when validating what kguardian inferred from
        // a pod's labels + owner refs, not steady-state operator info.
        debug!(
            "Pod {}: identity={:?}, workload_selector_labels={:?}",
            pod_name, pod_identity, workload_selector_labels
        );

        let z = PodDetail {
            pod_ip: pod_ip.to_string(),
            pod_name: pod_name.clone(),
            pod_namespace,
            pod_obj: Some(json!(pod)),
            time_stamp: Utc::now().naive_utc(),
            node_name: node_name.to_string(),
            is_dead: false,
            pod_identity,
            workload_selector_labels,
        };

        if let Err(e) = api_post_call(json!(z), "pod/spec").await {
            error!("Failed to post Pod details: {}", e);
        }
        pod_ip_address = Some(pod_ip.to_string());
        return Ok(pod_ip_address);
    }
    Ok(pod_ip_address)
}

async fn process_container_ids(
    con_ids: &[String],
    pod: &Pod,
    pod_ip: &str,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Option<u64> {
    for con_id in con_ids {
        let pod_info = create_pod_info(pod, pod_ip);
        let pod_inspect = PodInspect {
            status: pod_info,
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
                    "inode_num of pod {} is {}",
                    pod_inspect.status.pod_name, inode_num
                );
                // DashMap provides lock-free inserts!
                container_map.insert(inode_num, pod_inspect.clone());
                return Some(inode_num);
            }
        }
    }
    None
}

fn create_pod_info(pod: &Pod, pod_ip: &str) -> PodInfo {
    PodInfo {
        pod_name: pod.name_any(),
        pod_namespace: pod.metadata.namespace.to_owned(),
        pod_ip: pod_ip.to_string(),
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
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

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
