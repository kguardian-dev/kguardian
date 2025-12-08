use crate::{api_post_call, Error, PodDetail, PodInfo, PodInspect};
use chrono::Utc;
use dashmap::DashMap;
use futures::TryStreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    runtime::{reflector::Lookup, watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
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
    watcher(pods, wc)
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
                    info!("Pod {:?}, inode num {:?}", p.name(), inum);
                }
                Ok(())
            }
        })
        .await?;
    Ok(())
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
                info!("Ignoring daemonset pod: {}, {}", pod.name_any(), pod_ip);

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
        .map_or(false, |ns| excluded_namespaces.contains(ns))
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

async fn update_pods_details(pod: &Pod, node_name: &str, client: &Client) -> Result<Option<String>, Error> {
    let pod_name = pod.name_any();
    let pod_namespace = pod.metadata.namespace.to_owned();
    let pod_status = pod.status.as_ref().unwrap();
    let mut pod_ip_address: Option<String> = None;
    if pod_status.pod_ip.is_some() {
        let pod_ip = pod_status.pod_ip.as_ref().unwrap();

        // Extract pod identity and workload selector labels
        let (pod_identity, workload_selector_labels) = extract_pod_identity_and_selectors(pod, client).await;

        info!(
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
    pod_ip: &String,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Option<u64> {
    for con_id in con_ids {
        let pod_info = create_pod_info(pod, pod_ip);
        let pod_inspect = PodInspect {
            status: pod_info,
            ..Default::default()
        };
        info!("pod name {}", pod.name_any());
        if let Some(pod_inspect) = pod_inspect.get_pod_inspect(con_id).await {
            if let Some(inode_num) = pod_inspect.inode_num {
                info!(
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
async fn extract_pod_identity_and_selectors(pod: &Pod, client: &Client) -> (Option<String>, Option<BTreeMap<String, String>>) {
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
async fn trace_owner_to_workload_with_selectors(pod: &Pod, client: &Client) -> Option<BTreeMap<String, String>> {
    let owner_references = pod.metadata.owner_references.as_ref()?;
    let namespace = pod.metadata.namespace.as_ref()?;

    debug!("Tracing owner references for pod {} to get selector labels", pod.name_any());

    for owner in owner_references {
        debug!("Processing owner: kind={}, name={}", owner.kind, owner.name);
        match owner.kind.as_str() {
            "ReplicaSet" => {
                // Trace ReplicaSet to Deployment and get selector
                if let Some(selectors) = get_deployment_selector_from_replicaset(
                    &owner.name,
                    namespace,
                    client
                ).await {
                    return Some(selectors);
                }
            }
            "Deployment" => {
                if let Some(selectors) = get_deployment_selector(&owner.name, namespace, client).await {
                    return Some(selectors);
                }
            }
            "StatefulSet" => {
                if let Some(selectors) = get_statefulset_selector(&owner.name, namespace, client).await {
                    return Some(selectors);
                }
            }
            "DaemonSet" => {
                debug!("Found DaemonSet owner: {}", owner.name);
                if let Some(selectors) = get_daemonset_selector(&owner.name, namespace, client).await {
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
async fn trace_owner_to_workload_with_selectors_and_name(pod: &Pod, client: &Client) -> (Option<String>, Option<BTreeMap<String, String>>) {
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
                if let Some((name, selectors)) = get_deployment_name_and_selector_from_replicaset(
                    &owner.name,
                    namespace,
                    client
                ).await {
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
            let selectors = deployment.spec
                .and_then(|spec| spec.selector.match_labels);
            if selectors.is_none() {
                debug!("Deployment {} has no match_labels in selector", deployment_name);
            } else {
                debug!("Deployment {} selector labels: {:?}", deployment_name, selectors);
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
            let selectors = statefulset.spec
                .and_then(|spec| spec.selector.match_labels);
            if selectors.is_none() {
                debug!("StatefulSet {} has no match_labels in selector", statefulset_name);
            } else {
                debug!("StatefulSet {} selector labels: {:?}", statefulset_name, selectors);
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
            let selectors = daemonset.spec.map(|spec| spec.selector.match_labels).flatten();
            if selectors.is_none() {
                debug!("DaemonSet {} has no match_labels in selector", daemonset_name);
            } else {
                debug!("DaemonSet {} selector labels: {:?}", daemonset_name, selectors);
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
                        if let Some(selectors) = get_deployment_selector(&owner.name, namespace, client).await {
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
