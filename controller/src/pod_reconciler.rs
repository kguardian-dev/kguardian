use crate::{api_post_call, Error, PodDetail};
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use reqwest::Client as ReqwestClient;
use std::collections::HashSet;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

const RECONCILE_INTERVAL_SECS: u64 = 60; // Reconcile every 60 seconds

/// Periodically reconcile pods on this node with the database
/// Marks pods as dead if they're no longer running on this node
pub async fn reconcile_pods_task(
    node_name: String,
    broker_url: String,
) -> Result<(), Error> {
    let mut ticker = interval(Duration::from_secs(RECONCILE_INTERVAL_SECS));
    let reqwest_client = ReqwestClient::new();
    let kube_client = Client::try_default().await?;

    loop {
        ticker.tick().await;

        if let Err(e) = reconcile_pods(&node_name, &broker_url, &reqwest_client, &kube_client).await {
            error!("Pod reconciliation failed: {}", e);
        }
    }
}

async fn reconcile_pods(
    node_name: &str,
    broker_url: &str,
    reqwest_client: &ReqwestClient,
    kube_client: &Client,
) -> Result<(), Error> {
    debug!("Starting pod reconciliation for node: {}", node_name);

    // Get list of pods from database for this node (only alive pods)
    let url = format!("{}/pod/list/{}", broker_url, node_name);
    let response = reqwest_client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Custom(format!("Failed to fetch pods from broker: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Custom(format!(
            "Broker returned error status: {}",
            response.status()
        )));
    }

    let db_pods: Vec<PodDetail> = response
        .json::<Vec<PodDetail>>()
        .await
        .map_err(|e| Error::Custom(format!("Failed to parse broker response: {}", e)))?;

    // Get list of currently running pods from Kubernetes API for this node
    let pods_api: Api<Pod> = Api::all(kube_client.clone());
    let list_params = kube::api::ListParams::default()
        .fields(&format!("spec.nodeName={}", node_name));

    let pod_list = pods_api
        .list(&list_params)
        .await
        .map_err(|e| Error::Custom(format!("Failed to list pods from Kubernetes: {}", e)))?;

    // Build set of currently running pod names from Kubernetes
    let running_pods: HashSet<String> = pod_list
        .items
        .iter()
        .filter_map(|pod| pod.metadata.name.clone())
        .collect();

    debug!(
        "Node {} - Running pods in cluster: {}, DB pods (alive): {}",
        node_name,
        running_pods.len(),
        db_pods.len()
    );

    // Mark pods as dead if they're in DB but not running in cluster
    let mut marked_dead = 0;
    for db_pod in db_pods {
        if !running_pods.contains(&db_pod.pod_name) {
            info!(
                "Pod {} is no longer running on node {}, marking as dead",
                db_pod.pod_name, node_name
            );

            let mark_dead_req = serde_json::json!({
                "pod_name": db_pod.pod_name
            });

            if let Err(e) = api_post_call(mark_dead_req, "pod/mark_dead").await {
                error!("Failed to mark pod {} as dead: {}", db_pod.pod_name, e);
            } else {
                marked_dead += 1;
            }
        }
    }

    if marked_dead > 0 {
        info!(
            "Reconciliation complete for node {}: marked {} pods as dead",
            node_name, marked_dead
        );
    } else {
        debug!("Reconciliation complete for node {}: no changes", node_name);
    }

    Ok(())
}
