use crate::{api_post_call, Error, PodDetail};
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use reqwest::Client as ReqwestClient;
use std::collections::HashSet;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

const RECONCILE_INTERVAL_SECS: u64 = 60; // Reconcile every 60 seconds

/// Identifier used to match a DB pod against the live cluster pod list.
/// Namespace + name together — pod names are unique only within a
/// namespace, so name-only comparison silently misses cross-namespace
/// collisions (e.g. prod/web-1 vs staging/web-1).
type PodIdent = (Option<String>, String);

/// Returns the names of DB pods that no longer exist in the cluster.
/// Pure function so the comparison logic is unit-testable without a
/// live broker / kube client. Kept for the historical name-based
/// tests; new code should prefer find_dead_pod_details which yields
/// the full row (with pod_ip) for the mark-dead RPC.
fn find_dead_pods<'a>(db_pods: &'a [PodDetail], running: &HashSet<PodIdent>) -> Vec<&'a str> {
    find_dead_pod_details(db_pods, running)
        .into_iter()
        .map(|p| p.pod_name.as_str())
        .collect()
}

/// Returns the full PodDetail rows that are dead — namespace+name no
/// longer matches anything live in the cluster. The caller uses each
/// entry's pod_ip to send a precise mark-dead RPC to the broker
/// rather than the prior name-only RPC that flagged every historical
/// row (including a live restarted instance) dead.
fn find_dead_pod_details<'a>(
    db_pods: &'a [PodDetail],
    running: &HashSet<PodIdent>,
) -> Vec<&'a PodDetail> {
    db_pods
        .iter()
        .filter(|p| {
            let ident = (p.pod_namespace.clone(), p.pod_name.clone());
            !running.contains(&ident)
        })
        .collect()
}

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
    // debug not info — this fires every RECONCILE_INTERVAL_SECS (60s)
    // forever, which is 1440 daily per controller per node. The
    // outcome of the reconcile pass is already logged conditionally
    // below (info when pods were marked dead, debug for "no changes"),
    // so the per-tick "starting" line is pure noise at INFO.
    debug!("reconcile_pods: starting pod reconciliation for node: {}", node_name);

    // Get list of pods from database for this node (only alive pods).
    // Trim trailing slashes from broker_url so a configured
    // API_ENDPOINT="http://broker:9090/" doesn't produce a doubled
    // slash in the URL — same robustness pattern applied to
    // api_post_call's build_url helper.
    let url = format!("{}/pod/list/{}", broker_url.trim_end_matches('/'), node_name);
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

    // Build set of currently running (namespace, name) pairs from
    // Kubernetes. The previous version keyed on name only, which
    // silently failed when two pods on the same node shared a name
    // across namespaces (e.g. prod/web-1 and staging/web-1).
    let running_pods: HashSet<PodIdent> = pod_list
        .items
        .iter()
        .filter_map(|pod| {
            pod.metadata
                .name
                .clone()
                .map(|n| (pod.metadata.namespace.clone(), n))
        })
        .collect();

    debug!(
        "Node {} - Running pods in cluster: {}, DB pods (alive): {}",
        node_name,
        running_pods.len(),
        db_pods.len()
    );

    // Mark pods as dead if they're in DB but not running in cluster.
    // find_dead_pods returns the full PodDetail entries we need —
    // pod_ip in particular, which lets the broker target the exact
    // pod_details row (the PK). Without pod_ip the broker falls back
    // to a name-only filter that marks every historical row with
    // that name dead — including a live restarted instance with the
    // same name and a new IP.
    let dead = find_dead_pod_details(&db_pods, &running_pods);
    let mut marked_dead = 0;
    for db_pod in dead {
        info!(
            "Pod {}/{} (ip={}) is no longer running on node {}, marking as dead",
            db_pod.pod_namespace.as_deref().unwrap_or("?"),
            db_pod.pod_name,
            db_pod.pod_ip,
            node_name
        );
        let mark_dead_req = serde_json::json!({
            "pod_name": db_pod.pod_name,
            "pod_ip": db_pod.pod_ip,
        });
        if let Err(e) = api_post_call(mark_dead_req, "pod/mark_dead").await {
            error!("Failed to mark pod {} as dead: {}", db_pod.pod_name, e);
        } else {
            marked_dead += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;

    fn db_pod(namespace: Option<&str>, name: &str) -> PodDetail {
        PodDetail {
            pod_ip: "10.0.0.1".to_string(),
            pod_name: name.to_string(),
            pod_namespace: namespace.map(str::to_string),
            pod_obj: None,
            time_stamp: NaiveDateTime::default(),
            node_name: "node-a".to_string(),
            is_dead: false,
            pod_identity: None,
            workload_selector_labels: None,
        }
    }

    fn ident(namespace: Option<&str>, name: &str) -> PodIdent {
        (namespace.map(str::to_string), name.to_string())
    }

    #[test]
    fn find_dead_pods_empty_inputs() {
        let dead = find_dead_pods(&[], &HashSet::new());
        assert!(dead.is_empty());
    }

    #[test]
    fn find_dead_pods_all_alive() {
        let pods = vec![
            db_pod(Some("prod"), "web-1"),
            db_pod(Some("staging"), "api-2"),
        ];
        let mut running = HashSet::new();
        running.insert(ident(Some("prod"), "web-1"));
        running.insert(ident(Some("staging"), "api-2"));

        let dead = find_dead_pods(&pods, &running);
        assert!(dead.is_empty());
    }

    #[test]
    fn find_dead_pods_marks_missing_only() {
        let pods = vec![
            db_pod(Some("prod"), "web-1"),
            db_pod(Some("prod"), "web-2"),
            db_pod(Some("prod"), "web-3"),
        ];
        let mut running = HashSet::new();
        running.insert(ident(Some("prod"), "web-1"));
        running.insert(ident(Some("prod"), "web-3"));

        let dead = find_dead_pods(&pods, &running);
        assert_eq!(dead, vec!["web-2"]);
    }

    #[test]
    fn find_dead_pods_distinguishes_by_namespace() {
        // The bug case: two pods with the same name in different
        // namespaces. The cluster has prod/web-1 alive but
        // staging/web-1 has been deleted. The DB still has the
        // staging entry. Pre-fix the comparison was name-only — both
        // db entries (if both existed) would see "web-1" in running
        // and get marked alive. The reconciler's job is to mark
        // staging/web-1 dead — that requires namespace-aware compare.
        let pods = vec![
            db_pod(Some("prod"), "web-1"),
            db_pod(Some("staging"), "web-1"),
        ];
        let mut running = HashSet::new();
        running.insert(ident(Some("prod"), "web-1"));
        // staging/web-1 deliberately absent

        let dead = find_dead_pods(&pods, &running);
        assert_eq!(dead.len(), 1, "exactly one pod (staging/web-1) must be marked dead");
        // Both share the same name, so the name alone doesn't tell
        // us which one — but the find should produce one entry, not
        // zero (the bug) and not two.
        assert_eq!(dead[0], "web-1");
    }

    #[test]
    fn find_dead_pods_handles_db_pod_with_no_namespace() {
        // Older DB rows (pre pod_namespace migration) may have None.
        // Match against cluster pods that also have no namespace —
        // edge but defended against panicking.
        let pods = vec![db_pod(None, "orphan")];
        let mut running = HashSet::new();
        running.insert(ident(None, "orphan"));

        let dead = find_dead_pods(&pods, &running);
        assert!(dead.is_empty(), "None-namespace pod must match against None-namespace cluster entry");
    }

    #[test]
    fn find_dead_pods_db_namespace_mismatch_is_dead() {
        // DB says staging/web-1 but cluster only has prod/web-1.
        // Must mark dead — the DB row doesn't match anything live.
        let pods = vec![db_pod(Some("staging"), "web-1")];
        let mut running = HashSet::new();
        running.insert(ident(Some("prod"), "web-1")); // same name, different ns

        let dead = find_dead_pods(&pods, &running);
        assert_eq!(dead, vec!["web-1"]);
    }

    #[test]
    fn find_dead_pod_details_returns_full_rows_for_caller() {
        // The reconciler relies on the full PodDetail (not just the
        // name) to drive the iteration-66 mark-dead RPC — it sends
        // pod_ip alongside pod_name for race-window protection.
        // Pin that find_dead_pod_details yields references back to
        // the original db_pods entries (not copies, not just names).
        let pods = vec![
            db_pod(Some("prod"), "web-1"),  // alive
            db_pod(Some("prod"), "web-2"),  // dead
        ];
        let mut running = HashSet::new();
        running.insert(ident(Some("prod"), "web-1"));

        let dead = find_dead_pod_details(&pods, &running);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].pod_name, "web-2");
        // pod_ip must be accessible — the reconciler reads it for
        // the precise mark-dead RPC.
        assert_eq!(dead[0].pod_ip, "10.0.0.1");
        // pod_namespace also accessible for the log line.
        assert_eq!(dead[0].pod_namespace.as_deref(), Some("prod"));
    }
}
