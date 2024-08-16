use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    runtime::{reflector::Lookup, watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, PerfBufferBuilder,
};
use tcpprobe::{TcpProbeSkel, TcpProbeSkelBuilder};
use tracing::info;

use crate::{PodInfo, PodInspect};

pub mod tcpprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcp_probe.skel.rs"
    ));
}

pub async fn watch_pods(
    // container_map: Arc<Mutex<BTreeMap<u32, PodInspect>>>,
    node_name: String,
    tx: std::sync::mpsc::Sender<u64>,
    container_map: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Result<(), crate::Error> {
    let c = Client::try_default().await?;
    let pods: Api<Pod> = Api::all(c.clone());

    #[cfg(not(debug_assertions))]
    let wc = watcher::Config::default().fields(&format!("spec.nodeName={}", node_name));
    #[cfg(debug_assertions)]
    let wc = watcher::Config::default();

    // let ebpf = Arc::new(Mutex::new(ebpf));

    watcher(pods, wc)
        .applied_objects()
        .default_backoff()
        .try_for_each(|p| {
            let t = tx.clone();
            let container_map = Arc::clone(&container_map);
            async move {
                
                let inode_num = process_pod(&p, container_map).await;
                if let Some(inum) = inode_num {
                    _ = t.send(inum);
                    info!("Pod {:?}, inode num {:?}", p.name(), inum);
                }

                //let container_map = Arc::clone(&container_map);
                // let ebpf = Arc::clone(&ebpf);
                // let p = process_pod(&p, container_map, ebpf).await;
                // if let Err(e) = p {
                //dont panic and the error is already printed, so no point of reporting again
                // maybe find a better way of handling error
                //     error!("Error  processsing pod{}", e)
                // }

                Ok(())
            }
        })
        .await?;

    Ok(())
}

async fn process_pod(
    pod: &Pod,
    container_map: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Option<u64> {
    if let Some(con_ids) = pod_unready(pod) {
        
        let pod_ip = update_pods_details(pod).await;
        if should_process_pod(&pod.metadata.namespace) {
          
            if let Ok(Some(pod_ip)) = pod_ip {
                return process_container_ids(&con_ids, &pod, &pod_ip, container_map).await;
            }
        }
    }
    return None;
}

fn should_process_pod(namespace: &Option<String>) -> bool {
    // TODO : excluded_namespace needs to be paratermized
    let excluded_namespaces: [&str; 2] = ["kube-system", "kube-guardian"];
    !namespace
        .as_ref()
        .map_or(false, |ns| excluded_namespaces.contains(&ns.as_str()))
}

fn pod_unready(p: &Pod) -> Option<Vec<String>> {
    let status = p.status.as_ref().unwrap();
    if let Some(conds) = &status.conditions {
        let failed = conds
            .iter()
            .filter(|c| c.type_ == "Ready" && c.status == "False")
            .map(|c| c.message.clone().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",");
        if !failed.is_empty() {
            // if p.metadata.labels.as_ref().unwrap().contains_key("job-name") {
            //     return None; // ignore job based pods, they are meant to exit 0
            // }
            info!("Unready pod {}: {}", p.name_any(), failed);
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

async fn update_pods_details(pod: &Pod) -> Result<Option<String>, crate::Error> {
    let pod_name = pod.name_any();
    // let pod_namespace = pod.namespace();
    let pod_status = pod.status.as_ref().unwrap();
    let mut pod_ip_address: Option<String> = None;
    if pod_status.pod_ip.is_some() {
        let pod_ip = pod_status.pod_ip.as_ref().unwrap();
        // let z = PodDetail {
        //     pod_ip: pod_ip.to_string(),
        //     pod_name,
        //     pod_namespace,
        //     pod_obj: Some(json!(pod)),
        //     time_stamp: Utc::now().naive_utc(),
        // };
        // api_post_call(json!(z), "netpol/podspec").await?;
        pod_ip_address = Some(pod_ip.to_string());
        return Ok(pod_ip_address);
    }
    Ok(pod_ip_address)
}

async fn process_container_ids(
    con_ids: &[String],
    pod: &Pod,
    pod_ip: &String,
    container_map: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
) -> Option<u64> {
   
    for con_id in con_ids {
        let pod_info = create_pod_info(pod, pod_ip);
        let pod_inspect = PodInspect {
            status: pod_info,
            ..Default::default()
        };
        info!("pod name {}", pod.name_any());
        if let Some(pod_inspect) = pod_inspect.get_pod_inspect(&con_id).await {
            // get the inum of container
            let mut cm = container_map.lock().await;
            if let Some(inode_num) = pod_inspect.inode_num {
                info!(
                    "inode_num of pod {} is {}",
                    pod_inspect.status.pod_name, inode_num
                );
                cm.insert(inode_num, pod_inspect.clone());
                return Some(inode_num);
            }
        }
    }

    None
}

fn create_pod_info(pod: &Pod, pod_ip: &String) -> PodInfo {
    PodInfo {
        pod_name: pod.name_any(),
        pod_namespace: pod.metadata.namespace.to_owned(),
        pod_ip: pod_ip.clone(),
    }
}
