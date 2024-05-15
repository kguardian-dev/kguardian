#[allow(unused_imports)]
use crate::{api_post_call, Error, PodInspect, Traffic};
use crate::{
    cgroup::{attach_cgroup, EbpfPgm},
    PodInfo,
};
use chrono::{NaiveDateTime, Utc};
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{
    api::{Api, ResourceExt},
    runtime::{watcher, WatchStreamExt},
    Client,
};
use serde::Deserialize;
use serde_derive::Serialize;
use serde_json::json;
use std::{collections::BTreeMap, env, sync::Arc};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SvcDetail {
    pub svc_ip: String,
    pub svc_name: String,
    pub svc_namespace: Option<String>,
    pub service_spec: Option<serde_json::Value>,
    pub time_stamp: NaiveDateTime,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct PodDetail {
    pub pod_ip: String,
    pub pod_name: String,
    pub pod_namespace: Option<String>,
    pub pod_obj: Option<serde_json::Value>,
    pub time_stamp: NaiveDateTime,
}

pub async fn watch_pods(
    ebpf: EbpfPgm,
    container_map: Arc<Mutex<BTreeMap<u32, PodInspect>>>,
    node_name: String,
) -> Result<(), Error> {
    let c = Client::try_default().await?;
    let pods: Api<Pod> = Api::all(c.clone());
    #[cfg(not(debug_assertions))]
    let wc = watcher::Config::default().fields(&format!("spec.nodeName={}", node_name));
    // .fields(&format!("metadata.namespace!={}", "kube-system"));
    #[cfg(debug_assertions)]
    let wc = watcher::Config::default();
    let ebpf = Arc::new(Mutex::new(ebpf));
    watcher(pods, wc)
        .applied_objects()
        .default_backoff()
        .try_for_each(|p| {
            let container_map = Arc::clone(&container_map);
            let ebpf = Arc::clone(&ebpf);
            async move {
                if let Some(con_ids) = pod_unready(&p) {
                    // will use the con_id later
                    // TODO error handling
                    let pod_ip = update_pods_details(&p).await;
                    if !p.metadata.namespace.eq(&Some("kube-system".to_string())) {
                        if let Ok(Some(pod_ip)) = pod_ip {
                            for con_id in con_ids {
                                // if pod has a Ip pod_ip
                                let pod_info: PodInfo = PodInfo {
                                    pod_name: p.name_any(),
                                    pod_namespace: p.metadata.namespace.to_owned(),
                                    pod_ip: pod_ip.clone(),
                                };
                                let pod_inspect = PodInspect {
                                    status: pod_info,
                                    ..Default::default()
                                };

                                info!("pod name {}", p.name_any());

                                if let Some(pod_inspect) =
                                    pod_inspect.get_pod_inspect(&con_id).await
                                {
                                    let mut cm = container_map.lock().await;

                                    if let Some(cgro_path) = pod_inspect.cgroup_path.to_owned() {
                                        // loop thru both host and container if index and store the pod details
                                        pod_inspect.if_index.map(|i| {
                                            if let Some(if_index) = i {
                                                cm.insert(if_index, pod_inspect.clone());
                                            }
                                        });
                                        if pod_inspect.if_index.len() > 0 {
                                            let cgrp_attach =
                                                attach_cgroup(&cgro_path, ebpf.clone()).await;
                                            if let Err(e) = cgrp_attach {
                                                error!(
                                                    "Failed to attach cgroup to pod {} {:?} {}",
                                                    p.name_any(),
                                                    cgro_path,
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
        })
        .await?;
    Ok(())
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
            container_ids.push(container.container_id.to_owned().unwrap())
        }
        return Some(container_ids);
    }

    None
}

async fn update_pods_details(pod: &Pod) -> Result<Option<String>, Error> {
    let pod_name = pod.name_any();
    let pod_namespace = pod.namespace();
    let pod_status = pod.status.as_ref().unwrap();
    let mut pod_ip_address: Option<String> = None;
    if pod_status.pod_ip.is_some() {
        let pod_ip = pod_status.pod_ip.as_ref().unwrap();
        let z = PodDetail {
            pod_ip: pod_ip.to_string(),
            pod_name,
            pod_namespace,
            pod_obj: Some(json!(pod)),
            time_stamp: Utc::now().naive_utc(),
        };
        api_post_call(json!(z), "netpol/podspec").await?;
        pod_ip_address = Some(pod_ip.to_string());
        return Ok(pod_ip_address);
    }
    Ok(pod_ip_address)
}

pub async fn watch_service() -> Result<(), Error> {
    let c = Client::try_default().await?;
    let svc: Api<Service> = Api::all(c.clone());
    let wc = watcher::Config::default();
    watcher(svc, wc)
        .applied_objects()
        .default_backoff()
        .try_for_each(|p| {
            async move {
                if let Some(unready_reason) = svc_unready(&p) {
                    warn!("{}", unready_reason);
                } else {
                    info!("SVC  {} Ready", p.name_any());

                    let ep = update_serviceinfo(p).await;
                    // log the error and proceed
                    if let Err(e) = ep {
                        error!(
                            "Failed while updating the endpoint slice info {}",
                            e.to_string()
                        );
                    }
                }
                Ok(())
            }
        })
        .await?;

    Ok(())
}

async fn update_serviceinfo(svc: Service) -> Result<(), Error> {
    let svc_name = svc.name_any();
    let svc_namespace = svc.namespace();
    let svc_spec = &svc.spec;
    let svc_ip = svc_spec.as_ref().unwrap().cluster_ip.as_ref().unwrap();

    let z = SvcDetail {
        svc_ip: svc_ip.to_owned(),
        svc_name: svc_name.to_owned(),
        svc_namespace: svc_namespace.to_owned(),
        service_spec: Some(json!(svc)),
        time_stamp: Utc::now().naive_utc(),
    };
    api_post_call(json!(z), "netpol/svc").await?;
    Ok(())
}

fn svc_unready(p: &Service) -> Option<String> {
    let status = p.status.as_ref().unwrap();
    info!("Service Status {:?}", status);
    if let Some(conds) = &status.conditions {
        let failed = conds
            .iter()
            .filter(|c| c.type_ == "Ready" && c.status == "False")
            .map(|c| c.message.clone())
            .collect::<Vec<_>>()
            .join(",");
        if !failed.is_empty() {
            return Some(format!("Unready Service {}: {}", p.name_any(), failed));
        }
    }
    None
}
