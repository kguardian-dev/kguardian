use crate::PodInspect;
use containerd_client::{
    connect,
    services::v1::{
        containers_client::ContainersClient, tasks_client::TasksClient, Container,
        GetContainerRequest, GetRequest,
    },
    tonic::{transport::Channel, Request},
    with_namespace,
};
use procfs::process::Process;
use regex::Regex;
use std::{ffi::OsString, process::Command};
use tracing::*;

static REGEX_CONTAINERD: &str = "containerd://(?P<container_id>[0-9a-zA-Z]*)";

impl PodInspect {
    pub(crate) async fn get_pod_inspect(self, container_id: &str) -> Option<PodInspect> {
        let re = Regex::new(REGEX_CONTAINERD).unwrap();
        let container_id: Option<String> = re
            .captures(container_id)
            .map(|c| c["container_id"].parse().unwrap());

        if let Some(container_id) = container_id {
            let channel = connect("/run/containerd/containerd.sock").await;
            if let Err(e) = channel {
                error!("Error connect to containerd sock {}", e);
                return None;
            }
            let channel = channel.unwrap();
            let mut ps = ContainersClient::new(channel.clone());
            let req = GetContainerRequest {
                id: container_id.to_string(),
            };
            let req: Request<GetContainerRequest> = with_namespace!(req, "k8s.io");
            let container_resp = ps.get(req).await;

            if let Err(e) = container_resp {
                error!(
                    "failed to get container response for {} from containerd {}",
                    container_id, e
                );
                return None;
            } else {
                return Some(
                    self.set_container_id(container_id)
                        .get_pid(channel)
                        .await
                        .get_pid_for_children_namespace_id(),
                );
            }
        }
        None
    }

    fn set_container_id(mut self, container_id: String) -> Self {
        self.container_id = Some(container_id);
        self
    }

    async fn get_pid(mut self, channel: Channel) -> Self {
        let mut client = TasksClient::new(channel.clone());

        let req = GetRequest {
            container_id: self.container_id.to_owned().unwrap(),
            ..Default::default()
        };

        let req = with_namespace!(req, "k8s.io");
        let container_resp = client.get(req).await;
        if let Err(err) = container_resp {
            error!(
                "Failed to get container response for container id {:?}, {:?}",
                self.container_id, err
            );
            self.pid = None
        } else {
            let container_resp = container_resp.unwrap().into_inner();
            self.pid = Some(container_resp.process.unwrap().pid);
        }
        self
    }

    fn get_pid_for_children_namespace_id(mut self) -> Self {
        if self.pid.is_some() {
            if let Some(process) = Process::new(self.pid.unwrap() as i32).ok() {
                if let Ok(ns) = process.namespaces() {
                    if let Some(pid_for_children) = ns.0.get(&OsString::from("pid_for_children")) {
                        self.inode_num = Some(pid_for_children.identifier);
                    }
                }
            }
        }
        self
    }
}
