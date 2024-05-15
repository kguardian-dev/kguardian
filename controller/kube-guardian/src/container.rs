use crate::{Linux, PodInspect};
use containerd_client::{
    connect,
    services::v1::{
        containers_client::ContainersClient, tasks_client::TasksClient, Container,
        GetContainerRequest, GetRequest,
    },
    tonic::{transport::Channel, Request},
    with_namespace,
};
use regex::Regex;
use std::process::Command;
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
                let res = container_resp.unwrap().into_inner();
                let container: Container = res.container.unwrap();
                return Some(
                    self.set_container_id(container_id)
                        .get_pid(channel)
                        .await
                        .get_cgroup_path()
                        .extract_namespace_pid(container)
                        .get_peer_ifindex(),
                );
            }
        }
        None
    }

    fn set_container_id(mut self, container_id: String) -> Self {
        self.container_id = Some(container_id);
        self
    }

    // extract the network namespace pid
    // This is need to enter into process namespace and get the eth details of container
    fn extract_namespace_pid(mut self, c: Container) -> Self {
        let container_spec = String::from_utf8(c.spec.unwrap().value).unwrap();
        let ns: Linux = serde_json::from_str(&container_spec).unwrap();
        let namespaces = ns
            .linux
            .namespaces
            .iter()
            .filter(|ns| ns.nstype == Some("network".to_string()))
            .collect::<Vec<_>>()[0];

        // Exract container pid from the path the "path": "/proc/<pid>/ns/net"
        let namespace_pid = namespaces
            .path
            .as_ref()
            .unwrap()
            .split('/')
            .collect::<Vec<&str>>()[2]
            .parse()
            .unwrap();
        self.namespace_pid = Some(namespace_pid);
        self
    }

    fn get_peer_ifindex(mut self) -> Self {
        if self.namespace_pid.is_some() {
            // store if index both from host side and pod side
            let mut if_indexes: [Option<u32>; 2] = [None, None];
            let ns_enter = Command::new("nsenter")
                .arg("-t")
                .arg(&self.namespace_pid.unwrap().to_string())
                .arg("-n")
                .arg("ip")
                .arg("link")
                .output()
                .expect("nsenter is not install on kubernetes node");
            // parse the command output using regex
            // TODO Error Handling
            let ns_enter = std::str::from_utf8(&ns_enter.stdout).unwrap();
            debug!(
                "output from nsenter container_id {:?}  is \n {:?}",
                self.container_id, ns_enter
            );
            // parse the above string and get the ifindex
            //eth0@if(?P<index>[0-9]*)
            // TODO Error Handling
            let re = Regex::new("(?P<pod>[0-9]*): eth0@if(?P<host>[0-9]*)").unwrap();
            let pod_idex: Option<u32> = re.captures(ns_enter).map(|c| c["pod"].parse().unwrap());
            let host_idex: Option<u32> = re.captures(ns_enter).map(|c| c["host"].parse().unwrap());
            if_indexes[0] = pod_idex;
            if_indexes[1] = host_idex;
            self.if_index = if_indexes;
        } else {
            error!(
                "failed to extract the process id of container {:?}",
                self.container_id
            )
        }
        // execute sudo nsenter -t $pid -n ip link  to get the iplink of container
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

    fn get_cgroup_path(mut self) -> Self {
        if self.pid.is_some() {
            let pid = self.pid.unwrap();
            // get the cgroup path
            // https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
            // cgroupv2 contains only single entry
            let pod_cgroup_path = std::fs::read_to_string(format!("/proc/{}/cgroup", pid));
            if let Err(e) = pod_cgroup_path {
                error!("Failed to get process details for PID {} : {}", pid, e);
            } else {
                let cgrp = pod_cgroup_path.unwrap();
                let parts: Vec<&str> = cgrp.split("::").collect();
                self.cgroup_path = parts
                    .get(1)
                    .map(|value| format!("/sys/fs/cgroup{}", value.trim()))
            }
        }

        self
    }
}
