use crate::PodInspect;
use containerd_client::{
    connect,
    services::v1::{tasks_client::TasksClient, GetRequest},
    tonic::{transport::Channel, Request},
    with_namespace,
};
use procfs::process::Process;
use regex::Regex;
use std::ffi::OsString;
use tracing::*;

static REGEX_CONTAINERD: &str = "containerd://(?P<container_id>[0-9a-zA-Z]*)";

/// Parse a Kubernetes pod-status containerID URL.
///
/// Expects `containerd://<id>` — only the containerd runtime is
/// supported today. Returns the bare container ID, or None when the
/// input doesn't match (cri-o:// or docker:// prefixes, malformed
/// strings, etc.). A non-match is non-fatal at the call site — pods
/// using other runtimes are simply skipped.
pub(crate) fn parse_container_id(s: &str) -> Option<String> {
    let re = Regex::new(REGEX_CONTAINERD).ok()?;
    re.captures(s)
        .and_then(|c| c.name("container_id"))
        .map(|m| m.as_str().to_string())
        .filter(|s| !s.is_empty())
}

impl PodInspect {
    pub async fn get_pod_inspect(self, container_id: &str) -> Option<PodInspect> {
        let container_id = parse_container_id(container_id);

        if let Some(container_id) = container_id {
            let sock_path = std::env::var("CONTAINERD_SOCK")
                .unwrap_or_else(|_| "/run/containerd/containerd.sock".to_string());
            match connect(&sock_path).await {
                Ok(channel) => Some(
                    self.set_container_id(container_id)
                        .get_pid(channel)
                        .await
                        .get_net_namespace_id(),
                ),
                Err(err) => {
                    error!("Failed to connect to containerd socket: {:?}", err);
                    None
                }
            }
        } else {
            None
        }
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
        match client.get(req).await {
            Ok(resp) => {
                let container_resp = resp.into_inner();
                self.pid = container_resp.process.map(|p| p.pid);
            }
            Err(err) => {
                error!(
                    "Failed to get container response for container id {:?}, {:?}",
                    self.container_id, err
                );
                self.pid = None;
            }
        }
        self
    }

    fn get_net_namespace_id(mut self) -> Self {
        if let Some(pid) = self.pid {
            if let Ok(process) = Process::new(pid as i32) {
                if let Ok(ns) = process.namespaces() {
                    if let Some(netns) = ns.0.get(&OsString::from("net")) {
                        self.inode_num = Some(netns.identifier);
                    }
                }
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // parse_container_id is the gate that decides which pods we can
    // observe. A regression here either drops valid pods (we lose
    // visibility) or accepts garbage (we make containerd RPCs with
    // bad IDs, log noise).

    #[test]
    fn parse_extracts_id_from_containerd_url() {
        // 64-char hex is the canonical containerd ID shape.
        let id = "a".repeat(64);
        let url = format!("containerd://{id}");
        assert_eq!(parse_container_id(&url).as_deref(), Some(id.as_str()));
    }

    #[test]
    fn parse_accepts_alphanumeric_id() {
        // Mixed alphanumeric (rare but legal under the regex character class).
        assert_eq!(
            parse_container_id("containerd://Abc123Xyz").as_deref(),
            Some("Abc123Xyz"),
        );
    }

    #[test]
    fn parse_rejects_empty_id_after_prefix() {
        // `containerd://` with nothing after means no container ID — must
        // not produce Some("") which would be sent to the containerd
        // socket and 404 noisily.
        assert_eq!(parse_container_id("containerd://"), None);
    }

    #[test]
    fn parse_rejects_other_runtimes() {
        // Pods on cri-o, docker (legacy), or any other runtime should
        // be skipped, not misparsed.
        assert_eq!(parse_container_id("cri-o://abc123"), None);
        assert_eq!(parse_container_id("docker://abc123"), None);
        assert_eq!(parse_container_id("rkt://abc123"), None);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_container_id(""), None);
        assert_eq!(parse_container_id("just some text"), None);
        assert_eq!(parse_container_id("https://example.com"), None);
    }

    #[test]
    fn parse_stops_at_non_alphanumeric() {
        // The regex character class is [0-9a-zA-Z]*, so the first
        // non-alphanumeric char terminates the capture. A path like
        // `containerd://abc/def` yields just `abc` — that's fine,
        // but pin the contract.
        assert_eq!(
            parse_container_id("containerd://abc/def").as_deref(),
            Some("abc"),
        );
        assert_eq!(
            parse_container_id("containerd://abc-def").as_deref(),
            Some("abc"),
        );
    }
}
