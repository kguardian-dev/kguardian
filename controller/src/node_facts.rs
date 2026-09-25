//! Environment facts about the node this controller runs on, derived
//! from its own Node object and reported to the broker once at startup.
//!
//! The broker aggregates one row per node and folds the result into the
//! anonymous daily telemetry check-in (contract v2 — see
//! docs/telemetry.mdx). Everything here is deliberately COARSE: fixed
//! enum strings that match the version service's server-side
//! whitelists, never names, addresses, regions, or instance types.
//!
//! Reporting is telemetry-grade: any failure (missing RBAC on an older
//! chart, API hiccup, broker unreachable) logs at debug/warn and gives
//! up — it must never affect capture.

use k8s_openapi::api::core::v1::{Node, Pod};
use kube::{api::ListParams, Api, Client};
use serde::Serialize;
use std::path::Path;
use tracing::{debug, warn};

use crate::compute_sampler::{parse_meminfo_total_bytes, parse_proc_stat};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeFacts {
    pub node_name: String,
    pub provider: String,
    pub distro: String,
    pub cni: String,
    pub ip_family: String,
    pub node_os: String,
    /// Whether a NetworkPolicy applied to this node's pods would
    /// actually be *enforced*: `enforced`, `unenforced`, or `unknown`.
    ///
    /// Deliberately separate from `cni` rather than folded into it,
    /// because enforcement is orthogonal to which CNI is installed.
    /// AWS VPC CNI supports NetworkPolicy only when explicitly turned
    /// on and ships with it OFF, in which case it accepts a policy and
    /// silently ignores it — `kubectl apply` succeeds, `kubectl get`
    /// shows the object, nothing is enforced. Cilium and Calico can
    /// likewise be installed with policy disabled, and flannel never
    /// enforces at all.
    ///
    /// Knowing the CNI is therefore NOT the same claim as knowing a
    /// generated policy will do anything, and this project's whole
    /// value rests on the difference: kguardian tells an operator it is
    /// safe to deny what was never observed. Telling them a policy is
    /// in force when it is inert is the worst answer available, so
    /// `unknown` is reported wherever it cannot be established.
    pub policy_enforcement: String,
    /// Static compute facts (design D10), read from the node itself
    /// rather than the Node object. `None` when the source could not be
    /// read; an older broker ignores the fields.
    pub cpu_cores: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub kernel_version: Option<String>,
    /// 1 or 2. Decided by the presence of `cgroup.controllers` at the
    /// cgroup root, which only the unified (v2) hierarchy has.
    pub cgroup_version: Option<u8>,
    /// Whether `/proc/pressure/cpu` exists: PSI compiled in and enabled.
    pub psi_available: Option<bool>,
}

/// The node-local half of [`NodeFacts`]: what a compute gauge needs to
/// know that never changes for the life of the process.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StaticComputeFacts {
    pub cpu_cores: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub kernel_version: Option<String>,
    pub cgroup_version: Option<u8>,
    pub psi_available: Option<bool>,
}

/// Read the static compute facts from a host `/proc` and a cgroup root.
/// Pure over the two paths, so it is fixture-tested; every field
/// degrades to `None` independently.
pub fn static_compute_facts(host_proc: &Path, cgroup_root: &Path) -> StaticComputeFacts {
    let cpu_cores = std::fs::read_to_string(host_proc.join("stat"))
        .ok()
        .map(|b| parse_proc_stat(&b).cpus)
        .filter(|n| *n > 0);
    let memory_bytes = std::fs::read_to_string(host_proc.join("meminfo"))
        .ok()
        .and_then(|b| parse_meminfo_total_bytes(&b));
    let kernel_version = std::fs::read_to_string(host_proc.join("sys/kernel/osrelease"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let cgroup_version = if cgroup_root.join("cgroup.controllers").is_file() {
        Some(2)
    } else if cgroup_root.is_dir() {
        Some(1)
    } else {
        None
    };
    let psi_available = if host_proc.is_dir() {
        Some(host_proc.join("pressure/cpu").exists())
    } else {
        None
    };
    StaticComputeFacts {
        cpu_cores,
        memory_bytes,
        kernel_version,
        cgroup_version,
        psi_available,
    }
}

impl NodeFacts {
    /// Fold the node-local facts in.
    pub fn with_static(mut self, s: StaticComputeFacts) -> Self {
        self.cpu_cores = s.cpu_cores;
        self.memory_bytes = s.memory_bytes;
        self.kernel_version = s.kernel_version;
        self.cgroup_version = s.cgroup_version;
        self.psi_available = s.psi_available;
        self
    }
}

/// What a node-local CNI agent pod reveals about itself.
///
/// Read from the agent's own pod spec rather than inferred from Node
/// annotations, because the CNI that prompted this — AWS VPC CNI —
/// stamps no annotations at all, and because the enforcement flag only
/// exists in the agent's container arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct CniAgentFacts {
    pub cni: &'static str,
    pub policy_enforcement: &'static str,
}

/// Map a `spec.providerID` scheme to the telemetry provider enum.
/// The scheme is the part before "://" — `aws://…`, `gce://…`, etc.
///
/// `baremetal` here means "self-managed, no cloud controller integration"
/// rather than literally physical hardware: no providerID at all (bare
/// metal and Talos-on-metal) maps here, and so does the `k3s://` scheme.
/// K3s only stamps `k3s://<host>` when its embedded cloud-controller is
/// active, i.e. the operator wired in no real cloud CCM; the moment a
/// cloud CCM is configured the providerID becomes `aws://`/`gce://`/…
/// and is detected above. So a `k3s://` node is self-managed infra with
/// no cloud integration, whatever the box underneath — the same bucket
/// as no-providerID. `distro=k3s` carries the "it's k3s" signal
/// separately.
fn provider_from_id(provider_id: Option<&str>) -> &'static str {
    let Some(id) = provider_id.filter(|s| !s.trim().is_empty()) else {
        return "baremetal";
    };
    match id.split("://").next().unwrap_or("") {
        "aws" => "aws",
        "gce" => "gcp",
        "azure" => "azure",
        "digitalocean" => "digitalocean",
        "hcloud" => "hetzner",
        "openstack" => "openstack",
        "vsphere" => "vsphere",
        "oci" => "oracle",
        "ibm" | "ibmpowervs" => "ibm",
        "kind" => "kind",
        // K3s's embedded cloud-controller stamps `k3s://<host>` only when
        // no real cloud CCM is configured — self-managed infra, same
        // bucket as a node with no providerID at all.
        "k3s" => "baremetal",
        _ => "unknown",
    }
}

fn has_label_prefix(node: &Node, prefix: &str) -> bool {
    node.metadata
        .labels
        .as_ref()
        .is_some_and(|l| l.keys().any(|k| k.starts_with(prefix)))
}

fn has_annotation_prefix(node: &Node, prefix: &str) -> bool {
    node.metadata
        .annotations
        .as_ref()
        .is_some_and(|a| a.keys().any(|k| k.starts_with(prefix)))
}

fn kubelet_version(node: &Node) -> &str {
    node.status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.kubelet_version.as_str())
        .unwrap_or("")
}

fn os_image(node: &Node) -> String {
    node.status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.os_image.to_lowercase())
        .unwrap_or_default()
}

/// Kubernetes distribution flavor from well-known labels, kubelet
/// version suffixes, and the OS image. Order matters: managed-offering
/// labels are the strongest signal, version suffixes next, OS last.
fn distro(node: &Node, provider: &str) -> &'static str {
    if has_label_prefix(node, "eks.amazonaws.com/") {
        return "eks";
    }
    if has_label_prefix(node, "cloud.google.com/gke") {
        return "gke";
    }
    if has_label_prefix(node, "kubernetes.azure.com/") {
        return "aks";
    }
    if has_label_prefix(node, "node.openshift.io/") {
        return "openshift";
    }
    let kubelet = kubelet_version(node);
    if kubelet.contains("+k3s") {
        return "k3s";
    }
    if kubelet.contains("+rke2") {
        return "rke2";
    }
    if os_image(node).contains("talos") {
        return "talos";
    }
    if provider == "kind" {
        return "kind";
    }
    "vanilla"
}

/// CNI plugin from the annotations each CNI's node agent stamps on the
/// Node. Not every CNI annotates (kindnet doesn't) — "unknown" is an
/// honest answer.
fn cni(node: &Node) -> &'static str {
    if has_annotation_prefix(node, "io.cilium") || has_annotation_prefix(node, "network.cilium.io/")
    {
        return "cilium";
    }
    if has_annotation_prefix(node, "projectcalico.org/") {
        return "calico";
    }
    if has_annotation_prefix(node, "flannel.alpha.coreos.com/") {
        return "flannel";
    }
    if has_annotation_prefix(node, "node.antrea.io/") {
        return "antrea";
    }
    if has_annotation_prefix(node, "weave.works/") {
        return "weave";
    }
    "unknown"
}

/// Identify the CNI, and whether it enforces policy, from the agent
/// pods running on this node.
///
/// AWS VPC CNI is invisible to [`cni`]: it annotates neither the Node
/// nor its pods, so every EKS cluster running it reported `unknown`.
/// Its agent pod, however, states both facts outright — the DaemonSet
/// is labelled `k8s-app=aws-node`, and the `aws-eks-nodeagent`
/// container carries `--enable-network-policy` in its arguments.
///
/// Reading the pod rather than the DaemonSet is deliberate: the
/// controller already holds cluster-wide `pods get/watch`, while
/// `daemonsets` would need a new rule in the ClusterRole. A pod carries
/// the same container arguments its DaemonSet template does, so the
/// extra permission buys nothing.
///
/// `None` means no agent this function recognises was found, which is
/// not the same as "no CNI" — the caller falls back to annotations and
/// then to `unknown`.
fn cni_agent_facts(pods: &[Pod]) -> Option<CniAgentFacts> {
    pods.iter().find_map(|pod| {
        let is_aws_node = pod
            .metadata
            .labels
            .as_ref()
            .is_some_and(|l| l.get("k8s-app").is_some_and(|v| v == "aws-node"));
        if !is_aws_node {
            return None;
        }
        Some(CniAgentFacts {
            cni: "aws-vpc-cni",
            policy_enforcement: aws_policy_enforcement(pod),
        })
    })
}

/// Whether the VPC CNI node agent was started with policy enforcement
/// on.
///
/// Three outcomes, and the distinction between the last two matters:
/// the flag present and true is `enforced`; the container present with
/// the flag absent or false is `unenforced`, because the agent defaults
/// to off; and no `aws-eks-nodeagent` container at all is `unenforced`
/// too, since VPC CNI gained NetworkPolicy support only in v1.14 and an
/// older agent cannot enforce anything regardless of configuration.
fn aws_policy_enforcement(pod: &Pod) -> &'static str {
    let Some(spec) = pod.spec.as_ref() else {
        return "unknown";
    };
    let Some(agent) = spec
        .containers
        .iter()
        .find(|c| c.name == "aws-eks-nodeagent")
    else {
        // Pre-v1.14 VPC CNI: no policy agent exists to enforce with.
        return "unenforced";
    };
    let enabled = agent
        .args
        .as_ref()
        .is_some_and(|args| args.iter().any(|a| a == "--enable-network-policy=true"));
    if enabled {
        "enforced"
    } else {
        "unenforced"
    }
}

/// Enforcement for a CNI identified only by its Node annotations.
///
/// Only flannel gets a definite answer: it provides no NetworkPolicy
/// implementation at all, so a policy applied on it is inert by
/// construction. Cilium and Calico both ship enforcement on by default
/// but can be deployed with it disabled, and nothing on the Node says
/// which — claiming `enforced` for them would be a guess dressed as a
/// fact, so they report `unknown` until someone probes their agents the
/// way [`cni_agent_facts`] probes VPC CNI's.
fn annotated_cni_enforcement(cni: &str) -> &'static str {
    match cni {
        "flannel" => "unenforced",
        _ => "unknown",
    }
}

/// IP family of the node's pod CIDRs: ipv4 / ipv6 / dual.
fn ip_family(node: &Node) -> &'static str {
    let mut v4 = false;
    let mut v6 = false;
    let spec = node.spec.as_ref();
    let cidrs: Vec<&String> = spec
        .and_then(|s| s.pod_cidrs.as_ref())
        .map(|c| c.iter().collect())
        .or_else(|| spec.and_then(|s| s.pod_cidr.as_ref()).map(|c| vec![c]))
        .unwrap_or_default();
    for cidr in cidrs {
        if cidr.contains(':') {
            v6 = true;
        } else if cidr.contains('.') {
            v4 = true;
        }
    }
    match (v4, v6) {
        (true, true) => "dual",
        (true, false) => "ipv4",
        (false, true) => "ipv6",
        (false, false) => "unknown",
    }
}

/// Node OS family from `nodeInfo.osImage`, coarsened to the telemetry
/// enum. Anything recognizable-but-unlisted is "other", absent info is
/// "unknown".
fn node_os(node: &Node) -> &'static str {
    let img = os_image(node);
    if img.is_empty() {
        return "unknown";
    }
    if img.contains("talos") {
        "talos"
    } else if img.contains("bottlerocket") {
        "bottlerocket"
    } else if img.contains("flatcar") {
        "flatcar"
    } else if img.contains("container-optimized") {
        "cos"
    } else if img.contains("ubuntu") {
        "ubuntu"
    } else if img.contains("debian") {
        "debian"
    } else if img.contains("red hat") || img.contains("rhel") {
        "rhel"
    } else if img.contains("amazon linux") {
        "amazonlinux"
    } else if img.contains("alpine") {
        "alpine"
    } else {
        "other"
    }
}

/// Derive every fact from a Node object. Pure — the whole mapping is
/// unit-tested below against representative Node shapes.
/// Derive the reported facts.
///
/// `agent_pods` are the pods this controller could see on its own node.
/// An agent that names itself is believed over Node annotations: VPC CNI
/// leaves none, and an agent's own arguments are a direct statement of
/// configuration rather than a proxy for it. An empty slice — no pod
/// access, or nothing recognised — falls back to the annotation path,
/// which is exactly the pre-existing behaviour.
pub fn derive_facts(node_name: &str, node: &Node, agent_pods: &[Pod]) -> NodeFacts {
    let provider_id = node.spec.as_ref().and_then(|s| s.provider_id.as_deref());
    let provider = provider_from_id(provider_id);
    let agent = cni_agent_facts(agent_pods);
    let annotated = cni(node);
    let (cni_name, enforcement) = match agent {
        Some(a) => (a.cni, a.policy_enforcement),
        None => (annotated, annotated_cni_enforcement(annotated)),
    };
    NodeFacts {
        node_name: node_name.to_string(),
        provider: provider.to_string(),
        distro: distro(node, provider).to_string(),
        cni: cni_name.to_string(),
        ip_family: ip_family(node).to_string(),
        node_os: node_os(node).to_string(),
        policy_enforcement: enforcement.to_string(),
        cpu_cores: None,
        memory_bytes: None,
        kernel_version: None,
        cgroup_version: None,
        psi_available: None,
    }
}

/// Fetch this node's object, derive facts, and POST them to the broker.
/// Fire-and-forget: every failure path logs and returns.
pub async fn report_node_facts(node_name: String, broker_url: String) {
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "no kube client for node facts");
            return;
        }
    };
    let nodes: Api<Node> = Api::all(client.clone());
    // CNI agent pods on this node, used to identify a CNI that annotates
    // nothing and to read whether it enforces policy. Best-effort by
    // design: a failure here degrades the two CNI fields to the
    // annotation path and `unknown`, which is what every chart before
    // this reported anyway. Field-selected to this node so it is one
    // small list, not a cluster-wide scan.
    let agent_pods: Vec<Pod> = {
        let pods: Api<Pod> = Api::all(client);
        let params = ListParams::default()
            .fields(&format!("spec.nodeName={}", node_name))
            .labels("k8s-app=aws-node");
        match pods.list(&params).await {
            Ok(list) => list.items,
            Err(e) => {
                debug!(error = %e, "could not list CNI agent pods; CNI facts fall back to Node annotations");
                Vec::new()
            }
        }
    };
    let node = match nodes.get(&node_name).await {
        Ok(n) => n,
        Err(e) => {
            // Older charts don't grant `nodes get` — degrade silently
            // rather than nagging on every start.
            warn!(
                node = %node_name,
                error = %e,
                "could not read own Node object (missing RBAC on an older chart?); \
                 environment telemetry facts will report as unknown"
            );
            return;
        }
    };
    // Node-local compute facts come from the same host /proc and cgroup
    // root the sampler reads (COMPUTE_HOST_PROC / COMPUTE_CGROUP_ROOT),
    // whether or not the sampler is enabled: cgroup version and PSI
    // availability are what tell the UI *why* a node has no gauges.
    let compute_cfg = crate::compute_config::ComputeConfig::from_env();
    let facts = derive_facts(&node_name, &node, &agent_pods).with_static(static_compute_facts(
        &compute_cfg.host_proc,
        &compute_cfg.cgroup_root,
    ));
    debug!(?facts, "derived node environment facts");
    let url = format!("{}/node/facts", broker_url.trim_end_matches('/'));
    // The shared client: it carries the request/connect ceilings and the
    // broker bearer token. `reqwest::Client::new()` here had neither, so
    // with broker auth enabled every node-facts POST was a silent 401.
    match crate::client::http_client()
        .post(&url)
        .json(&facts)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            debug!(node = %node_name, "node facts reported");
        }
        Ok(resp)
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                || resp.status() == reqwest::StatusCode::FORBIDDEN =>
        {
            // Not a version skew: the token is missing, wrong, or lacks
            // the ingest scope. Say so where an operator will see it.
            warn!(status = %resp.status(), "broker rejected node facts: check BROKER_AUTH_TOKEN (needs the ingest token)");
        }
        Ok(resp) => {
            // An older broker without the endpoint 404s — expected
            // during mixed-version rollouts.
            debug!(status = %resp.status(), "broker did not accept node facts");
        }
        Err(e) => {
            debug!(error = %e, "node facts POST failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Container, NodeSpec, NodeStatus, NodeSystemInfo, PodSpec};
    use std::collections::BTreeMap;

    fn node(
        provider_id: Option<&str>,
        labels: &[(&str, &str)],
        annotations: &[(&str, &str)],
        kubelet: &str,
        os: &str,
        cidrs: &[&str],
    ) -> Node {
        let mut n = Node::default();
        n.metadata.labels = Some(
            labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        );
        n.metadata.annotations = Some(
            annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        );
        n.spec = Some(NodeSpec {
            provider_id: provider_id.map(String::from),
            pod_cidrs: if cidrs.is_empty() {
                None
            } else {
                Some(cidrs.iter().map(|c| c.to_string()).collect())
            },
            ..Default::default()
        });
        n.status = Some(NodeStatus {
            node_info: Some(NodeSystemInfo {
                kubelet_version: kubelet.to_string(),
                os_image: os.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });
        n
    }

    /// Build an `aws-node` agent pod. `agent_args` of `None` means the
    /// `aws-eks-nodeagent` container is absent entirely, which is how a
    /// pre-v1.14 VPC CNI presents.
    fn aws_node_pod(agent_args: Option<&[&str]>) -> Pod {
        let mut p = Pod::default();
        p.metadata.labels = Some(
            [("k8s-app".to_string(), "aws-node".to_string())]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        );
        let mut containers = vec![Container {
            name: "aws-node".to_string(),
            ..Default::default()
        }];
        if let Some(args) = agent_args {
            containers.push(Container {
                name: "aws-eks-nodeagent".to_string(),
                args: Some(args.iter().map(|a| a.to_string()).collect()),
                ..Default::default()
            });
        }
        p.spec = Some(PodSpec {
            containers,
            ..Default::default()
        });
        p
    }

    /// A bare EKS node: no CNI annotations at all, which is exactly how
    /// VPC CNI presents and why the annotation path returns "unknown".
    fn bare_eks_node() -> Node {
        node(
            Some("aws:///us-west-2a/i-0abc"),
            &[("eks.amazonaws.com/nodegroup", "ng-1")],
            &[],
            "v1.30.0-eks-1234",
            "amazon linux 2023",
            &["10.62.0.0/19"],
        )
    }

    // The regression these guard: AWS VPC CNI annotates nothing, so
    // before the agent probe every EKS cluster reported cni="unknown"
    // and the console could not tell an operator which policy type
    // their cluster would actually enforce.

    #[test]
    fn aws_vpc_cni_is_detected_from_the_agent_pod_not_annotations() {
        let facts = derive_facts(
            "node-a",
            &bare_eks_node(),
            &[aws_node_pod(Some(&["--enable-network-policy=true"]))],
        );
        assert_eq!(facts.cni, "aws-vpc-cni");
        assert_eq!(facts.policy_enforcement, "enforced");
    }

    #[test]
    fn vpc_cni_without_the_flag_is_unenforced_not_unknown() {
        // The dangerous case, and the reason enforcement is reported
        // separately from the CNI name: the flag defaults to off, and
        // with it off the CNI accepts a NetworkPolicy and silently
        // ignores it. Reporting "unknown" here would let the console
        // hedge; the truth is that policy is definitely inert.
        let facts = derive_facts(
            "node-a",
            &bare_eks_node(),
            &[aws_node_pod(Some(&["--enable-ipv6=false"]))],
        );
        assert_eq!(facts.cni, "aws-vpc-cni");
        assert_eq!(facts.policy_enforcement, "unenforced");
    }

    #[test]
    fn vpc_cni_explicitly_disabled_is_unenforced() {
        let facts = derive_facts(
            "node-a",
            &bare_eks_node(),
            &[aws_node_pod(Some(&["--enable-network-policy=false"]))],
        );
        assert_eq!(facts.policy_enforcement, "unenforced");
    }

    #[test]
    fn vpc_cni_older_than_the_policy_agent_is_unenforced() {
        // Pre-v1.14 has no aws-eks-nodeagent container at all. There is
        // nothing that could enforce, so this is a definite answer.
        let facts = derive_facts("node-a", &bare_eks_node(), &[aws_node_pod(None)]);
        assert_eq!(facts.cni, "aws-vpc-cni");
        assert_eq!(facts.policy_enforcement, "unenforced");
    }

    #[test]
    fn no_agent_pods_falls_back_to_the_annotation_path() {
        // Pod listing failed, or the chart lacks the RBAC. Behaviour
        // must be exactly what it was before the probe existed.
        let n = node(
            Some("aws:///us-west-2a/i-0abc"),
            &[],
            &[("io.cilium.network.ipv4-pod-cidr", "10.0.0.0/24")],
            "v1.30.0",
            "ubuntu 22.04",
            &["10.0.0.0/24"],
        );
        let facts = derive_facts("node-a", &n, &[]);
        assert_eq!(facts.cni, "cilium");
        assert_eq!(facts.policy_enforcement, "unknown");
    }

    #[test]
    fn the_agent_pod_beats_a_stale_annotation() {
        // A cluster migrated from Calico to VPC CNI can keep the old
        // annotations on long-lived nodes. The running agent is the
        // authority; an annotation is a leftover.
        let n = node(
            Some("aws:///us-west-2a/i-0abc"),
            &[],
            &[("projectcalico.org/IPv4Address", "10.0.0.5/24")],
            "v1.30.0-eks-1234",
            "amazon linux 2023",
            &["10.62.0.0/19"],
        );
        let facts = derive_facts(
            "node-a",
            &n,
            &[aws_node_pod(Some(&["--enable-network-policy=true"]))],
        );
        assert_eq!(facts.cni, "aws-vpc-cni");
        assert_eq!(facts.policy_enforcement, "enforced");
    }

    #[test]
    fn flannel_is_definitely_unenforced_others_are_unknown() {
        // flannel implements no NetworkPolicy at all, so that one can
        // be stated. Cilium and Calico default to enforcing but can be
        // installed without it, and nothing on the Node says which —
        // guessing "enforced" there would be the false assurance this
        // field exists to prevent.
        assert_eq!(annotated_cni_enforcement("flannel"), "unenforced");
        for c in ["cilium", "calico", "antrea", "weave", "unknown"] {
            assert_eq!(annotated_cni_enforcement(c), "unknown", "{c}");
        }
    }

    #[test]
    fn a_non_agent_pod_on_the_node_is_ignored() {
        let mut other = Pod::default();
        other.metadata.labels = Some(
            [("k8s-app".to_string(), "kube-proxy".to_string())]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        );
        assert_eq!(cni_agent_facts(&[other]), None);
    }

    #[test]
    fn eks_node_derives_aws_eks() {
        let n = node(
            Some("aws:///us-east-1a/i-0abc"),
            &[("eks.amazonaws.com/nodegroup", "ng-1")],
            &[],
            "v1.29.0-eks-abc",
            "Amazon Linux 2",
            &["10.0.0.0/24"],
        );
        let f = derive_facts("n1", &n, &[]);
        assert_eq!(
            (
                f.provider.as_str(),
                f.distro.as_str(),
                f.ip_family.as_str(),
                f.node_os.as_str()
            ),
            ("aws", "eks", "ipv4", "amazonlinux")
        );
    }

    #[test]
    fn talos_cilium_dual_stack_on_metal() {
        let n = node(
            None,
            &[],
            &[("network.cilium.io/ipv4-pod-cidr", "10.244.11.0/24")],
            "v1.35.6",
            "Talos (v1.13.4)",
            &["10.244.11.0/24", "fd00:10:244::/64"],
        );
        let f = derive_facts("n1", &n, &[]);
        assert_eq!(
            (
                f.provider.as_str(),
                f.distro.as_str(),
                f.cni.as_str(),
                f.ip_family.as_str(),
                f.node_os.as_str()
            ),
            ("baremetal", "talos", "cilium", "dual", "talos")
        );
    }

    #[test]
    fn gke_node_derives_gcp_gke_cos() {
        let n = node(
            Some("gce://proj/zone/instance"),
            &[("cloud.google.com/gke-nodepool", "default")],
            &[],
            "v1.30.1-gke.100",
            "Container-Optimized OS from Google",
            &["10.4.0.0/24"],
        );
        let f = derive_facts("n1", &n, &[]);
        assert_eq!(
            (f.provider.as_str(), f.distro.as_str(), f.node_os.as_str()),
            ("gcp", "gke", "cos")
        );
    }

    #[test]
    fn k3s_provider_id_is_self_managed_baremetal() {
        // K3s's embedded cloud-controller stamps `k3s://<host>`; with no
        // real cloud CCM that is self-managed infra, so provider folds
        // into `baremetal` (not `unknown`). `distro=k3s` still carries
        // the flavor, and the calico annotation still wins the CNI.
        let n = node(
            Some("k3s://node"),
            &[],
            &[("projectcalico.org/IPv4Address", "10.0.0.5/24")],
            "v1.29.4+k3s1",
            "Ubuntu 22.04.4 LTS",
            &["10.42.0.0/24"],
        );
        let f = derive_facts("n1", &n, &[]);
        assert_eq!(
            (
                f.provider.as_str(),
                f.distro.as_str(),
                f.cni.as_str(),
                f.node_os.as_str()
            ),
            ("baremetal", "k3s", "calico", "ubuntu")
        );
    }

    #[test]
    fn empty_node_degrades_to_unknowns_not_panics() {
        let f = derive_facts("n1", &Node::default(), &[]);
        assert_eq!(
            (
                f.provider.as_str(),
                f.distro.as_str(),
                f.cni.as_str(),
                f.ip_family.as_str(),
                f.node_os.as_str()
            ),
            ("baremetal", "vanilla", "unknown", "unknown", "unknown")
        );
    }

    #[test]
    fn derive_facts_leaves_static_compute_fields_unset() {
        // The pure Node-object mapping knows nothing about the host;
        // the fields are filled by `with_static` from the node itself.
        let f = derive_facts("n1", &Node::default(), &[]);
        assert_eq!(f.cpu_cores, None);
        assert_eq!(f.memory_bytes, None);
        assert_eq!(f.kernel_version, None);
        assert_eq!(f.cgroup_version, None);
        assert_eq!(f.psi_available, None);
        let v = serde_json::to_value(&f).unwrap();
        for k in [
            "cpu_cores",
            "memory_bytes",
            "kernel_version",
            "cgroup_version",
            "psi_available",
        ] {
            assert!(v.get(k).is_some(), "{k} must be present (null) on the wire");
        }
    }

    fn fixture_root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kg-node-facts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("proc/sys/kernel")).unwrap();
        std::fs::create_dir_all(d.join("cgroup")).unwrap();
        std::fs::write(
            d.join("proc/stat"),
            "cpu  1 2 3\ncpu0 1 2 3\ncpu1 1 2 3\ncpu2 1 2 3\ncpu3 1 2 3\nctxt 5\n",
        )
        .unwrap();
        std::fs::write(d.join("proc/meminfo"), "MemTotal:       16384000 kB\n").unwrap();
        std::fs::write(
            d.join("proc/sys/kernel/osrelease"),
            "6.6.87.2-microsoft-standard\n",
        )
        .unwrap();
        d
    }

    #[test]
    fn cgroup_v2_node_with_psi_reports_supported_facts() {
        let d = fixture_root("v2");
        std::fs::write(d.join("cgroup/cgroup.controllers"), "cpu memory io\n").unwrap();
        std::fs::create_dir_all(d.join("proc/pressure")).unwrap();
        std::fs::write(d.join("proc/pressure/cpu"), "some avg10=0.00\n").unwrap();
        let s = static_compute_facts(&d.join("proc"), &d.join("cgroup"));
        assert_eq!(
            s,
            StaticComputeFacts {
                cpu_cores: Some(4),
                memory_bytes: Some(16_384_000 * 1024),
                kernel_version: Some("6.6.87.2-microsoft-standard".into()),
                cgroup_version: Some(2),
                psi_available: Some(true),
            }
        );
        let f = derive_facts("n1", &Node::default(), &[]).with_static(s);
        assert_eq!(f.cgroup_version, Some(2));
        assert_eq!(f.psi_available, Some(true));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cgroup_v1_node_without_psi_reports_unsupported_facts() {
        // v1 root: a directory of controller subtrees, no
        // cgroup.controllers file; and no /proc/pressure at all.
        let d = fixture_root("v1");
        std::fs::create_dir_all(d.join("cgroup/cpu,cpuacct")).unwrap();
        let s = static_compute_facts(&d.join("proc"), &d.join("cgroup"));
        assert_eq!(s.cgroup_version, Some(1));
        assert_eq!(s.psi_available, Some(false));
        assert_eq!(s.cpu_cores, Some(4));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_sources_degrade_to_none_field_by_field() {
        let d = std::env::temp_dir().join(format!("kg-node-facts-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let s = static_compute_facts(&d.join("proc"), &d.join("cgroup"));
        assert_eq!(s, StaticComputeFacts::default());
    }

    #[test]
    fn ipv6_only_pod_cidr_derives_ipv6() {
        let n = node(
            None,
            &[],
            &[],
            "v1.30.0",
            "Debian GNU/Linux 12",
            &["fd00::/64"],
        );
        let f = derive_facts("n1", &n, &[]);
        assert_eq!(
            (f.ip_family.as_str(), f.node_os.as_str()),
            ("ipv6", "debian")
        );
    }
}
