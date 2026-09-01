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

use k8s_openapi::api::core::v1::Node;
use kube::{Api, Client};
use serde::Serialize;
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeFacts {
    pub node_name: String,
    pub provider: String,
    pub distro: String,
    pub cni: String,
    pub ip_family: String,
    pub node_os: String,
}

/// Map a `spec.providerID` scheme to the telemetry provider enum.
/// The scheme is the part before "://" — `aws://…`, `gce://…`, etc.
/// No providerID at all is how bare-metal (and Talos-on-metal) nodes
/// present.
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
pub fn derive_facts(node_name: &str, node: &Node) -> NodeFacts {
    let provider_id = node.spec.as_ref().and_then(|s| s.provider_id.as_deref());
    let provider = provider_from_id(provider_id);
    NodeFacts {
        node_name: node_name.to_string(),
        provider: provider.to_string(),
        distro: distro(node, provider).to_string(),
        cni: cni(node).to_string(),
        ip_family: ip_family(node).to_string(),
        node_os: node_os(node).to_string(),
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
    let nodes: Api<Node> = Api::all(client);
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
    let facts = derive_facts(&node_name, &node);
    debug!(?facts, "derived node environment facts");
    let url = format!("{}/node/facts", broker_url.trim_end_matches('/'));
    match reqwest::Client::new().post(&url).json(&facts).send().await {
        Ok(resp) if resp.status().is_success() => {
            debug!(node = %node_name, "node facts reported");
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
    use k8s_openapi::api::core::v1::{NodeSpec, NodeStatus, NodeSystemInfo};
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
        let f = derive_facts("n1", &n);
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
        let f = derive_facts("n1", &n);
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
        let f = derive_facts("n1", &n);
        assert_eq!(
            (f.provider.as_str(), f.distro.as_str(), f.node_os.as_str()),
            ("gcp", "gke", "cos")
        );
    }

    #[test]
    fn k3s_suffix_beats_vanilla_and_calico_annotation_wins() {
        let n = node(
            Some("k3s://node"),
            &[],
            &[("projectcalico.org/IPv4Address", "10.0.0.5/24")],
            "v1.29.4+k3s1",
            "Ubuntu 22.04.4 LTS",
            &["10.42.0.0/24"],
        );
        let f = derive_facts("n1", &n);
        assert_eq!(
            (
                f.provider.as_str(),
                f.distro.as_str(),
                f.cni.as_str(),
                f.node_os.as_str()
            ),
            ("unknown", "k3s", "calico", "ubuntu")
        );
    }

    #[test]
    fn empty_node_degrades_to_unknowns_not_panics() {
        let f = derive_facts("n1", &Node::default());
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
    fn ipv6_only_pod_cidr_derives_ipv6() {
        let n = node(
            None,
            &[],
            &[],
            "v1.30.0",
            "Debian GNU/Linux 12",
            &["fd00::/64"],
        );
        let f = derive_facts("n1", &n);
        assert_eq!(
            (f.ip_family.as_str(), f.node_os.as_str()),
            ("ipv6", "debian")
        );
    }
}
