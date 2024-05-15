use serde_derive::Deserialize;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodInspect {
    pub container_id: Option<String>,
    pub status: PodInfo,
    pub info: Info,
    pub if_index: [std::option::Option<u32>; 2],
    pub namespace_pid: Option<u32>,
    pub pid: Option<u32>,
    pub cgroup_path: Option<String>,
}
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Info {
    pub config: Config,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodInfo {
    pub pod_name: String,
    pub pod_namespace: Option<String>,
    pub pod_ip: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Network {
    pub ip: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Metadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
}
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    pub metadata: Metadata,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Traffic {
    pub(crate) pod_data: PodInfo,
    pub(crate) src_addr: String,
    pub(crate) dst_addr: String,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) traffic_type: u32,
    pub(crate) ip_protocol: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Labels {
    #[serde(rename = "io.kubernetes.pod.name")]
    pub pod_name: String,
    #[serde(rename = "io.kubernetes.pod.namespace")]
    pub pod_namespace: String,
    #[allow(dead_code)]
    #[serde(rename = "io.kubernetes.pod.uid")]
    pod_uid: String,
}

#[derive(Debug, Deserialize)]
pub struct Linux {
    pub linux: Namespaces,
}

#[derive(Debug, Deserialize)]
pub struct Namespaces {
    pub namespaces: Vec<Namespace>,
}

#[derive(Debug, Deserialize)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub nstype: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PodDetails {
    pub items: Vec<PodItems>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct PodItems {
    pub id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Containers {
    pub containers: Vec<Container>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct Container {
    #[serde(rename = "id")]
    pub container_id: String,
    pub labels: Labels,
}
