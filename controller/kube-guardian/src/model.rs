use serde_derive::Deserialize;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodInspect {
    pub container_id: Option<String>,
    pub status: PodInfo,
    pub info: Info,
    pub if_index: Option<u32>,
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
pub struct Metadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
}
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    pub metadata: Metadata,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Traffic {
    pub(crate) src_addr: String,
    pub(crate) dst_addr: String,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) traffic_type: u32,
    pub(crate) ip_protocol: String,
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
