use chrono::NaiveDateTime;
use serde::Serialize;
use serde_derive::Deserialize;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PodInspect {
    pub container_id: Option<String>,
    pub status: PodInfo,
    pub info: Info,
    pub if_index: Option<u32>,
    pub namespace_pid: Option<u32>,
    pub pid: Option<u32>,
    pub inode_num: Option<u64>,
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
pub struct Config {
    pub metadata: Metadata,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Metadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
}

#[derive(Debug, Default, Serialize)]
pub struct PodTraffic {
    pub uuid: String,
    pub pod_name: String,
    pub pod_namespace: Option<String>,
    pub pod_ip: String,
    pub pod_port: Option<String>,
    pub traffic_type: Option<String>,
    pub traffic_in_out_ip: Option<String>,
    pub traffic_in_out_port: Option<String>,
    pub ip_protocol: Option<String>,
    pub time_stamp: NaiveDateTime,
}

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

#[derive(Debug, Default, Serialize)]
pub struct SyscallData {
    pub pod_name: String,
    pub pod_namespace: String,
    pub syscalls: Vec<String>,
    pub arch: String,
    pub time_stamp: NaiveDateTime,
}
