use crate::schema::{pod_details, pod_syscalls, pod_traffic, pod_packet_drop,svc_details};
use chrono::NaiveDateTime;
use diesel::{AsChangeset, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};

#[derive(
    Default,
    Debug,
    Clone,
    Insertable,
    Queryable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Selectable,
)]
#[diesel(table_name = pod_traffic)]
#[diesel(primary_key(uuid))]
pub struct PodTraffic {
    pub uuid: String,
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub pod_ip: Option<String>,
    pub pod_port: Option<String>,
    pub ip_protocol: Option<String>,
    pub traffic_type: Option<String>,
    pub traffic_in_out_ip: Option<String>,
    pub traffic_in_out_port: Option<String>,
    pub time_stamp: NaiveDateTime,
}

#[derive(
    Default,
    Debug,
    Clone,
    Insertable,
    Queryable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Selectable,
)]
#[diesel(table_name = pod_packet_drop)]
#[diesel(primary_key(uuid))]
pub struct PodPacketDrop {
    pub uuid: String,
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub pod_ip: Option<String>,
    pub pod_port: Option<String>,
    pub ip_protocol: Option<String>,
    pub traffic_type: Option<String>,
    pub traffic_in_out_ip: Option<String>,
    pub traffic_in_out_port: Option<String>,
    pub drop_reason: Option<String>,
    pub time_stamp: NaiveDateTime,
}


#[derive(
    Default,
    Debug,
    Insertable,
    Queryable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Selectable,
)]
#[diesel(table_name = pod_details)]
#[diesel(primary_key(pod_name))]
pub struct PodDetail {
    pub pod_name: String,
    pub pod_ip: String,
    pub pod_namespace: Option<String>,
    pub pod_obj: Option<serde_json::Value>,
    pub time_stamp: NaiveDateTime,
}

#[derive(
    Default,
    Debug,
    Insertable,
    Queryable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Selectable,
)]
#[diesel(table_name = svc_details)]
#[diesel(primary_key(svc_ip))]
pub struct SvcDetail {
    pub svc_ip: String,
    pub svc_name: Option<String>,
    pub svc_namespace: Option<String>,
    pub service_spec: Option<serde_json::Value>,
    pub time_stamp: NaiveDateTime,
}

#[derive(
    Default,
    Debug,
    Insertable,
    Queryable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Selectable,
)]
#[diesel(table_name = pod_syscalls)]
#[diesel(primary_key(pod_name))]
pub struct PodSyscalls {
    pub pod_name: String,
    pub pod_namespace: String,
    pub syscalls: String,
    pub arch: String,
    pub time_stamp: NaiveDateTime,
}

#[derive(Serialize, Deserialize)]

pub struct PodInputSyscalls {
    pub pod_name: String,
    pub pod_namespace: String,
    pub syscalls: Vec<String>,
    pub arch: String,
    pub time_stamp: NaiveDateTime,
}
