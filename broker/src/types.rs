use crate::schema::{audit_verdicts, pod_details, pod_syscalls, pod_traffic, svc_details};
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
    pub decision: Option<String>,
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
    pub node_name: String,
    pub is_dead: bool,
    pub pod_identity: Option<String>,
    pub workload_selector_labels: Option<serde_json::Value>,
    /// Every address the pod holds, as a JSON array of canonicalised
    /// strings — the dual-stack counterpart to the scalar `pod_ip`
    /// above, which can only ever carry one family.
    ///
    /// Optional on the wire, and `#[serde(default)]` makes a missing
    /// field deserialise to `None` rather than a 400. The broker and
    /// the controller ship independently (RELEASES.md), so a
    /// controller predating dual-stack support posts `pod_ip` alone
    /// and must keep working; `upsert_pod_details` fills the gap with
    /// `[pod_ip]`. Field order matters — `Queryable` is positional, so
    /// new fields append after this to match `schema::pod_details`.
    #[serde(default)]
    pub pod_ips: Option<serde_json::Value>,
    /// Kind and name of the top-level controller that owns this pod
    /// (`Deployment`, `StatefulSet`, `DaemonSet`, `CronJob`, ...), as
    /// resolved by the controller from ownerReferences. `None` for a
    /// bare pod, and `None` from a controller old enough not to send
    /// these — `AsChangeset` skips `None`, so the upsert never nulls a
    /// previously-populated column. Keyed on by the per-workload
    /// seccomp profile aggregation.
    #[serde(default)]
    pub workload_kind: Option<String>,
    #[serde(default)]
    pub workload_name: Option<String>,
    /// Syscall capture tier the controller ran for this pod when it
    /// last upserted the row: `full` | `high` | `medium` | `low` |
    /// `custom`. `None` from a controller predating tiers (the JSON key
    /// is simply absent) or when the posted value is not one of the
    /// five (normalised away in `upsert_pod_details`). Capture
    /// completeness (every contributing pod `full`) feeds the CR's
    /// `CaptureComplete` condition, the export warning and drift
    /// reporting; `None` counts as `low` there — a profile is never
    /// assumed complete. Positional, so it stays last.
    #[serde(default)]
    pub capture_level: Option<String>,
    /// `spec.hostNetwork` of the pod. A host-network pod's address is
    /// the node's address, so a peer that resolves to one is node
    /// traffic and a NetworkPolicy `podSelector` on its labels can
    /// never match it — the generators render an `ipBlock` (Kubernetes)
    /// or `host`/`remote-node` entities (Cilium) instead. `None` from a
    /// controller predating the field, unless the posted `pod_obj`
    /// carries a manifest to derive it from (`upsert_pod_details`);
    /// `None` on the wire means "unknown" and generators keep their
    /// pre-existing behaviour. Positional, so it stays last.
    #[serde(default)]
    pub host_network: Option<bool>,
}

/// The syscall capture tiers, exactly as the controller and chart spell
/// them. Anything else on the wire is stored as NULL (unknown).
pub const CAPTURE_LEVELS: [&str; 5] = ["full", "high", "medium", "low", "custom"];

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

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = audit_verdicts)]
pub struct AuditVerdict {
    pub id: i64,
    pub policy_uid: String,
    pub policy_namespace: String,
    pub policy_name: String,
    pub direction: String,
    pub src_namespace: Option<String>,
    pub src_pod: Option<String>,
    pub dst_namespace: Option<String>,
    pub dst_pod: Option<String>,
    pub dst_port: i32,
    pub protocol: String,
    pub reason: Option<String>,
    pub observed_at: NaiveDateTime,
    pub verdict: String, // "Allow" | "WouldDeny"
}

/// One node's coarse environment facts, POSTed by the controller at
/// startup (controller/src/node_facts.rs) and aggregated into the
/// anonymous telemetry check-in (version_check.rs). Fixed enum strings
/// only — the wire values are re-whitelisted by the version service.
#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Insertable, AsChangeset, Identifiable,
)]
#[diesel(table_name = crate::schema::node_facts)]
#[diesel(primary_key(node_name))]
pub struct NodeFact {
    pub node_name: String,
    pub provider: String,
    pub distro: String,
    pub cni: String,
    pub ip_family: String,
    pub node_os: String,
    #[serde(default = "chrono_now")]
    pub time_stamp: NaiveDateTime,
}

/// Serde default for rows arriving without a timestamp (the controller
/// doesn't send one; the broker stamps arrival time).
fn chrono_now() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}
