use chrono::NaiveDateTime;
use serde::{Deserialize as _, Deserializer, Serialize};
use serde_derive::Deserialize;
use std::collections::BTreeMap;

/// Deserialise a value that may be absent, `null`, or present, into `T`'s
/// default when it is either of the first two.
///
/// `#[serde(default)]` alone covers only the ABSENT case. A field that
/// arrives as an explicit `null` is still handed to `T`'s deserialiser,
/// which for a sequence or map type is a hard error. Pairing this with
/// `default` covers both.
fn null_tolerant<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

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
    pub decision: Option<String>,
    pub time_stamp: NaiveDateTime,
}

#[derive(Debug, Default, Serialize)]
pub struct PodPacketDrop {
    pub uuid: String,
    pub pod_name: String,
    pub pod_namespace: Option<String>,
    pub pod_ip: String,
    pub pod_port: Option<String>,
    pub traffic_type: Option<String>,
    pub traffic_in_out_ip: Option<String>,
    pub traffic_in_out_port: Option<String>,
    pub ip_protocol: Option<String>,
    pub drop_reason: Option<String>,
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
    /// Every address Kubernetes reports for this pod (`status.podIPs`),
    /// in canonical `IpAddr::to_string()` form. A dual-stack pod has one
    /// IPv4 and one IPv6 entry; a single-stack pod has exactly one, equal
    /// to `pod_ip`.
    ///
    /// `pod_ip` remains the primary and stays populated from
    /// `status.podIP` — the broker keys existing rows on it and older
    /// brokers ignore this field entirely — so this is additive only.
    ///
    /// Deserialisation must tolerate BOTH a missing field and an
    /// explicit `null`, which are different cases in serde and only the
    /// first is covered by `#[serde(default)]` alone. The broker's own
    /// `PodDetail.pod_ips` is an `Option` with no `skip_serializing_if`,
    /// so a row whose column is NULL comes back over the wire as
    /// `"pod_ips": null` — and `Vec<String>` rejects that with "invalid
    /// type: null, expected a sequence". That matters because
    /// `pod_reconciler` parses `/pod/list/{node}` as a whole
    /// `Vec<PodDetail>`: a single NULL row would fail the entire
    /// response, so the reconcile loop would error every cycle and stop
    /// marking dead pods dead — leaving stale rows to resurface as
    /// phantom peers in generated policy.
    ///
    /// The column is NULL only in a broker-downgrade window (a
    /// pre-`pod_ips` broker inserting rows after the migration has been
    /// recorded as applied, so the backfill will not re-run), but the
    /// two components version independently and that window is real.
    #[serde(default, deserialize_with = "null_tolerant")]
    pub pod_ips: Vec<String>,
    pub pod_name: String,
    pub pod_namespace: Option<String>,
    pub pod_obj: Option<serde_json::Value>,
    pub time_stamp: NaiveDateTime,
    pub node_name: String,
    pub is_dead: bool,
    pub pod_identity: Option<String>,
    pub workload_selector_labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Serialize)]
pub struct SyscallData {
    pub pod_name: String,
    pub pod_namespace: String,
    pub syscalls: Vec<String>,
    pub arch: String,
    pub time_stamp: NaiveDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_detail_json(pod_ips_field: &str) -> String {
        format!(
            r#"{{"pod_ip":"10.0.0.1"{},"pod_name":"web","pod_namespace":"prod","pod_obj":null,"time_stamp":"2026-08-31T00:00:00","node_name":"node-a","is_dead":false,"pod_identity":null,"workload_selector_labels":null}}"#,
            pod_ips_field
        )
    }

    // pod_reconciler parses /pod/list/{node} as a whole Vec<PodDetail>,
    // so every row shape the broker can emit must deserialise. The
    // broker's pod_ips is an Option with no skip_serializing_if, so a
    // NULL column arrives as an explicit `null` rather than an omitted
    // key — and those are different cases in serde.

    #[test]
    fn pod_ips_absent_deserialises_to_empty() {
        let d: PodDetail = serde_json::from_str(&pod_detail_json("")).expect("absent must parse");
        assert!(d.pod_ips.is_empty());
    }

    #[test]
    fn pod_ips_null_deserialises_to_empty() {
        // The regression this guards. Under `#[serde(default)]` alone
        // this failed with "invalid type: null, expected a sequence",
        // and because the reconcile loop parses the whole list in one
        // go, ONE such row failed every pod on the node — dead pods
        // were never marked dead and stale rows resurfaced as phantom
        // peers in generated policy.
        let d: PodDetail = serde_json::from_str(&pod_detail_json(r#","pod_ips":null"#))
            .expect("explicit null must parse");
        assert!(d.pod_ips.is_empty());
    }

    #[test]
    fn pod_ips_populated_round_trips() {
        let d: PodDetail =
            serde_json::from_str(&pod_detail_json(r#","pod_ips":["10.0.0.1","fd00::1"]"#))
                .expect("array must parse");
        assert_eq!(d.pod_ips, vec!["10.0.0.1", "fd00::1"]);
    }
}
