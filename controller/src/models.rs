use chrono::NaiveDateTime;
use serde::{Deserialize as _, Deserializer, Serialize};
use serde_derive::Deserialize;
use std::collections::BTreeMap;

/// Bit flags packed into the eBPF `inode_num` map value. The network and
/// netpolicy probes only test the key for presence, but the syscall probe
/// reads `RECORD_ALL_SYSCALLS` to decide whether to bypass its allowlist.
/// Keep the bit positions in sync with the `KG_FLAG_*` defines in
/// `controller/src/bpf/helper.h`.
pub mod pod_flags {
    /// The netns belongs to a pod kube-guardian tracks. Always set on a
    /// registration; a bare "present" marker for the network probes.
    pub const POD_TRACKED: u32 = 1 << 0;
    /// Capture every syscall for this netns, ignoring `allowed_syscalls` —
    /// set when the pod's workload opted in via the seccomp-record
    /// annotation. See `docs/design/per-workload-seccomp-distribution.md`.
    pub const RECORD_ALL_SYSCALLS: u32 = 1 << 1;
}

/// One pod's netns registration, passed from the pod watcher to the eBPF
/// map-update loop in `bpf.rs`. This was a bare `u64` inode until
/// per-workload seccomp recording needed a second bit of state travelling
/// the same channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodRegistration {
    /// Network-namespace inode — the `inode_num` map key.
    pub netns_inode: u64,
    /// `pod_flags` bitfield stored as the map value.
    pub flags: u32,
}

/// Shared map from network-namespace inode to the pod occupying it.
///
/// The value is an `Arc` on purpose. `DashMap` is NOT lock-free despite what
/// the call sites used to claim: it is an array of `RwLock`-guarded shards,
/// and `get()` hands back a `Ref` that keeps that shard read-locked until it
/// is dropped. Holding one across an `.await` deadlocks the controller,
/// because every subsystem is joined into a single task by `try_join!` in
/// main.rs — a sibling future calling `insert()` on the same shard blocks the
/// thread, and the future holding the guard can then never be polled to
/// release it. Nothing recovers; the process stays alive and silent.
///
/// Wrapping the value in `Arc` makes the safe pattern free: copy the handle
/// out of the guard, let the guard drop, and only then await. See
/// `lookup_pod`, which is the only sanctioned way to read this map.
pub type ContainerMap = std::sync::Arc<dashmap::DashMap<u64, std::sync::Arc<PodInspect>>>;

/// Read a pod out of the container map, releasing the shard guard before
/// returning.
///
/// Callers must go through this rather than using `map.get(..)` inline: the
/// temporary `Ref` lives to the end of the enclosing statement, so
/// `if let Some(p) = map.get(&k) { something().await }` keeps the shard
/// read-locked for the whole body. Returning an owned `Arc` makes that
/// mistake impossible to express at the call site.
/// The single audited use of `DashMap::get` in the crate. `clippy.toml`
/// disallows that method everywhere else so a call site cannot reintroduce
/// the guard-across-await outage; this is the one place it is correct,
/// because the guard is dropped before the function returns.
#[allow(clippy::disallowed_methods)]
pub fn lookup_pod(
    map: &dashmap::DashMap<u64, std::sync::Arc<PodInspect>>,
    inum: u64,
) -> Option<std::sync::Arc<PodInspect>> {
    map.get(&inum).map(|entry| std::sync::Arc::clone(&entry))
}

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
    use dashmap::DashMap;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    /// Documents `lookup_pod`'s contract: the shard's read guard is released
    /// before it returns, so a caller may hold the result across an `.await`
    /// without blocking a writer.
    ///
    /// Read what this does NOT do. It cannot fail if someone reintroduces the
    /// outage, because the outage lived at a *call site* writing
    /// `map.get(&k)` inline, not inside this function. Restoring that line in
    /// network.rs leaves this test green and clippy clean. The real gate is
    /// the `disallowed-methods` entry in controller/clippy.toml, which fails
    /// the build on any `DashMap::get` outside the single audited use here.
    /// This test only pins the contract that gate assumes.
    ///
    /// The writer runs on its own thread with a bounded wait rather than
    /// calling `insert()` directly: a regression must fail in bounded time,
    /// not hang CI forever.
    #[test]
    fn lookup_pod_releases_the_shard_guard_before_returning() {
        let map: Arc<DashMap<u64, Arc<PodInspect>>> = Arc::new(DashMap::new());
        map.insert(7, Arc::new(PodInspect::default()));

        // Held for the rest of the test, exactly as a caller holds it across
        // an await. This must NOT keep the shard locked.
        let held = lookup_pod(&map, 7).expect("pod should be present");

        let (tx, rx) = mpsc::channel();
        let writer = Arc::clone(&map);
        std::thread::spawn(move || {
            writer.insert(7, Arc::new(PodInspect::default()));
            let _ = tx.send(());
        });

        assert!(
            rx.recv_timeout(Duration::from_secs(10)).is_ok(),
            "insert blocked while the looked-up pod was still held: lookup_pod \
             is keeping the shard guard past its return, which deadlocks the \
             whole controller (see the ContainerMap docs)"
        );

        assert!(held.status.pod_name.is_empty());
    }

    /// A miss must not lock anything either.
    #[test]
    fn lookup_pod_returns_none_for_an_unknown_inode() {
        let map: DashMap<u64, Arc<PodInspect>> = DashMap::new();
        assert!(lookup_pod(&map, 1234).is_none());
        map.insert(1234, Arc::new(PodInspect::default()));
        assert!(lookup_pod(&map, 1234).is_some());
    }

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
