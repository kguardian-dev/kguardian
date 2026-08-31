use chrono::NaiveDateTime;
use serde::Serialize;
use serde_derive::Deserialize;
use std::collections::BTreeMap;

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
}
