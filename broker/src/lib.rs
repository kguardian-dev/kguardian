mod add;
mod audit;
pub mod auth;
mod compute;
mod compute_api;
mod compute_types;
mod error;
mod get;
mod image_inventory;
mod ip;
mod peer;
mod pod_security;
mod read_budget;
mod retention;
pub mod routes;
mod seccomp;
mod seccomp_denial;
mod seccomp_profiles_cache;
mod telemetry;
mod types;
mod version_check;
mod workload_profile;
pub use add::{
    add_node_facts, add_pod_details, add_pods_batch, add_pods_syscalls, add_svc_details,
    mark_pod_dead,
};
pub use audit::AuditClient;
pub use compute::{compute_findings, ComputeThresholds};
pub use compute_api::{
    add_compute_batch, add_compute_history_batch, compute_ingest_scope, get_compute_contention,
    get_compute_findings, get_compute_history, get_compute_latest, get_compute_nodes,
};
pub use compute_types::*;
pub use error::*;
pub use image_inventory::{get_image, get_images, get_workload_containers};
pub use peer::spawn as spawn_peer_late_resolve;
pub use read_budget::*;
pub use retention::spawn as spawn_retention;
pub use telemetry::*;
pub use types::*;
pub use version_check::{
    get_cluster_environment, get_version, spawn as spawn_version_check, VersionCheckState,
};
pub use workload_profile::{
    get_workload_profile, get_workload_profile_diff, get_workload_profile_version,
    get_workload_profile_versions, get_workloads, spawn as spawn_workload_profile_snapshotter,
};
mod conn;
pub use conn::*;
mod schema;
pub use get::{
    get_audit_verdicts, get_pod_by_ip, get_pod_by_name, get_pod_details, get_pod_syscall_name,
    get_pod_traffic, get_pod_traffic_name, get_pods_by_node, get_svc_by_ip, get_svc_details,
};
pub use schema::{pod_details, pod_traffic};
pub use seccomp::{
    delete_seccomp_cr, export_seccomp_profile, export_seccomp_profile_post, get_seccomp_profile,
    get_seccomp_profile_file, list_seccomp_profiles, post_seccomp_node_status, put_seccomp_cr,
};
// `seccomp_denials_resource` rather than two `#[get]`/`#[post]` handlers:
// the ingest side needs its own JSON body limit, which has to be attached to
// the resource rather than applied app-wide. See the doc comment there.
pub use seccomp_denial::{
    seccomp_denials_resource, spawn_metrics_refresh as spawn_seccomp_denial_metrics, DenialLabels,
    DenialRow, SeccompDenialMetrics, SeccompDenialSeries,
};
pub use seccomp_profiles_cache::{SeccompProfilesCache, DEFAULT_PROFILES_CACHE_TTL_SECS};

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    /// Process-wide lock for tests that mutate environment variables.
    /// `std::env` is process-global: parallel tests mutating even
    /// *different* keys race on libc's `environ` (and one module's
    /// remove_var can crash another's concurrent var()). Every
    /// env-mutating test helper in this crate must hold this lock —
    /// per-module locks give no cross-module exclusion (the flaky
    /// conn::returns_connection_manager_when_url_set failure).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the env lock, tolerating poison: #[should_panic] tests
    /// legitimately panic while holding it, and the next test must not
    /// fail on the poisoned mutex.
    pub fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }
}
