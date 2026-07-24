mod add;
mod audit;
mod error;
mod get;
mod retention;
mod telemetry;
mod types;
mod version_check;
pub use add::{
    add_pod_details, add_pods, add_pods_batch, add_pods_syscalls, add_svc_details, mark_pod_dead,
};
pub use audit::AuditClient;
pub use error::*;
pub use retention::spawn as spawn_retention;
pub use telemetry::*;
pub use types::*;
pub use version_check::{get_version, spawn as spawn_version_check, VersionCheckState};
mod conn;
pub use conn::*;
mod schema;
pub use get::{
    get_audit_verdicts, get_pod_by_ip, get_pod_by_name, get_pod_details, get_pod_syscall_name,
    get_pod_traffic, get_pod_traffic_name, get_pods_by_node, get_svc_by_ip, get_svc_details,
};
pub use schema::{pod_details, pod_traffic};

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
