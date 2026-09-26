pub mod network;
pub mod seccomp_crd;
/// Kernel seccomp verdicts (`type=SECCOMP` audit records), captured on
/// the node and reported to the Broker.
pub mod seccomp_denial;
pub mod seccomp_distributor;
pub mod syscall;

pub mod error;
/// Image identity + securityContext subset reported on `/pod/spec`.
pub mod image_inventory;
pub mod pod_reconciler;
pub mod pod_watcher;
pub mod service_watcher;
/// Shared supervision for the long-lived apiserver watches above.
/// Internal: nothing outside the crate should drive a watch directly.
pub(crate) mod watch_loop;
use error::*;

pub mod models;
use models::*;
pub mod client;
pub mod container;
use client::*;

pub mod bpf;
pub mod capture_tiers;
pub mod compute_config;
pub mod compute_registry;
pub mod compute_sampler;
pub mod contention;
/// Startup syscall capture: containers that run before the pod watcher
/// has registered their pod (the seccomp startup-capture gap).
pub mod early_capture;
pub mod log;
pub mod node_facts;
/// One task per subsystem, with explicit supervision over what each
/// one stopping means. Replaces the `try_join!` fabric main used to
/// have; see the module docs for what that fused together.
pub mod supervisor;
