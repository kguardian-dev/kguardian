//! Route registration for the broker's data API.
//!
//! One function shared by `main.rs` and the auth tests, so the tests
//! exercise the same router the server runs. `/health` and `/metrics`
//! stay in `main.rs` (they need binary-only state). Every route
//! registered here must have an entry in [`crate::auth::ROUTES`].

use actix_web::web;

use crate::{
    add_node_facts, add_pod_details, add_pods_batch, add_pods_syscalls, add_svc_details,
    compute_ingest_scope, delete_seccomp_cr, export_seccomp_profile, export_seccomp_profile_post,
    get_audit_verdicts, get_cluster_environment, get_compute_contention, get_compute_findings,
    get_compute_history, get_compute_latest, get_compute_nodes, get_pod_by_ip, get_pod_by_name,
    get_pod_details, get_pod_syscall_name, get_pod_traffic, get_pod_traffic_name, get_pods_by_node,
    get_seccomp_profile, get_seccomp_profile_file, get_svc_by_ip, get_svc_details, get_version,
    list_seccomp_profiles, mark_pod_dead, post_seccomp_node_status, put_seccomp_cr,
    seccomp_denials_resource,
};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(add_pods_batch)
        .service(add_pod_details)
        .service(add_pods_syscalls)
        .service(get_pod_traffic)
        .service(get_pod_details)
        .service(add_svc_details)
        .service(get_pod_by_ip)
        .service(get_pod_by_name)
        .service(get_svc_details)
        .service(get_svc_by_ip)
        .service(get_pod_traffic_name)
        .service(get_pod_syscall_name)
        .service(list_seccomp_profiles)
        .service(get_seccomp_profile)
        .service(get_seccomp_profile_file)
        .service(export_seccomp_profile)
        .service(export_seccomp_profile_post)
        .service(post_seccomp_node_status)
        // GET + POST /seccomp/denials on one resource, carrying their
        // own JSON body limit (api::DENIAL_JSON_LIMIT_BYTES).
        .service(seccomp_denials_resource())
        .service(put_seccomp_cr)
        .service(delete_seccomp_cr)
        .service(get_pods_by_node)
        .service(get_audit_verdicts)
        .service(mark_pod_dead)
        .service(add_node_facts)
        // /pod/compute/{batch,history/batch} with their own 16 MiB
        // JsonConfig (compute_api::COMPUTE_JSON_LIMIT_BYTES).
        .service(compute_ingest_scope())
        .service(get_compute_latest)
        .service(get_compute_history)
        .service(get_compute_contention)
        .service(get_compute_findings)
        .service(get_compute_nodes)
        .service(get_version)
        .service(get_cluster_environment);
}
