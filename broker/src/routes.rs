//! Route registration for the broker's data API.
//!
//! One function shared by `main.rs` and the auth tests, so the tests
//! exercise the same router the server runs. `/health` and `/metrics`
//! stay in `main.rs` (they need binary-only state). Every route
//! registered here must have an entry in [`crate::auth::ROUTES`].

use actix_web::web;

use crate::{
    add_node_facts, add_pod_details, add_pods_batch, add_pods_syscalls, add_svc_details,
    attestation_resource, compute_ingest_scope, delete_seccomp_cr, export_seccomp_profile,
    export_seccomp_profile_post, get_attestation_policy, get_attestations, get_audit_verdicts,
    get_cluster_environment, get_compute_contention, get_compute_findings, get_compute_history,
    get_compute_latest, get_compute_nodes, get_image, get_image_runtime, get_images, get_pod_by_ip,
    get_pod_by_name, get_pod_details, get_pod_syscall_name, get_pod_traffic, get_pod_traffic_name,
    get_pods_by_node, get_running_attestations, get_seccomp_profile, get_seccomp_profile_file,
    get_svc_by_ip, get_svc_details, get_version, get_vulnerabilities, get_vulnerability_exposure,
    get_workload_containers, get_workload_export, get_workload_profile, get_workload_profile_diff,
    get_workload_profile_version, get_workload_profile_versions, get_workload_runtime,
    get_workloads, image_sbom_cyclonedx_resource, image_sbom_resource,
    image_vulnerabilities_resource, list_seccomp_profiles, mark_pod_dead, post_seccomp_node_status,
    post_workload_export, put_seccomp_cr, runtime_coverage_resource, runtime_executables_resource,
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
        // Image inventory (#1533): paginated, LIMIT-clamped and charged
        // to the read budget like every other read.
        .service(get_images)
        .service(get_image)
        .service(get_workload_containers)
        // Runtime executable / shared-library inventory (#1533 P1-2): the
        // ingest carries its own JSON body limit
        // (runtime_inventory::RUNTIME_JSON_LIMIT_BYTES); both reads are
        // LIMIT-clamped and charged to the read budget.
        .service(runtime_executables_resource())
        .service(runtime_coverage_resource())
        .service(get_workload_runtime)
        .service(get_image_runtime)
        // Workload security profile (#1533 P0-5): list, detail, versions, diff.
        .service(get_workloads)
        .service(get_workload_profile)
        .service(get_workload_profile_versions)
        .service(get_workload_profile_version)
        .service(get_workload_profile_diff)
        // Supply chain (#1533 P1-3). GET + POST share a resource per path;
        // the POSTs read and cap their own gzip bodies (supplychain.rs).
        .service(image_vulnerabilities_resource())
        // Image signatures and attestations (#1533 P2-1).
        .service(attestation_resource())
        .service(get_running_attestations)
        .service(get_attestation_policy)
        .service(get_attestations)
        .service(image_sbom_resource())
        .service(image_sbom_cyclonedx_resource())
        .service(get_vulnerabilities)
        .service(get_vulnerability_exposure)
        // Export bundle (#1533 P2-4).
        .service(get_workload_export)
        .service(post_workload_export)
        .service(get_version)
        .service(get_cluster_environment);
}
