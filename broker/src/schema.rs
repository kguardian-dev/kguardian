// @generated automatically by Diesel CLI.

diesel::table! {
    // PK is pod_name, matching the migration (`pod_name VARCHAR
    // PRIMARY KEY`) and the PodDetail struct's
    // `#[diesel(primary_key(pod_name))]` annotation. The previous
    // `(pod_ip)` declaration here was inconsistent with both and
    // would silently misbehave for any query using diesel's PK-aware
    // helpers (.find(), Identifiable impls, joins).
    pod_details (pod_name) {
        pod_name -> Varchar,
        pod_ip -> Varchar,
        pod_namespace -> Nullable<Varchar>,
        pod_obj -> Nullable<Json>,
        time_stamp -> Timestamp,
        node_name -> Varchar,
        is_dead -> Bool,
        pod_identity -> Nullable<Varchar>,
        workload_selector_labels -> Nullable<Json>,
        // Jsonb (not Json like the two columns above): the pod-by-IP
        // lookup matches with the `@>` containment operator, which
        // only exists for jsonb, and the GIN index added alongside
        // the column is a jsonb_path_ops index.
        pod_ips -> Nullable<Jsonb>,
        // Top-level owning controller, resolved by the controller from
        // ownerReferences (ReplicaSet→Deployment, Job→CronJob). The
        // key a per-workload seccomp profile is grouped on. Declared
        // last to match the physical column order ALTER TABLE ADD
        // COLUMN produces — PodDetail derives Queryable, which is
        // positional, so any new column goes here.
        workload_kind -> Nullable<Varchar>,
        workload_name -> Nullable<Varchar>,
        // Capture tier (full|high|medium|low|custom) the controller ran
        // for this pod; NULL = unknown / older controller. Feeds
        // capture completeness (CaptureComplete condition, export
        // warning, drift). Positional — stays last.
        capture_level -> Nullable<Varchar>,
        // spec.hostNetwork of the pod; NULL = unknown / older
        // controller with no manifest to derive it from. A host-network
        // pod's IP is the node IP, so generators render node-IP peers
        // as ipBlock / host entities instead of a podSelector.
        // Positional — stays last.
        host_network -> Nullable<Bool>,
    }
}

diesel::table! {
    pod_traffic (uuid) {
        uuid -> Varchar,
        pod_name -> Nullable<Varchar>,
        pod_namespace -> Nullable<Varchar>,
        pod_ip -> Nullable<Varchar>,
        pod_port -> Nullable<Varchar>,
        ip_protocol -> Nullable<Varchar>,
        traffic_type -> Nullable<Varchar>,
        traffic_in_out_ip -> Nullable<Varchar>,
        traffic_in_out_port -> Nullable<Varchar>,
        decision -> Nullable<Varchar>,
        time_stamp -> Timestamp,
    }
}

diesel::table! {
    pod_syscalls (pod_name) {
        pod_name -> Varchar,
        pod_namespace -> Varchar,
        syscalls -> Varchar,
        arch -> Varchar,
        time_stamp -> Timestamp,
    }
}

diesel::table! {
    svc_details (svc_ip) {
        svc_ip -> Varchar,
        svc_name -> Nullable<Varchar>,
        svc_namespace -> Nullable<Varchar>,
        service_spec -> Nullable<Json>,
        time_stamp -> Timestamp,
    }
}

diesel::table! {
    audit_verdicts (id) {
        id -> BigSerial,
        policy_uid -> Varchar,
        policy_namespace -> Varchar,
        policy_name -> Varchar,
        direction -> Varchar,
        src_namespace -> Nullable<Varchar>,
        src_pod -> Nullable<Varchar>,
        dst_namespace -> Nullable<Varchar>,
        dst_pod -> Nullable<Varchar>,
        dst_port -> Int4,
        protocol -> Varchar,
        reason -> Nullable<Varchar>,
        observed_at -> Timestamp,
        verdict -> Varchar,
    }
}

diesel::table! {
    // Single row: this installation's anonymous id for the version
    // check-in (version_check.rs). Random UUID, no cluster/user data.
    install_info (install_id) {
        install_id -> Varchar,
        created_at -> Timestamp,
    }
}

diesel::table! {
    // One row per node: coarse environment facts the controller derives
    // from its own Node object, aggregated into the telemetry check-in
    // (contract v2). Values are fixed enum strings, never identifiers.
    node_facts (node_name) {
        node_name -> Varchar,
        provider -> Varchar,
        distro -> Varchar,
        cni -> Varchar,
        ip_family -> Varchar,
        node_os -> Varchar,
        time_stamp -> Timestamp,
    }
}

diesel::table! {
    // Per-workload monotonic union of observed syscalls, keyed on the
    // stable (namespace, kind, name) identity. `syscalls` / `arches`
    // are comma-joined sorted sets; `hash` is a content fingerprint
    // that names the generated seccomp profile. See the migration and
    // src/seccomp.rs.
    workload_syscalls (pod_namespace, workload_kind, workload_name) {
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        syscalls -> Text,
        arches -> Text,
        hash -> Varchar,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    // What seccomp profile files each node's distributor currently has
    // on disk: a JSON array of `{path, hash}` objects (legacy rows may
    // hold bare path strings). Replaced wholesale on every distributor
    // pass. Drives per-CR readiness. See src/seccomp.rs.
    seccomp_node_status (node_name) {
        node_name -> Varchar,
        paths -> Jsonb,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    // Mirror of every SeccompProfile CR (kguardian.dev/v1alpha1) the
    // controller sees. `syscalls` = sorted csv of the CR's ALLOW names
    // (drift is computed against it); `hash` = the CR's status.hash
    // (rendered file bytes). See src/seccomp.rs and the migration.
    seccomp_crs (namespace, name) {
        namespace -> Varchar,
        name -> Varchar,
        workload_kind -> Nullable<Varchar>,
        workload_name -> Nullable<Varchar>,
        default_action -> Varchar,
        syscalls -> Text,
        architectures -> Text,
        hash -> Varchar,
        ready -> Int4,
        total -> Int4,
        dist_state -> Varchar,
        updated_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    pod_details,
    pod_traffic,
    svc_details,
    pod_syscalls,
    audit_verdicts,
    node_facts,
);
