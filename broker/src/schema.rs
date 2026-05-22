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

diesel::allow_tables_to_appear_in_same_query!(pod_details, pod_traffic, svc_details, pod_syscalls, audit_verdicts,);
