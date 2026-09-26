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
        // pod_obj.status.startTime as naive UTC, captured on /pod/spec
        // before compact_pod_obj strips `status`. Drives the start-time
        // guard: a flow never resolves to a pod that started after it.
        // NULL = unknown (older broker wrote the row, or no startTime).
        // Positional — stays last.
        started_at -> Nullable<Timestamp>,
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
        // Peer identity stamped at ingest (src/peer.rs). All nullable;
        // NULL peer_kind = unresolved (external / legacy / spec never
        // arrived). Declared after time_stamp to match the physical
        // column order — PodTraffic derives Queryable, which is
        // positional, so any new column goes here.
        peer_kind -> Nullable<Varchar>,
        peer_namespace -> Nullable<Varchar>,
        peer_name -> Nullable<Varchar>,
        peer_uid -> Nullable<Varchar>,
        peer_workload_kind -> Nullable<Varchar>,
        peer_workload_name -> Nullable<Varchar>,
        peer_resolved_at -> Nullable<Timestamp>,
        // Drop classification and its evidence. Positional (Queryable),
        // so these stay last too.
        drop_cause -> Nullable<Varchar>,
        syn_retries -> Nullable<Int4>,
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
        policy_enforcement -> Nullable<Varchar>,
        // Static compute facts (design D10): node capacity for gauge
        // normalisation and the three facts that decide whether the
        // compute feature can work on the node. NULL = a controller
        // that predates the columns. Positional — these stay last.
        cpu_cores -> Nullable<Int4>,
        memory_bytes -> Nullable<Int8>,
        kernel_version -> Nullable<Text>,
        cgroup_version -> Nullable<Int2>,
        psi_available -> Nullable<Bool>,
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
        // Cardinality of `syscalls`, written by recompute_workload so the
        // profile list never has to read the blob to report a count. NULL
        // on rows written before the column existed; the read path counts
        // those from the blob until the next recompute backfills them.
        // Last in the block because Queryable is positional.
        syscall_count -> Nullable<Integer>,
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

diesel::table! {
    // Live compute gauge per container: one row per LIVE container,
    // upserted on every sample interval by `POST /pod/compute/batch`.
    // Counters are deltas over `interval_ms`; gauges are instantaneous;
    // `cpu_usage_millis` is derived at ingest. `blame` is the wire
    // culprit list stored verbatim as a JSONB array. See
    // src/compute_api.rs and the migration.
    pod_compute_latest (container_uid) {
        container_uid -> Text,
        pod_uid -> Text,
        namespace -> Text,
        pod_name -> Text,
        container -> Text,
        node -> Text,
        cgroup_id -> Int8,
        ts -> Timestamp,
        interval_ms -> Int4,
        cpu_usage_millis -> Double,
        cpu_quota_usec -> Nullable<Int8>,
        cpu_period_usec -> Int8,
        cpu_request_millis -> Nullable<Int8>,
        cpu_limit_millis -> Nullable<Int8>,
        cpu_nr_periods -> Int8,
        cpu_nr_throttled -> Int8,
        cpu_throttled_usec -> Int8,
        cpu_psi_some10 -> Double,
        cpu_psi_full10 -> Double,
        mem_current -> Int8,
        mem_working_set -> Int8,
        mem_limit -> Nullable<Int8>,
        mem_request -> Nullable<Int8>,
        mem_psi_some10 -> Double,
        mem_psi_full10 -> Double,
        mem_events_high -> Int8,
        mem_events_max -> Int8,
        mem_oom_kill -> Int8,
        mem_refault -> Int8,
        mem_pgmajfault -> Int8,
        runq_count -> Nullable<Int8>,
        runq_p50_us -> Nullable<Int8>,
        runq_p95_us -> Nullable<Int8>,
        runq_p99_us -> Nullable<Int8>,
        runq_max_us -> Nullable<Int8>,
        runq_overflow -> Nullable<Int8>,
        blame -> Jsonb,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    // Per-container compute history: one row per container per minute
    // (`resolution_secs = 60`, written by the controller) or per five
    // minutes (`resolution_secs = 300`, produced by the retention.rs
    // downsample). Gauges carry avg/max/last, counters are sums,
    // `runq_hist` is the summed 24-bucket run-queue latency histogram.
    pod_compute_history (id) {
        id -> Int8,
        container_uid -> Text,
        pod_uid -> Text,
        namespace -> Text,
        pod_name -> Text,
        container -> Text,
        node -> Text,
        ts -> Timestamp,
        resolution_secs -> Int4,
        cpu_usage_millis_avg -> Double,
        cpu_usage_millis_max -> Double,
        cpu_usage_millis_last -> Double,
        cpu_quota_usec -> Nullable<Int8>,
        cpu_period_usec -> Int8,
        cpu_request_millis -> Nullable<Int8>,
        cpu_limit_millis -> Nullable<Int8>,
        cpu_nr_periods -> Int8,
        cpu_nr_throttled -> Int8,
        cpu_throttled_usec -> Int8,
        cpu_psi_some10_avg -> Double,
        cpu_psi_some10_max -> Double,
        cpu_psi_full10_avg -> Double,
        cpu_psi_full10_max -> Double,
        mem_current_avg -> Int8,
        mem_current_max -> Int8,
        mem_current_last -> Int8,
        mem_working_set_avg -> Int8,
        mem_working_set_max -> Int8,
        mem_working_set_last -> Int8,
        mem_limit -> Nullable<Int8>,
        mem_request -> Nullable<Int8>,
        mem_psi_some10_avg -> Double,
        mem_psi_some10_max -> Double,
        mem_psi_full10_avg -> Double,
        mem_psi_full10_max -> Double,
        mem_events_high -> Int8,
        mem_events_max -> Int8,
        mem_oom_kill -> Int8,
        mem_refault -> Int8,
        mem_pgmajfault -> Int8,
        runq_count -> Nullable<Int8>,
        runq_p50_us -> Nullable<Int8>,
        runq_p95_us -> Nullable<Int8>,
        runq_p99_us -> Nullable<Int8>,
        runq_max_us -> Nullable<Int8>,
        runq_overflow -> Nullable<Int8>,
        runq_hist -> Nullable<Array<Int8>>,
    }
}

diesel::table! {
    // Scheduler-probe blame pairs per minute: (victim container, culprit
    // cgroup) with the summed preemption count and wait. `culprit_kind`
    // is pod | system | kernel | unknown; `culprit_container_uid` is set
    // only for tracked pod culprits. See src/compute.rs (D6).
    pod_contention_history (id) {
        id -> Int8,
        ts -> Timestamp,
        node -> Text,
        victim_container_uid -> Text,
        victim_pod_uid -> Text,
        victim_namespace -> Text,
        culprit_cgroup_id -> Int8,
        culprit_kind -> Text,
        culprit_ref -> Text,
        culprit_container_uid -> Nullable<Text>,
        count -> Int8,
        wait_ns -> Int8,
    }
}

diesel::table! {
    // One row per node, upserted with every compute sample: the LIVE
    // half of node state (feature on / supported / probe loaded, node
    // PSI, context-switch rate, BPF map occupancy, unknown-blame share).
    // Static facts live on node_facts (D10).
    node_compute_latest (node) {
        node -> Text,
        ts -> Timestamp,
        interval_ms -> Int4,
        ctxt_per_sec -> Double,
        compute_enabled -> Bool,
        compute_supported -> Bool,
        contention_loaded -> Bool,
        cpu_some10 -> Double,
        cpu_full10 -> Double,
        mem_some10 -> Double,
        mem_full10 -> Double,
        cpu_cores -> Int4,
        memory_bytes -> Int8,
        bpf_runq_enqueued -> Int8,
        bpf_runq_hist -> Int8,
        bpf_pair -> Int8,
        unknown_blame_share -> Double,
        updated_at -> Timestamp,
        // BPF map insert failures during the last sample interval (the
        // controller ships deltas of the kernel's cumulative counters);
        // NULL from a controller that predates them. Positional — stay last.
        bpf_hist_update_failures -> Nullable<Int8>,
        bpf_pair_update_failures -> Nullable<Int8>,
    }
}

diesel::table! {
    // Kernel seccomp verdicts, aggregated per (pod, syscall, action).
    // One row accumulates every drain the controller ships for that key
    // — `count` is summed and the timestamps bracketed by the ingest
    // upsert — so this is a rollup table, not an event log. See the
    // migration and src/seccomp_denial.rs.
    //
    // `first_seen` / `last_seen` are Timestamptz, not the Timestamp the
    // rest of this schema uses: they are produced on the node rather
    // than stamped by the broker, so the zone travels with the value.
    seccomp_denials (id) {
        id -> BigSerial,
        pod_uid -> Text,
        pod_name -> Text,
        pod_namespace -> Text,
        // NULL = attribution unresolved when the row was written. The
        // upsert COALESCEs, so a later resolvable report fills it in and
        // an unresolvable one never erases it.
        workload_kind -> Nullable<Text>,
        workload_name -> Nullable<Text>,
        node_name -> Nullable<Text>,
        syscall -> Text,
        syscall_nr -> Nullable<Integer>,
        action -> Text,
        // Raw SECCOMP_RET_* value. Int8 because SECCOMP_RET_KILL_PROCESS
        // (0x80000000) overflows a signed 32-bit column.
        action_raw -> Nullable<Int8>,
        arch -> Nullable<Text>,
        count -> Int8,
        first_seen -> Timestamptz,
        last_seen -> Timestamptz,
    }
}

diesel::table! {
    // Per-node seccomp denial capture heartbeat. Upserted on every
    // Controller drain, INCLUDING an empty one — the empty report is the
    // point, because it is what separates "nothing was denied" from
    // "nothing was watching". See the migration and src/seccomp_denial.rs.
    seccomp_denial_nodes (node_name) {
        node_name -> Text,
        // The probe attached on this node. False on a CONFIG_AUDITSYSCALL=n kernel
        // where the Controller degraded gracefully: reporting in, not
        // capturing.
        capturing -> Bool,
        updated_at -> Timestamptz,
        // The drain cadence the node declares, in seconds. Staleness is
        // `max(300, interval * 3)` per node, capped at 1800, because the
        // Controller's drain interval is operator-set (1-600) and a fixed
        // window shorter than it reads a healthy fleet as Unknown. NULL =
        // the node declared none, which falls back to the 300 s floor.
        interval_seconds -> Nullable<Int8>,
    }
}

diesel::table! {
    // Image inventory, keyed by digest (#1533). One row per distinct
    // digest any container has been seen running; pruned when no
    // workload_containers row references it for the retention window.
    // See the migration and src/image_inventory.rs.
    images (digest) {
        digest -> Varchar,
        repository -> Nullable<Varchar>,
        tags -> Array<Text>,
        digest_kind -> Varchar,
        first_seen -> Timestamp,
        last_seen -> Timestamp,
    }
}

diesel::table! {
    // One row per (workload, container, digest): image ref and the
    // securityContext / pod-level posture subset the controller reports
    // on /pod/spec. Same (namespace, kind, name) workload key as
    // workload_syscalls, plus cluster_id.
    workload_containers (cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest) {
        cluster_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        container_name -> Varchar,
        image_digest -> Varchar,
        container_kind -> Varchar,
        image_ref -> Varchar,
        security_context -> Jsonb,
        pod_security -> Jsonb,
        last_pod_name -> Nullable<Varchar>,
        first_seen -> Timestamp,
        last_seen -> Timestamp,
        state -> Nullable<Varchar>,
        state_reason -> Nullable<Varchar>,
        ref_seen_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    // Workload security profile read model (#1533 P0-5): one row per
    // workload the snapshotter computed; backs GET /workloads. See
    // src/workload_profile.rs and the migration.
    workload_profile_latest (cluster_id, pod_namespace, workload_kind, workload_name) {
        cluster_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        revision -> Int4,
        content_hash -> Varchar,
        posture_status -> Varchar,
        summary -> Jsonb,
        computed_at -> Timestamp,
        last_changed_at -> Timestamp,
    }
}

diesel::table! {
    // Immutable, content-hashed profile snapshots, written only when the
    // hash changes. Bounded per workload and by age (retention.rs).
    workload_profile_versions (id) {
        id -> Int8,
        cluster_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        revision -> Int4,
        content_hash -> Varchar,
        dimension_hashes -> Jsonb,
        snapshot -> Jsonb,
        posture -> Jsonb,
        created_at -> Timestamp,
    }
}

diesel::table! {
    // Export bundles handed out (#1533 P2-4): the "last exported profile"
    // drift baseline. Bounded per workload and by age (retention.rs).
    workload_profile_exports (id) {
        id -> Int8,
        cluster_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        revision -> Nullable<Int4>,
        content_hash -> Varchar,
        mode -> Varchar,
        artifacts -> Array<Text>,
        baseline -> Jsonb,
        exported_at -> Timestamp,
    }
}

diesel::table! {
    // Executables and shared libraries seen running, one row per
    // (workload, container, digest, kind, path) (#1533 P1-2). See the
    // migration and src/runtime_inventory.rs.
    runtime_executables (cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest, kind, path) {
        cluster_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        container_name -> Varchar,
        image_digest -> Varchar,
        kind -> Varchar,
        path -> Varchar,
        path_complete -> Bool,
        source -> Varchar,
        origin -> Varchar,
        last_pod_name -> Nullable<Varchar>,
        first_seen -> Timestamp,
        last_seen -> Timestamp,
    }
}

diesel::table! {
    // Capture coverage heartbeats per container instance (#1533 P1-2);
    // read through the kg_runtime_coverage SQL function.
    runtime_coverage (cluster_id, container_id) {
        cluster_id -> Varchar,
        container_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        container_name -> Varchar,
        image_digest -> Varchar,
        pod_name -> Varchar,
        node_name -> Varchar,
        mode -> Varchar,
        exec_probe -> Bool,
        lib_probe -> Bool,
        start_mode -> Varchar,
        tracking_since -> Timestamp,
        covered_since -> Timestamp,
        last_heartbeat -> Timestamp,
        heartbeat_secs -> Int4,
        gaps -> Int4,
        last_gap -> Nullable<Varchar>,
        events_dropped -> Int8,
        last_drop_at -> Nullable<Timestamp>,
        unsent -> Int8,
        incomplete -> Bool,
        ended -> Bool,
        // Added by 2026-09-29-200000_runtime_capabilities (ALTER TABLE ADD
        // COLUMN appends it last).
        cap_probe -> Bool,
    }
}

diesel::table! {
    // Capability checks per workload container (#1533 P2-7). See the
    // migration and src/runtime_capabilities.rs.
    runtime_capabilities (cluster_id, pod_namespace, workload_kind, workload_name, container_name, image_digest, capability, granted) {
        cluster_id -> Varchar,
        pod_namespace -> Varchar,
        workload_kind -> Varchar,
        workload_name -> Varchar,
        container_name -> Varchar,
        image_digest -> Varchar,
        capability -> Varchar,
        granted -> Bool,
        count -> Int8,
        last_pod_name -> Nullable<Varchar>,
        first_seen -> Timestamp,
        last_seen -> Timestamp,
        last_reported -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    pod_details,
    pod_traffic,
    svc_details,
    pod_syscalls,
    audit_verdicts,
    node_facts,
    pod_compute_latest,
    pod_compute_history,
    pod_contention_history,
    node_compute_latest,
);
