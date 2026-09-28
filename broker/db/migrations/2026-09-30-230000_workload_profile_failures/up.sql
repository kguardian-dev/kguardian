-- The snapshotter's last failure per workload (workload_profile.rs), so
-- GET /workloads can say "profile failed" instead of "not computed yet".
-- One row per workload whose most recent snapshot attempt failed; the
-- next successful snapshot deletes it, and the snapshotter prunes rows of
-- workloads that no longer have any source data. Same key as
-- workload_profile_latest, which keeps the last good profile untouched.
CREATE TABLE IF NOT EXISTS workload_profile_failures (
    cluster_id     VARCHAR   NOT NULL DEFAULT 'primary',
    pod_namespace  VARCHAR   NOT NULL,
    workload_kind  VARCHAR   NOT NULL,
    workload_name  VARCHAR   NOT NULL,
    last_error     VARCHAR   NOT NULL,
    failed_at      TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name)
);
