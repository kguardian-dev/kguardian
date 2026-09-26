-- Workload security profile read model and versions (#1533 P0-5).
--
-- workload_profile_latest: one row per workload the snapshotter has
-- computed (workload_profile.rs). Backs GET /workloads. `summary` is the
-- list item's posture/dimension summary. Rows not recomputed within
-- PROFILE_VERSIONS_RETENTION_DAYS belong to a workload that no longer
-- has any source data and are pruned by retention.rs.
--
-- workload_profile_versions: immutable, content-hashed snapshots of the
-- policy-relevant parts of a profile. A row is written only when the
-- content hash changes. Bounded two ways:
--   * the newest PROFILE_VERSIONS_MAX_PER_WORKLOAD (default 50) per
--     workload are kept; the snapshotter trims older ones on write;
--   * retention.rs prunes versions older than
--     PROFILE_VERSIONS_RETENTION_DAYS (default 90), except each
--     workload's newest.
-- Same (namespace, kind, name) key as workload_syscalls and
-- workload_containers; cluster_id 'primary' until multi-cluster lands.

CREATE TABLE IF NOT EXISTS workload_profile_latest (
    cluster_id       VARCHAR   NOT NULL DEFAULT 'primary',
    pod_namespace    VARCHAR   NOT NULL,
    workload_kind    VARCHAR   NOT NULL,
    workload_name    VARCHAR   NOT NULL,
    revision         INTEGER   NOT NULL,
    content_hash     VARCHAR   NOT NULL,
    posture_status   VARCHAR   NOT NULL,
    summary          JSONB     NOT NULL,
    computed_at      TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    last_changed_at  TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (cluster_id, pod_namespace, workload_kind, workload_name)
);
CREATE INDEX IF NOT EXISTS idx_workload_profile_latest_computed_at
    ON workload_profile_latest (computed_at);

CREATE TABLE IF NOT EXISTS workload_profile_versions (
    id               BIGSERIAL PRIMARY KEY,
    cluster_id       VARCHAR   NOT NULL DEFAULT 'primary',
    pod_namespace    VARCHAR   NOT NULL,
    workload_kind    VARCHAR   NOT NULL,
    workload_name    VARCHAR   NOT NULL,
    revision         INTEGER   NOT NULL,
    content_hash     VARCHAR   NOT NULL,
    dimension_hashes JSONB     NOT NULL,
    snapshot         JSONB     NOT NULL,
    posture          JSONB     NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    UNIQUE (cluster_id, pod_namespace, workload_kind, workload_name, revision)
);
CREATE INDEX IF NOT EXISTS idx_workload_profile_versions_created_at
    ON workload_profile_versions (created_at);
