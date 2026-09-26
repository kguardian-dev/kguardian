-- Workload profile export records (#1533 P2-4 / P2-5).
--
-- One row per export bundle handed out by
-- GET /workloads/{ns}/{kind}/{name}/export (unless the caller passes
-- record=false). It is the "last exported profile" baseline that drift
-- detection compares against: `baseline` copies the images and
-- podSecurity parts of the profile snapshot at export time, so the
-- baseline survives version trimming.
--
-- Bounded two ways:
--   * the newest 20 per workload are kept; older ones are trimmed on write
--     (profile_drift::record_export);
--   * retention.rs prunes records older than PROFILE_VERSIONS_RETENTION_DAYS
--     except each live workload's newest.

CREATE TABLE IF NOT EXISTS workload_profile_exports (
    id               BIGSERIAL PRIMARY KEY,
    cluster_id       VARCHAR   NOT NULL DEFAULT 'primary',
    pod_namespace    VARCHAR   NOT NULL,
    workload_kind    VARCHAR   NOT NULL,
    workload_name    VARCHAR   NOT NULL,
    revision         INTEGER   NULL,
    content_hash     VARCHAR   NOT NULL,
    mode             VARCHAR   NOT NULL,
    artifacts        TEXT[]    NOT NULL DEFAULT '{}',
    baseline         JSONB     NOT NULL,
    exported_at      TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS idx_workload_profile_exports_workload
    ON workload_profile_exports (cluster_id, pod_namespace, workload_kind, workload_name, exported_at DESC);
CREATE INDEX IF NOT EXISTS idx_workload_profile_exports_exported_at
    ON workload_profile_exports (exported_at);
