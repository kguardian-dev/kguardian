DROP INDEX IF EXISTS idx_seccomp_crs_workload;
DROP TABLE IF EXISTS seccomp_crs;

-- Recreate the v1 lifecycle/override tables (shape as of the
-- 2026-09-03-120000 migration, `action` column included). Data is not
-- restored.
CREATE TABLE IF NOT EXISTS workload_seccomp_overrides (
    pod_namespace   VARCHAR   NOT NULL,
    workload_kind   VARCHAR   NOT NULL,
    workload_name   VARCHAR   NOT NULL,
    add_syscalls    TEXT      NOT NULL DEFAULT '',
    remove_syscalls TEXT      NOT NULL DEFAULT '',
    default_action  VARCHAR,
    note            TEXT,
    updated_by      VARCHAR   NOT NULL DEFAULT 'unknown',
    updated_at      TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    revision        INTEGER   NOT NULL DEFAULT 1,
    PRIMARY KEY (pod_namespace, workload_kind, workload_name)
);
CREATE TABLE IF NOT EXISTS seccomp_override_audit (
    id            BIGSERIAL PRIMARY KEY,
    pod_namespace VARCHAR   NOT NULL,
    workload_kind VARCHAR   NOT NULL,
    workload_name VARCHAR   NOT NULL,
    op            VARCHAR   NOT NULL,
    diff          JSONB     NOT NULL,
    updated_by    VARCHAR   NOT NULL,
    at            TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    action        VARCHAR   NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_seccomp_override_audit_workload
  ON seccomp_override_audit (pod_namespace, workload_kind, workload_name, at DESC);
CREATE TABLE IF NOT EXISTS workload_seccomp_state (
    pod_namespace VARCHAR   NOT NULL,
    workload_kind VARCHAR   NOT NULL,
    workload_name VARCHAR   NOT NULL,
    state         VARCHAR   NOT NULL DEFAULT 'draft',
    published_at  TIMESTAMP,
    published_by  VARCHAR,
    forced        BOOLEAN   NOT NULL DEFAULT false,
    PRIMARY KEY (pod_namespace, workload_kind, workload_name)
);
