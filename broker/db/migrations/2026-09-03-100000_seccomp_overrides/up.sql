-- Operator adjustments to a generated seccomp profile, kept SEPARATE from
-- the observed data. workload_syscalls.syscalls stays the pure observed
-- union — the ingest recompute rewrites it every ~10s and would clobber
-- any human edit made there. The effective profile a node gets is
--   (observed ∪ add_syscalls) \ remove_syscalls
-- with default_action overriding the served action. workload_syscalls.hash
-- names that effective set (recomputed on every ingest AND on every
-- override write), so an edit lands as a new file within one distributor
-- poll and the previous file stays for rollback.
--
-- `revision` is optimistic-concurrency: a client PUTs the revision it
-- last read; a mismatch is a 409 so two editors can't silently stomp.
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

-- Append-only trail. An override implicated in an incident needs "who
-- changed what, when". Not folded into audit_verdicts — different shape,
-- different retention, different subject.
CREATE TABLE IF NOT EXISTS seccomp_override_audit (
    id            BIGSERIAL PRIMARY KEY,
    pod_namespace VARCHAR   NOT NULL,
    workload_kind VARCHAR   NOT NULL,
    workload_name VARCHAR   NOT NULL,
    op            VARCHAR   NOT NULL,   -- 'put' | 'delete'
    diff          JSONB     NOT NULL,
    updated_by    VARCHAR   NOT NULL,
    at            TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE INDEX IF NOT EXISTS idx_seccomp_override_audit_workload
  ON seccomp_override_audit (pod_namespace, workload_kind, workload_name, at DESC);
