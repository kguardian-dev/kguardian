-- CR-driven seccomp distribution (CONTRACT v2). The broker is never the
-- source of truth for what is deployed: the user owns a SeccompProfile
-- CR (kguardian.dev/v1alpha1) in git, the controller reconciles it onto
-- nodes, and the broker only OBSERVES syscalls, RECOMMENDS a CR (the
-- export route) and REPORTS drift/completeness. So the lifecycle state
-- and the operator-override tables from the previous two migrations go
-- away: a "publish" is `kubectl apply`, an "override" is an edit to the
-- CR. Nothing ever read them from a UI, so no data migration.
DROP TABLE IF EXISTS workload_seccomp_state;
DROP TABLE IF EXISTS seccomp_override_audit;
DROP TABLE IF EXISTS workload_seccomp_overrides;

-- Mirror of every SeccompProfile CR the controller sees (one row per
-- CR, PUT on every watch event / resync, DELETE on CR deletion). It
-- exists so the UI can show "what is deployed vs what was observed"
-- without the broker talking to the API server.
--
-- `syscalls` is the sorted csv of the names in the CR's SCMP_ACT_ALLOW
-- rules — the set drift is computed against. `hash` is the CR's
-- status.hash (FNV-1a-64 over the rendered file bytes, controller-
-- computed) and is what a node's reported file hash must equal for the
-- node to count as Ready. ready/total/dist_state mirror the CR's own
-- status.distribution verbatim; the broker computes its own from
-- seccomp_node_status and reports both.
CREATE TABLE IF NOT EXISTS seccomp_crs (
    namespace      VARCHAR   NOT NULL,
    name           VARCHAR   NOT NULL,
    workload_kind  VARCHAR,
    workload_name  VARCHAR,
    default_action VARCHAR   NOT NULL DEFAULT 'SCMP_ACT_LOG',
    syscalls       TEXT      NOT NULL DEFAULT '',
    architectures  TEXT      NOT NULL DEFAULT '',
    hash           VARCHAR   NOT NULL DEFAULT '',
    ready          INTEGER   NOT NULL DEFAULT 0,
    total          INTEGER   NOT NULL DEFAULT 0,
    dist_state     VARCHAR   NOT NULL DEFAULT 'Pending',
    updated_at     TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    PRIMARY KEY (namespace, name)
);

-- The summary endpoints match CRs to workloads by workloadRef.
CREATE INDEX IF NOT EXISTS idx_seccomp_crs_workload
  ON seccomp_crs (namespace, workload_kind, workload_name);
