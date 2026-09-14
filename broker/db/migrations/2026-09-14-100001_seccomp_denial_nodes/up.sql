-- Per-node seccomp denial capture heartbeat (DEVOPS-2101).
--
-- This table exists to answer one question that `seccomp_denials` cannot:
-- **is anything actually looking?**
--
-- A denial row proves capture worked. The absence of denial rows proves
-- nothing at all — `audit_seccomp` needs CONFIG_AUDIT=y, the operator can
-- switch capture off, and the Controller skips the probe entirely on a
-- kernel without the symbol. Without this table the Broker cannot tell "no
-- workload has tripped a filter" from "no node has ever been watching", and
-- reporting the first when the second is true puts an all-clear into a
-- SeccompProfile status for a workload nobody is monitoring.
--
-- The cost of getting that wrong is not abstract: a `denials` block that
-- reads zero is what promotes a profile from audit to enforcing.
--
-- The Controller therefore POSTs /seccomp/denials on EVERY drain, including
-- when it drained nothing, and this row is upserted from that report.
CREATE TABLE IF NOT EXISTS seccomp_denial_nodes (
    node_name   TEXT PRIMARY KEY,
    -- Whether the probe actually attached on this node, as distinct from
    -- whether the Controller is reachable. A node that degraded gracefully
    -- on a CONFIG_AUDIT=n kernel reports in every interval with
    -- `capturing = false`: it is alive and it is NOT watching, and
    -- collapsing those two into "we heard from it" is precisely how
    -- graceful degradation turns into a false all-clear.
    capturing   BOOLEAN NOT NULL,
    -- Last report. Read as a freshness check rather than as history: a node
    -- whose Controller died stops updating this, and goes stale rather than
    -- flipping to `capturing = false` — nothing is left running to say so.
    updated_at  TIMESTAMPTZ NOT NULL
);

-- The freshness scan. Small table (one row per node), but this runs on the
-- GET /seccomp/profiles path, so it should not be a sequential scan on a
-- large cluster.
CREATE INDEX IF NOT EXISTS idx_seccomp_denial_nodes_updated_at
    ON seccomp_denial_nodes (updated_at);
