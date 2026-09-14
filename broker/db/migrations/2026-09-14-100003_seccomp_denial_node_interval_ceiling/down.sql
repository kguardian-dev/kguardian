-- Back to the one-day bound. No UPDATE: every value that survives the
-- tighter CHECK also satisfies the wider one, and the nodes re-declare their
-- cadence on the next report either way.
ALTER TABLE seccomp_denial_nodes
    DROP CONSTRAINT IF EXISTS seccomp_denial_nodes_interval_seconds_check;

ALTER TABLE seccomp_denial_nodes
    ADD CONSTRAINT seccomp_denial_nodes_interval_seconds_check
    CHECK (interval_seconds > 0 AND interval_seconds <= 86400);
