-- Tighten the declared-cadence bound to the one the Broker will honour
-- (DEVOPS-2101).
--
-- The previous bound was one day. That was reasoned about as a bound on "a
-- timeout", which is where it went wrong: the value is multiplied by three
-- and used as the staleness window, and the staleness window is the
-- all-clear gate. A day therefore bought a node three days during which the
-- whole cluster reads `total: 0` off one report — reachable by a node
-- departing on a spot reclaim, and reachable on purpose by one POST, since
-- broker auth is optional.
--
-- 600 s is the ceiling the Broker now trusts: the window ceiling (1800 s)
-- divided by the three intervals a node may miss. See
-- CAPTURE_REPORT_STALE_CEILING_SECS in src/seccomp_denial.rs for why the
-- window is bounded at half an hour.
--
-- Existing rows are clamped rather than deleted: the value is a cadence the
-- node will re-declare on its very next report, and dropping the row would
-- throw away the capture heartbeat with it.
UPDATE seccomp_denial_nodes
    SET interval_seconds = 600
    WHERE interval_seconds > 600;

-- The previous constraint was written inline on ADD COLUMN, so Postgres
-- named it `<table>_<column>_check`. Dropped by that name and re-added
-- explicitly, so the next change to it does not have to guess.
ALTER TABLE seccomp_denial_nodes
    DROP CONSTRAINT IF EXISTS seccomp_denial_nodes_interval_seconds_check;

ALTER TABLE seccomp_denial_nodes
    ADD CONSTRAINT seccomp_denial_nodes_interval_seconds_check
    CHECK (interval_seconds > 0 AND interval_seconds <= 600);
