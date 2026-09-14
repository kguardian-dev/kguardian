-- The drain cadence each node declares, so heartbeat staleness is computed
-- per node instead of against one fixed window (DEVOPS-2101).
--
-- The Controller's drain interval is an operator-set Helm value with no upper
-- bound (`seccomp.denials.intervalSeconds`, default 10). The Broker's
-- staleness window was a hard-coded 300 s, so any configured interval above
-- 100 s -- a supported value -- left every node looking stale between its own
-- reports and pinned the whole cluster at `DenialsObserved: Unknown` on a
-- fleet that was capturing perfectly.
--
-- Coupling the two config values would need the Broker to read a chart it
-- cannot see, so the node declares its own cadence on every report instead
-- and the Broker trusts it as `max(300 s, interval * 3)`.
--
-- NULL means the node did not declare one, which falls back to the 300 s
-- floor. The CHECK is the same bound ingest clamps to: the value is
-- multiplied inside the liveness query, so a row written by anything other
-- than that ingest path must not be able to overflow the multiplication or
-- claim a heartbeat that stays trustworthy for years. Added LAST (positional
-- Queryable).
ALTER TABLE seccomp_denial_nodes
    ADD COLUMN IF NOT EXISTS interval_seconds BIGINT
    CHECK (interval_seconds > 0 AND interval_seconds <= 86400);
