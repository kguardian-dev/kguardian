-- The broker's /audit/verdicts endpoint filters by policy_namespace
-- and/or policy_name (the human-friendly identifiers the frontend
-- Would-Deny view exposes), then orders by observed_at DESC and
-- caps with LIMIT. The pre-existing idx_audit_verdicts_policy_time
-- on (policy_uid, observed_at DESC) does NOT help these queries —
-- policy_uid is never the filter predicate from the broker — so the
-- planner falls back to either idx_audit_verdicts_observed_at (full
-- time range scan filtered post-fetch) or, when no time index is
-- selective enough, a sequential scan over audit_verdicts.
--
-- Add a composite that matches the actual query shape. Leftmost-
-- prefix lets a policy_namespace-only filter (operator looking at
-- everything in a namespace) reuse the same index, while still
-- benefiting fully-qualified policy_namespace+policy_name lookups.
CREATE INDEX IF NOT EXISTS idx_audit_verdicts_policy_name_time
  ON audit_verdicts (policy_namespace, policy_name, observed_at DESC);
