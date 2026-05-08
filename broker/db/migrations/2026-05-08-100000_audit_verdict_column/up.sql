-- Add a `verdict` column so we can persist Allow rows alongside
-- WouldDeny ones. Without this, operators only see "what's blocked"
-- — they can't verify "what's permitted" or spot policies whose
-- selectors don't match anything (which would have zero of either).
--
-- Existing rows pre-date this column. They were all WouldDeny by
-- construction (the broker's audit forwarder previously filtered to
-- that single verdict before insert), so the default is safe.
ALTER TABLE audit_verdicts
  ADD COLUMN verdict VARCHAR NOT NULL DEFAULT 'WouldDeny';

-- Composite index for "show me only Allow / only WouldDeny within a
-- time window" queries surfaced in the frontend's verdict filter.
CREATE INDEX idx_audit_verdicts_verdict_time
  ON audit_verdicts (verdict, observed_at DESC);
