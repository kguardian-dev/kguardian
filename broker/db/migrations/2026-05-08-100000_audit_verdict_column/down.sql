DROP INDEX IF EXISTS idx_audit_verdicts_verdict_time;
ALTER TABLE audit_verdicts DROP COLUMN IF EXISTS verdict;
