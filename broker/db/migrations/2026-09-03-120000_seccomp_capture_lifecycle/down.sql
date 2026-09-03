ALTER TABLE seccomp_override_audit DROP COLUMN IF EXISTS action;
DROP TABLE IF EXISTS workload_seccomp_state;
ALTER TABLE pod_details DROP COLUMN IF EXISTS capture_level;
