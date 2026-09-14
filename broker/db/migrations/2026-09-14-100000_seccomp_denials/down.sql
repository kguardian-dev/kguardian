-- Indexes go with the table; named explicitly so a partial apply that
-- created them without the table still reverses cleanly.
DROP INDEX IF EXISTS idx_seccomp_denials_last_seen;
DROP INDEX IF EXISTS idx_seccomp_denials_workload;
DROP INDEX IF EXISTS uq_seccomp_denials_pod_syscall_action;
DROP TABLE IF EXISTS seccomp_denials;
