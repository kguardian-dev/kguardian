DROP FUNCTION IF EXISTS kg_runtime_coverage(text, text, text, text, text, text, integer);
DROP TABLE IF EXISTS runtime_coverage;
DROP INDEX IF EXISTS idx_runtime_executables_last_seen;
DROP INDEX IF EXISTS idx_runtime_executables_digest;
DROP TABLE IF EXISTS runtime_executables;
