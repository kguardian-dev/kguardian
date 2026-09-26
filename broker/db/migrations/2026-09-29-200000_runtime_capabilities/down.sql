DROP FUNCTION IF EXISTS kg_capability_coverage(text, text, text, text, text, text, integer);
ALTER TABLE runtime_coverage DROP COLUMN IF EXISTS cap_hook;
ALTER TABLE runtime_coverage DROP COLUMN IF EXISTS cap_probe;
DROP INDEX IF EXISTS idx_runtime_capabilities_last_reported;
DROP TABLE IF EXISTS runtime_capabilities;
