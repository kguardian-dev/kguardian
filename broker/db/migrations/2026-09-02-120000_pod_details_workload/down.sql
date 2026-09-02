DROP INDEX IF EXISTS idx_pod_details_workload;
ALTER TABLE pod_details DROP COLUMN IF EXISTS workload_name;
ALTER TABLE pod_details DROP COLUMN IF EXISTS workload_kind;
