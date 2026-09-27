-- Look up one workload's containers (#1533 profile gate): the profile
-- GET's existence/running gate and load_sources' container read both
-- filter on (pod_namespace, workload_kind, workload_name) without
-- cluster_id, the primary key's leading column, so without this they scan
-- the table. The running predicate's columns (state, last_seen) are not
-- selective once the workload is fixed (a workload has a handful of rows),
-- so they are not part of the index.
CREATE INDEX IF NOT EXISTS idx_workload_containers_workload ON workload_containers (pod_namespace, workload_kind, workload_name);
