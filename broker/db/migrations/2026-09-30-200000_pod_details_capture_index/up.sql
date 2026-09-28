-- GET /seccomp/profiles joins pod_syscalls to pod_details on pod_name for
-- every pod with a workload, selecting only the columns below. With just the
-- primary key to join on, that read walked the pod_details heap (compacted
-- pod object, pod IPs, selector labels). Covering the select list under the
-- join's own predicate makes it an index-only scan that stops scaling with
-- the row width.
CREATE INDEX IF NOT EXISTS idx_pod_details_capture_contributors
  ON pod_details (pod_name)
  INCLUDE (pod_namespace, workload_kind, workload_name, capture_level)
  WHERE workload_kind IS NOT NULL AND workload_name IS NOT NULL;
