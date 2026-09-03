ALTER TABLE pod_details DROP COLUMN IF EXISTS started_at;
ALTER TABLE pod_traffic
  DROP COLUMN IF EXISTS peer_resolved_at,
  DROP COLUMN IF EXISTS peer_workload_name,
  DROP COLUMN IF EXISTS peer_workload_kind,
  DROP COLUMN IF EXISTS peer_uid,
  DROP COLUMN IF EXISTS peer_name,
  DROP COLUMN IF EXISTS peer_namespace,
  DROP COLUMN IF EXISTS peer_kind;
