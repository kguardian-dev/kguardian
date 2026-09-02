-- pod_details.pod_identity is a label-derived name (app.kubernetes.io/name,
-- k8s-app, app, ... in priority order, falling back to the owner name). It
-- is ambiguous by construction: two unrelated Deployments that both set
-- `app: web` collapse to the same identity. That is tolerable for the
-- network-graph grouping it was added for, but a per-workload seccomp
-- profile is keyed on the actual owning controller and must not merge the
-- syscall sets of distinct workloads.
--
-- workload_kind / workload_name record the top-level controller the
-- controller resolved by walking ownerReferences: a ReplicaSet collapses
-- to its Deployment, a Job to its CronJob, and Deployment / StatefulSet /
-- DaemonSet / ReplicationController are taken directly. A bare pod (no
-- controller owner) leaves both NULL.
--
-- Both are NULLable and added last so the positional Queryable/Insertable
-- ordering of broker/src/types.rs::PodDetail stays aligned with the
-- physical column order. A controller old enough not to send them keeps
-- working — diesel's AsChangeset skips None fields on upsert, exactly as
-- it already does for pod_identity.
ALTER TABLE pod_details ADD COLUMN IF NOT EXISTS workload_kind VARCHAR;
ALTER TABLE pod_details ADD COLUMN IF NOT EXISTS workload_name VARCHAR;

-- No backfill: the old rows have no reliable owner information stored
-- (compact_pod_obj strips spec/status before storage, and ownerReferences
-- live in metadata which is kept but not queried here). The controller
-- re-upserts every on-node pod within one resync interval (60s), which
-- populates the columns for anything still running.

-- The per-workload aggregation query groups by (namespace, kind, name).
CREATE INDEX IF NOT EXISTS idx_pod_details_workload
  ON pod_details (pod_namespace, workload_kind, workload_name);
