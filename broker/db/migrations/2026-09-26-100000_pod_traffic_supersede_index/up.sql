-- pod_traffic retention deletes a live pod's expired row once a NEWER row
-- of the same pod carries the same rule: same direction, protocol, ports,
-- decision and in-cluster peer identity (broker/src/retention.rs,
-- POD_TRAFFIC_PRUNE_SQL). That check runs once per candidate row, up to
-- 5 000 per batch, and the only index it could otherwise use is
-- idx_pod_traffic_pod_name, which reads every row of the pod per probe. A
-- pod with tens of thousands of rows is exactly the pod the rule exists
-- for, so that is a scan of the pod per candidate.
--
-- The key is the equality part of the lookup (pod, peer namespace, peer
-- workload-or-name) followed by time_stamp for the "newer than" range.
-- The expression must match the query's
-- COALESCE(peer_workload_name, peer_name) exactly for the planner to use
-- it. The remaining equalities (direction, protocol, ports, decision)
-- are filtered on the few rows the index returns.
--
-- Partial: only `pod` and `service` peers can be superseded (a `node`
-- peer renders as an ipBlock for its own IP; a NULL peer has no identity
-- to match), so rows the rule can never touch are not indexed and pay no
-- index maintenance on ingest.
CREATE INDEX IF NOT EXISTS idx_pod_traffic_supersede
  ON pod_traffic (pod_name, peer_namespace, (COALESCE(peer_workload_name, peer_name)), time_stamp)
  WHERE peer_kind IN ('pod', 'service');
