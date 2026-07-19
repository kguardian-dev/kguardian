-- The cluster-wide GET /pod/traffic reads the pod_traffic table
-- "most recent first": ORDER BY time_stamp DESC, uuid DESC LIMIT N
-- (see broker/src/get.rs::pod_traffic). The 2026-06-01 index migration
-- covered the dedup / per-pod / per-ip lookups but NOT this ordering, so
-- the endpoint fell back to a parallel seq-scan + full sort of the entire
-- table (millions of rows / multi-GB) on every call — tens of seconds and
-- a response large enough to overrun the mcp-server's body cap.
--
-- A btree on (time_stamp DESC, uuid DESC) matches the ORDER BY exactly, so
-- the bounded query becomes an index scan of the first N rows instead of a
-- whole-table sort.
CREATE INDEX IF NOT EXISTS idx_pod_traffic_time_stamp
  ON pod_traffic (time_stamp DESC, uuid DESC);
