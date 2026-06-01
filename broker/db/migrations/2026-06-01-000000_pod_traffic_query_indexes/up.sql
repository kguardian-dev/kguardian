-- pod_traffic / pod_syscalls only had their primary-key indexes (uuid),
-- so the broker's hot query paths were full sequential scans of tables
-- that grow into the millions of rows:
--   * get_row() dedup runs on EVERY inserted traffic event, filtering on
--     (pod_ip, pod_port, traffic_type, traffic_in_out_ip,
--      traffic_in_out_port, decision)
--   * /pod/traffic/<name> (frontend per-pod view) filters on pod_name
--   * /pod/ip/<ip> filters on pod_ip
--   * /pod/syscalls/<name> filters on pod_name
-- The frontend fetches per-pod traffic + syscalls for every pod when a
-- view loads, so those seqscans burst-saturate the broker — observed in
-- production as a liveness-probe crash-loop under UI load, and slow
-- ingest (the dedup seqscan ran per insert). Index the actual shapes.
CREATE INDEX IF NOT EXISTS idx_pod_traffic_pod_name ON pod_traffic (pod_name);
CREATE INDEX IF NOT EXISTS idx_pod_traffic_pod_ip ON pod_traffic (pod_ip);
CREATE INDEX IF NOT EXISTS idx_pod_traffic_dedup
  ON pod_traffic (pod_ip, pod_port, traffic_type, traffic_in_out_ip, traffic_in_out_port, decision);
CREATE INDEX IF NOT EXISTS idx_pod_syscalls_pod_name ON pod_syscalls (pod_name);
