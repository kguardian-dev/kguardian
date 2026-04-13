CREATE INDEX IF NOT EXISTS idx_pod_traffic_lookup ON pod_traffic(pod_ip, traffic_type, decision);
CREATE INDEX IF NOT EXISTS idx_pod_traffic_name ON pod_traffic(pod_name);
CREATE INDEX IF NOT EXISTS idx_pod_details_node ON pod_details(node_name, is_dead);
CREATE INDEX IF NOT EXISTS idx_pod_syscalls_name ON pod_syscalls(pod_name);
CREATE INDEX IF NOT EXISTS idx_svc_details_name ON svc_details(svc_name, svc_namespace);
