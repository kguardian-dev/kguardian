package tools

import "strings"

// filterByNamespace filters a slice of records by a namespace field.
// It checks for "pod_namespace" or "svc_namespace" keys in each record.
// Returns all data unchanged if namespace is empty or data is not a slice.
func filterByNamespace(data interface{}, namespace string) interface{} {
	if namespace == "" {
		return data
	}
	items, ok := data.([]interface{})
	if !ok {
		return data
	}

	var filtered []interface{}
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		// Check pod_namespace first, then svc_namespace
		if ns, ok := m["pod_namespace"].(string); ok && ns == namespace {
			filtered = append(filtered, item)
		} else if ns, ok := m["svc_namespace"].(string); ok && ns == namespace {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// compactTrafficSummary aggregates traffic records into per-pod summaries.
// Returns a map with total_records count and per-pod ingress/egress/peer counts.
func compactTrafficSummary(data interface{}) map[string]interface{} {
	items, ok := data.([]interface{})
	if !ok {
		return map[string]interface{}{"total_records": 0, "pods": map[string]interface{}{}}
	}

	type podStats struct {
		Ingress int
		Egress  int
		Peers   map[string]bool
	}
	pods := make(map[string]*podStats)

	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		podName, _ := m["pod_name"].(string)
		if podName == "" {
			continue
		}
		s, exists := pods[podName]
		if !exists {
			s = &podStats{Peers: make(map[string]bool)}
			pods[podName] = s
		}

		// The broker stores traffic_type as "INGRESS"/"EGRESS" (uppercase,
		// emitted from controller/src/network.rs). The previous switch
		// against lowercase silently matched nothing — both
		// ingress_count and egress_count were always 0 in the cluster
		// traffic summary returned to the LLM, regardless of how busy
		// the cluster was. Case-insensitive compare so this works
		// regardless of which writer populated the row.
		trafficType, _ := m["traffic_type"].(string)
		switch strings.ToUpper(trafficType) {
		case "INGRESS":
			s.Ingress++
		case "EGRESS":
			s.Egress++
		}

		// Track unique peers by the actual "other end" of the
		// conversation. The broker's PodTraffic wire format has NO
		// dst_ip / src_ip fields — the previous code referenced both
		// and got nil on every record, so unique_peer_count was
		// always 0 in the cluster_traffic summary sent to the LLM.
		// The real field is traffic_in_out_ip (destination IP for
		// egress, source IP for ingress — already the peer-side IP
		// regardless of direction).
		if peer, ok := m["traffic_in_out_ip"].(string); ok && peer != "" {
			s.Peers[peer] = true
		}
	}

	podSummaries := make(map[string]interface{}, len(pods))
	for name, s := range pods {
		podSummaries[name] = map[string]interface{}{
			"ingress_count":    s.Ingress,
			"egress_count":     s.Egress,
			"unique_peer_count": len(s.Peers),
		}
	}

	return map[string]interface{}{
		"total_records": len(items),
		"pod_count":     len(pods),
		"pods":          podSummaries,
	}
}

// compactPodsSummary strips heavyweight fields (pod_obj, service_spec) from
// pod records, keeping only the lightweight identity columns that the LLM
// actually reasons about.
//
// Field names match the brokers wire format (serde of PodDetail emits
// snake_case from the Rust struct fields). The previous keepFields list
// included a non-existent "labels" key, so the broker's
// workload_selector_labels — the single most useful field for the LLM
// to associate a pod with its workload identity — was silently stripped
// from every compacted response.
func compactPodsSummary(data interface{}) interface{} {
	items, ok := data.([]interface{})
	if !ok {
		return data
	}

	keepFields := map[string]bool{
		"pod_name":                 true,
		"pod_namespace":            true,
		"pod_ip":                   true,
		"node_name":                true,
		"is_dead":                  true,
		// pod_identity is the controllers heuristic label (e.g.
		// app.kubernetes.io/name) — short string, cheap to keep, and
		// usually the answer to "which workload is this".
		"pod_identity":             true,
		// workload_selector_labels is the resolved selector map from
		// the parent controller (Deployment/StatefulSet/DaemonSet).
		// Required for an LLM to construct accurate NetworkPolicy
		// selectors from observed traffic.
		"workload_selector_labels": true,
	}

	compacted := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			compacted = append(compacted, item)
			continue
		}
		slim := make(map[string]interface{})
		for k, v := range m {
			if keepFields[k] {
				slim[k] = v
			}
		}
		compacted = append(compacted, slim)
	}
	return compacted
}
