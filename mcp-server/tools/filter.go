package tools

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

		trafficType, _ := m["traffic_type"].(string)
		switch trafficType {
		case "ingress":
			s.Ingress++
		case "egress":
			s.Egress++
		}

		// Track unique peers by destination IP
		if dstIP, ok := m["dst_ip"].(string); ok && dstIP != "" {
			s.Peers[dstIP] = true
		}
		if srcIP, ok := m["src_ip"].(string); ok && srcIP != "" {
			s.Peers[srcIP] = true
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
// pod records, keeping only name, namespace, ip, node, is_dead, and labels.
func compactPodsSummary(data interface{}) interface{} {
	items, ok := data.([]interface{})
	if !ok {
		return data
	}

	keepFields := map[string]bool{
		"pod_name":      true,
		"pod_namespace": true,
		"pod_ip":        true,
		"node_name":     true,
		"is_dead":       true,
		"labels":        true,
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
