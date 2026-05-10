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

// compactSvcRecord strips the heavyweight `service_spec` from a
// SvcDetail record but lifts the two nested fields the LLM actually
// reasons about (`selector` and `ports`) up to the top level. The
// pre-compact response was the full Kubernetes Service object —
// often 1-2KB per call including type/sessionAffinity/loadBalancer
// status that's rarely useful for "what does this service do"
// queries.
func compactSvcRecord(m map[string]interface{}) map[string]interface{} {
	keep := map[string]bool{
		"svc_name":      true,
		"svc_namespace": true,
		"svc_ip":        true,
		"time_stamp":    true,
	}
	slim := make(map[string]interface{}, len(keep)+2)
	for k, v := range m {
		if keep[k] {
			slim[k] = v
		}
	}
	// Lift the two genuinely useful sub-fields of service_spec.
	if spec, ok := m["service_spec"].(map[string]interface{}); ok {
		if inner, ok := spec["spec"].(map[string]interface{}); ok {
			// Inside a real Kubernetes Service object the useful
			// fields are at spec.selector / spec.ports — the
			// broker stores the full object, so navigate one level
			// deeper than the outer "service_spec" key.
			if sel, ok := inner["selector"]; ok {
				slim["service_selector"] = sel
			}
			if ports, ok := inner["ports"]; ok {
				slim["service_ports"] = ports
			}
		}
	}
	return slim
}

// compactSvc dispatches on type the same way compactPodsSummary
// does — single-map → compactSvcRecord; slice → over each; scalar
// → passthrough.
func compactSvc(data interface{}) interface{} {
	if single, ok := data.(map[string]interface{}); ok {
		return compactSvcRecord(single)
	}
	items, ok := data.([]interface{})
	if !ok {
		return data
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, compactSvcRecord(m))
		} else {
			out = append(out, item)
		}
	}
	return out
}

// filterAlivePods drops pod records with is_dead=true. The brokers
// /pod/info endpoint returns every pod_details row regardless of
// liveness — so a cluster that has churned through pod restarts
// over time accumulates a long tail of dead rows that the LLM has
// to skip past. For "list pods" use cases (the LLMs only entry
// point via cluster_pods), live-only is the sensible default.
//
// is_dead absent or non-bool is treated as alive (defensive: a
// malformed row should not be silently dropped just because the
// flag is missing).
func filterAlivePods(data interface{}) interface{} {
	items, ok := data.([]interface{})
	if !ok {
		return data
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			out = append(out, item)
			continue
		}
		if dead, ok := m["is_dead"].(bool); ok && dead {
			continue
		}
		out = append(out, item)
	}
	return out
}

// compactPodRecord strips heavyweight fields from a single pod record.
// Shared between the slice (compactPodsSummary) and the single-record
// (get_pod_details) paths so both honour the same keepFields contract.
func compactPodRecord(m map[string]interface{}) map[string]interface{} {
	keepFields := map[string]bool{
		"pod_name":                 true,
		"pod_namespace":            true,
		"pod_ip":                   true,
		"node_name":                true,
		"is_dead":                  true,
		"pod_identity":             true,
		"workload_selector_labels": true,
	}
	slim := make(map[string]interface{}, len(keepFields))
	for k, v := range m {
		if keepFields[k] {
			slim[k] = v
		}
	}
	return slim
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
	// Single-record case: the get_pod_details handler passes a
	// map[string]interface{} (the broker's /pod/ip/{ip} response is
	// one PodDetail object, not an array). Without this path the
	// LLM gets the full pod_obj (kilobytes of Kubernetes Pod spec
	// + status) every time it asks "what pod is at this IP" —
	// floods context for an identity lookup.
	if single, ok := data.(map[string]interface{}); ok {
		return compactPodRecord(single)
	}

	items, ok := data.([]interface{})
	if !ok {
		return data
	}

	compacted := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			compacted = append(compacted, item)
			continue
		}
		compacted = append(compacted, compactPodRecord(m))
	}
	return compacted
}
