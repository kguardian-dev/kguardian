package tools

import (
	"reflect"
	"testing"
)

// filterByNamespace must:
//   - pass through any non-slice input unchanged
//   - pass through everything when the namespace string is empty
//   - keep only records whose pod_namespace OR svc_namespace matches
//   - skip non-map entries silently (don't panic on heterogeneous inputs)
//
// A regression here would either over-filter (return less data than the
// LLM expects) or leak across-namespace records into a namespace-scoped
// query.

func TestFilterByNamespace_EmptyNamespacePassesThrough(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"pod_namespace": "prod"},
		map[string]interface{}{"pod_namespace": "dev"},
	}
	got := filterByNamespace(in, "")
	if !reflect.DeepEqual(got, in) {
		t.Errorf("empty ns: want passthrough, got %#v", got)
	}
}

func TestFilterByNamespace_NonSliceReturnedUnchanged(t *testing.T) {
	// e.g. an upstream tool returned a single object instead of a list.
	obj := map[string]interface{}{"pod_namespace": "prod"}
	got := filterByNamespace(obj, "prod")
	if !reflect.DeepEqual(got, obj) {
		t.Errorf("non-slice: want passthrough, got %#v", got)
	}
}

func TestFilterByNamespace_KeepsPodNamespaceMatches(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"pod_namespace": "prod", "pod_name": "a"},
		map[string]interface{}{"pod_namespace": "dev", "pod_name": "b"},
		map[string]interface{}{"pod_namespace": "prod", "pod_name": "c"},
	}
	got := filterByNamespace(in, "prod")
	gotSlice, ok := got.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", got)
	}
	if len(gotSlice) != 2 {
		t.Fatalf("want 2 prod records, got %d: %#v", len(gotSlice), gotSlice)
	}
}

func TestFilterByNamespace_FallsBackToSvcNamespace(t *testing.T) {
	// Service records use svc_namespace not pod_namespace.
	in := []interface{}{
		map[string]interface{}{"svc_namespace": "prod", "svc_name": "api"},
		map[string]interface{}{"svc_namespace": "dev", "svc_name": "api2"},
	}
	got := filterByNamespace(in, "prod")
	gotSlice := got.([]interface{})
	if len(gotSlice) != 1 {
		t.Errorf("want 1 svc, got %d", len(gotSlice))
	}
}

func TestFilterByNamespace_SkipsNonMapEntries(t *testing.T) {
	// Heterogeneous slice — must not panic on the bare string.
	in := []interface{}{
		"unexpected-string",
		map[string]interface{}{"pod_namespace": "prod"},
	}
	got := filterByNamespace(in, "prod")
	gotSlice := got.([]interface{})
	if len(gotSlice) != 1 {
		t.Errorf("want only the matching map, got %#v", gotSlice)
	}
}

func TestFilterByNamespace_NoMatches(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"pod_namespace": "dev"},
	}
	got := filterByNamespace(in, "prod")
	// Implementation returns nil slice when nothing matches; that's fine —
	// JSON-encodes as null, the LLM tool layer handles both.
	if got != nil {
		gotSlice, ok := got.([]interface{})
		if ok && len(gotSlice) != 0 {
			t.Errorf("want empty/nil, got %#v", gotSlice)
		}
	}
}

func TestCompactTrafficSummary_NonSliceYieldsZeroSummary(t *testing.T) {
	got := compactTrafficSummary("not-a-slice")
	if got["total_records"] != 0 {
		t.Errorf("non-slice should yield total_records=0, got %#v", got)
	}
}

func TestCompactTrafficSummary_AggregatesIngressEgressAndPeers(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"pod_name": "web-1", "traffic_type": "ingress",
			"src_ip": "10.0.0.1", "dst_ip": "10.1.0.1",
		},
		map[string]interface{}{
			"pod_name": "web-1", "traffic_type": "ingress",
			"src_ip": "10.0.0.1", "dst_ip": "10.1.0.1",
		},
		map[string]interface{}{
			"pod_name": "web-1", "traffic_type": "egress",
			"src_ip": "10.1.0.1", "dst_ip": "10.0.0.5",
		},
		map[string]interface{}{
			"pod_name": "db-1", "traffic_type": "ingress",
			"src_ip": "10.1.0.1", "dst_ip": "10.2.0.1",
		},
	}
	got := compactTrafficSummary(in)
	if got["total_records"] != 4 {
		t.Errorf("total_records: want 4, got %v", got["total_records"])
	}
	if got["pod_count"] != 2 {
		t.Errorf("pod_count: want 2, got %v", got["pod_count"])
	}

	pods := got["pods"].(map[string]interface{})
	web := pods["web-1"].(map[string]interface{})
	if web["ingress_count"] != 2 {
		t.Errorf("web-1 ingress: want 2, got %v", web["ingress_count"])
	}
	if web["egress_count"] != 1 {
		t.Errorf("web-1 egress: want 1, got %v", web["egress_count"])
	}
	// 10.0.0.1, 10.1.0.1, 10.0.0.5 — three unique peers across three traffic rows.
	if web["unique_peer_count"] != 3 {
		t.Errorf("web-1 unique peers: want 3, got %v", web["unique_peer_count"])
	}
}

func TestCompactTrafficSummary_SkipsRecordsWithoutPodName(t *testing.T) {
	// Defensive: rows missing pod_name should be silently dropped from
	// the per-pod aggregation rather than being keyed under "".
	in := []interface{}{
		map[string]interface{}{"traffic_type": "ingress"}, // no pod_name
		map[string]interface{}{"pod_name": "web-1", "traffic_type": "ingress"},
	}
	got := compactTrafficSummary(in)
	if got["pod_count"] != 1 {
		t.Errorf("pod_count: want 1 (skip nameless), got %v", got["pod_count"])
	}
	if got["total_records"] != 2 {
		// The TOTAL must still reflect everything received, even rows
		// excluded from per-pod aggregation. Otherwise observability
		// understates the load.
		t.Errorf("total_records: want 2, got %v", got["total_records"])
	}
}

func TestCompactPodsSummary_StripsHeavyweightFields(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"pod_name":      "web-1",
			"pod_namespace": "prod",
			"pod_ip":        "10.1.0.1",
			"node_name":     "node-a",
			"is_dead":       false,
			"labels":        map[string]interface{}{"app": "web"},
			// These two should be stripped — they bloat MCP responses
			// well past sensible LLM context budgets.
			"pod_obj":      map[string]interface{}{"spec": "huge"},
			"service_spec": map[string]interface{}{"a": "b"},
		},
	}
	got := compactPodsSummary(in)
	gotSlice := got.([]interface{})
	if len(gotSlice) != 1 {
		t.Fatalf("want 1, got %d", len(gotSlice))
	}
	m := gotSlice[0].(map[string]interface{})

	for _, want := range []string{"pod_name", "pod_namespace", "pod_ip", "node_name", "is_dead", "labels"} {
		if _, ok := m[want]; !ok {
			t.Errorf("kept field missing: %s", want)
		}
	}
	for _, drop := range []string{"pod_obj", "service_spec"} {
		if _, ok := m[drop]; ok {
			t.Errorf("heavyweight field leaked through: %s", drop)
		}
	}
}

func TestCompactPodsSummary_NonSlicePassthrough(t *testing.T) {
	obj := map[string]interface{}{"pod_name": "web-1"}
	got := compactPodsSummary(obj)
	if !reflect.DeepEqual(got, obj) {
		t.Errorf("non-slice input must pass through unchanged")
	}
}

func TestCompactPodsSummary_NonMapEntryPreserved(t *testing.T) {
	// Heterogeneous list: a non-map entry should be passed through
	// unchanged so the caller can see it's malformed rather than us
	// silently dropping it.
	in := []interface{}{
		"unexpected",
		map[string]interface{}{"pod_name": "web-1", "pod_obj": "drop-me"},
	}
	got := compactPodsSummary(in).([]interface{})
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0] != "unexpected" {
		t.Errorf("non-map entry should be preserved, got %#v", got[0])
	}
}
