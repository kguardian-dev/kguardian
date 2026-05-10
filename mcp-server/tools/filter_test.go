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
	// Note: traffic_type comes off the broker in UPPERCASE ("INGRESS",
	// "EGRESS") as emitted by controller/src/network.rs. This test was
	// previously passing lowercase, which silently matched nothing
	// before the case-insensitive compare fix — false confidence. Use
	// the real wire format here.
	//
	// Similarly: the broker emits the peer IP as `traffic_in_out_ip`,
	// NOT `dst_ip` / `src_ip`. The previous fixture used the latter
	// (fictional) keys, which the implementation also (incorrectly)
	// read — masking that unique_peer_count was always 0 in production.
	in := []interface{}{
		map[string]interface{}{
			"pod_name": "web-1", "traffic_type": "INGRESS",
			"traffic_in_out_ip": "10.0.0.1",
		},
		map[string]interface{}{
			"pod_name": "web-1", "traffic_type": "INGRESS",
			"traffic_in_out_ip": "10.0.0.1",
		},
		map[string]interface{}{
			"pod_name": "web-1", "traffic_type": "EGRESS",
			"traffic_in_out_ip": "10.0.0.5",
		},
		map[string]interface{}{
			"pod_name": "db-1", "traffic_type": "INGRESS",
			"traffic_in_out_ip": "10.2.0.1",
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
	// web-1 talked to 10.0.0.1 (twice, ingress) and 10.0.0.5 (once,
	// egress). Two unique peers from web-1's perspective.
	if web["unique_peer_count"] != 2 {
		t.Errorf("web-1 unique peers: want 2, got %v", web["unique_peer_count"])
	}
}

func TestCompactTrafficSummary_PeerIPFieldIsTrafficInOutIP(t *testing.T) {
	// Regression for the unique_peer_count=always-0 bug. Pre-fix the
	// code referenced m["dst_ip"] and m["src_ip"] — neither field
	// exists in the broker's PodTraffic wire format, which emits
	// traffic_in_out_ip as the peer side. Both nils → no peers
	// counted → unique_peer_count=0 in every cluster_traffic
	// response sent to the LLM, regardless of how chatty a pod was.
	in := []interface{}{
		map[string]interface{}{
			"pod_name":          "web-1",
			"traffic_type":      "EGRESS",
			"traffic_in_out_ip": "10.42.0.5",
		},
		map[string]interface{}{
			"pod_name":          "web-1",
			"traffic_type":      "EGRESS",
			"traffic_in_out_ip": "10.42.0.6",
		},
		map[string]interface{}{
			"pod_name":          "web-1",
			"traffic_type":      "EGRESS",
			"traffic_in_out_ip": "10.42.0.5", // dup, must not double-count
		},
	}
	got := compactTrafficSummary(in)
	pods := got["pods"].(map[string]interface{})
	web := pods["web-1"].(map[string]interface{})
	if web["unique_peer_count"] != 2 {
		t.Errorf("unique_peer_count: want 2 (10.42.0.5 and 10.42.0.6), got %v", web["unique_peer_count"])
	}
}

func TestCompactTrafficSummary_LegacyFakeFieldsDoNotCount(t *testing.T) {
	// Defense in depth: should a caller (or test fixture) pass the
	// fictional dst_ip / src_ip fields, they MUST NOT contribute to
	// the peer count. The whole point of this commits fix was to
	// stop reading those — pin that contract.
	in := []interface{}{
		map[string]interface{}{
			"pod_name":     "web-1",
			"traffic_type": "EGRESS",
			"dst_ip":       "192.0.2.1",
			"src_ip":       "192.0.2.2",
			// no traffic_in_out_ip
		},
	}
	got := compactTrafficSummary(in)
	pods := got["pods"].(map[string]interface{})
	web := pods["web-1"].(map[string]interface{})
	if web["unique_peer_count"] != 0 {
		t.Errorf("fictional dst_ip / src_ip MUST NOT count toward peers; got unique_peer_count=%v", web["unique_peer_count"])
	}
}

func TestCompactTrafficSummary_CaseInsensitiveTrafficType(t *testing.T) {
	// Regression: pre-fix the switch only matched lowercase
	// "ingress"/"egress" but the broker stores UPPERCASE. Both
	// counters were always 0 in production. Verify the
	// case-insensitive compare handles every realistic spelling
	// (uppercase from the controller, mixed-case from a future
	// hand-rolled writer).
	cases := []string{"INGRESS", "ingress", "Ingress", "iNgReSs"}
	for _, tt := range cases {
		in := []interface{}{
			map[string]interface{}{"pod_name": "x", "traffic_type": tt},
		}
		got := compactTrafficSummary(in)
		pods := got["pods"].(map[string]interface{})
		x := pods["x"].(map[string]interface{})
		if x["ingress_count"] != 1 {
			t.Errorf("traffic_type=%q: ingress_count must be 1, got %v", tt, x["ingress_count"])
		}
	}
}

func TestCompactTrafficSummary_SkipsRecordsWithoutPodName(t *testing.T) {
	// Defensive: rows missing pod_name should be silently dropped from
	// the per-pod aggregation rather than being keyed under "".
	in := []interface{}{
		map[string]interface{}{"traffic_type": "INGRESS"}, // no pod_name
		map[string]interface{}{"pod_name": "web-1", "traffic_type": "INGRESS"},
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

func TestCompactSvc_SingleMapKeepsIdentityAndLiftsSelectorPorts(t *testing.T) {
	// Per-record contract for service compaction. The full
	// service_spec includes Kubernetes Service.spec which itself
	// contains selector + ports + the assorted fluff
	// (type, sessionAffinity, loadBalancer). Strip the outer
	// service_spec wrapper but lift selector + ports to top-level.
	in := map[string]interface{}{
		"svc_name":      "web",
		"svc_namespace": "prod",
		"svc_ip":        "10.96.0.42",
		"time_stamp":    "2026-05-11T00:00:00Z",
		"service_spec": map[string]interface{}{
			// The broker stores the full Kubernetes Service obj —
			// .spec is one nesting level inside.
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{"app": "web", "tier": "frontend"},
				"ports": []interface{}{
					map[string]interface{}{"port": 80, "targetPort": 8080, "protocol": "TCP"},
					map[string]interface{}{"port": 443, "targetPort": 8443, "protocol": "TCP"},
				},
				// Fluff that should NOT survive compactation:
				"type":            "ClusterIP",
				"sessionAffinity": "None",
				"ipFamilies":      []interface{}{"IPv4"},
			},
			"status": map[string]interface{}{"loadBalancer": map[string]interface{}{}},
		},
	}
	got := compactSvc(in).(map[string]interface{})

	// Identity fields kept.
	for _, want := range []string{"svc_name", "svc_namespace", "svc_ip", "time_stamp"} {
		if _, ok := got[want]; !ok {
			t.Errorf("identity field stripped: %s", want)
		}
	}
	// service_spec dropped wholesale.
	if _, ok := got["service_spec"]; ok {
		t.Error("service_spec must be dropped (the rest of the Service object is fluff)")
	}
	// selector lifted to top-level.
	sel, ok := got["service_selector"].(map[string]interface{})
	if !ok {
		t.Fatalf("service_selector missing — LLM cant construct NetworkPolicy selectors without it: %#v", got)
	}
	if sel["app"] != "web" {
		t.Errorf("selector content lost: %#v", sel)
	}
	// ports lifted to top-level.
	ports, ok := got["service_ports"].([]interface{})
	if !ok || len(ports) != 2 {
		t.Errorf("service_ports must be lifted and preserved (2 entries); got %#v", got["service_ports"])
	}
}

func TestCompactSvc_NoServiceSpecPassesThrough(t *testing.T) {
	// Defensive: if the broker returns a record without service_spec
	// (a degenerate row), the identity fields still come through and
	// no panic occurs from missing nested access.
	in := map[string]interface{}{
		"svc_name":      "headless",
		"svc_namespace": "prod",
		"svc_ip":        "None",
	}
	got := compactSvc(in).(map[string]interface{})
	if got["svc_name"] != "headless" {
		t.Errorf("identity must survive even without service_spec: %#v", got)
	}
	if _, ok := got["service_selector"]; ok {
		t.Error("service_selector must be absent when service_spec was missing")
	}
}

func TestCompactSvc_SliceInputCompactsEach(t *testing.T) {
	// The dispatch contract: slice in → slice out, each item
	// compacted via compactSvcRecord. Mirrors the
	// compactPodsSummary slice path.
	in := []interface{}{
		map[string]interface{}{
			"svc_name": "a", "svc_namespace": "ns",
			"service_spec": map[string]interface{}{
				"spec": map[string]interface{}{"selector": map[string]interface{}{"app": "a"}},
			},
		},
		map[string]interface{}{
			"svc_name": "b", "svc_namespace": "ns",
			"service_spec": map[string]interface{}{
				"spec": map[string]interface{}{"selector": map[string]interface{}{"app": "b"}},
			},
		},
	}
	got := compactSvc(in).([]interface{})
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	for _, item := range got {
		m := item.(map[string]interface{})
		if _, ok := m["service_spec"]; ok {
			t.Errorf("service_spec must be stripped from each slice entry")
		}
		if _, ok := m["service_selector"]; !ok {
			t.Errorf("service_selector must be lifted to each slice entry")
		}
	}
}

func TestFilterAlivePods_DropsDeadOnly(t *testing.T) {
	// /pod/info returns every pod_details row; the LLMs list-pods
	// tool wants only the live ones. Pin: alive rows pass through,
	// is_dead=true rows are dropped.
	in := []interface{}{
		map[string]interface{}{"pod_name": "alive-1", "is_dead": false},
		map[string]interface{}{"pod_name": "dead-1", "is_dead": true},
		map[string]interface{}{"pod_name": "alive-2", "is_dead": false},
		map[string]interface{}{"pod_name": "dead-2", "is_dead": true},
	}
	got := filterAlivePods(in).([]interface{})
	if len(got) != 2 {
		t.Fatalf("want 2 alive, got %d", len(got))
	}
	names := map[string]bool{}
	for _, item := range got {
		names[item.(map[string]interface{})["pod_name"].(string)] = true
	}
	if !names["alive-1"] || !names["alive-2"] {
		t.Errorf("expected alive-1 and alive-2; got %#v", names)
	}
	if names["dead-1"] || names["dead-2"] {
		t.Errorf("dead pods leaked through: %#v", names)
	}
}

func TestFilterAlivePods_MissingIsDeadTreatedAsAlive(t *testing.T) {
	// Defensive: a malformed row missing is_dead should be kept,
	// not silently dropped. The flag default is "alive" until
	// proven otherwise — the mark_dead RPC explicitly sets is_dead
	// to true, so its absence means "never been marked dead".
	in := []interface{}{
		map[string]interface{}{"pod_name": "no-flag"},
		map[string]interface{}{"pod_name": "explicit-alive", "is_dead": false},
		map[string]interface{}{"pod_name": "wrong-type", "is_dead": "false"}, // string, not bool
	}
	got := filterAlivePods(in).([]interface{})
	if len(got) != 3 {
		t.Errorf("missing or non-bool is_dead must be kept; got %d entries", len(got))
	}
}

func TestFilterAlivePods_NonSlicePassthrough(t *testing.T) {
	obj := map[string]interface{}{"pod_name": "x"}
	got := filterAlivePods(obj)
	if !reflect.DeepEqual(got, obj) {
		t.Errorf("non-slice input must pass through unchanged")
	}
}

func TestCompactPodsSummary_StripsHeavyweightFields(t *testing.T) {
	// Field names match the brokers actual wire format (serde
	// emission of the Rust PodDetail struct — snake_case). The test
	// previously used "labels" which doesnt exist on the wire; the
	// real field is "workload_selector_labels". A test built around
	// a fictional field gave false confidence that pods returned
	// from the broker carried selector labels through to the LLM —
	// they didnt, because the keepFields list looked for "labels".
	in := []interface{}{
		map[string]interface{}{
			"pod_name":                 "web-1",
			"pod_namespace":            "prod",
			"pod_ip":                   "10.1.0.1",
			"node_name":                "node-a",
			"is_dead":                  false,
			"pod_identity":             "web",
			"workload_selector_labels": map[string]interface{}{"app": "web"},
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

	for _, want := range []string{
		"pod_name", "pod_namespace", "pod_ip", "node_name",
		"is_dead", "pod_identity", "workload_selector_labels",
	} {
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

func TestCompactPodsSummary_SingleMapInputCompactsToMap(t *testing.T) {
	// The get_pod_details handler passes a single map (the broker's
	// /pod/ip/{ip} returns one PodDetail, not an array). Pre-fix
	// compactPodsSummary checked .([]interface{}) and fell through
	// for maps — returning the heavyweight pod_obj unchanged. The
	// LLM got kilobytes of Kubernetes Pod spec/status per identity
	// lookup, eating context budget.
	in := map[string]interface{}{
		"pod_name":      "web-1",
		"pod_namespace": "prod",
		"pod_ip":        "10.1.0.5",
		"node_name":     "node-a",
		"is_dead":       false,
		"pod_identity":  "web",
		"workload_selector_labels": map[string]interface{}{"app": "web"},
		// Heavyweight — must be stripped just like the slice path.
		"pod_obj": map[string]interface{}{
			"spec":   map[string]interface{}{"containers": "huge..."},
			"status": map[string]interface{}{"conditions": "more huge..."},
		},
	}
	got := compactPodsSummary(in)
	gotMap, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("single-map input must produce single-map output, got %T", got)
	}
	if _, present := gotMap["pod_obj"]; present {
		t.Error("pod_obj must be stripped from single-record compactation")
	}
	if gotMap["pod_name"] != "web-1" {
		t.Errorf("identity fields lost; got %#v", gotMap)
	}
	if labels, ok := gotMap["workload_selector_labels"].(map[string]interface{}); !ok || labels["app"] != "web" {
		t.Errorf("workload_selector_labels must survive single-record compactation")
	}
}

func TestCompactPodsSummary_PreservesWorkloadSelectorLabels(t *testing.T) {
	// Regression for the bug case. Pre-fix, the keepFields list
	// included "labels" (no such broker field) but NOT
	// "workload_selector_labels" (the actual wire field). Selector
	// labels — required for the LLM to construct accurate
	// NetworkPolicy selectors from observed traffic — were silently
	// stripped from every cluster_pods response.
	in := []interface{}{
		map[string]interface{}{
			"pod_name":                 "web-1",
			"workload_selector_labels": map[string]interface{}{
				"app.kubernetes.io/name": "web",
				"tier":                   "frontend",
			},
		},
	}
	got := compactPodsSummary(in).([]interface{})
	m := got[0].(map[string]interface{})
	labels, ok := m["workload_selector_labels"].(map[string]interface{})
	if !ok {
		t.Fatalf("workload_selector_labels stripped — LLM cant build accurate selectors from traffic")
	}
	if labels["app.kubernetes.io/name"] != "web" {
		t.Errorf("label content lost: %#v", labels)
	}
}

func TestCompactPodsSummary_NonSliceNonMapPassthrough(t *testing.T) {
	// True non-collection types (strings, numbers, nil) must pass
	// through unchanged — a map is now intentionally NOT passthrough
	// (it goes through compactPodRecord, see _SingleMapInputCompactsToMap)
	// so we test the truly-not-a-container case here.
	for _, in := range []interface{}{
		"some string",
		42,
		nil,
	} {
		got := compactPodsSummary(in)
		if !reflect.DeepEqual(got, in) {
			t.Errorf("non-collection input %#v must pass through unchanged; got %#v", in, got)
		}
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
