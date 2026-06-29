package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestBrokerClient_GetAuditVerdicts_BuildsQueryString pins that every
// supplied filter is forwarded as a query parameter to /audit/verdicts.
func TestBrokerClient_GetAuditVerdicts_BuildsQueryString(t *testing.T) {
	var gotQuery url.Values
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	_, err := c.GetAuditVerdicts(context.Background(), "web-deny", "prod", "WouldDeny", "Egress", 50, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/audit/verdicts" {
		t.Errorf("path: want /audit/verdicts, got %s", gotPath)
	}
	want := map[string]string{
		"policy":    "web-deny",
		"namespace": "prod",
		"verdict":   "WouldDeny",
		"direction": "Egress",
		"limit":     "50",
	}
	for k, v := range want {
		if got := gotQuery.Get(k); got != v {
			t.Errorf("query %s: want %q, got %q", k, v, got)
		}
	}
}

// TestBrokerClient_GetAuditVerdicts_OmitsEmptyAndZero pins that empty
// filters and a zero limit are not sent — the broker then applies its
// documented defaults (no filter, default row cap) rather than seeing
// empty-valued parameters.
func TestBrokerClient_GetAuditVerdicts_OmitsEmptyAndZero(t *testing.T) {
	var rawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	if _, err := c.GetAuditVerdicts(context.Background(), "", "", "", "", 0, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rawQuery != "" {
		t.Errorf("expected no query string, got %q", rawQuery)
	}
}

// TestBrokerClient_GetAuditVerdicts_ClusterScoped pins that clusterScoped=true
// sends namespace= (empty value PRESENT, not absent), which the broker reads as
// "cluster-scoped policy verdicts only". A bare empty namespace string can't
// express this — it would be omitted — so the dedicated flag is the only way to
// reach the broker's cluster-scoped filter.
func TestBrokerClient_GetAuditVerdicts_ClusterScoped(t *testing.T) {
	var rawQuery string
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	// namespace="prod" is provided but clusterScoped=true must take precedence.
	if _, err := c.GetAuditVerdicts(context.Background(), "", "prod", "", "", 0, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rawQuery, "namespace=") {
		t.Errorf("expected namespace= (empty value present) in query, got %q", rawQuery)
	}
	if ns, ok := gotQuery["namespace"]; !ok || len(ns) != 1 || ns[0] != "" {
		t.Errorf("expected namespace present with empty value, got %v", gotQuery["namespace"])
	}
}

// TestPodByNameHandler_EmptyPodNameRejected mirrors the other
// name-required handlers: a blank pod_name short-circuits to IsError
// without hitting the broker.
func TestPodByNameHandler_EmptyPodNameRejected(t *testing.T) {
	h := PodByNameHandler{client: NewBrokerClient("http://unused")}
	res, _, _ := h.Call(context.Background(), nil, PodByNameInput{PodName: ""})
	if !res.IsError {
		t.Fatalf("expected IsError for empty pod_name")
	}
}

// TestPodByNameHandler_StripsPodObj pins that get_pod_details_by_name
// strips the heavyweight pod_obj like get_pod_details does, while
// keeping identity fields.
func TestPodByNameHandler_StripsPodObj(t *testing.T) {
	c, cleanup := newBrokerWithJSON(t, `{
		"pod_name":"web-1",
		"pod_namespace":"prod",
		"pod_ip":"10.0.0.1",
		"workload_selector_labels":{"app":"web"},
		"pod_obj":{"spec":{"containers":[{"name":"app","image":"nginx"}]}}
	}`)
	defer cleanup()
	h := PodByNameHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, PodByNameInput{PodName: "web-1"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	body := textOf(t, res)
	if strings.Contains(body, "pod_obj") {
		t.Errorf("pod_obj must be stripped; got: %s", body)
	}
	if !strings.Contains(body, "web-1") || !strings.Contains(body, `"app":"web"`) {
		t.Errorf("identity fields lost: %s", body)
	}
}

// TestPodsOnNodeHandler pins node-scoped pod listing: empty-node rejection,
// and that the result is live-only with pod_obj stripped.
func TestPodsOnNodeHandler(t *testing.T) {
	reject := PodsOnNodeHandler{client: NewBrokerClient("http://unused")}
	if res, _, _ := reject.Call(context.Background(), nil, PodsOnNodeInput{Node: ""}); !res.IsError {
		t.Fatalf("expected IsError for empty node")
	}

	c, cleanup := newBrokerWithJSON(t, `[
		{"pod_name":"web-1","pod_namespace":"prod","node_name":"node-a","is_dead":false,"pod_obj":{"spec":{"containers":[]}}},
		{"pod_name":"old-1","pod_namespace":"prod","node_name":"node-a","is_dead":true}
	]`)
	defer cleanup()
	res, _, _ := PodsOnNodeHandler{client: c}.Call(context.Background(), nil, PodsOnNodeInput{Node: "node-a"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	body := textOf(t, res)
	if strings.Contains(body, "pod_obj") {
		t.Errorf("pod_obj must be stripped; got: %s", body)
	}
	if !strings.Contains(body, "web-1") || strings.Contains(body, "old-1") {
		t.Errorf("expected live web-1, dead old-1 filtered; got: %s", body)
	}
}

// TestClusterServicesHandler_CompactsAndFiltersNamespace pins that
// list_services strips the full service_spec down to selector+ports
// and honours the optional namespace filter.
func TestClusterServicesHandler_CompactsAndFiltersNamespace(t *testing.T) {
	c, cleanup := newBrokerWithJSON(t, `[
		{"svc_name":"web","svc_namespace":"prod","svc_ip":"10.96.0.1","service_spec":{"spec":{"selector":{"app":"web"},"ports":[{"port":80}],"type":"ClusterIP"}}},
		{"svc_name":"db","svc_namespace":"data","svc_ip":"10.96.0.2","service_spec":{"spec":{"selector":{"app":"db"},"ports":[{"port":5432}]}}}
	]`)
	defer cleanup()
	h := ClusterServicesHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ClusterServicesInput{Namespace: "prod"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	body := textOf(t, res)
	// Namespace filter keeps prod, drops data.
	if !strings.Contains(body, "web") || strings.Contains(body, `"db"`) {
		t.Errorf("namespace filter not applied; got: %s", body)
	}
	// Compaction: full service_spec wrapper stripped, selector lifted.
	if strings.Contains(body, "service_spec") || strings.Contains(body, "ClusterIP") {
		t.Errorf("service_spec must be stripped; got: %s", body)
	}
	if !strings.Contains(body, "service_selector") || !strings.Contains(body, "service_ports") {
		t.Errorf("selector/ports must be lifted; got: %s", body)
	}
}

// TestAuditVerdictsHandler_PassesThrough pins that get_audit_verdicts
// returns the broker's verdict rows unmodified (no compaction).
func TestAuditVerdictsHandler_PassesThrough(t *testing.T) {
	c, cleanup := newBrokerWithJSON(t, `[
		{"policy_name":"web-deny","src_pod":"web-1","dst_pod":"db-1","dst_port":5432,"protocol":"TCP","direction":"Egress","verdict":"WouldDeny","reason":"no rule permits this flow","observed_at":"2026-06-26T10:00:00"}
	]`)
	defer cleanup()
	h := AuditVerdictsHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, AuditVerdictsInput{Verdict: "WouldDeny"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	body := textOf(t, res)
	for _, want := range []string{"web-deny", "WouldDeny", "no rule permits this flow", "5432"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in response; got: %s", want, body)
		}
	}
}

// TestClusterTrafficHandler_CountsAllowAndDrop pins that the cluster-traffic
// summary surfaces policy-decision counts (the "what's being dropped" signal),
// both per-pod and as a cluster-wide total_drop_count.
func TestClusterTrafficHandler_CountsAllowAndDrop(t *testing.T) {
	c, cleanup := newBrokerWithJSON(t, `[
		{"pod_name":"web-1","traffic_type":"EGRESS","traffic_in_out_ip":"8.8.8.8","decision":"ALLOW"},
		{"pod_name":"web-1","traffic_type":"EGRESS","traffic_in_out_ip":"9.9.9.9","decision":"DROP"},
		{"pod_name":"web-1","traffic_type":"INGRESS","traffic_in_out_ip":"10.0.0.5","decision":"DROP"}
	]`)
	defer cleanup()
	h := ClusterTrafficHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ClusterTrafficInput{})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	body := textOf(t, res)
	for _, want := range []string{`"total_drop_count":2`, `"drop_count":2`, `"allow_count":1`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %s in summary; got: %s", want, body)
		}
	}
}

// TestAuditVerdictsHandler_BrokerErrorBecomesIsError pins that an
// upstream broker failure surfaces as a tool error, not a panic.
func TestAuditVerdictsHandler_BrokerErrorBecomesIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	h := AuditVerdictsHandler{client: NewBrokerClient(srv.URL)}
	res, _, _ := h.Call(context.Background(), nil, AuditVerdictsInput{})
	if !res.IsError {
		t.Fatalf("expected IsError on broker 500")
	}
}
