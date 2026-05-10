package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// End-to-end tests for the LLM-facing tool handlers. They each glue
// BrokerClient → filterByNamespace → compact* → JSON marshal, so a
// regression anywhere in that chain shows up in the LLM's response.
// Coverage lock: each handler must turn a successful broker call into
// a non-error mcp.CallToolResult with JSON content, and a broker error
// into IsError=true with a human-readable message.

func newBrokerWithJSON(t *testing.T, body string) (*BrokerClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return NewBrokerClient(srv.URL), srv.Close
}

func newBrokerWithError(t *testing.T, status int, body string) (*BrokerClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return NewBrokerClient(srv.URL), srv.Close
}

// --- ClusterPodsHandler ---

func TestClusterPodsHandler_StripsHeavyweightFields(t *testing.T) {
	body := `[{"pod_name":"web-1","pod_namespace":"prod","pod_ip":"10.0.0.1",
        "node_name":"node-a","is_dead":false,"labels":{"app":"web"},
        "pod_obj":{"spec":"huge"},"service_spec":{"a":"b"}}]`
	c, cleanup := newBrokerWithJSON(t, body)
	defer cleanup()

	h := ClusterPodsHandler{client: c}
	res, _, err := h.Call(context.Background(), nil, ClusterPodsInput{})
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected IsError=true: %#v", res.Content)
	}
	got := textOf(t, res)
	if strings.Contains(got, "pod_obj") {
		t.Errorf("pod_obj must be stripped from compact pods response: %s", got)
	}
	if !strings.Contains(got, "web-1") {
		t.Errorf("response should still contain pod_name: %s", got)
	}
}

func TestClusterPodsHandler_NamespaceFilter(t *testing.T) {
	body := `[
		{"pod_name":"a","pod_namespace":"prod","pod_ip":"10.0.0.1"},
		{"pod_name":"b","pod_namespace":"dev","pod_ip":"10.0.0.2"}
	]`
	c, cleanup := newBrokerWithJSON(t, body)
	defer cleanup()

	h := ClusterPodsHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ClusterPodsInput{Namespace: "prod"})
	if res.IsError {
		t.Fatalf("unexpected IsError=true")
	}
	got := textOf(t, res)
	if !strings.Contains(got, "\"pod_name\":\"a\"") {
		t.Errorf("expected prod pod 'a' in output: %s", got)
	}
	if strings.Contains(got, "\"pod_name\":\"b\"") {
		t.Errorf("dev pod 'b' should be filtered out: %s", got)
	}
}

func TestClusterPodsHandler_BrokerErrorBecomesIsError(t *testing.T) {
	c, cleanup := newBrokerWithError(t, http.StatusInternalServerError, "db offline")
	defer cleanup()

	h := ClusterPodsHandler{client: c}
	res, _, err := h.Call(context.Background(), nil, ClusterPodsInput{})
	if err != nil {
		// Handler must NOT propagate Go errors; it returns a CallToolResult
		// with IsError=true so the MCP layer can render a tool error to
		// the LLM cleanly.
		t.Fatalf("handler must not return Go error; got %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError=true on broker 500: %#v", res.Content)
	}
	got := textOf(t, res)
	if !strings.Contains(got, "error fetching cluster pods") {
		t.Errorf("error message should mention what failed: %s", got)
	}
}

// --- ClusterTrafficHandler ---

func TestClusterTrafficHandler_AggregatesByPod(t *testing.T) {
	body := `[
		{"pod_name":"web-1","pod_namespace":"prod","traffic_type":"ingress","src_ip":"10.0.0.1","dst_ip":"10.1.0.1"},
		{"pod_name":"web-1","pod_namespace":"prod","traffic_type":"egress","src_ip":"10.1.0.1","dst_ip":"10.0.0.5"},
		{"pod_name":"db-1","pod_namespace":"prod","traffic_type":"ingress","src_ip":"10.1.0.1","dst_ip":"10.2.0.1"}
	]`
	c, cleanup := newBrokerWithJSON(t, body)
	defer cleanup()

	h := ClusterTrafficHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ClusterTrafficInput{})
	if res.IsError {
		t.Fatalf("unexpected IsError=true: %s", textOf(t, res))
	}

	var summary map[string]any
	if err := json.Unmarshal([]byte(textOf(t, res)), &summary); err != nil {
		t.Fatalf("response must be JSON: %v", err)
	}
	if got := summary["total_records"]; got != float64(3) {
		t.Errorf("total_records: want 3, got %v", got)
	}
	if got := summary["pod_count"]; got != float64(2) {
		t.Errorf("pod_count: want 2, got %v", got)
	}
}

func TestClusterTrafficHandler_NamespaceFilterTaggedInResponse(t *testing.T) {
	body := `[
		{"pod_name":"a","pod_namespace":"prod","traffic_type":"ingress"},
		{"pod_name":"b","pod_namespace":"dev","traffic_type":"ingress"}
	]`
	c, cleanup := newBrokerWithJSON(t, body)
	defer cleanup()

	h := ClusterTrafficHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ClusterTrafficInput{Namespace: "prod"})

	var summary map[string]any
	_ = json.Unmarshal([]byte(textOf(t, res)), &summary)

	if got := summary["filtered_namespace"]; got != "prod" {
		t.Errorf("filtered_namespace tag missing or wrong: %v", got)
	}
	// pod_count should reflect filtered set, not the full input
	if got := summary["pod_count"]; got != float64(1) {
		t.Errorf("pod_count after ns filter: want 1, got %v", got)
	}
}

func TestClusterTrafficHandler_BrokerErrorBecomesIsError(t *testing.T) {
	c, cleanup := newBrokerWithError(t, http.StatusServiceUnavailable, "db unreachable")
	defer cleanup()

	h := ClusterTrafficHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ClusterTrafficInput{})
	if !res.IsError {
		t.Errorf("expected IsError=true on broker 503")
	}
}

// --- Single-target handlers: empty-input contract ---
//
// PodDetails / ServiceDetails / NetworkTraffic / Syscalls each take a
// single required parameter (IP or PodName). They ALL must short-circuit
// with IsError=true before making the broker call when the input is
// empty — otherwise we'd issue a `/pod/ip/` URL with a trailing slash
// and 404 against the broker, eating a round-trip and a noisy log line.

func TestPodDetailsHandler_EmptyIPRejected(t *testing.T) {
	// Pass a deliberately broken broker URL — the test must short-circuit
	// before any HTTP call.
	c := NewBrokerClient("http://broker-must-not-be-called.invalid")
	h := PodDetailsHandler{client: c}
	res, _, err := h.Call(context.Background(), nil, PodDetailsInput{IP: ""})
	if err != nil {
		t.Fatalf("handler must not return Go error: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError=true for empty IP")
	}
	if !strings.Contains(textOf(t, res), "IP address is required") {
		t.Errorf("error must explain what's missing: %s", textOf(t, res))
	}
}

func TestPodDetailsHandler_HappyPath(t *testing.T) {
	c, cleanup := newBrokerWithJSON(t, `{"pod_name":"web-1","pod_ip":"10.0.0.1"}`)
	defer cleanup()
	h := PodDetailsHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, PodDetailsInput{IP: "10.0.0.1"})
	if res.IsError {
		t.Fatalf("unexpected IsError=true: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "web-1") {
		t.Errorf("response missing pod_name: %s", textOf(t, res))
	}
}

func TestServiceDetailsHandler_EmptyIPRejected(t *testing.T) {
	c := NewBrokerClient("http://broker-must-not-be-called.invalid")
	h := ServiceDetailsHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, ServiceDetailsInput{IP: ""})
	if !res.IsError {
		t.Errorf("expected IsError=true for empty IP")
	}
}

func TestNetworkTrafficHandler_EmptyPodNameRejected(t *testing.T) {
	c := NewBrokerClient("http://broker-must-not-be-called.invalid")
	h := NetworkTrafficHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, NetworkTrafficInput{PodName: ""})
	if !res.IsError {
		t.Errorf("expected IsError=true for empty pod_name")
	}
}

func TestSyscallsHandler_EmptyPodNameRejected(t *testing.T) {
	c := NewBrokerClient("http://broker-must-not-be-called.invalid")
	h := SyscallsHandler{client: c}
	res, _, _ := h.Call(context.Background(), nil, SyscallsInput{PodName: ""})
	if !res.IsError {
		t.Errorf("expected IsError=true for empty pod_name")
	}
}

// textOf extracts the first TextContent from a CallToolResult — the
// shape every handler in this package returns.
func textOf(t *testing.T, res any) string {
	t.Helper()
	type contentBag struct {
		Content []struct{ Text string } `json:"-"`
	}
	_ = contentBag{} // unused — kept as a type-shape comment

	// Use reflection-free path: marshal then unmarshal a thin shape.
	// All handlers wrap content as []*mcp.TextContent so .Text is set.
	b, _ := json.Marshal(res)
	var raw struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal CallToolResult: %v\nbytes: %s", err, b)
	}
	if len(raw.Content) == 0 {
		t.Fatalf("CallToolResult has no content: %s", b)
	}
	return raw.Content[0].Text
}
