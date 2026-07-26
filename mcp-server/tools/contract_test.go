package tools

// G1 tool-contract snapshot (SIMPLIFICATION-GOAL.md §3).
//
// Pins the wire-visible MCP contract exactly as llm-bridge sees it: an
// in-memory MCP client connects to the real registered server and the test
// snapshots (a) the full tools/list result — names, descriptions, input
// schemas — and (b) a tools/call result per tool against fixture broker and
// advisor responses.
//
// The goldens under testdata/contract/ are the reference ANY reimplementation
// of this tool set must reproduce byte-for-byte (WS-B assistant merge): replay
// backend_fixtures.json through the new implementation and the same calls must
// yield the same results. A diff here is a contract change — never noise.
// Regenerate deliberately with: UPDATE_GOLDEN=1 go test ./tools -run Contract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const contractDir = "testdata/contract"

// calls: one representative invocation per tool, in registry order.
var contractCalls = []struct {
	Tool string
	Args map[string]any
}{
	{"get_pod_network_traffic", map[string]any{"pod_name": "web-1"}},
	{"get_pod_syscalls", map[string]any{"pod_name": "web-1"}},
	{"get_pod_details", map[string]any{"ip": "10.0.0.1"}},
	{"get_service_details", map[string]any{"ip": "10.96.0.10"}},
	{"get_cluster_traffic", map[string]any{}},
	{"get_cluster_pods", map[string]any{}},
	{"get_pod_details_by_name", map[string]any{"pod_name": "web-1"}},
	{"list_services", map[string]any{}},
	{"get_pods_on_node", map[string]any{"node": "node-a"}},
	{"get_audit_verdicts", map[string]any{}},
	{"generate_network_policy", map[string]any{"pod_name": "web-1"}},
	{"generate_seccomp_profile", map[string]any{"pod_name": "web-1"}},
}

// backendServer serves testdata/contract/backend_fixtures.json — a map of
// URL path → response body. Broker and advisor paths share one server; the
// fixture file is language-neutral so the WS-B TS port replays it verbatim.
func backendServer(t *testing.T) *httptest.Server {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contractDir, "backend_fixtures.json"))
	if err != nil {
		t.Fatalf("read backend fixtures: %v", err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("parse backend fixtures: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := fixtures[r.URL.Path]
		if !ok {
			t.Errorf("contract backend: no fixture for path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Advisor endpoints return YAML/JSON text bodies; the fixture stores
		// them as JSON strings. Everything else is raw JSON.
		var asString string
		if json.Unmarshal(body, &asString) == nil {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(asString))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func connectContractSession(t *testing.T, backendURL string) *mcp.ClientSession {
	t.Helper()
	t.Setenv("ADVISOR_URL", backendURL)

	server := mcp.NewServer(&mcp.Implementation{Name: "kguardian-mcp", Version: "1.0.0"}, nil)
	RegisterTools(server, backendURL)

	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "contract-test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(contractDir, name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden %s: %v", name, err)
		}
		t.Logf("updated golden %s", name)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run UPDATE_GOLDEN=1 go test ./tools -run Contract to create): %v", name, err)
	}
	if string(want) != string(got) {
		t.Errorf("CONTRACT DRIFT in %s.\nThis golden is the wire contract any tool-set reimplementation must match.\nIf the change is intentional, regenerate with UPDATE_GOLDEN=1 and call it out in review.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// TestContract_ToolsList pins names, descriptions, and input schemas for all
// 12 tools exactly as served over MCP.
func TestContract_ToolsList(t *testing.T) {
	backend := backendServer(t)
	cs := connectContractSession(t, backend.URL)

	res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(res.Tools) != len(contractCalls) {
		t.Fatalf("tool count drift: got %d tools, contract has %d", len(res.Tools), len(contractCalls))
	}
	got, err := json.MarshalIndent(res.Tools, "", "  ")
	if err != nil {
		t.Fatalf("marshal tools/list: %v", err)
	}
	checkGolden(t, "tools_list.golden.json", append(got, '\n'))
}

// TestContract_ToolCalls replays one call per tool against the fixture
// backend and pins each full CallToolResult.
func TestContract_ToolCalls(t *testing.T) {
	backend := backendServer(t)
	cs := connectContractSession(t, backend.URL)

	results := make(map[string]json.RawMessage, len(contractCalls))
	for _, call := range contractCalls {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      call.Tool,
			Arguments: call.Args,
		})
		if err != nil {
			t.Fatalf("tools/call %s: %v", call.Tool, err)
		}
		if res.IsError {
			t.Errorf("tools/call %s returned IsError=true against fixture data: %+v", call.Tool, res.Content)
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("marshal result for %s: %v", call.Tool, err)
		}
		results[call.Tool] = raw
	}
	got, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatalf("marshal call results: %v", err)
	}
	checkGolden(t, "tool_calls.golden.json", append(got, '\n'))
}
