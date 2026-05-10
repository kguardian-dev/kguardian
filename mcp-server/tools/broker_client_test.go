package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// All BrokerClient methods funnel into c.get(ctx, url), so most of the
// behavioural surface is covered by exercising one entry point against
// an httptest.Server.

func TestBrokerClient_GetPodNetworkTraffic_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pod/traffic/web-1" {
			t.Errorf("path: want /pod/traffic/web-1, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"pod_name":"web-1","traffic_type":"ingress"}]`))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	got, err := c.GetPodNetworkTraffic(context.Background(), "web-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := got.([]interface{})
	if !ok {
		t.Fatalf("want []interface{}, got %T", got)
	}
	if len(arr) != 1 {
		t.Errorf("want 1 record, got %d", len(arr))
	}
}

func TestBrokerClient_PodNameWithSlashesIsURLEscaped(t *testing.T) {
	// url.PathEscape converts '/' to %2F. A pod name like
	// "kube-system/kube-proxy" should not collapse the path segments.
	gotPath := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte("null"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	_, err := c.GetPodSyscalls(context.Background(), "kube-system/kube-proxy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// PathEscape encodes '/' as %2F. Path should contain the encoded form.
	if !strings.Contains(gotPath, "%2F") {
		t.Errorf("expected %%2F-encoded path; got %s", gotPath)
	}
}

func TestBrokerClient_NonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("relation \"audit_verdicts\" does not exist"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	_, err := c.GetAllPodTraffic(context.Background())
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	// The body is included in the error so operators can grep their logs
	// for the underlying schema/connection problem (this was exactly
	// today's symptom in the prod incident).
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error must include status code: %v", err)
	}
	if !strings.Contains(err.Error(), "audit_verdicts") {
		t.Errorf("error must include response body: %v", err)
	}
}

func TestBrokerClient_404ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	_, err := c.GetPodByIP(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error must mention 404: %v", err)
	}
}

func TestBrokerClient_UnreachableServerReturnsError(t *testing.T) {
	// Point at a port nothing is listening on. No retries — the broker
	// is single-source, so we surface the failure quickly.
	c := NewBrokerClient("http://127.0.0.1:1") // port 1, blocked
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.GetAllPods(ctx)
	if err == nil {
		t.Fatal("expected error against unreachable server, got nil")
	}
}

func TestBrokerClient_ContextCancellationStopsRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the connection until the client gives up.
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte("null"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.GetAllPodTraffic(ctx)
	dur := time.Since(start)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if dur > 1*time.Second {
		t.Errorf("cancellation should propagate quickly; took %s", dur)
	}
}

func TestBrokerClient_MalformedJSONReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not-valid-json"))
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	_, err := c.GetServiceByIP(context.Background(), "10.0.0.5")
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error must mention decode failure: %v", err)
	}
}

func TestBrokerClient_BodyAtLimitDecodes(t *testing.T) {
	// Build a JSON array roughly approaching the 10 MB cap and verify it
	// decodes. This is the boundary check for io.LimitReader behaviour.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 10k-element array of small objects ≈ a few hundred KB; well
		// inside the 10 MB cap, but exercises the streaming decoder
		// against a non-trivial body.
		var items []map[string]any
		for i := 0; i < 10_000; i++ {
			items = append(items, map[string]any{"i": i, "k": fmt.Sprintf("pod-%d", i)})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	got, err := c.GetAllPods(context.Background())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	arr, ok := got.([]interface{})
	if !ok {
		t.Fatalf("want []interface{}, got %T", got)
	}
	if len(arr) != 10_000 {
		t.Errorf("want 10_000 records, got %d", len(arr))
	}
}

func TestBrokerClient_OversizedBodyTruncated(t *testing.T) {
	// Server returns ~12 MB of garbage JSON. The 10 MB LimitReader cap
	// will truncate, the decoder will then hit EOF / unexpected end and
	// return an error rather than reading unbounded memory.
	const oversized = 12 * 1024 * 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Start a JSON array we'll never close — guarantees the decoder
		// either hits the truncation boundary or runs out of bytes.
		_, _ = w.Write([]byte("["))
		chunk := strings.Repeat(`{"k":"v"},`, 1024)
		written := 1
		for written < oversized {
			n, _ := w.Write([]byte(chunk))
			written += n
		}
	}))
	defer srv.Close()

	c := NewBrokerClient(srv.URL)
	_, err := c.GetAllPodTraffic(context.Background())
	if err == nil {
		t.Fatal("expected error on truncated/oversized response, got nil")
	}
}
