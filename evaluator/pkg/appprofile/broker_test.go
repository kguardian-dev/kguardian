package appprofile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBrokerClient_SendsReadTokenAndEscapesPath(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.EscapedPath()
		if r.Method != http.MethodGet {
			t.Errorf("method = %s; the evaluator only ever reads", r.Method)
		}
		_, _ = w.Write([]byte(`{"contentHash":"fnv1a64:1","version":null,"snapshotPending":true,
			"posture":{"status":"unknown","coverage":0,"unknownDimensions":["network","syscalls","podSecurity","images"],"reasons":[]},
			"dimensions":{"network":{"status":"unknown","reasons":[{"code":"no_flows","message":"x"}]}},"findings":[]}`))
	}))
	defer srv.Close()

	c, err := NewBrokerClient(srv.URL+"/", " read-token\n", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Profile(context.Background(), "team a", "Deployment", "web/1")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer read-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPath != "/workloads/team%20a/Deployment/web%2F1/profile" {
		t.Errorf("path = %q", gotPath)
	}
	if p.Version != nil || !p.SnapshotPending || p.Posture.Status != "unknown" || *p.Posture.Coverage != 0 {
		t.Errorf("decoded = %+v", p)
	}
	if p.Dimensions["network"].Reasons[0].Code != "no_flows" {
		t.Errorf("dimensions = %+v", p.Dimensions)
	}
}

func TestBrokerClient_NoTokenNoHeader(t *testing.T) {
	var had bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, had = r.Header["Authorization"]
		_, _ = w.Write([]byte(`{"revision":2,"contentHash":"h","createdAt":"2026-09-26T02:19:10.101753Z","dimensionHashes":{"network":"a"},"posture":{"status":"warn","coverage":0.5}}`))
	}))
	defer srv.Close()
	c, _ := NewBrokerClient(srv.URL, "", time.Second)
	v, err := c.Version(context.Background(), "ns", "Deployment", "web", 2)
	if err != nil {
		t.Fatal(err)
	}
	if had {
		t.Error("Authorization sent with no token configured")
	}
	if v.Revision != 2 || v.DimensionHashes["network"] != "a" || v.Posture.Status != "warn" {
		t.Errorf("decoded = %+v", v)
	}
}

func TestBrokerClient_ErrorCodes(t *testing.T) {
	cases := []struct {
		status   int
		body     string
		wantCode string
	}{
		{404, `{"error":"workload_not_found","message":"no such workload"}`, "workload_not_found"},
		{404, ``, ""}, // older broker without the routes
		{401, `unauthorized`, ""},
		{503, `read budget exhausted`, ""},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		c, _ := NewBrokerClient(srv.URL, "t", time.Second)
		_, err := c.Profile(context.Background(), "ns", "Deployment", "web")
		srv.Close()
		var be *BrokerError
		if !errors.As(err, &be) {
			t.Fatalf("%d: want BrokerError, got %v", tc.status, err)
		}
		if be.StatusCode != tc.status || be.Code != tc.wantCode {
			t.Errorf("%d: got status=%d code=%q", tc.status, be.StatusCode, be.Code)
		}
	}
}

func TestNewBrokerClient_RejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "kguardian-broker:9090", "://x"} {
		if _, err := NewBrokerClient(u, "", time.Second); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
