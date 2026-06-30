package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateNetworkPolicy_ReturnsYAML(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"))
	}))
	defer srv.Close()

	h := GenerateNetworkPolicyHandler{advisor: NewAdvisorClient(srv.URL)}
	res, _, _ := h.Call(context.Background(), nil, GenerateNetworkPolicyInput{PodName: "web-1", PolicyType: "cilium"})

	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	if gotPath != "/generate/networkpolicy" {
		t.Errorf("path: want /generate/networkpolicy, got %s", gotPath)
	}
	if !strings.Contains(gotQuery, "pod=web-1") || !strings.Contains(gotQuery, "type=cilium") {
		t.Errorf("query missing pod/type: %s", gotQuery)
	}
	if !strings.Contains(textOf(t, res), "kind: NetworkPolicy") {
		t.Errorf("expected YAML passed through; got: %s", textOf(t, res))
	}
}

func TestGenerateNetworkPolicy_DefaultsToKubernetesType(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("kind: NetworkPolicy\n"))
	}))
	defer srv.Close()

	h := GenerateNetworkPolicyHandler{advisor: NewAdvisorClient(srv.URL)}
	_, _, _ = h.Call(context.Background(), nil, GenerateNetworkPolicyInput{PodName: "web-1"})

	if !strings.Contains(gotQuery, "type=kubernetes") {
		t.Errorf("expected default type=kubernetes; got query: %s", gotQuery)
	}
}

func TestGenerateNetworkPolicy_EmptyPodRejected(t *testing.T) {
	h := GenerateNetworkPolicyHandler{advisor: NewAdvisorClient("http://unused")}
	res, _, _ := h.Call(context.Background(), nil, GenerateNetworkPolicyInput{PodName: ""})
	if !res.IsError {
		t.Fatalf("expected IsError for empty pod_name")
	}
}

func TestGenerateNetworkPolicy_AdvisorErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"no traffic data found for pod web-1"}`))
	}))
	defer srv.Close()

	h := GenerateNetworkPolicyHandler{advisor: NewAdvisorClient(srv.URL)}
	res, _, _ := h.Call(context.Background(), nil, GenerateNetworkPolicyInput{PodName: "web-1"})

	if !res.IsError {
		t.Fatalf("expected IsError on advisor 502")
	}
	if !strings.Contains(textOf(t, res), "no traffic data found") {
		t.Errorf("expected advisor error message surfaced; got: %s", textOf(t, res))
	}
}

func TestGenerateSeccompProfile_ReturnsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/generate/seccomp" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`))
	}))
	defer srv.Close()

	h := GenerateSeccompProfileHandler{advisor: NewAdvisorClient(srv.URL)}
	res, _, _ := h.Call(context.Background(), nil, GenerateSeccompProfileInput{PodName: "web-1"})

	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "SCMP_ACT_ERRNO") {
		t.Errorf("expected seccomp JSON passed through; got: %s", textOf(t, res))
	}
}

func TestNewAdvisorClient_PrecedenceAndTrim(t *testing.T) {
	// Explicit arg wins and trailing slash is stripped.
	c := NewAdvisorClient("  http://example:8082/  ")
	if c.baseURL != "http://example:8082" {
		t.Errorf("baseURL: want http://example:8082, got %q", c.baseURL)
	}
	// Empty arg + no env -> in-cluster default.
	t.Setenv("ADVISOR_URL", "")
	if d := NewAdvisorClient("").baseURL; d != defaultAdvisorURL {
		t.Errorf("default baseURL: want %s, got %s", defaultAdvisorURL, d)
	}
	// Env override.
	t.Setenv("ADVISOR_URL", "http://from-env:9000")
	if e := NewAdvisorClient("").baseURL; e != "http://from-env:9000" {
		t.Errorf("env baseURL: want http://from-env:9000, got %s", e)
	}
}
