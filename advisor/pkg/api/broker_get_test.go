package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBrokerGet_EscapesPathAndForwardsAuth verifies the two hardening fixes on
// the broker client used by `advisor serve`:
//   - the caller-supplied pod name is URL-escaped into the request path
//     (a '/' must not split the path), and
//   - BrokerAuthToken, when set, is sent as a Bearer token.
func TestBrokerGet_EscapesPathAndForwardsAuth(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		gotAuth = r.Header.Get("Authorization")
		// Valid syscalls payload so GetPodSysCall returns without error.
		_, _ = w.Write([]byte(`[{"pod_name":"a/b","syscalls":"read","arch":"x86_64"}]`))
	}))
	defer srv.Close()

	origURL, origTok := BrokerBaseURL, BrokerAuthToken
	BrokerBaseURL = srv.URL
	BrokerAuthToken = "s3cr3t"
	t.Cleanup(func() { BrokerBaseURL = origURL; BrokerAuthToken = origTok })

	if _, err := GetPodSysCall("a/b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// '/' in the pod name must be percent-encoded, not a path separator.
	if gotPath != "/pod/syscalls/a%2Fb" {
		t.Errorf("path: want /pod/syscalls/a%%2Fb, got %s", gotPath)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Errorf("auth header: want 'Bearer s3cr3t', got %q", gotAuth)
	}
}

// TestBrokerGet_NoAuthHeaderWhenTokenEmpty ensures we don't send an empty
// bearer token when auth is not configured (the default, no-auth deployment).
func TestBrokerGet_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	var hadAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		_, _ = w.Write([]byte(`[{"pod_name":"web-1","syscalls":"read","arch":"x86_64"}]`))
	}))
	defer srv.Close()

	origURL, origTok := BrokerBaseURL, BrokerAuthToken
	BrokerBaseURL = srv.URL
	BrokerAuthToken = ""
	t.Cleanup(func() { BrokerBaseURL = origURL; BrokerAuthToken = origTok })

	if _, err := GetPodSysCall("web-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hadAuth {
		t.Error("Authorization header should be absent when BrokerAuthToken is empty")
	}
}
