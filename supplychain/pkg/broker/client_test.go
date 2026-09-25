package broker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/sirupsen/logrus"
)

const testDigest = "sha256:53a13cd1588391888c5a8ac4cef13d3ee6d229cd904038936731af7131d193a9"

func TestHTTPClientSendsBearerAndJSON(t *testing.T) {
	var gotAuth, gotPath, gotCT string
	var got types.ImageVulnerabilities
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.EscapedPath()
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL+"/", " scoped-token\n")
	if err != nil {
		t.Fatal(err)
	}
	p := &types.ImageVulnerabilities{SchemaVersion: 1, Image: types.ImageRef{Digest: testDigest}, Source: types.SourceTrivyOperator}
	if err := c.SubmitVulnerabilities(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer scoped-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if !strings.HasPrefix(gotPath, "/images/sha256:53a1") || !strings.HasSuffix(gotPath, "/vulnerabilities") {
		t.Errorf("path = %q", gotPath)
	}
	if got.Image.Digest != testDigest {
		t.Errorf("body digest = %q", got.Image.Digest)
	}
}

func TestHTTPClientNoTokenNoHeader(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawAuth = r.Header["Authorization"]
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SubmitSBOM(context.Background(), &types.ImageSBOM{Image: types.ImageRef{Digest: testDigest}}); err != nil {
		t.Fatal(err)
	}
	if sawAuth {
		t.Error("sent an Authorization header with no token configured")
	}
}

func TestHTTPClientNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing scope supplychain", http.StatusForbidden)
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, "t")
	err := c.SubmitSBOM(context.Background(), &types.ImageSBOM{Image: types.ImageRef{Digest: testDigest}})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "missing scope") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewHTTPClientRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "broker:9090", "://x"} {
		if _, err := NewHTTPClient(u, ""); err == nil {
			t.Errorf("NewHTTPClient(%q) accepted", u)
		}
	}
}

func TestLoggingClientNeverFails(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	c := LoggingClient{Log: log}
	if err := c.SubmitVulnerabilities(context.Background(), &types.ImageVulnerabilities{}); err != nil {
		t.Fatal(err)
	}
	if err := c.SubmitSBOM(context.Background(), &types.ImageSBOM{}); err != nil {
		t.Fatal(err)
	}
}
