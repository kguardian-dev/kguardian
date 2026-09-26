package match

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// The response body below is what supplychain-matcher's server writes
// (internal/wire field names); decoding it into types.Vulnerability is the
// contract under test.
func TestHTTPMatcherRoundTrip(t *testing.T) {
	var gotDigest string
	var gotComps int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/db":
			_, _ = w.Write([]byte(`{"built":"2026-09-25T06:31:49Z","schema_version":"v6.1.9","loaded":true,"scanner":"grype v0.119.0"}`))
		case "/match":
			if r.Header.Get("Content-Encoding") != "gzip" {
				http.Error(w, "gzip", http.StatusUnsupportedMediaType)
				return
			}
			zr, _ := gzip.NewReader(r.Body)
			var req struct {
				Image      struct{ Digest string } `json:"image"`
				Components []json.RawMessage       `json:"components"`
			}
			_ = json.NewDecoder(zr).Decode(&req)
			gotDigest, gotComps = req.Image.Digest, len(req.Components)
			_, _ = w.Write([]byte(`{"db":{"built":"2026-09-25T06:31:49Z","schema_version":"v6.1.9","loaded":true,"scanner":"grype v0.119.0"},
			"vulnerabilities":[{"id":"CVE-2099-1","package":{"name":"libc6","version":"2.36-9+deb12u10","type":"deb","purl":"pkg:deb/debian/libc6@2.36-9%2Bdeb12u10"},
			"fixed_version":"2.36-9+deb12u11","severity":"HIGH","score":7.8,"kev":true,"kev_date_added":"2024-01-02T00:00:00Z","epss":0.42,"epss_percentile":0.97,
			"cvss":{"nvd@nist.gov":{"v3_score":7.8,"v3_vector":"CVSS:3.1/AV:L"}},"class":"os-pkgs","file_paths":["lib/x86_64-linux-gnu/libc.so.6"]}]}`))
		}
	}))
	defer srv.Close()
	m, err := NewHTTPMatcher(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	db := m.DB()
	if db.Built.IsZero() || db.SchemaVersion != "v6.1.9" {
		t.Fatalf("db %+v", db)
	}
	vs, err := m.Match(context.Background(), &types.ImageSBOM{Image: types.ImageRef{Digest: "sha256:abc"},
		Components: []types.Component{{Name: "libc6"}, {Name: "debian", Type: "operating-system"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != "sha256:abc" || gotComps != 2 {
		t.Errorf("request: %s %d", gotDigest, gotComps)
	}
	v := vs[0]
	if len(vs) != 1 || !v.KnownExploited || v.KEVDateAdded == nil || v.EPSS == nil || *v.EPSS != 0.42 ||
		v.EPSSPercentile == nil || v.FixedVersion != "2.36-9+deb12u11" || v.CVSS["nvd@nist.gov"].V3Score == nil || len(v.FilePaths) != 1 {
		t.Errorf("decoded %+v", v)
	}
	if s := m.Scanner(); s.Name != "grype" || s.Version != "v0.119.0" {
		t.Errorf("scanner %+v", s)
	}
}

func TestHTTPMatcherErrorsAndURL(t *testing.T) {
	for _, u := range []string{"http://10.0.0.1:8090", "https://127.0.0.1:8090", "ftp://127.0.0.1", "http://matcher:8090"} {
		if _, err := NewHTTPMatcher(u); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "vulnerability database not loaded", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m, _ := NewHTTPMatcher(srv.URL)
	if _, err := m.Match(context.Background(), &types.ImageSBOM{}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("err %v", err)
	}
	if !m.DB().Built.IsZero() {
		t.Error("DB before any success must be zero")
	}
}
