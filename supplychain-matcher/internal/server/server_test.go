package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/engine"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
	"github.com/sirupsen/logrus"
)

type fakeEngine struct {
	loaded bool
	got    []wire.Component
}

func (f *fakeEngine) Match(_ context.Context, cs []wire.Component) ([]wire.Vulnerability, error) {
	if !f.loaded {
		return nil, engine.ErrNotReady
	}
	f.got = cs
	return []wire.Vulnerability{{ID: "CVE-2099-1", Package: wire.Package{Name: cs[0].Name}, Severity: "HIGH", KnownExploited: true}}, nil
}
func (f *fakeEngine) DB() wire.DB  { return wire.DB{Loaded: f.loaded, Scanner: "grype v0.119.0"} }
func (f *fakeEngine) Loaded() bool { return f.loaded }

func gz(t *testing.T, v interface{}) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_ = json.NewEncoder(zw).Encode(v)
	_ = zw.Close()
	return buf.Bytes()
}

func do(h http.Handler, method, path, remote string, body []byte, gzipped bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = remote
	if gzipped {
		r.Header.Set("Content-Encoding", "gzip")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLoopbackOnly(t *testing.T) {
	s := &Server{Engine: &fakeEngine{loaded: true}, Log: logrus.New()}
	h := s.Handler()
	for _, remote := range []string{"10.0.0.7:5555", "192.0.2.1:1234", "[fd00::1]:1", "169.254.169.254:80"} {
		if w := do(h, http.MethodGet, "/db", remote, nil, false); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", remote, w.Code)
		}
	}
	for _, remote := range []string{"127.0.0.1:5555", "[::1]:1", "[::ffff:127.0.0.1]:9"} {
		if w := do(h, http.MethodGet, "/db", remote, nil, false); w.Code != http.StatusOK {
			t.Errorf("%s: %d", remote, w.Code)
		}
	}
}

func TestCheckListenAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8090": true, "[::1]:8090": true,
		":8090": false, "0.0.0.0:8090": false, "10.0.0.1:8090": false, "localhost:8090": false,
	} {
		if err := CheckListenAddr(addr); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestMatchEndpoint(t *testing.T) {
	f := &fakeEngine{}
	s := &Server{Engine: f, Log: logrus.New()}
	h := s.Handler()
	req := map[string]interface{}{
		"schema_version": 1, "source": "registry", // extra ImageSBOM fields are ignored
		"image":      map[string]string{"digest": "sha256:abc"},
		"components": []map[string]interface{}{{"name": "musl", "version": "1.2.5-r3", "purl": "pkg:apk/alpine/musl@1.2.5-r3", "file_paths": []string{"lib/ld-musl-x86_64.so.1"}}},
	}
	if w := do(h, http.MethodPost, "/match", "127.0.0.1:1", gz(t, req), true); w.Code != http.StatusServiceUnavailable {
		t.Errorf("not loaded: %d", w.Code)
	}
	if w := do(h, http.MethodGet, "/readyz", "127.0.0.1:1", nil, false); w.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz before load: %d", w.Code)
	}
	f.loaded = true
	w := do(h, http.MethodPost, "/match", "127.0.0.1:1", gz(t, req), true)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var resp wire.MatchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Vulnerabilities) != 1 || !resp.Vulnerabilities[0].KnownExploited || !resp.DB.Loaded ||
		len(f.got) != 1 || f.got[0].FilePaths[0] != "lib/ld-musl-x86_64.so.1" {
		t.Errorf("resp %+v got %+v", resp, f.got)
	}
	if !strings.Contains(w.Body.String(), `"kev":true`) {
		t.Errorf("wire field names: %s", w.Body.String())
	}
	if w := do(h, http.MethodPost, "/match", "127.0.0.1:1", []byte(`{}`), false); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("plain body: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/match", "127.0.0.1:1", []byte("not gzip"), true); w.Code != http.StatusBadRequest {
		t.Errorf("bad gzip: %d", w.Code)
	}
	body, _ := io.ReadAll(bytes.NewReader(gz(t, "not an object")))
	if w := do(h, http.MethodPost, "/match", "127.0.0.1:1", body, true); w.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", w.Code)
	}
}
