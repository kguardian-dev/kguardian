package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8090" || c.Engine.DBDir != "/var/lib/grype" || c.Engine.URL != "https://grype.anchore.io/databases" ||
		!c.Engine.AutoUpdate || c.Engine.UpdateInterval != 6*time.Hour || c.Engine.MaxAge != 120*time.Hour {
		t.Errorf("defaults %+v", c)
	}
	c, err = loadConfig(envMap(map[string]string{"GRYPE_DB_URL": "https://mirror.internal/grype", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_MAX_AGE": "0"}))
	if err != nil || c.Engine.URL != "https://mirror.internal/grype" || c.Engine.AutoUpdate || c.Engine.MaxAge != 0 {
		t.Errorf("overrides %+v %v", c, err)
	}
	for _, bad := range []map[string]string{
		{"LISTEN_ADDR": "0.0.0.0:8090"}, {"LISTEN_ADDR": ":8090"},
		{"GRYPE_DB_AUTO_UPDATE": "maybe"}, {"GRYPE_DB_UPDATE_INTERVAL": "0s"}, {"GRYPE_DB_MAX_AGE": "-1h"},
	} {
		if _, err := loadConfig(envMap(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestProbeAndCommands(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			w.WriteHeader(404)
		}
	}))
	defer ok.Close()
	addr := strings.TrimPrefix(ok.URL, "http://")
	var errb bytes.Buffer
	if probe(addr, "readyz", &errb) != 0 || probe(addr, "healthz", &errb) != 1 {
		t.Error("probe status mapping")
	}
	var out bytes.Buffer
	if run([]string{"version"}, envMap(nil), &out, &errb) != 0 || !strings.Contains(out.String(), "v0.119.0") {
		t.Errorf("version: %q", out.String())
	}
	if run(nil, envMap(nil), &out, &errb) != 2 || run([]string{"bogus"}, envMap(nil), &out, &errb) != 2 {
		t.Error("usage exit codes")
	}
}
