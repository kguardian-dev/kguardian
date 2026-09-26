package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/sirupsen/logrus"
)

func TestEndpoints(t *testing.T) {
	var ready atomic.Bool
	m := metrics.New()
	m.SourceAvailable.WithLabelValues("trivy-operator").Set(0)
	s := New(":0", ready.Load, m.Registry, logrus.New())
	h := s.Handler()

	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		b, _ := io.ReadAll(rec.Body)
		return rec.Code, string(b)
	}

	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Errorf("healthz %d", code)
	}
	if code, _ := get("/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz before ready %d", code)
	}
	ready.Store(true)
	if code, _ := get("/readyz"); code != http.StatusOK {
		t.Errorf("readyz after ready %d", code)
	}
	code, body := get("/metrics")
	if code != http.StatusOK || !strings.Contains(body, `kguardian_supplychain_source_available{source="trivy-operator"} 0`) {
		t.Errorf("metrics %d:\n%s", code, body)
	}
	if code, _ := get("/nope"); code != http.StatusNotFound {
		t.Errorf("unknown path %d", code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz %d", rec.Code)
	}
}
