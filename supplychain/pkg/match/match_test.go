package match

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

// mockMatcher returns one vulnerability per component and counts calls.
type mockMatcher struct {
	mu    sync.Mutex
	built time.Time
	calls map[string]int
}

func (m *mockMatcher) Match(_ context.Context, s *types.ImageSBOM) ([]types.Vulnerability, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls == nil {
		m.calls = map[string]int{}
	}
	m.calls[s.Image.Digest]++
	var out []types.Vulnerability
	for _, c := range s.Components {
		out = append(out, types.Vulnerability{ID: "CVE-2099-" + c.Name, Package: types.Package{Name: c.Name, Version: c.Version}, Severity: "HIGH", KnownExploited: true})
	}
	return out, nil
}
func (m *mockMatcher) DB() DBInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return DBInfo{Built: m.built, SchemaVersion: "v6.1.9"}
}
func (m *mockMatcher) Scanner() types.Scanner { return types.Scanner{Name: "grype", Version: "test"} }
func (m *mockMatcher) setBuilt(t time.Time)   { m.mu.Lock(); m.built = t; m.mu.Unlock() }
func (m *mockMatcher) n(d string) int         { m.mu.Lock(); defer m.mu.Unlock(); return m.calls[d] }

type sink struct {
	mu sync.Mutex
	es []trivy.Emission
}

func (s *sink) Enqueue(e trivy.Emission) { s.mu.Lock(); s.es = append(s.es, e); s.mu.Unlock() }
func (s *sink) vulns() []*types.ImageVulnerabilities {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*types.ImageVulnerabilities
	for _, e := range s.es {
		if e.Kind == trivy.KindVulnerabilities {
			out = append(out, e.Vulns)
		}
	}
	return out
}

func sbom(digest, source string, comps ...string) *types.ImageSBOM {
	s := &types.ImageSBOM{Image: types.ImageRef{Digest: digest}, Source: source}
	for _, c := range comps {
		s.Components = append(s.Components, types.Component{Name: c, Version: "1"})
	}
	return s
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quiet() *logrus.Logger { l := logrus.New(); l.SetOutput(io.Discard); return l }

func TestMatchesAndRematchesOnDBUpdate(t *testing.T) {
	m := &mockMatcher{}
	s := &sink{}
	met := metrics.New()
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet(), Metrics: met}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, 10*time.Millisecond)

	// Offered before any DB is loaded: held, not matched.
	c.Offer(sbom("sha256:a", types.SourceTrivyOperator, "openssl"))
	c.Offer(sbom("sha256:b", types.SourceRegistry, "musl", "zlib"))
	time.Sleep(50 * time.Millisecond)
	if len(s.vulns()) != 0 {
		t.Fatal("matched without a database")
	}

	db1 := time.Date(2026, 9, 25, 6, 31, 49, 0, time.UTC)
	m.setBuilt(db1)
	waitFor(t, func() bool { return len(s.vulns()) == 2 })
	for _, v := range s.vulns() {
		if v.Source != types.SourceGrype || v.DBUpdatedAt == nil || !v.DBUpdatedAt.Equal(db1) || v.Scanner.Name != "grype" {
			t.Errorf("payload: %+v", v)
		}
		if v.Image.Digest == "sha256:b" && (v.SBOMSource != types.SourceRegistry || len(v.Vulnerabilities) != 2 || !v.Vulnerabilities[0].KnownExploited) {
			t.Errorf("b: %+v", v)
		}
	}

	// Re-offering identical content does nothing.
	c.Offer(sbom("sha256:a", types.SourceTrivyOperator, "openssl"))
	time.Sleep(50 * time.Millisecond)
	if m.n("sha256:a") != 1 {
		t.Errorf("identical SBOM re-matched: %d", m.n("sha256:a"))
	}

	// A new DB re-matches everything held, with no new Offer.
	m.setBuilt(db1.Add(24 * time.Hour))
	waitFor(t, func() bool { return m.n("sha256:a") == 2 && m.n("sha256:b") == 2 })
	if v := testutil.ToFloat64(met.GrypeDBBuilt); v != float64(db1.Add(24*time.Hour).Unix()) {
		t.Errorf("db built gauge %v", v)
	}
	if v := testutil.ToFloat64(met.GrypeMatchRuns.WithLabelValues("ok")); v != 4 {
		t.Errorf("runs %v", v)
	}
}

func TestSourcePriority(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, time.Hour)

	c.Offer(sbom("sha256:x", types.SourceTrivyOperator, "a"))
	waitFor(t, func() bool { return len(s.vulns()) == 1 })
	// A registry SBOM supersedes Trivy's.
	c.Offer(sbom("sha256:x", types.SourceRegistry, "a", "b"))
	waitFor(t, func() bool { return len(s.vulns()) == 2 })
	if v := s.vulns()[1]; v.SBOMSource != types.SourceRegistry || len(v.Vulnerabilities) != 2 {
		t.Fatalf("%+v", v)
	}
	// A later Trivy SBOM for the same digest does not displace it.
	c.Offer(sbom("sha256:x", types.SourceTrivyOperator, "a", "b", "c"))
	time.Sleep(50 * time.Millisecond)
	if len(s.vulns()) != 2 || m.n("sha256:x") != 2 {
		t.Errorf("lower-priority SBOM was matched: %d vulns payloads, %d calls", len(s.vulns()), m.n("sha256:x"))
	}
}

func TestBoundedAndTee(t *testing.T) {
	m := &mockMatcher{}
	next := &sink{}
	c := &Coordinator{Matcher: m, Sink: &sink{}, MaxDigests: 3}
	tee := c.Tee(next)
	for i, d := range []string{"a", "b", "c", "d", "e"} {
		tee.Enqueue(trivy.Emission{Kind: trivy.KindSBOM, Digest: d, SBOM: sbom("sha256:"+d, types.SourceRegistry, "p")})
		_ = i
	}
	tee.Enqueue(trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: "z", Vulns: &types.ImageVulnerabilities{}})
	if c.Held() != 3 {
		t.Errorf("held %d, want 3", c.Held())
	}
	if len(next.es) != 6 {
		t.Errorf("tee did not forward everything: %d", len(next.es))
	}
}
