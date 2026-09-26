package match

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

// mockMatcher returns one vulnerability per non-OS component and records
// what it was asked to match.
type mockMatcher struct {
	mu    sync.Mutex
	built time.Time
	calls map[string]int
	last  map[string][]types.Component
}

func (m *mockMatcher) Match(_ context.Context, s *types.ImageSBOM) ([]types.Vulnerability, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls == nil {
		m.calls, m.last = map[string]int{}, map[string][]types.Component{}
	}
	m.calls[s.Image.Digest]++
	m.last[s.Image.Digest] = s.Components
	var out []types.Vulnerability
	for _, c := range s.Components {
		if c.Type == "operating-system" {
			continue
		}
		out = append(out, types.Vulnerability{ID: "CVE-2099-" + c.Name, Package: types.Package{Name: c.Name, Version: c.Version, PURL: c.PURL}, Severity: "HIGH", KnownExploited: true})
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
func (m *mockMatcher) input(d string) []types.Component {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last[d]
}

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
func (s *sink) last() *types.ImageVulnerabilities {
	v := s.vulns()
	if len(v) == 0 {
		return nil
	}
	return v[len(v)-1]
}

func trivySBOM(digest string, comps ...string) *types.ImageSBOM {
	s := &types.ImageSBOM{Image: types.ImageRef{Digest: digest}, Source: types.SourceTrivyOperator, SBOMTrust: types.SBOMTrustScanned,
		ObservedIn: []types.WorkloadRef{{Namespace: "shop", Kind: "ReplicaSet", Name: "api", Container: "api"}}}
	for _, c := range comps {
		s.Components = append(s.Components, types.Component{Name: c, Version: "1", PURL: "pkg:deb/debian/" + c + "@1"})
	}
	return s
}

func registrySBOM(digest, index string, comps ...string) *types.ImageSBOM {
	s := &types.ImageSBOM{Image: types.ImageRef{Digest: digest, IndexDigest: index}, Source: types.SourceRegistry, SBOMTrust: types.SBOMTrustUnverified}
	for _, c := range comps {
		s.Components = append(s.Components, types.Component{Name: c, Version: "1", PURL: "pkg:deb/debian/" + c + "@1?distro=debian-12"})
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

func start(t *testing.T, c *Coordinator, poll time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.Run(ctx, poll)
}

func TestMatchesAndRematchesOnDBUpdate(t *testing.T) {
	m := &mockMatcher{}
	s := &sink{}
	met := metrics.New()
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet(), Metrics: met}
	start(t, c, 10*time.Millisecond)

	// Offered before any DB is loaded: held, not matched.
	c.Offer(trivySBOM("sha256:a", "openssl"))
	c.Offer(registrySBOM("sha256:b", "", "musl", "zlib"))
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
		if v.Image.Digest == "sha256:b" && (!reflect.DeepEqual(v.SBOMSources, []string{"registry"}) || v.SBOMTrust != types.SBOMTrustUnverified || len(v.Vulnerabilities) != 2) {
			t.Errorf("b: %+v", v)
		}
	}

	// Re-offering identical content does nothing.
	c.Offer(trivySBOM("sha256:a", "openssl"))
	time.Sleep(50 * time.Millisecond)
	if m.n("sha256:a") != 1 {
		t.Errorf("identical SBOM re-matched: %d", m.n("sha256:a"))
	}

	// A new DB re-matches everything held, with no new Offer.
	m.setBuilt(db1.Add(24 * time.Hour))
	waitFor(t, func() bool { return m.n("sha256:a") == 2 && m.n("sha256:b") == 2 })
	if v := testutil.ToFloat64(met.GrypeMatchRuns.WithLabelValues("ok")); v != 4 {
		t.Errorf("runs %v", v)
	}
}

// The core rule: an unverified registry SBOM can only add. One that lists
// fewer packages than Trivy found cannot reduce what is matched.
func TestUnionRegistryCannotHide(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	start(t, c, time.Hour)

	c.Offer(trivySBOM("sha256:x", "openssl", "zlib", "libc6"))
	waitFor(t, func() bool { return len(s.vulns()) == 1 })
	if n := len(s.last().Vulnerabilities); n != 3 {
		t.Fatalf("trivy alone: %d", n)
	}

	// A registry SBOM claiming only libc6 is present.
	c.Offer(registrySBOM("sha256:x", "", "libc6"))
	waitFor(t, func() bool { return len(s.vulns()) >= 1 && m.n("sha256:x") >= 1 })
	time.Sleep(50 * time.Millisecond)
	v := s.last()
	if len(v.Vulnerabilities) != 3 {
		t.Fatalf("registry SBOM reduced findings to %d", len(v.Vulnerabilities))
	}
	// A registry SBOM that adds a package adds findings.
	c.Offer(registrySBOM("sha256:x", "", "libc6", "curl"))
	waitFor(t, func() bool { return len(s.last().Vulnerabilities) == 4 })
	v = s.last()
	if !reflect.DeepEqual(v.SBOMSources, []string{"registry", "trivy-operator"}) || v.SBOMTrust != types.SBOMTrustUnverified ||
		len(v.ObservedIn) != 1 {
		t.Errorf("union payload: sources=%v trust=%s observed=%v", v.SBOMSources, v.SBOMTrust, v.ObservedIn)
	}
}

// BuildKit registry SBOMs are keyed by the platform manifest; Trivy by the
// index. They must meet in one group keyed by the index.
func TestJoinPlatformSBOMIntoIndex(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	start(t, c, time.Hour)

	// Registry SBOM alone (no Trivy for its index yet): matched on its own.
	c.Offer(registrySBOM("sha256:amd64", "sha256:index", "musl"))
	waitFor(t, func() bool { return m.n("sha256:amd64") == 1 })

	// Trivy's SBOM for the index arrives: the platform SBOM folds into it.
	c.Offer(trivySBOM("sha256:index", "openssl"))
	waitFor(t, func() bool { return m.n("sha256:index") == 1 })
	in := m.input("sha256:index")
	names := []string{}
	for _, comp := range in {
		names = append(names, comp.Name)
	}
	// Trivy's components first, then what the registry SBOM added.
	if !reflect.DeepEqual(names, []string{"openssl", "musl"}) {
		t.Fatalf("index group input: %v", names)
	}
	v := s.last()
	if v.Image.Digest != "sha256:index" || !reflect.DeepEqual(v.SBOMSources, []string{"registry", "trivy-operator"}) {
		t.Errorf("joined payload: %+v", v)
	}
	// Re-offering the platform SBOM re-matches the index group, never the
	// platform digest alone again.
	c.Offer(registrySBOM("sha256:amd64", "sha256:index", "musl", "zlib"))
	waitFor(t, func() bool { return m.n("sha256:index") == 2 })
	time.Sleep(30 * time.Millisecond)
	if m.n("sha256:amd64") != 1 {
		t.Errorf("platform digest matched alone after Trivy's index SBOM arrived: %d", m.n("sha256:amd64"))
	}
}

// The same package from both sources is one component, and Trivy's
// identity wins: a registry entry cannot replace Trivy's PURL, source
// package or distro, only add file paths and licences.
func TestMergeTrivyIsAuthoritative(t *testing.T) {
	tr := &types.ImageSBOM{Source: types.SourceTrivyOperator, Components: []types.Component{
		{Name: "debian", Version: "12.7", Type: "operating-system"},
		{Name: "libc6", Version: "2.36-9+deb12u10", Type: "debian", PURL: "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64",
			SrcName: "glibc", SrcVersion: "2.36-9+deb12u10", FilePaths: []string{"lib/x86_64-linux-gnu/libc.so.6"}},
	}}
	reg := &types.ImageSBOM{Source: types.SourceRegistry, Components: []types.Component{
		{Name: "debian", Version: "99", Type: "operating-system"},
		{Name: "libc6", Version: "2.36-9+deb12u10", SrcName: "nothing-here",
			PURL:      "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64&distro=debian-99&upstream=nothing-here",
			FilePaths: []string{"usr/lib/x86_64-linux-gnu/libc.so.6"}, Licenses: []string{"LGPL-2.1"}},
	}}
	out, clamped := mergeComponents([]*types.ImageSBOM{reg, tr}, 0) // order must not matter
	if clamped != 0 || len(out) != 2 {
		t.Fatalf("%d components (clamped %d): %+v", len(out), clamped, out)
	}
	if out[0].Type != "operating-system" || out[0].Version != "12.7" {
		t.Errorf("os: %+v", out[0])
	}
	l := out[1]
	if l.PURL != "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64" || l.SrcName != "glibc" || l.SrcVersion != "2.36-9+deb12u10" {
		t.Errorf("registry took over libc6's identity: %+v", l)
	}
	if len(l.FilePaths) != 2 || len(l.Licenses) != 1 {
		t.Errorf("registry file paths/licences not added: %+v", l)
	}
}

// Registry junk that sorts first must not evict Trivy's components under
// the cap, and registry SBOMs share the leftover capacity.
func TestCapNeverEvictsTrivy(t *testing.T) {
	tr := &types.ImageSBOM{Source: types.SourceTrivyOperator, Components: []types.Component{
		{Name: "openssl", Version: "3.0.11", PURL: "pkg:deb/debian/openssl@3.0.11"},
		{Name: "zlib1g", Version: "1.2.13", PURL: "pkg:deb/debian/zlib1g@1.2.13"},
	}}
	junk := &types.ImageSBOM{Source: types.SourceRegistry}
	for i := 0; i < 100; i++ {
		junk.Components = append(junk.Components, types.Component{Name: fmt.Sprintf("a%03d", i), Version: "1", PURL: fmt.Sprintf("pkg:apk/x/a%03d@1", i)})
	}
	other := &types.ImageSBOM{Source: types.SourceRegistry, Components: []types.Component{
		{Name: "express", Version: "4", PURL: "pkg:npm/express@4"}, {Name: "lodash", Version: "4", PURL: "pkg:npm/lodash@4"},
	}}
	out, dropped := mergeComponents([]*types.ImageSBOM{junk, tr, other}, 6)
	names := map[string]bool{}
	for _, c := range out {
		names[c.Name] = true
	}
	if len(out) != 6 || !names["openssl"] || !names["zlib1g"] {
		t.Fatalf("trivy evicted or cap exceeded: %d %v", len(out), names)
	}
	if !names["express"] || !names["lodash"] {
		t.Errorf("junk SBOM crowded out the other registry SBOM: %v", names)
	}
	if dropped != 98 {
		t.Errorf("dropped %d, want 98", dropped)
	}
}

// Property: whatever registry SBOMs are merged in, every Trivy component
// survives unchanged (so Trivy-only findings are a subset of the union's
// findings for any matcher that is per-package).
func TestUnionPropertyTrivyPreserved(t *testing.T) {
	tr := &types.ImageSBOM{Source: types.SourceTrivyOperator, Components: []types.Component{
		{Name: "debian", Version: "12.7", Type: "operating-system"},
		{Name: "libc6", Version: "2.36", Type: "debian", PURL: "pkg:deb/debian/libc6@2.36?arch=amd64", SrcName: "glibc", SrcVersion: "2.36"},
		{Name: "openssl", Version: "3.0.11", Type: "debian", PURL: "pkg:deb/debian/openssl@3.0.11?arch=amd64"},
		{Name: "express", Version: "4.18.2", Type: "node-pkg", PURL: "pkg:npm/express@4.18.2"},
	}}
	trivyOnly := findings(t, mustMerge([]*types.ImageSBOM{tr}, DefaultMaxComponents))
	rng := rand.New(rand.NewSource(1533))
	names := []string{"libc6", "openssl", "express", "zlib1g", "aaa", "musl"}
	versions := []string{"2.36", "3.0.11", "4.18.2", "1", "0"}
	for round := 0; round < 500; round++ {
		members := []*types.ImageSBOM{}
		nReg := 1 + rng.Intn(3)
		for r := 0; r < nReg; r++ {
			reg := &types.ImageSBOM{Source: types.SourceRegistry}
			for n := rng.Intn(40); n > 0; n-- {
				name, ver := names[rng.Intn(len(names))], versions[rng.Intn(len(versions))]
				c := types.Component{Name: name, Version: ver,
					PURL:    fmt.Sprintf("pkg:deb/debian/%s@%s?distro=debian-%d&upstream=%s", name, ver, rng.Intn(99), names[rng.Intn(len(names))]),
					SrcName: names[rng.Intn(len(names))], FilePaths: []string{fmt.Sprintf("f%d", rng.Intn(9))}}
				if rng.Intn(10) == 0 {
					c = types.Component{Name: "debian", Version: fmt.Sprint(rng.Intn(99)), Type: "operating-system"}
				}
				reg.Components = append(reg.Components, c)
			}
			members = append(members, reg)
		}
		members = append(members, tr)
		rng.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
		max := 5 + rng.Intn(30)
		union := findings(t, mustMerge(members, max))
		for f := range trivyOnly {
			if !union[f] {
				t.Fatalf("round %d (cap %d): Trivy finding %q lost in the union", round, max, f)
			}
		}
	}
}

func mustMerge(members []*types.ImageSBOM, max int) []types.Component {
	out, _ := mergeComponents(members, max)
	return out
}

// findings stands in for a per-package matcher: one finding per package
// identity as matched (name, version, PURL, source package) under the
// chosen distro.
func findings(t *testing.T, cs []types.Component) map[string]bool {
	t.Helper()
	distro := ""
	for _, c := range cs {
		if c.Type == "operating-system" {
			distro = c.Name + " " + c.Version
		}
	}
	out := map[string]bool{}
	for _, c := range cs {
		if c.Type != "operating-system" {
			out[strings.Join([]string{distro, c.Name, c.Version, c.PURL, c.SrcName, c.SrcVersion}, "|")] = true
		}
	}
	return out
}

func TestClampIsCountedAndBounded(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	met := metrics.New()
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet(), Metrics: met, MaxComponents: 3}
	start(t, c, time.Hour)
	c.Offer(trivySBOM("sha256:big", "a", "b", "c"))
	c.Offer(registrySBOM("sha256:big", "", "d", "e"))
	waitFor(t, func() bool { return testutil.ToFloat64(met.GrypeComponentsClamped) >= 1 })
	waitFor(t, func() bool { return m.n("sha256:big") >= 1 })
	if n := len(m.input("sha256:big")); n > 3 {
		t.Errorf("matcher got %d components, cap 3", n)
	}
}

func TestBoundedAndTee(t *testing.T) {
	m := &mockMatcher{}
	next := &sink{}
	c := &Coordinator{Matcher: m, Sink: &sink{}, MaxDigests: 3}
	tee := c.Tee(next)
	for _, d := range []string{"a", "b", "c", "d", "e"} {
		tee.Enqueue(trivy.Emission{Kind: trivy.KindSBOM, Digest: d, SBOM: registrySBOM("sha256:"+d, "", "p")})
	}
	tee.Enqueue(trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: "z", Vulns: &types.ImageVulnerabilities{}})
	if c.Held() != 3 {
		t.Errorf("held %d, want 3", c.Held())
	}
	if len(next.es) != 6 {
		t.Errorf("tee did not forward everything: %d", len(next.es))
	}
}
