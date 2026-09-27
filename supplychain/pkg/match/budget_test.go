package match

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fatSBOM is shaped like a Debian-based Python image with a registry SBOM
// that lists files (open-webui:0.11.3's kind): linux-libc-dev with ~900
// headers, 450 more debs and 800 Python packages. It is decoded from JSON
// as the sources do, so every string is its own allocation.
func fatSBOM(t testing.TB, digest string) *types.ImageSBOM {
	t.Helper()
	fatOnce.Do(func() { fatTemplate = buildFat() })
	return cloneSBOM(&fatTemplate, digest, len(fatTemplate.Components))
}

// smallSBOM is the first 100 components of fatSBOM: the same shape, for
// tests of eviction behaviour rather than of the heap, and cheap to
// fingerprint under -race.
func smallSBOM(t testing.TB, digest string) *types.ImageSBOM {
	t.Helper()
	fatOnce.Do(func() { fatTemplate = buildFat() })
	return cloneSBOM(&fatTemplate, digest, 100)
}

// cloneSBOM copies the first n components with every string its own
// allocation, as decoding the JSON does.
func cloneSBOM(src *types.ImageSBOM, digest string, n int) *types.ImageSBOM {
	out := &types.ImageSBOM{Image: types.ImageRef{Digest: digest}, Source: src.Source, SBOMTrust: src.SBOMTrust,
		Components: make([]types.Component, n)}
	cl := func(ss []string) []string {
		if ss == nil {
			return nil
		}
		o := make([]string, len(ss))
		for i, x := range ss {
			o[i] = strings.Clone(x)
		}
		return o
	}
	for i, c := range src.Components[:n] {
		out.Components[i] = types.Component{Name: strings.Clone(c.Name), Version: strings.Clone(c.Version),
			PURL: strings.Clone(c.PURL), Type: strings.Clone(c.Type), Licenses: cl(c.Licenses), FilePaths: cl(c.FilePaths)}
	}
	return out
}

var (
	fatOnce     sync.Once
	fatTemplate types.ImageSBOM
)

// decodedSBOM decodes the fat template (without file paths when noFiles)
// from JSON, exactly as a source builds an SBOM: what the estimate is
// calibrated against.
func decodedSBOM(t testing.TB, digest string, noFiles bool) *types.ImageSBOM {
	t.Helper()
	var out types.ImageSBOM
	if err := json.Unmarshal(templateJSON(t, noFiles), &out); err != nil {
		t.Fatal(err)
	}
	out.Image.Digest = digest
	return &out
}

var (
	jsonOnce           sync.Once
	fatJSON, trivyJSON []byte
)

func templateJSON(t testing.TB, noFiles bool) []byte {
	jsonOnce.Do(func() {
		fatOnce.Do(func() { fatTemplate = buildFat() })
		src := fatTemplate
		fatJSON, _ = json.Marshal(src)
		src.Components = slices.Clone(src.Components)
		for i := range src.Components {
			src.Components[i].FilePaths = nil
		}
		trivyJSON, _ = json.Marshal(src)
	})
	if len(fatJSON) == 0 || len(trivyJSON) == 0 {
		t.Fatal("template JSON")
	}
	if noFiles {
		return trivyJSON
	}
	return fatJSON
}

func buildFat() types.ImageSBOM {
	s := types.ImageSBOM{Source: types.SourceRegistry, SBOMTrust: types.SBOMTrustUnverified}
	add := func(name, typ, purl string, files int, dir string) {
		c := types.Component{Name: name, Version: "1.2.3-4", Type: typ, PURL: purl, Licenses: []string{"MIT"}}
		for i := range files {
			c.FilePaths = append(c.FilePaths, fmt.Sprintf("%s/%s/file-%04d.h", dir, name, i))
		}
		s.Components = append(s.Components, c)
	}
	add("linux-libc-dev", "deb", "pkg:deb/debian/linux-libc-dev@6.1.180-1?arch=amd64&distro=debian-12", 907, "usr/include/linux")
	for i := range 450 {
		n := fmt.Sprintf("libdeb%03d", i)
		add(n, "deb", "pkg:deb/debian/"+n+"@1.2.3-4?arch=amd64&distro=debian-12", 40, "usr/lib/x86_64-linux-gnu")
	}
	for i := range 800 {
		n := fmt.Sprintf("pypkg%03d", i)
		add(n, "python", "pkg:pypi/"+n+"@1.2.3", 25, "usr/local/lib/python3.12/site-packages")
	}
	return s
}

func heapInuse() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// The estimate is what the budget counts, so it has to follow the heap,
// for a registry SBOM that lists files and for a Trivy one that does not.
func TestHeldBytesTracksTheHeap(t *testing.T) {
	templateJSON(t, false) // built before the first measurement
	for _, shape := range []struct {
		name    string
		noFiles bool
		n       int
	}{
		{"registry, with files", false, 8}, // ~26 MiB
		{"trivy, no files", true, 64},      // ~20 MiB: enough that GC noise does not decide the ratio
	} {
		before := heapInuse()
		keep := make([]*types.ImageSBOM, shape.n)
		var est int64
		for i := range keep {
			keep[i] = decodedSBOM(t, fmt.Sprintf("sha256:%d", i), shape.noFiles)
			est += heldBytes(keep[i])
		}
		after := heapInuse()
		runtime.KeepAlive(keep)
		real := int64(after - before)
		ratio := float64(real) / float64(est)
		t.Logf("%s: %d SBOMs x %d components: estimate %.1f MiB, heap %.1f MiB (heap/estimate %.2f)",
			shape.name, shape.n, len(keep[0].Components), float64(est)/(1<<20), float64(real)/(1<<20), ratio)
		if ratio < 0.8 || ratio > 1.25 {
			t.Errorf("%s: heap/estimate %.2f outside 0.8-1.25", shape.name, ratio)
		}
	}
}

// budgetCoord is a coordinator with a loaded database whose byte budget
// holds room fat SBOMs and a half.
func budgetCoord(t *testing.T, m Matcher, room int64) (*Coordinator, *metrics.Metrics, int64) {
	return budgetCoordOf(t, m, room, fatSBOM)
}

// budgetCoordOf sizes the budget in units of mk's SBOM.
func budgetCoordOf(t *testing.T, m Matcher, room int64, mk func(testing.TB, string) *types.ImageSBOM) (*Coordinator, *metrics.Metrics, int64) {
	t.Helper()
	c, mt := newCoord(m, "")
	one := heldBytes(mk(t, "sha256:probe"))
	if room > 0 {
		c.MaxHeldBytes = room*one + one/2
	}
	return c, mt, one
}

func fatDigest(i int) string { return fmt.Sprintf("sha256:%02d", i) }

// leanMatcher only counts, and discard drops emissions, so heap
// measurements see what the coordinator holds and nothing the test does.
type leanMatcher struct {
	mu    sync.Mutex
	calls map[string]int
}

func (m *leanMatcher) Match(_ context.Context, s *types.ImageSBOM) ([]types.Vulnerability, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls == nil {
		m.calls = map[string]int{}
	}
	m.calls[s.Image.Digest]++
	return nil, nil
}
func (m *leanMatcher) DB() DBInfo             { return DBInfo{Built: time.Unix(100, 0)} }
func (m *leanMatcher) Scanner() types.Scanner { return types.Scanner{Name: "grype"} }

type discard struct{}

func (discard) Enqueue(trivy.Emission) {}

func leanCoord(t *testing.T) (*Coordinator, *metrics.Metrics, *leanMatcher) {
	m := &leanMatcher{}
	c, mt := newCoord(m, "")
	c.Sink = discard{}
	return c, mt, m
}

// Past the byte budget the least recently offered matched groups lose
// their SBOMs, and what is held stays within it, on the heap too.
func TestByteBudgetEvictsLeastRecentlyOffered(t *testing.T) {
	c, mt, m := leanCoord(t)
	one := heldBytes(fatSBOM(t, "sha256:probe"))
	c.MaxHeldBytes = 3*one + one/2
	before := heapInuse()
	for i := range 10 {
		c.Offer(fatSBOM(t, fatDigest(i)))
		pass(c)
	}
	after := heapInuse()
	if c.Held() != 3 {
		t.Fatalf("held %d, want 3", c.Held())
	}
	for i := 7; i < 10; i++ {
		if _, ok := c.sboms[fatDigest(i)]; !ok {
			t.Errorf("%s (most recent) evicted", fatDigest(i))
		}
	}
	if c.heldBytes != 3*one || testutil.ToFloat64(mt.GrypeSBOMBytesHeld) != float64(3*one) {
		t.Errorf("held bytes %d (gauge %v), want %d", c.heldBytes, testutil.ToFloat64(mt.GrypeSBOMBytesHeld), 3*one)
	}
	if v := testutil.ToFloat64(mt.GrypeSBOMsEvicted.WithLabelValues("bytes")); v != 7 {
		t.Errorf("evicted(bytes) = %v, want 7", v)
	}
	for i := range 10 {
		if m.calls[fatDigest(i)] != 1 {
			t.Errorf("%s matched %d times", fatDigest(i), m.calls[fatDigest(i)])
		}
		if gs := c.groups[fatDigest(i)]; gs == nil || gs.fingerprint == "" {
			t.Errorf("%s: match state dropped with its SBOM", fatDigest(i))
		}
	}
	if real := int64(after) - int64(before); real > c.MaxHeldBytes*125/100 {
		t.Errorf("heap grew %.1f MiB holding a %.1f MiB budget", float64(real)/(1<<20), float64(c.MaxHeldBytes)/(1<<20))
	}
	runtime.KeepAlive(c)
}

// An evicted digest re-offered unchanged is not matched again: its match
// state outlives its SBOM. Neither one at a time nor in a burst.
func TestEvictedUnchangedReofferIsNotMatchedAgain(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	c, _, _ := budgetCoordOf(t, m, 3, smallSBOM)
	for i := range 10 {
		c.Offer(smallSBOM(t, fatDigest(i)))
		pass(c)
	}
	for i := range 10 { // a source pass re-offering everything, drained as it goes
		c.Offer(smallSBOM(t, fatDigest(i)))
		pass(c)
	}
	for i := range 10 { // and all at once
		c.Offer(smallSBOM(t, fatDigest(i)))
	}
	pass(c)
	for i := range 10 {
		if n := m.n(fatDigest(i)); n != 1 {
			t.Errorf("%s matched %d times, want 1", fatDigest(i), n)
		}
	}
	if c.heldBytes > c.MaxHeldBytes {
		t.Errorf("over budget after draining: %d > %d", c.heldBytes, c.MaxHeldBytes)
	}
	// A changed SBOM is matched again, of course.
	s := smallSBOM(t, fatDigest(0))
	s.Components = s.Components[1:]
	c.Offer(s)
	pass(c)
	if m.n(fatDigest(0)) != 2 {
		t.Errorf("changed SBOM not re-matched: %d", m.n(fatDigest(0)))
	}
}

// Offers made before the database loads all wait (over budget) and are
// all matched once it does; only then is the set cut back to the budget.
func TestOffersBeforeTheDBLoadsAreAllMatched(t *testing.T) {
	m := &mockMatcher{}
	c, _, one := budgetCoord(t, m, 0) // the default 96 MiB
	for i := range 40 {
		c.Offer(fatSBOM(t, fatDigest(i)))
	}
	pass(c) // no database yet
	if c.Held() != 40 || c.heldBytes != 40*one {
		t.Fatalf("before the DB: held %d (%d bytes); nothing may be dropped unmatched", c.Held(), c.heldBytes)
	}
	m.setBuilt(time.Unix(100, 0))
	pass(c)
	for i := range 40 {
		if n := m.n(fatDigest(i)); n != 1 {
			t.Errorf("%s matched %d times, want 1", fatDigest(i), n)
		}
	}
	if c.heldBytes > c.MaxHeldBytes || c.Held() >= 40 {
		t.Errorf("after matching: held %d, %d bytes (budget %d)", c.Held(), c.heldBytes, c.MaxHeldBytes)
	}
}

// tooLargeFor answers ErrTooLarge for one digest and matches the rest.
type tooLargeFor struct {
	mockMatcher
	digest string
}

func (m *tooLargeFor) Match(ctx context.Context, s *types.ImageSBOM) ([]types.Vulnerability, error) {
	v, _ := m.mockMatcher.Match(ctx, s)
	if s.Image.Digest == m.digest {
		return nil, fmt.Errorf("%w: matcher response exceeds 64 MiB", ErrTooLarge)
	}
	return v, nil
}

// A too-large quarantine survives its SBOM being evicted and re-offered.
func TestTooLargeQuarantineSurvivesEviction(t *testing.T) {
	m := &tooLargeFor{mockMatcher: mockMatcher{built: time.Unix(100, 0)}, digest: fatDigest(0)}
	c, mt, _ := budgetCoordOf(t, m, 2, smallSBOM)
	c.Offer(smallSBOM(t, fatDigest(0)))
	pass(c)
	for i := 1; i < 5; i++ {
		c.Offer(smallSBOM(t, fatDigest(i)))
		pass(c)
	}
	if _, held := c.sboms[fatDigest(0)]; held {
		t.Fatal("quarantined digest not evicted; the test proves nothing")
	}
	for range 3 {
		c.Offer(smallSBOM(t, fatDigest(0)))
		pass(c)
		tick(c)
	}
	if n := m.n(fatDigest(0)); n != 1 || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("matcher hit %d times, quarantined %v", n, testutil.ToFloat64(mt.GrypeQuarantined))
	}
}

// A crash quarantine survives too: no more deaths for the same input.
func TestCrashQuarantineSurvivesEviction(t *testing.T) {
	dir := t.TempDir()
	s := trivySBOM("sha256:crash", "linux-libc-dev")
	for range 2 { // two deaths leave two markers
		f := &failMatcher{built: time.Unix(100, 0), panics: true}
		c, _ := newCoord(f, dir)
		c.Offer(s)
		if !crashPass(c) {
			t.Fatal("did not crash")
		}
	}
	f := &failMatcher{built: time.Unix(100, 0)}
	c, mt := newCoord(f, dir)
	c.MaxHeldBytes = heldBytes(s) * 3 / 2
	c.Offer(s)
	pass(c)
	if f.n() != 0 || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("not crash-quarantined: calls %d", f.n())
	}
	c.Offer(trivySBOM("sha256:other", "linux-libc-dev"))
	pass(c)
	if _, held := c.sboms["sha256:crash"]; held {
		t.Fatal("quarantined digest not evicted; the test proves nothing")
	}
	f.mu.Lock()
	f.panics = true // it would die again if tried
	f.mu.Unlock()
	for range 3 {
		c.Offer(trivySBOM("sha256:crash", "linux-libc-dev"))
		if crashPass(c) {
			t.Fatal("crash-quarantined input matched again after eviction")
		}
	}
}

// Match state is bounded too: past MaxDigests groups whose SBOMs are gone
// are pruned, oldest first.
func TestGroupStateIsBounded(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	c, _ := newCoord(m, "")
	c.MaxDigests = 3
	now := time.Unix(1000, 0)
	c.now = func() time.Time { now = now.Add(time.Second); return now }
	for i := range 8 {
		c.Offer(trivySBOM(fatDigest(i), "openssl"))
		pass(c)
	}
	if len(c.groups) > 3 || c.Held() > 3 {
		t.Fatalf("groups %d, held %d", len(c.groups), c.Held())
	}
	if _, ok := c.groups[fatDigest(7)]; !ok {
		t.Error("newest group pruned")
	}
}

// Re-offering the same (digest, source) replaces it; it is not counted twice.
func TestReofferIsNotCountedTwice(t *testing.T) {
	c, _ := newCoord(&mockMatcher{}, "")
	s := fatSBOM(t, "sha256:a")
	for range 5 {
		c.Offer(s)
	}
	c.Offer(trivySBOM("sha256:a", "openssl"))
	if want := heldBytes(s) + heldBytes(trivySBOM("sha256:a", "openssl")); c.heldBytes != want || c.Held() != 1 {
		t.Fatalf("held bytes %d, want %d (held %d)", c.heldBytes, want, c.Held())
	}
}

// One SBOM bigger than the whole budget is still matched: it is held
// alone once the rest are matched.
func TestOversizedSBOMIsHeldAlone(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	c, _ := newCoord(m, "")
	c.Offer(trivySBOM("sha256:small", "openssl"))
	pass(c)
	big := fatSBOM(t, "sha256:big")
	c.MaxHeldBytes = heldBytes(big) / 2
	c.Offer(big)
	if c.Held() != 1 || c.heldBytes != heldBytes(big) {
		t.Fatalf("held %d, bytes %d", c.Held(), c.heldBytes)
	}
	pass(c)
	if m.n("sha256:big") != 1 {
		t.Error("oversized SBOM not matched")
	}
}

// The default budget, measured: how many fat SBOMs it holds and what the
// heap actually is at the cap.
func TestDefaultBudgetOnTheHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~100 MiB")
	}
	c, mt, _ := leanCoord(t)
	templateJSON(t, false)
	before := heapInuse()
	for i := range 40 {
		c.Offer(decodedSBOM(t, fatDigest(i), false))
		pass(c)
	}
	after := heapInuse()
	real := int64(after) - int64(before)
	t.Logf("default %d MiB budget: %d of 40 fat SBOMs held, estimate %.1f MiB, heap %.1f MiB, evicted %v",
		DefaultMaxHeldBytes>>20, c.Held(), float64(c.heldBytes)/(1<<20), float64(real)/(1<<20),
		testutil.ToFloat64(mt.GrypeSBOMsEvicted.WithLabelValues("bytes")))
	if c.heldBytes > DefaultMaxHeldBytes || real > DefaultMaxHeldBytes*115/100 {
		t.Errorf("over budget: estimate %d, heap %d", c.heldBytes, real)
	}
	runtime.KeepAlive(c)
}

// A changed SBOM waiting in the queue is never dropped, even though its
// group was matched at this database before: the change must be matched.
func TestQueuedChangeIsNotEvicted(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	c, _, _ := budgetCoordOf(t, m, 3, smallSBOM)
	for i := range 3 {
		c.Offer(smallSBOM(t, fatDigest(i)))
		pass(c)
	}
	changed := smallSBOM(t, fatDigest(0))
	changed.Components = changed.Components[1:]
	c.Offer(changed) // queued, not yet drained
	for i := 3; i < 6; i++ {
		c.Offer(smallSBOM(t, fatDigest(i)))
	}
	pass(c)
	if n := m.n(fatDigest(0)); n != 2 {
		t.Fatalf("changed SBOM matched %d times, want 2 (it was dropped before its match)", n)
	}
}
