package nodesource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

type fakeBroker struct {
	mu        sync.Mutex
	probeErr  error
	images    []broker.Image
	docs      map[string]*broker.NodeSBOM
	fetchErr  map[string]error
	probes    int
	listings  int
	fetches   map[string]int
	lastLimit int
	block     chan struct{} // NodeSBOM waits on it when set
}

func (f *fakeBroker) NodeCatalogAvailable(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return f.probeErr
}

func (f *fakeBroker) Images(context.Context) ([]broker.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listings++
	return append([]broker.Image(nil), f.images...), nil
}

func (f *fakeBroker) NodeSBOM(_ context.Context, digest string, max int) (*broker.NodeSBOM, error) {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fetches == nil {
		f.fetches = map[string]int{}
	}
	f.fetches[digest]++
	f.lastLimit = max
	if err := f.fetchErr[digest]; err != nil {
		return nil, err
	}
	return f.docs[digest], nil
}

func (f *fakeBroker) fetched() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.fetches {
		out[k] = v
	}
	return out
}

type offers struct {
	mu      sync.Mutex
	s       []*types.ImageSBOM
	evicted map[string]bool
	wants   map[string]bool
}

func (o *offers) Wants(digest string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.wants[digest]
}

func (o *offers) setWants(digest string, v bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.wants == nil {
		o.wants = map[string]bool{}
	}
	o.wants[digest] = v
}

func (o *offers) Offer(s *types.ImageSBOM) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.s = append(o.s, s)
	delete(o.evicted, s.Image.Digest)
}

// Holds is true for every digest offered and not evicted since.
func (o *offers) Holds(digest, source string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if source != types.SourceNode || o.evicted[digest] {
		return false
	}
	for _, s := range o.s {
		if s.Image.Digest == digest {
			return true
		}
	}
	return false
}

func (o *offers) evict(digest string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.evicted == nil {
		o.evicted = map[string]bool{}
	}
	o.evicted[digest] = true
}

func (o *offers) n() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.s) }
func (o *offers) last() *types.ImageSBOM {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.s[len(o.s)-1]
}
func (o *offers) digests() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []string
	for _, s := range o.s {
		out = append(out, s.Image.Digest)
	}
	sort.Strings(out)
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func img(digest, catalogedAt string, sources ...string) broker.Image {
	im := broker.Image{Digest: digest, Repository: "ghcr.io/acme/api", Tags: []string{"1.2"}, RunningContainers: 1, SBOMSources: sources}
	if catalogedAt != "" {
		im.NodeCatalog = &broker.NodeCatalog{State: "done", Platform: "linux/arm64", Completeness: "full", CatalogedAt: catalogedAt}
	}
	return im
}

func doc(names ...string) *broker.NodeSBOM {
	d := &broker.NodeSBOM{Format: "CycloneDX", Trust: "scanned", ScannedAt: "2026-09-30T10:00:00.5"}
	for _, n := range names {
		d.Components = append(d.Components, types.Component{Name: n, Version: "1", PURL: "pkg:deb/debian/" + n + "@1"})
	}
	return d
}

func newSource(b Broker, o Offerer, log *logrus.Logger, m *metrics.Metrics, c *clock) *Source {
	s := &Source{Broker: b, Matcher: o, Log: log, Metrics: m}
	s.now = c.now
	return s
}

func TestFetchesOnlyNewAndChangedNodeSBOMs(t *testing.T) {
	fb := &fakeBroker{
		images: []broker.Image{
			img("sha256:aa", "2026-09-30T10:00:00Z", "node", "trivy-operator"),
			img("sha256:bb", "2026-09-30T10:00:00Z", "node"),
			img("sha256:cc", "", "registry"), // no node SBOM
			img("sha256:dd", "2026-09-30T10:00:00Z"),
		},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6"), "sha256:bb": doc("musl")},
	}
	o := &offers{}
	log, _ := test.NewNullLogger()
	m := metrics.New()
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := newSource(fb, o, log, m, c)

	s.Pass(context.Background())
	if got := o.digests(); len(got) != 2 || got[0] != "sha256:aa" || got[1] != "sha256:bb" {
		t.Fatalf("first pass offered %v", got)
	}
	if !s.Ready() || fb.lastLimit != 50000 {
		t.Errorf("ready %v, limit %d", s.Ready(), fb.lastLimit)
	}
	sb := o.s[0]
	if sb.Image.Digest != "sha256:aa" {
		sb = o.s[1]
	}
	if sb.Source != types.SourceNode || sb.Platform != "linux/arm64" || sb.SBOMTrust != types.SBOMTrustScanned ||
		sb.Image.IndexDigest != "" || sb.Image.PlatformManifests != nil || sb.Image.Registry != "ghcr.io" ||
		sb.Image.Repository != "acme/api" || sb.Image.Tag != "1.2" || sb.Scanner.Name != "kguardian-cataloger" ||
		!sb.ScannedAt.Equal(time.Date(2026, 9, 30, 10, 0, 0, 5e8, time.UTC)) {
		t.Errorf("offered %+v", sb)
	}

	// Unchanged: nothing fetched.
	s.Pass(context.Background())
	if f := fb.fetched(); f["sha256:aa"] != 1 || f["sha256:bb"] != 1 || len(f) != 2 {
		t.Fatalf("unchanged pass fetched %v", f)
	}

	// A new catalog of bb: only bb.
	fb.mu.Lock()
	fb.images[1] = img("sha256:bb", "2026-09-30T11:00:00Z", "node")
	fb.mu.Unlock()
	s.Pass(context.Background())
	if f := fb.fetched(); f["sha256:aa"] != 1 || f["sha256:bb"] != 2 {
		t.Fatalf("changed pass fetched %v", f)
	}

	// Past RecheckAfter: everything again (the coordinator may have
	// dropped it to stay within budget).
	c.t = c.t.Add(25 * time.Hour)
	s.Pass(context.Background())
	if f := fb.fetched(); f["sha256:aa"] != 2 || f["sha256:bb"] != 3 {
		t.Fatalf("recheck pass fetched %v", f)
	}
	if n := testutil.ToFloat64(m.NodeSBOMFetches.WithLabelValues("fetched")); n != 5 {
		t.Errorf("fetched counter %v", n)
	}
	if v := testutil.ToFloat64(m.SourceAvailable.WithLabelValues("node")); v != 1 {
		t.Errorf("available gauge %v", v)
	}
}

// A node SBOM that was offered and is now gone or stored empty is
// replaced by an empty one, so its packages stop being matched.
func TestEmptyNodeSBOMReplacesAnOfferedOne(t *testing.T) {
	fb := &fakeBroker{
		images: []broker.Image{img("sha256:aa", "t1", "node")},
		docs:   map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")},
	}
	o := &offers{}
	log, _ := test.NewNullLogger()
	s := newSource(fb, o, log, nil, &clock{t: time.Unix(1, 0)})
	s.Pass(context.Background())
	fb.mu.Lock()
	fb.images = []broker.Image{img("sha256:aa", "t2", "node")}
	fb.docs["sha256:aa"] = doc()
	fb.mu.Unlock()
	s.Pass(context.Background())
	if len(o.s) != 2 || len(o.s[1].Components) != 0 || o.s[1].Source != types.SourceNode {
		t.Fatalf("offers %+v", o.s)
	}
	// Never held: nothing to release, so nothing is offered.
	fb.mu.Lock()
	fb.images = append(fb.images, img("sha256:bb", "t1", "node"))
	fb.docs["sha256:bb"] = doc()
	fb.mu.Unlock()
	s.Pass(context.Background())
	if len(o.s) != 2 {
		t.Errorf("empty offered for a digest never held: %d offers", len(o.s))
	}
}

func TestFetchErrors(t *testing.T) {
	fb := &fakeBroker{
		images: []broker.Image{img("sha256:big", "t", "node"), img("sha256:moving", "t", "node"), img("sha256:flaky", "t", "node")},
		fetchErr: map[string]error{
			"sha256:big":    broker.ErrNodeSBOMTooLarge,
			"sha256:moving": broker.ErrNodeSBOMChanged,
			"sha256:flaky":  errors.New("connection reset"),
		},
	}
	log, hook := test.NewNullLogger()
	m := metrics.New()
	s := newSource(fb, &offers{}, log, m, &clock{t: time.Unix(1, 0)})
	s.Pass(context.Background())
	s.Pass(context.Background())
	f := fb.fetched()
	// Too large is not fetched again until it changes; the others are
	// retried on the next pass.
	if f["sha256:big"] != 1 || f["sha256:moving"] != 2 || f["sha256:flaky"] != 2 {
		t.Errorf("fetches %v", f)
	}
	for r, want := range map[string]float64{"too_large": 1, "changed": 2, "error": 2} {
		if got := testutil.ToFloat64(m.NodeSBOMFetches.WithLabelValues(r)); got != want {
			t.Errorf("%s: %v, want %v", r, got, want)
		}
	}
	for _, e := range hook.AllEntries() {
		if e.Level <= logrus.ErrorLevel {
			t.Errorf("error log: %s", e.Message)
		}
	}
}

// An old broker (catalog routes 404): the source idles after one info
// line, lists nothing, logs nothing more, and asks again only after
// IdleRecheck; when the broker gains the catalog it resumes.
func TestOldBrokerIdlesQuietly(t *testing.T) {
	fb := &fakeBroker{probeErr: broker.ErrNoNodeCatalog, images: []broker.Image{img("sha256:aa", "t", "node")},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}}
	log, hook := test.NewNullLogger()
	m := metrics.New()
	c := &clock{t: time.Unix(1, 0)}
	s := newSource(fb, &offers{}, log, m, c)
	for range 20 {
		s.Pass(context.Background())
		c.t = c.t.Add(time.Minute)
	}
	if fb.probes != 1 || fb.listings != 0 || len(fb.fetched()) != 0 {
		t.Fatalf("idle: %d probes, %d listings, fetches %v", fb.probes, fb.listings, fb.fetched())
	}
	if !s.Ready() || !s.Idle() {
		t.Errorf("ready %v idle %v", s.Ready(), s.Idle())
	}
	if len(hook.AllEntries()) != 1 || hook.LastEntry().Level != logrus.InfoLevel {
		t.Fatalf("logs: %+v", hook.AllEntries())
	}
	if v := testutil.ToFloat64(m.SourceAvailable.WithLabelValues("node")); v != 0 {
		t.Errorf("available gauge %v", v)
	}
	if n := testutil.CollectAndCount(m.NodeSBOMFetches); n != 0 {
		t.Errorf("fetch results counted while idle: %d", n)
	}

	// An hour on, one more probe, still quiet.
	c.t = c.t.Add(time.Hour)
	s.Pass(context.Background())
	if fb.probes != 2 || len(hook.AllEntries()) != 1 {
		t.Fatalf("recheck: %d probes, %d logs", fb.probes, len(hook.AllEntries()))
	}

	// The broker is upgraded: the next recheck resumes.
	fb.mu.Lock()
	fb.probeErr = nil
	fb.mu.Unlock()
	c.t = c.t.Add(time.Hour)
	s.Pass(context.Background())
	if s.Idle() || fb.listings != 1 || fb.fetched()["sha256:aa"] != 1 {
		t.Errorf("after upgrade: idle %v, %d listings, fetches %v", s.Idle(), fb.listings, fb.fetched())
	}
}

// The same through the real client against an old broker's HTTP surface:
// its /images items carry no sbomSources or nodeCatalog, and every
// catalog route answers 404. One probe, no listing, one info line.
func TestOldBrokerOverHTTP(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/images" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items":     []map[string]interface{}{{"digest": "sha256:aa", "repository": "x", "tags": []string{}, "digestKind": "repo", "runningContainers": 1}},
				"nextAfter": nil,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rc, err := broker.NewReadClient(srv.URL, "sc")
	if err != nil {
		t.Fatal(err)
	}
	log, hook := test.NewNullLogger()
	c := &clock{t: time.Unix(1, 0)}
	s := newSource(rc, &offers{}, log, nil, c)
	for range 10 {
		s.Pass(context.Background())
		c.t = c.t.Add(5 * time.Minute)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/catalog/status"] != 1 || hits["/images"] != 0 || len(hits) != 1 {
		t.Errorf("requests %v", hits)
	}
	if len(hook.AllEntries()) != 1 || hook.LastEntry().Level != logrus.InfoLevel {
		t.Errorf("logs %+v", hook.AllEntries())
	}
}

// A transient probe failure is not idling: it warns once per streak and
// tries again on the next pass.
func TestProbeErrorRetriesNextPass(t *testing.T) {
	fb := &fakeBroker{probeErr: errors.New("connection refused")}
	log, hook := test.NewNullLogger()
	s := newSource(fb, &offers{}, log, nil, &clock{t: time.Unix(1, 0)})
	for range 3 {
		s.Pass(context.Background())
	}
	if fb.probes != 3 || s.Idle() || len(hook.AllEntries()) != 1 || hook.LastEntry().Level != logrus.WarnLevel {
		t.Errorf("%d probes, idle %v, logs %+v", fb.probes, s.Idle(), hook.AllEntries())
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	fb := &fakeBroker{probeErr: broker.ErrNoNodeCatalog}
	log := logrus.New()
	log.SetOutput(io.Discard)
	s := &Source{Broker: fb, Matcher: &offers{}, Log: log, Interval: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

// Readiness does not wait for the fetches: a fresh pod with many node
// SBOMs due must pass /readyz as soon as the inventory is listed.
func TestReadyBeforeFetchesFinish(t *testing.T) {
	fb := &fakeBroker{images: []broker.Image{img("sha256:aa", "t", "node")},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}, block: make(chan struct{})}
	log, _ := test.NewNullLogger()
	s := newSource(fb, &offers{}, log, nil, &clock{t: time.Unix(1, 0)})
	done := make(chan struct{})
	go func() { s.Pass(context.Background()); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !s.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("not ready while a fetch is blocked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("pass finished although the fetch is blocked")
	default:
	}
	close(fb.block)
	<-done
}

// An evicted node SBOM is offered again only while the coordinator Wants
// it (its group waits for it), and then at most once per backoff window,
// doubling from Interval up to RecheckAfter; the backoff resets once it
// is no longer wanted.
func TestReoffersOnlyWhatTheCoordinatorWants(t *testing.T) {
	fb := &fakeBroker{images: []broker.Image{img("sha256:aa", "t", "node")},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}}
	o := &offers{}
	log, _ := test.NewNullLogger()
	m := metrics.New()
	c := &clock{t: time.Unix(1, 0)}
	s := newSource(fb, o, log, m, c)
	s.Pass(context.Background())
	o.evict("sha256:aa")
	s.Pass(context.Background())
	if fb.fetched()["sha256:aa"] != 1 {
		t.Fatal("evicted but not wanted, yet fetched again")
	}
	o.setWants("sha256:aa", true)
	var at []int // passes (a minute apart) that fetched
	for minute := 0; minute < 40; minute++ {
		before := fb.fetched()["sha256:aa"]
		s.Pass(context.Background())
		if fb.fetched()["sha256:aa"] > before {
			at = append(at, minute)
		}
		c.t = c.t.Add(time.Minute)
	}
	if !reflect.DeepEqual(at, []int{0, 5, 15, 35}) {
		t.Errorf("wanted re-offers at minutes %v, want 0, 5, 15, 35 (backoff 5m doubling)", at)
	}
	if got := testutil.ToFloat64(m.NodeSBOMFetches.WithLabelValues("wanted")); got != 4 {
		t.Errorf("wanted counter %v", got)
	}
	o.setWants("sha256:aa", false)
	s.Pass(context.Background())
	o.setWants("sha256:aa", true)
	before := fb.fetched()["sha256:aa"]
	s.Pass(context.Background())
	if fb.fetched()["sha256:aa"] != before+1 {
		t.Error("backoff not reset after the SBOM stopped being wanted")
	}
}

// An SBOM that grows past the limit after a smaller one was offered
// replaces it with an empty one, and a later empty SBOM is still offered.
func TestTooLargeAfterAnOfferReleasesIt(t *testing.T) {
	fb := &fakeBroker{images: []broker.Image{img("sha256:aa", "t1", "node")},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}, fetchErr: map[string]error{}}
	o := &offers{}
	log, _ := test.NewNullLogger()
	s := newSource(fb, o, log, nil, &clock{t: time.Unix(1, 0)})
	s.Pass(context.Background())
	fb.mu.Lock()
	fb.images = []broker.Image{img("sha256:aa", "t2", "node")}
	fb.fetchErr["sha256:aa"] = broker.ErrNodeSBOMTooLarge
	fb.mu.Unlock()
	s.Pass(context.Background())
	if o.n() != 2 || len(o.last().Components) != 0 {
		t.Fatalf("too large: %d offers, last %+v", o.n(), o.last())
	}
	fb.mu.Lock()
	fb.images = []broker.Image{img("sha256:aa", "t3", "node")}
	delete(fb.fetchErr, "sha256:aa")
	fb.docs["sha256:aa"] = doc()
	fb.mu.Unlock()
	s.Pass(context.Background())
	if o.n() != 3 || len(o.last().Components) != 0 {
		t.Errorf("empty after too large: %d offers", o.n())
	}
}

// A node SBOM deleted while the digest is still in the inventory is
// released (only if the coordinator holds one). A digest that merely stops
// running, like a CronJob between runs, is left alone: no release, and no
// new fetch when it runs again unchanged. One that leaves the inventory is
// forgotten without a release.
func TestReleasesOnlyOnDeletion(t *testing.T) {
	running := img("sha256:aa", "t1", "node")
	stopped := running
	stopped.RunningContainers = 0
	deleted := img("sha256:aa", "t1", "registry")
	deleted.NodeCatalog = nil
	for _, tc := range []struct {
		name     string
		steps    [][]broker.Image
		releases int
		fetches  int
	}{
		{"cronjob", [][]broker.Image{{stopped}, {stopped}, {running}}, 0, 1},
		{"deleted", [][]broker.Image{{deleted}, {deleted}}, 1, 1},
		{"deleted while stopped", [][]broker.Image{{stopped}, {func() broker.Image { d := deleted; d.RunningContainers = 0; return d }()}}, 1, 1},
		{"left the inventory", [][]broker.Image{{}}, 0, 1},
	} {
		fb := &fakeBroker{images: []broker.Image{running}, docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}}
		o := &offers{}
		log, _ := test.NewNullLogger()
		m := metrics.New()
		s := newSource(fb, o, log, m, &clock{t: time.Unix(1, 0)})
		s.Pass(context.Background())
		for _, step := range tc.steps {
			fb.mu.Lock()
			fb.images = step
			fb.mu.Unlock()
			s.Pass(context.Background())
		}
		releases := 0
		for _, sb := range o.s {
			if len(sb.Components) == 0 {
				releases++
			}
		}
		if releases != tc.releases || fb.fetched()["sha256:aa"] != tc.fetches ||
			testutil.ToFloat64(m.NodeSBOMFetches.WithLabelValues("released")) != float64(tc.releases) {
			t.Errorf("%s: %d releases, %d fetches; want %d, %d", tc.name, releases, fb.fetched()["sha256:aa"], tc.releases, tc.fetches)
		}
	}
	// Deleted, but the coordinator holds none (evicted): nothing offered.
	fb := &fakeBroker{images: []broker.Image{running}, docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}}
	o := &offers{}
	log, _ := test.NewNullLogger()
	s := newSource(fb, o, log, nil, &clock{t: time.Unix(1, 0)})
	s.Pass(context.Background())
	o.evict("sha256:aa")
	fb.mu.Lock()
	fb.images = []broker.Image{deleted}
	fb.mu.Unlock()
	s.Pass(context.Background())
	if o.n() != 1 {
		t.Errorf("released an evicted SBOM: %d offers", o.n())
	}
}

// A token the broker refuses: one error line, the health gauge at 0, and
// no more probes until IdleRecheck.
func TestProbeDeniedBacksOff(t *testing.T) {
	for _, code := range []int{401, 403} {
		fb := &fakeBroker{probeErr: &broker.StatusError{Path: "/catalog/status", StatusCode: code}}
		log, hook := test.NewNullLogger()
		m := metrics.New()
		c := &clock{t: time.Unix(1, 0)}
		s := newSource(fb, &offers{}, log, m, c)
		for range 5 {
			s.Pass(context.Background())
			c.t = c.t.Add(5 * time.Minute)
		}
		if fb.probes != 1 || fb.listings != 0 || !s.Ready() {
			t.Fatalf("%d: %d probes, %d listings", code, fb.probes, fb.listings)
		}
		if len(hook.AllEntries()) != 1 || hook.LastEntry().Level != logrus.ErrorLevel {
			t.Fatalf("%d: logs %+v", code, hook.AllEntries())
		}
		if v := testutil.ToFloat64(m.SourceHealthy.WithLabelValues("node")); v != 0 {
			t.Errorf("%d: healthy gauge %v", code, v)
		}
		c.t = c.t.Add(time.Hour)
		fb.mu.Lock()
		fb.probeErr = nil
		fb.mu.Unlock()
		s.Pass(context.Background())
		if fb.probes != 2 || fb.listings != 1 || testutil.ToFloat64(m.SourceHealthy.WithLabelValues("node")) != 1 {
			t.Errorf("%d: after the fix: %d probes, %d listings", code, fb.probes, fb.listings)
		}
	}
}
