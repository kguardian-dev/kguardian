package nodesource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
}

func (f *fakeBroker) NodeCatalogAvailable(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return f.probeErr
}

func (f *fakeBroker) RunningImages(context.Context) ([]broker.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listings++
	return append([]broker.Image(nil), f.images...), nil
}

func (f *fakeBroker) NodeSBOM(_ context.Context, digest string, max int) (*broker.NodeSBOM, error) {
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
	mu sync.Mutex
	s  []*types.ImageSBOM
}

func (o *offers) Offer(s *types.ImageSBOM) { o.mu.Lock(); o.s = append(o.s, s); o.mu.Unlock() }
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
	// Never offered before: nothing to replace.
	fb.mu.Lock()
	fb.images = []broker.Image{img("sha256:aa", "t3", "node")}
	fb.mu.Unlock()
	s.Pass(context.Background())
	if len(o.s) != 2 {
		t.Errorf("empty re-offered: %d offers", len(o.s))
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
