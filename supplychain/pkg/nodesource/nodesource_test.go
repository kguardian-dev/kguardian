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
// line, lists nothing, logs nothing more, and asks again on the backoff
// (30s, 1m, 2m, 4m, 8m, 16m, ...); when the broker gains the catalog the
// next probe resumes.
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
	// Minutes 0, 1, 2, 4, 8 and 16.
	if fb.probes != 6 || fb.listings != 0 || len(fb.fetched()) != 0 {
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

	// The broker is upgraded: the next probe (minute 32) resumes.
	fb.mu.Lock()
	fb.probeErr = nil
	fb.mu.Unlock()
	c.t = time.Unix(1, 0).Add(32 * time.Minute)
	s.Pass(context.Background())
	if s.Idle() || fb.listings != 1 || fb.fetched()["sha256:aa"] != 1 {
		t.Errorf("after upgrade: idle %v, %d listings, fetches %v", s.Idle(), fb.listings, fb.fetched())
	}
}

// supplychain rolled out before its broker: the first probe hits the old
// one (404), the upgraded broker is ready moments later, and the source is
// active at the first retry, 30s on, not an hour later.
func TestRolledBeforeBrokerResumesAtFirstRetry(t *testing.T) {
	fb := &fakeBroker{probeErr: broker.ErrNoNodeCatalog, images: []broker.Image{img("sha256:aa", "t", "node")},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}}
	log, hook := test.NewNullLogger()
	c := &clock{t: time.Unix(1, 0)}
	s := newSource(fb, &offers{}, log, nil, c)
	s.Pass(context.Background())
	if !s.Idle() || fb.probes != 1 {
		t.Fatalf("idle %v, %d probes", s.Idle(), fb.probes)
	}
	if w := s.wait(); w != 30*time.Second {
		t.Errorf("Run would wait %v, want the first retry (30s)", w)
	}
	fb.mu.Lock()
	fb.probeErr = nil // the upgraded broker is ready 18s later
	fb.mu.Unlock()
	c.t = c.t.Add(18 * time.Second)
	s.Pass(context.Background())
	if fb.probes != 1 {
		t.Fatalf("probed before the retry was due: %d probes", fb.probes)
	}
	if w := s.wait(); w != 30*time.Second {
		t.Errorf("Run would wait %v, want the IdleRetry floor (30s), not what is left (12s)", w)
	}
	c.t = c.t.Add(12 * time.Second)
	s.Pass(context.Background())
	if s.Idle() || fb.probes != 2 || fb.listings != 1 || fb.fetched()["sha256:aa"] != 1 {
		t.Errorf("at the first retry: idle %v, %d probes, %d listings, fetches %v", s.Idle(), fb.probes, fb.listings, fb.fetched())
	}
	if s.wait() != s.Interval {
		t.Errorf("active: Run would wait %v, want Interval", s.wait())
	}
	if len(hook.AllEntries()) != 2 || hook.LastEntry().Level != logrus.InfoLevel {
		t.Errorf("logs %+v", hook.AllEntries())
	}
}

// The same through Run on the real clock: with an Interval far longer than
// the first retry, Run sleeps only until the retry, so the source resumes
// long before the next Interval.
func TestRunRetriesOnTheBackoffNotTheInterval(t *testing.T) {
	fb := &fakeBroker{probeErr: broker.ErrNoNodeCatalog, images: []broker.Image{img("sha256:aa", "t", "node")},
		docs: map[string]*broker.NodeSBOM{"sha256:aa": doc("libc6")}}
	log := logrus.New()
	log.SetOutput(io.Discard)
	s := &Source{Broker: fb, Matcher: &offers{}, Log: log, Interval: time.Hour, IdleRetry: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fb.mu.Lock()
		probes := fb.probes
		if probes >= 1 {
			fb.probeErr = nil
		}
		listings := fb.listings
		fb.mu.Unlock()
		if listings == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not active within 5s: %d probes, %d listings", probes, listings)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

// A 404, then connection refused while the new broker starts: each
// transient failure schedules the next probe IdleRetry on (no doubling),
// so Run does not spin, and wait never drops below IdleRetry.
func TestTransientErrorsWhileIdleDoNotSpin(t *testing.T) {
	fb := &fakeBroker{probeErr: broker.ErrNoNodeCatalog}
	log := logrus.New()
	log.SetOutput(io.Discard)
	retry := 20 * time.Millisecond
	s := &Source{Broker: fb, Matcher: &offers{}, Log: log, Interval: time.Hour, IdleRetry: retry}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	for {
		fb.mu.Lock()
		probed := fb.probes >= 1
		if probed {
			fb.probeErr = errors.New("connection refused")
		}
		fb.mu.Unlock()
		if probed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	const run = 500 * time.Millisecond
	time.Sleep(run)
	cancel()
	<-done
	fb.mu.Lock()
	probes := fb.probes
	fb.mu.Unlock()
	// At most one probe per IdleRetry (plus the first two), and more than
	// one: it keeps retrying on the schedule.
	if limit := int(run/retry) + 2; probes > limit || probes < 3 {
		t.Errorf("%d probes in %v, want 3..%d", probes, run, limit)
	}
	if !s.Idle() {
		t.Error("a transient failure ended the idle streak")
	}

	// On the fake clock: the next probe is IdleRetry on, not doubled.
	fb2 := &fakeBroker{probeErr: broker.ErrNoNodeCatalog}
	lg, hook := test.NewNullLogger()
	c := &clock{t: time.Unix(1, 0)}
	s2 := newSource(fb2, &offers{}, lg, nil, c)
	s2.Pass(context.Background())
	c.t = c.t.Add(30 * time.Second)
	s2.Pass(context.Background()) // 404 again: backoff 1m
	fb2.mu.Lock()
	fb2.probeErr = errors.New("connection refused")
	fb2.mu.Unlock()
	c.t = c.t.Add(time.Minute)
	for range 3 {
		s2.Pass(context.Background())
		s2.mu.Lock()
		next, backoff := s2.nextProbe, s2.backoff
		s2.mu.Unlock()
		if next.Sub(c.t) != 30*time.Second || backoff != time.Minute {
			t.Fatalf("after a transient error: next in %v, backoff %v", next.Sub(c.t), backoff)
		}
		if w := s2.wait(); w != 30*time.Second {
			t.Errorf("wait %v", w)
		}
		s2.Pass(context.Background()) // not due: no probe
		c.t = next
	}
	if fb2.probes != 5 {
		t.Errorf("%d probes, want 5", fb2.probes)
	}
	// One info line for the streak, one warning for the transient streak.
	if len(hook.AllEntries()) != 2 {
		t.Errorf("logs %+v", hook.AllEntries())
	}
}

// The backoff doubles from IdleRetry to IdleRecheck and stays there; a
// probe that succeeds resets it, and the next refusal starts a new streak
// at IdleRetry with one more log line. Within a streak, one line.
func TestIdleBackoffSequenceAndReset(t *testing.T) {
	fb := &fakeBroker{probeErr: broker.ErrNoNodeCatalog}
	log, hook := test.NewNullLogger()
	c := &clock{t: time.Unix(1, 0)}
	s := newSource(fb, &offers{}, log, nil, c)
	gaps := func(n int) []time.Duration {
		var out []time.Duration
		for range n {
			s.Pass(context.Background())
			s.mu.Lock()
			next := s.nextProbe
			s.mu.Unlock()
			out = append(out, next.Sub(c.t))
			c.t = next
		}
		return out
	}
	want := []time.Duration{
		30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour,
	}
	if got := gaps(len(want)); !reflect.DeepEqual(got, want) {
		t.Fatalf("backoff %v, want %v", got, want)
	}
	if fb.probes != len(want) || len(hook.AllEntries()) != 1 {
		t.Fatalf("%d probes, %d log lines in one streak", fb.probes, len(hook.AllEntries()))
	}

	// Available: the backoff is gone.
	fb.mu.Lock()
	fb.probeErr = nil
	fb.mu.Unlock()
	s.Pass(context.Background())
	s.mu.Lock()
	backoff, next := s.backoff, s.nextProbe
	s.mu.Unlock()
	if s.Idle() || backoff != 0 || !next.IsZero() {
		t.Fatalf("after success: idle %v, backoff %v, next %v", s.Idle(), backoff, next)
	}

	// A new streak (here a refused token) starts over at IdleRetry.
	s.available = false
	fb.mu.Lock()
	fb.probeErr = &broker.StatusError{Path: "/catalog/status", StatusCode: 403}
	fb.mu.Unlock()
	logs := len(hook.AllEntries())
	if got := gaps(3); !reflect.DeepEqual(got, want[:3]) {
		t.Errorf("new streak backoff %v, want %v", got, want[:3])
	}
	if n := len(hook.AllEntries()) - logs; n != 1 || hook.LastEntry().Level != logrus.ErrorLevel {
		t.Errorf("new streak: %d log lines, last %+v", n, hook.LastEntry())
	}

	// Switching from a refused token to a missing catalog is a new streak too.
	fb.mu.Lock()
	fb.probeErr = broker.ErrNoNodeCatalog
	fb.mu.Unlock()
	logs = len(hook.AllEntries())
	if got := gaps(2); !reflect.DeepEqual(got, want[:2]) {
		t.Errorf("switched streak backoff %v, want %v", got, want[:2])
	}
	if n := len(hook.AllEntries()) - logs; n != 1 || hook.LastEntry().Level != logrus.InfoLevel {
		t.Errorf("switched streak: %d log lines", n)
	}
}

// IdleRetry defaults to 30s, or Interval when shorter, and never exceeds
// IdleRecheck.
func TestIdleRetryDefaults(t *testing.T) {
	for _, tc := range []struct {
		interval, retry, recheck, want time.Duration
	}{
		{0, 0, 0, 30 * time.Second},
		{10 * time.Second, 0, 0, 10 * time.Second},
		{0, 2 * time.Minute, 0, 2 * time.Minute},
		{0, 2 * time.Hour, 0, time.Hour},
		{0, 0, 10 * time.Second, 10 * time.Second},
	} {
		s := &Source{Interval: tc.interval, IdleRetry: tc.retry, IdleRecheck: tc.recheck}
		s.defaults()
		if s.IdleRetry != tc.want {
			t.Errorf("%+v: IdleRetry %v", tc, s.IdleRetry)
		}
	}
}

// The same through the real client against an old broker's HTTP surface:
// its /images items carry no sbomSources or nodeCatalog, and every
// catalog route answers 404. Probes on the backoff, no listing, one info
// line.
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
	// Passes every 5m: probes at 0, 5, 10, 15, 20 and 30 minutes (the next
	// is due at 46).
	if hits["/catalog/status"] != 6 || hits["/images"] != 0 || len(hits) != 1 {
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
// probes on the backoff.
func TestProbeDeniedBacksOff(t *testing.T) {
	for _, code := range []int{401, 403} {
		fb := &fakeBroker{probeErr: &broker.StatusError{Path: "/catalog/status", StatusCode: code}}
		log, hook := test.NewNullLogger()
		m := metrics.New()
		c := &clock{t: time.Unix(1, 0)}
		s := newSource(fb, &offers{}, log, m, c)
		for range 8 {
			s.Pass(context.Background())
			c.t = c.t.Add(5 * time.Minute)
		}
		// Minutes 0, 5, 10, 15, 20 and 30 (the next is due at 46).
		if fb.probes != 6 || fb.listings != 0 || !s.Ready() {
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
		if fb.probes != 7 || fb.listings != 1 || testutil.ToFloat64(m.SourceHealthy.WithLabelValues("node")) != 1 {
			t.Errorf("%d: after the fix: %d probes, %d listings", code, fb.probes, fb.listings)
		}
	}
}
