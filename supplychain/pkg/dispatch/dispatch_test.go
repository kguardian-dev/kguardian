package dispatch

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

// fakeClient answers per digest: failures[digest] is a list of errors
// returned on successive calls before succeeding.
type fakeClient struct {
	mu       sync.Mutex
	failures map[string][]error
	sent     []*types.ImageVulnerabilities
	sboms    []*types.ImageSBOM
	calls    map[string]int
	block    chan struct{}
	entered  chan struct{}
}

func newFake() *fakeClient {
	return &fakeClient{failures: map[string][]error{}, calls: map[string]int{}}
}

func (f *fakeClient) SubmitVulnerabilities(_ context.Context, p *types.ImageVulnerabilities) error {
	if f.entered != nil {
		f.entered <- struct{}{}
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[p.Image.Digest]++
	if errs := f.failures[p.Image.Digest]; len(errs) > 0 {
		f.failures[p.Image.Digest] = errs[1:]
		return errs[0]
	}
	f.sent = append(f.sent, p)
	return nil
}

func (f *fakeClient) SubmitSBOM(_ context.Context, p *types.ImageSBOM) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sboms = append(f.sboms, p)
	return nil
}

func (f *fakeClient) sentDigests() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for _, p := range f.sent {
		out[p.Image.Digest] = p.Scanner.Version
	}
	return out
}

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func vulnEmission(digest, marker string) trivy.Emission {
	return trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: digest,
		Vulns: &types.ImageVulnerabilities{Image: types.ImageRef{Digest: digest}, Scanner: types.Scanner{Version: marker}}}
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

func fast(d *Dispatcher) {
	d.MinBackoff, d.MaxBackoff = time.Millisecond, 4*time.Millisecond
}

func run(t *testing.T, d *Dispatcher) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.Run(ctx)
}

func TestCoalescesPerKey(t *testing.T) {
	c := newFake()
	d := New(c, quiet(), nil)
	d.Enqueue(vulnEmission("a", "1"))
	d.Enqueue(vulnEmission("b", "1"))
	d.Enqueue(vulnEmission("a", "2"))
	d.Enqueue(trivy.Emission{Kind: trivy.KindSBOM, Digest: "a", SBOM: &types.ImageSBOM{}})
	if d.Pending() != 3 {
		t.Fatalf("pending = %d, want 3 (a/vulns, b/vulns, a/sbom)", d.Pending())
	}
	run(t, d)
	waitFor(t, func() bool { return len(c.sentDigests()) == 2 && d.Pending() == 0 })
	if got := c.sentDigests(); got["a"] != "2" {
		t.Errorf("sent %v; the latest payload for a must win", got)
	}
	if c.calls["a"] != 1 {
		t.Errorf("a sent %d times", c.calls["a"])
	}
}

// One permanently rejected payload must not block any other digest.
func TestNonRetryableIsDroppedAndDoesNotBlock(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 413, 422} {
		c := newFake()
		c.failures["bad"] = []error{&broker.StatusError{StatusCode: code}}
		m := metrics.New()
		d := New(c, quiet(), m)
		fast(d)
		d.Enqueue(vulnEmission("bad", "x"))
		for _, g := range []string{"g1", "g2", "g3", "g4", "g5"} {
			d.Enqueue(vulnEmission(g, "x"))
		}
		run(t, d)
		waitFor(t, func() bool { return len(c.sentDigests()) == 5 && d.Pending() == 0 })
		if c.calls["bad"] != 1 {
			t.Errorf("%d: rejected payload retried %d times", code, c.calls["bad"])
		}
		reason := broker.Reason(&broker.StatusError{StatusCode: code})
		if v := testutil.ToFloat64(m.Dropped.WithLabelValues("vulnerabilities", reason)); v != 1 {
			t.Errorf("%d: dropped{%s} = %v", code, reason, v)
		}
		if v := testutil.ToFloat64(m.Emissions.WithLabelValues("vulnerabilities", "dropped")); v != 1 {
			t.Errorf("%d: emissions{dropped} = %v", code, v)
		}
	}
}

func TestOversizedPayloadIsDropped(t *testing.T) {
	c := newFake()
	c.failures["huge"] = []error{broker.ErrPayloadTooLarge}
	m := metrics.New()
	d := New(c, quiet(), m)
	d.Enqueue(vulnEmission("huge", "x"))
	d.Enqueue(vulnEmission("ok", "x"))
	run(t, d)
	waitFor(t, func() bool { return len(c.sentDigests()) == 1 && d.Pending() == 0 })
	if v := testutil.ToFloat64(m.Dropped.WithLabelValues("vulnerabilities", "too_large")); v != 1 {
		t.Errorf("dropped{too_large} = %v", v)
	}
}

// A retryable failure backs off on its own key while the rest drain.
func TestRetryableBacksOffPerKeyWhileOthersDrain(t *testing.T) {
	for _, err := range []error{
		&broker.StatusError{StatusCode: http.StatusServiceUnavailable},
		&broker.StatusError{StatusCode: http.StatusTooManyRequests},
		&broker.StatusError{StatusCode: http.StatusRequestTimeout},
		io.ErrUnexpectedEOF, // network
	} {
		c := newFake()
		c.failures["flaky"] = []error{err, err, err}
		m := metrics.New()
		d := New(c, quiet(), m)
		d.MinBackoff, d.MaxBackoff = 50*time.Millisecond, 50*time.Millisecond
		d.jitter = func(x time.Duration) time.Duration { return x }
		d.Enqueue(vulnEmission("flaky", "x"))
		for _, g := range []string{"g1", "g2", "g3"} {
			d.Enqueue(vulnEmission(g, "x"))
		}
		run(t, d)
		// The healthy keys go out before flaky's first backoff expires.
		waitFor(t, func() bool { return len(c.sentDigests()) >= 3 })
		if _, ok := c.sentDigests()["flaky"]; ok {
			t.Errorf("%v: flaky sent before its backoff", err)
		}
		waitFor(t, func() bool { _, ok := c.sentDigests()["flaky"]; return ok })
		if c.calls["flaky"] != 4 {
			t.Errorf("%v: flaky called %d times, want 4", err, c.calls["flaky"])
		}
		if v := testutil.ToFloat64(m.Emissions.WithLabelValues("vulnerabilities", "retry")); v != 3 {
			t.Errorf("%v: retry count %v", err, v)
		}
		if v := testutil.ToFloat64(m.Dropped.WithLabelValues("vulnerabilities", broker.Reason(err))); v != 0 {
			t.Errorf("%v: retryable error was dropped", err)
		}
	}
}

func TestBackoffIsExponentialAndCapped(t *testing.T) {
	d := New(newFake(), quiet(), nil)
	d.MinBackoff, d.MaxBackoff = time.Second, 5*time.Second
	now := time.Unix(1000, 0)
	d.now = func() time.Time { return now }
	d.jitter = func(x time.Duration) time.Duration { return x }
	d.Enqueue(vulnEmission("a", "x"))
	k, it, _ := d.nextDue()
	var got []time.Duration
	for i := 0; i < 5; i++ {
		d.finish(k, it, io.ErrUnexpectedEOF)
		got = append(got, d.pending[k].notBefore.Sub(now))
		// Pop it again as if due.
		d.pending[k].notBefore = now
		k, it, _ = d.nextDue()
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoffs %v, want %v", got, want)
		}
	}
}

func TestJitterStaysWithinHalfToFull(t *testing.T) {
	d := New(newFake(), quiet(), nil)
	for i := 0; i < 1000; i++ {
		j := d.jitter(10 * time.Second)
		if j < 5*time.Second || j >= 10*time.Second {
			t.Fatalf("jitter %v out of [5s,10s)", j)
		}
	}
}

// A payload that fails while a newer one for the same key arrives must not
// be retried over the newer one.
func TestFailedSendDoesNotOverwriteNewer(t *testing.T) {
	c := newFake()
	c.failures["a"] = []error{io.ErrUnexpectedEOF}
	c.block, c.entered = make(chan struct{}), make(chan struct{})
	d := New(c, quiet(), nil)
	fast(d)
	run(t, d)
	d.Enqueue(vulnEmission("a", "old"))
	<-c.entered                         // "old" is in flight
	d.Enqueue(vulnEmission("a", "new")) // superseded while in flight
	c.block <- struct{}{}               // "old" fails
	<-c.entered
	c.block <- struct{}{} // "new" succeeds
	waitFor(t, func() bool { return len(c.sentDigests()) == 1 })
	if got := c.sentDigests()["a"]; got != "new" {
		t.Errorf("sent %q, want new", got)
	}
	waitFor(t, func() bool { return d.Pending() == 0 })
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.gens) != 0 {
		t.Errorf("generation map not cleaned: %v", d.gens)
	}
}

func TestEnricherRunsBeforeSend(t *testing.T) {
	c := newFake()
	d := New(c, quiet(), nil)
	d.Enrich = func(_ context.Context, e *trivy.Emission) { e.Vulns.Image.DigestKind = types.DigestKindIndex }
	d.Enqueue(vulnEmission("a", "x"))
	run(t, d)
	waitFor(t, func() bool { return len(c.sentDigests()) == 1 })
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent[0].Image.DigestKind != types.DigestKindIndex {
		t.Error("enricher did not run")
	}
}

// A slow lookup on one key occupies one worker; the others keep sending,
// and the lookup is cut off at EnrichTimeout.
func TestSlowEnrichDoesNotStallOthers(t *testing.T) {
	c := newFake()
	d := New(c, quiet(), nil)
	d.Workers = 2
	d.EnrichTimeout = 300 * time.Millisecond
	var timedOut atomic.Bool
	d.Enrich = func(ctx context.Context, e *trivy.Emission) {
		if e.Digest == "slow" {
			<-ctx.Done() // a registry that never answers
			timedOut.Store(true)
		}
	}
	d.Enqueue(vulnEmission("slow", "x"))
	for _, g := range []string{"g1", "g2", "g3", "g4"} {
		d.Enqueue(vulnEmission(g, "x"))
	}
	run(t, d)
	waitFor(t, func() bool { return len(c.sentDigests()) >= 4 })
	if _, ok := c.sentDigests()["slow"]; ok && !timedOut.Load() {
		t.Error("slow key sent before its lookup finished")
	}
	waitFor(t, func() bool { _, ok := c.sentDigests()["slow"]; return ok })
	if !timedOut.Load() {
		t.Error("enrich was not bounded by EnrichTimeout")
	}
}

// Keys are never sent concurrently with themselves: a replacement waits
// for the in-flight send of the same key.
func TestSameKeyNeverConcurrent(t *testing.T) {
	c := newFake()
	c.block, c.entered = make(chan struct{}), make(chan struct{})
	d := New(c, quiet(), nil)
	d.Workers = 4
	run(t, d)
	d.Enqueue(vulnEmission("a", "1"))
	<-c.entered
	d.Enqueue(vulnEmission("a", "2"))
	select {
	case <-c.entered:
		t.Fatal("second send of the same key started while the first was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	c.block <- struct{}{}
	<-c.entered
	c.block <- struct{}{}
	waitFor(t, func() bool { return d.Pending() == 0 && c.sentDigests()["a"] == "2" })
}
