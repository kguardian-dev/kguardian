package dispatch

import (
	"context"
	"errors"
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

type fakeClient struct {
	mu      sync.Mutex
	fail    int // fail this many calls first
	vulns   []*types.ImageVulnerabilities
	sboms   []*types.ImageSBOM
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeClient) SubmitVulnerabilities(_ context.Context, p *types.ImageVulnerabilities) error {
	if f.entered != nil {
		f.entered <- struct{}{}
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail > 0 {
		f.fail--
		return errors.New("broker unavailable")
	}
	f.vulns = append(f.vulns, p)
	return nil
}

func (f *fakeClient) SubmitSBOM(_ context.Context, p *types.ImageSBOM) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sboms = append(f.sboms, p)
	return nil
}

func (f *fakeClient) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.vulns), len(f.sboms)
}

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func vulnEmission(digest, scanner string) trivy.Emission {
	return trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: digest,
		Vulns: &types.ImageVulnerabilities{Image: types.ImageRef{Digest: digest}, Scanner: types.Scanner{Version: scanner}}}
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

func TestCoalescesPerKey(t *testing.T) {
	c := &fakeClient{}
	d := New(c, quiet(), nil)
	// Queued before Run starts: the second payload for "a" replaces the first.
	d.Enqueue(vulnEmission("a", "1"))
	d.Enqueue(vulnEmission("b", "1"))
	d.Enqueue(vulnEmission("a", "2"))
	d.Enqueue(trivy.Emission{Kind: trivy.KindSBOM, Digest: "a", SBOM: &types.ImageSBOM{}})
	if d.Pending() != 3 {
		t.Fatalf("pending = %d, want 3 (a/vulns, b/vulns, a/sbom)", d.Pending())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	waitFor(t, func() bool { v, s := c.counts(); return v == 2 && s == 1 })
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vulns[0].Image.Digest != "a" || c.vulns[0].Scanner.Version != "2" {
		t.Errorf("first send %+v, want latest payload for a in arrival order", c.vulns[0])
	}
}

func TestRetriesAfterFailure(t *testing.T) {
	c := &fakeClient{fail: 2}
	m := metrics.New()
	d := New(c, quiet(), m)
	d.MinBackoff, d.MaxBackoff = time.Millisecond, 4*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	d.Enqueue(vulnEmission("a", "1"))
	waitFor(t, func() bool { v, _ := c.counts(); return v == 1 })
	if got := testutil.ToFloat64(m.Emissions.WithLabelValues("vulnerabilities", "error")); got != 2 {
		t.Errorf("error count %v", got)
	}
	if got := testutil.ToFloat64(m.Emissions.WithLabelValues("vulnerabilities", "ok")); got != 1 {
		t.Errorf("ok count %v", got)
	}
	if d.Pending() != 0 {
		t.Errorf("pending %d", d.Pending())
	}
}

// A payload that fails while a newer one for the same key arrives must not
// be retried over the newer one.
func TestFailedSendDoesNotOverwriteNewer(t *testing.T) {
	c := &fakeClient{fail: 1, block: make(chan struct{}), entered: make(chan struct{})}
	d := New(c, quiet(), nil)
	d.MinBackoff, d.MaxBackoff = time.Millisecond, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	d.Enqueue(vulnEmission("a", "old"))
	<-c.entered                         // "old" is in flight
	d.Enqueue(vulnEmission("a", "new")) // superseded while in flight
	c.block <- struct{}{}               // "old" fails
	<-c.entered
	c.block <- struct{}{} // "new" succeeds
	waitFor(t, func() bool { v, _ := c.counts(); return v == 1 })
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vulns[0].Scanner.Version != "new" {
		t.Errorf("sent %q, want new", c.vulns[0].Scanner.Version)
	}
}
