package match

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// failMatcher fails every match with err, or panics (a process dying
// mid-match) when panics is set.
type failMatcher struct {
	mu     sync.Mutex
	built  time.Time
	err    error
	panics bool
	block  bool // wait for the match context to end
	calls  int
}

func (f *failMatcher) Match(ctx context.Context, _ *types.ImageSBOM) ([]types.Vulnerability, error) {
	f.mu.Lock()
	f.calls++
	p, err, block := f.panics, f.err, f.block
	f.mu.Unlock()
	if p {
		panic("simulated OOMKill mid-match")
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, err
}
func (f *failMatcher) setErr(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }
func (f *failMatcher) DB() DBInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return DBInfo{Built: f.built}
}
func (f *failMatcher) Scanner() types.Scanner { return types.Scanner{Name: "grype"} }
func (f *failMatcher) n() int                 { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func (f *failMatcher) setBuilt(t time.Time)   { f.mu.Lock(); f.built = t; f.mu.Unlock() }

// pass runs one scheduling pass the way Run does (DB check, then drain).
func pass(c *Coordinator) {
	c.checkDB()
	c.drain(context.Background())
}

func newCoord(m Matcher, dir string) (*Coordinator, *metrics.Metrics) {
	mt := metrics.New()
	c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet(), Metrics: mt, CrashDir: dir}
	c.mu.Lock()
	c.init()
	c.loadCrashesLocked()
	c.mu.Unlock()
	return c, mt
}

func TestTooLargeQuarantinesAtOnceUntilTheDBChanges(t *testing.T) {
	f := &failMatcher{built: time.Unix(100, 0), err: fmt.Errorf("%w: matcher response exceeds 64 MiB", ErrTooLarge)}
	c, mt := newCoord(f, "")
	s := trivySBOM("sha256:big", "linux-libc-dev")
	c.Offer(s)
	pass(c)
	c.Offer(s)
	pass(c)
	if f.n() != 1 {
		t.Fatalf("matched %d times; a too-large result must not be retried", f.n())
	}
	if testutil.ToFloat64(mt.GrypeMatchRuns.WithLabelValues("too_large")) != 1 ||
		testutil.ToFloat64(mt.GrypeMatchRuns.WithLabelValues("quarantined")) != 1 ||
		testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Error("too_large / quarantined not counted")
	}
	f.setBuilt(time.Unix(200, 0)) // a new database lifts it
	pass(c)
	if f.n() != 2 {
		t.Fatalf("after a DB update: %d", f.n())
	}
}

func TestErrorsQuarantineAfterThreeUntilTheSBOMChanges(t *testing.T) {
	f := &failMatcher{built: time.Unix(100, 0), err: errors.New("matcher: connection refused")}
	c, mt := newCoord(f, "")
	s := trivySBOM("sha256:flaky", "openssl")
	for i := 0; i < 6; i++ {
		c.Offer(s)
		pass(c)
	}
	if f.n() != 3 || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("matched %d times, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
	c.Offer(trivySBOM("sha256:flaky", "openssl", "zlib")) // a new SBOM lifts it
	pass(c)
	if f.n() != 4 || testutil.ToFloat64(mt.GrypeQuarantined) != 0 {
		t.Fatalf("after an SBOM change: %d, %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
}

// crashPass runs a pass whose match panics, as a process OOMKilled
// mid-match would stop: whatever was on disk stays.
func crashPass(c *Coordinator) (crashed bool) {
	defer func() { crashed = recover() != nil }()
	pass(c)
	return false
}

func TestACrashMarkerQuarantinesAfterTwoCrashes(t *testing.T) {
	dir := t.TempDir()
	s := trivySBOM("sha256:2349f3f7", "linux-libc-dev")
	var lastCalls int
	for run := 1; run <= 3; run++ {
		f := &failMatcher{built: time.Unix(100, 0), panics: true}
		c, mt := newCoord(f, dir)
		c.Offer(s)
		crashed := crashPass(c)
		markers, _ := filepath.Glob(filepath.Join(dir, "inflight-*.json"))
		switch run {
		case 1, 2: // tried, died, marker left for the next run
			if !crashed || f.n() != 1 || len(markers) != 1 {
				t.Fatalf("run %d: crashed %v calls %d markers %d", run, crashed, f.n(), len(markers))
			}
		case 3: // two deaths on this input: quarantined, not tried again
			if crashed || f.n() != 0 || len(markers) != 0 || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
				t.Fatalf("run 3: crashed %v calls %d markers %d quarantined %v",
					crashed, f.n(), len(markers), testutil.ToFloat64(mt.GrypeQuarantined))
			}
			// A new database is a new input: tried again.
			f.setBuilt(time.Unix(200, 0))
			f.panics = false
			pass(c)
			lastCalls = f.n()
		}
	}
	if lastCalls != 1 {
		t.Fatalf("after a DB update: %d", lastCalls)
	}
}

// Markers are per group and written atomically: two groups in flight at
// once leave two markers, and a successful match removes its own.
func TestMarkersArePerGroup(t *testing.T) {
	dir := t.TempDir()
	c, _ := newCoord(&failMatcher{}, dir)
	a := c.writeMarker("sha256:a", "fa", time.Unix(1, 0), 0)
	b := c.writeMarker("sha256:b", "fb", time.Unix(1, 0), 1)
	if a == "" || b == "" || a == b {
		t.Fatalf("%q %q", a, b)
	}
	c.removeMarker(a)
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 1 || left[0] != b {
		t.Fatalf("%v", left)
	}
	c2, mt := newCoord(&failMatcher{}, dir)
	if gs := c2.groups["sha256:b"]; gs == nil || gs.crashes != 2 || gs.quarantined == "" ||
		testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("%+v", c2.groups["sha256:b"])
	}
	if _, err := os.Stat(b); !os.IsNotExist(err) {
		t.Error("a loaded marker is removed")
	}
}

// tick is what the Run loop does on its ticker, then a pass.
func tick(c *Coordinator) {
	c.mu.Lock()
	c.requeueLocked()
	c.mu.Unlock()
	pass(c)
}

// A matcher outage (restart, rollout, DB load) says nothing about the
// SBOMs: nothing is quarantined, and once the matcher is back every digest
// is matched on the next tick, with no SBOM or database change.
func TestMatcherOutageNeverQuarantines(t *testing.T) {
	f := &failMatcher{built: time.Unix(100, 0), err: fmt.Errorf("%w: dial tcp 127.0.0.1:8090: connect: connection refused", ErrUnavailable)}
	c, mt := newCoord(f, "")
	for i := 0; i < 50; i++ {
		c.Offer(trivySBOM(fmt.Sprintf("sha256:%02d", i), "openssl"))
	}
	pass(c)
	tick(c)
	tick(c)
	if f.n() != 150 || testutil.ToFloat64(mt.GrypeQuarantined) != 0 ||
		testutil.ToFloat64(mt.GrypeMatchRuns.WithLabelValues("unavailable")) != 150 {
		t.Fatalf("down: %d calls, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
	f.setErr(nil) // back, same database
	tick(c)
	if f.n() != 200 || testutil.ToFloat64(mt.GrypeMatchRuns.WithLabelValues("ok")) != 50 {
		t.Fatalf("after recovery: %d calls, %v ok", f.n(), testutil.ToFloat64(mt.GrypeMatchRuns.WithLabelValues("ok")))
	}
	tick(c)
	if f.n() != 200 {
		t.Errorf("matched again with nothing changed: %d", f.n())
	}
}

// An error quarantine is not forever: after its TTL (1h, doubling for
// each repeat) the digest is tried once more, and quarantined again at
// once if it still fails.
func TestErrorQuarantineLiftsAfterItsTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &failMatcher{built: time.Unix(100, 0), err: errors.New("matcher returned 400 Bad Request: bad JSON")}
	c, mt := newCoord(f, "")
	c.now = func() time.Time { return now }
	s := trivySBOM("sha256:bad", "openssl")
	for i := 0; i < 3; i++ {
		c.Offer(s)
		pass(c)
	}
	tick(c)
	if f.n() != 3 || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("%d calls, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
	now = now.Add(time.Hour)
	tick(c) // 1h up: one more try, which fails and re-quarantines (2h)
	tick(c)
	if f.n() != 4 || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("after the TTL: %d calls, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
	now = now.Add(time.Hour)
	tick(c)
	if f.n() != 4 {
		t.Fatalf("the second quarantine lasts 2h: %d calls after 1h", f.n())
	}
	f.setErr(nil)
	now = now.Add(time.Hour)
	tick(c)
	if f.n() != 5 || testutil.ToFloat64(mt.GrypeQuarantined) != 0 {
		t.Fatalf("recovered: %d calls, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
}

// A too-large quarantine does not expire: the same input fails the same way.
func TestTooLargeQuarantineDoesNotExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &failMatcher{built: time.Unix(100, 0), err: fmt.Errorf("%w: over the cap", ErrTooLarge)}
	c, _ := newCoord(f, "")
	c.now = func() time.Time { return now }
	c.Offer(trivySBOM("sha256:big", "linux-libc-dev"))
	pass(c)
	now = now.Add(48 * time.Hour)
	tick(c)
	if f.n() != 1 {
		t.Fatalf("%d calls", f.n())
	}
}

// No marker is left behind by a match that returns, however it returns:
// a leftover marker would count as a crash on the next graceful restart.
func TestNoMarkerLeftAfterAMatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *failMatcher
	}{
		{"success", &failMatcher{built: time.Unix(100, 0)}},
		{"failure", &failMatcher{built: time.Unix(100, 0), err: errors.New("boom")}},
		{"unavailable", &failMatcher{built: time.Unix(100, 0), err: fmt.Errorf("%w: refused", ErrUnavailable)}},
		{"cancelled", &failMatcher{built: time.Unix(100, 0), block: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			c, _ := newCoord(tc.f, dir)
			c.Offer(trivySBOM("sha256:m", "openssl"))
			c.checkDB()
			if tc.f.block {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); c.drain(ctx) }()
				waitFor(t, func() bool {
					m, _ := filepath.Glob(filepath.Join(dir, "inflight-*.json"))
					return tc.f.n() == 1 && len(m) == 1
				})
				cancel() // a shutdown mid-match
				<-done
			} else {
				c.drain(context.Background())
			}
			if tc.f.n() != 1 {
				t.Fatalf("%d calls", tc.f.n())
			}
			if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
				t.Fatalf("left behind: %v", left)
			}
		})
	}
}

func TestErrorQuarantineTTLDoublesUpTo24h(t *testing.T) {
	c, _ := newCoord(&failMatcher{}, "")
	want := []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for i, w := range want {
		if got := c.ttlLocked(&groupState{errorQuarantines: i + 1}); got != w {
			t.Errorf("quarantine %d: %s, want %s", i+1, got, w)
		}
	}
}

// A match that times out says nothing about the SBOM either.
func TestMatchDeadlineNeverQuarantines(t *testing.T) {
	f := &failMatcher{built: time.Unix(100, 0), err: fmt.Errorf("matcher: %w", context.DeadlineExceeded)}
	c, mt := newCoord(f, "")
	c.Offer(trivySBOM("sha256:slow", "openssl"))
	pass(c)
	for i := 0; i < 5; i++ {
		tick(c)
	}
	if f.n() != 6 || testutil.ToFloat64(mt.GrypeQuarantined) != 0 {
		t.Fatalf("%d calls, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
}
