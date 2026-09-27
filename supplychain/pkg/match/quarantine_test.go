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
	calls  int
}

func (f *failMatcher) Match(context.Context, *types.ImageSBOM) ([]types.Vulnerability, error) {
	f.mu.Lock()
	f.calls++
	p, err := f.panics, f.err
	f.mu.Unlock()
	if p {
		panic("simulated OOMKill mid-match")
	}
	return nil, err
}
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
	if f.n() != quarantineAfterErrors || testutil.ToFloat64(mt.GrypeQuarantined) != 1 {
		t.Fatalf("matched %d times, quarantined %v", f.n(), testutil.ToFloat64(mt.GrypeQuarantined))
	}
	c.Offer(trivySBOM("sha256:flaky", "openssl", "zlib")) // a new SBOM lifts it
	pass(c)
	if f.n() != quarantineAfterErrors+1 || testutil.ToFloat64(mt.GrypeQuarantined) != 0 {
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
