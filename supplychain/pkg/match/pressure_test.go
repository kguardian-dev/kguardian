package match

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/regsource"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/sbomdoc"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// brokerSink stands in for the dispatch queue: it counts what would be
// sent to the broker (it drops match-only emissions, as dispatch does).
type brokerSink struct {
	mu    sync.Mutex
	sboms int
}

func (b *brokerSink) Enqueue(e trivy.Emission) {
	if e.MatchOnly || e.Kind != trivy.KindSBOM {
		return
	}
	b.mu.Lock()
	b.sboms++
	b.mu.Unlock()
}

type pressureLister struct{ images []broker.Image }

func (l pressureLister) RunningImages(context.Context) ([]broker.Image, error) { return l.images, nil }

type pressureFetcher struct {
	mu    sync.Mutex
	calls int
}

func (f *pressureFetcher) FetchSBOMs(ctx context.Context, reg, repo, digest string) ([]registry.FoundSBOM, []string, error) {
	found, rej, _, err := f.FetchSBOMsComplete(ctx, reg, repo, digest)
	return found, rej, err
}

func (f *pressureFetcher) FetchSBOMsComplete(_ context.Context, _, _, digest string) ([]registry.FoundSBOM, []string, bool, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	doc := &sbomdoc.Doc{Format: "SPDX", Components: []types.Component{{Name: "r-" + digest[7:9], Version: "1", PURL: "pkg:npm/r" + digest[7:9] + "@1"}}}
	return []registry.FoundSBOM{{Subject: digest, Doc: doc, Trust: types.SBOMTrustUnverified}}, nil, true, nil
}

func (f *pressureFetcher) n() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// Sustained memory pressure with twice as many node groups as the budget:
// groups keep being dropped and their node SBOMs re-catalogued. Trivy's
// SBOMs come back straight from the (fake) tracker and registry SBOMs
// match-only, so the broker gets no re-upload at all, and registry lookups
// stay within the per-SBOM refetch backoff.
func TestSustainedPressureCausesNoReuploads(t *testing.T) {
	const groups, budget = 12, 6
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	m := &mockMatcher{built: time.Unix(100, 0)}
	// The byte budget holds about half the groups (three SBOMs of ~1.2 KiB).
	c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet(), MaxHeldBytes: budget * 3700}
	c.now = clock
	up := &brokerSink{}
	tee := c.Tee(up)

	tr := &recordingRefetcher{hold: map[string]*types.ImageSBOM{}, inMemory: true}
	var images []broker.Image
	digest := func(i int) string { return fmt.Sprintf("sha256:%02d%062d", i, 0) }
	for i := 0; i < groups; i++ {
		d := digest(i)
		tr.hold[d] = trivySBOM(d, fmt.Sprintf("t%d", i))
		images = append(images, broker.Image{Digest: d, Repository: "docker.io/library/x", RunningContainers: 1})
	}
	f := &pressureFetcher{}
	reg := &regsource.Source{Lister: pressureLister{images}, Fetcher: f, Sink: tee, Log: quiet(), Interval: 15 * time.Minute}
	reg.OnGone = func(d string) { c.Gone(d, types.SourceRegistry) }
	c.SetRefetcher(types.SourceTrivyOperator, tr)
	c.SetRefetcher(types.SourceRegistry, reg)

	for i := 0; i < groups; i++ {
		tee.Enqueue(trivy.Emission{Kind: trivy.KindSBOM, Digest: digest(i), SBOM: tr.hold[digest(i)]})
		c.Offer(nodeSBOM(digest(i), "linux/arm64", "n"))
	}
	reg.Pass(context.Background())
	pass(c)
	baseline, lookups := up.sboms, f.n()
	if baseline != 2*groups || lookups != groups {
		t.Fatalf("setup: %d uploads, %d lookups", baseline, lookups)
	}

	const minutes = 240
	for minute := 1; minute <= minutes; minute++ {
		now = now.Add(time.Minute)
		c.Offer(nodeSBOM(digest(minute%groups), "linux/arm64", "n", fmt.Sprint(minute))) // a new catalog
		c.mu.Lock()
		c.requeueLocked()
		c.mu.Unlock()
		pass(c)
		if minute%15 == 0 {
			reg.Pass(context.Background())
			pass(c)
		}
		c.mu.Lock()
		held, limit := c.heldBytes, c.MaxHeldBytes
		c.mu.Unlock()
		if held > limit+limit/2 {
			t.Fatalf("minute %d: %d bytes held (budget %d)", minute, held, limit)
		}
	}
	t.Logf("trivy refetches %d, extra registry lookups %d, matches %d", tr.calls(), f.n()-lookups, len(m.calls))
	if up.sboms != baseline {
		t.Errorf("%d SBOM re-uploads to the broker under pressure", up.sboms-baseline)
	}
	// A registry refetch only drops the image's recheck mark: the lookup
	// happens on the source's next pass, so at most one per image per
	// pass (the refetch backoff restarts after each successful match).
	if extra := f.n() - lookups; extra > groups*minutes/15 {
		t.Errorf("%d registry lookups in %d minutes for %d images", extra, minutes, groups)
	}
	if tr.calls() == 0 || f.n() == lookups {
		t.Errorf("the pressure never made a group wait (trivy refetches %d, lookups %d)", tr.calls(), f.n()-lookups)
	}
}
