package regsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/sbomdoc"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

type lister struct {
	images []broker.Image
	err    error
}

func (l lister) RunningImages(context.Context) ([]broker.Image, error) { return l.images, l.err }

type fetcher struct {
	mu    sync.Mutex
	calls map[string]int
	res   map[string][]registry.FoundSBOM
	rej   map[string][]string
	errs  map[string]error
}

func (f *fetcher) FetchSBOMs(_ context.Context, _, repo, digest string) ([]registry.FoundSBOM, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[digest]++
	return f.res[digest], f.rej[digest], f.errs[digest]
}

type sink struct {
	mu sync.Mutex
	es []trivy.Emission
}

func (s *sink) Enqueue(e trivy.Emission) { s.mu.Lock(); s.es = append(s.es, e); s.mu.Unlock() }

func quiet() *logrus.Logger { l := logrus.New(); l.SetOutput(io.Discard); return l }

func doc() *sbomdoc.Doc {
	return &sbomdoc.Doc{Format: "SPDX", SpecVersion: "2.3", PredicateType: sbomdoc.PredicateSPDX,
		Components: []types.Component{{Name: "musl", Version: "1.2.5-r3", PURL: "pkg:apk/alpine/musl@1.2.5-r3", Type: "apk"}}}
}

func TestPassEmitsAndRechecks(t *testing.T) {
	idx, plat := "sha256:"+rep("a"), "sha256:"+rep("b")
	l := lister{images: []broker.Image{
		{Digest: idx, Repository: "docker.io/library/alpine", Tags: []string{"3.20"}, DigestKind: "index", RunningContainers: 2},
		{Digest: "sha256:" + rep("c"), Repository: "ghcr.io/x/none", DigestKind: "manifest", RunningContainers: 1},
		{Digest: "sha256:" + rep("d"), Repository: "10.0.0.5:5000/lan", RunningContainers: 1},
	}}
	f := &fetcher{
		res: map[string][]registry.FoundSBOM{idx: {{Subject: plat, IndexDigest: idx, Doc: doc(), Trust: types.SBOMTrustUnverified,
			Attestation: types.Attestation{Mechanism: types.MechanismBuildKitAttestation, ArtifactDigest: "sha256:" + rep("e")}}}},
		rej:  map[string][]string{"sha256:" + rep("c"): {registry.RejectEmpty, registry.RejectSubjectMismatch}},
		errs: map[string]error{"sha256:" + rep("d"): &registry.BlockedError{Reason: registry.ReasonPrivateAddress}},
	}
	s := &sink{}
	m := metrics.New()
	now := time.Unix(1_000_000, 0)
	src := &Source{Lister: l, Fetcher: f, Sink: s, Log: quiet(), Metrics: m, now: func() time.Time { return now }}

	src.Pass(context.Background())
	if len(s.es) != 1 {
		t.Fatalf("emissions: %d", len(s.es))
	}
	p := s.es[0].SBOM
	if s.es[0].Kind != trivy.KindSBOM || p.Source != types.SourceRegistry || p.Image.Digest != plat ||
		p.Image.DigestKind != types.DigestKindManifest || p.Image.Registry != "docker.io" ||
		p.Image.Repository != "library/alpine" || p.Image.Ref != "docker.io/library/alpine:3.20" ||
		p.Attestation == nil || p.Attestation.Verified || p.Format != "SPDX" || len(p.Components) != 1 ||
		p.Image.IndexDigest != idx || p.SBOMTrust != types.SBOMTrustUnverified {
		t.Fatalf("payload: %+v", p)
	}
	for result, want := range map[string]float64{"found": 1, "none": 1, "skipped_private_address": 1,
		"rejected_empty": 1, "rejected_subject_mismatch": 1} {
		if v := testutil.ToFloat64(m.RegistrySBOMLookups.WithLabelValues(result)); v != want {
			t.Errorf("%s = %v", result, v)
		}
	}
	if !src.Ready() {
		t.Error("not ready after a pass")
	}

	// A second pass within RecheckAfter makes no registry calls.
	src.Pass(context.Background())
	if f.calls[idx] != 1 || len(s.es) != 1 {
		t.Errorf("rechecked too early: calls=%v emissions=%d", f.calls, len(s.es))
	}
	// After RecheckAfter everything is looked up again.
	now = now.Add(25 * time.Hour)
	src.Pass(context.Background())
	if f.calls[idx] != 2 {
		t.Errorf("not rechecked: %v", f.calls)
	}
}

func TestListFailureIsReadyAndCounted(t *testing.T) {
	m := metrics.New()
	src := &Source{Lister: lister{err: errors.New("503")}, Fetcher: &fetcher{}, Sink: &sink{}, Log: quiet(), Metrics: m}
	src.Pass(context.Background())
	if !src.Ready() || testutil.ToFloat64(m.RegistrySBOMLookups.WithLabelValues("list_error")) != 1 {
		t.Error("list failure not handled")
	}
}

func TestTrackedMapIsBounded(t *testing.T) {
	now := time.Unix(0, 0)
	src := &Source{MaxTracked: 3, now: func() time.Time { return now }}
	src.defaults()
	for _, d := range []string{"a", "b", "c", "d", "e"} {
		src.markChecked(d)
	}
	if len(src.checked) > 3 {
		t.Errorf("tracked %d > 3", len(src.checked))
	}
}

func TestSplitRepository(t *testing.T) {
	for in, want := range map[string][2]string{
		"docker.io/library/nginx": {"docker.io", "library/nginx"},
		"ghcr.io/a/b":             {"ghcr.io", "a/b"},
		"localhost:5000/x":        {"localhost:5000", "x"},
		"library/nginx":           {"", "library/nginx"},
	} {
		r, p := splitRepository(in)
		if r != want[0] || p != want[1] {
			t.Errorf("%s -> %q %q", in, r, p)
		}
	}
}

func rep(c string) string {
	out := ""
	for len(out) < 64 {
		out += c
	}
	return out
}

func TestHasOSPackages(t *testing.T) {
	if !hasOSPackages([]types.Component{{PURL: "pkg:apk/alpine/musl@1"}}) || !hasOSPackages([]types.Component{{Type: "operating-system"}}) {
		t.Error("OS packages not detected")
	}
	if hasOSPackages([]types.Component{{PURL: "pkg:npm/express@4"}, {PURL: "pkg:golang/x@1"}}) {
		t.Error("language-only SBOM reported as having OS packages")
	}
}

// The inventory's digestKind (repo, config, pinned) is provenance, not
// index/manifest: an SBOM for the running digest itself is unknown, never
// assumed single-arch.
func TestToPayloadDigestKindUnknownUnlessPlatformManifest(t *testing.T) {
	d := "sha256:" + rep("f")
	for _, inv := range []string{"", "repo", "config", "pinned", "manifest", "index"} {
		im := broker.Image{Digest: d, Repository: "docker.io/library/alpine", DigestKind: inv, RunningContainers: 1}
		p := toPayload(im, registry.FoundSBOM{Subject: d, Doc: doc(), Trust: types.SBOMTrustAttachedUnbound}, time.Unix(0, 0))
		if p.Image.DigestKind != types.DigestKindUnknown || p.Image.IndexDigest != "" || len(p.Image.PlatformManifests) != 0 {
			t.Errorf("inventory kind %q: payload image %+v", inv, p.Image)
		}
	}
}

type gatedLister struct {
	release chan struct{}
	images  []broker.Image
}

func (l gatedLister) RunningImages(ctx context.Context) ([]broker.Image, error) {
	select {
	case <-l.release:
	case <-ctx.Done():
	}
	return l.images, nil
}

type blockingFetcher struct {
	started chan struct{}
	release chan struct{}
}

func (f *blockingFetcher) FetchSBOMs(ctx context.Context, _, _, _ string) ([]registry.FoundSBOM, []string, error) {
	f.started <- struct{}{}
	select {
	case <-f.release:
	case <-ctx.Done():
	}
	return nil, nil, nil
}

// Readiness follows the listing, not the lookups: a fresh pod's first pass
// fetches every running digest, which can take minutes and must not hold
// the pod NotReady past a helm/Flux --wait.
func TestReadyOnceListedWhileLookupsRun(t *testing.T) {
	var images []broker.Image
	for i := range 20 {
		images = append(images, broker.Image{Digest: fmt.Sprintf("sha256:%064x", i), Repository: "ghcr.io/x/y"})
	}
	l := gatedLister{release: make(chan struct{}), images: images}
	f := &blockingFetcher{started: make(chan struct{}, len(images)), release: make(chan struct{})}
	log, hook := logtest.NewNullLogger()
	src := &Source{Lister: l, Fetcher: f, Sink: &sink{}, Log: log, Metrics: metrics.New()}
	done := make(chan struct{})
	go func() { defer close(done); src.Pass(context.Background()) }()

	time.Sleep(20 * time.Millisecond)
	if src.Ready() {
		t.Fatal("ready before the inventory answered")
	}
	close(l.release)
	<-f.started // a lookup is in flight and blocked
	if !src.Ready() {
		t.Fatal("not ready while the first pass's lookups are still running")
	}
	if firstPassLogs(hook) != 0 {
		t.Fatal("first pass logged as complete while lookups still run")
	}
	close(f.release)
	<-done
	e := hook.LastEntry()
	if firstPassLogs(hook) != 1 || e.Level != logrus.InfoLevel || e.Data["running"] != 20 || e.Data["looked_up"] != 20 || e.Data["duration"] == nil {
		t.Fatalf("first-pass log: %d entries, last %+v", firstPassLogs(hook), e)
	}
	// Only the first pass is announced.
	src.Pass(context.Background())
	if firstPassLogs(hook) != 1 {
		t.Fatal("later pass logged as the first")
	}
}

func firstPassLogs(h *logtest.Hook) int {
	n := 0
	for _, e := range h.AllEntries() {
		if e.Message == "registry sbom source: first pass complete" {
			n++
		}
	}
	return n
}
