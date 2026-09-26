package regsource

import (
	"context"
	"errors"
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
	errs  map[string]error
}

func (f *fetcher) FetchSBOMs(_ context.Context, _, repo, digest string) ([]registry.FoundSBOM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[digest]++
	return f.res[digest], f.errs[digest]
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
		res: map[string][]registry.FoundSBOM{idx: {{Subject: plat, Doc: doc(),
			Attestation: types.Attestation{Mechanism: types.MechanismBuildKitAttestation, ArtifactDigest: "sha256:" + rep("e")}}}},
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
		p.Attestation == nil || p.Attestation.Verified || p.Format != "SPDX" || len(p.Components) != 1 {
		t.Fatalf("payload: %+v", p)
	}
	for result, want := range map[string]float64{"found": 1, "none": 1, "skipped_private_address": 1} {
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
