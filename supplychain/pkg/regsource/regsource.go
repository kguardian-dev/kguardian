// Package regsource is vulnerability-source B's first half: SBOMs that
// image publishers attach in the registry. It asks the broker's image
// inventory which digests are running, looks each one up anonymously
// through the address-guarded registry client, and emits an ImageSBOM
// (source=registry) per SBOM found.
//
// Every digest is looked up at most once per RecheckAfter, whether or not
// anything was found, so steady state costs one inventory listing per
// Interval and no registry traffic.
package regsource

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/sirupsen/logrus"
)

// SourceName labels this source in metrics.
const SourceName = types.SourceRegistry

// Lister returns the running images (broker.ReadClient).
type Lister interface {
	RunningImages(ctx context.Context) ([]broker.Image, error)
}

// Fetcher finds SBOMs for one digest (registry.Inspector).
type Fetcher interface {
	FetchSBOMs(ctx context.Context, registry, repository, digest string) ([]registry.FoundSBOM, error)
}

// Source polls the inventory and fetches registry SBOMs.
type Source struct {
	Lister  Lister
	Fetcher Fetcher
	Sink    trivy.Sink
	Log     *logrus.Logger
	Metrics *metrics.Metrics

	// Interval between inventory listings. Default 15m.
	Interval time.Duration
	// RecheckAfter is how long a digest's result (found or not) is kept
	// before it is looked up again. Default 24h.
	RecheckAfter time.Duration
	// Workers bounds concurrent registry lookups. Default 2.
	Workers int
	// MaxTracked bounds the per-digest bookkeeping. Default 20000.
	MaxTracked int

	now     func() time.Time
	mu      sync.Mutex
	checked map[string]time.Time
	ready   bool
}

func (s *Source) defaults() {
	if s.Interval <= 0 {
		s.Interval = 15 * time.Minute
	}
	if s.RecheckAfter <= 0 {
		s.RecheckAfter = 24 * time.Hour
	}
	if s.Workers <= 0 {
		s.Workers = 2
	}
	if s.MaxTracked <= 0 {
		s.MaxTracked = 20000
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.checked == nil {
		s.checked = map[string]time.Time{}
	}
}

// Ready is true after the first inventory pass (successful or not): an
// unreachable broker must not keep the pod NotReady.
func (s *Source) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// Run polls until ctx is cancelled.
func (s *Source) Run(ctx context.Context) {
	s.defaults()
	for {
		s.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.Interval):
		}
	}
}

// Pass runs one inventory listing and the lookups it calls for.
func (s *Source) Pass(ctx context.Context) {
	s.defaults()
	defer func() { s.mu.Lock(); s.ready = true; s.mu.Unlock() }()
	images, err := s.Lister.RunningImages(ctx)
	if err != nil {
		s.Log.WithError(err).Warn("registry sbom source: listing running images failed")
		s.count("list_error")
		return
	}
	due := s.due(images)
	work := make(chan broker.Image)
	var wg sync.WaitGroup
	for range s.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for im := range work {
				s.lookup(ctx, im)
			}
		}()
	}
	for _, im := range due {
		select {
		case work <- im:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
}

func (s *Source) due(images []broker.Image) []broker.Image {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []broker.Image
	for _, im := range images {
		if !strings.HasPrefix(im.Digest, "sha256:") || im.Repository == "" {
			continue
		}
		if t, ok := s.checked[im.Digest]; ok && now.Sub(t) < s.RecheckAfter {
			continue
		}
		out = append(out, im)
	}
	return out
}

func (s *Source) markChecked(digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.checked) >= s.MaxTracked {
		// Drop entries past their recheck time first; if that frees
		// nothing, start over (every digest is then re-checked once).
		now := s.now()
		for d, t := range s.checked {
			if now.Sub(t) >= s.RecheckAfter {
				delete(s.checked, d)
			}
		}
		if len(s.checked) >= s.MaxTracked {
			s.checked = map[string]time.Time{}
		}
	}
	s.checked[digest] = s.now()
}

func (s *Source) lookup(ctx context.Context, im broker.Image) {
	found, err := s.Fetcher.FetchSBOMs(ctx, "", im.Repository, im.Digest)
	s.markChecked(im.Digest)
	if err != nil {
		if r, ok := registryBlocked(err); ok {
			s.count("skipped_" + r)
		} else {
			s.count("error")
			s.Log.WithError(err).WithFields(logrus.Fields{"digest": im.Digest, "repository": im.Repository}).
				Debug("registry sbom lookup failed")
		}
		return
	}
	if len(found) == 0 {
		s.count("none")
		return
	}
	s.count("found")
	for _, f := range found {
		p := toPayload(im, f, s.now())
		s.Sink.Enqueue(trivy.Emission{Kind: trivy.KindSBOM, Digest: p.Image.Digest, SBOM: p})
	}
}

func (s *Source) count(result string) {
	if s.Metrics != nil {
		s.Metrics.RegistrySBOMLookups.WithLabelValues(result).Inc()
	}
}

func registryBlocked(err error) (string, bool) {
	var be *registry.BlockedError
	if errors.As(err, &be) {
		return be.Reason, true
	}
	return "", false
}

func toPayload(im broker.Image, f registry.FoundSBOM, now time.Time) *types.ImageSBOM {
	reg, repo := splitRepository(im.Repository)
	kind := im.DigestKind
	if f.Subject != im.Digest {
		kind = types.DigestKindManifest // a platform manifest of the index
	}
	if kind == "" {
		kind = types.DigestKindUnknown
	}
	tag := ""
	if len(im.Tags) > 0 {
		tag = im.Tags[0]
	}
	ref := im.Repository
	if tag != "" {
		ref += ":" + tag
	}
	att := f.Attestation
	return &types.ImageSBOM{
		SchemaVersion: types.SchemaVersion,
		Image: types.ImageRef{
			Digest: f.Subject, Ref: ref, Registry: reg, Repository: repo, Tag: tag, DigestKind: kind,
		},
		Source:      types.SourceRegistry,
		Scanner:     types.Scanner{Name: "registry", Vendor: att.Mechanism},
		ScannedAt:   now.UTC(),
		Format:      f.Doc.Format,
		SpecVersion: f.Doc.SpecVersion,
		Attestation: &att,
		Components:  f.Doc.Components,
	}
}

// splitRepository splits the inventory's normalised repository
// ("docker.io/library/nginx") into registry and path.
func splitRepository(r string) (string, string) {
	if i := strings.IndexByte(r, '/'); i > 0 && strings.ContainsAny(r[:i], ".:") {
		return r[:i], r[i+1:]
	}
	return "", r
}
