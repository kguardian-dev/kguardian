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
	"slices"
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
	FetchSBOMs(ctx context.Context, registry, repository, digest string) ([]registry.FoundSBOM, []string, error)
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
	// OnGone, when set, is called with the subject digest of an SBOM
	// found before that a later lookup of the same image no longer finds
	// (a definite answer, not an error). The match coordinator uses it to
	// stop waiting for that SBOM.
	OnGone func(digest string)

	now     func() time.Time
	mu      sync.Mutex
	checked map[string]time.Time
	// found: the subject digests found for an image digest at its last
	// lookup, and back (subject -> image digest), for OnGone and Refetch.
	found     map[string][]string
	subjectOf map[string]string
	ready     bool
	passed    bool // the first full pass has finished and been logged
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
		s.found = map[string][]string{}
		s.subjectOf = map[string]string{}
	}
}

// Ready is true once the first inventory listing has returned, whether it
// succeeded or not. It does not wait for that pass's registry lookups: on
// a fresh pod every running digest is due, and fetching them all can take
// minutes, which would fail a helm/Flux --wait upgrade. Lookups continue in
// the background and are counted in the lookup metrics. An unreachable
// broker must not keep the pod NotReady either.
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
	start := s.now()
	images, err := s.Lister.RunningImages(ctx)
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
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
	s.mu.Lock()
	first := !s.passed && ctx.Err() == nil
	if first {
		s.passed = true
	}
	s.mu.Unlock()
	if first {
		// Readiness does not wait for this pass, so say when it is done.
		s.Log.WithFields(logrus.Fields{"running": len(images), "looked_up": len(due),
			"duration": s.now().Sub(start).Round(time.Millisecond).String()}).
			Info("registry sbom source: first pass complete")
	}
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
				s.forgetFoundLocked(d)
			}
		}
		if len(s.checked) >= s.MaxTracked {
			s.checked = map[string]time.Time{}
			s.found, s.subjectOf = map[string][]string{}, map[string]string{}
		}
	}
	s.checked[digest] = s.now()
}

// Refetch makes the next pass look digest up again (digest is an image
// digest or a subject found for one), even within RecheckAfter. The match
// coordinator asks for it when it drops the SBOM to stay within budget.
func (s *Source) Refetch(digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checked == nil {
		return
	}
	if im, ok := s.subjectOf[digest]; ok {
		digest = im
	}
	delete(s.checked, digest)
}

func (s *Source) forgetFoundLocked(imageDigest string) {
	for _, sub := range s.found[imageDigest] {
		if s.subjectOf[sub] == imageDigest {
			delete(s.subjectOf, sub)
		}
	}
	delete(s.found, imageDigest)
}

// recordFound notes the subjects a definite lookup of imageDigest found
// and returns those found last time and not now.
func (s *Source) recordFound(imageDigest string, subjects []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []string
	for _, prev := range s.found[imageDigest] {
		if !slices.Contains(subjects, prev) {
			gone = append(gone, prev)
		}
	}
	s.forgetFoundLocked(imageDigest)
	if len(subjects) > 0 {
		s.found[imageDigest] = subjects
		for _, sub := range subjects {
			s.subjectOf[sub] = imageDigest
		}
	}
	return gone
}

func (s *Source) lookup(ctx context.Context, im broker.Image) {
	found, rejected, err := s.Fetcher.FetchSBOMs(ctx, "", im.Repository, im.Digest)
	s.markChecked(im.Digest)
	if err == nil {
		subjects := make([]string, 0, len(found))
		for _, f := range found {
			subjects = append(subjects, f.Subject)
		}
		for _, d := range s.recordFound(im.Digest, subjects) {
			if s.OnGone != nil {
				s.OnGone(d)
			}
		}
	}
	for _, r := range rejected {
		s.count("rejected_" + r)
	}
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
		if !hasOSPackages(f.Doc.Components) {
			// Source-level only (e.g. a language lockfile SBOM): partial by
			// nature. The matcher unions it with Trivy's, so it can add
			// packages but never stand in for an OS scan.
			s.count("found_source_only")
		}
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
	// The inventory's digestKind says where a digest came from (repo,
	// config, pinned), not what it points at, so it is never copied here.
	// Only a subject found as one of the digest's platform manifests is
	// known to be a manifest; everything else is unknown, never assumed
	// single-arch.
	kind := types.DigestKindUnknown
	index := f.IndexDigest
	if f.Subject != im.Digest {
		kind = types.DigestKindManifest // a platform manifest of the index
		if index == "" {
			index = im.Digest
		}
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
			Digest: f.Subject, IndexDigest: index, Ref: ref, Registry: reg, Repository: repo, Tag: tag, DigestKind: kind,
		},
		SBOMTrust:   f.Trust,
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

// hasOSPackages reports whether an SBOM lists any distro package (an
// operating-system component, or an apk/deb/rpm/alpm PURL).
func hasOSPackages(cs []types.Component) bool {
	for _, c := range cs {
		if c.Type == "operating-system" {
			return true
		}
		for _, t := range []string{"pkg:apk/", "pkg:deb/", "pkg:rpm/", "pkg:alpm/"} {
			if strings.HasPrefix(c.PURL, t) {
				return true
			}
		}
	}
	return false
}
