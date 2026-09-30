// Package nodesource feeds the node catalog's SBOMs to the matcher. The
// Controller and its cataloger worker catalog each running image on one
// node that runs it and store the result in the broker as source "node"
// (docs/design/node-catalog.md). This source reads them back and offers
// them to the match coordinator, which matches them with Grype in the
// union with every other SBOM held for the digest (precedence Trivy >
// node > registry; see pkg/match).
//
// Every Interval it lists the broker's image inventory (GET /images, read
// scope) and fetches, components only, the node SBOM of each running
// digest whose sbomSources include "node" and whose nodeCatalog.catalogedAt
// changed since it was last fetched (or that has not been fetched for
// RecheckAfter, so an SBOM the coordinator dropped to stay within its
// budget comes back). Node SBOMs are never sent to the broker again: they
// go to the coordinator only, not through the dispatch queue.
//
// Against a broker without the node catalog (its catalog routes answer
// 404) the source idles: it logs once, lists nothing, and asks again only
// every IdleRecheck.
package nodesource

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/sirupsen/logrus"
)

// SourceName labels this source in metrics.
const SourceName = types.SourceNode

// scannerName is the scanner the broker records for node SBOMs.
const scannerName = "kguardian-cataloger"

// Broker is the part of broker.ReadClient this source uses.
type Broker interface {
	NodeCatalogAvailable(ctx context.Context) error
	RunningImages(ctx context.Context) ([]broker.Image, error)
	NodeSBOM(ctx context.Context, digest string, maxComponents int) (*broker.NodeSBOM, error)
}

// Offerer takes SBOMs for matching (match.Coordinator).
type Offerer interface {
	Offer(sbom *types.ImageSBOM)
}

// Source polls the inventory and offers changed node SBOMs.
type Source struct {
	Broker  Broker
	Matcher Offerer
	Log     *logrus.Logger
	Metrics *metrics.Metrics

	// Interval between inventory listings. Default 5m.
	Interval time.Duration
	// RecheckAfter is how long an unchanged node SBOM goes before it is
	// fetched and offered again. Default 24h.
	RecheckAfter time.Duration
	// IdleRecheck is how often a broker without the node catalog is asked
	// again. Default 1h.
	IdleRecheck time.Duration
	// Workers bounds concurrent fetches. Default 2.
	Workers int
	// MaxComponents is the largest node SBOM fetched (the matcher's
	// request limit). Default 50000.
	MaxComponents int

	now       func() time.Time
	mu        sync.Mutex
	fetched   map[string]fetchState // digest -> last fetch
	ready     bool
	available bool      // the broker has the node catalog
	idle      bool      // idling on a broker without it (logged once)
	nextProbe time.Time // while idle
	probeErr  bool      // the last probe failed (logged once per streak)
}

type fetchState struct {
	version string // nodeCatalog.catalogedAt when fetched
	at      time.Time
	offered bool // a non-empty SBOM was offered
}

func (s *Source) defaults() {
	if s.Interval <= 0 {
		s.Interval = 5 * time.Minute
	}
	if s.RecheckAfter <= 0 {
		s.RecheckAfter = 24 * time.Hour
	}
	if s.IdleRecheck <= 0 {
		s.IdleRecheck = time.Hour
	}
	if s.Workers <= 0 {
		s.Workers = 2
	}
	if s.MaxComponents <= 0 {
		s.MaxComponents = 50000
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.fetched == nil {
		s.fetched = map[string]fetchState{}
	}
}

// Ready is true once the first pass has run, whatever its outcome: an
// unreachable or old broker must not keep the pod NotReady, and fetches
// continue in the background.
func (s *Source) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// Idle reports whether the source is idling on a broker without the node
// catalog.
func (s *Source) Idle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idle
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

// Pass runs one inventory listing and the fetches it calls for.
func (s *Source) Pass(ctx context.Context) {
	s.defaults()
	defer func() {
		s.mu.Lock()
		s.ready = true
		s.mu.Unlock()
	}()
	if !s.checkAvailable(ctx) {
		return
	}
	images, err := s.Broker.RunningImages(ctx)
	if err != nil {
		s.Log.WithError(err).Warn("node sbom source: listing running images failed")
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
				s.fetch(ctx, im)
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

// checkAvailable asks the broker whether it has the node catalog until it
// says yes, at most once per IdleRecheck while it says no.
func (s *Source) checkAvailable(ctx context.Context) bool {
	s.mu.Lock()
	if s.available {
		s.mu.Unlock()
		return true
	}
	if s.idle && s.now().Before(s.nextProbe) {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()

	err := s.Broker.NodeCatalogAvailable(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err == nil:
		s.available, s.probeErr = true, false
		if s.idle {
			s.Log.Info("node sbom source: the broker now has the node catalog; resuming")
		}
		s.idle = false
		s.setAvailable(1)
		return true
	case errors.Is(err, broker.ErrNoNodeCatalog):
		s.goIdleLocked()
		return false
	default:
		// Transient (network, 5xx): try again next pass, one line per streak.
		s.count("probe_error")
		if !s.probeErr {
			s.Log.WithError(err).Warn("node sbom source: cannot tell whether the broker has the node catalog; will retry")
		}
		s.probeErr = true
		return false
	}
}

// goIdleLocked switches to idle: logged once, then quiet, asking again
// every IdleRecheck.
func (s *Source) goIdleLocked() {
	if !s.idle {
		s.Log.WithField("recheck", s.IdleRecheck.String()).
			Info("node sbom source: the broker has no node catalog (its catalog routes answer 404); idle")
	}
	s.idle, s.available, s.probeErr = true, false, false
	s.nextProbe = s.now().Add(s.IdleRecheck)
	s.setAvailable(0)
}

// due returns the running images whose node SBOM is new, changed or due
// for its recheck, and forgets digests no longer listed with one.
func (s *Source) due(images []broker.Image) []broker.Image {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	listed := make(map[string]bool, len(images))
	var out []broker.Image
	for _, im := range images {
		if !strings.HasPrefix(im.Digest, "sha256:") || !im.HasSBOM(types.SourceNode) {
			continue
		}
		listed[im.Digest] = true
		f, ok := s.fetched[im.Digest]
		if ok && f.version == version(im) && now.Sub(f.at) < s.RecheckAfter {
			continue
		}
		out = append(out, im)
	}
	for d := range s.fetched {
		if !listed[d] {
			delete(s.fetched, d)
		}
	}
	if s.Metrics != nil {
		s.Metrics.TrackedDigests.WithLabelValues(SourceName, "sbom").Set(float64(len(listed)))
	}
	return out
}

func version(im broker.Image) string {
	if im.NodeCatalog == nil {
		return ""
	}
	return im.NodeCatalog.CatalogedAt
}

func (s *Source) fetch(ctx context.Context, im broker.Image) {
	doc, err := s.Broker.NodeSBOM(ctx, im.Digest, s.MaxComponents)
	switch {
	case errors.Is(err, broker.ErrNoNodeCatalog):
		s.mu.Lock()
		s.goIdleLocked()
		s.mu.Unlock()
		return
	case errors.Is(err, broker.ErrNodeSBOMTooLarge):
		// Fails the same way until it changes: not fetched again before.
		s.count("too_large")
		s.mark(im, false)
		s.Log.WithError(err).WithField("digest", im.Digest).Warn("node sbom source: node SBOM too large to match; skipped")
		return
	case errors.Is(err, broker.ErrNodeSBOMChanged):
		s.count("changed")
		return // re-read next pass
	case err != nil:
		if ctx.Err() == nil {
			s.count("error")
			s.Log.WithError(err).WithField("digest", im.Digest).Debug("node sbom fetch failed")
		}
		return
	}
	if doc == nil || len(doc.Components) == 0 {
		// Gone since the listing, or stored empty (no_packages_found).
		// If an earlier version was offered, replace it with an empty one
		// so its packages are not matched (and reported) any more.
		s.count("none")
		if s.mark(im, false) {
			s.Matcher.Offer(toSBOM(im, &broker.NodeSBOM{Digest: im.Digest}))
		}
		return
	}
	s.count("fetched")
	s.mark(im, true)
	s.Matcher.Offer(toSBOM(im, doc))
}

// mark records a fetch of im and reports whether a non-empty SBOM had
// been offered for it before.
func (s *Source) mark(im broker.Image, offered bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	was := s.fetched[im.Digest].offered
	s.fetched[im.Digest] = fetchState{version: version(im), at: s.now(), offered: offered}
	return was
}

func (s *Source) count(result string) {
	if s.Metrics != nil {
		s.Metrics.NodeSBOMFetches.WithLabelValues(result).Inc()
	}
}

func (s *Source) setAvailable(v float64) {
	if s.Metrics != nil {
		s.Metrics.SourceAvailable.WithLabelValues(SourceName).Set(v)
	}
}

// toSBOM builds the coordinator's ImageSBOM for a node SBOM. It is keyed
// by the inventory digest alone, with no index or platform manifests, and
// carries the one platform it was cataloged for.
func toSBOM(im broker.Image, doc *broker.NodeSBOM) *types.ImageSBOM {
	reg, repo := splitRepository(im.Repository)
	tag := ""
	if len(im.Tags) > 0 {
		tag = im.Tags[0]
	}
	ref := im.Repository
	if tag != "" {
		ref += ":" + tag
	}
	trust := doc.Trust
	if trust == "" {
		trust = types.SBOMTrustScanned
	}
	platform := ""
	if im.NodeCatalog != nil {
		platform = im.NodeCatalog.Platform
	}
	return &types.ImageSBOM{
		SchemaVersion: types.SchemaVersion,
		Image: types.ImageRef{
			Digest: im.Digest, Ref: ref, Registry: reg, Repository: repo, Tag: tag, DigestKind: types.DigestKindUnknown,
		},
		Source:     types.SourceNode,
		Scanner:    types.Scanner{Name: scannerName},
		ScannedAt:  parseTime(doc.ScannedAt),
		Format:     doc.Format,
		SBOMTrust:  trust,
		Components: doc.Components,
		Platform:   platform,
	}
}

// parseTime reads the broker's timestamps: RFC 3339, or a naive UTC
// timestamp (a Rust NaiveDateTime). Zero when neither.
func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// splitRepository splits the inventory's normalised repository
// ("docker.io/library/nginx") into registry and path.
func splitRepository(r string) (string, string) {
	if i := strings.IndexByte(r, '/'); i > 0 && strings.ContainsAny(r[:i], ".:") {
		return r[:i], r[i+1:]
	}
	return "", r
}
