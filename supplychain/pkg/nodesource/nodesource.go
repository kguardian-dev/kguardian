// Package nodesource feeds the node catalog's SBOMs to the matcher. The
// Controller and its cataloger worker catalog each running image on one
// node that runs it and store the result in the broker as source "node"
// (docs/design/node-catalog.md). This source reads them back and offers
// them to the match coordinator, which matches them with Grype in the
// union with every other SBOM held for the digest. There a node SBOM only
// adds packages: Trivy's and registry SBOMs keep everything they give
// (see pkg/match).
//
// Every Interval it lists the broker's image inventory (GET /images, read
// scope) and fetches, components only, the node SBOM of each running
// digest whose sbomSources include "node" when it is new, when its
// nodeCatalog.catalogedAt changed, or once every RecheckAfter; and when
// the coordinator Wants it (its group, evicted, is waiting for it), at
// most once per backoff window. A node SBOM the coordinator holds is
// replaced by an empty one when it is deleted (the digest is still in the
// inventory but no longer lists "node") or stored empty, so its packages
// are released. A digest that merely stops running (a CronJob between
// runs) is left alone. Node SBOMs are never sent to the broker again:
// they go to the coordinator only, not through the dispatch queue.
//
// Against a broker without the node catalog (GET /catalog/status answers
// 404) the source idles: it logs once, lists nothing, and asks again only
// every IdleRecheck. A token the broker refuses (401/403) is logged once
// at error level and retried at the same pace.
package nodesource

import (
	"context"
	"errors"
	"net/http"
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
	Images(ctx context.Context) ([]broker.Image, error)
	NodeSBOM(ctx context.Context, digest string, maxComponents int) (*broker.NodeSBOM, error)
}

// Offerer takes SBOMs for matching (match.Coordinator).
type Offerer interface {
	Offer(sbom *types.ImageSBOM)
	// Holds reports whether an SBOM from source is held for digest.
	Holds(digest, source string) bool
	// Wants reports whether the coordinator waits for digest's node SBOM.
	Wants(digest string) bool
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
	// IdleRecheck is how often a broker without the node catalog, or one
	// that refuses the token, is asked again. Default 1h.
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
	idle      bool      // on a broker without it (logged once)
	denied    bool      // the broker refuses the token (logged once)
	nextProbe time.Time // while idle or denied
	probeErr  bool      // the last probe failed (logged once per streak)
}

type fetchState struct {
	version string // nodeCatalog.catalogedAt when fetched
	at      time.Time
	// While the coordinator Wants the SBOM: when it may be offered again,
	// and the current backoff (doubling from Interval, at most
	// RecheckAfter). Reset once it is no longer wanted.
	wantNext    time.Time
	wantBackoff time.Duration
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

// Ready is true once the first pass has listed the inventory (or found it
// cannot), whatever the outcome. It does not wait for that pass's
// fetches: on a fresh pod every node SBOM is due, and reading them all
// can take minutes, which would fail a helm/Flux --wait upgrade. An
// unreachable or old broker must not keep the pod NotReady either.
func (s *Source) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

func (s *Source) setReady() {
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
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
	if !s.checkAvailable(ctx) {
		s.setReady()
		return
	}
	images, err := s.Broker.Images(ctx)
	s.setReady()
	if err != nil {
		s.Log.WithError(err).Warn("node sbom source: listing images failed")
		s.count("list_error")
		return
	}
	due, deleted := s.due(images)
	for _, im := range deleted {
		s.release(im)
	}
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
// says yes, at most once per IdleRecheck while it says no (or refuses).
func (s *Source) checkAvailable(ctx context.Context) bool {
	s.mu.Lock()
	if s.available {
		s.mu.Unlock()
		return true
	}
	if (s.idle || s.denied) && s.now().Before(s.nextProbe) {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()

	err := s.Broker.NodeCatalogAvailable(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	var se *broker.StatusError
	switch {
	case err == nil:
		if s.idle || s.denied {
			s.Log.Info("node sbom source: the broker now serves the node catalog; resuming")
		}
		s.available, s.idle, s.denied, s.probeErr = true, false, false, false
		s.setGauges(1, 1)
		return true
	case errors.Is(err, broker.ErrNoNodeCatalog):
		if !s.idle {
			s.Log.WithField("recheck", s.IdleRecheck.String()).
				Info("node sbom source: the broker has no node catalog (GET /catalog/status answers 404); idle")
		}
		s.idle, s.denied, s.probeErr = true, false, false
		s.nextProbe = s.now().Add(s.IdleRecheck)
		s.setGauges(0, 1)
		return false
	case errors.As(err, &se) && (se.StatusCode == http.StatusUnauthorized || se.StatusCode == http.StatusForbidden):
		s.count("probe_denied")
		if !s.denied {
			s.Log.WithError(err).WithField("recheck", s.IdleRecheck.String()).
				Error("node sbom source: the broker refuses this token (it needs the read scope); not reading node SBOMs")
		}
		s.denied, s.idle, s.probeErr = true, false, false
		s.nextProbe = s.now().Add(s.IdleRecheck)
		s.setGauges(-1, 0)
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

// due returns the running images whose node SBOM is new, changed, due for
// its recheck, or wanted by the coordinator (bounded by the backoff); and
// the images whose node SBOM was deleted while the digest is still in the
// inventory. State is kept for digests that are not running (a CronJob
// between runs), so they are not fetched again when they run again
// unchanged, and forgotten for digests that left the inventory.
func (s *Source) due(images []broker.Image) (due, deleted []broker.Image) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	inInventory := make(map[string]bool, len(images))
	withNode := 0
	for _, im := range images {
		if !strings.HasPrefix(im.Digest, "sha256:") {
			continue
		}
		inInventory[im.Digest] = true
		if !im.HasSBOM(types.SourceNode) {
			if _, ok := s.fetched[im.Digest]; ok {
				delete(s.fetched, im.Digest)
				deleted = append(deleted, im)
			}
			continue
		}
		withNode++
		if im.RunningContainers <= 0 {
			continue
		}
		f, ok := s.fetched[im.Digest]
		if !ok || f.version != version(im) || now.Sub(f.at) >= s.RecheckAfter {
			due = append(due, im)
			continue
		}
		if !s.Matcher.Wants(im.Digest) {
			if f.wantBackoff != 0 {
				f.wantNext, f.wantBackoff = time.Time{}, 0
				s.fetched[im.Digest] = f
			}
			continue
		}
		if now.Before(f.wantNext) {
			continue
		}
		f.wantBackoff = min(max(f.wantBackoff*2, s.Interval), s.RecheckAfter)
		f.wantNext = now.Add(f.wantBackoff)
		s.fetched[im.Digest] = f
		s.count("wanted")
		due = append(due, im)
	}
	for d := range s.fetched {
		if !inInventory[d] {
			delete(s.fetched, d)
		}
	}
	if s.Metrics != nil {
		s.Metrics.TrackedDigests.WithLabelValues(SourceName, "sbom").Set(float64(withNode))
	}
	return due, deleted
}

// release replaces the node SBOM the coordinator holds for im with an
// empty one, so its packages stop being matched. With none held
// (evicted, or never offered) there is nothing to release.
func (s *Source) release(im broker.Image) {
	if !s.Matcher.Holds(im.Digest, types.SourceNode) {
		return
	}
	s.Matcher.Offer(toSBOM(im, &broker.NodeSBOM{Digest: im.Digest}))
	s.count("released")
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
	case errors.Is(err, broker.ErrNodeSBOMTooLarge):
		// Fails the same way until it changes: not fetched again before.
		// A smaller version held is released: it no longer describes the
		// image.
		s.count("too_large")
		s.Log.WithError(err).WithField("digest", im.Digest).Warn("node sbom source: node SBOM too large to match; skipped")
		s.mark(im)
		s.release(im)
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
	s.mark(im)
	if doc == nil || len(doc.Components) == 0 {
		// Gone since the listing, or stored empty (no_packages_found).
		s.count("none")
		s.release(im)
		return
	}
	s.count("fetched")
	s.Matcher.Offer(toSBOM(im, doc))
}

// mark records a fetch of im, keeping its want backoff.
func (s *Source) mark(im broker.Image) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fetched[im.Digest]
	f.version, f.at = version(im), s.now()
	s.fetched[im.Digest] = f
}

func (s *Source) count(result string) {
	if s.Metrics != nil {
		s.Metrics.NodeSBOMFetches.WithLabelValues(result).Inc()
	}
}

// setGauges sets source_available (skipped when negative) and
// source_healthy for this source.
func (s *Source) setGauges(available, healthy float64) {
	if s.Metrics == nil {
		return
	}
	if available >= 0 {
		s.Metrics.SourceAvailable.WithLabelValues(SourceName).Set(available)
	}
	s.Metrics.SourceHealthy.WithLabelValues(SourceName).Set(healthy)
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
