// Package engine owns the Grype vulnerability database and matching.
//
// Database lifecycle (grype v6 distribution/installation, pinned in go.mod):
//   - the listing (LatestURL/v6/latest.json) names an archive and its
//     sha256; go-getter verifies that checksum on download, and the curator
//     re-validates the unpacked database's checksum (import.json) on load.
//     Anchore does not publish a signature for the listing or archive, so
//     authenticity rests on TLS to the configured URL;
//   - an update is downloaded next to the current database and swapped in,
//     so the volume must hold two databases at once during a refresh;
//   - a new database is loaded into a fresh provider and swapped under a
//     lock; the old one is closed. A failed refresh keeps the old one.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
	"github.com/sirupsen/logrus"
)

// GrypeVersion is the pinned library version, reported as the scanner.
const GrypeVersion = "v0.119.0"

// Config controls the database.
type Config struct {
	// DBDir holds the database (a volume).
	DBDir string
	// URL is the listing base, e.g. https://grype.anchore.io/databases or
	// an internal mirror serving the same layout.
	URL string
	// AutoUpdate enables downloading and refreshing. When false, only a
	// database already present in DBDir is used (air-gapped preload).
	AutoUpdate bool
	// UpdateInterval between refresh attempts. Grype itself also rate
	// limits update checks to once per 2h.
	UpdateInterval time.Duration
	// MaxAge refuses a database older than this (0 disables the check).
	MaxAge time.Duration
}

// ErrNotReady is returned by Match before a database is loaded.
var ErrNotReady = errors.New("vulnerability database not loaded")

// Engine matches SBOM components against the loaded database.
type Engine struct {
	cfg Config
	log *logrus.Logger

	// load is replaceable in tests.
	load func(update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error)

	mu        sync.RWMutex
	prov      vulnerability.Provider
	status    *vulnerability.ProviderStatus
	lastCheck time.Time
	lastErr   error

	// matchMu serialises matching: one SBOM at a time bounds memory.
	matchMu sync.Mutex
}

// New returns an Engine; call Run to load and refresh the database.
func New(cfg Config, log *logrus.Logger) *Engine {
	e := &Engine{cfg: cfg, log: log}
	e.load = e.grypeLoad
	return e
}

func (e *Engine) grypeLoad(update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	id := clio.Identification{Name: "kguardian-supplychain-matcher", Version: GrypeVersion}
	dist := v6dist.DefaultConfig()
	dist.ID = id
	if e.cfg.URL != "" {
		dist.LatestURL = e.cfg.URL
	}
	inst := v6inst.DefaultConfig(id)
	inst.DBRootDir = e.cfg.DBDir
	inst.ValidateAge = e.cfg.MaxAge > 0
	if e.cfg.MaxAge > 0 {
		inst.MaxAllowedBuiltAge = e.cfg.MaxAge
	}
	return grype.LoadVulnerabilityDB(dist, inst, update)
}

// Run loads the database (downloading it if allowed and absent) and
// refreshes it every UpdateInterval until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	interval := e.cfg.UpdateInterval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	backoff := time.Minute
	for {
		err := e.refresh()
		wait := interval
		if err != nil && !e.Loaded() {
			// Nothing to serve yet: retry sooner, with backoff.
			wait = backoff
			backoff = min(backoff*2, interval)
		} else {
			backoff = time.Minute
		}
		select {
		case <-ctx.Done():
			e.close()
			return
		case <-time.After(wait):
		}
	}
}

func (e *Engine) refresh() error {
	start := time.Now()
	prov, status, err := e.load(e.cfg.AutoUpdate)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastCheck = time.Now().UTC()
	e.lastErr = err
	if err != nil {
		e.log.WithError(err).Warn("vulnerability database load/refresh failed")
		return err
	}
	if e.status != nil && status != nil && e.status.Built.Equal(status.Built) {
		_ = prov.Close() // unchanged; keep the provider already open
		return nil
	}
	old := e.prov
	e.prov, e.status = prov, status
	if old != nil {
		_ = old.Close()
	}
	e.log.WithFields(logrus.Fields{
		"built": status.Built, "schema": status.SchemaVersion, "took": time.Since(start).String(),
	}).Info("vulnerability database loaded")
	return nil
}

func (e *Engine) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.prov != nil {
		_ = e.prov.Close()
		e.prov = nil
	}
}

// Loaded reports whether a database is ready.
func (e *Engine) Loaded() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.prov != nil
}

// DB describes the loaded database and the refresh loop.
func (e *Engine) DB() wire.DB {
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := wire.DB{Loaded: e.prov != nil, Scanner: "grype " + GrypeVersion}
	if e.status != nil {
		b := e.status.Built.UTC()
		d.Built = &b
		d.SchemaVersion = e.status.SchemaVersion
	}
	if !e.lastCheck.IsZero() {
		t := e.lastCheck
		d.LastUpdateCheck = &t
	}
	if e.lastErr != nil {
		d.LastUpdateError = e.lastErr.Error()
	}
	return d
}

// Match matches components against the loaded database.
func (e *Engine) Match(ctx context.Context, cs []wire.Component) ([]wire.Vulnerability, error) {
	e.matchMu.Lock()
	defer e.matchMu.Unlock()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.prov == nil {
		return nil, ErrNotReady
	}
	doc, _ := BuildCycloneDX(cs)
	pkgs, pctx, _, err := pkg.ProvideFromReader(bytes.NewReader(doc), pkg.ProviderConfig{})
	if err != nil {
		return nil, fmt.Errorf("reading components: %w", err)
	}
	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: e.prov,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
	}
	res, _, err := vm.FindMatchesContext(ctx, pkgs, pctx)
	if err != nil {
		return nil, err
	}
	return convert(res.Sorted(), pathIndex(cs)), nil
}

func pathIndex(cs []wire.Component) func(purl, name, version string) []string {
	byPURL := map[string][]string{}
	byNV := map[string][]string{}
	for _, c := range cs {
		if len(c.FilePaths) == 0 {
			continue
		}
		if c.PURL != "" {
			byPURL[c.PURL] = c.FilePaths
		}
		byNV[c.Name+"\x00"+c.Version] = c.FilePaths
	}
	return func(purl, name, version string) []string {
		if p, ok := byPURL[purl]; ok {
			return p
		}
		return byNV[name+"\x00"+version]
	}
}
