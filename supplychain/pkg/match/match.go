// Package match turns stored SBOMs into vulnerability payloads with a
// Matcher (Grype), independent of which Matcher implementation is used.
//
// It keeps one SBOM per digest - the highest-priority source seen
// (registry-attested > Trivy SbomReport) - bounded by MaxDigests, matches
// each new or changed SBOM once, and re-matches everything it holds when
// the Matcher reports a new vulnerability database, without fetching any
// SBOM again.
package match

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
	"github.com/sirupsen/logrus"
)

// DBInfo describes the vulnerability database a Matcher is using.
type DBInfo struct {
	// Built is when the database was built; zero when none is loaded.
	Built         time.Time
	SchemaVersion string
}

// Matcher matches one SBOM against a vulnerability database.
type Matcher interface {
	// Match returns the vulnerabilities for sbom's packages.
	Match(ctx context.Context, sbom *types.ImageSBOM) ([]types.Vulnerability, error)
	// DB reports the database currently loaded.
	DB() DBInfo
	// Scanner identifies the matcher in payloads (name, vendor, version).
	Scanner() types.Scanner
}

// Priority of SBOM sources for matching; higher wins.
func priority(source string) int {
	switch source {
	case types.SourceRegistry:
		return 2
	case types.SourceTrivyOperator:
		return 1
	}
	return 0
}

type entry struct {
	sbom        *types.ImageSBOM
	fingerprint string
	lastUsed    time.Time
	matchedDB   time.Time // DBInfo.Built it was last matched against
}

// Coordinator holds SBOMs and schedules matching on one worker.
type Coordinator struct {
	Matcher Matcher
	Sink    trivy.Sink
	Log     *logrus.Logger
	Metrics *metrics.Metrics
	// MaxDigests bounds the SBOMs held. Default 2000.
	MaxDigests int
	// MatchTimeout bounds one match. Default 2m.
	MatchTimeout time.Duration

	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*entry
	queue   map[string]struct{}
	notify  chan struct{}
	dbSeen  time.Time
}

func (c *Coordinator) init() {
	if c.entries == nil {
		c.entries = map[string]*entry{}
		c.queue = map[string]struct{}{}
		c.notify = make(chan struct{}, 1)
	}
	if c.MaxDigests <= 0 {
		c.MaxDigests = 2000
	}
	if c.MatchTimeout <= 0 {
		c.MatchTimeout = 2 * time.Minute
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// Offer records an SBOM. It replaces the held SBOM for the digest only if
// its source has equal or higher priority, and queues a match when the
// held SBOM's content changed. Never blocks.
func (c *Coordinator) Offer(sbom *types.ImageSBOM) {
	if sbom == nil || sbom.Image.Digest == "" || sbom.Page != nil {
		return
	}
	c.mu.Lock()
	c.init()
	d := sbom.Image.Digest
	fp := fingerprint(sbom)
	cur, ok := c.entries[d]
	switch {
	case ok && priority(sbom.Source) < priority(cur.sbom.Source):
		cur.lastUsed = c.now()
		c.mu.Unlock()
		return
	case ok && cur.fingerprint == fp:
		cur.lastUsed = c.now()
		c.mu.Unlock()
		return
	}
	c.evictLocked(d)
	c.entries[d] = &entry{sbom: sbom, fingerprint: fp, lastUsed: c.now()}
	c.queue[d] = struct{}{}
	c.gaugesLocked()
	c.mu.Unlock()
	c.wake()
}

// Tee returns a Sink that forwards to next and offers every SBOM emission
// to the coordinator, so all SBOM sources feed matching without knowing
// about it.
func (c *Coordinator) Tee(next trivy.Sink) trivy.Sink {
	return teeSink{c: c, next: next}
}

type teeSink struct {
	c    *Coordinator
	next trivy.Sink
}

func (t teeSink) Enqueue(e trivy.Emission) {
	t.next.Enqueue(e)
	if e.Kind == trivy.KindSBOM {
		t.c.Offer(e.SBOM)
	}
}

func (c *Coordinator) evictLocked(keep string) {
	for len(c.entries) >= c.MaxDigests {
		var oldest string
		var t time.Time
		for d, e := range c.entries {
			if d == keep {
				continue
			}
			if oldest == "" || e.lastUsed.Before(t) {
				oldest, t = d, e.lastUsed
			}
		}
		if oldest == "" {
			return
		}
		delete(c.entries, oldest)
		delete(c.queue, oldest)
	}
}

func (c *Coordinator) wake() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// Held returns the number of SBOMs held.
func (c *Coordinator) Held() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Run matches queued SBOMs until ctx is cancelled, polling the Matcher's
// database every dbPoll and re-queuing everything when it changes.
func (c *Coordinator) Run(ctx context.Context, dbPoll time.Duration) {
	c.mu.Lock()
	c.init()
	c.mu.Unlock()
	if dbPoll <= 0 {
		dbPoll = time.Minute
	}
	t := time.NewTicker(dbPoll)
	defer t.Stop()
	for {
		c.checkDB()
		c.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-c.notify:
		case <-t.C:
		}
	}
}

// checkDB re-queues every held SBOM when the database changed.
func (c *Coordinator) checkDB() {
	db := c.Matcher.DB()
	if c.Metrics != nil && !db.Built.IsZero() {
		c.Metrics.GrypeDBBuilt.Set(float64(db.Built.Unix()))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if db.Built.IsZero() || db.Built.Equal(c.dbSeen) {
		return
	}
	first := c.dbSeen.IsZero()
	c.dbSeen = db.Built
	for d, e := range c.entries {
		if !e.matchedDB.Equal(db.Built) {
			c.queue[d] = struct{}{}
		}
	}
	if !first && c.Log != nil {
		c.Log.WithFields(logrus.Fields{"built": db.Built, "held": len(c.entries)}).
			Info("vulnerability database updated; re-matching held SBOMs")
	}
}

func (c *Coordinator) drain(ctx context.Context) {
	for ctx.Err() == nil {
		c.mu.Lock()
		if c.dbSeen.IsZero() {
			c.mu.Unlock()
			return // no database yet: keep the queue for when one loads
		}
		var d string
		for k := range c.queue {
			d = k
			break
		}
		if d == "" {
			c.mu.Unlock()
			return
		}
		delete(c.queue, d)
		e := c.entries[d]
		c.mu.Unlock()
		if e == nil {
			continue
		}
		c.matchOne(ctx, d, e)
	}
}

func (c *Coordinator) matchOne(ctx context.Context, digest string, e *entry) {
	db := c.Matcher.DB()
	mctx, cancel := context.WithTimeout(ctx, c.MatchTimeout)
	start := c.now()
	vulns, err := c.Matcher.Match(mctx, e.sbom)
	cancel()
	if c.Metrics != nil {
		c.Metrics.GrypeMatchSeconds.Observe(c.now().Sub(start).Seconds())
	}
	if err != nil {
		c.count("error")
		if c.Log != nil {
			c.Log.WithError(err).WithField("digest", digest).Warn("matching failed")
		}
		return
	}
	c.count("ok")
	c.mu.Lock()
	if cur := c.entries[digest]; cur == e {
		e.matchedDB = db.Built
	}
	c.mu.Unlock()
	if vulns == nil {
		vulns = []types.Vulnerability{}
	}
	built := db.Built
	c.Sink.Enqueue(trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: digest, Vulns: &types.ImageVulnerabilities{
		SchemaVersion:   types.SchemaVersion,
		Image:           e.sbom.Image,
		Source:          types.SourceGrype,
		SBOMSource:      e.sbom.Source,
		Scanner:         c.Matcher.Scanner(),
		ScannedAt:       c.now().UTC(),
		DBUpdatedAt:     &built,
		ObservedIn:      e.sbom.ObservedIn,
		Vulnerabilities: vulns,
	}})
	if c.Metrics != nil {
		c.Metrics.GrypeMatches.Add(float64(len(vulns)))
	}
}

func (c *Coordinator) count(result string) {
	if c.Metrics != nil {
		c.Metrics.GrypeMatchRuns.WithLabelValues(result).Inc()
	}
}

func (c *Coordinator) gaugesLocked() {
	if c.Metrics != nil {
		c.Metrics.GrypeSBOMsHeld.Set(float64(len(c.entries)))
	}
}

// fingerprint covers what matching depends on: the components.
func fingerprint(s *types.ImageSBOM) string {
	b, _ := json.Marshal(s.Components)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
