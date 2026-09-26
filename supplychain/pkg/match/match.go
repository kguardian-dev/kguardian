// Package match turns stored SBOMs into vulnerability payloads with a
// Matcher (the Grype sidecar), independent of which Matcher is used.
//
// Registry SBOMs are unverified: anyone who can push to an image's
// repository can attach one. So an unverified document may only ADD to
// what is matched, never remove from it. For each image the matcher's
// input is the UNION of every SBOM held for it - Trivy's SbomReport (a
// scan of the running image) and any registry SBOM - with duplicate
// packages merged. A registry SBOM that lists fewer packages than Trivy
// found can therefore never hide a finding.
//
// Join key. BuildKit registry SBOMs are keyed by a platform manifest
// digest (with image.index_digest set), while Trivy usually reports the
// index digest. A platform SBOM whose index has a Trivy SBOM is folded
// into the index's group, so the two meet; it is not matched on its own
// (an unverified document is never the only input while Trivy's exists).
//
// Everything held is re-matched when the Matcher reports a new database,
// without fetching any SBOM again.
package match

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strings"
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

// DefaultMaxComponents matches the sidecar's per-request limit.
const DefaultMaxComponents = 50000

type held struct {
	sbom     *types.ImageSBOM
	lastUsed time.Time
}

type groupState struct {
	fingerprint string
	matchedDB   time.Time
}

// Coordinator holds SBOMs and schedules matching on one worker.
type Coordinator struct {
	Matcher Matcher
	Sink    trivy.Sink
	Log     *logrus.Logger
	Metrics *metrics.Metrics
	// MaxDigests bounds the digests whose SBOMs are held. Default 2000.
	MaxDigests int
	// MaxComponents caps one match's input after de-duplication.
	// Default DefaultMaxComponents.
	MaxComponents int
	// MatchTimeout bounds one match. Default 2m.
	MatchTimeout time.Duration

	now    func() time.Time
	mu     sync.Mutex
	sboms  map[string]map[string]*held // digest -> source -> SBOM
	groups map[string]*groupState
	queue  map[string]struct{}
	notify chan struct{}
	dbSeen time.Time
}

func (c *Coordinator) init() {
	if c.sboms == nil {
		c.sboms = map[string]map[string]*held{}
		c.groups = map[string]*groupState{}
		c.queue = map[string]struct{}{}
		c.notify = make(chan struct{}, 1)
	}
	if c.MaxDigests <= 0 {
		c.MaxDigests = 2000
	}
	if c.MaxComponents <= 0 {
		c.MaxComponents = DefaultMaxComponents
	}
	if c.MatchTimeout <= 0 {
		c.MatchTimeout = 2 * time.Minute
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// Offer records an SBOM (replacing the previous one from the same source
// for the same digest) and queues its group for matching. Never blocks.
func (c *Coordinator) Offer(sbom *types.ImageSBOM) {
	if sbom == nil || sbom.Image.Digest == "" || sbom.Page != nil {
		return
	}
	c.mu.Lock()
	c.init()
	d := sbom.Image.Digest
	if _, ok := c.sboms[d]; !ok {
		c.evictLocked()
		c.sboms[d] = map[string]*held{}
	}
	c.sboms[d][sbom.Source] = &held{sbom: sbom, lastUsed: c.now()}
	c.queue[c.groupKeyLocked(d)] = struct{}{}
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

// parentLocked returns the index a digest's SBOMs name, if any.
func (c *Coordinator) parentLocked(d string) string {
	for _, h := range c.sboms[d] {
		if h.sbom.Image.IndexDigest != "" && h.sbom.Image.IndexDigest != d {
			return h.sbom.Image.IndexDigest
		}
	}
	return ""
}

// groupKeyLocked is the digest a digest's SBOMs are matched under: its
// index when that index has a Trivy SBOM, else itself.
func (c *Coordinator) groupKeyLocked(d string) string {
	if p := c.parentLocked(d); p != "" {
		if _, ok := c.sboms[p][types.SourceTrivyOperator]; ok {
			return p
		}
	}
	return d
}

// membersLocked returns the SBOMs matched under key: Trivy's first.
func (c *Coordinator) membersLocked(key string) []*types.ImageSBOM {
	var out []*types.ImageSBOM
	add := func(d string) {
		srcs := make([]string, 0, len(c.sboms[d]))
		for s := range c.sboms[d] {
			srcs = append(srcs, s)
		}
		sort.Slice(srcs, func(i, j int) bool {
			return srcs[i] == types.SourceTrivyOperator || (srcs[j] != types.SourceTrivyOperator && srcs[i] < srcs[j])
		})
		for _, s := range srcs {
			out = append(out, c.sboms[d][s].sbom)
		}
	}
	add(key)
	var children []string
	for d := range c.sboms {
		if d != key && c.groupKeyLocked(d) == key {
			children = append(children, d)
		}
	}
	sort.Strings(children)
	for _, d := range children {
		add(d)
	}
	return out
}

func (c *Coordinator) evictLocked() {
	for len(c.sboms) >= c.MaxDigests {
		var oldest string
		var t time.Time
		for d, bySrc := range c.sboms {
			for _, h := range bySrc {
				if oldest == "" || h.lastUsed.Before(t) {
					oldest, t = d, h.lastUsed
				}
			}
		}
		if oldest == "" {
			return
		}
		delete(c.sboms, oldest)
		delete(c.groups, oldest)
		delete(c.queue, oldest)
	}
}

func (c *Coordinator) wake() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// Held returns the number of digests with SBOMs held.
func (c *Coordinator) Held() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sboms)
}

// Run matches queued groups until ctx is cancelled, polling the Matcher's
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
	for d := range c.sboms {
		c.queue[c.groupKeyLocked(d)] = struct{}{}
	}
	if !first && c.Log != nil {
		c.Log.WithFields(logrus.Fields{"built": db.Built, "held": len(c.sboms)}).
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
		var key string
		for k := range c.queue {
			key = k
			break
		}
		if key == "" {
			c.mu.Unlock()
			return
		}
		delete(c.queue, key)
		if c.groupKeyLocked(key) != key {
			c.mu.Unlock()
			continue // folded into its index's group
		}
		in := c.unionLocked(key)
		gs := c.groups[key]
		if gs == nil {
			gs = &groupState{}
			c.groups[key] = gs
		}
		db := c.dbSeen
		skip := in == nil || (gs.fingerprint == in.fingerprint && gs.matchedDB.Equal(db))
		c.mu.Unlock()
		if !skip {
			c.matchOne(ctx, key, in, db)
		}
	}
}

// union is one group's matcher input.
type union struct {
	sbom        *types.ImageSBOM
	sources     []string
	trust       string
	observedIn  []types.WorkloadRef
	fingerprint string
}

func (c *Coordinator) unionLocked(key string) *union {
	members := c.membersLocked(key)
	if len(members) == 0 {
		return nil
	}
	comps, clamped := mergeComponents(members, c.MaxComponents)
	if clamped > 0 {
		if c.Metrics != nil {
			c.Metrics.GrypeComponentsClamped.Inc()
		}
		if c.Log != nil {
			c.Log.WithFields(logrus.Fields{"digest": key, "dropped": clamped, "max": c.MaxComponents}).
				Warn("SBOM union exceeds the component limit; matching a truncated set")
		}
	}
	u := &union{trust: types.SBOMTrustVerified}
	img := members[0].Image
	for _, m := range members {
		if !slices.Contains(u.sources, m.Source) {
			u.sources = append(u.sources, m.Source)
		}
		if types.TrustRank(m.SBOMTrust) < types.TrustRank(u.trust) {
			u.trust = m.SBOMTrust
		}
		if m.Source == types.SourceTrivyOperator {
			img = m.Image
			u.observedIn = m.ObservedIn
		}
	}
	sort.Strings(u.sources)
	img.Digest = key
	u.sbom = &types.ImageSBOM{Image: img, Components: comps}
	b, _ := json.Marshal(comps)
	sum := sha256.Sum256(b)
	u.fingerprint = hex.EncodeToString(sum[:])
	return u
}

func (c *Coordinator) matchOne(ctx context.Context, key string, in *union, db time.Time) {
	mctx, cancel := context.WithTimeout(ctx, c.MatchTimeout)
	start := c.now()
	vulns, err := c.Matcher.Match(mctx, in.sbom)
	cancel()
	if c.Metrics != nil {
		c.Metrics.GrypeMatchSeconds.Observe(c.now().Sub(start).Seconds())
	}
	if err != nil {
		c.count("error")
		if c.Log != nil {
			c.Log.WithError(err).WithField("digest", key).Warn("matching failed")
		}
		return
	}
	c.count("ok")
	c.mu.Lock()
	if gs := c.groups[key]; gs != nil {
		gs.fingerprint, gs.matchedDB = in.fingerprint, db
	}
	c.mu.Unlock()
	if vulns == nil {
		vulns = []types.Vulnerability{}
	}
	built := db
	c.Sink.Enqueue(trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: key, Vulns: &types.ImageVulnerabilities{
		SchemaVersion:   types.SchemaVersion,
		Image:           in.sbom.Image,
		Source:          types.SourceGrype,
		SBOMSources:     in.sources,
		SBOMTrust:       in.trust,
		Scanner:         c.Matcher.Scanner(),
		ScannedAt:       c.now().UTC(),
		DBUpdatedAt:     &built,
		ObservedIn:      in.observedIn,
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
		c.Metrics.GrypeSBOMsHeld.Set(float64(len(c.sboms)))
	}
}

// --- union of components ---------------------------------------------

// osTypes maps Trivy's distro-named package types onto PURL types, so a
// Trivy "debian" package and a registry "deb" PURL de-duplicate.
var osTypes = map[string]string{
	"debian": "deb", "ubuntu": "deb", "distroless": "deb",
	"alpine": "apk", "wolfi": "apk", "chainguard": "apk",
	"redhat": "rpm", "centos": "rpm", "rocky": "rpm", "alma": "rpm", "amazon": "rpm",
	"oracle": "rpm", "suse": "rpm", "opensuse": "rpm", "opensuse.leap": "rpm", "sles": "rpm",
	"photon": "rpm", "fedora": "rpm", "cbl-mariner": "rpm", "azurelinux": "rpm",
}

func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}

func componentKey(c types.Component) string {
	t := purlType(c.PURL)
	if t == "" {
		t = strings.ToLower(c.Type)
		if m, ok := osTypes[t]; ok {
			t = m
		}
	}
	return t + "\x00" + c.Name + "\x00" + c.Version
}

// mergeComponents returns the union of the members' components and how
// many were dropped by the cap. Trivy's scan is authoritative; registry
// SBOMs are unverified and may only add:
//
//   - Every Trivy component is kept exactly as Trivy reported it. On a
//     collision (same type, name and version) a registry entry may only add
//     file paths and licences, and fill a PURL Trivy left empty; it never
//     changes Trivy's PURL (distro, arch, upstream), source package or
//     version.
//   - The operating-system component is Trivy's when it has one; a
//     registry one is used only when Trivy has none.
//   - The cap never evicts a Trivy component (unless Trivy alone exceeds
//     it). Registry components fill only the capacity left over, split
//     evenly between registry SBOMs, so one SBOM full of junk cannot crowd
//     out another; what does not fit is counted as dropped.
//   - Between registry SBOMs the first to name a package wins, on the same
//     add-only terms.
func mergeComponents(members []*types.ImageSBOM, max int) ([]types.Component, int) {
	if max <= 0 {
		max = int(^uint(0) >> 1)
	}
	var trivySBOMs, others []*types.ImageSBOM
	for _, m := range members {
		if m.Source == types.SourceTrivyOperator {
			trivySBOMs = append(trivySBOMs, m)
		} else {
			others = append(others, m)
		}
	}
	byKey := map[string]*types.Component{}
	var osComp *types.Component
	addOnly := func(cur *types.Component, c types.Component) {
		if cur.PURL == "" {
			cur.PURL = c.PURL
		}
		cur.FilePaths = unionStrings(cur.FilePaths, c.FilePaths)
		cur.Licenses = unionStrings(cur.Licenses, c.Licenses)
	}
	clone := func(c types.Component) *types.Component {
		cc := c
		cc.FilePaths = slices.Clone(c.FilePaths)
		cc.Licenses = slices.Clone(c.Licenses)
		return &cc
	}

	// Trivy first: authoritative, never evicted.
	var base []string
	for _, m := range trivySBOMs {
		for _, c := range m.Components {
			if c.Type == "operating-system" {
				if osComp == nil {
					osComp = clone(c)
				}
				continue
			}
			k := componentKey(c)
			if cur, ok := byKey[k]; ok {
				addOnly(cur, c)
				continue
			}
			byKey[k] = clone(c)
			base = append(base, k)
		}
	}
	sort.Strings(base)
	dropped := 0
	room := max - len(base)
	if osComp != nil {
		room--
	}
	if room < 0 {
		// Trivy alone exceeds the cap (not seen in practice).
		dropped += -room
		base = base[:len(base)+room]
		room = 0
	}

	// Registry SBOMs: add-only, within an even share of what is left.
	var added []string
	for i, m := range others {
		share := room / (len(others) - i)
		var fresh []string
		for _, c := range m.Components {
			if c.Type == "operating-system" {
				if osComp == nil {
					osComp = clone(c)
					if room > 0 {
						room--
						share = min(share, room)
					} else {
						dropped++
						osComp = nil
					}
				}
				continue
			}
			k := componentKey(c)
			if cur, ok := byKey[k]; ok {
				addOnly(cur, c)
				continue
			}
			byKey[k] = clone(c)
			fresh = append(fresh, k)
		}
		sort.Strings(fresh)
		if len(fresh) > share {
			for _, k := range fresh[share:] {
				delete(byKey, k)
			}
			dropped += len(fresh) - share
			fresh = fresh[:share]
		}
		room -= len(fresh)
		added = append(added, fresh...)
	}
	sort.Strings(added)

	out := make([]types.Component, 0, len(base)+len(added)+1)
	if osComp != nil {
		out = append(out, *osComp)
	}
	for _, k := range base {
		out = append(out, *byKey[k])
	}
	for _, k := range added {
		out = append(out, *byKey[k])
	}
	return out, dropped
}

func unionStrings(a, b []string) []string {
	for _, s := range b {
		if !slices.Contains(a, s) {
			a = append(a, s)
		}
	}
	sort.Strings(a)
	return a
}
