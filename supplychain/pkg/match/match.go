// Package match turns stored SBOMs into vulnerability payloads with a
// Matcher (the Grype sidecar), independent of which Matcher is used.
//
// Registry SBOMs are unverified: anyone who can push to an image's
// repository can attach one. So an unverified document may only ADD to
// what is matched, never remove from it. For each image the matcher's
// input is the UNION of every SBOM held for it - Trivy's SbomReport (a
// scan of the running image), any registry SBOM and the node catalog's
// SBOM (the same image cataloged on a node that runs it) - with duplicate
// packages merged. Trivy's entries are authoritative; a registry SBOM
// only adds to them; a node SBOM only adds to both. A registry SBOM that
// lists fewer packages than Trivy found can therefore never hide a
// finding, and a node SBOM, however partial, never removes, changes or
// re-attributes a finding the other sources give.
//
// Join key. BuildKit registry SBOMs are keyed by a platform manifest
// digest (with image.index_digest set), while Trivy usually reports the
// index digest. A platform SBOM whose index has a Trivy SBOM is folded
// into the index's group, so the two meet; it is not matched on its own
// (an unverified document is never the only input while Trivy's exists).
// A node SBOM does not change grouping: it joins whatever group its
// digest is matched in.
//
// A node SBOM describes one platform of its inventory digest. When it is
// its group's only input the payload is pinned to that platform (see
// PinPlatform), so its findings reach no other platform of an index. With
// Trivy's or a registry SBOM in the group it is not pinned: the payload
// keeps the links those sources give, and the node SBOM only adds
// packages to them.
//
// Everything held is re-matched when the Matcher reports a new database,
// without fetching any SBOM again.
package match

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	bytes    int64 // heldBytes(sbom)
}

// DefaultMaxHeldBytes bounds the SBOMs held for re-matching (see
// Coordinator.MaxHeldBytes).
const DefaultMaxHeldBytes = 96 << 20

// heldBytes estimates what sbom keeps alive on the heap: the component
// structs and every string they reference. A fat Debian image's file
// lists dominate. It is an estimate for a budget, not an exact count;
// TestHeldBytesTracksTheHeap checks it against the runtime.
func heldBytes(sbom *types.ImageSBOM) int64 {
	const (
		structOverhead = 1024 // ImageSBOM header, maps and held entry
		componentSize  = 176  // types.Component: 8 strings + 2 slices
		stringHeader   = 16
	)
	// str is one string allocation: decoded JSON gives every string its
	// own, rounded up to a 16-byte size class, except that strings under
	// 16 bytes share tiny-allocator blocks.
	str := func(s string) int64 {
		if len(s) < 16 {
			return int64(len(s))
		}
		return int64((len(s) + 15) &^ 15)
	}
	n := int64(structOverhead) + int64(cap(sbom.Components))*componentSize
	for i := range sbom.Components {
		c := &sbom.Components[i]
		n += str(c.Name) + str(c.Version) + str(c.PURL) + str(c.Type) + str(c.Class) +
			str(c.SrcName) + str(c.SrcVersion) + str(c.LayerDigest)
		n += int64(cap(c.Licenses)+cap(c.FilePaths)) * stringHeader
		for _, l := range c.Licenses {
			n += str(l)
		}
		for _, f := range c.FilePaths {
			n += str(f)
		}
	}
	return n
}

type groupState struct {
	fingerprint string
	matchedDB   time.Time
	// touched is when an SBOM of the group was last offered; groups whose
	// SBOMs are no longer held are pruned oldest first past MaxDigests.
	touched time.Time

	// Failures of the current input (failFP against failDB). Reset when
	// either changes; at the threshold the group is quarantined: not
	// matched again until its SBOM or the database changes.
	failFP      string
	failDB      time.Time
	failures    int
	crashes     int
	quarantined string // why; empty when not quarantined
	// quarantinedAt and expires: an error quarantine (not too large, not
	// a crash) lifts after its TTL for one more try; errorQuarantines
	// counts them for this input, doubling the TTL each time.
	quarantinedAt    time.Time
	expires          bool
	errorQuarantines int

	// Set by a match that included a node SBOM: lastOthers lists the
	// other SBOMs it matched (digest -> source), lastNode the digests whose
	// node SBOM it matched. The group is not matched again while one of
	// lastOthers is not held (evicted, and not offered again yet), so the
	// broker keeps that payload rather than one without their findings;
	// and while one of lastNode's node SBOMs is not held it waits for it up
	// to NodeRefetchGrace, counted from nodeWaitSince. Nil after a match
	// without a node SBOM: such a group is handled as it always was.
	lastOthers    map[string]map[string]bool
	lastNode      map[string]bool
	nodeWaitSince time.Time
	// othersWaitSince is when the group started waiting for one of
	// lastOthers, lastRefetch when it last asked a source for one with
	// external work; see waitLocked for the cap.
	othersWaitSince time.Time
	lastRefetch     time.Time
}

// maxErrorQuarantineTTL caps the doubling of ErrorQuarantineTTL.
const maxErrorQuarantineTTL = 24 * time.Hour

// ttlLocked is how long gs's current error quarantine lasts:
// ErrorQuarantineTTL, doubled for every earlier quarantine of the same
// input, at most maxErrorQuarantineTTL.
func (c *Coordinator) ttlLocked(gs *groupState) time.Duration {
	ttl := c.ErrorQuarantineTTL
	for i := 1; i < gs.errorQuarantines && ttl < maxErrorQuarantineTTL; i++ {
		ttl *= 2
	}
	return min(ttl, maxErrorQuarantineTTL)
}

// Quarantine thresholds: a match that is too large fails the same way
// every time, so once is enough; other errors may be transient.
const (
	quarantineAfterErrors  = 3
	quarantineAfterCrashes = 2
)

// Coordinator holds SBOMs and schedules matching on one worker.
type Coordinator struct {
	Matcher Matcher
	Sink    trivy.Sink
	Log     *logrus.Logger
	Metrics *metrics.Metrics
	// MaxDigests bounds the digests whose SBOMs are held, and separately
	// the groups whose match state (fingerprint, database, quarantine) is
	// kept. Default 2000.
	MaxDigests int
	// MaxHeldBytes bounds the estimated heap the held SBOMs use (see
	// heldBytes). Past it, and past MaxDigests, whole groups' SBOMs are
	// dropped, least recently offered first, but only groups that need
	// nothing more: matched at the current database, or quarantined, and
	// not queued, retried or in flight. Their match state is kept, so an
	// unchanged re-offer is not matched again and a quarantine holds. A
	// group still waiting for its match is never dropped, so the budget
	// can be exceeded until it is matched (e.g. before the first database
	// loads). Default DefaultMaxHeldBytes.
	MaxHeldBytes int64
	// MaxComponents caps one match's input after de-duplication.
	// Default DefaultMaxComponents.
	MaxComponents int
	// MatchTimeout bounds one match. Default 2m.
	MatchTimeout time.Duration
	// ErrorQuarantineTTL is how long a group quarantined by repeated
	// errors waits before one more try, doubling each time the same input
	// is quarantined again (at most 24h). Too-large and crash quarantines
	// wait for an SBOM or database change instead. Default 1h.
	ErrorQuarantineTTL time.Duration
	// NodeRefetchGrace is how long a group whose node SBOM was evicted
	// waits for it, once its other SBOMs are all held again, before it is
	// matched without it. Default 10m (twice the node source's default
	// interval).
	NodeRefetchGrace time.Duration
	// NodeGroupMaxWait caps how long such a group waits for the other
	// SBOMs of its last match (after an eviction, until their sources
	// emit them again or declare them gone), counted from the later of
	// the start of the wait and its last external refetch, and at most
	// twice this from the start. Past it the group is matched with what it
	// holds, under the usual union rules, and counted in
	// kguardian_supplychain_grype_node_group_wait_expired_total.
	// Default 30m.
	NodeGroupMaxWait time.Duration
	// RefetchMinInterval and RefetchMaxInterval bound how often one SBOM
	// is asked of its source again (see allowRefetchLocked). Defaults 10m
	// (Trivy's resync period) and 24h (the registry recheck).
	RefetchMinInterval time.Duration
	RefetchMaxInterval time.Duration
	// CrashDir, when set, holds a marker for each match in flight
	// (written before, removed after). A marker left behind means the
	// process died mid-match (e.g. OOMKilled); after
	// quarantineAfterCrashes such deaths for the same input the group is
	// quarantined, so one digest cannot crash every pass. It must survive
	// a container restart (the chart's /tmp emptyDir does). Markers are
	// per group key and written atomically, so concurrent matches of
	// different groups cannot collide; a replica has its own emptyDir.
	CrashDir string

	now    func() time.Time
	mu     sync.Mutex
	sboms  map[string]map[string]*held // digest -> source -> SBOM
	groups map[string]*groupState
	queue  map[string]struct{}
	// retry holds groups whose match found the matcher unavailable; the
	// ticker queues them again. unavailable* summarise one pass of them
	// for a single log line.
	retry             map[string]struct{}
	heldBytes         int64  // sum of held.bytes
	inflight          string // the group being matched
	unavailable       int
	unavailableSample string
	unavailableErr    error
	notify            chan struct{}
	dbSeen            time.Time
	// lastNodeIn maps a digest to the group whose last match included its
	// node SBOM (groupState.lastNode), for Wants. Entries go when that
	// group is matched without it, or with the group's state if
	// pruneGroupsLocked drops it, so the map is bounded by the kept state.
	lastNodeIn map[string]string
	// nodeWait holds groups waiting for evicted SBOMs; the ticker queues
	// them again (for the grace and the cap to take effect).
	nodeWait map[string]struct{}
	// nodeGroups holds the groups whose last match included a node SBOM
	// (groupState.lastNode set): Gone and pruning look only at these.
	nodeGroups map[string]struct{}
	// refetchers are the sources that can emit an SBOM again on request,
	// by source name; refetchQueue collects requests made under mu, run
	// after it is released (a source's lock may be held while it offers).
	refetchers   map[string]Refetcher
	refetchQueue []refetchRequest
	refetchState map[refetchRequest]refetchBackoff
	// budgetWarned: when the "budget too small" warning was last logged
	// (at most hourly).
	budgetWarned time.Time
	// nodeHeld counts the digests with a node SBOM held; 0 (node source
	// off) short-cuts every node check. nodeSeen: a node SBOM was ever
	// offered; until then no match keeps groupState.lastOthers.
	nodeHeld int
	nodeSeen bool
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
	if c.MaxHeldBytes <= 0 {
		c.MaxHeldBytes = DefaultMaxHeldBytes
	}
	if c.MaxComponents <= 0 {
		c.MaxComponents = DefaultMaxComponents
	}
	if c.MatchTimeout <= 0 {
		c.MatchTimeout = 2 * time.Minute
	}
	if c.ErrorQuarantineTTL <= 0 {
		c.ErrorQuarantineTTL = time.Hour
	}
	if c.retry == nil {
		c.retry = map[string]struct{}{}
	}
	if c.lastNodeIn == nil {
		c.lastNodeIn = map[string]string{}
		c.nodeWait = map[string]struct{}{}
		c.nodeGroups = map[string]struct{}{}
	}
	if c.NodeRefetchGrace <= 0 {
		c.NodeRefetchGrace = 10 * time.Minute
	}
	if c.NodeGroupMaxWait <= 0 {
		c.NodeGroupMaxWait = 30 * time.Minute
	}
	if c.RefetchMinInterval <= 0 {
		c.RefetchMinInterval = 10 * time.Minute
	}
	if c.RefetchMaxInterval < c.RefetchMinInterval {
		c.RefetchMaxInterval = max(24*time.Hour, c.RefetchMinInterval)
	}
	if c.refetchState == nil {
		c.refetchState = map[refetchRequest]refetchBackoff{}
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
	_, hadNode := c.sboms[d][types.SourceNode]
	if sbom.Source == types.SourceNode && len(sbom.Components) == 0 && !hadNode {
		// An empty node SBOM releases one held; with none held (evicted,
		// or never offered) there is nothing to release, and matching it
		// would only produce an empty payload.
		c.mu.Unlock()
		return
	}
	h := &held{sbom: sbom, lastUsed: c.now(), bytes: heldBytes(sbom)}
	// The digest may move groups (a registry SBOM re-offered under
	// another index). When a node SBOM is involved, the group it leaves
	// is matched again without it, so node components do not linger
	// there; without one this is left as it always was.
	oldKey, oldHadNode := "", false
	if _, ok := c.sboms[d]; ok {
		oldKey = c.groupKeyLocked(d)
		oldHadNode = c.groupHoldsNodeLocked(oldKey)
	}
	if old, ok := c.sboms[d][sbom.Source]; ok {
		c.heldBytes -= old.bytes
		delete(c.sboms[d], sbom.Source)
	}
	c.evictLocked(d, h.bytes)
	if _, ok := c.sboms[d]; !ok {
		c.sboms[d] = map[string]*held{}
	}
	c.sboms[d][sbom.Source] = h
	c.heldBytes += h.bytes
	if sbom.Source == types.SourceNode {
		c.nodeSeen = true
		if !hadNode {
			c.nodeHeld++
		}
	}
	k := c.groupKeyLocked(d)
	c.queue[k] = struct{}{}
	if oldKey != "" && oldKey != k &&
		(sbom.Source == types.SourceNode || oldHadNode || c.groupHoldsNodeLocked(k)) {
		c.queue[oldKey] = struct{}{}
	}
	gs := c.groups[k]
	if gs == nil {
		gs = &groupState{}
		c.groups[k] = gs
	}
	gs.touched = h.lastUsed
	c.pruneGroupsLocked()
	c.gaugesLocked()
	c.mu.Unlock()
	c.flushRefetches()
	c.wake()
}

// Refetcher is a source that can supply an SBOM again on request (Trivy's
// tracker, the registry source). Refetch must not block or call back into
// the coordinator: it is called outside the coordinator's lock, but from
// Offer and the match loop.
type Refetcher interface {
	// Refetch returns digest's SBOM when the source holds it (the
	// coordinator offers it directly: it never reaches the broker), or nil
	// after arranging to emit it again on the source's next pass, marked
	// match-only when it has not changed (trivy.Emission.MatchOnly), so
	// the broker never sees a re-upload caused by a refetch.
	Refetch(digest string) *types.ImageSBOM
}

type refetchRequest struct {
	source, digest string
}

// InMemoryRefetcher is a Refetcher that answers from what it holds (no
// network, nothing sent to the broker), like Trivy's tracker. Its
// refetches are not rate-limited.
type InMemoryRefetcher interface {
	Refetcher
	RefetchesFromMemory() bool
}

func inMemory(f Refetcher) bool {
	m, ok := f.(InMemoryRefetcher)
	return ok && m.RefetchesFromMemory()
}

// SetRefetcher registers the source that can emit source's SBOMs again.
// Only groups whose last match included a node SBOM ever ask.
func (c *Coordinator) SetRefetcher(source string, r Refetcher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if c.refetchers == nil {
		c.refetchers = map[string]Refetcher{}
	}
	c.refetchers[source] = r
}

// flushRefetches runs the refetch requests queued under mu.
func (c *Coordinator) flushRefetches() {
	c.mu.Lock()
	reqs := c.refetchQueue
	c.refetchQueue = nil
	rs := c.refetchers
	c.mu.Unlock()
	for _, r := range reqs {
		if f := rs[r.source]; f != nil {
			if sb := f.Refetch(r.digest); sb != nil {
				c.Offer(sb)
			}
		}
	}
}

// refetchBackoff rate-limits refetches of one (source, digest).
type refetchBackoff struct {
	next    time.Time
	backoff time.Duration
}

// allowRefetchLocked reports whether (source, digest) may be refetched now,
// at most once per window, doubling from RefetchMinInterval up to
// RefetchMaxInterval, so a group that keeps being dropped and waiting does
// not keep its sources busy. Counted by result (requested, limited).
func (c *Coordinator) allowRefetchLocked(r refetchRequest) bool {
	now := c.now()
	b := c.refetchState[r]
	if now.Before(b.next) {
		c.countRefetch(r.source, "limited")
		return false
	}
	if len(c.refetchState) >= c.MaxDigests*maxWaitingGroupsFactor {
		// Forget entries whose window has long closed.
		for k, v := range c.refetchState {
			if now.Sub(v.next) >= c.RefetchMaxInterval {
				delete(c.refetchState, k)
			}
		}
	}
	b.backoff = min(max(b.backoff*2, c.RefetchMinInterval), c.RefetchMaxInterval)
	b.next = now.Add(b.backoff)
	c.refetchState[r] = b
	c.countRefetch(r.source, "requested")
	return true
}

func (c *Coordinator) countRefetch(source, result string) {
	if c.Metrics != nil {
		c.Metrics.GrypeRefetches.WithLabelValues(source, result).Inc()
	}
}

// Gone tells the coordinator that source's SBOM for digest is gone for
// good (the registry no longer has it, the Trivy report was deleted). A
// group whose last match included it stops waiting for it. Groups that
// never matched a node SBOM keep no such requirement, so this changes
// nothing for them.
func (c *Coordinator) Gone(digest, source string) {
	c.mu.Lock()
	c.init()
	for key, gs := range c.groups {
		if !gs.lastOthers[digest][source] {
			continue
		}
		delete(gs.lastOthers[digest], source)
		if len(gs.lastOthers[digest]) == 0 {
			delete(gs.lastOthers, digest)
		}
		c.queue[key] = struct{}{}
	}
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

// groupHoldsNodeLocked reports whether any SBOM matched under key is a
// node SBOM.
func (c *Coordinator) groupHoldsNodeLocked(key string) bool {
	if c.nodeHeld == 0 {
		return false
	}
	for d, bySrc := range c.sboms {
		if _, ok := bySrc[types.SourceNode]; ok && c.groupKeyLocked(d) == key {
			return true
		}
	}
	return false
}

// Holds reports whether an SBOM from source is held for digest.
func (c *Coordinator) Holds(digest, source string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.sboms[digest][source]
	return ok
}

// Wants reports whether digest's node SBOM is awaited: the last match of
// its group included it, it is no longer held (evicted), and every other
// SBOM of that match is held again, so the group is waiting for it (up to
// NodeRefetchGrace) before it is matched. The node source then offers it
// again. At any other time an evicted node SBOM is not wanted: offered
// while the group's other SBOMs are missing, it would not be matched.
func (c *Coordinator) Wants(digest string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	gs := c.groups[c.lastNodeIn[digest]]
	if gs == nil || !gs.lastNode[digest] {
		return false
	}
	_, held := c.sboms[digest][types.SourceNode]
	return !held && c.othersHeldLocked(gs)
}

// othersHeldLocked reports whether every non-node SBOM of gs's last match
// is held (in whatever group it is now: one that moved has changed).
func (c *Coordinator) othersHeldLocked(gs *groupState) bool {
	for d, srcs := range gs.lastOthers {
		for src := range srcs {
			if _, ok := c.sboms[d][src]; !ok {
				return false
			}
		}
	}
	return true
}

// Why a group is not matched yet (waitLocked).
const (
	matchReady = iota
	waitOthers
	waitNode
)

// waitLocked decides whether group key may be matched now. After a match
// that included a node SBOM, the group waits while any other SBOM of that
// match is not held (for ever: until then the broker keeps that payload,
// as it keeps any evicted group's), then for its node SBOMs up to
// NodeRefetchGrace.
func (c *Coordinator) waitLocked(key string) int {
	gs := c.groups[key]
	if gs == nil || (gs.lastOthers == nil && gs.lastNode == nil) {
		return matchReady
	}
	// Only a group whose last match, or whose union now, has a node SBOM
	// waits; any other is matched as it always was.
	if gs.lastNode == nil && !c.groupHoldsNodeLocked(key) {
		return matchReady
	}
	if !c.othersHeldLocked(gs) {
		now := c.now()
		if gs.othersWaitSince.IsZero() {
			gs.othersWaitSince = now
		}
		// Ask the sources for what is missing, on every pass while the
		// group waits (the ticker brings it back): Trivy re-emits only a
		// changed SBOM, and the registry source rechecks daily. A source
		// that answers from memory is asked every time; one that does
		// external work is spaced by the per-SBOM backoff.
		for d, srcs := range gs.lastOthers {
			for src := range srcs {
				f := c.refetchers[src]
				if _, held := c.sboms[d][src]; held || f == nil {
					continue
				}
				r := refetchRequest{src, d}
				if inMemory(f) {
					c.refetchQueue = append(c.refetchQueue, r)
				} else if c.allowRefetchLocked(r) {
					c.refetchQueue = append(c.refetchQueue, r)
					gs.lastRefetch = now
				}
			}
		}
		// The cap runs from the later of the start of the wait and the
		// last external refetch, so an SBOM asked for late still has
		// NodeGroupMaxWait to arrive; and never past twice the cap from
		// the start, so the wait always ends.
		from := gs.othersWaitSince
		if gs.lastRefetch.After(from) {
			from = gs.lastRefetch
		}
		if now.Sub(from) < c.NodeGroupMaxWait && now.Sub(gs.othersWaitSince) < 2*c.NodeGroupMaxWait {
			return waitOthers
		}
		// Waited long enough: matched with what it holds.
		gs.othersWaitSince, gs.nodeWaitSince, gs.lastRefetch = time.Time{}, time.Time{}, time.Time{}
		gs.lastOthers = nil
		if c.Metrics != nil {
			c.Metrics.GrypeNodeGroupWaitExpired.Inc()
		}
		if c.Log != nil {
			c.Log.WithField("digest", key).Info("SBOMs of a group's last match did not come back in time; matching what is held")
			if now.Sub(c.budgetWarned) >= time.Hour {
				c.budgetWarned = now
				c.Log.Warn("groups with node SBOMs are being matched without SBOMs dropped to stay within the SBOM budget; " +
					"raise GRYPE_SBOM_BUDGET_MIB (see kguardian_supplychain_grype_node_group_wait_expired_total)")
			}
		}
		return matchReady
	}
	gs.othersWaitSince, gs.lastRefetch = time.Time{}, time.Time{}
	for d := range gs.lastNode {
		if _, held := c.sboms[d][types.SourceNode]; held {
			continue
		}
		now := c.now()
		if gs.nodeWaitSince.IsZero() {
			gs.nodeWaitSince = now
		}
		if now.Sub(gs.nodeWaitSince) < c.NodeRefetchGrace {
			return waitNode
		}
		break // waited long enough: matched without it
	}
	gs.nodeWaitSince = time.Time{}
	return matchReady
}

// recordMatchLocked notes what a successful match of group key included
// (see groupState.lastOthers).
func (c *Coordinator) recordMatchLocked(key string, gs *groupState, in *union) {
	for d := range gs.lastNode {
		if !in.nodes[d] && c.lastNodeIn[d] == key {
			delete(c.lastNodeIn, d)
		}
	}
	gs.nodeWaitSince, gs.othersWaitSince, gs.lastRefetch = time.Time{}, time.Time{}, time.Time{}
	// The refetch backoff is not reset here: registry refetches keep
	// their doubling window across matches, so a group dropped over and
	// over cannot turn into a lookup per pass (and trip registry rate
	// limits for everything else). In-memory refetches are never limited.
	if len(in.nodes) == 0 {
		// Kept (once any node SBOM has been seen) so that a node SBOM
		// joining this group later cannot be matched without them.
		gs.lastOthers, gs.lastNode = nil, nil
		if c.nodeSeen {
			gs.lastOthers = in.others
		}
		delete(c.nodeGroups, key)
		return
	}
	gs.lastOthers, gs.lastNode = in.others, in.nodes
	c.nodeGroups[key] = struct{}{}
	for d := range in.nodes {
		c.lastNodeIn[d] = key
	}
}

// forgetGroupLocked drops what Wants and Gone know of group gk.
func (c *Coordinator) forgetGroupLocked(gk string) {
	if gs := c.groups[gk]; gs != nil {
		for d := range gs.lastNode {
			if c.lastNodeIn[d] == gk {
				delete(c.lastNodeIn, d)
			}
		}
	}
	delete(c.nodeWait, gk)
	delete(c.nodeGroups, gk)
}

// groupKeyLocked is the digest a digest's SBOMs are matched under: its
// index when that index has a Trivy SBOM, else itself. A node SBOM does
// not change this: on a digest whose index has Trivy's SBOM it joins
// that group, adding only.
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

// settledLocked reports whether group k needs nothing more from its held
// SBOMs until something changes: matched at the current database (or
// quarantined) and not queued, waiting for a retry or being matched.
func (c *Coordinator) settledLocked(k string) bool {
	if _, q := c.queue[k]; q {
		return false
	}
	if _, r := c.retry[k]; r {
		return false
	}
	gs := c.groups[k]
	if k == c.inflight || gs == nil {
		return false
	}
	// A group waiting for the other SBOMs of its last match, or for its
	// node SBOM past the grace, needs nothing more from what it holds
	// until they come back: its requirement lives in groupState, so its
	// SBOMs can go.
	if !gs.othersWaitSince.IsZero() || (!gs.nodeWaitSince.IsZero() && c.now().Sub(gs.nodeWaitSince) >= c.NodeRefetchGrace) {
		return true
	}
	return gs.quarantined != "" || (!c.dbSeen.IsZero() && gs.matchedDB.Equal(c.dbSeen))
}

// evictLocked drops held SBOMs, a whole group at a time and least
// recently offered first, until one more SBOM of size bytes for digest
// keep (empty: none) fits MaxDigests and MaxHeldBytes. Only settled
// groups are dropped, and only their SBOMs: groupState and the queue are
// kept. If nothing is settled it stops over budget.
func (c *Coordinator) evictLocked(keep string, bytes int64) {
	keepKey := ""
	if keep != "" {
		keepKey = c.groupKeyLocked(keep)
	}
	for {
		_, have := c.sboms[keep]
		tooMany := keep != "" && !have && len(c.sboms) >= c.MaxDigests
		tooBig := c.heldBytes+bytes > c.MaxHeldBytes
		if !tooMany && !tooBig {
			return
		}
		members := map[string][]string{}
		last := map[string]time.Time{}
		for d, bySrc := range c.sboms {
			k := c.groupKeyLocked(d)
			members[k] = append(members[k], d)
			for _, h := range bySrc {
				if h.lastUsed.After(last[k]) {
					last[k] = h.lastUsed
				}
			}
		}
		victim := ""
		for k := range members {
			if k == keepKey || k == keep || !c.settledLocked(k) {
				continue
			}
			if victim == "" || last[k].Before(last[victim]) || (last[k].Equal(last[victim]) && k < victim) {
				victim = k
			}
		}
		if victim == "" {
			return // everything else still needs matching: hold over budget
		}
		reason := "digests"
		if tooBig {
			reason = "bytes"
		}
		for _, d := range members[victim] {
			for src, h := range c.sboms[d] {
				c.heldBytes -= h.bytes
				if src == types.SourceNode {
					c.nodeHeld--
				}
			}
			delete(c.sboms, d)
			if c.Metrics != nil {
				c.Metrics.GrypeSBOMsEvicted.WithLabelValues(reason).Inc()
			}
		}
	}
}

// maxWaitingGroupsFactor bounds the kept state of groups whose last match
// included a node SBOM: past MaxDigests*maxWaitingGroupsFactor groups,
// pruneGroupsLocked drops them too (oldest first), and such a group may
// then be matched from a partial re-offer.
const maxWaitingGroupsFactor = 4

// pruneGroupsLocked keeps the match state of at most MaxDigests groups,
// dropping first the least recently offered whose SBOMs are no longer
// held and that are not queued, retried or in flight.
func (c *Coordinator) pruneGroupsLocked() {
	// Two limits: groups whose last match did not include a node SBOM at
	// most MaxDigests; all groups at most MaxDigests*maxWaitingGroupsFactor.
	// Without node SBOMs nodeGroups is empty and this is the one limit it
	// always was. Nothing to do while both hold.
	plain := len(c.groups) - len(c.nodeGroups)
	if plain <= c.MaxDigests && len(c.groups) <= c.MaxDigests*maxWaitingGroupsFactor {
		return
	}
	heldKeys := map[string]bool{}
	for d := range c.sboms {
		heldKeys[c.groupKeyLocked(d)] = true
	}
	var idle []string
	for k := range c.groups {
		_, q := c.queue[k]
		_, r := c.retry[k]
		if !heldKeys[k] && !q && !r && k != c.inflight {
			idle = append(idle, k)
		}
	}
	sort.Slice(idle, func(i, j int) bool { return c.groups[idle[i]].touched.Before(c.groups[idle[j]].touched) })
	// Groups whose last match included a node SBOM go last, and only far
	// past the bound: dropping their state would let a partial re-offer
	// through before NodeGroupMaxWait.
	for _, k := range idle {
		if plain <= c.MaxDigests {
			break
		}
		if _, n := c.nodeGroups[k]; n {
			continue
		}
		delete(c.groups, k)
		plain--
	}
	for _, k := range idle {
		if len(c.groups) <= c.MaxDigests*maxWaitingGroupsFactor {
			break
		}
		if _, n := c.nodeGroups[k]; !n {
			continue
		}
		c.forgetGroupLocked(k)
		delete(c.groups, k)
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
	c.loadCrashesLocked()
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
			c.mu.Lock()
			c.requeueLocked()
			c.mu.Unlock()
		}
	}
}

// logUnavailable writes one WARN for the digests a pass could not match
// because the matcher was unreachable (count plus one example).
func (c *Coordinator) logUnavailable() {
	c.mu.Lock()
	n, sample, err := c.unavailable, c.unavailableSample, c.unavailableErr
	c.unavailable, c.unavailableSample, c.unavailableErr = 0, "", nil
	c.mu.Unlock()
	if n > 0 && c.Log != nil {
		c.Log.WithError(err).WithFields(logrus.Fields{"digests": n, "example": sample}).
			Warn("matcher unavailable; will retry on the next tick")
	}
}

// requeueLocked queues again the groups a tick should retry: those that
// found the matcher unavailable, and error quarantines whose TTL is up.
func (c *Coordinator) requeueLocked() {
	for k := range c.retry {
		c.queue[k] = struct{}{}
		delete(c.retry, k)
	}
	for k := range c.nodeWait {
		c.queue[k] = struct{}{}
		delete(c.nodeWait, k)
	}
	now := c.now()
	for k, gs := range c.groups {
		if gs.quarantined != "" && gs.expires && !now.Before(gs.quarantinedAt.Add(c.ttlLocked(gs))) {
			c.queue[k] = struct{}{}
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
	defer c.logUnavailable()
	for ctx.Err() == nil {
		c.flushRefetches() // requested by the previous iteration
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
		switch c.waitLocked(key) {
		case waitOthers:
			// Matched when the missing SBOMs are offered again or declared
			// gone, or at NodeGroupMaxWait: the ticker looks again.
			c.nodeWait[key] = struct{}{}
			c.mu.Unlock()
			continue
		case waitNode:
			c.nodeWait[key] = struct{}{} // looked at again next tick
			c.mu.Unlock()
			continue
		}
		in := c.unionLocked(key)
		gs := c.groups[key]
		if gs == nil {
			gs = &groupState{}
			c.groups[key] = gs
		}
		db := c.dbSeen
		skip := in == nil || (gs.fingerprint == in.fingerprint && gs.matchedDB.Equal(db))
		if !skip && (gs.failFP != in.fingerprint || !gs.failDB.Equal(db)) {
			// A new SBOM or database: start over, quarantine lifted.
			gs.failFP, gs.failDB, gs.failures, gs.crashes, gs.quarantined = "", time.Time{}, 0, 0, ""
			gs.errorQuarantines = 0
			c.gaugesLocked()
		}
		if !skip && gs.quarantined != "" {
			if gs.expires && !c.now().Before(gs.quarantinedAt.Add(c.ttlLocked(gs))) {
				// One more try; a failure re-quarantines at once.
				gs.quarantined, gs.expires, gs.failures = "", false, quarantineAfterErrors-1
				c.gaugesLocked()
				if c.Log != nil {
					c.Log.WithField("digest", key).Info("retrying a digest quarantined by errors")
				}
			} else {
				skip = true
			}
		}
		crashes := gs.crashes
		if !skip {
			c.inflight = key
		}
		c.mu.Unlock()
		if !skip {
			c.matchOne(ctx, key, in, db, crashes)
		}
		// The group may be settled now: bring what is held back within
		// budget.
		c.mu.Lock()
		c.inflight = ""
		c.evictLocked("", 0)
		c.gaugesLocked()
		c.mu.Unlock()
		c.flushRefetches()
	}
}

// union is one group's matcher input.
type union struct {
	sbom        *types.ImageSBOM
	sources     []string
	trust       string
	observedIn  []types.WorkloadRef
	fingerprint string
	// pinned: the inputs are node SBOMs only, so the payload is limited to
	// the node's platform (empty when the catalog did not record one).
	pinned   bool
	platform string
	// nodes: digests whose node SBOM is an input; others: the other
	// inputs (digest -> sources). Recorded by a match (recordMatchLocked).
	nodes  map[string]bool
	others map[string]map[string]bool
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
	// The payload's image (and so the inventory images the broker links
	// it to) comes from Trivy's SBOM, else from the first other non-node
	// SBOM, exactly as without a node SBOM; from the node SBOM only when
	// it is the only input. A node SBOM never changes where the findings
	// of the other sources are linked.
	var img *types.ImageRef
	nodeOnly := true
	for _, m := range members {
		if !slices.Contains(u.sources, m.Source) {
			u.sources = append(u.sources, m.Source)
		}
		if types.TrustRank(m.SBOMTrust) < types.TrustRank(u.trust) {
			u.trust = m.SBOMTrust
		}
		if m.Source == types.SourceNode {
			if u.nodes == nil {
				u.nodes = map[string]bool{}
			}
			u.nodes[m.Image.Digest] = true
		} else {
			if u.others == nil {
				u.others = map[string]map[string]bool{}
			}
			if u.others[m.Image.Digest] == nil {
				u.others[m.Image.Digest] = map[string]bool{}
			}
			u.others[m.Image.Digest][m.Source] = true
		}
		switch m.Source {
		case types.SourceTrivyOperator:
			img = &m.Image
			u.observedIn = m.ObservedIn
		case types.SourceNode:
			u.platform = m.Platform
		default:
			if img == nil {
				img = &m.Image
			}
		}
		if m.Source != types.SourceNode {
			nodeOnly = false
		}
	}
	if img == nil {
		img = &members[0].Image
	}
	sort.Strings(u.sources)
	image := *img
	image.Digest = key
	// Pinned only when the node SBOM is alone: then no other source's
	// links exist to lose. With Trivy or a registry SBOM in the group the
	// node SBOM only adds components, and the links stay theirs.
	u.pinned = nodeOnly
	if u.pinned {
		PinPlatform(&image, u.platform)
	}
	img = &image
	u.sbom = &types.ImageSBOM{Image: *img, Components: comps}
	b, _ := json.Marshal(comps)
	if u.pinned {
		b = append(b, "\x00platform="+u.platform...)
	}
	sum := sha256.Sum256(b)
	u.fingerprint = hex.EncodeToString(sum[:])
	return u
}

// PinPlatform limits img to one platform: only platform's entry in
// PlatformManifests is kept and IndexDigest is cleared. The broker links a
// payload to the inventory images its digest, platform manifests and index
// name, so this keeps a match of a single-platform SBOM (the node
// catalog's) off every other platform of the index.
//
// The node reports "os/arch" or "os/arch/variant" (the Controller sends
// linux/arm64, linux/arm), while index keys often carry a variant
// (linux/arm64/v8, linux/arm/v7). See platformKey for how they are paired.
// When the pairing is ambiguous nothing is changed: failing open keeps
// every link, where a wrong pin would drop one. When platform is empty or
// names no platform of the index, no platform manifest is kept.
func PinPlatform(img *types.ImageRef, platform string) {
	key, ok := platformKey(img.PlatformManifests, platform)
	if !ok {
		return
	}
	var kept map[string]string
	if key != "" {
		kept = map[string]string{key: img.PlatformManifests[key]}
	}
	img.PlatformManifests = kept
	img.IndexDigest = ""
}

// platformKey finds the entry of manifests that platform names: an exact
// match; else, for a platform without a variant, the one entry with the
// same os/arch, or among several the default variant (v8 for arm64);
// else, for one with a variant, the one entry that platform is a prefix of
// or that is a prefix of it. It returns "", true when no entry matches and
// ok false when several do and none is the default.
func platformKey(manifests map[string]string, platform string) (string, bool) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		return "", true
	}
	if _, ok := manifests[platform]; ok {
		return platform, true
	}
	parts := strings.Split(platform, "/")
	if len(parts) < 2 {
		return "", true
	}
	osArch := parts[0] + "/" + parts[1]
	var candidates []string
	for k := range manifests {
		kp := strings.Split(strings.ToLower(k), "/")
		if len(kp) < 2 || kp[0]+"/"+kp[1] != osArch {
			continue
		}
		// Same os/arch. With a variant on both sides they must agree.
		if len(parts) > 2 && len(kp) > 2 && kp[2] != parts[2] {
			continue
		}
		candidates = append(candidates, k)
	}
	switch len(candidates) {
	case 0:
		return "", true
	case 1:
		return candidates[0], true
	}
	if len(parts) == 2 {
		defaults := map[string]string{"arm64": "v8"}
		if v, ok := defaults[parts[1]]; ok {
			for _, k := range candidates {
				if strings.EqualFold(k, osArch+"/"+v) {
					return k, true
				}
			}
		}
	}
	return "", false
}

func (c *Coordinator) matchOne(ctx context.Context, key string, in *union, db time.Time, crashes int) {
	// Not deferred: a marker must outlive a process that dies mid-match.
	marker := c.writeMarker(key, in.fingerprint, db, crashes)
	mctx, cancel := context.WithTimeout(ctx, c.MatchTimeout)
	start := c.now()
	vulns, err := c.Matcher.Match(mctx, in.sbom)
	cancel()
	c.removeMarker(marker)
	if err != nil && ctx.Err() != nil {
		return // our own shutdown: neither a failure nor a retry
	}
	if c.Metrics != nil {
		c.Metrics.GrypeMatchSeconds.Observe(c.now().Sub(start).Seconds())
	}
	if err != nil {
		c.failed(key, in.fingerprint, db, err)
		return
	}
	c.count("ok")
	c.mu.Lock()
	if gs := c.groups[key]; gs != nil {
		c.recordMatchLocked(key, gs, in)
		gs.fingerprint, gs.matchedDB = in.fingerprint, db
		gs.failFP, gs.failDB, gs.failures, gs.crashes, gs.quarantined = "", time.Time{}, 0, 0, ""
		gs.errorQuarantines = 0
	}
	c.gaugesLocked()
	c.mu.Unlock()
	if vulns == nil {
		vulns = []types.Vulnerability{}
	}
	built := db
	c.Sink.Enqueue(trivy.Emission{Kind: trivy.KindVulnerabilities, Digest: key, PinPlatform: in.pinned, Platform: in.platform, Vulns: &types.ImageVulnerabilities{
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

// failed records a failed match and quarantines the group when the same
// input keeps failing. A too-large result is logged as such (it is not a
// transient error) and quarantines at once.
func (c *Coordinator) failed(key, fp string, db time.Time, err error) {
	if errors.Is(err, ErrUnavailable) {
		// The matcher could not be reached or was not ready: not the
		// SBOM's fault, so never a step towards quarantine. Retried on the
		// next tick; drain logs one line per pass for all of them.
		c.count("unavailable")
		c.mu.Lock()
		c.retry[key] = struct{}{}
		c.unavailable++
		if c.unavailableSample == "" {
			c.unavailableSample, c.unavailableErr = key, err
		}
		c.mu.Unlock()
		if c.Log != nil {
			c.Log.WithError(err).WithField("digest", key).Debug("matcher unavailable; will retry")
		}
		return
	}
	tooLarge := errors.Is(err, ErrTooLarge)
	reason := "error"
	switch {
	case tooLarge:
		reason = "too_large"
	case errors.Is(err, ErrTruncated):
		reason = "truncated"
	}
	if tooLarge {
		c.count("too_large")
	} else {
		c.count("error")
	}
	c.mu.Lock()
	gs := c.groups[key]
	if gs == nil {
		gs = &groupState{}
		c.groups[key] = gs
	}
	if gs.failFP != fp || !gs.failDB.Equal(db) {
		gs.failFP, gs.failDB, gs.failures, gs.crashes, gs.errorQuarantines = fp, db, 0, 0, 0
	}
	gs.failures++
	failures := gs.failures
	threshold := quarantineAfterErrors
	if tooLarge {
		threshold = 1
	}
	quarantine := gs.quarantined == "" && failures >= threshold
	if !quarantine && gs.quarantined == "" {
		// Not yet quarantined: try again on the next tick, so a failing
		// input reaches its verdict in a few minutes.
		c.retry[key] = struct{}{}
	}
	if quarantine {
		gs.quarantined = fmt.Sprintf("%s: %v", reason, err)
		gs.quarantinedAt, gs.expires = c.now(), !tooLarge
		if !tooLarge {
			gs.errorQuarantines++
		}
		c.gaugesLocked()
	}
	c.mu.Unlock()
	if c.Log != nil {
		msg := "matching failed"
		if tooLarge {
			msg = "match result too large"
		}
		c.Log.WithError(err).WithFields(logrus.Fields{"digest": key, "reason": reason, "failures": failures}).Warn(msg)
		if quarantine {
			until := "until its SBOM or the vulnerability database changes"
			if !tooLarge {
				c.mu.Lock()
				ttl := c.ttlLocked(gs)
				c.mu.Unlock()
				until = fmt.Sprintf("for %s, or until its SBOM or the vulnerability database changes", ttl)
			}
			c.Log.WithFields(logrus.Fields{"digest": key, "reason": reason, "failures": failures}).
				Warn("digest quarantined: not matched again " + until)
		}
	}
	if quarantine {
		c.count("quarantined")
	}
}

// crashMarker is what writeMarker leaves for the duration of one match.
type crashMarker struct {
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	DB          time.Time `json:"db"`
	// Crashes before this attempt (from earlier markers).
	Crashes int `json:"crashes"`
}

func (c *Coordinator) markerPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.CrashDir, "inflight-"+hex.EncodeToString(sum[:])+".json")
}

// writeMarker records the match about to run; "" when crash tracking is
// off or the marker cannot be written (matching goes ahead regardless).
func (c *Coordinator) writeMarker(key, fp string, db time.Time, crashes int) string {
	if c.CrashDir == "" {
		return ""
	}
	b, _ := json.Marshal(crashMarker{Key: key, Fingerprint: fp, DB: db, Crashes: crashes})
	path := c.markerPath(key)
	if err := os.MkdirAll(c.CrashDir, 0o700); err == nil {
		tmp, err := os.CreateTemp(c.CrashDir, ".marker-*")
		if err == nil {
			_, werr := tmp.Write(b)
			cerr := tmp.Close()
			if werr == nil && cerr == nil && os.Rename(tmp.Name(), path) == nil {
				return path
			}
			_ = os.Remove(tmp.Name())
		}
	}
	if c.Log != nil {
		c.Log.WithField("dir", c.CrashDir).Warn("cannot write the in-flight match marker; crash quarantine is off for this match")
	}
	return ""
}

func (c *Coordinator) removeMarker(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// loadCrashesLocked turns markers left by a process that died mid-match
// into crash counts, quarantining a group whose same input has now
// crashed quarantineAfterCrashes times, and removes them.
func (c *Coordinator) loadCrashesLocked() {
	if c.CrashDir == "" {
		return
	}
	paths, _ := filepath.Glob(filepath.Join(c.CrashDir, "inflight-*.json"))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		_ = os.Remove(p)
		var m crashMarker
		if err != nil || json.Unmarshal(b, &m) != nil || m.Key == "" || p != c.markerPath(m.Key) {
			continue
		}
		crashes := m.Crashes + 1
		gs := &groupState{failFP: m.Fingerprint, failDB: m.DB, failures: crashes, crashes: crashes}
		if crashes >= quarantineAfterCrashes {
			gs.quarantined = fmt.Sprintf("crashed during match (%d times)", crashes)
			c.count("quarantined")
		}
		c.groups[m.Key] = gs
		if c.Log != nil {
			e := c.Log.WithFields(logrus.Fields{"digest": m.Key, "crashes": crashes})
			if gs.quarantined != "" {
				e.Warn("digest quarantined: the process died while matching it; not matched again until its SBOM or the vulnerability database changes")
			} else {
				e.Warn("the previous run died while matching this digest; it will be tried once more")
			}
		}
	}
	c.gaugesLocked()
}

func (c *Coordinator) count(result string) {
	if c.Metrics != nil {
		c.Metrics.GrypeMatchRuns.WithLabelValues(result).Inc()
	}
}

func (c *Coordinator) gaugesLocked() {
	if c.Metrics != nil {
		c.Metrics.GrypeSBOMsHeld.Set(float64(len(c.sboms)))
		c.Metrics.GrypeSBOMBytesHeld.Set(float64(c.heldBytes))
		q := 0
		for _, gs := range c.groups {
			if gs.quarantined != "" {
				q++
			}
		}
		c.Metrics.GrypeQuarantined.Set(float64(q))
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

// purlKey is a component's package identity from its PURL, without
// qualifiers or subpath: "type/namespace/name@version", percent-decoded.
// It is "" when there is no PURL with a type, name and version. Only
// normalisations that cannot merge two different packages are made:
//
//   - deb and rpm: an epoch given as the "epoch" qualifier (Trivy) is put
//     in front of the version, where Syft writes it ("1:2.36.1-8"), and an
//     epoch of 0, which both package managers treat as no epoch, is
//     dropped; the namespace (the distro) is lower-cased.
//   - golang stdlib: Trivy writes "v1.22.1", Syft "go1.22.1" or "1.22.1";
//     the prefix is dropped (only for stdlib, the one package that has it).
//   - pypi: the name is normalised as PEP 503 and the purl spec require.
//
// Maven needs nothing: both write pkg:maven/<groupId>/<artifactId>@<v>,
// while their component names differ ("org.example:lib" and "lib").
func purlKey(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	rest = strings.TrimLeft(rest, "/")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	quals := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, quals = rest[:i], rest[i+1:]
	}
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return ""
	}
	ver, err := url.PathUnescape(rest[at+1:])
	if err != nil || ver == "" {
		return ""
	}
	segs := strings.Split(rest[:at], "/")
	if len(segs) < 2 {
		return ""
	}
	for i := range segs {
		if segs[i], err = url.PathUnescape(segs[i]); err != nil {
			return ""
		}
	}
	typ := strings.ToLower(segs[0])
	name := segs[len(segs)-1]
	ns := strings.Join(segs[1:len(segs)-1], "/")
	if typ == "" || name == "" {
		return ""
	}
	switch typ {
	case "deb", "rpm":
		ns = strings.ToLower(ns)
		epoch := ""
		if q, err := url.ParseQuery(quals); err == nil {
			epoch = q.Get("epoch")
		}
		if e, v, found := strings.Cut(ver, ":"); found {
			epoch, ver = e, v
		}
		if epoch != "" && epoch != "0" {
			ver = epoch + ":" + ver
		}
	case "golang":
		if ns == "" && name == "stdlib" {
			if v, found := strings.CutPrefix(ver, "go"); found {
				ver = v
			} else if v, found := strings.CutPrefix(ver, "v"); found {
				ver = v
			}
		}
	case "pypi":
		name = pep503(name)
	}
	return typ + "/" + ns + "/" + name + "@" + ver
}

// pep503 normalises a Python package name: lower case, and each run of
// "-", "_" and "." as one "-".
func pep503(name string) string {
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteRune(r)
	}
	return b.String()
}

// mergeComponents returns the union of the members' components and how
// many were dropped by the cap. Trivy's scan is authoritative; registry
// SBOMs are unverified and may only add; a node catalog SBOM adds last,
// so it never removes or changes anything the other two contribute:
//
//   - Every Trivy component is kept exactly as Trivy reported it. On a
//     collision a registry entry may only add file paths and licences, and
//     fill a PURL Trivy left empty; it never changes Trivy's PURL (distro,
//     arch, upstream), source package or version.
//   - The operating-system component is Trivy's when it has one; a
//     registry one is used only when Trivy has none, and a node one only
//     when the node SBOM is the only input.
//   - The cap never evicts a Trivy component (unless Trivy alone exceeds
//     it). Registry SBOMs fill only the capacity left over, split evenly
//     between them, so a registry SBOM full of junk cannot crowd out
//     Trivy's packages or another SBOM's. Node components fill what is
//     left after that. What does not fit is counted as dropped.
//   - Between registry SBOMs the first to name a package wins, on the same
//     add-only terms.
//   - A node component that collides with any entry adds only its file
//     paths and licences; it never fills a PURL, so no finding of the
//     other sources is re-attributed. So a node SBOM, however partial,
//     can only add packages to the union, never remove or change one.
//
// Components collide when they share type, name and version (see
// componentKey). A node component also collides with an entry whose PURL
// names the same package (see purlKey), which catches what the names miss
// (Trivy's "org.example:lib" and Syft's "lib" for one Maven artifact).
// The PURL match is used for node components only: Trivy and registry
// components de-duplicate among themselves exactly as without a node SBOM,
// so adding one never changes how the others merge.
func mergeComponents(members []*types.ImageSBOM, max int) ([]types.Component, int) {
	if max <= 0 {
		max = int(^uint(0) >> 1)
	}
	var trivySBOMs, nodeSBOMs, others []*types.ImageSBOM
	for _, m := range members {
		switch m.Source {
		case types.SourceTrivyOperator:
			trivySBOMs = append(trivySBOMs, m)
		case types.SourceNode:
			nodeSBOMs = append(nodeSBOMs, m)
		default:
			others = append(others, m)
		}
	}
	byKey := map[string]*types.Component{}  // componentKey -> entry
	byPURL := map[string]*types.Component{} // purlKey -> entry
	// PURL keys are indexed only with a node SBOM in the union, and looked
	// up only for node components (viaPURL): without one the union
	// de-duplicates exactly as it always has.
	usePURL := len(nodeSBOMs) > 0
	var osComp *types.Component
	find := func(c types.Component, viaPURL bool) *types.Component {
		if pk := purlKey(c.PURL); viaPURL && pk != "" {
			if cur := byPURL[pk]; cur != nil {
				return cur
			}
		}
		return byKey[componentKey(c)]
	}
	index := func(cur *types.Component) {
		if !usePURL {
			return
		}
		if pk := purlKey(cur.PURL); pk != "" && byPURL[pk] == nil {
			byPURL[pk] = cur
		}
	}
	insert := func(c types.Component) string {
		cc := c
		cc.FilePaths = slices.Clone(c.FilePaths)
		cc.Licenses = slices.Clone(c.Licenses)
		k := componentKey(c)
		byKey[k] = &cc
		index(&cc)
		return k
	}
	remove := func(k string) {
		cur := byKey[k]
		delete(byKey, k)
		if pk := purlKey(cur.PURL); pk != "" && byPURL[pk] == cur {
			delete(byPURL, pk)
		}
	}
	addOnly := func(cur *types.Component, c types.Component, fillPURL bool) {
		if fillPURL && cur.PURL == "" && c.PURL != "" {
			cur.PURL = c.PURL
			index(cur)
		}
		cur.FilePaths = unionStrings(cur.FilePaths, c.FilePaths)
		cur.Licenses = unionStrings(cur.Licenses, c.Licenses)
	}
	cloneOS := func(c types.Component) *types.Component {
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
					osComp = cloneOS(c)
				}
				continue
			}
			if cur := find(c, false); cur != nil {
				addOnly(cur, c, true)
				continue
			}
			base = append(base, insert(c))
		}
	}
	sort.Strings(base)
	dropped := 0
	room := max - len(base)
	if osComp != nil {
		room--
	}
	if room < 0 {
		// Trivy alone exceeds the cap (not seen in practice). As on main
		// the trimmed entries stay in byKey (and, with a node SBOM, in
		// byPURL): a lower component colliding with one merges into it
		// and is not output nor counted as dropped.
		dropped += -room
		base = base[:len(base)+room]
		room = 0
	}

	// addFrom merges one lower SBOM, add-only, keeping at most share of
	// its new components (lowest keys first) and taking its OS component
	// only when none is held yet. It returns the new keys kept. A node
	// SBOM fills no PURL, and its OS component is used only when it is the
	// only input: the OS sets the distro every package is matched under,
	// so taking it beside another source would re-attribute that source's
	// packages.
	nodeOnly := len(trivySBOMs) == 0 && len(others) == 0
	addFrom := func(m *types.ImageSBOM, share int, node bool) []string {
		fillPURL := !node
		var fresh []string
		for _, c := range m.Components {
			if c.Type == "operating-system" {
				if osComp == nil && (!node || nodeOnly) {
					if room > 0 {
						osComp = cloneOS(c)
						room--
						share = min(share, room)
					} else {
						dropped++
					}
				}
				continue
			}
			if cur := find(c, node); cur != nil {
				addOnly(cur, c, fillPURL)
				continue
			}
			fresh = append(fresh, insert(c))
		}
		sort.Strings(fresh)
		if len(fresh) > share {
			for _, k := range fresh[share:] {
				remove(k)
			}
			dropped += len(fresh) - share
			fresh = fresh[:share]
		}
		room -= len(fresh)
		return fresh
	}

	// Registry SBOMs: add-only, within an even share of what is left.
	var added []string
	for i, m := range others {
		added = append(added, addFrom(m, room/(len(others)-i), false)...)
	}
	sort.Strings(added)

	// Node SBOMs: add-only against everything above, in what is left.
	var fromNode []string
	for _, m := range nodeSBOMs {
		fromNode = append(fromNode, addFrom(m, room, true)...)
	}
	sort.Strings(fromNode)

	out := make([]types.Component, 0, len(base)+len(added)+len(fromNode)+1)
	if osComp != nil {
		out = append(out, *osComp)
	}
	for _, k := range base {
		out = append(out, *byKey[k])
	}
	for _, k := range added {
		out = append(out, *byKey[k])
	}
	for _, k := range fromNode {
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
