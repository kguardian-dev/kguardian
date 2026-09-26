package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// Kind is the payload family an Emission carries.
type Kind string

// Payload kinds.
const (
	KindVulnerabilities Kind = "vulnerabilities"
	KindSBOM            Kind = "sbom"
)

// DigestResolver resolves the digest a workload container is actually
// running, for reports that name the image only by tag. The planned
// implementation asks the broker's image inventory (built from pod
// containerStatuses[].imageID); until that endpoint exists no resolver is
// configured and such reports are held back.
type DigestResolver interface {
	ResolveDigest(ctx context.Context, w types.WorkloadRef, imageRef string) (string, error)
}

// Emission is one payload ready for the broker. Exactly one of Vulns/SBOM
// is set, matching Kind. The payload is the receiver's own copy.
type Emission struct {
	Kind   Kind
	Digest string
	Vulns  *types.ImageVulnerabilities
	SBOM   *types.ImageSBOM
}

// objEntry is what the tracker remembers about one Kubernetes report
// object: only its identity and which digest it points at. The payload
// itself lives once per digest, except for a report still waiting for a
// digest, which keeps its own (pendingV/pendingS) until resolved.
type objEntry struct {
	workload types.WorkloadRef
	ref      string
	digest   string // "" while unresolved
	pendingV *types.ImageVulnerabilities
	pendingS *types.ImageSBOM
}

// digestState holds the single payload kept for one (kind, digest) - the
// newest scan seen from any report - plus the reports that point at it.
type digestState struct {
	vulns *types.ImageVulnerabilities
	sbom  *types.ImageSBOM
	refs  map[string]types.WorkloadRef
}

type sentKey struct {
	kind   Kind
	digest string
}

type sentState struct {
	fingerprint string
	scannedAt   time.Time
}

// Tracker turns report churn into per-digest emissions. Many reports (one
// per workload container) usually describe the same image; the tracker
// keeps one payload per (kind, digest) - memory scales with distinct
// images, not with replicas or workloads - and only emits when that
// payload's content changes. It is safe for concurrent use.
type Tracker struct {
	resolver DigestResolver

	mu          sync.Mutex
	vulnObjs    map[string]*objEntry
	sbomObjs    map[string]*objEntry
	vulnDigests map[string]*digestState
	sbomDigests map[string]*digestState
	sent        map[sentKey]sentState
}

// NewTracker returns an empty tracker. resolver may be nil.
func NewTracker(resolver DigestResolver) *Tracker {
	return &Tracker{
		resolver:    resolver,
		vulnObjs:    map[string]*objEntry{},
		sbomObjs:    map[string]*objEntry{},
		vulnDigests: map[string]*digestState{},
		sbomDigests: map[string]*digestState{},
		sent:        map[sentKey]sentState{},
	}
}

func objectKey(m reportMeta) string {
	if m.UID != "" {
		return m.UID
	}
	return m.Namespace + "/" + m.Name
}

// resolve returns the digest for a report: the one it states, else one
// correlated from another report for the same workload container, else
// the external resolver's answer, else "".
func (t *Tracker) resolve(ctx context.Context, stated string, w types.WorkloadRef, ref string) string {
	if stated != "" {
		return stated
	}
	t.mu.Lock()
	d := t.correlateLocked(w, ref)
	t.mu.Unlock()
	if d != "" {
		return d
	}
	return t.resolveExternal(ctx, w, ref)
}

// UpsertVulnerabilityReport records r (add or update) and returns the
// emissions it causes.
func (t *Tracker) UpsertVulnerabilityReport(ctx context.Context, r *VulnerabilityReport) []Emission {
	key := objectKey(r.Metadata)
	w := workloadOf(r.Metadata)
	ref := imageRefOf(r.Report.Registry, r.Report.Artifact, "").Ref
	digest := t.resolve(ctx, NormaliseDigest(r.Report.Artifact.Digest), w, ref)
	payload := NormaliseVulnerabilities(r, digest, nil)
	payload.ObservedIn = nil

	t.mu.Lock()
	defer t.mu.Unlock()
	if digest == "" {
		// Re-check under the lock: a report for the same container may have
		// been recorded between resolve() and here, and it would have missed
		// this one (not yet stored) when it looked for tag-only reports.
		if digest = t.correlateLocked(w, ref); digest != "" {
			payload.Image.Digest = digest
		}
	}
	t.detachLocked(KindVulnerabilities, key, digest)
	e := &objEntry{workload: w, ref: ref, digest: digest}
	t.vulnObjs[key] = e
	if digest == "" {
		e.pendingV = payload
		return nil
	}
	t.attachVulnLocked(key, e, payload)
	var out []Emission
	// The reverse correlation: tag-only SBOMs for the same container.
	for k, se := range t.sbomObjs {
		if se.digest == "" && se.workload == w && se.ref == ref {
			se.digest = digest
			p := se.pendingS
			se.pendingS = nil
			p.Image.Digest = digest
			t.attachSBOMLocked(k, se, p)
			out = appendEmission(out, t.evaluateSBOMLocked(digest))
		}
	}
	return appendEmission(out, t.evaluateVulnsLocked(digest))
}

// UpsertSbomReport records r and returns the emissions it causes. A new
// SBOM can also change vulnerability payloads: it supplies file paths for
// the join, and its digest can resolve tag-only vulnerability reports for
// the same workload container.
func (t *Tracker) UpsertSbomReport(ctx context.Context, r *SbomReport) []Emission {
	key := objectKey(r.Metadata)
	w := workloadOf(r.Metadata)
	ref := imageRefOf(r.Report.Registry, r.Report.Artifact, "").Ref
	digest := t.resolve(ctx, sbomDigest(r), w, ref)
	payload := NormaliseSBOM(r, digest)
	payload.ObservedIn = nil

	t.mu.Lock()
	defer t.mu.Unlock()
	if digest == "" {
		// Re-check under the lock: a report for the same container may have
		// been recorded between resolve() and here, and it would have missed
		// this one (not yet stored) when it looked for tag-only reports.
		if digest = t.correlateLocked(w, ref); digest != "" {
			payload.Image.Digest = digest
		}
	}
	t.detachLocked(KindSBOM, key, digest)
	e := &objEntry{workload: w, ref: ref, digest: digest}
	t.sbomObjs[key] = e
	if digest == "" {
		e.pendingS = payload
		return nil
	}
	t.attachSBOMLocked(key, e, payload)
	// Resolve tag-only vulnerability reports for the same container.
	for k, ve := range t.vulnObjs {
		if ve.digest == "" && ve.workload == w && ve.ref == ref {
			ve.digest = digest
			p := ve.pendingV
			ve.pendingV = nil
			p.Image.Digest = digest
			t.attachVulnLocked(k, ve, p)
		}
	}
	out := appendEmission(nil, t.evaluateSBOMLocked(digest))
	// This digest's vulnerability payload picks up the SBOM's file paths
	// (and any report just resolved above).
	return appendEmission(out, t.evaluateVulnsLocked(digest))
}

// DeleteVulnerabilityReport forgets the report with the given UID (or
// namespace/name). Deleting a report never emits a deletion to the broker:
// image lifetime is owned by the broker's digest GC.
func (t *Tracker) DeleteVulnerabilityReport(r *VulnerabilityReport) []Emission {
	key := objectKey(r.Metadata)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.vulnObjs[key]; !ok {
		return nil
	}
	t.detachLocked(KindVulnerabilities, key, "")
	delete(t.vulnObjs, key)
	return nil
}

// DeleteSbomReport is DeleteVulnerabilityReport for SbomReports. When the
// last SBOM for a digest goes, that digest's vulnerability payload loses
// the joined file paths and is re-emitted.
func (t *Tracker) DeleteSbomReport(r *SbomReport) []Emission {
	key := objectKey(r.Metadata)
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.sbomObjs[key]
	if !ok {
		return nil
	}
	gone := t.detachLocked(KindSBOM, key, "")
	delete(t.sbomObjs, key)
	if gone && prev.digest != "" {
		return appendEmission(nil, t.evaluateVulnsLocked(prev.digest))
	}
	return nil
}

// detachLocked removes object key's reference from the digest it pointed
// at, unless that is newDigest. It reports whether the digest's state was
// dropped because nothing references it any more.
func (t *Tracker) detachLocked(kind Kind, key, newDigest string) bool {
	objs, states := t.vulnObjs, t.vulnDigests
	if kind == KindSBOM {
		objs, states = t.sbomObjs, t.sbomDigests
	}
	prev, ok := objs[key]
	if !ok || prev.digest == "" || prev.digest == newDigest {
		return false
	}
	ds := states[prev.digest]
	if ds == nil {
		return false
	}
	delete(ds.refs, key)
	if len(ds.refs) > 0 {
		return false
	}
	delete(states, prev.digest)
	delete(t.sent, sentKey{kind, prev.digest})
	return true
}

func (t *Tracker) attachVulnLocked(key string, e *objEntry, p *types.ImageVulnerabilities) {
	ds := t.vulnDigests[e.digest]
	if ds == nil {
		ds = &digestState{refs: map[string]types.WorkloadRef{}}
		t.vulnDigests[e.digest] = ds
	}
	ds.refs[key] = e.workload
	if ds.vulns == nil || !p.ScannedAt.Before(ds.vulns.ScannedAt) {
		ds.vulns = p
	}
}

func (t *Tracker) attachSBOMLocked(key string, e *objEntry, p *types.ImageSBOM) {
	ds := t.sbomDigests[e.digest]
	if ds == nil {
		ds = &digestState{refs: map[string]types.WorkloadRef{}}
		t.sbomDigests[e.digest] = ds
	}
	ds.refs[key] = e.workload
	if ds.sbom == nil || !p.ScannedAt.Before(ds.sbom.ScannedAt) {
		ds.sbom = p
	}
}

// Stats reports what the tracker currently holds.
type Stats struct {
	VulnDigests, SBOMDigests         int
	UnresolvedVulns, UnresolvedSBOMs int
	// VulnPayloads/SBOMPayloads count normalised payloads held in memory:
	// one per digest plus one per unresolved report.
	VulnPayloads, SBOMPayloads int
}

// Stats returns current counts for metrics.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Stats{VulnDigests: len(t.vulnDigests), SBOMDigests: len(t.sbomDigests)}
	for _, e := range t.vulnObjs {
		if e.digest == "" {
			s.UnresolvedVulns++
		}
	}
	for _, e := range t.sbomObjs {
		if e.digest == "" {
			s.UnresolvedSBOMs++
		}
	}
	s.VulnPayloads = s.VulnDigests + s.UnresolvedVulns
	s.SBOMPayloads = s.SBOMDigests + s.UnresolvedSBOMs
	return s
}

// correlateLocked finds a digest for a tag-only report from any other
// report about the same workload container and image reference that does
// state one. Matching on the container as well as the ref keeps a moving
// tag from being mapped to another workload's (older or newer) digest.
func (t *Tracker) correlateLocked(w types.WorkloadRef, ref string) string {
	if ref == "" {
		return ""
	}
	for _, e := range t.sbomObjs {
		if e.digest != "" && e.workload == w && e.ref == ref {
			return e.digest
		}
	}
	for _, e := range t.vulnObjs {
		if e.digest != "" && e.workload == w && e.ref == ref {
			return e.digest
		}
	}
	return ""
}

func (t *Tracker) resolveExternal(ctx context.Context, w types.WorkloadRef, ref string) string {
	if t.resolver == nil || ref == "" {
		return ""
	}
	d, err := t.resolver.ResolveDigest(ctx, w, ref)
	if err != nil {
		return ""
	}
	return NormaliseDigest(d)
}

func (t *Tracker) evaluateVulnsLocked(digest string) *Emission {
	ds := t.vulnDigests[digest]
	if ds == nil || ds.vulns == nil {
		return nil
	}
	var sbom *types.ImageSBOM
	if ss := t.sbomDigests[digest]; ss != nil {
		sbom = ss.sbom
	}
	p := withFilePaths(ds.vulns, FilePathsByPURL(sbom))
	p.ObservedIn = nil
	fp := fingerprint(p)
	if !t.shouldSendLocked(sentKey{KindVulnerabilities, digest}, fp, p.ScannedAt) {
		return nil
	}
	p.ObservedIn = workloadsOf(ds.refs)
	return &Emission{Kind: KindVulnerabilities, Digest: digest, Vulns: p}
}

func (t *Tracker) evaluateSBOMLocked(digest string) *Emission {
	ds := t.sbomDigests[digest]
	if ds == nil || ds.sbom == nil {
		return nil
	}
	p := *ds.sbom // shallow copy; the stored payload is never mutated
	p.ObservedIn = nil
	fp := fingerprint(&p)
	if !t.shouldSendLocked(sentKey{KindSBOM, digest}, fp, p.ScannedAt) {
		return nil
	}
	p.Components = append([]types.Component(nil), ds.sbom.Components...)
	p.ObservedIn = workloadsOf(ds.refs)
	return &Emission{Kind: KindSBOM, Digest: digest, SBOM: &p}
}

// shouldSendLocked records and approves a payload unless it is identical to
// the last one sent for the key, or older than it.
func (t *Tracker) shouldSendLocked(k sentKey, fp string, scannedAt time.Time) bool {
	if prev, ok := t.sent[k]; ok {
		if prev.fingerprint == fp || scannedAt.Before(prev.scannedAt) {
			return false
		}
	}
	t.sent[k] = sentState{fingerprint: fp, scannedAt: scannedAt}
	return true
}

func fingerprint(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func workloadsOf(refs map[string]types.WorkloadRef) []types.WorkloadRef {
	seen := map[types.WorkloadRef]struct{}{}
	out := make([]types.WorkloadRef, 0, len(refs))
	for _, w := range refs {
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Container < b.Container
	})
	return out
}

// withFilePaths returns a copy of p whose vulnerabilities also carry the
// file paths the SBOM attributes to their package PURL. p is not modified.
func withFilePaths(p *types.ImageVulnerabilities, byPURL map[string][]string) *types.ImageVulnerabilities {
	cp := *p
	cp.Vulnerabilities = make([]types.Vulnerability, len(p.Vulnerabilities))
	copy(cp.Vulnerabilities, p.Vulnerabilities)
	if len(byPURL) == 0 {
		return &cp
	}
	for i := range cp.Vulnerabilities {
		v := &cp.Vulnerabilities[i]
		extra := byPURL[v.Package.PURL]
		if v.Package.PURL == "" || len(extra) == 0 {
			continue
		}
		set := map[string]struct{}{}
		for _, f := range v.FilePaths {
			set[f] = struct{}{}
		}
		for _, f := range extra {
			set[f] = struct{}{}
		}
		v.FilePaths = sortedKeys(set)
	}
	return &cp
}

func appendEmission(out []Emission, e *Emission) []Emission {
	if e == nil {
		return out
	}
	return append(out, *e)
}
