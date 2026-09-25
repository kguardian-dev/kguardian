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
// is set, matching Kind.
type Emission struct {
	Kind   Kind
	Digest string
	Vulns  *types.ImageVulnerabilities
	SBOM   *types.ImageSBOM
}

type vulnEntry struct {
	workload types.WorkloadRef
	ref      string
	digest   string // "" while unresolved
	// payload is normalised without the SBOM file-path join, which is
	// applied at emission time against whatever SBOM is current.
	payload *types.ImageVulnerabilities
}

type sbomEntry struct {
	workload types.WorkloadRef
	ref      string
	digest   string // "" while unresolved
	payload  *types.ImageSBOM
}

type sentKey struct {
	kind   Kind
	digest string
}

type sentState struct {
	fingerprint string
	scannedAt   time.Time
}

// Tracker holds the latest report per Kubernetes object and turns report
// churn into per-digest emissions. Many reports (one per workload
// container) usually describe the same image; the tracker collapses them
// to one payload per (kind, digest) and only emits when that payload's
// content changes. It is safe for concurrent use.
type Tracker struct {
	resolver DigestResolver

	mu    sync.Mutex
	vulns map[string]*vulnEntry
	sboms map[string]*sbomEntry
	sent  map[sentKey]sentState
}

// NewTracker returns an empty tracker. resolver may be nil.
func NewTracker(resolver DigestResolver) *Tracker {
	return &Tracker{
		resolver: resolver,
		vulns:    map[string]*vulnEntry{},
		sboms:    map[string]*sbomEntry{},
		sent:     map[sentKey]sentState{},
	}
}

func objectKey(m reportMeta) string {
	if m.UID != "" {
		return m.UID
	}
	return m.Namespace + "/" + m.Name
}

// UpsertVulnerabilityReport records r (add or update) and returns the
// emissions it causes.
func (t *Tracker) UpsertVulnerabilityReport(ctx context.Context, r *VulnerabilityReport) []Emission {
	key := objectKey(r.Metadata)
	w := workloadOf(r.Metadata)
	ref := imageRefOf(r.Report.Registry, r.Report.Artifact, "").Ref
	digest := NormaliseDigest(r.Report.Artifact.Digest)
	if digest == "" {
		t.mu.Lock()
		digest = t.correlateLocked(w, ref)
		t.mu.Unlock()
	}
	if digest == "" {
		digest = t.resolveExternal(ctx, w, ref)
	}
	payload := NormaliseVulnerabilities(r, digest, nil)

	t.mu.Lock()
	defer t.mu.Unlock()
	affected := map[string]struct{}{}
	if prev, ok := t.vulns[key]; ok && prev.digest != "" {
		affected[prev.digest] = struct{}{}
	}
	t.vulns[key] = &vulnEntry{workload: w, ref: ref, digest: digest, payload: payload}
	var out []Emission
	if digest != "" {
		affected[digest] = struct{}{}
		// The reverse correlation: a tag-only SBOM for the same container.
		resolvedSBOM := false
		for _, e := range t.sboms {
			if e.digest == "" && e.workload == w && e.ref == ref {
				e.digest = digest
				e.payload.Image.Digest = digest
				resolvedSBOM = true
			}
		}
		if resolvedSBOM {
			out = appendEmission(out, t.evaluateSBOMLocked(digest))
		}
	}
	for _, d := range sortedKeys(affected) {
		out = appendEmission(out, t.evaluateVulnsLocked(d))
	}
	return out
}

// UpsertSbomReport records r and returns the emissions it causes. A new
// SBOM can also change vulnerability payloads: it supplies file paths for
// the join, and its digest can resolve tag-only vulnerability reports for
// the same workload container.
func (t *Tracker) UpsertSbomReport(ctx context.Context, r *SbomReport) []Emission {
	key := objectKey(r.Metadata)
	w := workloadOf(r.Metadata)
	ref := imageRefOf(r.Report.Registry, r.Report.Artifact, "").Ref
	digest := sbomDigest(r)
	if digest == "" {
		t.mu.Lock()
		digest = t.correlateLocked(w, ref)
		t.mu.Unlock()
	}
	if digest == "" {
		digest = t.resolveExternal(ctx, w, ref)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	affected := map[string]struct{}{}
	if prev, ok := t.sboms[key]; ok && prev.digest != "" {
		affected[prev.digest] = struct{}{}
	}
	t.sboms[key] = &sbomEntry{workload: w, ref: ref, digest: digest, payload: NormaliseSBOM(r, digest)}
	if digest != "" {
		affected[digest] = struct{}{}
		// Resolve tag-only vulnerability reports for the same container.
		for _, e := range t.vulns {
			if e.digest == "" && e.workload == w && e.ref == ref {
				e.digest = digest
				e.payload.Image.Digest = digest
			}
		}
	}
	var out []Emission
	for _, d := range sortedKeys(affected) {
		out = appendEmission(out, t.evaluateSBOMLocked(d))
	}
	// The same digests' vulnerability payloads pick up (or lose) this
	// SBOM's file paths.
	for _, d := range sortedKeys(affected) {
		out = appendEmission(out, t.evaluateVulnsLocked(d))
	}
	return out
}

// DeleteVulnerabilityReport forgets the report with the given UID (or
// namespace/name). Deleting a report never emits a deletion to the broker:
// image lifetime is owned by the broker's digest GC. It can emit a new
// payload when another report for the same digest now wins.
func (t *Tracker) DeleteVulnerabilityReport(r *VulnerabilityReport) []Emission {
	key := objectKey(r.Metadata)
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.vulns[key]
	if !ok {
		return nil
	}
	delete(t.vulns, key)
	if prev.digest == "" {
		return nil
	}
	return appendEmission(nil, t.evaluateVulnsLocked(prev.digest))
}

// DeleteSbomReport is DeleteVulnerabilityReport for SbomReports.
func (t *Tracker) DeleteSbomReport(r *SbomReport) []Emission {
	key := objectKey(r.Metadata)
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.sboms[key]
	if !ok {
		return nil
	}
	delete(t.sboms, key)
	if prev.digest == "" {
		return nil
	}
	out := appendEmission(nil, t.evaluateSBOMLocked(prev.digest))
	return appendEmission(out, t.evaluateVulnsLocked(prev.digest))
}

// Stats reports what the tracker currently holds.
type Stats struct {
	VulnDigests, SBOMDigests         int
	UnresolvedVulns, UnresolvedSBOMs int
}

// Stats returns current counts for metrics.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	var s Stats
	vd, sd := map[string]struct{}{}, map[string]struct{}{}
	for _, e := range t.vulns {
		if e.digest == "" {
			s.UnresolvedVulns++
		} else {
			vd[e.digest] = struct{}{}
		}
	}
	for _, e := range t.sboms {
		if e.digest == "" {
			s.UnresolvedSBOMs++
		} else {
			sd[e.digest] = struct{}{}
		}
	}
	s.VulnDigests, s.SBOMDigests = len(vd), len(sd)
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
	for _, e := range t.sboms {
		if e.digest != "" && e.workload == w && e.ref == ref {
			return e.digest
		}
	}
	for _, e := range t.vulns {
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

func (t *Tracker) sbomForDigestLocked(digest string) *types.ImageSBOM {
	var best *types.ImageSBOM
	for _, e := range t.sboms {
		if e.digest != digest {
			continue
		}
		if best == nil || e.payload.ScannedAt.After(best.ScannedAt) {
			best = e.payload
		}
	}
	return best
}

func (t *Tracker) evaluateVulnsLocked(digest string) *Emission {
	var winnerKey string
	var winner *vulnEntry
	var observed []types.WorkloadRef
	for k, e := range t.vulns {
		if e.digest != digest {
			continue
		}
		observed = append(observed, e.workload)
		if winner == nil || e.payload.ScannedAt.After(winner.payload.ScannedAt) ||
			(e.payload.ScannedAt.Equal(winner.payload.ScannedAt) && k < winnerKey) {
			winner, winnerKey = e, k
		}
	}
	sk := sentKey{KindVulnerabilities, digest}
	if winner == nil {
		delete(t.sent, sk)
		return nil
	}
	p := withFilePaths(winner.payload, FilePathsByPURL(t.sbomForDigestLocked(digest)))
	p.ObservedIn = nil
	fp := fingerprint(p)
	p.ObservedIn = uniqueWorkloads(observed)
	if !t.shouldSendLocked(sk, fp, p.ScannedAt) {
		return nil
	}
	return &Emission{Kind: KindVulnerabilities, Digest: digest, Vulns: p}
}

func (t *Tracker) evaluateSBOMLocked(digest string) *Emission {
	var winnerKey string
	var winner *sbomEntry
	var observed []types.WorkloadRef
	for k, e := range t.sboms {
		if e.digest != digest {
			continue
		}
		observed = append(observed, e.workload)
		if winner == nil || e.payload.ScannedAt.After(winner.payload.ScannedAt) ||
			(e.payload.ScannedAt.Equal(winner.payload.ScannedAt) && k < winnerKey) {
			winner, winnerKey = e, k
		}
	}
	sk := sentKey{KindSBOM, digest}
	if winner == nil {
		delete(t.sent, sk)
		return nil
	}
	// Copy: the stored payload is shared with the file-path join.
	p := *winner.payload
	p.ObservedIn = nil
	fp := fingerprint(&p)
	p.ObservedIn = uniqueWorkloads(observed)
	if !t.shouldSendLocked(sk, fp, p.ScannedAt) {
		return nil
	}
	return &Emission{Kind: KindSBOM, Digest: digest, SBOM: &p}
}

// shouldSendLocked records and approves a payload unless it is identical to
// the last one sent for the key, or older than it (a stale report for the
// same digest must not overwrite a newer scan).
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

func uniqueWorkloads(in []types.WorkloadRef) []types.WorkloadRef {
	seen := map[types.WorkloadRef]struct{}{}
	out := make([]types.WorkloadRef, 0, len(in))
	for _, w := range in {
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
