package attest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
)

// Target is one running image digest to check, as the broker's inventory
// lists it.
type Target struct {
	Digest string
	// Repository is the normalised repository, e.g.
	// "docker.io/library/nginx" or "ghcr.io/org/app".
	Repository string
	// DigestKind is the inventory's kind: "repo" (a registry digest),
	// "pinned" (a digest from the spec) or "config" (a node-local image
	// ID with no registry digest).
	DigestKind string
	// Tags seen for the digest; used to find a signed multi-arch index
	// that lists it.
	Tags []string
}

// Identity is a trusted signer: the OIDC issuer and the certificate SAN,
// each matched exactly or by a Go regular expression that must match the
// whole value.
type Identity struct {
	Issuer        string
	IssuerRegExp  string
	Subject       string
	SubjectRegExp string
}

type compiledIdentity struct {
	issuer, subject     string
	issuerRE, subjectRE *regexp.Regexp
}

func compileIdentities(ids []Identity) ([]compiledIdentity, error) {
	out := make([]compiledIdentity, 0, len(ids))
	for _, id := range ids {
		c := compiledIdentity{issuer: id.Issuer, subject: id.Subject}
		var err error
		if id.Issuer != "" && id.IssuerRegExp != "" || id.Subject != "" && id.SubjectRegExp != "" {
			return nil, fmt.Errorf("identity: set the issuer (subject) exactly or as a regexp, not both")
		}
		// Regular expressions must match the whole value: unanchored, a
		// trusted SAN would also match any SAN that merely contains it.
		if id.IssuerRegExp != "" {
			if c.issuerRE, err = regexp.Compile("^(?:" + id.IssuerRegExp + ")$"); err != nil {
				return nil, fmt.Errorf("issuer regexp %q: %w", id.IssuerRegExp, err)
			}
		}
		if id.SubjectRegExp != "" {
			if c.subjectRE, err = regexp.Compile("^(?:" + id.SubjectRegExp + ")$"); err != nil {
				return nil, fmt.Errorf("subject regexp %q: %w", id.SubjectRegExp, err)
			}
		}
		if c.issuer == "" && c.issuerRE == nil || c.subject == "" && c.subjectRE == nil {
			return nil, fmt.Errorf("identity needs an issuer and a subject (exact or regexp)")
		}
		out = append(out, c)
	}
	return out, nil
}

func (c compiledIdentity) matches(s Signer) bool {
	okIss := (c.issuer != "" && s.Issuer == c.issuer) || (c.issuerRE != nil && c.issuerRE.MatchString(s.Issuer))
	okSub := (c.subject != "" && s.SAN == c.subject) || (c.subjectRE != nil && c.subjectRE.MatchString(s.SAN))
	return okIss && okSub
}

// Options configure a Verifier.
type Options struct {
	// Guard restricts registry destinations (the supplychain SSRF guard).
	Guard registry.Guard
	// TrustRoot supplies the Sigstore trusted material. Required.
	TrustRoot TrustRoot
	// SkipSCT drops the certificate-transparency requirement, for a
	// private Fulcio without a CT log.
	SkipSCT bool
	// Timeout bounds the registry work for one digest. Default 60s.
	Timeout time.Duration
	// RequestTimeout bounds one registry request. Default 10s.
	RequestTimeout time.Duration
	// RegistryRPS and RegistryBurst rate-limit registry requests (all
	// registries together). Defaults 5 and 10.
	RegistryRPS   float64
	RegistryBurst int
	// TTL for a definitive result (verified, unsigned, invalid) and for
	// unknown. Defaults 24h and 1h. Digests are immutable, so a definitive
	// result only changes when signatures are added or revoked.
	TTL        time.Duration
	UnknownTTL time.Duration
	// MaxEntries bounds the cache; when full it is cleared. Default 10000.
	MaxEntries int
	// TrustedKeys verify key-signed ("cosign sign --key") signatures.
	// Without them a key signature is reported as VerdictKeySigned.
	TrustedKeys []PublicKey
	// TrustedIdentities, when set, turns a verified keyless signature from
	// any other signer into VerdictUntrustedIdentity (a signature verified
	// by a TrustedKeys key is trusted by that configuration). Discovery leaves it
	// empty; trust policies are evaluated from the recorded signers.
	TrustedIdentities []Identity
	// Insecure allows plain-HTTP registries (tests only).
	Insecure bool
	// transport replaces the guarded transport and skipHostCheck the
	// guard's host pre-check (tests only: the fixture registry is on
	// loopback).
	transport     http.RoundTripper
	skipHostCheck bool
}

// Verifier discovers and verifies the signatures and attestations of
// image digests, with a per-digest cache.
type Verifier struct {
	opts       Options
	fetch      *fetcher
	identities []compiledIdentity
	keys       []trustedKey

	mu       sync.Mutex
	cache    map[string]cacheEntry
	byDigest map[string]string // digest -> cache key, for SBOMTrust
	vmu      sync.Mutex
	vlast    *verifier
	vtm      any
}

type cacheEntry struct {
	res     Result
	expires time.Time
}

// New returns a Verifier.
func New(o Options) (*Verifier, error) {
	if o.TrustRoot == nil {
		return nil, errors.New("attest: TrustRoot is required")
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 10 * time.Second
	}
	if o.RegistryRPS <= 0 {
		o.RegistryRPS = 5
	}
	if o.RegistryBurst <= 0 {
		o.RegistryBurst = 10
	}
	if o.TTL <= 0 {
		o.TTL = 24 * time.Hour
	}
	if o.UnknownTTL <= 0 {
		o.UnknownTTL = time.Hour
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 10000
	}
	ids, err := compileIdentities(o.TrustedIdentities)
	if err != nil {
		return nil, err
	}
	keys, err := parseKeys(o.TrustedKeys)
	if err != nil {
		return nil, err
	}
	rt := o.transport
	if rt == nil {
		rt = o.Guard.Transport(o.RequestTimeout)
	}
	rt = RateLimit(rt, o.RegistryRPS, o.RegistryBurst)
	return &Verifier{
		opts:       o,
		fetch:      &fetcher{rt: rt, insecure: o.Insecure},
		identities: ids,
		keys:       keys,
		cache:      map[string]cacheEntry{},
		byDigest:   map[string]string{},
	}, nil
}

// Cached returns the cached result for a digest, if any and not expired.
func (v *Verifier) Cached(repository, digest string) (Result, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[repository+"@"+digest]
	if !ok || now().After(e.expires) {
		return Result{}, false
	}
	return e.res, true
}

// Verify returns the result for t, from the cache when fresh.
func (v *Verifier) Verify(ctx context.Context, t Target) Result {
	if r, ok := v.Cached(t.Repository, t.Digest); ok {
		return r
	}
	r := v.check(ctx, t)
	ttl := v.opts.TTL
	if r.Verdict == VerdictUnknown {
		ttl = v.opts.UnknownTTL
	}
	v.mu.Lock()
	if len(v.cache) >= v.opts.MaxEntries {
		v.cache = map[string]cacheEntry{}
		v.byDigest = map[string]string{}
	}
	key := t.Repository + "@" + t.Digest
	v.cache[key] = cacheEntry{res: r, expires: now().Add(ttl)}
	v.byDigest[t.Digest] = key
	v.mu.Unlock()
	return r
}

// sigVerifier returns a verifier for the current trusted material,
// rebuilt only when the material changes.
func (v *Verifier) sigVerifier(ctx context.Context) (*verifier, string, error) {
	tm, label, err := v.opts.TrustRoot.Material(ctx)
	if err != nil {
		return nil, "", err
	}
	v.vmu.Lock()
	defer v.vmu.Unlock()
	if v.vlast != nil && v.vtm == any(tm) {
		return v.vlast, label, nil
	}
	sv, err := newVerifier(tm, !v.opts.SkipSCT, v.keys)
	if err != nil {
		return nil, "", err
	}
	v.vlast, v.vtm = sv, tm
	return sv, label, nil
}

func unknown(r Result, reason string) Result {
	r.Verdict, r.Reason = VerdictUnknown, reason
	return r
}

func (v *Verifier) check(ctx context.Context, t Target) Result {
	r := Result{
		SchemaVersion: SchemaVersion,
		Digest:        t.Digest,
		Repository:    t.Repository,
		CheckedAt:     now(),
		Signatures:    []Signature{},
		Attestations:  []Attestation{},
	}
	if t.DigestKind == "config" || t.Repository == "" {
		return unknown(r, ReasonNoRepoDigest)
	}
	if _, _, err := digestBytes(t.Digest); err != nil {
		return unknown(r, ReasonMalformed)
	}
	repo, err := v.fetch.repo(t.Repository)
	if err != nil {
		return unknown(r, ReasonMalformed)
	}
	if !v.opts.skipHostCheck {
		if err := v.opts.Guard.CheckHost(hostOnly(repo.RegistryStr())); err != nil {
			return unknown(r, classify(err).reason)
		}
	}
	sv, label, err := v.sigVerifier(ctx)
	if err != nil {
		return unknown(r, ReasonTrustRootUnavailable)
	}
	r.TrustRoot = label

	ctx, cancel := context.WithTimeout(ctx, v.opts.Timeout)
	defer cancel()

	c := &collector{f: v.fetch, sv: sv, repo: repo}
	c.collect(ctx, t.Digest, "")
	hasSig := len(c.sigs) > 0
	hasProv := c.hasProvenance()
	if (!hasSig || !hasProv) && c.lookupErr == "" {
		// Signatures and provenance are often on the multi-arch index,
		// while the kubelet runs a platform manifest.
		tried := 0
		for _, tag := range t.Tags {
			if tried == maxIndexTagsResolved {
				break
			}
			tried++
			idx, ok := v.fetch.indexListing(ctx, repo, tag, t.Digest)
			if !ok || idx == t.Digest {
				continue
			}
			ic := &collector{f: v.fetch, sv: sv, repo: repo}
			ic.collect(ctx, idx, idx)
			if !hasSig && len(ic.sigs) > 0 {
				c.sigs = append(c.sigs, ic.sigs...)
				r.SignedVia, r.SignedDigest = SignedViaIndex, idx
			}
			if !hasProv {
				c.atts = append(c.atts, ic.atts...)
			}
			if ic.lookupErr != "" && c.lookupErr == "" && len(ic.sigs) == 0 {
				// The index could not be read completely: its absence
				// of signatures is not established.
				c.indexErr = ic.lookupErr
			}
			break
		}
	}
	if len(c.sigs) > 0 && r.SignedVia == "" {
		r.SignedVia, r.SignedDigest = SignedViaSelf, t.Digest
	}
	r.Signatures, r.Attestations = c.sigs, c.atts
	if r.Signatures == nil {
		r.Signatures = []Signature{}
	}
	if r.Attestations == nil {
		r.Attestations = []Attestation{}
	}
	r.Verdict, r.Reason = c.verdict()
	if r.Verdict == VerdictVerified && len(v.identities) > 0 && !v.trusted(r.Signatures) {
		r.Verdict, r.Reason = VerdictUntrustedIdentity, ""
	}
	return r
}

func (v *Verifier) trusted(sigs []Signature) bool {
	for _, s := range sigs {
		if !s.Verified {
			continue
		}
		if s.Kind == SignerKey {
			return true // a configured key is itself the trust decision
		}
		for _, id := range v.identities {
			if id.matches(s.Signer) {
				return true
			}
		}
	}
	return false
}

// collector gathers and verifies everything attached to one digest.
type collector struct {
	f    *fetcher
	sv   *verifier
	repo name.Repository

	sigs []Signature
	atts []Attestation
	// lookupErr is the reason of the first lookup that failed; while set,
	// "no signature found" is not established.
	lookupErr string
	indexErr  string
}

func (c *collector) fail(err error) {
	if c.lookupErr == "" {
		c.lookupErr = classify(err).reason
	}
}

func (c *collector) hasProvenance() bool {
	for _, a := range c.atts {
		if a.PredicateType == PredicateSLSAv1 || a.PredicateType == PredicateSLSAv02 {
			return true
		}
	}
	return false
}

// collect reads the .sig and .att tags and the referrers of digest.
// subject is recorded on each finding when it differs from the running
// digest (the index route).
func (c *collector) collect(ctx context.Context, digest, subject string) {
	c.legacySigs(ctx, digest, subject)
	c.legacyAtts(ctx, digest, subject)
	c.bundles(ctx, digest, subject)
}

func (c *collector) legacySigs(ctx context.Context, digest, subject string) {
	m, found, err := c.f.manifestAt(ctx, tagFor(c.repo, digest, "sig"))
	if err != nil {
		c.fail(err)
		return
	}
	if !found {
		return
	}
	for i, l := range m.Layers {
		if i == maxLayersPerTag {
			break
		}
		if string(l.MediaType) != mediaSimpleSigning {
			continue
		}
		s := Signature{Format: FormatCosignLegacy, Source: SourceSigTag, Subject: subject}
		payload, err := c.f.blob(ctx, c.repo, l, maxSigPayloadBytes)
		if err != nil {
			if fe := classify(err); fe.reason != ReasonTooLarge {
				c.fail(err)
			}
			s.Error, s.Detail = reasonOf(err), detail(err)
			c.sigs = append(c.sigs, s)
			continue
		}
		signer, err := c.sv.verifyLegacySig(payload, l.Annotations, digest)
		if err != nil {
			s.Error, s.Detail = reasonOf(err), detail(err)
			s.KeyHint = signer.KeyHint
		} else {
			s.Verified, s.Signer = true, signer
		}
		c.sigs = append(c.sigs, s)
	}
}

func (c *collector) legacyAtts(ctx context.Context, digest, subject string) {
	m, found, err := c.f.manifestAt(ctx, tagFor(c.repo, digest, "att"))
	if err != nil {
		c.fail(err)
		return
	}
	if !found {
		return
	}
	for i, l := range m.Layers {
		if i == maxLayersPerTag {
			break
		}
		if string(l.MediaType) != mediaDSSE {
			continue
		}
		a := Attestation{PredicateType: l.Annotations[annPredicate], Format: FormatCosignLegacyAtt, Source: SourceAttTag, Subject: subject}
		env, err := c.f.blob(ctx, c.repo, l, maxAttestationBytes)
		if err != nil {
			a.Error, a.Detail = reasonOf(err), detail(err)
			c.atts = append(c.atts, a)
			continue
		}
		chk, err := c.sv.verifyLegacyAtt(env, l.Annotations, digest)
		c.atts = append(c.atts, fillAttestation(a, chk, err))
	}
}

func (c *collector) bundles(ctx context.Context, digest, subject string) {
	refs, err := c.f.referrers(ctx, c.repo, digest)
	if err != nil {
		c.fail(err)
		return
	}
	for _, ref := range refs {
		pt := ref.Annotations["dev.sigstore.bundle.predicateType"]
		limit := int64(maxAttestationBytes)
		if pt == PredicateCosignSign {
			limit = maxBundleBytes
		}
		raw, err := c.f.bundleBlob(ctx, c.repo, ref, limit)
		if errors.Is(err, errNotBundle) {
			continue
		}
		if err != nil {
			if fe := classify(err); fe.reason != ReasonTooLarge && fe.reason != ReasonUnsupportedFormat {
				c.fail(err)
			}
			c.addBundleFailure(pt, subject, err)
			continue
		}
		b, err := loadBundle(raw)
		if err != nil {
			c.addBundleFailure(pt, subject, err)
			continue
		}
		chk, err := c.sv.verifyDSSEBundle(b, digest)
		if chk != nil && chk.predicateType != "" {
			pt = chk.predicateType
		}
		if pt == PredicateCosignSign {
			s := Signature{Format: FormatCosignBundle, Source: SourceReferrers, Subject: subject}
			if err != nil {
				s.Error, s.Detail = reasonOf(err), detail(err)
				if chk != nil {
					s.KeyHint = chk.signer.KeyHint
				}
			} else {
				s.Verified, s.Signer = true, chk.signer
			}
			c.sigs = append(c.sigs, s)
			continue
		}
		a := Attestation{PredicateType: pt, Format: FormatBundle, Source: SourceReferrers, Subject: subject}
		c.atts = append(c.atts, fillAttestation(a, chk, err))
	}
}

func (c *collector) addBundleFailure(pt, subject string, err error) {
	if pt == PredicateCosignSign {
		c.sigs = append(c.sigs, Signature{Format: FormatCosignBundle, Source: SourceReferrers, Subject: subject, Error: reasonOf(err), Detail: detail(err)})
		return
	}
	c.atts = append(c.atts, Attestation{PredicateType: pt, Format: FormatBundle, Source: SourceReferrers, Subject: subject, Error: reasonOf(err), Detail: detail(err)})
}

func fillAttestation(a Attestation, chk *dsseCheck, err error) Attestation {
	if chk != nil {
		if chk.predicateType != "" {
			a.PredicateType = chk.predicateType
		}
		a.PayloadSHA256 = chk.payloadSHA256
		if chk.stmt != nil && err == nil {
			a.Provenance = provenanceOf(chk.predicateType, chk.stmt.Predicate)
		}
	}
	if err != nil {
		a.Error, a.Detail = reasonOf(err), detail(err)
		if chk != nil {
			a.KeyHint = chk.signer.KeyHint
		}
		return a
	}
	a.Verified, a.Signer = true, chk.signer
	return a
}

// verdict applies the discovery rules: any verified signature wins; then
// a cryptographic failure is invalid; a signature made with a key we do
// not hold is key_signed; a signature that could not be evaluated, or a
// failed lookup, is unknown; only a complete, empty search is unsigned.
func (c *collector) verdict() (string, string) {
	var invalid, unsupported string
	var keySigned bool
	for _, s := range c.sigs {
		switch {
		case s.Verified:
			return VerdictVerified, ""
		case s.Error == ReasonBadSignature || s.Error == ReasonDigestMismatch || s.Error == ReasonMalformed:
			if invalid == "" {
				invalid = s.Error
			}
		case s.Error == ReasonUntrustedKey:
			keySigned = true
		case unsupported == "":
			unsupported = s.Error
		}
	}
	switch {
	case invalid != "":
		return VerdictInvalid, invalid
	case keySigned:
		return VerdictKeySigned, ReasonUntrustedKey
	case unsupported != "":
		return VerdictUnknown, unsupported
	case c.lookupErr != "":
		return VerdictUnknown, c.lookupErr
	case c.indexErr != "":
		return VerdictUnknown, c.indexErr
	}
	return VerdictUnsigned, ""
}

func hostOnly(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		if i := strings.Index(hostport, "]"); i > 0 {
			return hostport[1:i]
		}
	}
	if i := strings.LastIndex(hostport, ":"); i > 0 && strings.Count(hostport, ":") == 1 {
		return hostport[:i]
	}
	return hostport
}
