// Package imagetrust evaluates ImageTrustPolicy and
// ClusterImageTrustPolicy (#1533 P2-2) against the running containers the
// broker knows about and the signatures kguardian's supplychain component
// verified for their images. Report only: it computes what WOULD be
// denied and writes it to the policies' status. It never verifies a
// signature itself and never admits or blocks anything.
package imagetrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
)

// Container is one running workload container with the signature result
// of its image, as GET /attestations/running returns it.
type Container struct {
	Namespace    string   `json:"namespace"`
	WorkloadKind string   `json:"workloadKind"`
	WorkloadName string   `json:"workloadName"`
	Container    string   `json:"container"`
	Digest       string   `json:"digest"`
	ImageRef     string   `json:"imageRef"`
	Repository   *string  `json:"repository"`
	Verdict      *string  `json:"verdict"`
	Reason       *string  `json:"reason"`
	Signers      []Signer `json:"signers"`
	Attestations []Signed `json:"attestations"`
}

// Signer is a verified signature's signer.
type Signer struct {
	Kind           string `json:"signerKind"`
	Issuer         string `json:"issuer"`
	SAN            string `json:"san"`
	KeyFingerprint string `json:"keyFingerprint"`
}

// Signed is a verified attestation.
type Signed struct {
	PredicateType string `json:"predicateType"`
	Signer
	Provenance *struct {
		BuilderID  string `json:"builderId"`
		SourceRepo string `json:"sourceRepo"`
	} `json:"provenance"`
}

// Reasons for WouldDeny and Unknown.
const (
	ReasonUnsigned           = "unsigned"
	ReasonInvalid            = "invalid"
	ReasonUntrustedSigner    = "untrusted-signer"
	ReasonKeyNotVerified     = "key-not-verified"
	ReasonAttestationMissing = "attestation-missing"
	ReasonNotChecked         = "not-checked"
)

// Discovery verdicts (supplychain attest.Verdict*).
const (
	discVerified  = "verified"
	discKeySigned = "key_signed"
	discUnsigned  = "unsigned"
	discInvalid   = "invalid"
	discUnknown   = "unknown"
)

// Policy is a compiled spec.
type Policy struct {
	images []*regexp.Regexp
	auths  []authority
	atts   []attReq
}

type authority struct {
	keylessIss, keylessSub *matcher
	fingerprint            string
}

type attReq struct {
	predicate          string
	builder, sourceRep *regexp.Regexp
}

// matcher is an exact value or a full-match regexp.
type matcher struct {
	exact string
	re    *regexp.Regexp
}

func (m *matcher) match(v string) bool {
	if m.re != nil {
		return m.re.MatchString(v)
	}
	return v == m.exact
}

func fullMatch(expr string) (*regexp.Regexp, error) {
	return regexp.Compile("^(?:" + expr + ")$")
}

func newMatcher(exact, expr, what string) (*matcher, error) {
	switch {
	case exact != "" && expr != "":
		return nil, fmt.Errorf("%s: set %s or %sRegExp, not both", what, what, what)
	case expr != "":
		re, err := fullMatch(expr)
		if err != nil {
			return nil, fmt.Errorf("%sRegExp: %w", what, err)
		}
		return &matcher{re: re}, nil
	case exact != "":
		return &matcher{exact: exact}, nil
	}
	return nil, fmt.Errorf("keyless authority needs an %s (exact or regexp)", what)
}

// globToRegexp turns an image glob into a full-match regexp: "**" matches
// anything, "*" anything but "/", "?" one character but "/".
func globToRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		switch {
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i++
		case g[i] == '*':
			b.WriteString("[^/]*")
		case g[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(g[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// Fingerprint returns the sha256 (hex) of a PEM public key's DER
// SubjectPublicKeyInfo, the same value supplychain reports.
func Fingerprint(pemKey string) (string, error) {
	blk, _ := pem.Decode([]byte(pemKey))
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("publicKey is not a PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", fmt.Errorf("publicKey: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

var hexFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Compile validates and compiles a spec.
func Compile(spec v1alpha1.ImageTrustPolicySpec) (*Policy, error) {
	p := &Policy{}
	for _, g := range spec.Images {
		re, err := globToRegexp(strings.TrimSpace(g))
		if err != nil {
			return nil, fmt.Errorf("images %q: %w", g, err)
		}
		p.images = append(p.images, re)
	}
	if len(spec.Authorities) == 0 {
		return nil, fmt.Errorf("authorities: at least one is required")
	}
	for i, a := range spec.Authorities {
		switch {
		case a.Keyless != nil && a.Key != nil, a.Keyless == nil && a.Key == nil:
			return nil, fmt.Errorf("authorities[%d]: set exactly one of keyless and key", i)
		case a.Keyless != nil:
			iss, err := newMatcher(a.Keyless.Issuer, a.Keyless.IssuerRegExp, "issuer")
			if err != nil {
				return nil, fmt.Errorf("authorities[%d]: %w", i, err)
			}
			sub, err := newMatcher(a.Keyless.Subject, a.Keyless.SubjectRegExp, "subject")
			if err != nil {
				return nil, fmt.Errorf("authorities[%d]: %w", i, err)
			}
			p.auths = append(p.auths, authority{keylessIss: iss, keylessSub: sub})
		default:
			fp := strings.ToLower(strings.TrimSpace(a.Key.Fingerprint))
			if a.Key.PublicKey != "" {
				got, err := Fingerprint(a.Key.PublicKey)
				if err != nil {
					return nil, fmt.Errorf("authorities[%d].key: %w", i, err)
				}
				if fp != "" && fp != got {
					return nil, fmt.Errorf("authorities[%d].key: fingerprint does not match publicKey", i)
				}
				fp = got
			}
			if !hexFingerprint.MatchString(fp) {
				return nil, fmt.Errorf("authorities[%d].key: needs publicKey or a sha256 hex fingerprint", i)
			}
			p.auths = append(p.auths, authority{fingerprint: fp})
		}
	}
	for i, r := range spec.Attestations {
		if strings.TrimSpace(r.PredicateType) == "" {
			return nil, fmt.Errorf("attestations[%d]: predicateType is required", i)
		}
		ar := attReq{predicate: r.PredicateType}
		var err error
		if r.BuilderIDRegExp != "" {
			if ar.builder, err = fullMatch(r.BuilderIDRegExp); err != nil {
				return nil, fmt.Errorf("attestations[%d].builderIdRegExp: %w", i, err)
			}
		}
		if r.SourceRepoRegExp != "" {
			if ar.sourceRep, err = fullMatch(r.SourceRepoRegExp); err != nil {
				return nil, fmt.Errorf("attestations[%d].sourceRepoRegExp: %w", i, err)
			}
		}
		p.atts = append(p.atts, ar)
	}
	return p, nil
}

// repository is the name images globs match: the inventory's normalised
// repository, else the image reference without tag or digest.
func (c Container) repository() string {
	if c.Repository != nil && *c.Repository != "" {
		return *c.Repository
	}
	ref := c.ImageRef
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

// Selects reports whether the policy's images cover c.
func (p *Policy) Selects(c Container) bool {
	if len(p.images) == 0 {
		return true
	}
	repo := c.repository()
	for _, re := range p.images {
		if re.MatchString(repo) {
			return true
		}
	}
	return false
}

func (p *Policy) trusts(s Signer) bool {
	for _, a := range p.auths {
		if a.fingerprint != "" {
			if s.Kind == "key" && strings.EqualFold(s.KeyFingerprint, a.fingerprint) {
				return true
			}
			continue
		}
		if s.Kind != "key" && s.Issuer != "" && a.keylessIss.match(s.Issuer) && a.keylessSub.match(s.SAN) {
			return true
		}
	}
	return false
}

// HasKeyAuthority is true when the policy trusts at least one key.
func (p *Policy) hasKeyAuthority() bool {
	for _, a := range p.auths {
		if a.fingerprint != "" {
			return true
		}
	}
	return false
}

// Evaluate returns the verdict (v1alpha1.Image*) and reason for c.
//
// Order: a container whose signatures were never checked, or could not be
// checked, is Unknown (never Trusted). Otherwise the signature must come
// from a policy authority, then every required attestation must be
// verified and signed by one.
func (p *Policy) Evaluate(c Container) (string, string) {
	if c.Verdict == nil {
		return v1alpha1.ImageUnknown, ReasonNotChecked
	}
	switch *c.Verdict {
	case discUnknown:
		r := ReasonNotChecked
		if c.Reason != nil && *c.Reason != "" {
			r = *c.Reason
		}
		return v1alpha1.ImageUnknown, r
	case discUnsigned:
		return v1alpha1.ImageWouldDeny, ReasonUnsigned
	case discInvalid:
		return v1alpha1.ImageWouldDeny, ReasonInvalid
	case discKeySigned:
		// A key signature supplychain could not check. If this policy
		// trusts a key, the operator probably has to give supplychain the
		// key; say so rather than "untrusted".
		if p.hasKeyAuthority() {
			return v1alpha1.ImageWouldDeny, ReasonKeyNotVerified
		}
		return v1alpha1.ImageWouldDeny, ReasonUntrustedSigner
	case discVerified:
	default:
		return v1alpha1.ImageUnknown, ReasonNotChecked
	}
	trusted := false
	for _, s := range c.Signers {
		if p.trusts(s) {
			trusted = true
			break
		}
	}
	if !trusted {
		return v1alpha1.ImageWouldDeny, ReasonUntrustedSigner
	}
	for _, r := range p.atts {
		if !p.attested(c, r) {
			return v1alpha1.ImageWouldDeny, ReasonAttestationMissing
		}
	}
	return v1alpha1.ImageTrusted, ""
}

func (p *Policy) attested(c Container, r attReq) bool {
	for _, a := range c.Attestations {
		if a.PredicateType != r.predicate || !p.trusts(a.Signer) {
			continue
		}
		if r.builder != nil && (a.Provenance == nil || !r.builder.MatchString(a.Provenance.BuilderID)) {
			continue
		}
		if r.sourceRep != nil && (a.Provenance == nil || !r.sourceRep.MatchString(a.Provenance.SourceRepo)) {
			continue
		}
		return true
	}
	return false
}
