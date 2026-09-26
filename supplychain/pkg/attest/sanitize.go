package attest

import (
	"strings"
	"unicode"
)

// The broker refuses any string with a control character or a Unicode
// line/paragraph separator (they would let a value start a new line in
// generated YAML). Signer-supplied values (SAN, predicate type, provenance)
// can hold them, so they are neutralised here instead of letting one odd
// attestation get the whole result refused and the digest left unchecked.

func badRune(r rune) bool { return unicode.IsControl(r) || r == ' ' || r == ' ' }

func hasBad(ss ...string) bool {
	for _, s := range ss {
		if strings.IndexFunc(s, badRune) >= 0 {
			return true
		}
	}
	return false
}

// clean replaces every such character with a space (our own text only:
// error details).
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if badRune(r) {
			return ' '
		}
		return r
	}, s)
}

const detailBadChars = "signer-supplied fields contain control characters; not shown"

// neutralize runs before the verdict: a signature or attestation whose
// signer-supplied fields hold such characters is reported malformed and
// unverified, without those fields. A signature so neutralised counts as
// invalid (malformed), never as verified.
func (c *collector) neutralize() {
	for i := range c.sigs {
		s := &c.sigs[i]
		s.Detail = clean(s.Detail)
		if hasBad(s.Issuer, s.SAN, s.KeyName, s.KeyFingerprint, s.KeyHint, s.Subject) {
			*s = Signature{Format: s.Format, Source: s.Source, Subject: clean(s.Subject), Error: ReasonMalformed, Detail: detailBadChars}
		}
	}
	for i := range c.atts {
		a := &c.atts[i]
		a.Detail = clean(a.Detail)
		bad := hasBad(a.PredicateType, a.Subject, a.PayloadSHA256, a.Issuer, a.SAN, a.KeyName, a.KeyFingerprint, a.KeyHint)
		if p := a.Provenance; p != nil && hasBad(p.BuilderID, p.BuildType, p.SourceRepo, p.SourceCommit, p.SourceRef) {
			bad = true
		}
		if bad {
			*a = Attestation{PredicateType: clean(a.PredicateType), Format: a.Format, Source: a.Source,
				Subject: clean(a.Subject), Error: ReasonMalformed, Detail: detailBadChars}
		}
	}
}
