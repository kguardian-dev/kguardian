package attest

import (
	"strings"
	"testing"
)

// A signer can put anything in a keyless SAN or an attestation's predicate
// type. Such entries become malformed and unverified before the verdict,
// so the result is still posted (the broker refuses control characters)
// and nothing unprintable is shown as a verified identity.
func TestNeutralizeControlCharacters(t *testing.T) {
	for _, bad := range []string{"\n", "\r", "\t", "\x00", "\x7f", "\u0085", "\u2028", "\u2029", "\u200e", "\u200f", "\u202a", "\u202e", "\u2066", "\u2069", "\ufeff"} {
		c := &collector{
			sigs: []Signature{
				{Format: FormatCosignBundle, Verified: true, Signer: Signer{Kind: SignerKeyless, Issuer: issuerGoogle, SAN: sanK8sRelease}},
				{Format: FormatCosignBundle, Verified: true, Signer: Signer{Kind: SignerKeyless, Issuer: issuerGitHub, SAN: "evil" + bad + "---"}},
				{Format: FormatCosignLegacy, Error: ReasonBadSignature, Detail: "line one" + bad + "line two"},
			},
			atts: []Attestation{
				{PredicateType: "https://evil.example/" + bad + "kind: Secret", Verified: true, Signer: Signer{Kind: SignerKeyless, Issuer: issuerGitHub, SAN: "s"}},
				{PredicateType: PredicateSLSAv1, Verified: true, Signer: Signer{Kind: SignerKeyless, Issuer: issuerGitHub, SAN: "s"},
					Provenance: &Provenance{BuilderID: "b" + bad}},
				{PredicateType: PredicateSLSAv1, Verified: true, Signer: Signer{Kind: SignerKeyless, Issuer: issuerGitHub, SAN: "s"}},
			},
		}
		c.neutralize()
		if len(c.sigs) != 3 || len(c.atts) != 3 {
			t.Fatalf("%q: entries dropped", bad)
		}
		if !c.sigs[0].Verified {
			t.Fatalf("%q: clean signature touched", bad)
		}
		if s := c.sigs[1]; s.Verified || s.Error != ReasonMalformed || s.SAN != "" || s.Issuer != "" {
			t.Fatalf("%q: bad signer kept: %+v", bad, s)
		}
		if strings.IndexFunc(c.sigs[2].Detail, badRune) >= 0 {
			t.Fatalf("%q: detail not cleaned", bad)
		}
		for i := 0; i < 2; i++ {
			a := c.atts[i]
			if a.Verified || a.Error != ReasonMalformed || a.Provenance != nil || hasBad(a.PredicateType) || a.SAN != "" {
				t.Fatalf("%q: bad attestation %d kept: %+v", bad, i, a)
			}
		}
		if !c.atts[2].Verified {
			t.Fatalf("%q: clean attestation touched", bad)
		}
		// One verified clean signature: still verified.
		if v, _ := c.verdict(); v != VerdictVerified {
			t.Fatalf("%q: verdict %s", bad, v)
		}
		// Only the bad signer: malformed is invalid, never verified.
		only := &collector{sigs: []Signature{c.sigs[1]}}
		if v, r := only.verdict(); v != VerdictInvalid || r != ReasonMalformed {
			t.Fatalf("%q: verdict %s(%s)", bad, v, r)
		}
	}
}

// The verdict rule the broker enforces (check_verdict): tamper wins over a
// key signature, a key signature over anything else.
func TestVerdictClasses(t *testing.T) {
	sig := func(e string) Signature { return Signature{Format: FormatCosignBundle, Error: e} }
	for _, tc := range []struct {
		errs    []string
		verdict string
	}{
		{[]string{ReasonBadSignature, ReasonUntrustedKey}, VerdictInvalid},
		{[]string{ReasonUntrustedKey, ReasonDigestMismatch}, VerdictInvalid},
		{[]string{ReasonMalformed}, VerdictInvalid},
		{[]string{ReasonUntrustedKey}, VerdictKeySigned},
		{[]string{ReasonUntrustedKey, ReasonUnsupportedFormat}, VerdictKeySigned},
		{[]string{ReasonUntrustedRoot}, VerdictUnknown},
		{nil, VerdictUnsigned},
	} {
		c := &collector{}
		for _, e := range tc.errs {
			c.sigs = append(c.sigs, sig(e))
		}
		if v, _ := c.verdict(); v != tc.verdict {
			t.Errorf("%v: verdict %s, want %s", tc.errs, v, tc.verdict)
		}
	}
}
