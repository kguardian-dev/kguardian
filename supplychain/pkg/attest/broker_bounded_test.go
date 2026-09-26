package attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const buriedFixture = "../../../test/fixtures/contracts/attestation-post-buried-signature.json"

// buriedResult: 40 junk signatures (bad signature, key signature by an
// unknown key) and 70 junk attestations ahead of the one verified
// signature and the one verified provenance attestation.
func buriedResult() Result {
	dg := "sha256:" + strings.Repeat("ab", 32)
	r := Result{SchemaVersion: SchemaVersion, Digest: dg, Repository: "ghcr.io/example/api",
		CheckedAt: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC), Verdict: VerdictVerified,
		TrustRoot: TrustRootPublicGood, SignedVia: SignedViaSelf, SignedDigest: dg}
	for i := 0; i < 40; i++ {
		e := ReasonBadSignature
		if i%10 == 9 {
			e = ReasonUntrustedKey
		}
		r.Signatures = append(r.Signatures, Signature{Format: FormatCosignBundle, Source: SourceReferrers, Error: e, Detail: fmt.Sprintf("junk %d", i)})
	}
	r.Signatures = append(r.Signatures, Signature{Format: FormatCosignBundle, Source: SourceReferrers, Verified: true,
		Signer: Signer{Kind: SignerKeyless, Issuer: issuerGitHub, SAN: "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1.0.0"}})
	for i := 0; i < 70; i++ {
		r.Attestations = append(r.Attestations, Attestation{PredicateType: PredicateSLSAv1, Format: FormatBundle, Source: SourceReferrers, Error: ReasonBadSignature})
	}
	r.Attestations = append(r.Attestations, Attestation{PredicateType: PredicateSLSAv1, Format: FormatBundle, Source: SourceReferrers, Verified: true,
		Signer: Signer{Kind: SignerKeyless, Issuer: issuerGitHub, SAN: "s"}})
	return r
}

// The verified signature and attestation survive the caps, and the post
// is the one checked in as the broker's contract fixture (the broker test
// verified_signature_survives_the_caps parses that file and must accept
// it). Regenerate with ATTEST_UPDATE_CONTRACT=1.
func TestEncodeBoundedKeepsTheVerifiedSignature(t *testing.T) {
	body, err := encodeBounded(buriedResult())
	if err != nil {
		t.Fatal(err)
	}
	var got Result
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Signatures) != maxSignatures || !got.Signatures[0].Verified || got.Verdict != VerdictVerified {
		t.Fatalf("signatures: %d, first %+v", len(got.Signatures), got.Signatures[0])
	}
	// Key signatures rank next, ahead of bad ones.
	for i := 1; i <= 4; i++ {
		if got.Signatures[i].Error != ReasonUntrustedKey {
			t.Fatalf("signature %d = %+v", i, got.Signatures[i])
		}
	}
	if len(got.Attestations) != maxAttestation || !got.Attestations[0].Verified {
		t.Fatalf("attestations: %d, first %+v", len(got.Attestations), got.Attestations[0])
	}
	// The caller's slices are not reordered.
	if r := buriedResult(); !r.Signatures[40].Verified {
		t.Fatal("input mutated")
	}
	if os.Getenv("ATTEST_UPDATE_CONTRACT") == "1" {
		var buf bytes.Buffer
		_ = json.Indent(&buf, body, "", " ")
		if err := os.WriteFile(buriedFixture, append(buf.Bytes(), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(buriedFixture)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal(want, &a)
	_ = json.Unmarshal(body, &b)
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if !bytes.Equal(aj, bj) {
		t.Fatal("encodeBounded output differs from the contract fixture; regenerate with ATTEST_UPDATE_CONTRACT=1 and re-run the broker test")
	}
}
