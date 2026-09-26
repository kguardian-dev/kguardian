package attest

// SBOMTrust says whether a signed SBOM attestation verified for a digest,
// signed by someone the caller trusts. The registry-SBOM source (#1533
// P1-4b) may label an SBOM sbomTrust=verified only when Verified is true
// and the sha256 of the DSSE payload it fetched equals PayloadSHA256, so a
// different, unsigned SBOM for the same digest is never promoted.
//
// "Verified" alone means a valid signature by ANY Fulcio identity or
// configured key: anyone who can push to the repository can attach one.
// So the caller must pass the identity check it requires; there is no
// variant that accepts any signer.
type SBOMTrust interface {
	SBOMTrust(digest string, trusted func(Signer) bool) (SBOMTrustInfo, bool)
}

// SBOMTrustInfo describes the verified SBOM attestation for a digest.
type SBOMTrustInfo struct {
	Verified      bool
	PredicateType string
	Signer        Signer
	PayloadSHA256 string
}

var _ SBOMTrust = (*Verifier)(nil)

// SBOMTrust implements SBOMTrust from the cached results: the first
// verified SBOM attestation bound to the digest itself whose signer
// trusted accepts. A nil trusted accepts nobody.
func (v *Verifier) SBOMTrust(digest string, trusted func(Signer) bool) (SBOMTrustInfo, bool) {
	if trusted == nil {
		return SBOMTrustInfo{}, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	key, ok := v.byDigest[digest]
	if !ok {
		return SBOMTrustInfo{}, false
	}
	e, ok := v.cache[key]
	if !ok || now().After(e.expires) {
		return SBOMTrustInfo{}, false
	}
	for _, a := range e.res.Attestations {
		if a.Verified && a.Subject == "" && IsSBOM(a.PredicateType) && trusted(a.Signer) {
			return SBOMTrustInfo{Verified: true, PredicateType: a.PredicateType, Signer: a.Signer, PayloadSHA256: a.PayloadSHA256}, true
		}
	}
	return SBOMTrustInfo{}, false
}
