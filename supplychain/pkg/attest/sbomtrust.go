package attest

// SBOMTrust says whether a signed SBOM attestation verified for a digest.
// The registry-SBOM source (#1533 P1-4b) labels an SBOM
// sbomTrust=verified only when Verified is true and the sha256 of the DSSE
// payload it fetched equals PayloadSHA256, so a different, unsigned SBOM
// for the same digest is never promoted.
type SBOMTrust interface {
	SBOMTrust(digest string) (SBOMTrustInfo, bool)
}

// SBOMTrustInfo describes the verified SBOM attestation for a digest.
type SBOMTrustInfo struct {
	Verified      bool
	PredicateType string
	Issuer        string
	SAN           string
	PayloadSHA256 string
}

var _ SBOMTrust = (*Verifier)(nil)

// SBOMTrust implements SBOMTrust from the cached results: the first
// verified SBOM attestation bound to the digest itself.
func (v *Verifier) SBOMTrust(digest string) (SBOMTrustInfo, bool) {
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
		if a.Verified && a.Subject == "" && IsSBOM(a.PredicateType) {
			return SBOMTrustInfo{Verified: true, PredicateType: a.PredicateType, Issuer: a.Issuer, SAN: a.SAN, PayloadSHA256: a.PayloadSHA256}, true
		}
	}
	return SBOMTrustInfo{}, false
}
