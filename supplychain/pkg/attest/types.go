// Package attest discovers and verifies the Sigstore signatures and
// attestations attached to the image digests a cluster is running
// (#1533 P2-1).
//
// It reports and never enforces. For each digest it looks for:
//
//   - legacy cosign signatures and attestations in the "sha256-<hex>.sig"
//     and "sha256-<hex>.att" tags;
//   - Sigstore bundles attached as OCI 1.1 referrers, through the referrers
//     API or, for registries without it (GHCR), the "sha256-<hex>" tag
//     fallback.
//
// Every signature and attestation is verified with sigstore-go against a
// trusted root (the public-good instance by default, or a mounted
// trusted_root.json for a private Sigstore). Verification is offline: the
// transparency-log inclusion proofs and promises come from the signature
// itself, so Rekor is never contacted. The signer identity (OIDC issuer and
// certificate SAN) and, for SLSA provenance, the builder and source are
// recorded.
//
// Registry access is anonymous and goes through the supplychain SSRF
// guard. Pull secrets are never read (#1533 decision D3): a private image
// is reported as unknown, never as unsigned.
package attest

import "time"

// SchemaVersion of the broker payload (Result).
const SchemaVersion = 1

// Discovery verdicts, from the signatures alone. Trust-policy verdicts
// (untrusted_identity, attestation_missing) are derived from these by the
// policy layer.
const (
	// VerdictVerified: at least one signature verified against the trusted
	// root, whoever signed it.
	VerdictVerified = "verified"
	// VerdictUnsigned: every lookup answered, and no signature exists.
	VerdictUnsigned = "unsigned"
	// VerdictInvalid: signatures exist, none verified, and at least one
	// failed a cryptographic check or is bound to a different digest.
	VerdictInvalid = "invalid"
	// VerdictUnknown: something could not be checked (see Reason). Never
	// read as unsigned or clean.
	VerdictUnknown = "unknown"
	// VerdictKeySigned: signed with a public key (no Fulcio certificate)
	// that is not one of the configured keys, so the signature could not
	// be checked. A signature exists; whether it is genuine is not known.
	// Configure the key (Options.TrustedKeys) to turn this into verified
	// or invalid.
	VerdictKeySigned = "key_signed"
	// VerdictUntrustedIdentity: a valid signature, but no signer the
	// caller's identity list accepts. Only produced when identities are
	// given (Options.TrustedIdentities).
	VerdictUntrustedIdentity = "untrusted_identity"
)

// Signer kinds.
const (
	SignerKeyless = "keyless" // Fulcio certificate: OIDC issuer + SAN
	SignerKey     = "key"     // a configured public key
)

// Reasons for VerdictUnknown and VerdictInvalid, and for a single
// signature's Error.
const (
	ReasonRegistryAuth         = "registry_auth" // 401/403 anonymously: private image
	ReasonRateLimited          = "rate_limited"
	ReasonNetwork              = "network"
	ReasonTimeout              = "timeout"
	ReasonNoRepoDigest         = "no_repo_digest" // node-local image, nothing to look up
	ReasonTrustRootUnavailable = "trust_root_unavailable"
	ReasonUnsupportedFormat    = "unsupported_format"
	ReasonTooLarge             = "too_large"
	ReasonRegistryError        = "registry_error"
	// Guard refusals reuse registry.Reason* ("blocked_address", ...).

	ReasonDigestMismatch = "digest_mismatch" // signed a different digest
	ReasonBadSignature   = "bad_signature"   // signature, certificate chain or log proof failed
	ReasonMalformed      = "malformed"       // could not be parsed
	// ReasonUntrustedKey: signed with a key rather than a Fulcio
	// certificate, and no configured key verifies it.
	ReasonUntrustedKey = "untrusted_key"
)

// Signature formats and sources.
const (
	FormatCosignBundle    = "cosign-bundle"     // Sigstore bundle, cosign/sign predicate
	FormatCosignLegacy    = "cosign-legacy"     // simplesigning payload in a .sig tag
	FormatBundle          = "bundle"            // Sigstore bundle attestation
	FormatCosignLegacyAtt = "cosign-legacy-att" // DSSE envelope in a .att tag

	SourceReferrers = "referrers" // referrers API or its sha256-<hex> tag fallback
	SourceSigTag    = "sig-tag"
	SourceAttTag    = "att-tag"

	SignedViaSelf  = "self"
	SignedViaIndex = "index"
)

// Well-known predicate types.
const (
	PredicateCosignSign  = "https://sigstore.dev/cosign/sign/v1"
	PredicateSLSAv1      = "https://slsa.dev/provenance/v1"
	PredicateSLSAv02     = "https://slsa.dev/provenance/v0.2"
	PredicateCycloneDX   = "https://cyclonedx.org/bom"
	PredicateSPDX        = "https://spdx.dev/Document"
	TrustRootPublicGood  = "public-good"
	trustRootCustomLabel = "custom:"
)

// Result is what was found for one digest. It is the body of
// POST /images/{digest}/attestation (see supplychain/README.md).
type Result struct {
	SchemaVersion int       `json:"schema_version"`
	Digest        string    `json:"digest"`
	Repository    string    `json:"repository"`
	CheckedAt     time.Time `json:"checked_at"`
	Verdict       string    `json:"verdict"`
	Reason        string    `json:"reason,omitempty"`
	TrustRoot     string    `json:"trust_root"`
	// SignedVia is "index" when the signature was found on the multi-arch
	// index that lists Digest rather than on Digest itself.
	SignedVia    string        `json:"signed_via,omitempty"`
	SignedDigest string        `json:"signed_digest,omitempty"`
	Signatures   []Signature   `json:"signatures"`
	Attestations []Attestation `json:"attestations"`
}

// Signature is one cosign signature over the image.
type Signature struct {
	Format   string `json:"format"`
	Source   string `json:"source"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
	// Detail is a bounded, human-readable error message.
	Detail string `json:"detail,omitempty"`
	// Subject is the digest the signature is bound to when it is not the
	// running digest (a signed multi-arch index that lists it).
	Subject string `json:"subject,omitempty"`
	Signer
}

// Signer is the verified signer: the identity from the Fulcio
// certificate (keyless), or the configured key that verified the
// signature. Empty for a signature that did not verify, except KeyHint.
type Signer struct {
	// Kind is SignerKeyless or SignerKey.
	Kind   string `json:"signer_kind,omitempty"`
	Issuer string `json:"issuer,omitempty"`
	SAN    string `json:"san,omitempty"`
	// KeyName is the configured key's name, KeyFingerprint the sha256
	// (hex) of its DER SubjectPublicKeyInfo.
	KeyName        string `json:"key_name,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	// KeyHint is the key hint a key-signed bundle carries, verified or
	// not (cosign sets it to the base64 sha256 of the public key).
	KeyHint        string     `json:"key_hint,omitempty"`
	IntegratedTime *time.Time `json:"integrated_time,omitempty"`
	TlogIndex      *int64     `json:"tlog_index,omitempty"`
}

// Attestation is one signed in-toto statement about the image.
type Attestation struct {
	PredicateType string `json:"predicate_type"`
	Format        string `json:"format"`
	Source        string `json:"source"`
	Verified      bool   `json:"verified"`
	Error         string `json:"error,omitempty"`
	Detail        string `json:"detail,omitempty"`
	// PayloadSHA256 is the sha256 (hex) of the DSSE payload, i.e. the raw
	// in-toto statement bytes. Lets another component prove it holds the
	// same statement.
	PayloadSHA256 string      `json:"payload_sha256,omitempty"`
	Provenance    *Provenance `json:"provenance,omitempty"`
	// Subject: as for Signature.
	Subject string `json:"subject,omitempty"`
	Signer
}

// Provenance is the part of a SLSA provenance predicate worth showing.
type Provenance struct {
	BuilderID    string `json:"builder_id,omitempty"`
	BuildType    string `json:"build_type,omitempty"`
	SourceRepo   string `json:"source_repo,omitempty"`
	SourceCommit string `json:"source_commit,omitempty"`
	SourceRef    string `json:"source_ref,omitempty"`
}

// IsSBOM reports whether a predicate type is an SBOM (CycloneDX or SPDX).
func IsSBOM(predicateType string) bool {
	switch {
	case predicateType == PredicateCycloneDX,
		predicateType == PredicateSPDX,
		len(predicateType) > len(PredicateSPDX) && predicateType[:len(PredicateSPDX)+1] == PredicateSPDX+"/":
		return true
	}
	return false
}
