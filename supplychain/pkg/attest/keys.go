package attest

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// PublicKey is a signing key the operator trusts, for images signed with
// "cosign sign --key" rather than keyless. Public keys only: discovery
// never holds a private key or a KMS reference.
type PublicKey struct {
	// Name labels the key in results (Signer.KeyName).
	Name string
	// PEM is the PKIX public key ("-----BEGIN PUBLIC KEY-----").
	PEM string
}

// trustedKey is a parsed PublicKey.
type trustedKey struct {
	name        string
	fingerprint string // hex sha256 of the DER SubjectPublicKeyInfo
	hint        string // base64 of the same sha256: cosign's bundle key hint
	v           signature.Verifier
}

func parseKeys(keys []PublicKey) ([]trustedKey, error) {
	out := make([]trustedKey, 0, len(keys))
	seen := map[string]bool{}
	for _, k := range keys {
		if strings.TrimSpace(k.Name) == "" {
			return nil, fmt.Errorf("public key needs a name")
		}
		if seen[k.Name] {
			return nil, fmt.Errorf("public key name %q is used twice", k.Name)
		}
		seen[k.Name] = true
		pub, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(k.PEM))
		if err != nil {
			return nil, fmt.Errorf("public key %q: %w", k.Name, err)
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("public key %q: %w", k.Name, err)
		}
		v, err := signature.LoadVerifier(pub, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("public key %q: %w", k.Name, err)
		}
		sum := sha256.Sum256(der)
		out = append(out, trustedKey{
			name:        k.Name,
			fingerprint: hex.EncodeToString(sum[:]),
			hint:        base64.StdEncoding.EncodeToString(sum[:]),
			v:           v,
		})
	}
	return out, nil
}

// pae is the DSSE pre-authentication encoding, what a DSSE signature
// signs.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// verifyWithKeys checks sigs over msg with the configured keys. hint is
// the key hint the signature carries ("" for a legacy .sig).
//
// A signature no key verifies is untrusted_key (signed by a key we do not
// hold) unless the hint names one of our keys: then it claims to be from
// that key and does not verify, which is bad_signature.
func verifyWithKeys(keys []trustedKey, msg []byte, sigs [][]byte, hint string) (Signer, error) {
	for _, k := range keys {
		for _, sig := range sigs {
			if k.v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)) == nil {
				return Signer{Kind: SignerKey, KeyName: k.name, KeyFingerprint: k.fingerprint, KeyHint: hint}, nil
			}
		}
	}
	s := Signer{KeyHint: hint}
	if hint != "" {
		for _, k := range keys {
			if k.hint == hint {
				return s, vErr(ReasonBadSignature, "signature does not verify with key %q, which the signature names", k.name)
			}
		}
	}
	if len(keys) == 0 {
		return s, vErr(ReasonUntrustedKey, "signed with a public key; no keys are configured")
	}
	return s, vErr(ReasonUntrustedKey, "signed with a public key none of the %d configured keys verifies", len(keys))
}
