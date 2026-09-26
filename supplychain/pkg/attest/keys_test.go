package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureKeyHint is cosign's hint for testdata/cosign.pub: base64 of the
// sha256 of its DER SubjectPublicKeyInfo (checked with openssl).
const fixtureKeyHint = "4jEsKCCfR3j/xsDKJ4Zji7htYCfugJKrpnxdlNJo7jA="

func fixtureKey(t *testing.T) PublicKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return PublicKey{Name: "fixture", PEM: string(b)}
}

func otherKey(t *testing.T) PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return PublicKey{Name: "other", PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

func newKeyVerifier(t *testing.T, keys ...PublicKey) *Verifier {
	t.Helper()
	v, err := New(Options{
		TrustRoot:     fixtureTrustRoot(t),
		TrustedKeys:   keys,
		Insecure:      true,
		transport:     http.DefaultTransport,
		skipHostCheck: true,
		RegistryRPS:   1000,
		RegistryBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestParseKeys(t *testing.T) {
	ks, err := parseKeys([]PublicKey{fixtureKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	if ks[0].hint != fixtureKeyHint || len(ks[0].fingerprint) != 64 {
		t.Fatalf("key = %+v", ks[0])
	}
	for _, bad := range [][]PublicKey{
		{{Name: "", PEM: fixtureKey(t).PEM}},
		{{Name: "x", PEM: "not a key"}},
		{fixtureKey(t), fixtureKey(t)},
	} {
		if _, err := parseKeys(bad); err == nil {
			t.Fatalf("parseKeys(%v) accepted", bad)
		}
	}
}

// Real cosign v3.0.5 key signatures, in both storage formats.
func TestKeySigned(t *testing.T) {
	for _, file := range []string{"key-legacy", "key-bundle"} {
		t.Run(file, func(t *testing.T) {
			reg := newFixtureRegistry(t, false)
			tg := reg.load(loadRecording(t, file), "")

			// No keys configured: a signature exists, nobody can check it.
			r := newKeyVerifier(t).Verify(context.Background(), tg)
			wantVerdict(t, r, VerdictKeySigned, ReasonUntrustedKey)
			if len(r.Signatures) != 1 || r.Signatures[0].Verified || r.Signatures[0].Error != ReasonUntrustedKey {
				t.Fatalf("signatures = %+v", r.Signatures)
			}
			wantHint := ""
			if file == "key-bundle" {
				wantHint = fixtureKeyHint
			}
			if r.Signatures[0].KeyHint != wantHint {
				t.Fatalf("hint = %q, want %q", r.Signatures[0].KeyHint, wantHint)
			}

			// A different key: still key_signed, never verified.
			r = newKeyVerifier(t, otherKey(t)).Verify(context.Background(), tg)
			wantVerdict(t, r, VerdictKeySigned, ReasonUntrustedKey)

			// The signing key configured: verified, attributed to it.
			r = newKeyVerifier(t, otherKey(t), fixtureKey(t)).Verify(context.Background(), tg)
			wantVerdict(t, r, VerdictVerified, "")
			s := verified(t, r)
			ks, _ := parseKeys([]PublicKey{fixtureKey(t)})
			if s.Kind != SignerKey || s.KeyName != "fixture" || s.KeyFingerprint != ks[0].fingerprint || s.Issuer != "" || s.SAN != "" {
				t.Fatalf("signer = %+v", s)
			}
			if r.SignedVia != SignedViaSelf {
				t.Fatalf("signed via %q", r.SignedVia)
			}
		})
	}
}

// A configured key makes identity lists irrelevant for its signatures.
func TestKeySignedWithIdentityList(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "key-legacy"), "")
	v, err := New(Options{
		TrustRoot: fixtureTrustRoot(t), TrustedKeys: []PublicKey{fixtureKey(t)},
		TrustedIdentities: []Identity{{Issuer: issuerGitHub, SubjectRegExp: kguardianReleaseSAN}},
		Insecure:          true, transport: http.DefaultTransport, skipHostCheck: true, RegistryRPS: 1000, RegistryBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, v.Verify(context.Background(), tg), VerdictVerified, "")
}

// tamperKeyBundle flips one byte of the DSSE signature in the key-bundle
// recording and re-links the referrer manifest and fallback index to the
// altered blob, as an attacker with registry write access would.
func tamperKeyBundle(t *testing.T) recording {
	t.Helper()
	rec := loadRecording(t, "key-bundle")
	var oldBlob, newBlob string
	var newSize int
	for i, b := range rec.Blobs {
		var doc map[string]any
		if json.Unmarshal(b.Body, &doc) != nil || doc["dsseEnvelope"] == nil {
			continue
		}
		sigs := doc["dsseEnvelope"].(map[string]any)["signatures"].([]any)
		s0 := sigs[0].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(s0["sig"].(string))
		raw[len(raw)-1] ^= 0x01
		s0["sig"] = base64.StdEncoding.EncodeToString(raw)
		body, _ := json.Marshal(doc)
		oldBlob, newBlob, newSize = b.Digest, sha(body), len(body)
		rec.Blobs[i] = recBlob{Digest: newBlob, Body: body}
	}
	if oldBlob == "" {
		t.Fatal("no bundle blob in key-bundle")
	}
	relink := func(from, to string, size int, which func(recManifest) bool) (string, string) {
		for i, m := range rec.Manifests {
			if !which(m) {
				continue
			}
			body := strings.Replace(string(m.Body), from, to, 1)
			if size >= 0 {
				var doc map[string]any
				_ = json.Unmarshal([]byte(body), &doc)
				for _, l := range doc["layers"].([]any) {
					if l.(map[string]any)["digest"] == to {
						l.(map[string]any)["size"] = size
					}
				}
				b, _ := json.Marshal(doc)
				body = string(b)
			}
			old := m.Ref
			rec.Manifests[i].Body = []byte(body)
			if strings.HasPrefix(m.Ref, "sha256:") {
				rec.Manifests[i].Ref = sha([]byte(body))
			}
			return old, rec.Manifests[i].Ref
		}
		t.Fatal("manifest to relink not found")
		return "", ""
	}
	oldRef, newRef := relink(oldBlob, newBlob, newSize, func(m recManifest) bool {
		return strings.Contains(string(m.Body), oldBlob)
	})
	var newRefSize int
	for _, m := range rec.Manifests {
		if m.Ref == newRef {
			newRefSize = len(m.Body)
		}
	}
	fallback := "sha256-" + strings.TrimPrefix(rec.Digest, "sha256:")
	for i, m := range rec.Manifests {
		if m.Ref != fallback {
			continue
		}
		var idx map[string]any
		_ = json.Unmarshal(m.Body, &idx)
		for _, d := range idx["manifests"].([]any) {
			if d.(map[string]any)["digest"] == oldRef {
				d.(map[string]any)["digest"] = newRef
				d.(map[string]any)["size"] = newRefSize
			}
		}
		rec.Manifests[i].Body, _ = json.Marshal(idx)
	}
	return rec
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// A key bundle whose signature was altered: with the key it names
// configured, invalid; without it, still only key_signed (nothing can be
// said about a key we do not hold).
func TestTamperedKeyBundle(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(tamperKeyBundle(t), "")
	r := newKeyVerifier(t, fixtureKey(t)).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictInvalid, ReasonBadSignature)
	if r.Signatures[0].KeyHint != fixtureKeyHint {
		t.Fatalf("hint = %q", r.Signatures[0].KeyHint)
	}
	r = newKeyVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictKeySigned, ReasonUntrustedKey)
}

// A legacy key .sig carries no key hint, so an altered one is
// indistinguishable from a signature by another key: key_signed, never
// verified.
func TestTamperedLegacyKeySignature(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	rec := loadRecording(t, "key-legacy")
	for i, m := range rec.Manifests {
		if !strings.HasSuffix(m.Ref, ".sig") {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(m.Body, &doc); err != nil {
			t.Fatal(err)
		}
		ann := doc["layers"].([]any)[0].(map[string]any)["annotations"].(map[string]any)
		sig, _ := base64.StdEncoding.DecodeString(ann[annSignature].(string))
		sig[len(sig)-1] ^= 0x01
		ann[annSignature] = base64.StdEncoding.EncodeToString(sig)
		rec.Manifests[i].Body, _ = json.Marshal(doc)
	}
	tg := reg.load(rec, "")
	wantVerdict(t, newKeyVerifier(t, fixtureKey(t)).Verify(context.Background(), tg), VerdictKeySigned, ReasonUntrustedKey)
}

// The acceptance fixtures of #1533 P2-1: keyless, key, unsigned and
// tampered each produce a distinct, correct result. Discovery with no
// configuration yields four distinct verdicts; with the signing key
// configured the key fixture verifies and is attributed to the key, not
// to a keyless identity.
func TestAcceptanceFourFixtures(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	keyless := reg.load(loadRecording(t, "pause-3.10"), "")
	key := reg.load(loadRecording(t, "key-legacy"), "")
	unsigned := reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), "")
	tampered := reg.load(tamperKeylessSig(t), "tampered/pause")

	ctx := context.Background()
	disc := newKeyVerifier(t)
	got := map[string]string{
		"keyless":  disc.Verify(ctx, keyless).Verdict,
		"key":      disc.Verify(ctx, key).Verdict,
		"unsigned": disc.Verify(ctx, unsigned).Verdict,
		"tampered": disc.Verify(ctx, tampered).Verdict,
	}
	want := map[string]string{"keyless": VerdictVerified, "key": VerdictKeySigned, "unsigned": VerdictUnsigned, "tampered": VerdictInvalid}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s: verdict %s, want %s (all: %v)", k, got[k], w, got)
		}
	}

	withKey := newKeyVerifier(t, fixtureKey(t))
	ks := verified(t, withKey.Verify(ctx, key))
	kl := verified(t, withKey.Verify(ctx, keyless))
	if ks.Kind != SignerKey || ks.KeyName != "fixture" || kl.Kind != SignerKeyless || kl.SAN != sanK8sRelease || kl.Issuer != issuerGoogle {
		t.Fatalf("key signer %+v, keyless signer %+v", ks, kl)
	}
	wantVerdict(t, withKey.Verify(ctx, unsigned), VerdictUnsigned, "")
	wantVerdict(t, withKey.Verify(ctx, tampered), VerdictInvalid, ReasonBadSignature)
}

// tamperKeylessSig is pause-3.10 with one byte of its keyless signature
// flipped.
func tamperKeylessSig(t *testing.T) recording {
	t.Helper()
	rec := loadRecording(t, "pause-3.10")
	for i, m := range rec.Manifests {
		if !strings.HasSuffix(m.Ref, ".sig") {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(m.Body, &doc); err != nil {
			t.Fatal(err)
		}
		ann := doc["layers"].([]any)[0].(map[string]any)["annotations"].(map[string]any)
		sig, _ := base64.StdEncoding.DecodeString(ann[annSignature].(string))
		sig[len(sig)-1] ^= 0x01
		ann[annSignature] = base64.StdEncoding.EncodeToString(sig)
		rec.Manifests[i].Body, _ = json.Marshal(doc)
	}
	return rec
}
