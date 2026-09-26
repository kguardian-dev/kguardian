package attest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
)

const (
	sanCosignKeyless = "keyless@projectsigstore.iam.gserviceaccount.com"
	sanK8sRelease    = "krel-trust@k8s-releng-prod.iam.gserviceaccount.com"
	issuerGoogle     = "https://accounts.google.com"
	issuerGitHub     = "https://token.actions.githubusercontent.com"

	// kguardian's own release identity (docs/verifying-releases.mdx).
	kguardianReleaseSAN = `^https://github\.com/kguardian-dev/kguardian/\.github/workflows/(controller|broker|frontend|llm-bridge|evaluator|supplychain)-release\.yaml@refs/tags/(controller|broker|frontend|llm-bridge|evaluator|supplychain)/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`
)

func verified(t *testing.T, r Result) Signature {
	t.Helper()
	for _, s := range r.Signatures {
		if s.Verified {
			return s
		}
	}
	t.Fatalf("no verified signature in %+v", r)
	return Signature{}
}

func wantVerdict(t *testing.T, r Result, verdict, reason string) {
	t.Helper()
	if r.Verdict != verdict || r.Reason != reason {
		b, _ := json.MarshalIndent(r, "", " ")
		t.Fatalf("verdict = %s(%s), want %s(%s)\n%s", r.Verdict, r.Reason, verdict, reason, b)
	}
}

// The cosign v3 bundle signature is found through the referrers API and,
// on a registry without it (GHCR), through the sha256-<hex> tag fallback.
func TestCosignBundleBothReferrerPaths(t *testing.T) {
	for _, api := range []bool{true, false} {
		name := "tag-fallback"
		if api {
			name = "referrers-api"
		}
		t.Run(name, func(t *testing.T) {
			reg := newFixtureRegistry(t, api)
			tg := reg.load(loadRecording(t, "cosign-v3.1.3"), "")
			r := newFixtureVerifier(t).Verify(context.Background(), tg)
			wantVerdict(t, r, VerdictVerified, "")
			s := verified(t, r)
			if s.Format != FormatCosignBundle || s.Issuer != issuerGoogle || s.SAN != sanCosignKeyless {
				t.Fatalf("signer = %+v", s)
			}
			if s.TlogIndex == nil || s.IntegratedTime == nil {
				t.Fatalf("missing tlog data: %+v", s)
			}
			if r.SignedVia != SignedViaSelf || r.SignedDigest != tg.Digest || r.TrustRoot == "" {
				t.Fatalf("signed via %q %q root %q", r.SignedVia, r.SignedDigest, r.TrustRoot)
			}
			// The second bundle is signed with a KMS key: reported, not
			// counted as invalid.
			var keyed int
			for _, s := range r.Signatures {
				if s.Error == ReasonUntrustedKey {
					keyed++
				}
			}
			if keyed != 1 || len(r.Signatures) != 2 {
				t.Fatalf("signatures = %+v", r.Signatures)
			}
		})
	}
}

func TestLegacySignature(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "pause-3.10"), "")
	r := newFixtureVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictVerified, "")
	s := verified(t, r)
	if s.Format != FormatCosignLegacy || s.Source != SourceSigTag || s.SAN != sanK8sRelease || s.Issuer != issuerGoogle {
		t.Fatalf("signer = %+v", s)
	}
	if s.TlogIndex == nil || *s.TlogIndex != 96410323 {
		t.Fatalf("tlog index = %v", s.TlogIndex)
	}
}

func TestLegacyAttestationsAndSBOMTrust(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "chainguard-static"), "")
	v := newFixtureVerifier(t)
	r := v.Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictVerified, "")
	got := map[string]Attestation{}
	for _, a := range r.Attestations {
		got[a.PredicateType] = a
	}
	slsa, ok := got[PredicateSLSAv1]
	if !ok || !slsa.Verified || slsa.Format != FormatCosignLegacyAtt || slsa.Provenance == nil {
		t.Fatalf("slsa = %+v", slsa)
	}
	sbom, ok := got[PredicateSPDX]
	if !ok || !sbom.Verified || len(sbom.PayloadSHA256) != 64 || sbom.SAN == "" {
		t.Fatalf("sbom = %+v", sbom)
	}
	info, ok := v.SBOMTrust(tg.Digest)
	if !ok || !info.Verified || info.PredicateType != PredicateSPDX || info.PayloadSHA256 != sbom.PayloadSHA256 {
		t.Fatalf("SBOMTrust = %+v %v", info, ok)
	}
}

func TestProvenanceOnlyIsUnsignedWithVerifiedProvenance(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "actions-runner"), "")
	r := newFixtureVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictUnsigned, "")
	if len(r.Attestations) != 1 {
		t.Fatalf("attestations = %+v", r.Attestations)
	}
	a := r.Attestations[0]
	if !a.Verified || a.PredicateType != PredicateSLSAv1 || a.Issuer != issuerGitHub {
		t.Fatalf("attestation = %+v", a)
	}
	p := a.Provenance
	if p == nil || p.SourceRepo != "https://github.com/actions/runner" || p.SourceCommit != "397b032cbf865e9c3ddfab89d533ec19325e1273" ||
		!strings.HasPrefix(p.BuilderID, "https://github.com/actions/runner/.github/workflows/release.yml") {
		t.Fatalf("provenance = %+v", p)
	}
}

func TestUnsignedKguardianImage(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), "")
	r := newFixtureVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictUnsigned, "")
	if len(r.Signatures) != 0 || len(r.Attestations) != 0 {
		t.Fatalf("found %+v", r)
	}
}

// A real signature for another image, copied onto this one's .sig tag.
func TestTamperedSignatureForAnotherDigest(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	pause := loadRecording(t, "pause-3.10")
	tg := reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), "")
	repo := repoPath(loadRecording(t, "kguardian-controller-v1.15.1").Repository)
	for _, b := range pause.Blobs {
		reg.putBlob(repo, b.Digest, b.Body)
	}
	sigTag := "sha256-" + strings.TrimPrefix(tg.Digest, "sha256:") + ".sig"
	for _, m := range pause.Manifests {
		if strings.HasSuffix(m.Ref, ".sig") {
			reg.putManifest(repo, sigTag, m.MediaType, m.Body)
		}
	}
	r := newFixtureVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictInvalid, ReasonDigestMismatch)
}

// A signature whose bytes were altered.
func TestTamperedSignatureBytes(t *testing.T) {
	reg := newFixtureRegistry(t, false)
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
		body, _ := json.Marshal(doc)
		rec.Manifests[i].Body = body
	}
	tg := reg.load(rec, "")
	r := newFixtureVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictInvalid, ReasonBadSignature)
}

// A cosign bundle referrer re-pointed at another image.
func TestTamperedBundleReferrer(t *testing.T) {
	reg := newFixtureRegistry(t, true)
	cosign := loadRecording(t, "cosign-v3.1.3")
	ctrl := loadRecording(t, "kguardian-controller-v1.15.1")
	tg := reg.load(ctrl, "")
	repo := repoPath(ctrl.Repository)
	for _, b := range cosign.Blobs {
		reg.putBlob(repo, b.Digest, b.Body)
	}
	var subjectMT string
	for _, m := range ctrl.Manifests {
		if m.Ref == ctrl.Digest {
			subjectMT = m.MediaType
		}
	}
	for _, m := range cosign.Manifests {
		var doc map[string]any
		if err := json.Unmarshal(m.Body, &doc); err != nil || doc["artifactType"] == nil {
			continue
		}
		doc["subject"] = map[string]any{"mediaType": subjectMT, "digest": ctrl.Digest, "size": 1}
		body, _ := json.Marshal(doc)
		reg.putManifest(repo, "sha256-"+strings.Repeat("0", 8)+"-"+m.Ref[7:19], m.MediaType, body)
	}
	r := newFixtureVerifier(t).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictInvalid, ReasonDigestMismatch)
}

// A valid signature from a signer the identity list does not trust.
func TestWrongIdentity(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "cosign-v3.1.3"), "")
	kg := Identity{Issuer: issuerGitHub, SubjectRegExp: kguardianReleaseSAN}
	r := newFixtureVerifier(t, kg).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictUntrustedIdentity, "")
	if s := verified(t, r); s.SAN != sanCosignKeyless {
		t.Fatalf("signer = %+v", s)
	}
	ok := Identity{Issuer: issuerGoogle, Subject: sanCosignKeyless}
	r = newFixtureVerifier(t, kg, ok).Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictVerified, "")
}

// The four outcomes the brief requires are distinct and correct.
func TestFourDistinctVerdicts(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	signed := reg.load(loadRecording(t, "cosign-v3.1.3"), "")
	unsigned := reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), "")
	pause := loadRecording(t, "pause-3.10")
	tampered := reg.load(loadRecording(t, "kguardian-controller-v1.15.1"), "tampered/controller")
	for _, b := range pause.Blobs {
		reg.putBlob("tampered/controller", b.Digest, b.Body)
	}
	for _, m := range pause.Manifests {
		if strings.HasSuffix(m.Ref, ".sig") {
			reg.putManifest("tampered/controller", "sha256-"+strings.TrimPrefix(tampered.Digest, "sha256:")+".sig", m.MediaType, m.Body)
		}
	}
	v := newFixtureVerifier(t, Identity{Issuer: issuerGoogle, Subject: sanCosignKeyless})
	wrong := newFixtureVerifier(t, Identity{Issuer: issuerGitHub, SubjectRegExp: kguardianReleaseSAN})
	got := map[string]bool{
		v.Verify(context.Background(), signed).Verdict:     true,
		v.Verify(context.Background(), unsigned).Verdict:   true,
		v.Verify(context.Background(), tampered).Verdict:   true,
		wrong.Verify(context.Background(), signed).Verdict: true,
	}
	for _, want := range []string{VerdictVerified, VerdictUnsigned, VerdictInvalid, VerdictUntrustedIdentity} {
		if !got[want] {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("verdicts = %v", got)
	}
}

// A platform manifest whose signature is on the index that lists it.
func TestSignedViaIndex(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	rec := loadRecording(t, "pause-3.10")
	tg := reg.load(rec, "")
	var idx recManifest
	for _, m := range rec.Manifests {
		if m.Ref == rec.Digest {
			idx = m
		}
	}
	reg.putManifest(repoPath(rec.Repository), "3.10", idx.MediaType, idx.Body)
	var platform string
	for _, m := range rec.Manifests {
		if strings.HasPrefix(m.Ref, "sha256:") && m.Ref != rec.Digest && !v1MediaIsIndex(m.MediaType) {
			platform = m.Ref
			break
		}
	}
	if platform == "" {
		t.Fatal("no platform manifest recorded")
	}
	r := newFixtureVerifier(t).Verify(context.Background(), Target{Repository: tg.Repository, Digest: platform, DigestKind: "repo", Tags: []string{"3.10"}})
	wantVerdict(t, r, VerdictVerified, "")
	if r.SignedVia != SignedViaIndex || r.SignedDigest != rec.Digest || verified(t, r).Subject != rec.Digest {
		t.Fatalf("signed via %q %q", r.SignedVia, r.SignedDigest)
	}
	// Without a tag there is no route to the index: unsigned for this
	// digest, which is what a cosign verify of it would say.
	r = newFixtureVerifier(t).Verify(context.Background(), Target{Repository: tg.Repository, Digest: platform, DigestKind: "repo"})
	wantVerdict(t, r, VerdictUnsigned, "")
}

// A private registry answers 401 anonymously: unknown, never unsigned.
func TestPrivateRegistryIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := newFixtureVerifier(t).Verify(context.Background(), Target{Repository: u.Host + "/private/app", Digest: "sha256:" + strings.Repeat("a", 64), DigestKind: "repo"})
	wantVerdict(t, r, VerdictUnknown, ReasonRegistryAuth)
}

func TestRateLimitedRegistryIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	v := newFixtureVerifier(t)
	r := v.Verify(context.Background(), Target{Repository: u.Host + "/busy/app", Digest: "sha256:" + strings.Repeat("b", 64), DigestKind: "repo"})
	wantVerdict(t, r, VerdictUnknown, ReasonRateLimited)
}

func TestNoRepoDigest(t *testing.T) {
	r := newFixtureVerifier(t).Verify(context.Background(), Target{Repository: "ghcr.io/a/b", Digest: "sha256:" + strings.Repeat("c", 64), DigestKind: "config"})
	wantVerdict(t, r, VerdictUnknown, ReasonNoRepoDigest)
}

// The guard refuses metadata and loopback destinations before any request.
func TestGuardRefusal(t *testing.T) {
	var hits atomic.Int32
	v, err := New(Options{Guard: registry.Guard{}, TrustRoot: fixtureTrustRoot(t), transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		hits.Add(1)
		return nil, http.ErrHandlerTimeout
	})})
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"169.254.169.254/latest/app", "127.0.0.1:5000/app", "localhost/app"} {
		r := v.Verify(context.Background(), Target{Repository: repo, Digest: "sha256:" + strings.Repeat("d", 64), DigestKind: "repo"})
		wantVerdict(t, r, VerdictUnknown, registry.ReasonBlockedAddress)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests made", hits.Load())
	}
}

func TestTrustRootUnavailable(t *testing.T) {
	v, err := New(Options{TrustRoot: &FileTrustRoot{Path: "testdata/missing.json"}, skipHostCheck: true, transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	r := v.Verify(context.Background(), Target{Repository: "ghcr.io/a/b", Digest: "sha256:" + strings.Repeat("e", 64), DigestKind: "repo"})
	wantVerdict(t, r, VerdictUnknown, ReasonTrustRootUnavailable)
}

// A digest is looked up once per TTL.
func TestCache(t *testing.T) {
	reg := newFixtureRegistry(t, false)
	tg := reg.load(loadRecording(t, "pause-3.10"), "")
	var hits atomic.Int32
	v, err := New(Options{TrustRoot: fixtureTrustRoot(t), Insecure: true, skipHostCheck: true, RegistryRPS: 1000, RegistryBurst: 1000,
		transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			hits.Add(1)
			return http.DefaultTransport.RoundTrip(r)
		})})
	if err != nil {
		t.Fatal(err)
	}
	v.Verify(context.Background(), tg)
	first := hits.Load()
	r := v.Verify(context.Background(), tg)
	wantVerdict(t, r, VerdictVerified, "")
	if first == 0 || hits.Load() != first {
		t.Fatalf("requests: first pass %d, after second %d", first, hits.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
