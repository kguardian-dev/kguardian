package imagetrust

import (
	"strings"
	"testing"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
)

// Signers as the broker served them for the supplychain acceptance
// fixtures (TestBrokerE2E in supplychain/pkg/attest).
const (
	k8sIssuer = "https://accounts.google.com"
	k8sSAN    = "krel-trust@k8s-releng-prod.iam.gserviceaccount.com"
	// supplychain/pkg/attest/testdata/cosign.pub and its fingerprint.
	fixturePub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErBclBIBz28Uo7W6PFzioZ8s5BVr2
EYJgLPCfyhpM7+6uFQCC2ImZ9FKVx4+CV1qtW4tSBa49kJwn4pedaEd69A==
-----END PUBLIC KEY-----`
	fixtureFP = "e2312c28209f4778ffc6c0ca2786638bb86d6027ee8092aba67c5d94d268ee30"
)

func str(s string) *string { return &s }

func container(verdict *string, signers ...Signer) Container {
	return Container{Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "api", Container: "app",
		Digest: "sha256:" + strings.Repeat("a", 64), ImageRef: "registry.k8s.io/pause:3.10",
		Repository: str("registry.k8s.io/pause"), Verdict: verdict, Signers: signers}
}

var (
	keyless  = container(str("verified"), Signer{Kind: "keyless", Issuer: k8sIssuer, SAN: k8sSAN})
	keyed    = container(str("verified"), Signer{Kind: "key", KeyFingerprint: fixtureFP})
	unsigned = container(str("unsigned"))
	tampered = container(str("invalid"))
)

func policy(t *testing.T, spec v1alpha1.ImageTrustPolicySpec) *Policy {
	t.Helper()
	p, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func both() v1alpha1.ImageTrustPolicySpec {
	return v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{
		{Name: "k8s", Keyless: &v1alpha1.KeylessAuthority{Issuer: k8sIssuer, Subject: k8sSAN}},
		{Name: "fixture", Key: &v1alpha1.KeyAuthority{Fingerprint: fixtureFP}},
	}}
}

func want(t *testing.T, p *Policy, c Container, verdict, reason string) {
	t.Helper()
	v, r := p.Evaluate(c)
	if v != verdict || r != reason {
		t.Fatalf("got %s(%s), want %s(%s)", v, r, verdict, reason)
	}
}

// The four acceptance fixtures give four distinct, correct outcomes.
func TestFourFixtures(t *testing.T) {
	p := policy(t, both())
	want(t, p, keyless, v1alpha1.ImageTrusted, "")
	want(t, p, keyed, v1alpha1.ImageTrusted, "")
	want(t, p, unsigned, v1alpha1.ImageWouldDeny, ReasonUnsigned)
	want(t, p, tampered, v1alpha1.ImageWouldDeny, ReasonInvalid)

	// Trusting only the keyless identity: the key image is an untrusted
	// signer, and vice versa.
	kl := policy(t, v1alpha1.ImageTrustPolicySpec{Authorities: both().Authorities[:1]})
	want(t, kl, keyed, v1alpha1.ImageWouldDeny, ReasonUntrustedSigner)
	k := policy(t, v1alpha1.ImageTrustPolicySpec{Authorities: both().Authorities[1:]})
	want(t, k, keyless, v1alpha1.ImageWouldDeny, ReasonUntrustedSigner)
	want(t, k, keyed, v1alpha1.ImageTrusted, "")
}

func TestUnknownIsNeverTrusted(t *testing.T) {
	p := policy(t, both())
	want(t, p, container(nil), v1alpha1.ImageUnknown, ReasonNotChecked)
	c := container(str("unknown"))
	c.Reason = str("registry_auth")
	want(t, p, c, v1alpha1.ImageUnknown, "registry_auth")
	want(t, p, container(str("something-new")), v1alpha1.ImageUnknown, ReasonNotChecked)
}

// A key signature supplychain could not check: if the policy trusts a key
// the likely fix is giving supplychain the key.
func TestKeySigned(t *testing.T) {
	want(t, policy(t, both()), container(str("key_signed")), v1alpha1.ImageWouldDeny, ReasonKeyNotVerified)
	kl := policy(t, v1alpha1.ImageTrustPolicySpec{Authorities: both().Authorities[:1]})
	want(t, kl, container(str("key_signed")), v1alpha1.ImageWouldDeny, ReasonUntrustedSigner)
}

// A keyless signer whose SAN merely contains the trusted one does not
// match: regexps are full-match.
func TestRegexpsAreAnchored(t *testing.T) {
	p := policy(t, v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Keyless: &v1alpha1.KeylessAuthority{
		Issuer:        "https://token.actions.githubusercontent.com",
		SubjectRegExp: `https://github\.com/example/api/\.github/workflows/release\.yaml@refs/tags/v.*`,
	}}}})
	good := container(str("verified"), Signer{Kind: "keyless", Issuer: "https://token.actions.githubusercontent.com",
		SAN: "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1.2.3"})
	want(t, p, good, v1alpha1.ImageTrusted, "")
	evil := container(str("verified"), Signer{Kind: "keyless", Issuer: "https://token.actions.githubusercontent.com",
		SAN: "https://github.com/attacker/x/.github/workflows/y.yaml@refs/heads/https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1"})
	want(t, p, evil, v1alpha1.ImageWouldDeny, ReasonUntrustedSigner)
	// A key signer never matches a keyless authority, even with an
	// issuer-shaped field.
	fake := container(str("verified"), Signer{Kind: "key", Issuer: "https://token.actions.githubusercontent.com", SAN: good.Signers[0].SAN})
	want(t, p, fake, v1alpha1.ImageWouldDeny, ReasonUntrustedSigner)
}

func TestAttestations(t *testing.T) {
	spec := both()
	spec.Attestations = []v1alpha1.AttestationRequirement{{
		PredicateType:    "https://slsa.dev/provenance/v1",
		SourceRepoRegExp: `https://github\.com/example/.*`,
	}}
	p := policy(t, spec)
	want(t, p, keyless, v1alpha1.ImageWouldDeny, ReasonAttestationMissing)

	c := keyless
	prov := Signed{PredicateType: "https://slsa.dev/provenance/v1", Signer: keyless.Signers[0]}
	prov.Provenance = &struct {
		BuilderID  string `json:"builderId"`
		SourceRepo string `json:"sourceRepo"`
	}{BuilderID: "b", SourceRepo: "https://github.com/example/api"}
	c.Attestations = []Signed{prov}
	want(t, p, c, v1alpha1.ImageTrusted, "")

	// Signed by someone the policy does not trust: missing.
	other := prov
	other.Signer = Signer{Kind: "keyless", Issuer: "https://token.actions.githubusercontent.com", SAN: "x"}
	c.Attestations = []Signed{other}
	want(t, p, c, v1alpha1.ImageWouldDeny, ReasonAttestationMissing)

	// Wrong source repository: missing.
	wrong := prov
	wrong.Provenance = &struct {
		BuilderID  string `json:"builderId"`
		SourceRepo string `json:"sourceRepo"`
	}{SourceRepo: "https://github.com/attacker/api"}
	c.Attestations = []Signed{wrong}
	want(t, p, c, v1alpha1.ImageWouldDeny, ReasonAttestationMissing)
}

func TestImagesGlob(t *testing.T) {
	p := policy(t, v1alpha1.ImageTrustPolicySpec{Images: []string{"ghcr.io/example/*", "registry.k8s.io/**"}, Authorities: both().Authorities})
	for repo, sel := range map[string]bool{
		"ghcr.io/example/api":         true,
		"ghcr.io/example/team/api":    false,
		"registry.k8s.io/pause":       true,
		"registry.k8s.io/sig/x/y":     true,
		"ghcr.io/examplex/api":        false,
		"evil.io/ghcr.io/example/api": false,
	} {
		c := keyless
		c.Repository = str(repo)
		if p.Selects(c) != sel {
			t.Errorf("%s: selects = %v", repo, !sel)
		}
	}
	// No repository (node-local image): the ref without tag or digest.
	c := keyless
	c.Repository, c.ImageRef = nil, "ghcr.io/example/api:1.0@sha256:abc"
	if !p.Selects(c) {
		t.Error("ref fallback not selected")
	}
	c.ImageRef = "localhost:5000/example/api:1.0"
	if p.Selects(c) {
		t.Error("registry port parsed as tag")
	}
}

// The fingerprint of a PEM key equals the one supplychain reports, so a
// policy can carry the key itself.
func TestKeyAuthorityFromPEM(t *testing.T) {
	fp, err := Fingerprint(fixturePub)
	if err != nil || fp != fixtureFP {
		t.Fatalf("fingerprint %s, %v", fp, err)
	}
	p := policy(t, v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Key: &v1alpha1.KeyAuthority{PublicKey: fixturePub}}}})
	want(t, p, keyed, v1alpha1.ImageTrusted, "")
	if _, err := Compile(v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Key: &v1alpha1.KeyAuthority{
		PublicKey: fixturePub, Fingerprint: strings.Repeat("0", 64)}}}}); err == nil {
		t.Fatal("mismatched fingerprint accepted")
	}
}

func TestCompileErrors(t *testing.T) {
	kl := func(k v1alpha1.KeylessAuthority) v1alpha1.ImageTrustPolicySpec {
		return v1alpha1.ImageTrustPolicySpec{Authorities: []v1alpha1.Authority{{Keyless: &k}}}
	}
	for name, spec := range map[string]v1alpha1.ImageTrustPolicySpec{
		"no authorities":  {},
		"both kinds":      {Authorities: []v1alpha1.Authority{{Keyless: &v1alpha1.KeylessAuthority{Issuer: "i", Subject: "s"}, Key: &v1alpha1.KeyAuthority{Fingerprint: fixtureFP}}}},
		"neither kind":    {Authorities: []v1alpha1.Authority{{Name: "x"}}},
		"no subject":      kl(v1alpha1.KeylessAuthority{Issuer: "i"}),
		"exact and regex": kl(v1alpha1.KeylessAuthority{Issuer: "i", IssuerRegExp: "i", Subject: "s"}),
		"bad regexp":      kl(v1alpha1.KeylessAuthority{Issuer: "i", SubjectRegExp: "("}),
		"bad fingerprint": {Authorities: []v1alpha1.Authority{{Key: &v1alpha1.KeyAuthority{Fingerprint: "abc"}}}},
		"bad pem":         {Authorities: []v1alpha1.Authority{{Key: &v1alpha1.KeyAuthority{PublicKey: "nope"}}}},
		"no predicate":    {Authorities: both().Authorities, Attestations: []v1alpha1.AttestationRequirement{{}}},
	} {
		if _, err := Compile(spec); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}
