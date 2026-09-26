package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/sbomdoc"
	sctypes "github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

// The SBOM documents are the real fixtures from pkg/sbomdoc/testdata
// (BuildKit SPDX statement for alpine:3.20 linux/amd64, and syft's
// CycloneDX for the same image); only the registry wrapping is built here,
// following the cosign and BuildKit storage specs.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../sbomdoc/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type reg struct {
	t    *testing.T
	host string
}

func newReg(t *testing.T) *reg {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	return &reg{t: t, host: strings.TrimPrefix(srv.URL, "http://")}
}

func (r *reg) ref(s string) name.Reference {
	ref, err := name.ParseReference(r.host+"/"+s, name.Insecure)
	if err != nil {
		r.t.Fatal(err)
	}
	return ref
}

func (r *reg) push(s string, img v1.Image) v1.Hash {
	r.t.Helper()
	if err := remote.Write(r.ref(s), img); err != nil {
		r.t.Fatal(err)
	}
	d, _ := img.Digest()
	return d
}

// artifact is a one-layer image carrying body with the given media type.
func artifact(t *testing.T, body []byte, mt types.MediaType, ann map[string]string) v1.Image {
	t.Helper()
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: static.NewLayer(body, mt), Annotations: ann, MediaType: mt})
	if err != nil {
		t.Fatal(err)
	}
	return mutate.MediaType(img, types.OCIManifestSchema1)
}

func dsse(stmt []byte) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stmt),
		"signatures":  []map[string]string{{"sig": "MEUCIQ=="}},
	})
	return b
}

func inspector() *Inspector {
	in := New(Guard{allowLoopbackForTest: true})
	in.Insecure = true
	return in
}

// withSubject rewrites an in-toto statement's subject to name digest.
func withSubject(t *testing.T, stmt []byte, digest string) []byte {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(stmt, &m); err != nil {
		t.Fatal(err)
	}
	hexd := strings.TrimPrefix(digest, "sha256:")
	m["subject"] = []interface{}{map[string]interface{}{"name": "image", "digest": map[string]string{"sha256": hexd}}}
	b, _ := json.Marshal(m)
	return b
}

func cdxStatement(t *testing.T, subject string) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": sbomdoc.PredicateCycloneDX,
		"subject": []interface{}{}, "predicate": json.RawMessage(fixture(t, "alpine-cyclonedx.json")),
	})
	if subject != "" {
		b = withSubject(t, b, subject)
	}
	return b
}

func fetchAll(t *testing.T, host, repo, digest string) ([]FoundSBOM, []string) {
	t.Helper()
	found, rejected, err := inspector().FetchSBOMs(context.Background(), host, repo, digest)
	if err != nil {
		t.Fatal(err)
	}
	return found, rejected
}

func buildKitIndex(t *testing.T, r *reg, stmt []byte) (idx, amd v1.Hash) {
	t.Helper()
	amdImg, _ := random.Image(64, 1)
	amdDigest, _ := amdImg.Digest()
	att := artifact(t, withSubjectIf(t, stmt, amdDigest.String()), mtInToto, map[string]string{annPredicateType: sbomdoc.PredicateSPDX})
	prov := artifact(t, []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","predicate":{}}`),
		mtInToto, map[string]string{annPredicateType: "https://slsa.dev/provenance/v0.2"})
	// BuildKit puts SBOM and provenance in one attestation manifest.
	both, _ := mutate.Append(att, mutate.Addendum{Layer: mustLayer(t, prov), Annotations: map[string]string{annPredicateType: "https://slsa.dev/provenance/v0.2"}, MediaType: mtInToto})
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amdImg, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: both, Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{annRefType: "attestation-manifest", annRefDigest: amdDigest.String()},
		}},
	)
	if err := remote.WriteIndex(r.ref("library/alpine:3.20"), index); err != nil {
		t.Fatal(err)
	}
	idx, _ = index.Digest()
	return idx, amdDigest
}

// withSubjectIf keeps stmt when it already names a subject we want to
// keep (the mismatch test passes its own), else points it at digest.
func withSubjectIf(t *testing.T, stmt []byte, digest string) []byte {
	if strings.Contains(string(stmt), "keep-subject") {
		return stmt
	}
	return withSubject(t, stmt, digest)
}

func TestFetchBuildKitAttestation(t *testing.T) {
	r := newReg(t)
	idx, amd := buildKitIndex(t, r, fixture(t, "alpine-spdx-intoto.json"))
	found, rejected := fetchAll(t, r.host, "library/alpine", idx.String())
	if len(found) != 1 || len(rejected) != 0 {
		t.Fatalf("found %d, rejected %v", len(found), rejected)
	}
	f := found[0]
	if f.Subject != amd.String() || f.IndexDigest != idx.String() {
		t.Errorf("subject %s index %s, want %s under %s", f.Subject, f.IndexDigest, amd, idx)
	}
	if f.Attestation.Mechanism != sctypes.MechanismBuildKitAttestation || f.Attestation.PredicateType != sbomdoc.PredicateSPDX ||
		f.Attestation.Verified || f.Trust != sctypes.SBOMTrustUnverified || len(f.Doc.Components) != 17 {
		t.Errorf("found: %+v trust=%s (%d components)", f.Attestation, f.Trust, len(f.Doc.Components))
	}
}

// A statement whose subject is some other image is rejected, never used.
func TestFetchRejectsSubjectMismatch(t *testing.T) {
	r := newReg(t)
	// The real fixture names alpine's linux/amd64 manifest, which is not
	// part of this registry's index.
	stmt := fixture(t, "alpine-spdx-intoto.json")
	var m map[string]interface{}
	_ = json.Unmarshal(stmt, &m)
	m["keep-subject"] = true
	stmt, _ = json.Marshal(m)
	idx, _ := buildKitIndex(t, r, stmt)
	found, rejected := fetchAll(t, r.host, "library/alpine", idx.String())
	if len(found) != 0 || len(rejected) != 1 || rejected[0] != RejectSubjectMismatch {
		t.Fatalf("found %+v rejected %v", found, rejected)
	}

	// Same through a cosign .att on a plain image, and a statement with no
	// subject at all.
	img, _ := random.Image(64, 1)
	d := r.push("app:1", img)
	tagBase := "app:" + strings.Replace(d.String(), ":", "-", 1)
	r.push(tagBase+".att", artifact(t, dsse(cdxStatement(t, "sha256:"+strings.Repeat("e", 64))), mtDSSE, nil))
	if found, rejected := fetchAll(t, r.host, "app", d.String()); len(found) != 0 || len(rejected) != 1 || rejected[0] != RejectSubjectMismatch {
		t.Fatalf("att mismatch: found %+v rejected %v", found, rejected)
	}
	r.push(tagBase+".att", artifact(t, dsse(cdxStatement(t, "")), mtDSSE, nil))
	if found, rejected := fetchAll(t, r.host, "app", d.String()); len(found) != 0 || len(rejected) != 1 || rejected[0] != RejectSubjectMissing {
		t.Fatalf("att without subject: found %+v rejected %v", found, rejected)
	}
}

func TestFetchRejectsEmptySBOM(t *testing.T) {
	r := newReg(t)
	img, _ := random.Image(64, 1)
	d := r.push("app:1", img)
	empty := []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)
	r.push("app:"+strings.Replace(d.String(), ":", "-", 1)+".sbom", artifact(t, empty, mtSPDXJSON, nil))
	found, rejected := fetchAll(t, r.host, "app", d.String())
	if len(found) != 0 || len(rejected) != 1 || rejected[0] != RejectEmpty {
		t.Fatalf("found %+v rejected %v", found, rejected)
	}
}

func mustLayer(t *testing.T, img v1.Image) v1.Layer {
	t.Helper()
	ls, err := img.Layers()
	if err != nil || len(ls) == 0 {
		t.Fatal(err)
	}
	return ls[0]
}

func TestFetchCosignAttestationAndSBOMTags(t *testing.T) {
	r := newReg(t)
	img, _ := random.Image(64, 1)
	d := r.push("app:1", img)
	tagBase := "app:" + strings.Replace(d.String(), ":", "-", 1)

	// Only a legacy .sbom attachment (bare SPDX JSON): accepted, unbound.
	spdx := fixture(t, "alpine-spdx-intoto.json")
	var stmt struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	_ = json.Unmarshal(spdx, &stmt)
	r.push(tagBase+".sbom", artifact(t, stmt.Predicate, mtSPDXJSON, nil))
	found, _ := fetchAll(t, r.host, "app", d.String())
	if len(found) != 1 || found[0].Attestation.Mechanism != sctypes.MechanismCosignSBOM || found[0].Subject != d.String() ||
		found[0].Attestation.PayloadSHA256 != "" ||
		found[0].Trust != sctypes.SBOMTrustAttachedUnbound || found[0].IndexDigest != "" {
		t.Fatalf("sbom tag: %+v", found)
	}

	// A bound .att attestation (DSSE CycloneDX statement) takes precedence.
	r.push(tagBase+".att", artifact(t, dsse(cdxStatement(t, d.String())), mtDSSE, nil))
	found, _ = fetchAll(t, r.host, "app", d.String())
	if len(found) != 1 {
		t.Fatalf("att tag: %+v", found)
	}
	if a := found[0].Attestation; a.PayloadSHA256 == "" || len(a.PayloadSHA256) != 64 {
		t.Errorf("att payload sha256 %q", a.PayloadSHA256)
	}
	if a := found[0].Attestation; a.Mechanism != sctypes.MechanismCosignAttestation || a.MediaType != mtDSSE ||
		a.PredicateType != sbomdoc.PredicateCycloneDX || found[0].Doc.Format != sbomdoc.FormatCycloneDX || found[0].Trust != sctypes.SBOMTrustUnverified {
		t.Errorf("att: %+v", found[0])
	}
}

// cosign v3 stores attestations as sigstore bundles in OCI referrers.
func TestFetchReferrerBundle(t *testing.T) {
	r := newReg(t)
	img, _ := random.Image(64, 1)
	d := r.push("svc:2", img)
	desc, _ := partial(t, img)

	bundle, _ := json.Marshal(map[string]interface{}{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{},
		"dsseEnvelope":         json.RawMessage(dsse(withSubject(t, fixture(t, "alpine-spdx-intoto.json"), d.String()))),
	})
	const bundleMT = "application/vnd.dev.sigstore.bundle.v0.3+json"
	art := artifact(t, bundle, bundleMT, nil)
	art = mutate.ConfigMediaType(art, bundleMT) // becomes the referrer's artifactType
	art = mutate.Subject(art, desc).(v1.Image)
	artDigest, _ := art.Digest()
	if err := remote.Write(r.ref("svc@"+artDigest.String()), art); err != nil {
		t.Fatal(err)
	}
	found, _ := fetchAll(t, r.host, "svc", d.String())
	if len(found) != 1 {
		t.Fatalf("%+v", found)
	}
	if a := found[0].Attestation; a.Mechanism != sctypes.MechanismOCIReferrer || a.ArtifactDigest != artDigest.String() || a.PredicateType != sbomdoc.PredicateSPDX {
		t.Errorf("referrer: %+v", a)
	}
}

func partial(t *testing.T, img v1.Image) (v1.Descriptor, error) {
	t.Helper()
	d, _ := img.Digest()
	sz, _ := img.Size()
	mt, _ := img.MediaType()
	return v1.Descriptor{MediaType: mt, Digest: d, Size: sz}, nil
}

func TestFetchNothingAttachedAndNonSBOMs(t *testing.T) {
	r := newReg(t)
	img, _ := random.Image(64, 1)
	d := r.push("plain:1", img)
	// A provenance-only attestation is not an SBOM.
	prov, _ := json.Marshal(map[string]interface{}{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]string{}})
	r.push("plain:"+strings.Replace(d.String(), ":", "-", 1)+".att", artifact(t, dsse(prov), mtDSSE, nil))
	found, rejected := fetchAll(t, r.host, "plain", d.String())
	if len(found) != 0 || len(rejected) != 0 {
		t.Fatalf("%+v %v", found, rejected)
	}
}

func TestFetchRefusedDestination(t *testing.T) {
	in := New(Guard{})
	_, _, err := in.FetchSBOMs(context.Background(), "169.254.169.254", "x/y", "sha256:"+strings.Repeat("a", 64))
	if reason, ok := blockedReason(err); !ok || reason != ReasonBlockedAddress {
		t.Fatalf("err %v", err)
	}
}
