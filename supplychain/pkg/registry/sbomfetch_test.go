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

func TestFetchBuildKitAttestation(t *testing.T) {
	r := newReg(t)
	amd, _ := random.Image(64, 1)
	amdDigest, _ := amd.Digest()
	att := artifact(t, fixture(t, "alpine-spdx-intoto.json"), mtInToto, map[string]string{annPredicateType: sbomdoc.PredicateSPDX})
	prov := artifact(t, []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","predicate":{}}`),
		mtInToto, map[string]string{annPredicateType: "https://slsa.dev/provenance/v0.2"})
	// BuildKit puts SBOM and provenance in one attestation manifest.
	both, _ := mutate.Append(att, mutate.Addendum{Layer: mustLayer(t, prov), Annotations: map[string]string{annPredicateType: "https://slsa.dev/provenance/v0.2"}, MediaType: mtInToto})
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: both, Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{annRefType: "attestation-manifest", annRefDigest: amdDigest.String()},
		}},
	)
	if err := remote.WriteIndex(r.ref("library/alpine:3.20"), idx); err != nil {
		t.Fatal(err)
	}
	idxDigest, _ := idx.Digest()

	found, err := inspector().FetchSBOMs(context.Background(), r.host, "library/alpine", idxDigest.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d SBOMs", len(found))
	}
	f := found[0]
	if f.Subject != amdDigest.String() {
		t.Errorf("subject %s, want the platform manifest %s", f.Subject, amdDigest)
	}
	if f.Attestation.Mechanism != sctypes.MechanismBuildKitAttestation || f.Attestation.PredicateType != sbomdoc.PredicateSPDX ||
		f.Attestation.Verified || len(f.Doc.Components) != 17 {
		t.Errorf("found: %+v (%d components)", f.Attestation, len(f.Doc.Components))
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

	// Only a legacy .sbom attachment (SPDX JSON, text/spdx+json).
	spdx := fixture(t, "alpine-spdx-intoto.json")
	var stmt struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	_ = json.Unmarshal(spdx, &stmt)
	r.push(tagBase+".sbom", artifact(t, stmt.Predicate, mtSPDXJSON, nil))
	found, err := inspector().FetchSBOMs(context.Background(), r.host, "app", d.String())
	if err != nil || len(found) != 1 || found[0].Attestation.Mechanism != sctypes.MechanismCosignSBOM || found[0].Subject != d.String() {
		t.Fatalf("sbom tag: %v %+v", err, found)
	}

	// Adding a .att attestation (DSSE CycloneDX statement) takes precedence.
	cdxStmt, _ := json.Marshal(map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": sbomdoc.PredicateCycloneDX,
		"subject": []interface{}{}, "predicate": json.RawMessage(fixture(t, "alpine-cyclonedx.json")),
	})
	r.push(tagBase+".att", artifact(t, dsse(cdxStmt), mtDSSE, nil))
	found, err = inspector().FetchSBOMs(context.Background(), r.host, "app", d.String())
	if err != nil || len(found) != 1 {
		t.Fatalf("att tag: %v %+v", err, found)
	}
	if a := found[0].Attestation; a.Mechanism != sctypes.MechanismCosignAttestation || a.MediaType != mtDSSE ||
		a.PredicateType != sbomdoc.PredicateCycloneDX || found[0].Doc.Format != sbomdoc.FormatCycloneDX {
		t.Errorf("att: %+v", a)
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
		"dsseEnvelope":         json.RawMessage(dsse(fixture(t, "alpine-spdx-intoto.json"))),
	})
	const bundleMT = "application/vnd.dev.sigstore.bundle.v0.3+json"
	art := artifact(t, bundle, bundleMT, nil)
	art = mutate.ConfigMediaType(art, bundleMT) // becomes the referrer's artifactType
	art = mutate.Subject(art, desc).(v1.Image)
	artDigest, _ := art.Digest()
	if err := remote.Write(r.ref("svc@"+artDigest.String()), art); err != nil {
		t.Fatal(err)
	}
	found, err := inspector().FetchSBOMs(context.Background(), r.host, "svc", d.String())
	if err != nil || len(found) != 1 {
		t.Fatalf("%v %+v", err, found)
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
	found, err := inspector().FetchSBOMs(context.Background(), r.host, "plain", d.String())
	if err != nil || len(found) != 0 {
		t.Fatalf("%v %+v", err, found)
	}
}

func TestFetchRefusedDestination(t *testing.T) {
	in := New(Guard{})
	_, err := in.FetchSBOMs(context.Background(), "169.254.169.254", "x/y", "sha256:"+strings.Repeat("a", 64))
	if reason, ok := blockedReason(err); !ok || reason != ReasonBlockedAddress {
		t.Fatalf("err %v", err)
	}
}
