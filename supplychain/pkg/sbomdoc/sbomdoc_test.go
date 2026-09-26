package sbomdoc

// Fixtures (real documents, not hand-written):
//   - testdata/alpine-spdx-intoto.json: the BuildKit SBOM attestation layer
//     (in-toto statement, SPDX-2.3 predicate) attached to
//     docker.io/library/alpine:3.20, linux/amd64 manifest
//     sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e,
//     blob sha256:d4050d56ebf2da9d1352fb10698f571aaf0c4cb85b12fc6bf6f67faeb0e873cf,
//     fetched with crane on 2026-09-26.
//   - testdata/alpine-cyclonedx.json: syft 1.42.1
//     `-o cyclonedx-json` of the same manifest (CycloneDX 1.6).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func find(d *Doc, name string) *types.Component {
	for i := range d.Components {
		if d.Components[i].Name == name {
			return &d.Components[i]
		}
	}
	return nil
}

func TestParseBuildKitSPDXStatement(t *testing.T) {
	d, err := Parse(read(t, "alpine-spdx-intoto.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Format != FormatSPDX || d.SpecVersion != "2.3" || d.PredicateType != PredicateSPDX {
		t.Errorf("header: %+v", d)
	}
	// 18 SPDX packages: 17 apk packages plus the document's own "sbom"
	// FILE-purpose package, which is not a component.
	if len(d.Components) != 17 {
		t.Fatalf("components: %d", len(d.Components))
	}
	musl := find(d, "musl")
	if musl == nil || musl.Version != "1.2.5-r3" || musl.Type != "apk" ||
		musl.PURL != "pkg:apk/alpine/musl@1.2.5-r3?os_name=alpine&os_version=3.20" ||
		!reflect.DeepEqual(musl.Licenses, []string{"MIT"}) {
		t.Fatalf("musl: %+v", musl)
	}
	// File ownership comes from CONTAINS relationships - the runtime join key.
	want := map[string]bool{"lib/ld-musl-x86_64.so.1": false}
	for _, f := range musl.FilePaths {
		if _, ok := want[f]; ok {
			want[f] = true
		}
		if f != "" && f[0] == '/' {
			t.Errorf("path not image-root relative: %q", f)
		}
	}
	if !want["lib/ld-musl-x86_64.so.1"] {
		t.Errorf("musl file paths: %v", musl.FilePaths)
	}
}

func TestParseSyftCycloneDX(t *testing.T) {
	d, err := Parse(read(t, "alpine-cyclonedx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Format != FormatCycloneDX || d.SpecVersion != "1.6" {
		t.Errorf("header: %+v", d)
	}
	// 92 components: 77 files (not packages), 14 libraries, 1 OS.
	if len(d.Components) != 15 {
		t.Fatalf("components: %d", len(d.Components))
	}
	musl := find(d, "musl")
	if musl == nil || musl.Type != "apk" || musl.Version != "1.2.5-r3" || !reflect.DeepEqual(musl.Licenses, []string{"MIT"}) {
		t.Fatalf("musl: %+v", musl)
	}
	if os := find(d, "alpine"); os == nil || os.Type != "operating-system" {
		t.Errorf("os component: %+v", os)
	}
}

// The same statement wrapped as cosign stores it: a DSSE envelope, and a
// sigstore bundle (v0.3) carrying that envelope.
func TestParseDSSEAndBundle(t *testing.T) {
	stmt := read(t, "alpine-spdx-intoto.json")
	env := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stmt),
		"signatures":  []map[string]string{{"sig": "MEUCIQ=="}},
	}
	envJSON, _ := json.Marshal(env)
	bundle, _ := json.Marshal(map[string]interface{}{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{},
		"dsseEnvelope":         env,
	})
	for name, b := range map[string][]byte{"dsse": envJSON, "bundle": bundle} {
		d, err := Parse(b)
		if err != nil || len(d.Components) != 17 || d.PredicateType != PredicateSPDX {
			t.Errorf("%s: %v %+v", name, err, d)
		}
	}
}

// cosign's legacy CycloneDX attestation stores the predicate as a string.
func TestParseStatementWithStringPredicate(t *testing.T) {
	cdx := read(t, "alpine-cyclonedx.json")
	stmt, _ := json.Marshal(map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://cyclonedx.org/bom",
		"subject":       []interface{}{},
		"predicate":     string(cdx),
	})
	d, err := Parse(stmt)
	if err != nil || d.Format != FormatCycloneDX || len(d.Components) != 15 {
		t.Fatalf("%v %+v", err, d)
	}
}

func TestParseRejectsNonSBOMs(t *testing.T) {
	slsa, _ := json.Marshal(map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": map[string]string{},
	})
	for name, b := range map[string][]byte{
		"slsa":        slsa,
		"random json": []byte(`{"hello":"world"}`),
		"other dsse":  []byte(`{"payloadType":"text/plain","payload":"aGk="}`),
	} {
		if _, err := Parse(b); !errors.Is(err, ErrNotSBOM) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse([]byte("SPDXVersion: SPDX-2.3")); err == nil || errors.Is(err, ErrNotSBOM) {
		t.Errorf("tag-value SPDX should be a parse error, got %v", err)
	}
}

func TestPurlTypeAndPaths(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:apk/alpine/musl@1": "apk", "pkg:NPM/x@1": "npm", "": "", "pkg:": "", "notapurl": "",
	} {
		if got := purlType(in); got != want {
			t.Errorf("purlType(%q) = %q", in, got)
		}
	}
	if cleanPath("/usr/lib/x.so") != "usr/lib/x.so" || cleanPath("usr/x") != "usr/x" {
		t.Error("cleanPath")
	}
}
