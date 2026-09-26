package trivy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

const (
	apiDigest       = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	apiserverDigest = "sha256:53a13cd1588391888c5a8ac4cef13d3ee6d229cd904038936731af7131d193a9"
)

func loadObject(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]interface{}
	if err := yaml.Unmarshal(b, &obj); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return obj
}

func loadVuln(t *testing.T, name string) *VulnerabilityReport {
	t.Helper()
	r, err := DecodeVulnerabilityReport(loadObject(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func loadSBOM(t *testing.T, name string) *SbomReport {
	t.Helper()
	r, err := DecodeSbomReport(loadObject(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFixturesDecode(t *testing.T) {
	cases := map[string]int{
		"vulnerabilityreport-docs-basic.yaml":        2,
		"vulnerabilityreport-docs-extended.yaml":     2,
		"vulnerabilityreport-apiserver-tagonly.yaml": 2,
		"vulnerabilityreport-api-digest.yaml":        3,
	}
	for name, want := range cases {
		r := loadVuln(t, name)
		if got := len(r.Report.Vulnerabilities); got != want {
			t.Errorf("%s: %d vulnerabilities, want %d", name, got, want)
		}
		if r.Report.Scanner.Name != "Trivy" {
			t.Errorf("%s: scanner %q", name, r.Report.Scanner.Name)
		}
	}
	ext := loadVuln(t, "vulnerabilityreport-docs-extended.yaml")
	nvd := ext.Report.Vulnerabilities[0].CVSS["nvd"]
	if nvd.V3Score == nil || *nvd.V3Score != 5.7 || nvd.V2Vector != "AV:L/AC:L/Au:N/C:P/I:P/A:P" {
		t.Errorf("extended sample cvss not decoded: %+v", nvd)
	}
	for _, name := range []string{"sbomreport-docs.yaml", "sbomreport-api-digest.yaml"} {
		s := loadSBOM(t, name)
		if s.Report.BOM.BOMFormat != "CycloneDX" || len(s.Report.BOM.Components) == 0 {
			t.Errorf("%s: bom not decoded: %+v", name, s.Report.BOM)
		}
	}
}

func TestNormaliseDigest(t *testing.T) {
	cases := map[string]string{
		apiDigest:                          apiDigest,
		"  " + apiDigest + "\n":            apiDigest,
		"ghcr.io/example/api@" + apiDigest: apiDigest,
		"SHA256:9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08": apiDigest,
		"":                        "",
		"sha256:abc":              "",
		"sha512:" + apiDigest[7:]: "",
		"example/api:2.4.1":       "",
	}
	for in, want := range cases {
		if got := NormaliseDigest(in); got != want {
			t.Errorf("NormaliseDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseVulnerabilities(t *testing.T) {
	r := loadVuln(t, "vulnerabilityreport-api-digest.yaml")
	p := NormaliseVulnerabilities(r, apiDigest, nil)

	if p.SchemaVersion != 1 || p.Source != "trivy-operator" {
		t.Errorf("header: %+v", p)
	}
	if p.Image.Digest != apiDigest || p.Image.Ref != "ghcr.io/example/api:2.4.1" ||
		p.Image.Registry != "ghcr.io" || p.Image.Repository != "example/api" || p.Image.Tag != "2.4.1" {
		t.Errorf("image: %+v", p.Image)
	}
	if want := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC); !p.ScannedAt.Equal(want) {
		t.Errorf("scanned_at %v", p.ScannedAt)
	}
	if p.DBUpdatedAt != nil {
		t.Error("trivy-operator reports carry no DB timestamp; db_updated_at must be nil")
	}
	if p.OS.Family != "alpine" || p.OS.Name != "3.20.3" {
		t.Errorf("os: %+v", p.OS)
	}
	if len(p.ObservedIn) != 1 || p.ObservedIn[0].Namespace != "shop" || p.ObservedIn[0].Kind != "ReplicaSet" ||
		p.ObservedIn[0].Name != "api-7c9d8f6b5" || p.ObservedIn[0].Container != "api" {
		t.Errorf("observed_in: %+v", p.ObservedIn)
	}
	// Three findings in the report, one verbatim duplicate.
	if len(p.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2 after de-dup", len(p.Vulnerabilities))
	}
	crit := p.Vulnerabilities[0]
	if crit.ID != "CVE-2099-1001" || crit.Severity != "CRITICAL" || crit.FixedVersion != "3.3.2-r1" {
		t.Errorf("critical: %+v", crit)
	}
	// "score: 9" arrives as an integer and must still decode.
	if crit.Score == nil || *crit.Score != 9 {
		t.Errorf("integer score not decoded: %v", crit.Score)
	}
	if c := crit.CVSS["nvd"]; c.V3Score == nil || *c.V3Score != 9.8 || c.V3Vector == "" {
		t.Errorf("cvss: %+v", crit.CVSS)
	}
	if crit.Package.Name != "libcrypto3" || crit.Package.Version != "3.3.2-r0" ||
		crit.Package.Type != "alpine" || crit.Package.PURL != "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&distro=3.20.3" {
		t.Errorf("package: %+v", crit.Package)
	}
	if crit.Class != "os-pkgs" || crit.PrimaryURL == "" || crit.Target == "" {
		t.Errorf("metadata: %+v", crit)
	}
	if crit.FilePaths != nil {
		t.Errorf("no path source, got %v", crit.FilePaths)
	}
}

func TestNormaliseVulnerabilitiesPathsAndDates(t *testing.T) {
	r := loadVuln(t, "vulnerabilityreport-apiserver-tagonly.yaml")
	p := NormaliseVulnerabilities(r, apiserverDigest, map[string][]string{
		"pkg:deb/debian/tzdata@2021a-0+deb10u1?arch=all&distro=debian-10.9": {"usr/share/zoneinfo"},
	})
	byID := map[string]int{}
	for i, v := range p.Vulnerabilities {
		byID[v.ID] = i
	}
	gov := p.Vulnerabilities[byID["CVE-2099-0001"]]
	if !reflect.DeepEqual(gov.FilePaths, []string{"usr/local/bin/kube-apiserver"}) {
		t.Errorf("packagePath not carried: %v", gov.FilePaths)
	}
	if len(gov.CVSS) != 2 {
		t.Errorf("want nvd+ghsa cvss, got %v", gov.CVSS)
	}
	tz := p.Vulnerabilities[byID["CVE-2099-0002"]]
	if !reflect.DeepEqual(tz.FilePaths, []string{"usr/share/zoneinfo"}) {
		t.Errorf("sbom path join: %v", tz.FilePaths)
	}
	if tz.FixedVersion != "" {
		t.Errorf("unfixed finding has fixed_version %q", tz.FixedVersion)
	}
	if tz.PublishedAt == nil || tz.PublishedAt.Year() != 2099 || tz.LastModifiedAt == nil {
		t.Errorf("dates: %v %v", tz.PublishedAt, tz.LastModifiedAt)
	}
}

func TestNormaliseSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": "CRITICAL", "high": "HIGH", " Medium ": "MEDIUM", "LOW": "LOW",
		"NONE": "NONE", "UNKNOWN": "UNKNOWN", "": "UNKNOWN", "severe": "UNKNOWN",
	} {
		if got := normaliseSeverity(in); got != want {
			t.Errorf("normaliseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseSBOMDocs(t *testing.T) {
	r := loadSBOM(t, "sbomreport-docs.yaml")
	d := sbomDigest(r)
	if d != apiserverDigest {
		t.Fatalf("RepoDigest fallback: got %q", d)
	}
	p := NormaliseSBOM(r, d)
	if p.Format != "CycloneDX" || p.Image.Ref != "k8s.gcr.io/kube-apiserver:v1.21.1" || p.Image.Digest != d {
		t.Errorf("header: %+v", p)
	}
	if len(p.Components) != 4 {
		t.Fatalf("components: %d", len(p.Components))
	}
	var os, base bool
	for _, c := range p.Components {
		switch c.Name {
		case "debian":
			os = c.Type == "operating-system" && c.Version == "10.9" && c.Class == "os-pkgs"
		case "base-files":
			base = c.Type == "debian" && c.SrcName == "base-files" && c.SrcVersion == "10.3+deb10u9" &&
				reflect.DeepEqual(c.Licenses, []string{"GPL-3.0"}) &&
				c.LayerDigest == "sha256:5dea5ec2316d4a067b946b15c3c4f140b4f2ad607e73e9bc41b673ee5ebb99a3" &&
				c.PURL == "pkg:deb/debian/base-files@10.3+deb10u9?arch=amd64&distro=debian-10.9"
		}
	}
	if !os || !base {
		t.Errorf("component mapping wrong: %+v", p.Components)
	}
}

func TestNormaliseSBOMFilePathsAndLicenseID(t *testing.T) {
	r := loadSBOM(t, "sbomreport-api-digest.yaml")
	if sbomDigest(r) != apiDigest {
		t.Fatal("artifact digest should win")
	}
	p := NormaliseSBOM(r, apiDigest)
	idx := FilePathsByPURL(p)
	if !reflect.DeepEqual(idx["pkg:npm/express@4.18.2"], []string{"app/node_modules/express/package.json"}) {
		t.Errorf("file path index: %v", idx)
	}
	for _, c := range p.Components {
		if c.Name == "express" && !reflect.DeepEqual(c.Licenses, []string{"MIT"}) {
			t.Errorf("license id: %v", c.Licenses)
		}
	}
}
