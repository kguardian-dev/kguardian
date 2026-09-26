package engine

// testdata/alpine-spdx.json is the SPDX-2.3 predicate of the BuildKit SBOM
// attestation for docker.io/library/alpine:3.20 linux/amd64 (manifest
// sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e),
// the same real document supplychain/pkg/sbomdoc/testdata carries wrapped
// in its in-toto statement.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
	"github.com/sirupsen/logrus"
)

// alpineComponents turns the SPDX fixture into the components supplychain
// would send (name, version, purl, type) - with no OS component, as
// sbomdoc produces for this document.
func alpineComponents(t *testing.T) []wire.Component {
	t.Helper()
	b, err := os.ReadFile("testdata/alpine-spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Packages []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	var out []wire.Component
	for _, p := range d.Packages {
		for _, r := range p.ExternalRefs {
			if r.Type == "purl" {
				out = append(out, wire.Component{Name: p.Name, Version: p.VersionInfo, PURL: r.Locator, Type: "apk"})
			}
		}
	}
	return out
}

func TestInferDistro(t *testing.T) {
	cases := []struct {
		cs   []wire.Component
		want Distro
		ok   bool
	}{
		{[]wire.Component{{Name: "debian", Version: "12.7", Type: "operating-system"}}, Distro{"debian", "12.7"}, true},
		{[]wire.Component{{PURL: "pkg:apk/alpine/musl@1.2.5-r3?arch=x86_64&distro=alpine-3.20.10"}}, Distro{"alpine", "3.20.10"}, true},
		{[]wire.Component{{PURL: "pkg:apk/alpine/musl@1.2.5-r3?os_name=alpine&os_version=3.20"}}, Distro{"alpine", "3.20"}, true},
		{[]wire.Component{{PURL: "pkg:rpm/opensuse/x@1?distro=opensuse-leap-15.5"}}, Distro{"opensuse-leap", "15.5"}, true},
		{[]wire.Component{{PURL: "pkg:npm/express@4.18.2"}}, Distro{}, false},
	}
	for _, c := range cases {
		got, ok := inferDistro(c.cs)
		if ok != c.ok || got != c.want {
			t.Errorf("%+v: got %+v %v", c.cs, got, ok)
		}
	}
}

func TestWithUpstream(t *testing.T) {
	for _, c := range []struct {
		in   wire.Component
		want string
	}{
		{wire.Component{Name: "libssl3", Version: "3.0.11-1", SrcName: "openssl", SrcVersion: "3.0.11-1", PURL: "pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12"},
			"pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12&upstream=openssl"},
		{wire.Component{Name: "tzdata", Version: "2021a-0+deb10u1", SrcName: "tzdata", SrcVersion: "2021a", PURL: "pkg:deb/debian/tzdata@2021a-0+deb10u1"},
			"pkg:deb/debian/tzdata@2021a-0+deb10u1?upstream=tzdata%402021a"},
		{wire.Component{Name: "base-files", SrcName: "base-files", PURL: "pkg:deb/debian/base-files@1"}, "pkg:deb/debian/base-files@1"},
		// src_name wins over an upstream already in the PURL.
		{wire.Component{Name: "x", SrcName: "y", PURL: "pkg:deb/debian/x@1?upstream=z"}, "pkg:deb/debian/x@1?upstream=y"},
		{wire.Component{Name: "libc6", Version: "2.36", SrcName: "glibc", PURL: "pkg:deb/debian/libc6@2.36?arch=amd64&upstream=nothing-here&distro=debian-99"},
			"pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-99&upstream=glibc"},
		// No src_name: an existing upstream is kept.
		{wire.Component{Name: "x", PURL: "pkg:deb/debian/x@1?upstream=z"}, "pkg:deb/debian/x@1?upstream=z"},
	} {
		if got := withUpstream(c.in); got != c.want {
			t.Errorf("got %s want %s", got, c.want)
		}
		if strings.Contains(c.want, "upstream=") && !strings.Contains(c.in.PURL, "upstream=") {
			if back := stripUpstream(withUpstream(c.in)); back != c.in.PURL {
				t.Errorf("stripUpstream: %s != %s", back, c.in.PURL)
			}
		}
	}
}

// The synthesised document must give Grype the distro, or apk packages
// match nothing. Checked through Grype's own SBOM reader (no DB needed).
func TestBuildCycloneDXReadByGrype(t *testing.T) {
	cs := alpineComponents(t)
	doc, d := BuildCycloneDX(cs)
	if d == nil || d.ID != "alpine" || d.Version != "3.20" {
		t.Fatalf("distro %+v", d)
	}
	pkgs, pctx, _, err := pkg.ProvideFromReader(bytes.NewReader(doc), pkg.ProviderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if pctx.Distro == nil || !strings.HasPrefix(pctx.Distro.String(), "alpine 3.20") {
		t.Fatalf("grype distro: %v", pctx.Distro)
	}
	if len(pkgs) != len(cs) {
		t.Errorf("grype read %d packages, want %d", len(pkgs), len(cs))
	}
	for _, p := range pkgs {
		if string(p.Type) != "apk" {
			t.Errorf("%s: type %s", p.Name, p.Type)
		}
	}
}

func TestConvert(t *testing.T) {
	added := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	ms := []match.Match{{
		Package: pkg.Package{Name: "libssl3", Version: "3.3.2-r0", Type: "apk", PURL: "pkg:apk/alpine/libssl3@3.3.2-r0?upstream=openssl"},
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2099-0001", Namespace: "alpine:distro:alpine:3.20"},
			Fix:       vulnerability.Fix{Versions: []string{"3.3.2-r1"}, State: vulnerability.FixStateFixed},
			Metadata: &vulnerability.Metadata{
				Severity: "High", DataSource: "https://security.alpinelinux.org/vuln/CVE-2099-0001",
				Cvss: []vulnerability.Cvss{
					{Source: "nvd@nist.gov", Version: "3.1", Vector: "CVSS:3.1/AV:N", Metrics: vulnerability.CvssMetrics{BaseScore: 7.5}},
					{Source: "nvd@nist.gov", Version: "2.0", Vector: "AV:N/AC:L", Metrics: vulnerability.CvssMetrics{BaseScore: 5.0}},
				},
				KnownExploited: []vulnerability.KnownExploited{{CVE: "CVE-2099-0001", DateAdded: &added}},
				EPSS:           []vulnerability.EPSS{{CVE: "CVE-2099-0001", EPSS: 0.42, Percentile: 0.97}},
			},
		},
	}, {
		Package:       pkg.Package{Name: "express", Version: "4.18.2", Type: "npm", PURL: "pkg:npm/express@4.18.2"},
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "GHSA-xxxx"}, Fix: vulnerability.Fix{State: vulnerability.FixStateNotFixed}},
	}}
	paths := pathIndex([]wire.Component{{Name: "libssl3", Version: "3.3.2-r0", PURL: "pkg:apk/alpine/libssl3@3.3.2-r0", FilePaths: []string{"usr/lib/libssl.so.3"}}})
	got := convert(ms, paths)
	if len(got) != 2 {
		t.Fatalf("%d", len(got))
	}
	v := got[0]
	if v.ID != "CVE-2099-0001" || v.Severity != "HIGH" || v.FixedVersion != "3.3.2-r1" || v.Class != "os-pkgs" ||
		!v.KnownExploited || v.KEVDateAdded == nil || !v.KEVDateAdded.Equal(added) ||
		v.EPSS == nil || *v.EPSS != 0.42 || v.EPSSPercentile == nil || *v.EPSSPercentile != 0.97 ||
		v.Score == nil || *v.Score != 7.5 || len(v.FilePaths) != 1 {
		t.Errorf("converted: %+v", v)
	}
	nvd := v.CVSS["nvd@nist.gov"]
	if nvd.V3Score == nil || *nvd.V3Score != 7.5 || nvd.V2Score == nil || *nvd.V2Score != 5.0 {
		t.Errorf("cvss: %+v", v.CVSS)
	}
	if w := got[1]; w.Severity != "UNKNOWN" || w.FixedVersion != "" || w.KnownExploited || w.EPSS != nil || w.Class != "lang-pkgs" {
		t.Errorf("no-metadata vuln: %+v", w)
	}
}

// fakeProvider is a vulnerability.Provider that records Close.
type fakeProvider struct {
	vulnerability.Provider
	closed bool
}

func (f *fakeProvider) Close() error { f.closed = true; return nil }

func TestRefreshSwapsKeepsAndCloses(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	e := New(Config{}, log)
	built := time.Date(2026, 9, 25, 6, 31, 49, 0, time.UTC)
	var next *fakeProvider
	var nextErr error
	e.load = func(bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
		if nextErr != nil {
			return nil, nil, nextErr
		}
		return next, &vulnerability.ProviderStatus{Built: built, SchemaVersion: "v6.1.9"}, nil
	}
	if _, err := e.Match(context.Background(), nil); !errors.Is(err, ErrNotReady) {
		t.Fatalf("match before load: %v", err)
	}

	p1 := &fakeProvider{}
	next = p1
	if err := e.refresh(); err != nil || !e.Loaded() {
		t.Fatal(err)
	}
	// Same build: the freshly opened provider is closed, p1 kept.
	p2 := &fakeProvider{}
	next = p2
	_ = e.refresh()
	if !p2.closed || p1.closed {
		t.Errorf("unchanged refresh: p1 closed=%v p2 closed=%v", p1.closed, p2.closed)
	}
	// New build: swapped, old closed.
	built = built.Add(24 * time.Hour)
	p3 := &fakeProvider{}
	next = p3
	_ = e.refresh()
	if !p1.closed || p3.closed {
		t.Errorf("new build: p1 closed=%v p3 closed=%v", p1.closed, p3.closed)
	}
	// A failed refresh keeps serving the loaded database and reports why.
	nextErr = errors.New("listing unreachable")
	_ = e.refresh()
	db := e.DB()
	if !db.Loaded || db.Built == nil || !db.Built.Equal(built) || db.LastUpdateError == "" || !strings.HasPrefix(db.Scanner, "grype ") {
		t.Errorf("db after failed refresh: %+v", db)
	}
}

// With a real database (GRYPE_TEST_DB_DIR pointing at an unpacked v6 DB
// root), check both reasons BuildCycloneDX exists against real advisories.
// Skipped in CI: the database is about 3 GB. Run locally on 2026-09-26
// against the v6.1.9 DB built 2026-09-25.
func TestMatchRealDB(t *testing.T) {
	dir := os.Getenv("GRYPE_TEST_DB_DIR")
	if dir == "" {
		t.Skip("GRYPE_TEST_DB_DIR not set")
	}
	log := logrus.New()
	log.SetOutput(io.Discard)
	e := New(Config{DBDir: dir, AutoUpdate: false}, log)
	if err := e.refresh(); err != nil {
		t.Fatal(err)
	}
	defer e.close()
	// libc6 from nginx:1.27 (debian 12), PURL as Trivy writes it: no
	// upstream qualifier, source package in src_name.
	libc6 := wire.Component{Name: "libc6", Version: "2.36-9+deb12u10", Type: "debian",
		PURL: "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64", SrcName: "glibc", SrcVersion: "2.36-9+deb12u10"}
	os12 := wire.Component{Name: "debian", Version: "12", Type: "operating-system"}
	count := func(cs ...wire.Component) int {
		start := time.Now()
		vs, err := e.Match(context.Background(), cs)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%d vulnerabilities in %v", len(vs), time.Since(start))
		return len(vs)
	}
	full := count(os12, libc6)
	noUpstream := libc6
	noUpstream.SrcName, noUpstream.SrcVersion = "", ""
	if full == 0 || count(os12, noUpstream) != 0 || count(libc6) != 0 {
		t.Errorf("want matches only with both distro and upstream (full=%d)", full)
	}
	// A hostile upstream in the PURL cannot override src_name.
	hijacked := libc6
	hijacked.PURL = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64&upstream=nothing-here"
	if got := count(os12, hijacked); got != full {
		t.Errorf("PURL upstream overrode src_name: %d matches, want %d", got, full)
	}
	// The alpine 3.20 SBOM (distro only in PURL qualifiers) must match
	// without error; this release has no open distro advisories.
	_ = count(alpineComponents(t)...)
}
