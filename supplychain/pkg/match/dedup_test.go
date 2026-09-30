package match

import (
	"testing"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

func TestPURLKey(t *testing.T) {
	cases := []struct{ purl, want string }{
		// Trivy (SbomReport) and Syft shapes of one package.
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"pkg:golang/stdlib@v1.22.1", "golang//stdlib@1.22.1"},
		{"pkg:golang/stdlib@go1.22.1", "golang//stdlib@1.22.1"},
		{"pkg:golang/stdlib@1.22.1", "golang//stdlib@1.22.1"},
		{"pkg:golang/github.com/x/net@v0.23.0", "golang/github.com/x/net@v0.23.0"},
		{"pkg:deb/debian/bsdutils@2.36.1-8%2Bdeb11u1?arch=amd64&distro=debian-11&epoch=1", "deb/debian/bsdutils@1:2.36.1-8+deb11u1"},
		{"pkg:deb/debian/bsdutils@1%3A2.36.1-8%2Bdeb11u1?arch=amd64&upstream=util-linux&distro=debian-11", "deb/debian/bsdutils@1:2.36.1-8+deb11u1"},
		{"pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64&epoch=0", "deb/debian/libc6@2.36-9+deb12u10"},
		{"pkg:deb/debian/libc6@0:2.36-9+deb12u10?arch=arm64", "deb/debian/libc6@2.36-9+deb12u10"},
		{"pkg:rpm/redhat/bash@5.1.8-6.el9?arch=x86_64&epoch=0&distro=rhel-9.3", "rpm/redhat/bash@5.1.8-6.el9"},
		{"pkg:npm/%40babel/core@7.24.0", "npm/@babel/core@7.24.0"},
		{"pkg:pypi/PyYAML@6.0.1", "pypi//pyyaml@6.0.1"},
		{"pkg:pypi/typing_extensions@4.10.0", "pypi//typing-extensions@4.10.0"},
		{"pkg:apk/alpine/musl@1.2.5-r3?arch=aarch64&distro=alpine-3.20.10", "apk/alpine/musl@1.2.5-r3"},
		// Not identities: no version, no PURL, garbage.
		{"pkg:npm/express", ""},
		{"", ""},
		{"cpe:2.3:a:x:y:1", ""},
		{"pkg:deb/debian/x@%zz", ""},
	}
	for _, c := range cases {
		if got := purlKey(c.purl); got != c.want {
			t.Errorf("purlKey(%q) = %q, want %q", c.purl, got, c.want)
		}
	}
}

// Real Trivy and Syft output shapes of the same packages merge into one
// entry (Trivy's), where the name/version key alone kept both.
func TestDedupTrivySyftShapes(t *testing.T) {
	tr := &types.ImageSBOM{Source: types.SourceTrivyOperator, Components: []types.Component{
		{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Type: "jar", Class: "lang-pkgs",
			PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{Name: "stdlib", Version: "v1.22.1", Type: "gobinary", Class: "lang-pkgs", PURL: "pkg:golang/stdlib@v1.22.1"},
		{Name: "bsdutils", Version: "1:2.36.1-8+deb11u1", Type: "debian", Class: "os-pkgs", SrcName: "util-linux",
			PURL: "pkg:deb/debian/bsdutils@2.36.1-8%2Bdeb11u1?arch=amd64&distro=debian-11&epoch=1"},
	}}
	syft := func(source string) *types.ImageSBOM {
		return &types.ImageSBOM{Source: source, Components: []types.Component{
			{Name: "log4j-core", Version: "2.14.1", Type: "java-archive",
				PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", FilePaths: []string{"/app/app.jar"}},
			{Name: "stdlib", Version: "go1.22.1", Type: "go-module", PURL: "pkg:golang/stdlib@1.22.1"},
			{Name: "bsdutils", Version: "1:2.36.1-8+deb11u1", Type: "deb",
				PURL: "pkg:deb/debian/bsdutils@1:2.36.1-8%2Bdeb11u1?arch=amd64&upstream=util-linux&distro=debian-11"},
		}}
	}
	for _, src := range []string{types.SourceRegistry, types.SourceNode} {
		out, dropped := mergeComponents([]*types.ImageSBOM{tr, syft(src)}, DefaultMaxComponents)
		if dropped != 0 || len(out) != 3 {
			t.Fatalf("%s: %d components (dropped %d), want Trivy's 3: %+v", src, len(out), dropped, out)
		}
		for i, c := range out {
			want := tr.Components[i]
			// base is sorted by key; find Trivy's entry by name.
			for _, w := range tr.Components {
				if w.Name == c.Name {
					want = w
				}
			}
			if identity(c) != identity(want) {
				t.Errorf("%s: %s is not Trivy's entry", src, identity(c))
			}
		}
	}
}

// Node off: a Trivy-only or registry-only union merges exactly as before,
// except true duplicates (one PURL, two name spellings). Distinct packages
// stay distinct, and a PURL mismatch never splits what the names merge.
func TestDedupNodeOffRegression(t *testing.T) {
	reg := &types.ImageSBOM{Source: types.SourceRegistry, Components: []types.Component{
		{Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2"},
		{Name: "express", Version: "4.18.3", PURL: "pkg:npm/express@4.18.3"},
		{Name: "core", Version: "7.24.0", PURL: "pkg:npm/%40babel/core@7.24.0"},
		{Name: "core", Version: "7.24.0", PURL: "pkg:npm/core@7.24.0"},                   // same name/version: merged, as before
		{Name: "lib", Version: "1.0", PURL: "pkg:maven/org.example/lib@1.0"},             // one artifact,
		{Name: "org.example:lib", Version: "1.0", PURL: "pkg:maven/org.example/lib@1.0"}, // two spellings
		{Name: "noversion", Type: "npm"},
	}}
	out, _ := mergeComponents([]*types.ImageSBOM{reg}, DefaultMaxComponents)
	got := map[string]bool{}
	for _, c := range out {
		got[c.Name+"@"+c.Version+" "+c.PURL] = true
	}
	want := []string{
		"express@4.18.2 pkg:npm/express@4.18.2",
		"express@4.18.3 pkg:npm/express@4.18.3",
		"core@7.24.0 pkg:npm/%40babel/core@7.24.0",
		"lib@1.0 pkg:maven/org.example/lib@1.0",
		"noversion@ ",
	}
	if len(out) != len(want) {
		t.Errorf("%d components, want %d: %v", len(out), len(want), got)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %q in %v", w, got)
		}
	}

	// Trivy-only: unchanged but for the true duplicate.
	tr := &types.ImageSBOM{Source: types.SourceTrivyOperator, Components: []types.Component{
		{Name: "debian", Version: "12.7", Type: "operating-system"},
		{Name: "libc6", Version: "2.36-9+deb12u10", Type: "debian", PURL: "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64", SrcName: "glibc"},
		{Name: "openssl", Version: "3.0.11", Type: "debian", PURL: "pkg:deb/debian/openssl@3.0.11?arch=amd64"},
	}}
	out, _ = mergeComponents([]*types.ImageSBOM{tr}, DefaultMaxComponents)
	if len(out) != 3 || identity(out[1]) != identity(tr.Components[1]) || identity(out[2]) != identity(tr.Components[2]) {
		t.Errorf("Trivy-only union changed: %+v", out)
	}
}
