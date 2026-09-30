package match

import (
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"sort"
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
	// A node SBOM (Syft's shapes) merges into Trivy's entries.
	out, dropped := mergeComponents([]*types.ImageSBOM{tr, syft(types.SourceNode)}, DefaultMaxComponents)
	if dropped != 0 || len(out) != 3 {
		t.Fatalf("node: %d components (dropped %d), want Trivy's 3: %+v", len(out), dropped, out)
	}
	for _, c := range out {
		found := false
		for _, w := range tr.Components {
			found = found || identity(c) == identity(w)
		}
		if !found {
			t.Errorf("node: %s is not Trivy's entry", identity(c))
		}
	}
	// The same document as a registry SBOM merges as on main: by name.
	reg := []*types.ImageSBOM{tr, syft(types.SourceRegistry)}
	got, _ := mergeComponents(reg, DefaultMaxComponents)
	want, _ := mainMergeComponents(reg, DefaultMaxComponents)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("registry union differs from main:\n got %+v\nwant %+v", got, want)
	}
}

// Node off, the union is byte-for-byte main's: the same random
// Trivy/registry unions as the property tests, under random caps, merged
// by main's mergeComponents (copied below) and by this one.
func TestDedupNodeOffRegression(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	purls := func(name, ver string) []string {
		return []string{"", "pkg:npm/" + name + "@" + ver, "pkg:npm/%40s/" + name + "@" + ver, "pkg:maven/g/" + name + "@" + ver,
			"pkg:deb/debian/" + name + "@" + ver + "?epoch=1", "pkg:golang/stdlib@go" + ver}
	}
	names := []string{"lib", "g:lib", "core", "stdlib", "libc6"}
	versions := []string{"1.0", "v1.0", "2"}
	for round := 0; round < 3000; round++ {
		var members []*types.ImageSBOM
		n := 1 + rng.Intn(4)
		for i := 0; i < n; i++ {
			src := types.SourceRegistry
			if i == 0 && rng.Intn(2) == 0 {
				src = types.SourceTrivyOperator
			}
			m := &types.ImageSBOM{Source: src}
			for k := rng.Intn(10); k > 0; k-- {
				name, ver := names[rng.Intn(len(names))], versions[rng.Intn(len(versions))]
				ps := purls(name, ver)
				c := types.Component{Name: name, Version: ver, PURL: ps[rng.Intn(len(ps))], Type: []string{"", "jar", "debian"}[rng.Intn(3)],
					SrcName: fmt.Sprint(rng.Intn(2)), FilePaths: []string{fmt.Sprint(rng.Intn(3))}, Licenses: []string{fmt.Sprint(rng.Intn(2))}}
				if rng.Intn(9) == 0 {
					c = types.Component{Name: "os", Version: fmt.Sprint(rng.Intn(3)), Type: "operating-system"}
				}
				m.Components = append(m.Components, c)
			}
			members = append(members, m)
		}
		max := 1 + rng.Intn(20)
		got, gd := mergeComponents(members, max)
		want, wd := mainMergeComponents(members, max)
		if gd != wd || !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d (cap %d): differs from main\n got %d %+v\nwant %d %+v", round, max, gd, got, wd, want)
		}
	}
}

// mainMergeComponents is mergeComponents as on main before node SBOMs
// (the reference for TestDedupNodeOffRegression).
func mainMergeComponents(members []*types.ImageSBOM, max int) ([]types.Component, int) {
	if max <= 0 {
		max = int(^uint(0) >> 1)
	}
	var trivySBOMs, others []*types.ImageSBOM
	for _, m := range members {
		if m.Source == types.SourceTrivyOperator {
			trivySBOMs = append(trivySBOMs, m)
		} else {
			others = append(others, m)
		}
	}
	byKey := map[string]*types.Component{}
	var osComp *types.Component
	addOnly := func(cur *types.Component, c types.Component) {
		if cur.PURL == "" {
			cur.PURL = c.PURL
		}
		cur.FilePaths = unionStrings(cur.FilePaths, c.FilePaths)
		cur.Licenses = unionStrings(cur.Licenses, c.Licenses)
	}
	clone := func(c types.Component) *types.Component {
		cc := c
		cc.FilePaths = slices.Clone(c.FilePaths)
		cc.Licenses = slices.Clone(c.Licenses)
		return &cc
	}

	// Trivy first: authoritative, never evicted.
	var base []string
	for _, m := range trivySBOMs {
		for _, c := range m.Components {
			if c.Type == "operating-system" {
				if osComp == nil {
					osComp = clone(c)
				}
				continue
			}
			k := componentKey(c)
			if cur, ok := byKey[k]; ok {
				addOnly(cur, c)
				continue
			}
			byKey[k] = clone(c)
			base = append(base, k)
		}
	}
	sort.Strings(base)
	dropped := 0
	room := max - len(base)
	if osComp != nil {
		room--
	}
	if room < 0 {
		// Trivy alone exceeds the cap (not seen in practice).
		dropped += -room
		base = base[:len(base)+room]
		room = 0
	}

	// Registry SBOMs: add-only, within an even share of what is left.
	var added []string
	for i, m := range others {
		share := room / (len(others) - i)
		var fresh []string
		for _, c := range m.Components {
			if c.Type == "operating-system" {
				if osComp == nil {
					osComp = clone(c)
					if room > 0 {
						room--
						share = min(share, room)
					} else {
						dropped++
						osComp = nil
					}
				}
				continue
			}
			k := componentKey(c)
			if cur, ok := byKey[k]; ok {
				addOnly(cur, c)
				continue
			}
			byKey[k] = clone(c)
			fresh = append(fresh, k)
		}
		sort.Strings(fresh)
		if len(fresh) > share {
			for _, k := range fresh[share:] {
				delete(byKey, k)
			}
			dropped += len(fresh) - share
			fresh = fresh[:share]
		}
		room -= len(fresh)
		added = append(added, fresh...)
	}
	sort.Strings(added)

	out := make([]types.Component, 0, len(base)+len(added)+1)
	if osComp != nil {
		out = append(out, *osComp)
	}
	for _, k := range base {
		out = append(out, *byKey[k])
	}
	for _, k := range added {
		out = append(out, *byKey[k])
	}
	return out, dropped
}
