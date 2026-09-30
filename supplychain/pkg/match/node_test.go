package match

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/types"
)

func nodeSBOM(digest, platform string, comps ...string) *types.ImageSBOM {
	s := &types.ImageSBOM{Image: types.ImageRef{Digest: digest}, Source: types.SourceNode, SBOMTrust: types.SBOMTrustScanned, Platform: platform}
	for _, c := range comps {
		s.Components = append(s.Components, types.Component{Name: c, Version: "1", PURL: "pkg:deb/debian/" + c + "@1?arch=arm64&distro=debian-12"})
	}
	return s
}

// identity is what a per-package matcher keys a finding on.
func identity(c types.Component) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", c.Type, c.Name, c.Version, c.PURL, c.SrcName, c.SrcVersion, c.Class)
}

// Property: over random combinations of sources (Trivy or not, node or
// not, zero to three registry SBOMs), random overlapping packages, random
// operating-system entries and random caps, the union keeps the
// precedence Trivy > node > registry:
//   - every Trivy component is in the union exactly as Trivy reported it,
//     so Trivy's findings always survive;
//   - every node component Trivy does not also list is in the union
//     exactly as the node SBOM reported it, unless the cap left no room,
//     and then no registry-only component was kept in its place;
//   - the operating-system component is Trivy's, else the node SBOM's,
//     else a registry one's;
//   - no package appears twice (nothing is matched, so counted, twice);
//   - the union stays within the cap whenever Trivy alone does.
func TestUnionPropertyPrecedenceTrivyNodeRegistry(t *testing.T) {
	rng := rand.New(rand.NewSource(1850))
	names := []string{"libc6", "openssl", "zlib1g", "musl", "express", "log4j-core", "busybox", "curl"}
	versions := []string{"1", "2", "3.0.11"}
	purlTypes := []string{"deb", "apk", "npm", "maven"}
	randComp := func(tag string) types.Component {
		name, ver := names[rng.Intn(len(names))], versions[rng.Intn(len(versions))]
		pt := purlTypes[rng.Intn(len(purlTypes))]
		c := types.Component{Name: name, Version: ver,
			PURL:    fmt.Sprintf("pkg:%s/x/%s@%s?%s=%d", pt, name, ver, tag, rng.Intn(9)),
			SrcName: fmt.Sprintf("%s-src-%d", tag, rng.Intn(3)), Class: tag}
		if rng.Intn(4) == 0 {
			c.PURL = "" // an entry a lower source may fill in
			c.Type = pt
		}
		if rng.Intn(3) == 0 {
			c.FilePaths = []string{fmt.Sprintf("/%s/%d", tag, rng.Intn(5))}
		}
		return c
	}
	randSBOM := func(source, tag string) *types.ImageSBOM {
		s := &types.ImageSBOM{Source: source}
		for n := rng.Intn(12); n > 0; n-- {
			if rng.Intn(8) == 0 {
				s.Components = append(s.Components, types.Component{Name: tag + "-os", Version: fmt.Sprint(rng.Intn(9)), Type: "operating-system"})
				continue
			}
			s.Components = append(s.Components, randComp(tag))
		}
		return s
	}
	firstOS := func(ss ...*types.ImageSBOM) *types.Component {
		for _, s := range ss {
			if s == nil {
				continue
			}
			for i := range s.Components {
				if s.Components[i].Type == "operating-system" {
					return &s.Components[i]
				}
			}
		}
		return nil
	}

	for round := 0; round < 2000; round++ {
		var tr, nd *types.ImageSBOM
		var regs []*types.ImageSBOM
		members := []*types.ImageSBOM{}
		if rng.Intn(2) == 0 {
			tr = randSBOM(types.SourceTrivyOperator, "trivy")
			members = append(members, tr)
		}
		if rng.Intn(3) != 0 {
			nd = randSBOM(types.SourceNode, "node")
			members = append(members, nd)
		}
		for n := rng.Intn(4); n > 0; n-- {
			r := randSBOM(types.SourceRegistry, "registry")
			regs = append(regs, r)
			members = append(members, r)
		}
		rng.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
		max := 3 + rng.Intn(40)
		if rng.Intn(4) == 0 {
			max = DefaultMaxComponents
		}
		out, _ := mergeComponents(members, max)

		byKey := map[string]types.Component{}
		var osOut *types.Component
		for i, c := range out {
			if c.Type == "operating-system" {
				if osOut != nil {
					t.Fatalf("round %d: two operating-system components", round)
				}
				osOut = &out[i]
				continue
			}
			k := componentKey(c)
			if _, dup := byKey[k]; dup {
				t.Fatalf("round %d: package %q listed twice", round, k)
			}
			byKey[k] = c
		}

		trivyKeys := map[string]bool{}
		trivyCount := 0
		if tr != nil {
			first := map[string]types.Component{}
			for _, c := range tr.Components {
				if c.Type == "operating-system" {
					continue
				}
				k := componentKey(c)
				if _, ok := first[k]; !ok {
					first[k] = c
				}
			}
			trivyCount = len(first)
			for k, c := range first {
				trivyKeys[k] = true
				got, ok := byKey[k]
				if trivyCount+1 <= max && !ok {
					t.Fatalf("round %d (cap %d): Trivy component %q lost", round, max, k)
				}
				if ok && identity(got) != identity(withPURL(c, got.PURL)) {
					t.Fatalf("round %d: Trivy component %q changed: %s -> %s", round, k, identity(c), identity(got))
				}
				if ok && c.PURL != "" && got.PURL != c.PURL {
					t.Fatalf("round %d: Trivy PURL of %q replaced", round, k)
				}
			}
		}

		// Node components not in Trivy: kept as reported, and only dropped
		// when no registry-only component took the room.
		registryOnlyKept := 0
		nodeKeys := map[string]bool{}
		if nd != nil {
			for _, c := range nd.Components {
				if c.Type != "operating-system" && !trivyKeys[componentKey(c)] {
					nodeKeys[componentKey(c)] = true
				}
			}
		}
		for k := range byKey {
			if !trivyKeys[k] && !nodeKeys[k] {
				registryOnlyKept++
			}
		}
		if nd != nil {
			seen := map[string]bool{}
			for _, c := range nd.Components {
				k := componentKey(c)
				if c.Type == "operating-system" || trivyKeys[k] || seen[k] {
					continue
				}
				seen[k] = true
				got, ok := byKey[k]
				if !ok {
					if registryOnlyKept > 0 {
						t.Fatalf("round %d (cap %d): node component %q dropped while %d registry-only kept", round, max, k, registryOnlyKept)
					}
					continue
				}
				if identity(got) != identity(withPURL(c, got.PURL)) || (c.PURL != "" && got.PURL != c.PURL) {
					t.Fatalf("round %d: node component %q changed by a registry SBOM: %s -> %s", round, k, identity(c), identity(got))
				}
			}
		}

		// Operating system: Trivy's, else node's, else a registry one's.
		want := firstOS(tr)
		if want == nil {
			want = firstOS(nd)
		}
		if want == nil {
			want = firstOS(regs...)
		}
		if osOut != nil && want != nil && tr != nil && firstOS(tr) != nil && !reflect.DeepEqual(*osOut, *firstOS(tr)) {
			t.Fatalf("round %d: OS %+v, want Trivy's %+v", round, *osOut, *firstOS(tr))
		}
		if osOut != nil && (tr == nil || firstOS(tr) == nil) && firstOS(nd) != nil && !reflect.DeepEqual(*osOut, *firstOS(nd)) {
			t.Fatalf("round %d: OS %+v, want the node SBOM's %+v", round, *osOut, *firstOS(nd))
		}
		if tr != nil && firstOS(tr) != nil && osOut == nil {
			t.Fatalf("round %d: Trivy's OS component lost", round)
		}
		if osOut != nil && want == nil {
			t.Fatalf("round %d: OS component from nowhere", round)
		}

		limit := trivyCount
		if firstOS(tr) != nil {
			limit++
		}
		if limit <= max && len(out) > max {
			t.Fatalf("round %d: %d components over the cap %d", round, len(out), max)
		}
	}
}

// withPURL is c with its PURL as filled in by a lower source, if c had
// none (the one change a lower source may make).
func withPURL(c types.Component, purl string) types.Component {
	if c.PURL == "" {
		c.PURL = purl
	}
	return c
}

// A node SBOM wins over a registry SBOM's entry for the same package and
// fills the room before any registry component does.
func TestMergeNodeBeforeRegistry(t *testing.T) {
	nd := &types.ImageSBOM{Source: types.SourceNode, Components: []types.Component{
		{Name: "debian", Version: "12", Type: "operating-system"},
		{Name: "libc6", Version: "2.36", PURL: "pkg:deb/debian/libc6@2.36?arch=arm64", SrcName: "glibc"},
		{Name: "zlib1g", Version: "1.2", PURL: "pkg:deb/debian/zlib1g@1.2?arch=arm64"},
	}}
	reg := &types.ImageSBOM{Source: types.SourceRegistry, Components: []types.Component{
		{Name: "alpine", Version: "3.20", Type: "operating-system"},
		{Name: "libc6", Version: "2.36", PURL: "pkg:deb/debian/libc6@2.36?upstream=evil", SrcName: "evil", FilePaths: []string{"/lib/libc.so.6"}},
		{Name: "aaa", Version: "1", PURL: "pkg:npm/aaa@1"},
	}}
	out, dropped := mergeComponents([]*types.ImageSBOM{reg, nd}, 3)
	if dropped != 1 {
		t.Errorf("dropped %d, want 1 (aaa; the registry OS entry is ignored, not dropped)", dropped)
	}
	if len(out) != 3 || out[0].Name != "debian" || out[1].Name != "libc6" || out[2].Name != "zlib1g" {
		t.Fatalf("out %+v", out)
	}
	if out[1].SrcName != "glibc" || out[1].PURL != "pkg:deb/debian/libc6@2.36?arch=arm64" || !reflect.DeepEqual(out[1].FilePaths, []string{"/lib/libc.so.6"}) {
		t.Errorf("registry changed the node entry (only file paths may be added): %+v", out[1])
	}
}

func TestPinPlatform(t *testing.T) {
	img := types.ImageRef{Digest: "sha256:ix", IndexDigest: "sha256:parent",
		PlatformManifests: map[string]string{"linux/amd64": "sha256:a", "linux/arm64": "sha256:b"}}
	PinPlatform(&img, "linux/arm64")
	if !reflect.DeepEqual(img.PlatformManifests, map[string]string{"linux/arm64": "sha256:b"}) || img.IndexDigest != "" {
		t.Errorf("pinned: %+v", img)
	}
	for _, p := range []string{"", "linux/s390x"} {
		img := types.ImageRef{Digest: "sha256:ix", PlatformManifests: map[string]string{"linux/amd64": "sha256:a"}}
		PinPlatform(&img, p)
		if img.PlatformManifests != nil {
			t.Errorf("%q: kept %v", p, img.PlatformManifests)
		}
	}
}

// A node SBOM is matched under its own digest, never fanned out to the
// other platforms of an index: a registry SBOM of another platform stays
// in its own group, and the payload is pinned to the node's platform.
func TestNodeSBOMIsSinglePlatform(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	start(t, c, time.Hour)

	c.Offer(nodeSBOM("sha256:index", "linux/arm64", "libc6"))
	c.Offer(registrySBOM("sha256:amd64", "sha256:index", "musl"))
	waitFor(t, func() bool { return m.n("sha256:index") == 1 && m.n("sha256:amd64") == 1 })
	if names(m.input("sha256:index")) != "libc6" || names(m.input("sha256:amd64")) != "musl" {
		t.Fatalf("groups mixed: index %v, amd64 %v", m.input("sha256:index"), m.input("sha256:amd64"))
	}
	e := emission(t, s, "sha256:index")
	if !e.PinPlatform || e.Platform != "linux/arm64" || e.Vulns.Image.PlatformManifests != nil || e.Vulns.Image.IndexDigest != "" ||
		!reflect.DeepEqual(e.Vulns.SBOMSources, []string{"node"}) || e.Vulns.SBOMTrust != types.SBOMTrustScanned {
		t.Errorf("node payload: %+v %+v", e, e.Vulns)
	}
	if e := emission(t, s, "sha256:amd64"); e.PinPlatform {
		t.Errorf("registry-only payload pinned")
	}
}

// With Trivy's SBOM on the same digest the node SBOM joins its union
// (Trivy authoritative), and the payload, including what enrichment adds,
// keeps only the node platform's manifest.
func TestNodeJoinsTrivyAndPinsThePayload(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	start(t, c, time.Hour)

	tr := trivySBOM("sha256:index", "openssl")
	tr.Image.PlatformManifests = map[string]string{"linux/amd64": "sha256:amd64", "linux/arm64": "sha256:arm64"}
	c.Offer(tr)
	c.Offer(nodeSBOM("sha256:index", "linux/arm64", "openssl", "libc6"))
	waitFor(t, func() bool {
		v := s.last()
		return v != nil && reflect.DeepEqual(v.SBOMSources, []string{"node", "trivy-operator"})
	})
	if got := names(m.input("sha256:index")); got != "openssl,libc6" {
		t.Errorf("union %s, want Trivy's openssl then the node's libc6", got)
	}
	in := m.input("sha256:index")
	if in[0].PURL != "pkg:deb/debian/openssl@1" {
		t.Errorf("node SBOM changed Trivy's entry: %+v", in[0])
	}
	e := emission(t, s, "sha256:index")
	if !reflect.DeepEqual(e.Vulns.Image.PlatformManifests, map[string]string{"linux/arm64": "sha256:arm64"}) {
		t.Errorf("payload platforms %v, want only linux/arm64", e.Vulns.Image.PlatformManifests)
	}
	if len(e.Vulns.ObservedIn) != 1 {
		t.Errorf("Trivy's provenance lost: %+v", e.Vulns.ObservedIn)
	}
}

// A platform-manifest digest with a node SBOM is not folded into its
// index's Trivy group: its findings stay on the digest the node
// cataloged, and the index group is matched again without it.
func TestNodeSBOMKeepsItsDigestOutOfTheIndexGroup(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	start(t, c, time.Hour)

	c.Offer(trivySBOM("sha256:index", "openssl"))
	c.Offer(registrySBOM("sha256:arm64", "sha256:index", "musl"))
	waitFor(t, func() bool { return names(m.input("sha256:index")) == "openssl,musl" })

	c.Offer(nodeSBOM("sha256:arm64", "linux/arm64", "libc6"))
	waitFor(t, func() bool { return m.n("sha256:arm64") == 1 && names(m.input("sha256:index")) == "openssl" })
	if got := names(m.input("sha256:arm64")); got != "libc6,musl" {
		t.Errorf("node group %s, want the node's libc6 plus the registry's musl", got)
	}
}

func names(cs []types.Component) string {
	out := ""
	for i, c := range cs {
		if i > 0 {
			out += ","
		}
		out += c.Name
	}
	return out
}

func emission(t *testing.T, s *sink, digest string) trivy.Emission {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.es) - 1; i >= 0; i-- {
		if e := s.es[i]; e.Kind == trivy.KindVulnerabilities && e.Digest == digest {
			return e
		}
	}
	t.Fatalf("no vulnerabilities emitted for %s", digest)
	return trivy.Emission{}
}
