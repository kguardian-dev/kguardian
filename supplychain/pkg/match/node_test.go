package match

import (
	"context"
	"fmt"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
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

// Property: over random combinations of sources (Trivy or not, zero to
// three registry SBOMs, a node SBOM), random overlapping packages, random
// operating-system entries and random caps, adding the node SBOM never
// takes anything from the union the other sources make:
//   - every entry of the union without the node SBOM is in the union with
//     it, with the same identity (so the same findings), and the
//     operating-system component is the same;
//   - node components are only appended, never listed twice, and dropped
//     only when the cap leaves no room;
//   - every Trivy component is in the union exactly as Trivy reported it;
//   - the union stays within the cap whenever Trivy alone does.
//
// Partial and os_only node SBOMs are just small ones here: however few
// packages the node lists, the property holds.
func TestUnionPropertyNodeOnlyAdds(t *testing.T) {
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
		switch rng.Intn(5) {
		case 0:
			c.PURL = "" // an entry a lower source might try to fill in
			c.Type = pt
		case 1:
			// Same package, another name spelling (Trivy's maven
			// "group:artifact"): only the PURL says they are one.
			c.Name = "group:" + name
		}
		if rng.Intn(3) == 0 {
			c.FilePaths = []string{fmt.Sprintf("/%s/%d", tag, rng.Intn(5))}
		}
		return c
	}
	randSBOM := func(source, tag string, n int) *types.ImageSBOM {
		s := &types.ImageSBOM{Source: source}
		for ; n > 0; n-- {
			if rng.Intn(8) == 0 {
				s.Components = append(s.Components, types.Component{Name: tag + "-os", Version: fmt.Sprint(rng.Intn(9)), Type: "operating-system"})
				continue
			}
			s.Components = append(s.Components, randComp(tag))
		}
		return s
	}

	for round := 0; round < 3000; round++ {
		var members []*types.ImageSBOM
		var tr *types.ImageSBOM
		if rng.Intn(2) == 0 {
			tr = randSBOM(types.SourceTrivyOperator, "trivy", rng.Intn(12))
			members = append(members, tr)
		}
		for n := rng.Intn(4); n > 0; n-- {
			members = append(members, randSBOM(types.SourceRegistry, "registry", rng.Intn(12)))
		}
		size := rng.Intn(12)
		if rng.Intn(3) == 0 {
			size = rng.Intn(3) // an os_only / partial catalog
		}
		nd := randSBOM(types.SourceNode, "node", size)
		// The other SBOMs keep their order (between registry SBOMs the
		// first wins); the node SBOM goes anywhere among them.
		rng.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
		at := rng.Intn(len(members) + 1)
		with := append(append(append([]*types.ImageSBOM{}, members[:at]...), nd), members[at:]...)
		max := 3 + rng.Intn(40)
		if rng.Intn(4) == 0 {
			max = DefaultMaxComponents
		}
		u0, _ := mergeComponents(members, max)
		u1, _ := mergeComponents(with, max)

		seen := map[string]bool{}
		ids := map[string]bool{}
		var os1 *types.Component
		for i, c := range u1 {
			if c.Type == "operating-system" {
				if os1 != nil {
					t.Fatalf("round %d: two operating-system components", round)
				}
				os1 = &u1[i]
				continue
			}
			if seen[componentKey(c)] {
				t.Fatalf("round %d: %q listed twice", round, componentKey(c))
			}
			seen[componentKey(c)] = true
			ids[identity(c)] = true
		}
		var os0 *types.Component
		for i, c := range u0 {
			if c.Type == "operating-system" {
				os0 = &u0[i]
				continue
			}
			if !ids[identity(c)] {
				t.Fatalf("round %d (cap %d, node %d): %s lost or changed by the node SBOM", round, max, size, identity(c))
			}
		}
		if len(members) > 0 && !reflect.DeepEqual(os0, os1) {
			t.Fatalf("round %d: node SBOM changed the OS component: %+v -> %+v", round, os0, os1)
		}
		if len(u1) < len(u0) {
			t.Fatalf("round %d: union shrank from %d to %d", round, len(u0), len(u1))
		}
		// Node components are dropped only for want of room.
		if len(u1) < max {
			for _, c := range nd.Components {
				if c.Type == "operating-system" {
					continue
				}
				found := false
				for _, e := range u1 {
					if e.Type != "operating-system" && (componentKey(e) == componentKey(c) || (purlKey(c.PURL) != "" && purlKey(e.PURL) == purlKey(c.PURL))) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("round %d: node component %s dropped with room left (%d of %d)", round, identity(c), len(u1), max)
				}
			}
		}
		if tr != nil {
			first := map[string]types.Component{}
			hasOS := false
			for _, c := range tr.Components {
				if c.Type == "operating-system" {
					hasOS = true
					continue
				}
				if _, ok := first[componentKey(c)]; !ok {
					first[componentKey(c)] = c
				}
			}
			limit := len(first)
			if hasOS {
				limit++
			}
			if limit <= max && len(u1) > max {
				t.Fatalf("round %d: %d components over the cap %d", round, len(u1), max)
			}
		}
	}
}

// A node entry colliding with a registry one adds only file paths and
// licences, never its PURL or source package; its OS component is not
// used beside another source; and under the cap registry components keep
// their room.
func TestMergeNodeAddsAfterRegistry(t *testing.T) {
	nd := &types.ImageSBOM{Source: types.SourceNode, Components: []types.Component{
		{Name: "debian", Version: "12", Type: "operating-system"},
		{Name: "libc6", Version: "2.36", PURL: "pkg:deb/debian/libc6@2.36?arch=arm64", SrcName: "glibc", FilePaths: []string{"/lib/libc.so.6"}},
		{Name: "zlib1g", Version: "1.2", PURL: "pkg:deb/debian/zlib1g@1.2?arch=arm64"},
	}}
	reg := &types.ImageSBOM{Source: types.SourceRegistry, Components: []types.Component{
		{Name: "libc6", Version: "2.36", Type: "deb"},
		{Name: "aaa", Version: "1", PURL: "pkg:npm/aaa@1"},
	}}
	out, dropped := mergeComponents([]*types.ImageSBOM{nd, reg}, 2)
	if dropped != 1 || len(out) != 2 || out[0].Name != "libc6" || out[1].Name != "aaa" {
		t.Fatalf("out %+v dropped %d, want the registry entries kept and zlib1g dropped", out, dropped)
	}
	if out[0].PURL != "" || out[0].SrcName != "" || !reflect.DeepEqual(out[0].FilePaths, []string{"/lib/libc.so.6"}) {
		t.Errorf("node re-attributed the registry entry (only paths may be added): %+v", out[0])
	}
	// Alone, the node SBOM is used whole, OS included.
	out, _ = mergeComponents([]*types.ImageSBOM{nd}, 10)
	if len(out) != 3 || out[0].Name != "debian" {
		t.Errorf("node alone: %+v", out)
	}
}

func TestPinPlatform(t *testing.T) {
	manifests := func(keys ...string) map[string]string {
		m := map[string]string{}
		for _, k := range keys {
			m[k] = "sha256:" + k
		}
		return m
	}
	cases := []struct {
		name     string
		index    []string
		platform string
		want     []string // kept keys; nil = none kept
		unpinned bool     // ambiguous: left as it was
	}{
		{"exact", []string{"linux/amd64", "linux/arm64"}, "linux/arm64", []string{"linux/arm64"}, false},
		{"arm64 means v8", []string{"linux/amd64", "linux/arm64/v8"}, "linux/arm64", []string{"linux/arm64/v8"}, false},
		{"arm64 default among variants", []string{"linux/arm64/v8", "linux/arm64/v9"}, "linux/arm64", []string{"linux/arm64/v8"}, false},
		{"arm unique variant", []string{"linux/amd64", "linux/arm/v7"}, "linux/arm", []string{"linux/arm/v7"}, false},
		{"arm ambiguous", []string{"linux/arm/v6", "linux/arm/v7"}, "linux/arm", nil, true},
		{"variant on node only", []string{"linux/arm", "linux/amd64"}, "linux/arm/v7", []string{"linux/arm"}, false},
		{"variant mismatch", []string{"linux/arm/v6"}, "linux/arm/v7", nil, false},
		{"absent", []string{"linux/amd64"}, "linux/s390x", nil, false},
		{"unknown platform", []string{"linux/amd64"}, "", nil, false},
		{"case", []string{"linux/amd64"}, "Linux/AMD64", []string{"linux/amd64"}, false},
	}
	for _, c := range cases {
		img := types.ImageRef{Digest: "sha256:ix", IndexDigest: "sha256:parent", PlatformManifests: manifests(c.index...)}
		PinPlatform(&img, c.platform)
		if c.unpinned {
			if !reflect.DeepEqual(img.PlatformManifests, manifests(c.index...)) || img.IndexDigest != "sha256:parent" {
				t.Errorf("%s: ambiguous pin changed the image: %+v", c.name, img)
			}
			continue
		}
		var got []string
		for k := range img.PlatformManifests {
			got = append(got, k)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) || img.IndexDigest != "" {
			t.Errorf("%s: kept %v (index %q), want %v", c.name, got, img.IndexDigest, c.want)
		}
	}
}

// A node SBOM alone in its group is pinned to its platform, and the
// registry SBOMs of the index's other platforms keep their own groups
// and links (index_digest) exactly as before.
func TestNodeAloneIsPinnedAndSiblingsKeepTheirLinks(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	c.Offer(registrySBOM("sha256:amd64", "sha256:index", "musl"))
	c.Offer(registrySBOM("sha256:arm64", "sha256:index", "zlib"))
	pass(c)
	before := map[string]types.ImageRef{"sha256:amd64": emission(t, s, "sha256:amd64").Vulns.Image, "sha256:arm64": emission(t, s, "sha256:arm64").Vulns.Image}

	c.Offer(nodeSBOM("sha256:index", "linux/arm64", "libc6"))
	pass(c)
	if names(m.input("sha256:index")) != "libc6" || m.n("sha256:amd64") != 1 || m.n("sha256:arm64") != 1 {
		t.Fatalf("groups changed: index %v, amd64 %d, arm64 %d", m.input("sha256:index"), m.n("sha256:amd64"), m.n("sha256:arm64"))
	}
	e := emission(t, s, "sha256:index")
	if !e.PinPlatform || e.Platform != "linux/arm64" || e.Vulns.Image.PlatformManifests != nil || e.Vulns.Image.IndexDigest != "" ||
		!reflect.DeepEqual(e.Vulns.SBOMSources, []string{"node"}) || e.Vulns.SBOMTrust != types.SBOMTrustScanned {
		t.Errorf("node payload: %+v %+v", e, e.Vulns)
	}
	for d, img := range before {
		if got := emission(t, s, d).Vulns.Image; !reflect.DeepEqual(got, img) || got.IndexDigest != "sha256:index" {
			t.Errorf("%s: sibling links changed: %+v -> %+v", d, img, got)
		}
	}
}

// With Trivy's SBOM on the digest the node SBOM joins its group unpinned:
// Trivy's entries and links stay, the node only adds packages.
func TestNodeJoinsTrivyUnpinned(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	tr := trivySBOM("sha256:index", "openssl")
	tr.Image.PlatformManifests = map[string]string{"linux/amd64": "sha256:amd64", "linux/arm64": "sha256:arm64"}
	c.Offer(tr)
	c.Offer(nodeSBOM("sha256:index", "linux/arm64", "openssl", "libc6"))
	pass(c)
	if got := names(m.input("sha256:index")); got != "openssl,libc6" {
		t.Errorf("union %s, want Trivy's openssl then the node's libc6", got)
	}
	if in := m.input("sha256:index"); in[0].PURL != "pkg:deb/debian/openssl@1" {
		t.Errorf("node SBOM changed Trivy's entry: %+v", in[0])
	}
	e := emission(t, s, "sha256:index")
	if e.PinPlatform || !reflect.DeepEqual(e.Vulns.Image.PlatformManifests, tr.Image.PlatformManifests) ||
		!reflect.DeepEqual(e.Vulns.SBOMSources, []string{"node", "trivy-operator"}) || len(e.Vulns.ObservedIn) != 1 {
		t.Errorf("payload %+v %+v", e, e.Vulns)
	}
}

// A node SBOM on a platform digest whose index has Trivy's SBOM does not
// split the digest out of the index's group: it joins it, unpinned.
func TestNodeOnPlatformJoinsTheTrivyIndexGroup(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	c.Offer(trivySBOM("sha256:index", "openssl"))
	c.Offer(registrySBOM("sha256:arm64", "sha256:index", "musl"))
	pass(c)
	c.Offer(nodeSBOM("sha256:arm64", "linux/arm64", "libc6"))
	pass(c)
	if got := names(m.input("sha256:index")); got != "openssl,musl,libc6" {
		t.Errorf("index group %s", got)
	}
	if m.n("sha256:arm64") != 0 || emission(t, s, "sha256:index").PinPlatform {
		t.Errorf("platform digest split out (%d matches) or payload pinned", m.n("sha256:arm64"))
	}
}

// The reverse case: a registry SBOM of one platform (no Trivy anywhere)
// links its findings to the index too. A node SBOM on that digest,
// however partial, keeps that link and every finding.
func TestNodeBesideRegistryKeepsItsLinksAndFindings(t *testing.T) {
	for _, nodeComps := range [][]string{{}, {"musl"}, {"libc6"}} { // os_only-like, colliding, new
		m := &mockMatcher{built: time.Unix(100, 0)}
		s := &sink{}
		c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
		c.Offer(registrySBOM("sha256:arm64", "sha256:index", "musl", "zlib"))
		pass(c)
		v0 := emission(t, s, "sha256:arm64").Vulns
		n := nodeSBOM("sha256:arm64", "linux/arm64", nodeComps...)
		n.Components = append(n.Components, types.Component{Name: "alpine", Version: "3.20", Type: "operating-system"})
		c.Offer(n)
		pass(c)
		e := emission(t, s, "sha256:arm64")
		if e.PinPlatform || !reflect.DeepEqual(e.Vulns.Image, v0.Image) {
			t.Errorf("%v: links changed: %+v -> %+v", nodeComps, v0.Image, e.Vulns.Image)
		}
		got := map[string]bool{}
		for _, v := range e.Vulns.Vulnerabilities {
			got[v.ID+"|"+v.Package.PURL] = true
		}
		for _, v := range v0.Vulnerabilities {
			if !got[v.ID+"|"+v.Package.PURL] {
				t.Errorf("%v: finding %s on %s lost", nodeComps, v.ID, v.Package.PURL)
			}
		}
		for _, comp := range m.input("sha256:arm64") {
			if comp.Type == "operating-system" {
				t.Errorf("%v: the node's OS component was used beside a registry SBOM", nodeComps)
			}
		}
	}
}

// Node off: a registry SBOM re-offered under another index leaves the old
// group alone, as it always has. With a node SBOM on the moving digest
// the old group is matched again without it.
func TestGroupMoveRequeuesOnlyWithANodeSBOM(t *testing.T) {
	for _, withNode := range []bool{false, true} {
		m := &mockMatcher{built: time.Unix(100, 0)}
		c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet()}
		c.Offer(trivySBOM("sha256:index", "openssl"))
		c.Offer(registrySBOM("sha256:arm64", "sha256:index", "musl"))
		if withNode {
			c.Offer(nodeSBOM("sha256:arm64", "linux/arm64", "libc6"))
		}
		pass(c)
		before := m.n("sha256:index")
		c.Offer(registrySBOM("sha256:arm64", "", "musl")) // leaves the index's group
		pass(c)
		requeued := m.n("sha256:index") > before
		if requeued != withNode {
			t.Errorf("node %v: index re-matched %v", withNode, requeued)
		}
		if withNode && names(m.input("sha256:index")) != "openssl" {
			t.Errorf("index group still holds the moved digest: %v", m.input("sha256:index"))
		}
	}
}

// evictAll drops every settled group's SBOMs, as a full budget would.
func evictAll(c *Coordinator) {
	c.mu.Lock()
	limit := c.MaxHeldBytes
	c.MaxHeldBytes = 1
	c.evictLocked("", 0)
	c.MaxHeldBytes = limit
	c.mu.Unlock()
	c.flushRefetches()
}

func emissions(s *sink) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.es)
}

// The reviewer's case: Trivy (two platforms) and a node SBOM, evicted;
// the node SBOM comes back first and alone. It must not be matched on its
// own (pinned, without Trivy's findings); the broker keeps the complete
// payload until Trivy's SBOM is back, and then both are matched unpinned.
func TestEvictedGroupNodeBackFirstIsNotMatchedAlone(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	tr := trivySBOM("sha256:d", "openssl")
	tr.Image.PlatformManifests = map[string]string{"linux/amd64": "sha256:amd64", "linux/arm64": "sha256:arm64"}
	c.Offer(tr)
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
	pass(c)
	before := emissions(s)
	evictAll(c)
	if c.Held() != 0 {
		t.Fatal("not evicted")
	}

	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
	pass(c)
	if c.Wants("sha256:d") {
		t.Error("node SBOM wanted while Trivy's is missing")
	}
	m.setBuilt(time.Unix(200, 0)) // a new database re-queues what is held
	pass(c)
	if emissions(s) != before || m.n("sha256:d") != 1 {
		t.Fatalf("matched from the node SBOM alone: %d matches, input %v", m.n("sha256:d"), m.input("sha256:d"))
	}

	tr2 := trivySBOM("sha256:d", "openssl", "zlib") // Trivy re-offers only on change
	tr2.Image.PlatformManifests = tr.Image.PlatformManifests
	c.Offer(tr2)
	pass(c)
	e := emission(t, s, "sha256:d")
	if names(m.input("sha256:d")) != "openssl,zlib,libc6" || e.PinPlatform ||
		!reflect.DeepEqual(e.Vulns.SBOMSources, []string{"node", "trivy-operator"}) || len(e.Vulns.Image.PlatformManifests) != 2 {
		t.Errorf("after Trivy's return: %v %+v", m.input("sha256:d"), e)
	}
}

// Trivy's SBOM back first: the group waits for the node SBOM (Wants says
// so) instead of dropping the node's findings; the node SBOM completes
// it. Without the node SBOM it is matched once the grace is over.
func TestEvictedGroupWaitsForItsNodeSBOM(t *testing.T) {
	for _, nodeBack := range []bool{true, false} {
		now := time.Unix(1000, 0)
		m := &mockMatcher{built: time.Unix(100, 0)}
		s := &sink{}
		c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
		c.now = func() time.Time { return now }
		c.Offer(trivySBOM("sha256:d", "openssl"))
		c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
		pass(c)
		evictAll(c)
		c.Offer(trivySBOM("sha256:d", "openssl", "zlib"))
		pass(c)
		if m.n("sha256:d") != 1 || !c.Wants("sha256:d") {
			t.Fatalf("back %v: %d matches, wants %v", nodeBack, m.n("sha256:d"), c.Wants("sha256:d"))
		}
		if nodeBack {
			c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
			pass(c)
			if names(m.input("sha256:d")) != "openssl,zlib,libc6" || c.Wants("sha256:d") {
				t.Errorf("node back: %v, wants %v", m.input("sha256:d"), c.Wants("sha256:d"))
			}
			continue
		}
		now = now.Add(11 * time.Minute)
		c.mu.Lock()
		c.requeueLocked()
		c.mu.Unlock()
		pass(c)
		if names(m.input("sha256:d")) != "openssl,zlib" || c.Wants("sha256:d") {
			t.Errorf("after the grace: %v, wants %v", m.input("sha256:d"), c.Wants("sha256:d"))
		}
	}
}

// An empty node offer releases a held node SBOM, and is ignored for a
// digest with none held (evicted or never offered): no empty payload.
func TestEmptyNodeOfferOnlyReleasesAHeldOne(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet()}
	c.Offer(nodeSBOM("sha256:never", "linux/arm64"))
	c.Offer(trivySBOM("sha256:d", "openssl"))
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
	pass(c)
	if c.Holds("sha256:never", types.SourceNode) || m.n("sha256:never") != 0 {
		t.Fatal("empty offer for a digest never offered was taken")
	}
	evictAll(c)
	before := emissions(s)
	c.Offer(nodeSBOM("sha256:d", "linux/arm64"))
	pass(c)
	if c.Held() != 0 || emissions(s) != before {
		t.Fatalf("empty offer after eviction: held %d, %d new emissions", c.Held(), emissions(s)-before)
	}

	// Held: the release takes the node's packages out.
	c.Offer(trivySBOM("sha256:e", "openssl"))
	c.Offer(nodeSBOM("sha256:e", "linux/arm64", "libc6"))
	pass(c)
	c.Offer(nodeSBOM("sha256:e", "linux/arm64"))
	pass(c)
	if names(m.input("sha256:e")) != "openssl" {
		t.Errorf("release: %v", m.input("sha256:e"))
	}
}

// heldCheckMatcher checks, at every match, that the input contains every
// component of the Trivy and registry SBOMs the coordinator holds for the
// group: whatever the waiting did, a payload never has fewer of their
// findings than the SBOMs actually held.
type heldCheckMatcher struct {
	*mockMatcher
	c   *Coordinator
	bad []string
}

func (h *heldCheckMatcher) Match(ctx context.Context, sb *types.ImageSBOM) ([]types.Vulnerability, error) {
	h.c.mu.Lock()
	want := map[string]bool{}
	for _, m := range h.c.membersLocked(sb.Image.Digest) {
		if m.Source == types.SourceNode {
			continue
		}
		for _, comp := range m.Components {
			want[comp.Name] = true
		}
	}
	h.c.mu.Unlock()
	got := map[string]bool{}
	for _, comp := range sb.Components {
		got[comp.Name] = true
	}
	for n := range want {
		if !got[n] {
			h.bad = append(h.bad, sb.Image.Digest+" lacks held "+n)
		}
	}
	return h.mockMatcher.Match(ctx, sb)
}

// Invariant, over random orders of offers, evictions, database updates
// and time:
//   - within NodeGroupMaxWait, once a group with a node SBOM has been
//     matched with Trivy's or a registry SBOM, it is never matched without
//     it again (none is ever declared gone here; changed content is
//     re-offered, so still present);
//   - at every match, including after the cap, the input holds every
//     component of the Trivy and registry SBOMs held for the group;
//   - no payload with Trivy's or a registry SBOM is pinned.
//
// Groups that never held a node SBOM are left as on main and not checked
// for the first rule.
func TestInvariantNodeNeverDropsOtherSources(t *testing.T) {
	rng := rand.New(rand.NewSource(1851))
	expiredRounds := 0
	for round := 0; round < 300; round++ {
		now := time.Unix(1000, 0)
		mm := &mockMatcher{built: time.Unix(100, 0)}
		s := &sink{}
		met := metrics.New()
		log, hook := logtest.NewNullLogger()
		c := &Coordinator{Sink: s, Log: log, Metrics: met}
		hm := &heldCheckMatcher{mockMatcher: mm, c: c}
		c.Matcher = hm
		c.now = func() time.Time { return now }
		content := func(prefix string) []string {
			n := rng.Intn(3)
			out := []string{}
			for i := 0; i < n; i++ {
				out = append(out, fmt.Sprintf("%s%d", prefix, rng.Intn(4)))
			}
			return out
		}
		prev := map[string][]string{}
		expiredSince := map[string]bool{} // the cap ended the key's wait since its last payload
		seen := 0
		var ops []string
		for step := 0; step < 40; step++ {
			switch op := rng.Intn(8); op {
			case 0:
				c.Offer(trivySBOM("sha256:d", append([]string{"t"}, content("t")...)...))
				ops = append(ops, "trivy")
			case 1:
				c.Offer(registrySBOM("sha256:p", "sha256:d", append([]string{"r"}, content("r")...)...))
				ops = append(ops, "reg-p")
			case 2:
				c.Offer(nodeSBOM("sha256:d", "linux/arm64", content("n")...))
				ops = append(ops, "node-d")
			case 3:
				c.Offer(nodeSBOM("sha256:p", "linux/arm64", content("m")...))
				ops = append(ops, "node-p")
			case 4, 5:
				evictAll(c)
				ops = append(ops, "evict")
			case 6:
				mm.setBuilt(time.Unix(int64(200+step), 0))
				ops = append(ops, "db")
			case 7:
				now = now.Add(time.Duration(rng.Intn(15)) * time.Minute)
				c.mu.Lock()
				c.requeueLocked()
				c.mu.Unlock()
				ops = append(ops, fmt.Sprintf("tick@%d", now.Unix()-1000))
			}
			pass(c)
			if len(hm.bad) > 0 {
				t.Fatalf("round %d: %v after %v", round, hm.bad, ops)
			}
			for _, entry := range hook.AllEntries() {
				if d, ok := entry.Data["digest"].(string); ok && strings.Contains(entry.Message, "did not come back in time") {
					expiredSince[d] = true
					expiredRounds++
					ops = append(ops, "expired:"+d[7:])
				}
			}
			hook.Reset()
			s.mu.Lock()
			fresh := s.es[seen:]
			seen = len(s.es)
			s.mu.Unlock()
			for _, e := range fresh {
				if e.Kind != trivy.KindVulnerabilities {
					continue
				}
				cur := e.Vulns.SBOMSources
				if p := prev[e.Digest]; !expiredSince[e.Digest] && slices.Contains(p, types.SourceNode) {
					for _, src := range p {
						if src != types.SourceNode && !slices.Contains(cur, src) {
							t.Fatalf("round %d: %s matched without %s after %v (before %v, now %v)", round, e.Digest, src, ops, p, cur)
						}
					}
				}
				if e.PinPlatform && (slices.Contains(cur, types.SourceTrivyOperator) || slices.Contains(cur, types.SourceRegistry)) {
					t.Fatalf("round %d: pinned payload with other sources %v after %v", round, cur, ops)
				}
				ops = append(ops, fmt.Sprintf("emit:%s%v", e.Digest[7:], cur))
				delete(expiredSince, e.Digest)
				prev[e.Digest] = cur
			}
		}
	}
	if expiredRounds == 0 {
		t.Error("the cap never expired: the sequences do not exercise it")
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

type recordingRefetcher struct {
	mu       sync.Mutex
	digests  []string
	hold     map[string]*types.ImageSBOM // returned by Refetch (a source that holds SBOMs)
	inMemory bool                        // answers from memory, like Trivy's tracker
}

func (r *recordingRefetcher) RefetchesFromMemory() bool { return r.inMemory }

func (r *recordingRefetcher) setHold(d string, sb *types.ImageSBOM) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hold[d] = sb
}

func (r *recordingRefetcher) Refetch(d string) *types.ImageSBOM {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.digests = append(r.digests, d)
	return r.hold[d]
}
func (r *recordingRefetcher) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := slices.Clone(r.digests)
	sort.Strings(out)
	return slices.Compact(out)
}
func (r *recordingRefetcher) calls() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.digests) }

func advance(c *Coordinator, now *time.Time, d time.Duration) {
	*now = now.Add(d)
	c.mu.Lock()
	c.requeueLocked()
	c.mu.Unlock()
	pass(c)
}

// A changed node SBOM after an eviction: the eviction asks nothing; the
// group starting to wait asks Trivy, which hands its SBOM straight back
// (offered directly, never emitted), and the group is matched with the
// new node SBOM. A source that holds nothing leaves it to the cap.
func TestChangedNodeSBOMAfterEvictionIsMatched(t *testing.T) {
	for _, trivyHolds := range []bool{true, false} {
		now := time.Unix(1000, 0)
		m := &mockMatcher{built: time.Unix(100, 0)}
		met := metrics.New()
		s := &sink{}
		c := &Coordinator{Matcher: m, Sink: s, Log: quiet(), Metrics: met}
		c.now = func() time.Time { return now }
		tr, reg := &recordingRefetcher{hold: map[string]*types.ImageSBOM{}, inMemory: true}, &recordingRefetcher{}
		if trivyHolds {
			tr.hold["sha256:d"] = trivySBOM("sha256:d", "openssl")
		}
		c.SetRefetcher(types.SourceTrivyOperator, tr)
		c.SetRefetcher(types.SourceRegistry, reg)
		c.Offer(trivySBOM("sha256:d", "openssl"))
		c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
		pass(c)
		evictAll(c)
		if tr.calls() != 0 || reg.calls() != 0 {
			t.Fatalf("eviction asked for refetches: trivy %v, registry %v", tr.got(), reg.got())
		}
		c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6", "zlib")) // a new catalog
		pass(c)
		if !reflect.DeepEqual(tr.got(), []string{"sha256:d"}) || reg.calls() != 0 || (trivyHolds && tr.calls() != 1) {
			t.Fatalf("waiting asked trivy %v, registry %v", tr.got(), reg.got())
		}
		for _, e := range s.es {
			if e.Kind == trivy.KindSBOM {
				t.Fatal("a refetched SBOM went out through the sink")
			}
		}
		if trivyHolds {
			if names(m.input("sha256:d")) != "openssl,libc6,zlib" {
				t.Errorf("with Trivy's SBOM handed back: %v", m.input("sha256:d"))
			}
			continue
		}
		if m.n("sha256:d") != 1 {
			t.Fatal("matched without Trivy's SBOM inside the wait")
		}
		advance(c, &now, 29*time.Minute)
		if m.n("sha256:d") != 1 {
			t.Fatal("matched before the cap")
		}
		advance(c, &now, 2*time.Minute)
		if names(m.input("sha256:d")) != "libc6,zlib" || testutil.ToFloat64(met.GrypeNodeGroupWaitExpired) != 1 {
			t.Errorf("after the cap: %v (expired %v)", m.input("sha256:d"), testutil.ToFloat64(met.GrypeNodeGroupWaitExpired))
		}
	}
}

// Refetches that cost external work (a registry lookup) are spaced by the
// backoff but retried on every pass while the group waits; the cap runs
// from the last of them, bounded by twice the cap from the start.
func TestExternalRefetchesAreSpacedAndExtendTheCap(t *testing.T) {
	now := time.Unix(1000, 0)
	m := &mockMatcher{built: time.Unix(100, 0)}
	met := metrics.New()
	c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet(), Metrics: met}
	c.now = func() time.Time { return now }
	reg := &recordingRefetcher{}
	c.SetRefetcher(types.SourceRegistry, reg)
	c.Offer(registrySBOM("sha256:d", "", "musl"))
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
	pass(c)
	evictAll(c)
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6", "zlib"))
	pass(c)
	var at []int
	matchedAt := -1
	for minute := 0; minute <= 70; minute++ {
		before := reg.calls()
		if minute > 0 {
			advance(c, &now, time.Minute)
		}
		if reg.calls() > before || (minute == 0 && reg.calls() == 1) {
			at = append(at, minute)
		}
		if matchedAt < 0 && m.n("sha256:d") > 1 {
			matchedAt = minute
		}
	}
	if !reflect.DeepEqual(at, []int{0, 10, 30}) {
		t.Errorf("registry refetches at minutes %v, want 0, 10, 30", at)
	}
	// The last refetch at 30 would put the cap at 60; twice the cap from
	// the start is also 60.
	if matchedAt != 60 {
		t.Errorf("matched at minute %d, want 60", matchedAt)
	}
	if testutil.ToFloat64(met.GrypeRefetches.WithLabelValues(types.SourceRegistry, "requested")) != 3 ||
		testutil.ToFloat64(met.GrypeRefetches.WithLabelValues(types.SourceRegistry, "limited")) == 0 {
		t.Error("refetch counters")
	}
}

// The reviewer's case: Trivy's SBOM dropped twice, five minutes apart,
// and the tracker holding it only later. Trivy's refetches answer from
// memory, so they are never limited and are retried on every pass: the
// group re-matches with Trivy's SBOM inside the wait, and no Trivy
// finding is lost.
func TestTrivyRefetchIsRetriedAndNeverLimited(t *testing.T) {
	now := time.Unix(1000, 0)
	m := &mockMatcher{built: time.Unix(100, 0)}
	met := metrics.New()
	s := &sink{}
	c := &Coordinator{Matcher: m, Sink: s, Log: quiet(), Metrics: met}
	c.now = func() time.Time { return now }
	tr := &recordingRefetcher{hold: map[string]*types.ImageSBOM{}, inMemory: true}
	c.SetRefetcher(types.SourceTrivyOperator, tr)
	c.Offer(trivySBOM("sha256:d", "openssl"))
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
	pass(c)
	for i := 0; i < 2; i++ { // evicted twice, five minutes apart
		evictAll(c)
		c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6", fmt.Sprint(i)))
		pass(c)
		advance(c, &now, 5*time.Minute)
	}
	before := tr.calls()
	advance(c, &now, 5*time.Minute)
	if tr.calls() <= before {
		t.Fatal("Trivy's refetch was not retried while the group waits")
	}
	tr.setHold("sha256:d", trivySBOM("sha256:d", "openssl")) // the tracker has it again
	advance(c, &now, time.Minute)
	if got := names(m.input("sha256:d")); got != "openssl,1,libc6" {
		t.Errorf("re-matched with %s, want Trivy's openssl and the node's libc6,1", got)
	}
	for _, v := range s.vulns() {
		found := false
		for _, f := range v.Vulnerabilities {
			found = found || f.Package.Name == "openssl"
		}
		if !found {
			t.Fatalf("a payload without Trivy's openssl finding: %v", v.SBOMSources)
		}
	}
	if testutil.ToFloat64(met.GrypeRefetches.WithLabelValues(types.SourceTrivyOperator, "limited")) != 0 {
		t.Error("an in-memory refetch was rate-limited")
	}
}

// A successful match with an SBOM resets its refetch backoff: the next
// wait asks for it at once.
func TestRefetchBackoffResetsAfterAMatch(t *testing.T) {
	now := time.Unix(1000, 0)
	m := &mockMatcher{built: time.Unix(100, 0)}
	c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet()}
	c.now = func() time.Time { return now }
	reg := &recordingRefetcher{}
	c.SetRefetcher(types.SourceRegistry, reg)
	c.Offer(registrySBOM("sha256:d", "", "musl"))
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
	pass(c)
	evictAll(c)
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6", "a"))
	pass(c) // refetch 1; window now 10m
	advance(c, &now, time.Minute)
	c.Offer(registrySBOM("sha256:d", "", "musl")) // the source re-emits it
	pass(c)                                       // matched: backoff reset
	evictAll(c)
	c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6", "b"))
	pass(c)
	if reg.calls() != 2 {
		t.Errorf("%d refetches, want 2: the second wait asks at once", reg.calls())
	}
}

// A Trivy change while the group's registry input is gone for good: the
// registry source's gone signal ends the wait at once; without it the cap
// does.
func TestTrivyChangeWithAGoneRegistryInputIsMatched(t *testing.T) {
	for _, gone := range []bool{true, false} {
		now := time.Unix(1000, 0)
		m := &mockMatcher{built: time.Unix(100, 0)}
		c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet()}
		c.now = func() time.Time { return now }
		c.Offer(trivySBOM("sha256:d", "openssl"))
		c.Offer(registrySBOM("sha256:p", "sha256:d", "musl"))
		c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
		pass(c)
		evictAll(c)
		c.Offer(trivySBOM("sha256:d", "openssl", "curl")) // changed
		c.Offer(nodeSBOM("sha256:d", "linux/arm64", "libc6"))
		pass(c)
		if m.n("sha256:d") != 1 {
			t.Fatal("matched while the registry SBOM may still come back")
		}
		if gone {
			c.Gone("sha256:p", types.SourceRegistry)
			pass(c)
		} else {
			advance(c, &now, 31*time.Minute)
		}
		if names(m.input("sha256:d")) != "curl,openssl,libc6" {
			t.Errorf("gone %v: %v", gone, m.input("sha256:d"))
		}
	}
}

// Waiting groups are evictable: under memory pressure their SBOMs go (the
// requirement stays in groupState), so what is held stays bounded.
func TestWaitingGroupsAreEvicted(t *testing.T) {
	const groups = 15 // within the kept state (MaxDigests*maxWaitingGroupsFactor = 20)
	m := &mockMatcher{built: time.Unix(100, 0)}
	c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet(), MaxDigests: 5}
	for i := 0; i < groups; i++ {
		d := fmt.Sprintf("sha256:%02d", i)
		c.Offer(trivySBOM(d, "openssl"))
		c.Offer(nodeSBOM(d, "linux/arm64", "libc6"))
		pass(c)
	}
	evictAll(c)
	m.setBuilt(time.Unix(200, 0)) // stale matches: only waiting could let them go
	for i := 0; i < groups; i++ {
		d := fmt.Sprintf("sha256:%02d", i)
		c.Offer(nodeSBOM(d, "linux/arm64", "libc6", "zlib")) // each group now waits for Trivy
		pass(c)
		if m.n(d) != 1 {
			t.Fatalf("%s matched without Trivy's SBOM", d)
		}
		if c.Held() > 6 {
			t.Fatalf("held %d digests after %d waiting groups (MaxDigests 5)", c.Held(), i+1)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.groups) > 5*maxWaitingGroupsFactor {
		t.Errorf("%d group states kept", len(c.groups))
	}
}

// Node off: evictions ask no source to emit again, and Gone changes
// nothing.
func TestNodeOffEvictionAsksNothing(t *testing.T) {
	m := &mockMatcher{built: time.Unix(100, 0)}
	c := &Coordinator{Matcher: m, Sink: &sink{}, Log: quiet()}
	tr := &recordingRefetcher{}
	c.SetRefetcher(types.SourceTrivyOperator, tr)
	c.SetRefetcher(types.SourceRegistry, tr)
	c.Offer(trivySBOM("sha256:d", "openssl"))
	c.Offer(registrySBOM("sha256:p", "sha256:d", "musl"))
	pass(c)
	evictAll(c)
	c.Gone("sha256:p", types.SourceRegistry)
	c.Offer(trivySBOM("sha256:d", "openssl", "curl"))
	pass(c)
	if len(tr.got()) != 0 || names(m.input("sha256:d")) != "curl,openssl" {
		t.Errorf("refetches %v, input %v", tr.got(), m.input("sha256:d"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.groups["sha256:d"].lastOthers != nil {
		t.Error("node off, yet a requirement was kept")
	}
}
