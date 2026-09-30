// Package difftest compares the cataloger's kernel-confined resolver with
// Syft's stock directory source over the same unpacked image, with the
// same Syft version and configuration. It is the gate for resolver (a) in
// the design: the package sets must be identical, and so must file
// ownership and package evidence, except for paths under a mount the
// resolver refuses to enter.
package difftest

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/rootfs"
	"github.com/kguardian-dev/kguardian/cataloger/internal/scan"
)

// Summary is one side of the comparison, normalised.
type Summary struct {
	// Packages: "type|name|version|purl" (a multiset, as sorted lines).
	Packages []string
	// Owned: package key -> sorted owned files (FileOwner.OwnedFiles).
	Owned map[string][]string
	// Evidence: package key -> sorted "realPath<-accessPath" locations.
	Evidence map[string][]string
	// Relationships between packages and to files, as sorted lines.
	Relationships []string
	Distro        string
}

func pkgKey(p pkg.Package) string {
	return strings.Join([]string{string(p.Type), p.Name, p.Version, p.PURL}, "|")
}

// Summarise normalises an SBOM.
func Summarise(s *sbom.SBOM) Summary {
	out := Summary{Owned: map[string][]string{}, Evidence: map[string][]string{}}
	byID := map[artifact.ID]string{}
	for _, p := range s.Artifacts.Packages.Sorted() {
		k := pkgKey(p)
		byID[p.ID()] = k
		out.Packages = append(out.Packages, k)
		if fo, ok := p.Metadata.(pkg.FileOwner); ok {
			files := append([]string{}, fo.OwnedFiles()...)
			sort.Strings(files)
			out.Owned[k] = append(out.Owned[k], files...)
		}
		for _, l := range p.Locations.ToSlice() {
			out.Evidence[k] = append(out.Evidence[k], l.RealPath+"<-"+l.AccessPath)
		}
		sort.Strings(out.Evidence[k])
	}
	sort.Strings(out.Packages)
	node := func(i artifact.Identifiable) string {
		switch v := i.(type) {
		case pkg.Package:
			return "pkg:" + pkgKey(v)
		case file.Coordinates:
			return "file:" + v.RealPath
		case file.Location:
			return "file:" + v.RealPath
		}
		if k, ok := byID[i.ID()]; ok {
			return "pkg:" + k
		}
		return fmt.Sprintf("%T", i)
	}
	for _, r := range s.Relationships {
		out.Relationships = append(out.Relationships, fmt.Sprintf("%s -%s-> %s", node(r.From), r.Type, node(r.To)))
	}
	sort.Strings(out.Relationships)
	if d := s.Artifacts.LinuxDistribution; d != nil {
		out.Distro = d.ID + " " + d.VersionID
	}
	return out
}

// Ours catalogs dir through rootfs (opened as an fd, as in production),
// with the root options production uses for the profile and the default
// budgets (scan.RootOptions). submounts are treated as mount points the
// resolver must not enter.
func Ours(ctx context.Context, dir, profile string, submounts ...string) (*sbom.SBOM, error) {
	root, err := rootfs.OpenPath(dir, scan.RootOptions(profile, protocol.Budgets{}.Effective(), submounts, 0))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return syft.CreateSBOM(ctx, rootfs.NewSource(root), scan.SyftConfig(profile, "difftest"))
}

// Stock catalogs dir with Syft's own directory source, rooted at dir
// (base path = dir, so absolute symlinks resolve inside it as they do in
// the container).
func Stock(ctx context.Context, dir, profile string) (*sbom.SBOM, error) {
	src, err := directorysource.New(directorysource.Config{Path: dir, Base: dir})
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	return syft.CreateSBOM(ctx, src, scan.SyftConfig(profile, "difftest"))
}

// Sentinel is a package a fixture must yield: it proves the fixture still
// exercises the cataloger it is there for (an empty or broken fixture
// would otherwise compare equal and pass).
type Sentinel struct {
	Type    string
	Name    string // "" means any package of Type
	Version string // "" means any version
	Min     int    // at least this many matches
}

// Sentinels per fixture and profile. The os_only profile runs only the
// OS database and binary catalogers.
var Sentinels = map[string]map[string][]Sentinel{
	"alpine":            {protocol.ProfileFull: {{Type: "apk", Min: 10}}, protocol.ProfileOSOnly: {{Type: "apk", Min: 10}}},
	"debian":            {protocol.ProfileFull: {{Type: "deb", Min: 50}}, protocol.ProfileOSOnly: {{Type: "deb", Min: 50}}},
	"ubi-minimal":       {protocol.ProfileFull: {{Type: "rpm", Min: 50}}, protocol.ProfileOSOnly: {{Type: "rpm", Min: 50}}},
	"distroless":        {protocol.ProfileFull: {{Type: "deb", Min: 3}}, protocol.ProfileOSOnly: {{Type: "deb", Min: 3}}},
	"static-go":         {protocol.ProfileFull: {{Type: "go-module", Name: "golang.org/x/text", Version: "v0.30.0", Min: 1}}, protocol.ProfileOSOnly: {{Type: "go-module", Name: "golang.org/x/text", Min: 1}}},
	"rust-auditable":    {protocol.ProfileFull: {{Type: "rust-crate", Name: "itoa", Min: 1}, {Type: "deb", Min: 3}}, protocol.ProfileOSOnly: {{Type: "rust-crate", Name: "itoa", Min: 1}}},
	"spring-boot":       {protocol.ProfileFull: {{Type: "java-archive", Name: "log4j-core", Version: "2.14.1", Min: 1}, {Type: "java-archive", Name: "spring-core", Min: 1}, {Type: "apk", Min: 10}}, protocol.ProfileOSOnly: {{Type: "apk", Min: 10}}},
	"python":            {protocol.ProfileFull: {{Type: "python", Min: 1}, {Type: "deb", Min: 50}}, protocol.ProfileOSOnly: {{Type: "deb", Min: 50}}},
	"node":              {protocol.ProfileFull: {{Type: "npm", Min: 100}, {Type: "apk", Min: 10}}, protocol.ProfileOSOnly: {{Type: "apk", Min: 10}}},
	"symlinked-apk-db":  {protocol.ProfileFull: {{Type: "apk", Min: 10}}, protocol.ProfileOSOnly: {{Type: "apk", Min: 10}}},
	"symlinked-dpkg-db": {protocol.ProfileFull: {{Type: "deb", Min: 50}}, protocol.ProfileOSOnly: {{Type: "deb", Min: 50}}},
}

// MissingSentinels lists the sentinels s does not satisfy.
func MissingSentinels(s *sbom.SBOM, want []Sentinel) []string {
	var missing []string
	for _, w := range want {
		n := 0
		for _, p := range s.Artifacts.Packages.Sorted() {
			if string(p.Type) == w.Type && (w.Name == "" || p.Name == w.Name) && (w.Version == "" || p.Version == w.Version) {
				n++
			}
		}
		if n < w.Min {
			missing = append(missing, fmt.Sprintf("%s %s@%s: %d, want at least %d", w.Type, w.Name, w.Version, n, w.Min))
		}
	}
	return missing
}

// Diff reports every difference between two summaries; excluded paths
// (under a mount the resolver skips) are tolerated in file lists.
func Diff(ours, stock Summary, excluded []string) []string {
	var d []string
	d = append(d, lineDiff("package", ours.Packages, stock.Packages)...)
	if ours.Distro != stock.Distro {
		d = append(d, fmt.Sprintf("distro: ours %q stock %q", ours.Distro, stock.Distro))
	}
	keep := func(lines []string) []string {
		var out []string
		for _, l := range lines {
			p := strings.SplitN(l, "<-", 2)[0]
			if !isExcluded(p, excluded) {
				out = append(out, l)
			}
		}
		return out
	}
	for _, k := range union(keys(ours.Owned), keys(stock.Owned)) {
		d = append(d, lineDiff("owned["+k+"]", keep(ours.Owned[k]), keep(stock.Owned[k]))...)
	}
	for _, k := range union(keys(ours.Evidence), keys(stock.Evidence)) {
		d = append(d, lineDiff("evidence["+k+"]", keep(ours.Evidence[k]), keep(stock.Evidence[k]))...)
	}
	keepRel := func(lines []string) []string {
		var out []string
		for _, l := range lines {
			drop := false
			for _, part := range strings.Split(l, " ") {
				if p, ok := strings.CutPrefix(part, "file:"); ok && isExcluded(p, excluded) {
					drop = true
				}
			}
			if !drop {
				out = append(out, l)
			}
		}
		return out
	}
	d = append(d, lineDiff("relationship", keepRel(ours.Relationships), keepRel(stock.Relationships))...)
	return d
}

func isExcluded(p string, excluded []string) bool {
	p = path.Clean("/" + p)
	for _, e := range excluded {
		if p == e || strings.HasPrefix(p, e+"/") {
			return true
		}
	}
	return false
}

func keys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range append(append([]string{}, a...), b...) {
		set[s] = true
	}
	out := keys(map[string][]string{})
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// lineDiff compares two sorted multisets of lines.
func lineDiff(what string, ours, stock []string) []string {
	count := map[string]int{}
	for _, l := range ours {
		count[l]++
	}
	for _, l := range stock {
		count[l]--
	}
	var out []string
	for l, n := range count {
		switch {
		case n > 0:
			out = append(out, fmt.Sprintf("%s only in ours (x%d): %s", what, n, l))
		case n < 0:
			out = append(out, fmt.Sprintf("%s only in stock (x%d): %s", what, -n, l))
		}
	}
	sort.Strings(out)
	return out
}

// Profiles compared.
var Profiles = []string{protocol.ProfileFull, protocol.ProfileOSOnly}
