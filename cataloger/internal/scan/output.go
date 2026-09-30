package scan

import (
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/anchore/syft/syft/pkg"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/rootfs"
)

// interpretedExts: owned files with these extensions are interpreted or
// bytecode (design §5).
var interpretedExts = map[string]bool{
	".py": true, ".pyc": true, ".pl": true, ".pm": true, ".rb": true, ".js": true, ".mjs": true,
	".cjs": true, ".php": true, ".lua": true, ".tcl": true, ".sh": true, ".bash": true,
	".jar": true, ".class": true, ".el": true,
}

// loadableDirs: a non-executable, non-*.so* file under one of these can be
// loaded or interpreted by something else (design §5), except under the
// share subtrees in docShare.
var loadableDirs = []string{"/lib", "/usr/lib", "/usr/local/lib", "/usr/libexec", "/usr/share", "/usr/local/share"}

var docShare = []string{"/usr/share/doc", "/usr/share/man", "/usr/share/info", "/usr/share/locale", "/usr/share/licenses",
	"/usr/local/share/doc", "/usr/local/share/man", "/usr/local/share/info", "/usr/local/share/locale", "/usr/local/share/licenses"}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// Interpreted reports whether an owned regular file at p (real path) with
// mode bits makes its package interpreted_content.
func Interpreted(p string, mode uint32) bool {
	if interpretedExts[strings.ToLower(path.Ext(p))] {
		return true
	}
	if mode&0o111 != 0 || rootfs.IsSharedObjectName(p) {
		return false
	}
	for _, d := range docShare {
		if under(p, d) {
			return false
		}
	}
	for _, d := range loadableDirs {
		if under(p, d) {
			return true
		}
	}
	return false
}

// ExecutableLooking: any execute bit, or *.so / *.so.*.
func ExecutableLooking(p string, mode uint32) bool {
	return mode&0o111 != 0 || rootfs.IsSharedObjectName(p)
}

// validPath is what the broker and Controller accept.
func validPath(p string) bool {
	return len(p) > 0 && len(p) <= protocol.MaxPathLen && p[0] == '/' && path.Clean(p) == p && utf8.ValidString(p)
}

func validField(s string, max int) bool { return len(s) <= max && utf8.ValidString(s) }

// osTypes are package-manager types reported as class os-pkgs.
var osTypes = map[pkg.Type]bool{pkg.ApkPkg: true, pkg.DebPkg: true, pkg.RpmPkg: true, pkg.AlpmPkg: true, pkg.PortagePkg: true}

// ownedPaths is what the package claims: its database file list when it
// has one (dpkg, apk, rpm, Python RECORD, ...), else its evidence
// locations (a Go or Rust binary, a jar). Evidence of a package that has a
// file list is its database (lib/apk/db/installed, ...), which it does
// not own as content.
func ownedPaths(p pkg.Package) []string {
	if fo, ok := p.Metadata.(pkg.FileOwner); ok {
		if files := fo.OwnedFiles(); len(files) > 0 {
			return files
		}
	}
	var out []string
	for _, l := range p.Locations.ToSlice() {
		out = append(out, l.RealPath)
	}
	return out
}

// FileResolution is the subset of rootfs.Resolver the mapping needs.
type FileResolution interface {
	Lookup(p string) (realPath string, mode uint32, regular bool, ok bool)
	Dropped(p string) bool
}

// resolverAdapter adapts rootfs to FileResolution.
type resolverAdapter struct {
	res  *rootfs.Resolver
	root *rootfs.Root
}

func (a resolverAdapter) Lookup(p string) (string, uint32, bool, bool) {
	real, md, ok := a.res.Lookup(p)
	if !ok {
		return "", 0, false, false
	}
	return real, uint32(md.Mode().Perm()), md.Mode().IsRegular(), true
}

// Dropped: p itself, or p with its directory resolved (a file under a
// symlinked directory is recorded by its real path).
func (a resolverAdapter) Dropped(p string) bool {
	if a.root.Dropped(p) {
		return true
	}
	if dir, _, _, ok := a.Lookup(path.Dir(p)); ok {
		return a.root.Dropped(path.Join(dir, path.Base(p)))
	}
	return false
}

// PackageFiles computes a package's output paths and flags from its
// complete owned-file list: interpreted_content from every owned regular
// file, then the executable-looking real paths, drift-dropped files
// flagged, capped at maxPaths.
func PackageFiles(owned []string, fr FileResolution, maxPaths int) (paths []string, truncated, interpreted bool) {
	set := map[string]struct{}{}
	for _, o := range owned {
		if o == "" {
			continue
		}
		o = path.Clean("/" + o)
		real, mode, regular, ok := fr.Lookup(o)
		if !ok {
			if fr.Dropped(o) {
				truncated = true
			}
			continue
		}
		if !regular {
			continue
		}
		if Interpreted(real, mode) {
			interpreted = true
		}
		if !ExecutableLooking(real, mode) {
			continue
		}
		if !validPath(real) {
			truncated = true
			continue
		}
		set[real] = struct{}{}
	}
	paths = make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if maxPaths > 0 && len(paths) > maxPaths {
		paths, truncated = paths[:maxPaths], true
	}
	return paths, truncated, interpreted
}

// srcOf returns the source package of OS packages.
func srcOf(p pkg.Package) (string, string) {
	switch m := p.Metadata.(type) {
	case pkg.DpkgDBEntry:
		name, ver := m.Source, m.SourceVersion
		if name == "" {
			return "", ""
		}
		if ver == "" {
			ver = p.Version
		}
		return name, ver
	case pkg.ApkDBEntry:
		if m.OriginPackage == "" {
			return "", ""
		}
		return m.OriginPackage, p.Version
	case pkg.RpmDBEntry:
		return splitSourceRPM(m.SourceRpm)
	}
	return "", ""
}

// splitSourceRPM: "glibc-2.34-100.el9.src.rpm" -> ("glibc", "2.34-100.el9").
func splitSourceRPM(s string) (string, string) {
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".rpm"), ".src")
	s = strings.TrimSuffix(s, ".nosrc")
	i := strings.LastIndex(s, "-")
	if i <= 0 {
		return "", ""
	}
	j := strings.LastIndex(s[:i], "-")
	if j <= 0 {
		return "", ""
	}
	return s[:j], s[j+1:]
}

func licensesOf(p pkg.Package) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range p.Licenses.ToSlice() {
		v := l.SPDXExpression
		if v == "" {
			v = l.Value
		}
		v = protocol.Truncate(strings.TrimSpace(v), protocol.MaxLicenseLen)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) == protocol.MaxLicenses {
			break
		}
	}
	return out
}

// Component maps one Syft package; ok is false when it fails the broker's
// field limits (it is then dropped and counted).
func Component(p pkg.Package, fr FileResolution, maxPaths int) (protocol.Component, bool) {
	c := protocol.Component{
		Name:     p.Name,
		Version:  p.Version,
		PURL:     p.PURL,
		Type:     string(p.Type),
		Class:    "lang-pkgs",
		Licenses: licensesOf(p),
	}
	if osTypes[p.Type] {
		c.Class = "os-pkgs"
	}
	if c.Name == "" || !validField(c.Name, protocol.MaxNameLen) || !validField(c.Version, protocol.MaxVersionLen) {
		return c, false
	}
	if !validField(c.PURL, protocol.MaxPURLLen) {
		c.PURL = ""
	}
	c.SrcName, c.SrcVersion = srcOf(p)
	if !validField(c.SrcName, protocol.MaxNameLen) || !validField(c.SrcVersion, protocol.MaxVersionLen) {
		c.SrcName, c.SrcVersion = "", ""
	}
	c.FilePaths, c.FilesTruncated, c.InterpretedContent = PackageFiles(ownedPaths(p), fr, maxPaths)
	return c, true
}
