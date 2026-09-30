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

// interpretedExts: an owned file with one of these extensions is
// interpreted source, bytecode or code another runtime loads, wherever it
// lives (design §5).
var interpretedExts = map[string]bool{
	".py": true, ".pyc": true, ".pyo": true, ".pyz": true,
	".pl": true, ".pm": true, ".rb": true,
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".wasm": true,
	".php": true, ".phar": true,
	".lua": true, ".luac": true, ".tcl": true, ".r": true,
	".sh": true, ".bash": true, ".zsh": true, ".ksh": true, ".csh": true, ".fish": true, ".awk": true, ".ps1": true,
	".jar": true, ".class": true, ".groovy": true, ".beam": true, ".ex": true, ".exs": true,
	".el": true, ".elc": true, ".scm": true, ".ss": true,
	".xsl": true, ".xslt": true,
	".dll": true,
}

// scopedInterpreted: extensions that mean interpreted code only under a
// given path component (".rules" is also udev's data format, ".go" also
// Go source): polkit's JavaScript rules, Guile's compiled objects.
var scopedInterpreted = map[string]string{".rules": "polkit-1", ".go": "guile"}

// shellSnippet: files a shell sources at login or start-up.
func shellSnippet(p string) bool {
	base := path.Base(p)
	switch {
	case p == "/etc/profile", p == "/etc/bash.bashrc", under(p, "/etc/profile.d") && p != "/etc/profile.d":
		return true
	case path.Dir(p) == "/etc/skel" && strings.HasPrefix(base, "."):
		return true
	}
	return strings.HasSuffix(base, ".bashrc") || strings.HasSuffix(base, ".profile") || strings.HasSuffix(base, ".zshrc")
}

// buildTimeExts are only read by compilers and linkers, never at run time.
var buildTimeExts = map[string]bool{".a": true, ".la": true, ".pc": true, ".h": true}

// libRoots, and loadableDirs: a non-executable, non-*.so* file under one of
// these can be loaded or interpreted by something else (design §5), unless
// it is known data (below).
var (
	libRoots     = []string{"/lib", "/lib64", "/lib32", "/usr/lib", "/usr/lib64", "/usr/lib32", "/usr/libx32", "/usr/local/lib"}
	shareRoots   = []string{"/usr/share", "/usr/local/share"}
	loadableDirs = append(append([]string{"/usr/libexec"}, libRoots...), shareRoots...)
)

// shareNotCode: subtrees of a share root that are documentation,
// packaging metadata or pure data, never loaded as code. Each entry names
// known data, never a whole tree that could also hold scripts.
var shareNotCode = []string{
	// documentation
	"doc", "man", "info", "locale", "licenses",
	// Debian packaging metadata
	"lintian", "doc-base", "common-licenses", "menu",
	"bug/*/control", "bug/*/presubj", // not bug/*/script, which reportbug runs
	// pure data
	"zoneinfo", "terminfo", "mime", "xml", "icons", "pixmaps", "applications", "metainfo",
	"pkgconfig", "polkit-1/actions", "dbus-1",
	"debianutils/shells.d", "binfmts", // lists, not code
}

// libNotCode: subtrees of a lib root that are data or host configuration
// read by the system, not code a process loads (known data only: udev and
// systemd also ship sourced helpers, generators and the like).
var libNotCode = []string{
	// pure data
	"terminfo", "locale",
	// host configuration
	"tmpfiles.d", "sysctl.d", "sysusers.d", "modprobe.d", "modules-load.d", "binfmt.d", "environment.d",
	"udev/rules.d", "udev/hwdb.d", "udev/hwdb.bin",
	"systemd/system", "systemd/user", "systemd/network", "systemd/*-preset", "systemd/catalog",
	"kernel/install.conf",
	"os-release", "mime/packages",
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// underPattern: p is dir or below it, where dir may contain "*" path
// components (one component each).
func underPattern(p, dir string) bool {
	if !strings.Contains(dir, "*") {
		return under(p, dir)
	}
	want := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	got := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(got) < len(want) {
		return false
	}
	for i, w := range want {
		if ok, _ := path.Match(w, got[i]); !ok {
			return false
		}
	}
	return true
}

func underAny(p string, roots, subs []string) bool {
	for _, r := range roots {
		for _, sub := range subs {
			if underPattern(p, r+"/"+sub) {
				return true
			}
		}
	}
	return false
}

func hasComponent(p, name string) bool {
	return strings.Contains(p+"/", "/"+name+"/")
}

// gconvConfig: glibc's gconv module lists and cache (gconv-modules,
// gconv-modules.cache, gconv-modules.d/*.conf). The gconv modules
// themselves are *.so, executable-looking, and captured when mapped.
func gconvConfig(p string) bool {
	dir, base := path.Dir(p), path.Base(p)
	switch {
	case path.Base(dir) == "gconv" && (base == "gconv-modules" || base == "gconv-modules.cache"):
		return true
	case path.Base(dir) == "gconv-modules.d" && strings.HasSuffix(base, ".conf"):
		return true
	}
	return false
}

// Interpreted reports whether an owned regular file at p (real path) with
// mode bits makes its package interpreted_content: an interpreter,
// bytecode or foreign-runtime extension anywhere (some only under their
// runtime's directory); a shell start-up snippet under /etc; or a
// non-executable, non-*.so* file under a loadable directory that is not
// known documentation, packaging metadata, data, host configuration, gconv
// configuration or a build-time file. Such a package can be used without
// any exec or mmap the runtime capture would see, so it is never
// installed_not_observed.
func Interpreted(p string, mode uint32) bool {
	ext := strings.ToLower(path.Ext(p))
	if interpretedExts[ext] {
		return true
	}
	if dir, ok := scopedInterpreted[ext]; ok && hasComponent(path.Dir(p), dir) {
		return true
	}
	if shellSnippet(p) {
		return true
	}
	if mode&0o111 != 0 || rootfs.IsSharedObjectName(p) {
		return false
	}
	if buildTimeExts[ext] || gconvConfig(p) || underAny(p, shareRoots, shareNotCode) || underAny(p, libRoots, libNotCode) {
		return false
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

// validPath is what the broker and Controller accept: absolute, clean,
// bounded, valid UTF-8, no control characters.
func validPath(p string) bool {
	return protocol.ValidPath(p)
}

func validField(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !protocol.HasControl(s)
}

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

// Dropped: p, or any component on its way, was left out as runtime drift.
// A symlink anywhere in the path counts (a /bin link replaced after start
// takes every /bin/... file with it), and so does p with its directory
// resolved (a file under a symlinked directory is recorded by its real
// path).
func (a resolverAdapter) Dropped(p string) bool {
	for q := p; q != "/" && q != "."; q = path.Dir(q) {
		if a.root.Dropped(q) {
			return true
		}
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
		v = strings.TrimSpace(v)
		// Over-long licenses are dropped, never cut: the broker would
		// otherwise truncate them silently.
		if v == "" || seen[v] || !validField(v, protocol.MaxLicenseLen) {
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
	if c.Name == "" || !validField(c.Name, protocol.MaxNameLen) || !validField(c.Version, protocol.MaxVersionLen) ||
		!validField(c.Type, protocol.MaxShortLen) {
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
