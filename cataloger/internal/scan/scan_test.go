package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/anchore/syft/syft"
	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/rootfs"
)

type apkPkg struct {
	name, version string
	files         map[string]os.FileMode // path (no leading /) -> mode; 0 = not created on disk
}

// apkRoot writes a minimal Alpine root: os-release and an apk database
// listing each package's files, and creates the files.
func apkRoot(t *testing.T, pkgs []apkPkg) string {
	t.Helper()
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"), 0o644))
	var db strings.Builder
	for _, p := range pkgs {
		fmt.Fprintf(&db, "C:Q1abc=\nP:%s\nV:%s\nA:x86_64\nS:1\nI:1\nT:test\nU:https://example.com\nL:MIT\no:%s-src\nm:t\nt:1\nc:abc\n", p.name, p.version, p.name)
		dirs := map[string][]string{}
		for f, mode := range p.files {
			dirs[filepath.Dir(f)] = append(dirs[filepath.Dir(f)], filepath.Base(f))
			if mode != 0 {
				must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(f)), 0o755))
				must(t, os.WriteFile(filepath.Join(root, f), []byte("\x7fELF..."), mode))
			}
		}
		for d, names := range dirs {
			fmt.Fprintf(&db, "F:%s\n", d)
			for _, n := range names {
				fmt.Fprintf(&db, "R:%s\n", n)
			}
		}
		db.WriteString("\n")
	}
	must(t, os.WriteFile(filepath.Join(root, "lib/apk/db/installed"), []byte(db.String()), 0o644))
	return root
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func opts() Options {
	return Options{Profile: protocol.ProfileFull, Budgets: protocol.Budgets{}.Effective(), CapsModel: "i", Version: "test"}
}

func runDir(t *testing.T, dir string, o Options) *protocol.Response {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	must(t, err)
	done := make(chan *protocol.Response, 1)
	go func() { done <- Run(context.Background(), fd, o) }()
	select {
	case r := <-done:
		return r
	case <-time.After(60 * time.Second):
		t.Fatal("scan hung")
		return nil
	}
}

func comp(t *testing.T, r *protocol.Response, name string) protocol.Component {
	t.Helper()
	for _, c := range r.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("component %s not found in %+v", name, r.Components)
	return protocol.Component{}
}

func TestScanApkRoot(t *testing.T) {
	root := apkRoot(t, []apkPkg{
		{"busybox", "1.36.1-r29", map[string]os.FileMode{"bin/busybox": 0o755, "etc/securetty": 0o644}},
		{"musl", "1.2.5-r0", map[string]os.FileMode{"lib/ld-musl-x86_64.so.1": 0o755, "lib/libc.musl-x86_64.so.1": 0o644}},
		{"py3-foo", "1.0-r0", map[string]os.FileMode{"usr/lib/python3.12/foo/__init__.py": 0o644}},
		{"data-only", "1.0-r0", map[string]os.FileMode{"usr/share/foo/table.dat": 0o644, "usr/share/doc/foo/README": 0o644}},
		{"docs-only", "1.0-r0", map[string]os.FileMode{"usr/share/doc/bar/README": 0o644, "usr/share/man/man1/bar.1": 0o644}},
	})
	must(t, os.Symlink("busybox", filepath.Join(root, "bin/sh")))
	r := runDir(t, root, opts())
	if r.Status != protocol.StatusOK || r.Completeness != protocol.CompletenessFull {
		t.Fatalf("status %s/%s completeness %s partial %v: %s", r.Status, r.Reason, r.Completeness, r.PartialReasons, r.Message)
	}
	if r.OS == nil || r.OS.Family != "alpine" || r.OS.Name != "3.20.3" {
		t.Errorf("os = %+v", r.OS)
	}
	if r.Components[0].Type != "operating-system" || r.Components[0].Name != "alpine" || r.Components[0].Version != "3.20.3" {
		t.Errorf("first component %+v", r.Components[0])
	}
	bb := comp(t, r, "busybox")
	if bb.Type != "apk" || bb.Class != "os-pkgs" || bb.SrcName != "busybox-src" || bb.SrcVersion != "1.36.1-r29" ||
		!strings.HasPrefix(bb.PURL, "pkg:apk/alpine/busybox@1.36.1-r29") || len(bb.Licenses) != 1 {
		t.Errorf("busybox %+v", bb)
	}
	if fmt.Sprint(bb.FilePaths) != "[/bin/busybox]" || bb.InterpretedContent || bb.FilesTruncated {
		t.Errorf("busybox files %v interp %v trunc %v (etc/securetty is neither executable nor loadable)", bb.FilePaths, bb.InterpretedContent, bb.FilesTruncated)
	}
	if m := comp(t, r, "musl"); fmt.Sprint(m.FilePaths) != "[/lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1]" || m.InterpretedContent {
		t.Errorf("musl %+v (a *.so* file is executable-looking, not interpreted)", m)
	}
	if p := comp(t, r, "py3-foo"); !p.InterpretedContent || len(p.FilePaths) != 0 {
		t.Errorf("py3-foo %+v", p)
	}
	if d := comp(t, r, "data-only"); !d.InterpretedContent {
		t.Errorf("non-executable file under /usr/share must be interpreted_content: %+v", d)
	}
	if d := comp(t, r, "docs-only"); d.InterpretedContent {
		t.Errorf("share/doc and share/man are excluded: %+v", d)
	}
	if r.Stats.Files == 0 || r.Stats.SyftVersion == "" || r.Stats.CapsModel != "i" {
		t.Errorf("stats %+v", r.Stats)
	}
}

func TestFIFOAtApkDatabaseDoesNotHang(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\n"), 0o644))
	must(t, unix.Mkfifo(filepath.Join(root, "lib/apk/db/installed"), 0o644))
	r := runDir(t, root, opts())
	if r.Reason != protocol.ReasonNoPackagesFound {
		t.Fatalf("got %s/%s: %s", r.Status, r.Reason, r.Message)
	}
}

func TestEmptyReadableRootIsNoPackagesFound(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
	r := runDir(t, root, opts())
	if r.Status != protocol.StatusFailed || r.Reason != protocol.ReasonNoPackagesFound || len(r.Components) != 0 {
		t.Fatalf("got %+v", r)
	}
}

// no_packages_found is terminal at the Controller only with completeness
// "full" and no partial reasons (PROTOCOL.md §4.4): a clean root gives
// exactly that, and anything that could have hidden a package does not.
func TestNoPackagesFoundIsCleanOnlyWhenComplete(t *testing.T) {
	clean := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(clean, "etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(clean, "etc/os-release"), []byte("ID=alpine\n"), 0o644))
	r := runDir(t, clean, opts())
	if r.Reason != protocol.ReasonNoPackagesFound || r.Completeness != protocol.CompletenessFull || len(r.PartialReasons) != 0 {
		t.Fatalf("clean root: reason %s completeness %q partial %v", r.Reason, r.Completeness, r.PartialReasons)
	}
	// Model (ii) on a fully readable root is still clean.
	o := opts()
	o.CapsModel = "ii"
	if r := runDir(t, clean, o); r.Reason != protocol.ReasonNoPackagesFound || r.Completeness != protocol.CompletenessFull || len(r.PartialReasons) != 0 {
		t.Errorf("model (ii), readable root: %q %v", r.Completeness, r.PartialReasons)
	}

	// The only binary changed after container start.
	drift := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(drift, "usr/bin"), 0o755))
	o = opts()
	o.ContainerStartNanos = time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	must(t, os.WriteFile(filepath.Join(drift, "usr/bin/app"), []byte("\x7fELF"), 0o755))
	if r := runDir(t, drift, o); r.Reason != protocol.ReasonNoPackagesFound || r.Completeness != protocol.CompletenessPartial ||
		!has(r.PartialReasons, protocol.PartialCtimeDropped) {
		t.Errorf("runtime drift: %s %v", r.Reason, r.PartialReasons)
	}

	// A tree deeper than the depth cap.
	deep := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(deep, "a/b/c/d"), 0o755))
	o = opts()
	o.Budgets.MaxDepth = 2
	if r := runDir(t, deep, o); r.Reason != protocol.ReasonNoPackagesFound || !has(r.PartialReasons, protocol.PartialDepthLimited) {
		t.Errorf("depth cap: %s %v", r.Reason, r.PartialReasons)
	}

	// The os_only profile skips the language catalogers.
	o = opts()
	o.Profile = protocol.ProfileOSOnly
	if r := runDir(t, clean, o); r.Reason != protocol.ReasonNoPackagesFound || r.Completeness != protocol.CompletenessOSOnly {
		t.Errorf("os_only: %s %q", r.Reason, r.Completeness)
	}
}

// Unreadable entries and zero packages: under model (i) (DAC bypassed)
// only an LSM can have refused, so lsm_denied; under model (ii) it is a
// plain DAC refusal and the scan is just incomplete, so a partial
// no_packages_found the Controller retries.
func TestZeroPackagesWithUnreadableEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 directory")
	}
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\n"), 0o644))
	must(t, os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755))
	must(t, os.Chmod(filepath.Join(root, "lib/apk"), 0o000))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "lib/apk"), 0o755) })

	o := opts()
	o.CapsModel = "ii"
	r := runDir(t, root, o)
	if r.Reason != protocol.ReasonNoPackagesFound || r.Completeness != protocol.CompletenessPartial ||
		!has(r.PartialReasons, protocol.PartialEACCES) || !has(r.PartialReasons, protocol.PartialNoDACReadSearch) {
		t.Errorf("model (ii): %s %q %v", r.Reason, r.Completeness, r.PartialReasons)
	}
	o.CapsModel = "i"
	if r := runDir(t, root, o); r.Reason != protocol.ReasonLSMDenied {
		t.Errorf("model (i): %s", r.Reason)
	}
}

func TestUnreadableOSReleaseIsLSMDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	root := apkRoot(t, []apkPkg{{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755}}})
	must(t, os.Chmod(filepath.Join(root, "etc/os-release"), 0o000))
	r := runDir(t, root, opts())
	if r.Reason != protocol.ReasonLSMDenied {
		t.Fatalf("got %s/%s: %s", r.Status, r.Reason, r.Message)
	}
}

func TestCtimeDroppedFileTruncatesItsPackage(t *testing.T) {
	root := apkRoot(t, []apkPkg{
		{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755, "bin/other": 0o755}},
		{"zlib", "1.3", map[string]os.FileMode{"lib/libz.so.1": 0o755}},
	})
	o := opts()
	o.ContainerStartNanos = time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	// Runtime drift: a package file rewritten, and a new binary.
	must(t, os.WriteFile(filepath.Join(root, "bin/other"), []byte("\x7fELF changed"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "bin/dropped-in"), []byte("\x7fELF"), 0o755))
	r := runDir(t, root, o)
	if r.Status != protocol.StatusOK || r.Completeness != protocol.CompletenessPartial {
		t.Fatalf("got %s %s %v", r.Status, r.Completeness, r.PartialReasons)
	}
	bb := comp(t, r, "busybox")
	if !bb.FilesTruncated || fmt.Sprint(bb.FilePaths) != "[/bin/busybox]" {
		t.Errorf("busybox %+v", bb)
	}
	if z := comp(t, r, "zlib"); z.FilesTruncated {
		t.Errorf("zlib untouched but truncated")
	}
	if !has(r.PartialReasons, protocol.PartialCtimeDropped) || !has(r.PartialReasons, protocol.PartialFilesTruncated) {
		t.Errorf("partial reasons %v", r.PartialReasons)
	}
	for _, c := range r.Components {
		for _, p := range c.FilePaths {
			if p == "/bin/dropped-in" || p == "/bin/other" {
				t.Errorf("drift credited to %s: %s", c.Name, p)
			}
		}
	}
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// writeLate writes files (path -> content, mode) into root after the
// container start it returns, so their ctime is later.
func writeLate(t *testing.T, root string, files map[string]lateFile) int64 {
	t.Helper()
	start := time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	for p, f := range files {
		must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755))
		must(t, os.WriteFile(filepath.Join(root, p), []byte(f.content), f.mode))
		must(t, os.Chmod(filepath.Join(root, p), f.mode))
	}
	return start
}

type lateFile struct {
	content string
	mode    os.FileMode
}

// runtimeData is what workloads on dev write after start (logs, Python
// bytecode caches, pid and lock files, migrations extracted to /tmp,
// Laravel's compiled views and bootstrap cache, the latter with a stray
// execute bit): none of it is package evidence.
var runtimeData = map[string]lateFile{
	"var/log/app.log": {"started\n", 0o644},
	"tmp/cron.log":    {"{\"message\":\"tick\"}\n", 0o644},
	"usr/local/lib/python3.11/__pycache__/base64.cpython-311.pyc":          {"\xa7\r\r\n\x00\x00\x00\x00binary bytecode\x00\x01", 0o644},
	"usr/local/lib/python3.11/encodings/__pycache__/utf_8.cpython-311.pyc": {"\xa7\r\r\n\x00\x00\x00\x00\xe3\x00", 0o644},
	"run/app.pid":                              {"1\n", 0o644},
	"tmp/ddappsec_1.3.1_82.82.lock":            {"", 0o744},
	"tmp/migrations-1123293262/0001.up.sql":    {"CREATE TABLE t (id int);\n", 0o600},
	"app/bootstrap/cache/packages.php":         {"<?php return array ();\n", 0o755},
	"app/storage/framework/views/00f1aadc.php": {"<?php echo 1; ?>\n", 0o644},
	"home/app/.cache/pip/http/0/1/abcdef":      {"\x00\x01cache", 0o600},
}

func TestRuntimeDataKeepsCompletenessFull(t *testing.T) {
	root := apkRoot(t, []apkPkg{{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755}}})
	o := opts()
	o.ContainerStartNanos = writeLate(t, root, runtimeData)
	r := runDir(t, root, o)
	if r.Status != protocol.StatusOK || r.Completeness != protocol.CompletenessFull || len(r.PartialReasons) != 0 {
		t.Fatalf("got %s %s %v (sample %v)", r.Status, r.Completeness, r.PartialReasons, r.Stats.CtimeDroppedSample)
	}
	n := int64(len(runtimeData))
	if r.Stats.CtimeDropped != n || r.Stats.CtimeDroppedData != n || r.Stats.CtimeDroppedEvidence != 0 {
		t.Errorf("stats dropped %d evidence %d data %d, want %d data", r.Stats.CtimeDropped,
			r.Stats.CtimeDroppedEvidence, r.Stats.CtimeDroppedData, n)
	}
	if len(r.Stats.CtimeDroppedSample) != len(runtimeData) || !slices.IsSorted(r.Stats.CtimeDroppedSample) {
		t.Errorf("sample %v", r.Stats.CtimeDroppedSample)
	}
	if bb := comp(t, r, "busybox"); bb.FilesTruncated {
		t.Errorf("busybox truncated by unrelated runtime data")
	}
}

// Any runtime change that could have been package evidence the SBOM now
// misses keeps it partial: a replaced or added binary (by execute bit or
// ELF content), a shared object, a jar, language package metadata and a
// package database, each on its own.
func TestPossibleEvidenceMakesItPartial(t *testing.T) {
	cases := map[string]lateFile{
		"usr/local/bin/app":      {"\x7fELF\x02\x01\x01", 0o755},   // replaced executable
		"app/server":             {"\x7fELF\x02\x01\x01", 0o644},   // ELF without an execute bit (MIME)
		"usr/local/bin/wrapper":  {"\x00\x01\x02 not text", 0o755}, // unrecognised binary, execute bit
		"usr/lib/libfoo.so.1":    {"\x00\x01\x02 not text", 0o644}, // *.so*
		"app/lib/guava-33.0.jar": {"PK\x03\x04", 0o644},            // jar (glob)
		"app/app.war":            {"PK\x03\x04", 0o644},            // war (glob)
		"usr/lib/python3.12/site-packages/requests-2.32.3.dist-info/METADATA": {"Name: requests\nVersion: 2.32.3\n", 0o644},
		"app/node_modules/left-pad/package.json":                              {"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}", 0o644},
		"usr/local/lib/ruby/gems/3.3.0/specifications/rack-3.0.gemspec":       {"Gem::Specification.new", 0o644},
		"var/www/vendor/composer/installed.json":                              {"{\"packages\":[]}", 0o644},
		"usr/share/java/release":                                              {"JAVA_VERSION=\"21\"\n", 0o644},
	}
	for p, f := range cases {
		t.Run(p, func(t *testing.T) {
			root := apkRoot(t, []apkPkg{{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755}}})
			o := opts()
			files := map[string]lateFile{p: f}
			for k, v := range runtimeData {
				files[k] = v
			}
			o.ContainerStartNanos = writeLate(t, root, files)
			r := runDir(t, root, o)
			if r.Completeness != protocol.CompletenessPartial || !has(r.PartialReasons, protocol.PartialCtimeDropped) {
				t.Fatalf("got %s %v", r.Completeness, r.PartialReasons)
			}
			if r.Stats.CtimeDroppedEvidence != 1 || r.Stats.CtimeDroppedData != int64(len(runtimeData)) {
				t.Errorf("evidence %d data %d", r.Stats.CtimeDroppedEvidence, r.Stats.CtimeDroppedData)
			}
			if len(r.Stats.CtimeDroppedSample) == 0 || r.Stats.CtimeDroppedSample[0] != "/"+p {
				t.Errorf("evidence not first in the sample: %v", r.Stats.CtimeDroppedSample)
			}
		})
	}

	// The package database itself, rewritten at runtime.
	root := apkRoot(t, []apkPkg{{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755}}})
	db, err := os.ReadFile(filepath.Join(root, "lib/apk/db/installed"))
	must(t, err)
	o := opts()
	o.ContainerStartNanos = writeLate(t, root, map[string]lateFile{"lib/apk/db/installed": {string(db), 0o644}})
	r := runDir(t, root, o)
	if r.Completeness != protocol.CompletenessPartial || !has(r.PartialReasons, protocol.PartialCtimeDropped) || r.Stats.CtimeDroppedEvidence != 1 {
		t.Errorf("package database: %s %s %v", r.Status, r.Completeness, r.PartialReasons)
	}
}

func TestDriftSampleIsBounded(t *testing.T) {
	root := apkRoot(t, []apkPkg{{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755}}})
	files := map[string]lateFile{}
	for i := range 60 {
		files[fmt.Sprintf("var/cache/app/%02d.cache", i)] = lateFile{"x", 0o644}
	}
	long := strings.Repeat("d", 200) + "/" + strings.Repeat("e", 200) + "/" + strings.Repeat("é", 100) + ".log"
	files[long] = lateFile{"x", 0o644}
	files["usr/local/bin/zz-new"] = lateFile{"\x7fELF", 0o755}
	o := opts()
	o.ContainerStartNanos = writeLate(t, root, files)
	r := runDir(t, root, o)
	s := r.Stats.CtimeDroppedSample
	if len(s) != protocol.MaxDriftSample || s[0] != "/usr/local/bin/zz-new" {
		t.Fatalf("sample (%d) %v", len(s), s)
	}
	if r.Stats.CtimeDropped != 62 || r.Stats.CtimeDroppedEvidence != 1 || r.Stats.CtimeDroppedData != 61 {
		t.Errorf("stats %+v", r.Stats)
	}
	for _, p := range s {
		if len(p) > protocol.MaxDriftSamplePathLen || !utf8.ValidString(p) {
			t.Errorf("sample path %d bytes: %q", len(p), p)
		}
	}
	// The long path sorts before var/: it is in the sample, cut.
	if !slices.ContainsFunc(s, func(p string) bool { return strings.HasPrefix(p, "/ddd") && len(p) <= protocol.MaxDriftSamplePathLen }) {
		t.Errorf("long path missing or uncut: %v", s)
	}
	if b, _ := json.Marshal(r.Stats); len(b) > 16*1024 {
		t.Errorf("stats are %d bytes, over the broker's 16 KiB", len(b))
	}
}

// The drift rule tests dropped files against what the pinned Syft's
// catalogers asked the resolver for. No cataloger may list every file
// (that would make every runtime write evidence again), except the Nix
// store cataloger, recorded as its store globs. A Syft bump that adds
// another such cataloger fails here.
func TestCatalogerQueriesAreBounded(t *testing.T) {
	for _, prof := range []string{protocol.ProfileFull, protocol.ProfileOSOnly} {
		root := apkRoot(t, []apkPkg{{"busybox", "1.0", map[string]os.FileMode{"bin/busybox": 0o755}}})
		fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		must(t, err)
		r, err := rootfs.Open(fd, RootOptions(prof, protocol.Budgets{}.Effective(), nil, 0))
		must(t, err)
		src := rootfs.NewSource(r)
		if _, err := syft.CreateSBOM(context.Background(), src, SyftConfig(prof, "test")); err != nil {
			t.Fatal(err)
		}
		globs, _, mimes, all := src.Resolver().Queries()
		_ = r.Close()
		if all {
			t.Errorf("%s: a cataloger listed every file", prof)
		}
		if !slices.Contains(mimes, "application/x-executable") || !slices.Contains(globs, "**/lib/apk/db/installed") {
			t.Errorf("%s: globs %v mimes %v", prof, globs, mimes)
		}
		if prof == protocol.ProfileFull {
			for _, g := range []string{"**/*.jar", "**/*dist-info/METADATA", "**/package.json", "**/nix/store/*"} {
				if !slices.Contains(globs, g) {
					t.Errorf("full: %s not asked for", g)
				}
			}
		}
	}
}

func TestSamplePath(t *testing.T) {
	for in, want := range map[string]string{
		"/var/log/a.log":               "/var/log/a.log",
		"/tmp/a\nb\x7f":                "/tmp/a?b?",
		"/tmp/\xff\xfe":                "/tmp/?",
		"/" + strings.Repeat("é", 200): "/" + strings.Repeat("é", 127),
	} {
		if got := SamplePath(in); got != want {
			t.Errorf("SamplePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTooManyExecutablePathsTruncates(t *testing.T) {
	files := map[string]os.FileMode{}
	for i := range 40 {
		files[fmt.Sprintf("usr/bin/tool%02d", i)] = 0o755
	}
	root := apkRoot(t, []apkPkg{{"big", "1.0", files}})
	o := opts()
	o.Budgets.MaxPathsPerPackage = 10
	r := runDir(t, root, o)
	b := comp(t, r, "big")
	if len(b.FilePaths) != 10 || !b.FilesTruncated || r.Completeness != protocol.CompletenessPartial {
		t.Fatalf("big: %d paths, truncated %v, completeness %s", len(b.FilePaths), b.FilesTruncated, r.Completeness)
	}
}

func TestBudgets(t *testing.T) {
	var pkgs []apkPkg
	for i := range 30 {
		pkgs = append(pkgs, apkPkg{fmt.Sprintf("p%02d", i), "1.0", map[string]os.FileMode{fmt.Sprintf("usr/bin/p%02d", i): 0o755}})
	}
	root := apkRoot(t, pkgs)

	o := opts()
	o.Budgets.MaxComponents = 10
	if r := runDir(t, root, o); r.Reason != protocol.ReasonTooManyComponents {
		t.Errorf("component budget: %s/%s", r.Status, r.Reason)
	}
	o = opts()
	o.Budgets.MaxFiles = 20
	if r := runDir(t, root, o); r.Reason != protocol.ReasonTooManyFiles {
		t.Errorf("file budget: %s/%s", r.Status, r.Reason)
	}
	// os_only indexes up to the budget, system directories first.
	o.Profile = protocol.ProfileOSOnly
	r := runDir(t, root, o)
	if r.Status != protocol.StatusOK || r.Completeness != protocol.CompletenessOSOnly || !has(r.PartialReasons, protocol.PartialFileBudget) {
		t.Errorf("os_only under budget: %s/%s %s %v", r.Status, r.Reason, r.Completeness, r.PartialReasons)
	}
}

func TestResponseFitsByDroppingPaths(t *testing.T) {
	r := protocol.Failed(nil, "", "")
	r.Status, r.Reason, r.Completeness = protocol.StatusOK, "", protocol.CompletenessFull
	for i := range 50 {
		c := protocol.Component{Name: fmt.Sprintf("p%d", i), Version: "1"}
		for j := range 20 * (i % 5) {
			c.FilePaths = append(c.FilePaths, fmt.Sprintf("/usr/lib/p%d/file-with-a-long-name-%04d.so", i, j))
		}
		r.Components = append(r.Components, c)
	}
	if err := Fit(r, 20000); err != nil {
		t.Fatal(err)
	}
	if !has(r.PartialReasons, protocol.PartialResponseTrimmed) || r.Completeness != protocol.CompletenessPartial {
		t.Errorf("trim not recorded: %v %s", r.PartialReasons, r.Completeness)
	}
	for i, c := range r.Components {
		hadPaths := i%5 != 0
		if hadPaths && len(c.FilePaths) == 0 && !c.FilesTruncated {
			t.Errorf("%s lost its paths without files_truncated", c.Name)
		}
		if !hadPaths && c.FilesTruncated {
			t.Errorf("%s never had paths but is marked truncated", c.Name)
		}
	}
	if err := Fit(r, 100); err == nil {
		t.Error("a response too large even without paths must fail")
	}
}

func TestInterpretedRules(t *testing.T) {
	for _, c := range []struct {
		path string
		mode uint32
		want bool
	}{
		{"/usr/lib/python3/x.py", 0o644, true},
		{"/usr/bin/script.sh", 0o755, true}, // extension wins over the execute bit
		{"/opt/app/app.jar", 0o644, true},
		{"/usr/lib/x/Foo.class", 0o644, true},
		{"/usr/share/emacs/foo.el", 0o644, true},
		{"/usr/lib/locale/C.utf8/LC_CTYPE", 0o644, false},
		{"/usr/libexec/helper", 0o755, false},
		{"/usr/lib/libz.so.1", 0o644, false},
		{"/usr/share/doc/x/README", 0o644, false},
		{"/usr/share/man/man1/x.1", 0o644, false},
		{"/usr/share/locale/de/LC_MESSAGES/x.mo", 0o644, false},
		{"/usr/share/licenses/x/COPYING", 0o644, false},
		{"/usr/local/share/info/x.info", 0o644, false},
		{"/etc/x.conf", 0o644, false},
		{"/usr/bin/tool", 0o755, false},
		{"/usr/share/zoneinfo/UTC", 0o644, false},
		{"/usr/libfoo/x", 0o644, false},
		// Still loaded or interpreted.
		{"/usr/lib/python3.11/os.py", 0o644, true},
		{"/usr/share/bash-completion/completions/git", 0o644, true},
		{"/usr/share/perl5/Foo.pm", 0o644, true},
		{"/usr/lib/x86_64-linux-gnu/gconv/UTF-7.so", 0o644, false}, // exec-mapped, captured
		// Interpreter and foreign-runtime extensions, wherever they are.
		{"/opt/app/app.pyz", 0o644, true},
		{"/usr/local/bin/tool.phar", 0o755, true},
		{"/opt/erl/lib/x.beam", 0o644, true},
		{"/usr/share/emacs/x.elc", 0o644, true},
		{"/etc/profile.d/x.zsh", 0o644, true},
		{"/opt/app/plugin.dll", 0o644, true},
		{"/opt/app/mod.wasm", 0o644, true},
		{"/srv/x.R", 0o644, true},
		{"/usr/lib/x.pyo", 0o644, true}, {"/x.luac", 0o644, true}, {"/x.awk", 0o644, true},
		{"/x.ksh", 0o644, true}, {"/x.csh", 0o644, true}, {"/x.fish", 0o644, true}, {"/x.ps1", 0o644, true},
		// Debian packaging metadata.
		{"/usr/share/lintian/overrides/libc6", 0o644, false},
		{"/usr/share/bug/bash/presubj", 0o644, false},
		{"/usr/share/bug/foo/control", 0o644, false},
		{"/usr/share/bug/foo/script", 0o644, true}, // run by reportbug
		{"/usr/share/doc-base/foo", 0o644, false},
		{"/usr/share/common-licenses/GPL-3", 0o644, false},
		{"/usr/share/menu/foo", 0o644, false},
		// Pure data.
		{"/usr/share/terminfo/x/xterm", 0o644, false},
		{"/lib/terminfo/l/linux", 0o644, false},
		{"/usr/share/mime/packages/freedesktop.org.xml", 0o644, false},
		{"/usr/share/xml/iso-codes/iso_639.xml", 0o644, false},
		{"/usr/share/icons/hicolor/index.theme", 0o644, false},
		{"/usr/share/pixmaps/foo.png", 0o644, false},
		{"/usr/share/applications/foo.desktop", 0o644, false},
		{"/usr/share/metainfo/foo.xml", 0o644, false},
		{"/usr/share/pkgconfig/foo.pc", 0o644, false},
		{"/usr/share/polkit-1/actions/foo.policy", 0o644, false},
		{"/usr/share/polkit-1/rules.d/50-default.rules", 0o644, true}, // JavaScript polkitd runs
		{"/etc/polkit-1/rules.d/49-local.rules", 0o644, true},
		{"/usr/lib/udev/rules.d/60-foo.rules", 0o644, false}, // udev's .rules are data
		{"/usr/share/xml/docbook/stylesheet/html.xsl", 0o644, true},
		{"/usr/share/xml/foo/t.xslt", 0o644, true},
		{"/usr/share/debianutils/shells.d/bash", 0o644, false},
		{"/usr/share/binfmts/python3.11", 0o644, false},
		{"/usr/share/dbus-1/system.d/foo.conf", 0o644, false},
		// Host configuration.
		{"/usr/lib/tmpfiles.d/foo.conf", 0o644, false},
		{"/usr/lib/sysctl.d/50-default.conf", 0o644, false},
		{"/usr/lib/sysusers.d/foo.conf", 0o644, false},
		{"/lib/modprobe.d/aliases.conf", 0o644, false},
		{"/usr/lib/modules-load.d/foo.conf", 0o644, false},
		{"/usr/lib/binfmt.d/python3.11.conf", 0o644, false},
		{"/usr/lib/environment.d/99-foo.conf", 0o644, false},
		{"/lib/udev/rules.d/60-foo.rules", 0o644, false},
		{"/lib/udev/hwdb.d/20-foo.hwdb", 0o644, false},
		{"/lib/udev/hwdb.bin", 0o644, false},
		{"/lib/udev/hotplug.functions", 0o644, true}, // a shell library udev helpers source
		{"/lib/systemd/system/foo.service", 0o644, false},
		{"/usr/lib/systemd/user/foo.service", 0o644, false},
		{"/usr/lib/systemd/network/99-default.link", 0o644, false},
		{"/usr/lib/systemd/system-preset/90-systemd.preset", 0o644, false},
		{"/usr/lib/systemd/user-preset/90-systemd.preset", 0o644, false},
		{"/usr/lib/systemd/catalog/systemd.catalog", 0o644, false},
		{"/usr/lib/systemd/system-generators/foo-generator", 0o644, true}, // a generator, not a unit
		{"/usr/lib/kernel/install.conf", 0o644, false},
		{"/usr/lib/kernel/install.d/50-foo.install", 0o644, true}, // an install plugin
		{"/usr/lib/os-release", 0o644, false},
		{"/usr/lib/mime/packages/foo", 0o644, false},
		// gconv configuration (the modules themselves are *.so).
		{"/usr/lib/x86_64-linux-gnu/gconv/gconv-modules", 0o644, false},
		{"/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", 0o644, false},
		{"/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/gconv-modules-extra.conf", 0o644, false},
		// Build-time files.
		{"/usr/lib/x86_64-linux-gnu/libfoo.a", 0o644, false},
		{"/usr/lib/x86_64-linux-gnu/libfoo.la", 0o644, false},
		{"/usr/lib/x86_64-linux-gnu/pkgconfig/foo.pc", 0o644, false},
		{"/usr/lib/gcc/x86_64-linux-gnu/12/include/stddef.h", 0o644, false},
		// The other lib roots.
		{"/usr/lib64/guile/3.0/ccache/ice-9/boot-9.go", 0o644, true}, // Guile compiled
		{"/lib64/security/pam_foo.conf", 0o644, true},
		{"/usr/lib32/foo/data", 0o644, true},
		{"/usr/libx32/foo/data", 0o644, true},
		{"/lib32/terminfo/x/xterm", 0o644, false},
		{"/opt/src/main.go", 0o644, false}, // Go source is not Guile
		{"/usr/share/guile/3.0/ice-9/boot-9.scm", 0o644, true},
		{"/opt/app/x.ts", 0o644, true}, {"/opt/app/x.groovy", 0o644, true}, {"/opt/app/x.ex", 0o644, true},
		{"/opt/app/x.exs", 0o644, true}, {"/opt/app/x.ss", 0o644, true},
		// Shell start-up snippets under /etc.
		{"/etc/profile", 0o644, true},
		{"/etc/profile.d/bash_completion.sh", 0o644, true},
		{"/etc/profile.d/locale", 0o644, true},
		{"/etc/bash.bashrc", 0o644, true},
		{"/etc/skel/.bashrc", 0o644, true},
		{"/etc/skel/.profile", 0o644, true},
		{"/etc/skel/.bash_logout", 0o644, true},
		{"/etc/zsh/zshrc.zshrc", 0o644, true},
		{"/root/.profile", 0o644, true},
		{"/etc/zsh/zshrc", 0o644, true}, {"/etc/zsh/zprofile", 0o644, true}, {"/etc/zsh/zshenv", 0o644, true},
		{"/etc/zsh/zlogin", 0o644, true}, {"/etc/zsh/zlogout", 0o644, true},
		{"/etc/bash_completion", 0o644, true},
		{"/etc/bash_completion.d/git-prompt", 0o644, true},
		{"/etc/X11/Xsession.d/90x11-common_ssh-agent", 0o644, true},
		{"/etc/csh.cshrc", 0o644, true}, {"/etc/csh.login", 0o644, true},
		{"/etc/default/locale", 0o644, true},
		{"/etc/zsh/newuser.zshrc.recommended", 0o644, false}, // not sourced
		{"/usr/local/libexec/foo/helper-lib", 0o644, true},
		{"/usr/local/libexecx/foo", 0o644, false},
		{"/etc/hostname", 0o644, false},
	} {
		if got := Interpreted(c.path, c.mode); got != c.want {
			t.Errorf("Interpreted(%s, %o) = %v, want %v", c.path, c.mode, got, c.want)
		}
	}
}

func TestSplitSourceRPM(t *testing.T) {
	for in, want := range map[string][2]string{
		"glibc-2.34-100.el9.src.rpm":     {"glibc", "2.34-100.el9"},
		"python3.9-3.9.18-3.el9.src.rpm": {"python3.9", "3.9.18-3.el9"},
		"bad.src.rpm":                    {"", ""},
		"":                               {"", ""},
	} {
		n, v := splitSourceRPM(in)
		if n != want[0] || v != want[1] {
			t.Errorf("%q -> %q %q", in, n, v)
		}
	}
}

type fakeFR map[string]struct {
	real    string
	mode    uint32
	regular bool
}

func (f fakeFR) Lookup(p string) (string, uint32, bool, bool) {
	e, ok := f[p]
	return e.real, e.mode, e.regular, ok
}
func (f fakeFR) Dropped(p string) bool { return p == "/usr/bin/late" }

func TestPackageFiles(t *testing.T) {
	fr := fakeFR{
		"/bin/sh":          {"/bin/busybox", 0o755, true},
		"/bin/busybox":     {"/bin/busybox", 0o755, true},
		"/usr/lib/libx.so": {"/usr/lib/libx.so.1", 0o644, true},
		"/usr/lib/data":    {"/usr/lib/data", 0o644, true},
		"/usr/lib":         {"/usr/lib", 0o755, false},
		"/opt/" + bad():    {"/opt/" + bad(), 0o755, true},
	}
	paths, trunc, interp := PackageFiles([]string{"/bin/sh", "bin/busybox", "/usr/lib/libx.so", "/usr/lib/data", "/usr/lib", "/missing", "/usr/bin/late"}, fr, 0)
	if fmt.Sprint(paths) != "[/bin/busybox /usr/lib/libx.so.1]" || !trunc || !interp {
		t.Errorf("paths %v truncated %v interpreted %v", paths, trunc, interp)
	}
	paths, trunc, _ = PackageFiles([]string{"/opt/" + bad()}, fr, 0)
	if len(paths) != 0 || !trunc {
		t.Errorf("an over-long path must be dropped and truncate: %v %v", paths, trunc)
	}
}

func bad() string { return strings.Repeat("x", 1100) }

// A package's file behind a symlinked directory that was replaced after
// the container started (/bin -> usr/bin swapped at runtime) is drift too.
func TestDriftOnAnIntermediateSymlink(t *testing.T) {
	root := apkRoot(t, []apkPkg{
		{"tool", "1.0", map[string]os.FileMode{"usr/bin/tool": 0o755, "bin/tool": 0}},
	})
	o := opts()
	o.ContainerStartNanos = time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	must(t, os.Symlink("usr/bin", filepath.Join(root, "bin")))
	r := runDir(t, root, o)
	c := comp(t, r, "tool")
	if !c.FilesTruncated {
		t.Errorf("/bin/tool reached through a runtime-created /bin link: %+v", c)
	}
}

func TestPathsWithControlCharactersAreDropped(t *testing.T) {
	bad := "/usr/bin/evil\nname"
	fr := fakeFR{bad: {bad, 0o755, true}, "/usr/bin/ok": {"/usr/bin/ok", 0o755, true}}
	paths, trunc, _ := PackageFiles([]string{bad, "/usr/bin/ok"}, fr, 0)
	if fmt.Sprint(paths) != "[/usr/bin/ok]" || !trunc {
		t.Errorf("paths %q truncated %v", paths, trunc)
	}
	for _, s := range []string{"a\tb", "x\x7f", "\x00"} {
		if validField(s, 100) {
			t.Errorf("%q accepted", s)
		}
	}
}

// ownedList reads testdata/owned/<pkg>.txt: the regular files of a real
// Debian or Ubuntu package (dpkg-deb -c), as "<mode string> <path>".
func ownedList(t *testing.T, pkg string) ([]string, fakeFR) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "owned", pkg+".txt"))
	must(t, err)
	fr := fakeFR{}
	var owned []string
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		perm, p, ok := strings.Cut(line, " ")
		if !ok || len(perm) != 10 {
			t.Fatalf("%s: bad line %q", pkg, line)
		}
		var mode uint32
		for i, c := range perm[1:] {
			if c != '-' {
				mode |= 1 << (8 - i)
			}
		}
		fr[p] = struct {
			real    string
			mode    uint32
			regular bool
		}{p, mode & 0o777, true}
		owned = append(owned, p)
	}
	return owned, fr
}

// The interpreted_content rule on real packages' complete file lists.
// libc6 and libssl3/libssl3t64 used to be flagged only by packaging
// metadata (lintian overrides) and gconv configuration, so they could
// never be installed_not_observed; interpreted code still flags.
func TestInterpretedContentOnRealPackages(t *testing.T) {
	// For a flagged package, a file that must be among the reasons: the
	// flag must come from genuinely interpreted content, not incidental
	// data.
	for pkg, want := range map[string]struct {
		flagged bool
		because string
	}{
		"libc6":                 {false, ""}, // gconv config and a lintian override: not code
		"libssl3":               {false, ""}, // .so files and docs
		"libssl3t64":            {false, ""}, // Ubuntu: plus a lintian override
		"python3.11-minimal":    {false, ""}, // the interpreter binary; binfmt entries are data
		"libpython3.11-minimal": {true, "/usr/lib/python3.11/os.py"},
		"bash-completion":       {true, "/usr/share/bash-completion/bash_completion"},
		"bash":                  {true, "/etc/bash.bashrc"}, // and /etc/skel dotfiles
	} {
		owned, fr := ownedList(t, pkg)
		_, _, got := PackageFiles(owned, fr, 0)
		var why []string
		for _, p := range owned {
			if Interpreted(p, fr[p].mode) {
				why = append(why, p)
			}
		}
		if got != want.flagged {
			t.Errorf("%s: interpreted_content %v, want %v (flagging files: %v)", pkg, got, want.flagged, why)
		}
		if want.because != "" && !slices.Contains(why, want.because) {
			t.Errorf("%s: %s is not among the flagging files %v", pkg, want.because, why)
		}
		for _, p := range why {
			if strings.Contains(p, "shells.d") || strings.Contains(p, "binfmts") {
				t.Errorf("%s: flagged by the data file %s", pkg, p)
			}
		}
	}
}
