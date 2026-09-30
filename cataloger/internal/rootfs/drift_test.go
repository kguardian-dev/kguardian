package rootfs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// driftRoot is a small root with a merged-usr style /lib -> usr/lib
// link; files are written after the returned cutoff.
func driftRoot(t *testing.T, late map[string]string, modes map[string]os.FileMode) (string, *Root, *Resolver) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "usr/lib/apk/db", "usr/bin"} {
		must(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	must(t, os.Symlink("usr/lib", filepath.Join(root, "lib")))
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\n"), 0o644))
	cut := time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	for p, content := range late {
		mode := modes[p]
		if mode == 0 {
			mode = 0o644
		}
		must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755))
		must(t, os.WriteFile(filepath.Join(root, p), []byte(content), mode))
	}
	r, err := OpenPath(root, Options{CtimeCutoffNanos: cut})
	must(t, err)
	t.Cleanup(func() { _ = r.Close() })
	res, err := NewResolver(r)
	must(t, err)
	return root, r, res
}

func TestClassifyDropped(t *testing.T) {
	_, _, res := driftRoot(t, map[string]string{
		"usr/lib/apk/db/installed": "P:busybox\n", // asked for through /lib
		"usr/bin/new":              "\x7fELF\x02",
		"usr/bin/script":           "#!/bin/sh\necho hi\n",
		"usr/lib/libx.so.2":        "\x00\x01",
		"opt/app/lib/a.jar":        "PK\x03\x04",
		"var/log/app.log":          "hello\n",
		"tmp/empty.lock":           "",
	}, map[string]os.FileMode{"usr/bin/new": 0o755, "usr/bin/script": 0o755, "tmp/empty.lock": 0o755})
	// What catalogers ask for.
	_, _ = res.FilesByPath("/lib/apk/db/installed")
	_, _ = res.FilesByGlob("**/*.jar")
	_, _ = res.FilesByMIMEType("application/x-elf")

	d := res.ClassifyDropped(3)
	// Evidence: the database (path through the link), the ELF, the
	// shared object, the jar. Data: the script (text), the log, the
	// empty lock file.
	if d.Evidence != 4 || d.Data != 3 {
		t.Fatalf("evidence %d data %d", d.Evidence, d.Data)
	}
	want := []string{"/opt/app/lib/a.jar", "/usr/bin/new", "/usr/lib/apk/db/installed"}
	if !slices.Equal(d.Sample, want) {
		t.Errorf("sample %v, want %v", d.Sample, want)
	}
}

// A file a cataloger went to read and found changed is evidence, whatever
// it looks like.
func TestDroppedAtReadIsEvidence(t *testing.T) {
	dir, r, res := driftRoot(t, nil, nil)
	locs, _ := res.FilesByPath("/etc/os-release")
	r.opts.CtimeCutoffNanos = time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	// Move the ctime without changing the content.
	must(t, os.Chmod(filepath.Join(dir, "etc/os-release"), 0o640))
	if _, err := res.FileContentsByLocation(locs[0]); err == nil {
		t.Fatal("read a file changed after the cutoff")
	}
	if d := res.ClassifyDropped(20); d.Evidence != 1 || d.Data != 0 {
		t.Errorf("evidence %d data %d", d.Evidence, d.Data)
	}
}

// A listing of every file by anything but the Nix store cataloger makes
// every dropped entry evidence (fail safe).
func TestListingEveryFileMakesEverythingEvidence(t *testing.T) {
	_, _, res := driftRoot(t, map[string]string{"var/log/app.log": "x", "tmp/a": "y"}, nil)
	if d := res.ClassifyDropped(20); d.Evidence != 0 || d.Data != 2 {
		t.Fatalf("before: evidence %d data %d", d.Evidence, d.Data)
	}
	for range res.AllLocations(context.Background()) {
	}
	if _, _, _, all := res.Queries(); !all {
		t.Fatal("listing not recorded")
	}
	if d := res.ClassifyDropped(20); d.Evidence != 2 || d.Data != 0 {
		t.Errorf("after: evidence %d data %d", d.Evidence, d.Data)
	}
}

// "<dir>/*" globs (the distroless dpkg database, Nix store entries) are
// matched: stereoscope's subdirectory search needs the parent directories
// in the index (review probe).
func TestSubdirectoryGlobs(t *testing.T) {
	_, _, res := driftRoot(t, map[string]string{
		"var/lib/dpkg/status.d/libssl3": "Package: libssl3\nVersion: 3.0\n",
		"nix/store/abc-foo/bin/foo":     "#!/bin/sh\n",
		"nix/store/abc-bar":             "plain",
		"var/log/app.log":               "x",
	}, nil)
	_, _ = res.FilesByGlob("**/var/lib/dpkg/status.d/*")
	_, _ = res.FilesByGlob(nixStoreGlobs...)
	if d := res.ClassifyDropped(20); d.Evidence != 3 || d.Data != 1 {
		t.Errorf("evidence %d data %d, sample %v", d.Evidence, d.Data, d.Sample)
	}
}

// Dropped symlinks: to a directory, evidence (it can reroute a database
// or any tree a cataloger walks); to a file, evidence when the link or
// its target was asked for by glob or path; to plain data or nowhere,
// data.
func TestDroppedSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc", "data/apk/db", "opt/pkg", "var/log", "lib"} {
		must(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "opt/pkg/package.json"), []byte("{}"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "opt/blob"), []byte("x"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "var/log/x.log"), []byte("x"), 0o644))
	cut := time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	for link, target := range map[string]string{
		"lib/apk":          "../data/apk",           // directory: evidence
		"app/current.jar":  "/opt/blob",             // link path matches a glob: evidence
		"app/lib/manifest": "/opt/pkg/package.json", // target matches a glob: evidence
		"var/log/current":  "x.log",                 // plain data
		"var/log/gone":     "/nonexistent",          // dangling
	} {
		must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(link)), 0o755))
		must(t, os.Symlink(target, filepath.Join(root, link)))
	}
	r, err := OpenPath(root, Options{CtimeCutoffNanos: cut})
	must(t, err)
	t.Cleanup(func() { _ = r.Close() })
	res, err := NewResolver(r)
	must(t, err)
	_, _ = res.FilesByGlob("**/*.jar", "**/package.json")
	d := res.ClassifyDropped(20)
	want := []string{"/app/current.jar", "/app/lib/manifest", "/lib/apk", "/var/log/current", "/var/log/gone"}
	if d.Evidence != 3 || d.Data != 2 || !slices.Equal(d.Sample, want) {
		t.Errorf("evidence %d data %d sample %v", d.Evidence, d.Data, d.Sample)
	}
}
