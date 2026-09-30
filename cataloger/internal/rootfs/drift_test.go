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
