package rootfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// scaleRoot: links symlinks in /l (to target), then drops runtime log
// files under /d.
func scaleRoot(t *testing.T, links, drops int, target func(i int) string) *Resolver {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "l", "d", "t"} {
		must(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	must(t, os.WriteFile(filepath.Join(root, "t/f"), []byte("x"), 0o644))
	for i := range links {
		must(t, os.Symlink(target(i), filepath.Join(root, "l", fmt.Sprintf("link%d", i))))
	}
	cut := time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	for i := range drops {
		p := filepath.Join(root, "d", fmt.Sprintf("s%d", i%20), fmt.Sprintf("f%d.log", i))
		must(t, os.MkdirAll(filepath.Dir(p), 0o755))
		must(t, os.WriteFile(p, []byte("x"), 0o644))
	}
	r, err := OpenPath(root, Options{CtimeCutoffNanos: cut})
	must(t, err)
	t.Cleanup(func() { _ = r.Close() })
	res, err := NewResolver(r)
	must(t, err)
	for _, g := range []string{"**/nix/store/*", "**/nix/store/*/**", "**/lib/dpkg/status.d/*", "**/lib/modules/**/*.ko",
		"**/php*/**/*.so", "**/var/lib/pacman/local/**/desc", "**/*.jar", "**/package.json", "**/python*"} {
		_, _ = res.FilesByGlob(g)
	}
	return res
}

// The glob matching is bounded (review scale probe). Links that cannot
// give a dropped file another path (to a file, to a directory with no
// dropped file below, dangling loops) are left out, so a normal image
// keeps exact classification; links that can, times many drops, run into
// the bound, and then every drop counts as evidence (fail safe).
func TestDriftScale(t *testing.T) {
	for name, tc := range map[string]struct {
		target       func(i int) string
		unclassified bool
	}{
		"links to a file":           {func(int) string { return "/t/f" }, false},
		"links to an unrelated dir": {func(int) string { return "/t" }, false},
		"dangling loops":            {func(i int) string { return fmt.Sprintf("link%d", i) }, false},
		"links to the drops' dir":   {func(int) string { return "/d" }, true},
		"links to the root":         {func(int) string { return "/" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			res := scaleRoot(t, 10000, 5000, tc.target)
			start := time.Now()
			d := res.ClassifyDropped(20)
			took := time.Since(start)
			if took > 10*time.Second {
				t.Errorf("took %v", took)
			}
			switch {
			case tc.unclassified && (d.Evidence != 5000 || d.Unclassified != 5000):
				t.Errorf("over the bound: evidence %d unclassified %d data %d", d.Evidence, d.Unclassified, d.Data)
			case !tc.unclassified && (d.Data != 5000 || d.Unclassified != 0):
				t.Errorf("exact: evidence %d unclassified %d data %d", d.Evidence, d.Unclassified, d.Data)
			}
			t.Logf("%v evidence %d unclassified %d data %d", took, d.Evidence, d.Unclassified, d.Data)
		})
	}
}

// Under the bound, links to the drops' directory still classify exactly;
// a spent time budget also gives up safely.
func TestDriftBounds(t *testing.T) {
	res := scaleRoot(t, 50, 200, func(int) string { return "/d" })
	if d := res.ClassifyDropped(20); d.Data != 200 || d.Unclassified != 0 {
		t.Errorf("under the bound: %+v", d)
	}
	defer SetDriftBounds(1<<40, 0)()
	if d := res.ClassifyDropped(20); d.Evidence != 200 || d.Unclassified != 200 {
		t.Errorf("time budget spent: evidence %d unclassified %d", d.Evidence, d.Unclassified)
	}
}
