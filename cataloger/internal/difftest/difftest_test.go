//go:build difftest

package difftest

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
)

// TestDifferential runs over every fixture directory under
// $KG_DIFFTEST_FIXTURES (made by testdata/difftest/fixtures.sh). Set
// $KG_DIFFTEST_REQUIRE to a comma-separated list of fixture names that must
// be present (CI requires all of them, so a failed pull cannot silently
// shrink the gate).
func TestDifferential(t *testing.T) {
	dir := os.Getenv("KG_DIFFTEST_FIXTURES")
	if dir == "" {
		t.Skip("KG_DIFFTEST_FIXTURES not set")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range strings.Split(os.Getenv("KG_DIFFTEST_REQUIRE"), ",") {
		if want = strings.TrimSpace(want); want != "" && !have[want] {
			t.Errorf("required fixture %q missing", want)
		}
	}
	for _, name := range names {
		root := filepath.Join(dir, name)
		for _, profile := range Profiles {
			t.Run(name+"/"+profile, func(t *testing.T) {
				ctx := context.Background()
				o, err := Ours(ctx, root, profile)
				if err != nil {
					t.Fatalf("ours: %v", err)
				}
				s, err := Stock(ctx, root, profile)
				if err != nil {
					t.Fatalf("stock: %v", err)
				}
				so, ss := Summarise(o), Summarise(s)
				owned := 0
				for _, f := range so.Owned {
					owned += len(f)
				}
				t.Logf("%s: %d packages, %d owned files, %d relationships, distro %q",
					name, len(so.Packages), owned, len(so.Relationships), so.Distro)
				if len(so.Packages) == 0 && profile == protocol.ProfileFull {
					t.Errorf("no packages: the fixture is not exercising anything")
				}
				want, ok := Sentinels[name][profile]
				if !ok {
					t.Errorf("fixture %s has no sentinel packages for %s: add them to difftest.Sentinels", name, profile)
				}
				for _, m := range MissingSentinels(o, want) {
					t.Errorf("sentinel missing: %s", m)
				}
				d := Diff(so, ss, nil)
				for i, l := range d {
					if i == 50 {
						t.Errorf("... %d more differences", len(d)-50)
						break
					}
					t.Error(l)
				}
			})
		}
	}
}

// TestDifferentialControl proves the gate can fail: excluding a directory
// the way a submount is excluded must show up as a difference, and must
// be tolerated only when that path is declared mount-excluded.
func TestDifferentialControl(t *testing.T) {
	dir := os.Getenv("KG_DIFFTEST_FIXTURES")
	if dir == "" {
		t.Skip("KG_DIFFTEST_FIXTURES not set")
	}
	root := filepath.Join(dir, "debian")
	if _, err := os.Stat(root); err != nil {
		t.Skip("debian fixture not present")
	}
	ctx := context.Background()
	const sub = "/usr/share/doc"
	o, err := Ours(ctx, root, protocol.ProfileFull, sub)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Stock(ctx, root, protocol.ProfileFull)
	if err != nil {
		t.Fatal(err)
	}
	so, ss := Summarise(o), Summarise(s)
	if d := Diff(so, ss, nil); len(d) == 0 {
		t.Fatal("hiding a directory produced no difference: the comparison is blind")
	}
	// Owned-file lists come from the dpkg database, so they stay
	// identical; the file-ownership relationships change (Syft relates
	// only files it can see), and tolerance must cover exactly those.
	for _, l := range Diff(so, ss, []string{sub}) {
		t.Error("difference outside the excluded mount:", l)
	}
}
