package k8s

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// G2 generator parity — seccomp, reference side.
// advisor is the reference implementation: these shared fixtures under
// test/fixtures/generators/seccomp encode its output, and the frontend TS
// suite asserts the same fixtures from the other language so the two
// generators cannot diverge. Compared as parsed objects, so serialization
// details never matter.

type seccompFixture struct {
	Name  string `json:"name"`
	Input struct {
		Syscalls []string `json:"syscalls"`
		Arch     string   `json:"arch"`
	} `json:"input"`
	Expected map[string]interface{} `json:"expected"`
}

func TestSeccompGeneratorMatchesSharedFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "test", "fixtures", "generators", "seccomp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	found := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		found++
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read fixture %s: %v", e.Name(), err)
		}
		var fx seccompFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("parse fixture %s: %v", e.Name(), err)
		}

		profile := BuildSeccompProfile(fx.Input.Syscalls, fx.Input.Arch, "")

		// Round-trip through JSON so we compare the wire object, matching the
		// TS side's comparison exactly.
		gotJSON, err := json.Marshal(profile)
		if err != nil {
			t.Fatalf("marshal profile for %s: %v", e.Name(), err)
		}
		var got map[string]interface{}
		if err := json.Unmarshal(gotJSON, &got); err != nil {
			t.Fatalf("unmarshal profile for %s: %v", e.Name(), err)
		}

		if !reflect.DeepEqual(got, fx.Expected) {
			t.Errorf("G2 seccomp parity drift in %s (%s):\n got:      %v\n expected: %v", e.Name(), fx.Name, got, fx.Expected)
		}
	}
	if found == 0 {
		t.Fatal("no seccomp fixtures found")
	}
}
