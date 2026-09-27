package wire

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The broker's per-payload limits (broker/src/supplychain.rs) are what the
// matcher's limits exist to respect; the modules cannot share a constant,
// so this test fails if either side changes alone.
func TestLimitsMatchTheBroker(t *testing.T) {
	src, err := os.ReadFile("../../../broker/src/supplychain.rs")
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) int {
		m := regexp.MustCompile(`(?m)^pub const ` + name + `: usize = ([0-9_]+);`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("%s not found in broker/src/supplychain.rs", name)
		}
		n, err := strconv.Atoi(strings.ReplaceAll(string(m[1]), "_", ""))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := get("MAX_FILE_PATHS"); got != MaxFilePaths {
		t.Errorf("wire.MaxFilePaths = %d, broker MAX_FILE_PATHS = %d", MaxFilePaths, got)
	}
	if got := get("MAX_VULNERABILITIES"); got != MaxFindings {
		t.Errorf("wire.MaxFindings = %d, broker MAX_VULNERABILITIES = %d", MaxFindings, got)
	}
}
