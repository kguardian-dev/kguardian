package types

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The broker's per-payload limits (broker/src/supplychain.rs) are what
// these constants exist to respect; the modules cannot share a constant,
// so this fails if either side changes alone.
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
		n, _ := strconv.Atoi(strings.ReplaceAll(string(m[1]), "_", ""))
		return n
	}
	if got := get("MAX_FILE_PATHS"); got != MaxFindingFilePaths {
		t.Errorf("MaxFindingFilePaths = %d, broker MAX_FILE_PATHS = %d", MaxFindingFilePaths, got)
	}
	if got := get("MAX_VULNERABILITIES"); got != MaxFindings {
		t.Errorf("MaxFindings = %d, broker MAX_VULNERABILITIES = %d", MaxFindings, got)
	}
}

func TestCapFilePathsCopies(t *testing.T) {
	long := make([]string, 1520)
	got := CapFilePaths(long)
	if len(got) != MaxFindingFilePaths || cap(got) != MaxFindingFilePaths || &got[0] == &long[0] {
		t.Errorf("len %d cap %d (must be a copy)", len(got), cap(got))
	}
	short := []string{"a"}
	if got := CapFilePaths(short); &got[0] != &short[0] {
		t.Error("short lists are returned as is")
	}
}
