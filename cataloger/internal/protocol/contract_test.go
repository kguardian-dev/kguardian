package protocol

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The response's components are posted to the broker as ImageSBOM v1
// WireComponents (broker/src/supplychain.rs). The modules cannot share
// code, so this test fails if either side changes alone: every broker
// field must exist here under the same JSON name, and the limits the
// worker enforces must be the broker's.
func TestComponentsMatchTheBroker(t *testing.T) {
	src, err := os.ReadFile("../../../broker/src/supplychain.rs")
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`(?s)pub struct WireComponent \{(.*?)\n\}`).FindSubmatch(src)
	if body == nil {
		t.Fatal("WireComponent not found in broker/src/supplychain.rs")
	}
	fieldRe := regexp.MustCompile(`(?m)((?:#\[serde\([^\]]*\)\]\s*)*)pub (\w+):`)
	renameRe := regexp.MustCompile(`rename = "([^"]+)"`)
	var brokerFields []string
	for _, m := range fieldRe.FindAllSubmatch(body[1], -1) {
		name := string(m[2])
		if r := renameRe.FindSubmatch(m[1]); r != nil {
			name = string(r[1])
		}
		brokerFields = append(brokerFields, name)
	}
	if len(brokerFields) < 5 {
		t.Fatalf("parsed only %v from WireComponent", brokerFields)
	}
	b, _ := json.Marshal(Component{Name: "n", Version: "v", PURL: "p", Type: "t", Class: "c", SrcName: "s",
		SrcVersion: "v", Licenses: []string{"l"}, FilePaths: []string{"/f"}, FilesTruncated: true, InterpretedContent: true})
	var ours map[string]any
	_ = json.Unmarshal(b, &ours)
	for _, f := range brokerFields {
		if f == "layer_digest" {
			continue // never sent: a mounted root has no layers (PROTOCOL.md §4.3)
		}
		if _, ok := ours[f]; !ok {
			t.Errorf("broker WireComponent field %q missing from protocol.Component", f)
		}
	}

	get := func(re string) int {
		m := regexp.MustCompile(`(?m)^(?:pub )?const ` + re + `: usize = ([0-9_]+);`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("%s not found in broker/src/supplychain.rs", re)
		}
		n, _ := strconv.Atoi(strings.ReplaceAll(string(m[1]), "_", ""))
		return n
	}
	for name, ours := range map[string]int{
		"MAX_SBOM_COMPONENTS": int(CeilingBudgets.MaxComponents),
		"LEN_NAME":            MaxNameLen,
		"LEN_VERSION":         MaxVersionLen,
		"MAX_LICENSES":        MaxLicenses,
		"MAX_PATH_LEN":        MaxPathLen,
	} {
		if got := get(name); got != ours {
			t.Errorf("broker %s = %d, protocol uses %d", name, got, ours)
		}
	}
}
