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
		"LEN_SHORT":           MaxShortLen,
		"LEN_URL":             MaxPURLLen,
		"MAX_LICENSES":        MaxLicenses,
		"MAX_PATH_LEN":        MaxPathLen,
	} {
		if got := get(name); got != ours {
			t.Errorf("broker %s = %d, protocol uses %d", name, got, ours)
		}
	}

	// Which constant bounds which field is part of the contract too: a
	// field the broker cuts to a shorter length than the worker allows
	// would be truncated silently.
	for field, want := range map[string]string{
		`clean(Some(&comp.name), LEN_NAME)`:                     "name",
		`clean(comp.version.as_deref(), LEN_VERSION)`:           "version",
		`clean(comp.purl.as_deref(), LEN_URL)`:                  "purl",
		`clean(comp.comp_type.as_deref(), LEN_SHORT)`:           "type",
		`clean(comp.class.as_deref(), LEN_SHORT)`:               "class",
		`clean(comp.src_name.as_deref(), LEN_NAME)`:             "src_name",
		`clean(comp.src_version.as_deref(), LEN_VERSION)`:       "src_version",
		`clean_list(&comp.licenses, MAX_LICENSES, LEN_VERSION)`: "licenses (MaxLicenseLen = LEN_VERSION)",
		`clean(p.os.family.as_deref(), LEN_SHORT)`:              "os.family (MaxOSLen = LEN_SHORT)",
		`clean(p.os.name.as_deref(), LEN_SHORT)`:                "os.name (MaxOSLen = LEN_SHORT)",
	} {
		if !strings.Contains(string(src), field) {
			t.Errorf("broker no longer bounds %s with %s; re-check the protocol limit", want, field)
		}
	}
	if MaxLicenseLen != MaxVersionLen || MaxOSLen != MaxShortLen {
		t.Errorf("MaxLicenseLen %d / MaxOSLen %d no longer match LEN_VERSION / LEN_SHORT", MaxLicenseLen, MaxOSLen)
	}

	// The catalog route (broker/src/node_catalog.rs) sets the per-component
	// path limit the worker caps at. Absent in trees older than the route.
	if nc, err := os.ReadFile("../../../broker/src/node_catalog.rs"); err == nil {
		m := regexp.MustCompile(`(?m)^pub const MAX_CATALOG_PATHS: usize = ([0-9_]+);`).FindSubmatch(nc)
		if m == nil {
			t.Error("MAX_CATALOG_PATHS not found in broker/src/node_catalog.rs")
		} else if n, _ := strconv.Atoi(strings.ReplaceAll(string(m[1]), "_", "")); n != MaxPathsPerPkgCeiling {
			t.Errorf("broker MAX_CATALOG_PATHS = %d, protocol caps at %d", n, MaxPathsPerPkgCeiling)
		}
	}
}

func TestValidPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/bin/ls": true, "/": true, "usr/bin": false, "/a/../b": false, "/a//b": false,
		"/a\nb": false, "/a\x00b": false, "/a\x7fb": false, "/\xff": false,
		"/" + strings.Repeat("x", MaxPathLen): false,
	} {
		if got := ValidPath(p); got != want {
			t.Errorf("ValidPath(%q) = %v", p, got)
		}
	}
}
