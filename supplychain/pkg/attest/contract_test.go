package attest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestVerdictContract: the verdicts and signer kinds discovery emits are
// exactly the ones in the shared contract file, which the broker's
// whitelist is tested against too (attestation_tests.rs). A value added or
// removed on either side without the other fails here or there.
func TestVerdictContract(t *testing.T) {
	raw, err := os.ReadFile("../../../test/fixtures/contracts/attestation-verdicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Verdicts    []string `json:"verdicts"`
		SignerKinds []string `json:"signer_kinds"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		name       string
		got, wants []string
	}{{"verdicts", Verdicts, c.Verdicts}, {"signer_kinds", SignerKinds, c.SignerKinds}} {
		got, want := slices.Clone(x.got), slices.Clone(x.wants)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: supplychain emits %v, contract says %v", x.name, got, want)
		}
	}
	// Every Verdict* / Signer{Keyless,Key} constant in the package is in
	// the lists, so a new constant cannot bypass the contract.
	consts := stringConsts(t)
	for name, val := range consts {
		switch {
		case strings.HasPrefix(name, "Verdict") && !slices.Contains(Verdicts, val):
			t.Errorf("constant %s = %q is not in Verdicts", name, val)
		case (name == "SignerKeyless" || name == "SignerKey") && !slices.Contains(SignerKinds, val):
			t.Errorf("constant %s = %q is not in SignerKinds", name, val)
		}
	}
}

// stringConsts parses the package's non-test files for string constants.
func stringConsts(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]string{}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
							v, _ := strconv.Unquote(bl.Value)
							out[n.Name] = v
						}
					}
				}
			}
		}
	}
	if _, ok := out["VerdictVerified"]; !ok {
		t.Fatal("constant parser found no verdicts")
	}
	return out
}
