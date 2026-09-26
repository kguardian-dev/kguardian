package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/spf13/cobra"
)

const policyYAML = "# kguardian image admission policy for namespace shop\napiVersion: policies.kyverno.io/v1beta1\nkind: ImageValidatingPolicy\n"

func TestAdmissionPolicyFetchesAndPrints(t *testing.T) {
	fb := startFakeBroker(t, map[string]string{"/attestations/policy": policyYAML})
	var out bytes.Buffer
	err := writeAdmissionPolicy(api.AdmissionPolicyOptions{Format: "policy-controller", Mode: "enforce", Namespace: "shop", AcknowledgePartial: true}, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != policyYAML {
		t.Fatalf("out = %q", out.String())
	}
	q := fb.lastReq.URL.Query()
	if q.Get("format") != "policy-controller" || q.Get("mode") != "enforce" || q.Get("namespace") != "shop" || q.Get("acknowledgePartial") != "true" {
		t.Fatalf("query = %v", q)
	}
	if fb.lastReq.Header.Get("Authorization") != "Bearer read-token" {
		t.Fatalf("auth = %q", fb.lastReq.Header.Get("Authorization"))
	}
}

func TestAdmissionPolicyBrokerRefusal(t *testing.T) {
	startFakeBroker(t, map[string]string{"/attestations/policy": "409:an enforcing policy would not cover every running image: x (a running digest is unsigned)"})
	err := writeAdmissionPolicy(api.AdmissionPolicyOptions{Format: "kyverno", Mode: "enforce"}, "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("err = %v", err)
	}
}

func TestAdmissionOptionsValidation(t *testing.T) {
	c := &cobra.Command{}
	c.Flags().StringP("namespace", "n", "", "")
	for _, tc := range []struct{ format, mode string }{{"opa", "audit"}, {"kyverno", "block"}, {"kguardian", "enforce"}} {
		admissionFormat, admissionMode = tc.format, tc.mode
		if _, err := admissionOptions(c); err == nil {
			t.Errorf("%s/%s accepted", tc.format, tc.mode)
		}
	}
	admissionFormat, admissionMode = "Kyverno ", "AUDIT"
	o, err := admissionOptions(c)
	if err != nil || o.Format != "kyverno" || o.Mode != "audit" || o.Namespace != "" {
		t.Fatalf("o = %+v, %v", o, err)
	}
	admissionFormat, admissionMode = "kyverno", "audit"
}

// An oversized response is never written cut off: exit 2, no file, no
// partial output.
func TestAdmissionPolicyOversizedResponse(t *testing.T) {
	big := "# header\n" + strings.Repeat("x", 10*1024*1024)
	startFakeBroker(t, map[string]string{"/attestations/policy": big})
	file := filepath.Join(t.TempDir(), "policy.yaml")
	var out bytes.Buffer
	err := writeAdmissionPolicy(api.AdmissionPolicyOptions{Format: "kyverno", Mode: "audit"}, file, &out)
	var ge *gateError
	if !errors.As(err, &ge) || ge.code != exitGateNoCheck || !strings.Contains(ge.msg, "nothing was written") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
		t.Fatalf("partial file written: %v", statErr)
	}
	if out.Len() != 0 {
		t.Fatalf("partial stdout: %d bytes", out.Len())
	}
	// Exactly at the limit is complete and written.
	startFakeBroker(t, map[string]string{"/attestations/policy": big[:10*1024*1024]})
	if err := writeAdmissionPolicy(api.AdmissionPolicyOptions{Format: "kyverno"}, file, &out); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(file); err != nil || st.Size() != 10*1024*1024 {
		t.Fatalf("file = %v, %v", st, err)
	}
}

// -f replaces the file whole: an existing policy survives a failed fetch
// untouched, a successful one replaces it, and no temporary file is left.
func TestAdmissionPolicyAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(file, []byte("old policy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	startFakeBroker(t, map[string]string{"/attestations/policy": "# header\n" + strings.Repeat("x", 10*1024*1024)})
	if err := writeAdmissionPolicy(api.AdmissionPolicyOptions{Format: "kyverno"}, file, &bytes.Buffer{}); err == nil {
		t.Fatal("oversized response accepted")
	}
	if b, _ := os.ReadFile(file); string(b) != "old policy\n" {
		t.Fatalf("old policy changed: %q", b)
	}
	startFakeBroker(t, map[string]string{"/attestations/policy": policyYAML})
	if err := writeAdmissionPolicy(api.AdmissionPolicyOptions{Format: "kyverno"}, file, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != policyYAML {
		t.Fatalf("policy = %q", b)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", st.Mode())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
	// A directory that cannot be written: an error, nothing left behind.
	if err := writeFileAtomic(filepath.Join(dir, "missing", "p.yaml"), []byte("x")); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
}
