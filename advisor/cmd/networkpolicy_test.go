package cmd

import (
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/network"
)

// parsePolicyType is the input-validation seam for the --type flag on
// `kguardian gen networkpolicy`. The pre-fix code was a silent
// "anything not 'cilium' → standard" coercion, so a typo like
// `--type=cillium` produced unintended standard policies.

func TestParsePolicyType_AcceptsKubernetes(t *testing.T) {
	got, err := parsePolicyType("kubernetes")
	if err != nil {
		t.Fatalf("kubernetes: unexpected error %v", err)
	}
	if got != network.StandardPolicy {
		t.Errorf("want StandardPolicy, got %s", got)
	}
}

func TestParsePolicyType_AcceptsK8sAlias(t *testing.T) {
	// "k8s" is the common shorthand and a likely typo target. Accept
	// it to keep `--type=k8s` working as users expect.
	got, err := parsePolicyType("k8s")
	if err != nil {
		t.Fatalf("k8s: unexpected error %v", err)
	}
	if got != network.StandardPolicy {
		t.Errorf("want StandardPolicy, got %s", got)
	}
}

func TestParsePolicyType_AcceptsCilium(t *testing.T) {
	got, err := parsePolicyType("cilium")
	if err != nil {
		t.Fatalf("cilium: unexpected error %v", err)
	}
	if got != network.CiliumPolicy {
		t.Errorf("want CiliumPolicy, got %s", got)
	}
}

func TestParsePolicyType_RejectsTyposAndUnknown(t *testing.T) {
	// The reason for strict validation: previously these all silently
	// produced StandardPolicy. A user who meant "cilium" but typed
	// "cillium" got a Kubernetes NetworkPolicy with no warning.
	for _, bad := range []string{"cillium", "Kubernetes", "K8S", "calico", "globalnetworkpolicy", "", "kubernetes "} {
		t.Run(bad, func(t *testing.T) {
			_, err := parsePolicyType(bad)
			if err == nil {
				t.Fatalf("input %q must be rejected", bad)
			}
		})
	}
}

func TestParsePolicyType_ErrorMentionsAcceptedValues(t *testing.T) {
	// If the user gets an error, the message must list what's
	// actually accepted. Stripping that hint forces the user to read
	// docs or shell-completion to figure out the alternative.
	_, err := parsePolicyType("globalnetworkpolicy")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "kubernetes") || !strings.Contains(msg, "cilium") {
		t.Errorf("error must list accepted values; got %q", msg)
	}
	if !strings.Contains(msg, "globalnetworkpolicy") {
		t.Errorf("error must echo the offending input %q for debuggability; got %q", "globalnetworkpolicy", msg)
	}
}
