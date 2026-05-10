package k8s

import (
	"strings"
	"testing"

	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// processIngressRules and processEgressRules are //nolint:unused —
// "Reserved for future refactoring". When a future caller wires them
// up, they MUST reject malformed port strings. The pre-fix version
// used `_, _ = fmt.Sscanf("%d", ...)` which silently turned an empty
// or junk port into zero, then wrote port: 0 into the generated
// NetworkPolicy.
//
// These tests run today (so the strict-parse behavior is enforced
// even while the functions are dormant) and prevent re-introducing
// the silent-fallback bug when the functions are eventually used.

// stubPeer makes the tests independent of the determinePeerForTraffic
// API-lookup chain — we're testing the parse-port path, not peer
// resolution.
func stubPeer(t *testing.T) func() {
	t.Helper()
	prev := determinePeerForTrafficFunc
	determinePeerForTrafficFunc = func(_ string, _ *Config) (networkingv1.NetworkPolicyPeer, error) {
		return networkingv1.NetworkPolicyPeer{}, nil
	}
	return func() { determinePeerForTrafficFunc = prev }
}

func TestProcessIngressRules_RejectsMalformedSrcPodPort(t *testing.T) {
	defer stubPeer(t)()

	for _, bad := range []string{"", "8.5", "80junk", " 80", "abc", "0xff"} {
		t.Run(bad, func(t *testing.T) {
			_, err := processIngressRules(api.PodTraffic{
				SrcPodPort: bad,
				DstIP:      "10.0.0.1",
				Protocol:   corev1.ProtocolTCP,
			}, nil)
			if err == nil {
				t.Fatalf("input %q must produce an error, not silently parse to zero", bad)
			}
			if !strings.Contains(err.Error(), bad) && bad != "" {
				t.Errorf("error message must include the offending value %q for debuggability; got %v", bad, err)
			}
		})
	}
}

func TestProcessIngressRules_AcceptsValidPort(t *testing.T) {
	defer stubPeer(t)()
	rule, err := processIngressRules(api.PodTraffic{
		SrcPodPort: "8080",
		DstIP:      "10.0.0.1",
		Protocol:   corev1.ProtocolTCP,
	}, nil)
	if err != nil {
		t.Fatalf("valid port must parse: %v", err)
	}
	if got := rule.Ports[0].Port.IntValue(); got != 8080 {
		t.Errorf("Port: want 8080, got %d", got)
	}
}

func TestProcessEgressRules_RejectsMalformedDstPort(t *testing.T) {
	defer stubPeer(t)()

	for _, bad := range []string{"", "5432.0", "5432 ", "fivethousand"} {
		t.Run(bad, func(t *testing.T) {
			_, err := processEgressRules(api.PodTraffic{
				DstPort:  bad,
				DstIP:    "10.0.0.1",
				Protocol: corev1.ProtocolTCP,
			}, nil)
			if err == nil {
				t.Fatalf("input %q must produce an error, not silently parse to zero", bad)
			}
		})
	}
}

func TestProcessEgressRules_AcceptsValidPort(t *testing.T) {
	defer stubPeer(t)()
	rule, err := processEgressRules(api.PodTraffic{
		DstPort:  "5432",
		DstIP:    "10.0.0.1",
		Protocol: corev1.ProtocolTCP,
	}, nil)
	if err != nil {
		t.Fatalf("valid port must parse: %v", err)
	}
	if got := rule.Ports[0].Port.IntValue(); got != 5432 {
		t.Errorf("Port: want 5432, got %d", got)
	}
}
