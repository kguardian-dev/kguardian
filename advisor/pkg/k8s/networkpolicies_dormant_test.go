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

// determinePeerForTraffic is dormant for the same reason, and its IPBlock
// fallback carried the same hardcoded "/32" the two live generators did.
// Pin the address-family behavior now so a future caller inherits a
// correct helper rather than one that silently widens an IPv6 peer into
// the surrounding /32 of IPv6 space.

// stubPeerLookups forces both API lookups to miss, so
// determinePeerForTraffic falls through to its external-IP branch.
func stubPeerLookups(t *testing.T) func() {
	t.Helper()
	prevSvc, prevPod := api.GetSvcSpecFunc, api.GetPodSpecFunc
	api.GetSvcSpecFunc = func(string) (*api.SvcDetail, error) { return nil, nil }
	api.GetPodSpecFunc = func(string) (*api.PodDetail, error) { return nil, nil }
	return func() { api.GetSvcSpecFunc, api.GetPodSpecFunc = prevSvc, prevPod }
}

func TestDeterminePeerForTraffic_HostCIDRPerAddressFamily(t *testing.T) {
	defer stubPeerLookups(t)()

	for _, tc := range []struct {
		name string
		ip   string
		want string
	}{
		{name: "ipv4 peer keeps /32", ip: "10.96.0.10", want: "10.96.0.10/32"},
		{name: "ipv6 peer gets /128", ip: "fd00:96::a", want: "fd00:96::a/128"},
		{name: "ipv6 loopback gets /128", ip: "::1", want: "::1/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, err := determinePeerForTraffic(tc.ip, nil)
			if err != nil {
				t.Fatalf("determinePeerForTraffic(%q): unexpected error: %v", tc.ip, err)
			}
			if peer.IPBlock == nil {
				t.Fatalf("determinePeerForTraffic(%q): expected an IPBlock peer, got %#v", tc.ip, peer)
			}
			if peer.IPBlock.CIDR != tc.want {
				t.Errorf("determinePeerForTraffic(%q) CIDR = %q, want %q", tc.ip, peer.IPBlock.CIDR, tc.want)
			}
		})
	}
}

func TestDeterminePeerForTraffic_RejectsUnparseableIP(t *testing.T) {
	// Unlike the generators — which can only drop the peer — this
	// function returns an error, so the caller decides. Either way the
	// malformed ipBlock never reaches the generated policy.
	defer stubPeerLookups(t)()

	for _, bad := range []string{"", "not-an-ip", "10.0.0.256", "10.0.0.0/8", "fe80::1%eth0"} {
		t.Run(bad, func(t *testing.T) {
			peer, err := determinePeerForTraffic(bad, nil)
			if err == nil {
				t.Fatalf("determinePeerForTraffic(%q): want an error, got peer %#v", bad, peer)
			}
			if !strings.Contains(err.Error(), "host CIDR") {
				t.Errorf("determinePeerForTraffic(%q): error should name the failure, got %v", bad, err)
			}
			if peer.IPBlock != nil {
				t.Errorf("determinePeerForTraffic(%q): must not return a peer alongside the error, got %#v", bad, peer)
			}
		})
	}
}
