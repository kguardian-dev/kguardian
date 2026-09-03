package network

import (
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

func TestCiliumPolicyGenerator_Generate_NoTraffic(t *testing.T) {
	gen := NewCiliumPolicyGenerator()
	podDetail := mockPodDetail("test-pod", "default", "192.168.1.10", map[string]string{"app": "test"})
	var podTraffic []api.PodTraffic // Empty traffic

	policyInterface, err := gen.Generate("test-pod", podTraffic, podDetail)
	assert.NoError(t, err)
	assert.NotNil(t, policyInterface)

	policy, ok := policyInterface.(*CiliumNetworkPolicy)
	assert.True(t, ok)
	assert.Equal(t, GetPolicyName("test-pod", "cilium-policy-deny-all"), policy.Name)
	assert.Equal(t, podDetail.Namespace, policy.Namespace)
	assert.NotNil(t, policy.Spec.EnableDefaultDeny.Ingress)
	assert.NotNil(t, policy.Spec.EnableDefaultDeny.Egress)
	assert.True(t, *policy.Spec.EnableDefaultDeny.Ingress)
	assert.True(t, *policy.Spec.EnableDefaultDeny.Egress)
}

func TestCiliumPolicyGenerator_Generate_BasicIngressEgress(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		if ip == "10.0.0.1" {
			return mockPodDetail("client-pod", "default", ip, map[string]string{"app": "client"}), nil
		}
		return nil, nil // Not found
	}
	api.GetSvcSpecFunc = func(ip string) (*api.SvcDetail, error) {
		if ip == "10.0.0.2" {
			return mockSvcDetail("backend-svc", "default", ip, map[string]string{"app": "backend"}), nil
		}
		return nil, nil // Not found
	}
	// --- End Mocks ---

	gen := NewCiliumPolicyGenerator()
	podDetail := mockPodDetail("test-pod", "default", "192.168.1.10", map[string]string{"app": "test"})
	podTraffic := []api.PodTraffic{
		{
			// INGRESS: client-pod (10.0.0.1) -> test-pod (192.168.1.10:80)
			SrcPodName:  "test-pod",
			SrcIP:       "192.168.1.10", // test-pod's IP
			SrcPodPort:  "80",           // port on test-pod receiving traffic
			DstIP:       "10.0.0.1",     // client-pod's IP (the peer)
			DstPort:     "80",           // not used for ingress
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "INGRESS",
		},
		{
			// EGRESS: test-pod (192.168.1.10) -> backend-svc (10.0.0.2:443)
			SrcPodName:  "test-pod",
			SrcIP:       "192.168.1.10", // test-pod's IP
			SrcPodPort:  "0",            // not used for egress
			DstIP:       "10.0.0.2",     // backend-svc's IP (the peer)
			DstPort:     "443",          // port on backend-svc
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "EGRESS",
		},
	}

	policyInterface, err := gen.Generate("test-pod", podTraffic, podDetail)
	assert.NoError(t, err)
	assert.NotNil(t, policyInterface)

	policy, ok := policyInterface.(*CiliumNetworkPolicy)
	assert.True(t, ok)
	assert.Equal(t, GetPolicyName("test-pod", "cilium-policy"), policy.Name)
	assert.Equal(t, podDetail.Namespace, policy.Namespace)
	assert.Contains(t, policy.Spec.Description, "Cilium network policy for pod test-pod")

	// Verify EndpointSelector has pod labels
	assert.NotEmpty(t, policy.Spec.EndpointSelector.MatchLabels)

	// Verify Ingress Rule
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	// Should use EndpointSelector for pod peer
	assert.Len(t, ingressRule.FromEndpoints, 1)
	assert.NotEmpty(t, ingressRule.FromEndpoints[0].MatchLabels)
	assert.Len(t, ingressRule.ToPorts, 1)
	assert.Equal(t, "80", ingressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, "TCP", ingressRule.ToPorts[0].Ports[0].Protocol)

	// Verify Egress Rule
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	// Should use EndpointSelector for service peer
	assert.Len(t, egressRule.ToEndpoints, 1)
	assert.NotEmpty(t, egressRule.ToEndpoints[0].MatchLabels)
	assert.Len(t, egressRule.ToPorts, 1)
	assert.Equal(t, "443", egressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, "TCP", egressRule.ToPorts[0].Ports[0].Protocol)
}

func TestCiliumPolicyGenerator_Generate_CIDRFallback(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	// Mock APIs to return nothing found
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		return nil, nil
	}
	api.GetSvcSpecFunc = func(ip string) (*api.SvcDetail, error) {
		return nil, nil
	}
	// --- End Mocks ---

	gen := NewCiliumPolicyGenerator()
	podDetail := mockPodDetail("test-pod", "default", "192.168.1.10", map[string]string{"app": "test"})
	podTraffic := []api.PodTraffic{
		{
			// INGRESS: unknown-peer (10.0.0.5) -> test-pod (192.168.1.10:8080)
			SrcPodName:  "test-pod",
			SrcIP:       "192.168.1.10", // test-pod's IP
			SrcPodPort:  "8080",         // port on test-pod receiving traffic
			DstIP:       "10.0.0.5",     // unknown peer IP
			DstPort:     "8080",         // not used for ingress
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "INGRESS",
		},
		{
			// EGRESS: test-pod (192.168.1.10) -> external DNS (8.8.8.8:53)
			SrcPodName:  "test-pod",
			SrcIP:       "192.168.1.10", // test-pod's IP
			SrcPodPort:  "0",            // not used for egress
			DstIP:       "8.8.8.8",      // external DNS IP
			DstPort:     "53",           // DNS port
			Protocol:    corev1.ProtocolUDP,
			TrafficType: "EGRESS",
		},
	}

	policyInterface, err := gen.Generate("test-pod", podTraffic, podDetail)
	assert.NoError(t, err)
	policy, ok := policyInterface.(*CiliumNetworkPolicy)
	assert.True(t, ok)

	// Verify Ingress Rule (should use CIDR)
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	assert.Empty(t, ingressRule.FromEndpoints) // No endpoint selectors
	assert.Len(t, ingressRule.FromCIDR, 1)
	assert.Equal(t, "10.0.0.5/32", ingressRule.FromCIDR[0])
	assert.Len(t, ingressRule.ToPorts, 1)
	assert.Equal(t, "8080", ingressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, "TCP", ingressRule.ToPorts[0].Ports[0].Protocol)

	// Verify Egress Rule (should use CIDR)
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	assert.Empty(t, egressRule.ToEndpoints) // No endpoint selectors
	assert.Len(t, egressRule.ToCIDR, 1)
	assert.Equal(t, "8.8.8.8/32", egressRule.ToCIDR[0])
	assert.Len(t, egressRule.ToPorts, 1)
	assert.Equal(t, "53", egressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, "UDP", egressRule.ToPorts[0].Ports[0].Protocol)
}

func TestCiliumPolicyGenerator_Generate_SelfTrafficFiltering(t *testing.T) {
	gen := NewCiliumPolicyGenerator()
	podDetail := mockPodDetail("test-pod", "default", "192.168.1.10", map[string]string{"app": "test"})
	podTraffic := []api.PodTraffic{
		{
			// Self-traffic that should be filtered out
			SrcPodName:  "test-pod",
			SrcIP:       "192.168.1.10", // test-pod's IP
			SrcPodPort:  "8080",
			DstIP:       "192.168.1.10", // same as pod IP (self-traffic)
			DstPort:     "8080",
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "INGRESS",
		},
	}

	policyInterface, err := gen.Generate("test-pod", podTraffic, podDetail)
	assert.NoError(t, err)

	// Should generate default-deny policy since self-traffic was filtered out
	policy, ok := policyInterface.(*CiliumNetworkPolicy)
	assert.True(t, ok)
	assert.Contains(t, policy.Name, "deny-all")
	assert.NotNil(t, policy.Spec.EnableDefaultDeny.Ingress)
	assert.True(t, *policy.Spec.EnableDefaultDeny.Ingress)
}

func TestCiliumPolicyGenerator_GetType(t *testing.T) {
	gen := NewCiliumPolicyGenerator()
	assert.Equal(t, CiliumPolicy, gen.GetType())
}

// addOrUpdateRule on the Cilium generator must behave the same as on
// the Standard one — port-on-existing-peer merging, duplicate suppression,
// (port, proto) distinctness, and per-peer separation. A regression in
// either generator would silently bloat or under-match generated policies.

func TestCiliumPolicy_AddOrUpdateRule_NewPeerCreatesRule(t *testing.T) {
	g := &CiliumPolicyGenerator{}
	port := intstr.FromInt(8080)
	got := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	if len(got) != 1 || got[0].PeerIP != "10.1.0.1" {
		t.Fatalf("want 1 rule for new peer, got %#v", got)
	}
	if len(got[0].Ports) != 1 {
		t.Errorf("want 1 port on new rule, got %d", len(got[0].Ports))
	}
}

func TestCiliumPolicy_AddOrUpdateRule_ExistingPeerAddsPort(t *testing.T) {
	g := &CiliumPolicyGenerator{}
	p80 := intstr.FromInt(80)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", p80, "TCP")
	p443 := intstr.FromInt(443)
	got := g.addOrUpdateRule(rules, "10.1.0.1", p443, "TCP")

	if len(got) != 1 {
		t.Fatalf("want merged rule, got %d entries", len(got))
	}
	if len(got[0].Ports) != 2 {
		t.Errorf("want 2 ports merged, got %d", len(got[0].Ports))
	}
}

func TestCiliumPolicy_AddOrUpdateRule_DuplicatePortIsNoOp(t *testing.T) {
	g := &CiliumPolicyGenerator{}
	port := intstr.FromInt(80)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	got := g.addOrUpdateRule(rules, "10.1.0.1", port, "TCP")

	if len(got) != 1 || len(got[0].Ports) != 1 {
		t.Errorf("dup port must be a no-op; got rules=%d ports=%d", len(got), len(got[0].Ports))
	}
}

func TestCiliumPolicy_AddOrUpdateRule_SamePortDifferentProtocol(t *testing.T) {
	g := &CiliumPolicyGenerator{}
	port := intstr.FromInt(53)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	got := g.addOrUpdateRule(rules, "10.1.0.1", port, "UDP")

	if len(got) != 1 || len(got[0].Ports) != 2 {
		t.Errorf("DNS over TCP/UDP must coexist; got rules=%d ports=%d", len(got), len(got[0].Ports))
	}
}

func TestCiliumPolicy_AddOrUpdateRule_MultiplePeersStaySeparate(t *testing.T) {
	g := &CiliumPolicyGenerator{}
	port := intstr.FromInt(80)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	got := g.addOrUpdateRule(rules, "10.1.0.2", port, "TCP")

	if len(got) != 2 {
		t.Errorf("two distinct peers should yield 2 rules, got %d", len(got))
	}
}

func TestCreateEndpointSelector_DeterministicYAMLOutput(t *testing.T) {
	// createEndpointSelector iterates the input labels map. Without
	// sorting the keys, Go's randomised map iteration leaks into the
	// resulting LabelArray's slice order, and depending on which
	// internal Cilium field NewESFromLabels populates, the YAML could
	// vary across regenerations. Assert byte-identical YAML across
	// many invocations as the user-visible contract — if any future
	// refactor breaks this, kubectl/git diffs would re-surface.
	g := &CiliumPolicyGenerator{}
	in := map[string]string{
		"app":     "web",
		"tier":    "frontend",
		"version": "v1",
		"env":     "prod",
		"team":    "platform",
	}

	first, err := yaml.Marshal(g.createEndpointSelector(in))
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := yaml.Marshal(g.createEndpointSelector(in))
		if err != nil {
			t.Fatalf("yaml.Marshal run %d: %v", i, err)
		}
		if string(got) != string(first) {
			t.Errorf("run %d: YAML differs from baseline\nfirst=\n%s\ngot=\n%s",
				i, string(first), string(got))
		}
	}
}

func TestConvertPortsToCiliumPortRules_DedupsDuplicates(t *testing.T) {
	// Cilium's convertPortsToCiliumPortRules used to emit one PortRule
	// per input entry, including duplicates. A noisy broker (same flow
	// reported twice) would produce a YAML with two identical
	// PortProtocol entries for the same port — bloat that Cilium would
	// dedup itself but that pollutes the operator-reviewed YAML.
	//
	// Route through deduplicatePorts now means duplicate (port,
	// protocol) pairs collapse to one PortRule.
	g := &CiliumPolicyGenerator{}
	p80 := intstr.FromInt(80)
	tcp := corev1.ProtocolTCP

	in := []networkingv1.NetworkPolicyPort{
		{Port: &p80, Protocol: &tcp},
		{Port: &p80, Protocol: &tcp}, // dup
		{Port: &p80, Protocol: &tcp}, // dup
	}
	got := g.convertPortsToCiliumPortRules(in)
	if len(got) != 1 {
		t.Fatalf("dup ports should collapse to 1 PortRule, got %d", len(got))
	}
	if len(got[0].Ports) != 1 || got[0].Ports[0].Port != "80" || got[0].Ports[0].Protocol != "TCP" {
		t.Errorf("unexpected port: %+v", got[0].Ports)
	}
}

func TestConvertPortsToCiliumPortRules_DeterministicOrdering(t *testing.T) {
	// Same UX-stability class as the standard generator's
	// TestDeduplicatePorts_DeterministicOrderAcrossRuns: scrambled
	// input must produce sorted output, byte-identical across runs.
	// Without the dedup-then-sort, two regenerations could emit
	// different PortRule orderings depending on broker response order,
	// surfacing as spurious kubectl/git diffs.
	g := &CiliumPolicyGenerator{}
	p22 := intstr.FromInt(22)
	p80 := intstr.FromInt(80)
	p443 := intstr.FromInt(443)
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	scrambled := []networkingv1.NetworkPolicyPort{
		{Port: &p443, Protocol: &tcp},
		{Port: &p22, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &p80, Protocol: &tcp},
	}
	wantPorts := []string{"22", "80", "80", "443"}
	wantProtos := []string{"TCP", "TCP", "UDP", "TCP"}
	first := g.convertPortsToCiliumPortRules(scrambled)
	if len(first) != 4 {
		t.Fatalf("want 4 PortRules, got %d", len(first))
	}
	for i, w := range wantPorts {
		if first[i].Ports[0].Port != w {
			t.Errorf("index %d: port want %s, got %s", i, w, first[i].Ports[0].Port)
		}
		if first[i].Ports[0].Protocol != wantProtos[i] {
			t.Errorf("index %d: proto want %s, got %s", i, wantProtos[i], first[i].Ports[0].Protocol)
		}
	}
	// Repeat to catch any residual map-iteration coupling.
	for run := 0; run < 20; run++ {
		got := g.convertPortsToCiliumPortRules(scrambled)
		for i := range got {
			if got[i].Ports[0].Port != first[i].Ports[0].Port ||
				got[i].Ports[0].Protocol != first[i].Ports[0].Protocol {
				t.Errorf("run %d index %d: ordering must match", run, i)
			}
		}
	}
}

func TestResolvePeerForCilium_HostCIDRPerAddressFamily(t *testing.T) {
	// Mirror of the standard generator's fallback test. toCIDR entries
	// used to be built with a hardcoded "/32", so an IPv6 peer became
	// fd00::1/32 — ~2^96 addresses granted in place of one host.
	gen := NewCiliumPolicyGenerator()
	gen.setBrokerData(stubBrokerData{})

	for _, tc := range []struct {
		name string
		ip   string
		want []string
	}{
		{name: "ipv4 peer keeps /32", ip: "10.96.0.10", want: []string{"10.96.0.10/32"}},
		{name: "ipv6 peer gets /128", ip: "fd00:96::a", want: []string{"fd00:96::a/128"}},
		{name: "ipv6 loopback gets /128", ip: "::1", want: []string{"::1/128"}},
		// No CIDR and no endpoint selector is the existing "could not
		// resolve peer" signal the rule builders already drop on.
		{name: "unparseable peer yields no selector", ip: "not-an-ip", want: nil},
		{name: "empty peer yields no selector", ip: "", want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := gen.resolvePeerForCilium(tc.ip, "prod")
			assert.Nil(t, peer.endpoints, "unresolvable peers must not produce an endpoint selector")
			assert.Nil(t, peer.entities, "unresolvable peers must not produce entities")
			assert.Equal(t, tc.want, peer.cidr)
		})
	}
}

func TestCiliumGenerate_DualStackAndUnparseablePeer(t *testing.T) {
	// A dual-stack pod's policy must carry /128 and /32 entries together,
	// and an unparseable peer must cost only its own rule.
	gen := NewCiliumPolicyGenerator()
	gen.setBrokerData(stubBrokerData{})
	detail := mockPodDetail("web6", "prod", "fd00::1", map[string]string{"app": "web"})
	traffic := []api.PodTraffic{
		{TrafficType: "EGRESS", SrcIP: "fd00::1", DstIP: "fd00:96::a", DstPort: "5432", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "fd00::1", DstIP: "10.96.0.10", DstPort: "5432", Protocol: "TCP"},
		{TrafficType: "EGRESS", SrcIP: "fd00::1", DstIP: "junk", DstPort: "5432", Protocol: "TCP"},
	}

	policyInterface, err := gen.Generate("web6", traffic, detail)
	assert.NoError(t, err)
	policy, ok := policyInterface.(*CiliumNetworkPolicy)
	assert.True(t, ok, "expected a *CiliumNetworkPolicy")

	var got []string
	for _, rule := range policy.Spec.Egress {
		got = append(got, rule.ToCIDR...)
	}
	assert.ElementsMatch(t, []string{"10.96.0.10/32", "fd00:96::a/128"}, got,
		"both families must appear side by side and the unparseable peer must be dropped")
}

func TestCreatePeerEndpointSelector_CrossNamespace(t *testing.T) {
	g := &CiliumPolicyGenerator{}
	labels := map[string]string{"app": "sonarr"}

	same := g.createPeerEndpointSelector(labels, "prod", "prod")
	assert.Equal(t, map[string]string{"k8s:app": "sonarr"}, same.MatchLabels, "same namespace: unchanged")

	cross := g.createPeerEndpointSelector(labels, "downloads", "media")
	assert.Equal(t, map[string]string{"k8s:app": "sonarr", "k8s:io.kubernetes.pod.namespace": "downloads"}, cross.MatchLabels)

	unknown := g.createPeerEndpointSelector(labels, "", "media")
	assert.Equal(t, map[string]string{"k8s:app": "sonarr"}, unknown.MatchLabels, "unknown peer namespace: left as before")

	// The input map must not be mutated (it is the broker's label map).
	assert.Equal(t, map[string]string{"app": "sonarr"}, labels)
}
