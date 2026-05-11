package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Helper to create mock PodDetail
func mockPodDetail(name, ns, ip string, labels map[string]string) *api.PodDetail {
	return &api.PodDetail{
		Name:      name,
		Namespace: ns,
		PodIP:     ip,
		Pod: corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels:    labels,
			},
		},
	}
}

// Helper to create mock SvcDetail
func mockSvcDetail(name, ns, ip string, selector map[string]string) *api.SvcDetail {
	return &api.SvcDetail{
		SvcName:      name,
		SvcNamespace: ns,
		SvcIp:        ip,
		Service: corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
			Spec: corev1.ServiceSpec{
				Selector: selector,
			},
		},
	}
}

// --- Test Generate ---

func TestStandardPolicyGenerator_Generate_NoTraffic(t *testing.T) {
	gen := NewStandardPolicyGenerator()
	podDetail := mockPodDetail("test-pod", "default", "192.168.1.10", map[string]string{"app": "test"})
	var podTraffic []api.PodTraffic // Empty traffic

	policyInterface, err := gen.Generate("test-pod", podTraffic, podDetail)
	assert.NoError(t, err)
	assert.NotNil(t, policyInterface)

	policy, ok := policyInterface.(*networkingv1.NetworkPolicy)
	assert.True(t, ok)
	assert.Equal(t, GetPolicyName("test-pod", "standard-policy-deny-all"), policy.Name)
	assert.Equal(t, podDetail.Namespace, policy.Namespace)
	assert.Equal(t, podDetail.Pod.Labels, policy.Spec.PodSelector.MatchLabels)
	assert.Contains(t, policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
	assert.Contains(t, policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
	assert.Empty(t, policy.Spec.Ingress)
	assert.Empty(t, policy.Spec.Egress)
}

func TestStandardPolicyGenerator_Generate_BasicIngressEgress(t *testing.T) {
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

	gen := NewStandardPolicyGenerator()
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

	policy, ok := policyInterface.(*networkingv1.NetworkPolicy)
	assert.True(t, ok)
	assert.Equal(t, GetPolicyName("test-pod", "standard-policy"), policy.Name)
	assert.Equal(t, podDetail.Namespace, policy.Namespace)
	assert.Equal(t, podDetail.Pod.Labels, policy.Spec.PodSelector.MatchLabels)
	assert.Len(t, policy.Spec.PolicyTypes, 2)
	assert.Contains(t, policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
	assert.Contains(t, policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)

	// Verify Ingress Rule
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	assert.Len(t, ingressRule.From, 1)
	assert.NotNil(t, ingressRule.From[0].PodSelector) // Should use pod selector for 10.0.0.1
	assert.Equal(t, map[string]string{"app": "client"}, ingressRule.From[0].PodSelector.MatchLabels)
	assert.NotNil(t, ingressRule.From[0].NamespaceSelector)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "default"}, ingressRule.From[0].NamespaceSelector.MatchLabels)
	assert.Len(t, ingressRule.Ports, 1)
	assert.Equal(t, intstr.FromInt(80), *ingressRule.Ports[0].Port)
	assert.Equal(t, corev1.ProtocolTCP, *ingressRule.Ports[0].Protocol)

	// Verify Egress Rule
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	assert.Len(t, egressRule.To, 1)
	assert.NotNil(t, egressRule.To[0].PodSelector) // Should use service selector for 10.0.0.2
	assert.Equal(t, map[string]string{"app": "backend"}, egressRule.To[0].PodSelector.MatchLabels)
	assert.NotNil(t, egressRule.To[0].NamespaceSelector)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "default"}, egressRule.To[0].NamespaceSelector.MatchLabels)
	assert.Len(t, egressRule.Ports, 1)
	assert.Equal(t, intstr.FromInt(443), *egressRule.Ports[0].Port)
	assert.Equal(t, corev1.ProtocolTCP, *egressRule.Ports[0].Protocol)
}

func TestStandardPolicyGenerator_Generate_IpBlockFallback(t *testing.T) {
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

	gen := NewStandardPolicyGenerator()
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
	policy, ok := policyInterface.(*networkingv1.NetworkPolicy)
	assert.True(t, ok)

	// Verify Ingress Rule (should be IPBlock)
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	assert.Len(t, ingressRule.From, 1)
	assert.Nil(t, ingressRule.From[0].PodSelector)
	assert.Nil(t, ingressRule.From[0].NamespaceSelector)
	assert.NotNil(t, ingressRule.From[0].IPBlock)
	assert.Equal(t, "10.0.0.5/32", ingressRule.From[0].IPBlock.CIDR)
	assert.Len(t, ingressRule.Ports, 1)
	assert.Equal(t, intstr.FromInt(8080), *ingressRule.Ports[0].Port)
	assert.Equal(t, corev1.ProtocolTCP, *ingressRule.Ports[0].Protocol)

	// Verify Egress Rule (should be IPBlock)
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	assert.Len(t, egressRule.To, 1)
	assert.Nil(t, egressRule.To[0].PodSelector)
	assert.Nil(t, egressRule.To[0].NamespaceSelector)
	assert.NotNil(t, egressRule.To[0].IPBlock)
	assert.Equal(t, "8.8.8.8/32", egressRule.To[0].IPBlock.CIDR)
	assert.Len(t, egressRule.Ports, 1)
	assert.Equal(t, intstr.FromInt(53), *egressRule.Ports[0].Port)
	assert.Equal(t, corev1.ProtocolUDP, *egressRule.Ports[0].Protocol)
}

func TestStandardPolicyGenerator_Generate_CorrectedTrafficLogic(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		if ip == "10.0.1.100" {
			return mockPodDetail("frontend-pod", "web", ip, map[string]string{"app": "frontend", "tier": "web"}), nil
		}
		return nil, nil // Not found
	}
	api.GetSvcSpecFunc = func(ip string) (*api.SvcDetail, error) {
		if ip == "10.0.2.200" {
			return mockSvcDetail("database-svc", "data", ip, map[string]string{"app": "database", "tier": "data"}), nil
		}
		return nil, nil // Not found
	}
	// --- End Mocks ---

	gen := NewStandardPolicyGenerator()
	podDetail := mockPodDetail("my-app", "default", "10.0.1.50", map[string]string{"app": "my-app", "version": "v1"})

	// Traffic data with corrected understanding:
	// - SrcPodName, SrcIP, SrcPodPort: represent the target pod (the one we're generating policy for)
	// - DstIP, DstPort: represent the peer/remote entity
	// - TrafficType: direction relative to the target pod
	podTraffic := []api.PodTraffic{
		{
			// INGRESS: frontend-pod (10.0.1.100) -> my-app (10.0.1.50:8080)
			SrcPodName:  "my-app",
			SrcIP:       "10.0.1.50",  // my-app's IP
			SrcPodPort:  "8080",       // port on my-app receiving traffic
			DstIP:       "10.0.1.100", // frontend-pod's IP (the peer)
			DstPort:     "0",          // not relevant for ingress
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "INGRESS",
		},
		{
			// EGRESS: my-app (10.0.1.50) -> database-svc (10.0.2.200:5432)
			SrcPodName:  "my-app",
			SrcIP:       "10.0.1.50",  // my-app's IP
			SrcPodPort:  "0",          // not relevant for egress
			DstIP:       "10.0.2.200", // database-svc's IP (the peer)
			DstPort:     "5432",       // port on database-svc
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "EGRESS",
		},
	}

	policyInterface, err := gen.Generate("my-app", podTraffic, podDetail)
	assert.NoError(t, err)
	assert.NotNil(t, policyInterface)

	policy, ok := policyInterface.(*networkingv1.NetworkPolicy)
	assert.True(t, ok)
	assert.Equal(t, GetPolicyName("my-app", "standard-policy"), policy.Name)
	assert.Equal(t, "default", policy.Namespace)
	assert.Equal(t, map[string]string{"app": "my-app", "version": "v1"}, policy.Spec.PodSelector.MatchLabels)
	assert.Len(t, policy.Spec.PolicyTypes, 2)
	assert.Contains(t, policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
	assert.Contains(t, policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)

	// Verify Ingress Rule: frontend-pod -> my-app:8080
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	assert.Len(t, ingressRule.From, 1)
	assert.NotNil(t, ingressRule.From[0].PodSelector)
	assert.Equal(t, map[string]string{"app": "frontend", "tier": "web"}, ingressRule.From[0].PodSelector.MatchLabels)
	assert.NotNil(t, ingressRule.From[0].NamespaceSelector)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "web"}, ingressRule.From[0].NamespaceSelector.MatchLabels)
	assert.Len(t, ingressRule.Ports, 1)
	assert.Equal(t, intstr.FromInt(8080), *ingressRule.Ports[0].Port) // Port on my-app
	assert.Equal(t, corev1.ProtocolTCP, *ingressRule.Ports[0].Protocol)

	// Verify Egress Rule: my-app -> database-svc:5432
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	assert.Len(t, egressRule.To, 1)
	assert.NotNil(t, egressRule.To[0].PodSelector)
	assert.Equal(t, map[string]string{"app": "database", "tier": "data"}, egressRule.To[0].PodSelector.MatchLabels)
	assert.NotNil(t, egressRule.To[0].NamespaceSelector)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "data"}, egressRule.To[0].NamespaceSelector.MatchLabels)
	assert.Len(t, egressRule.Ports, 1)
	assert.Equal(t, intstr.FromInt(5432), *egressRule.Ports[0].Port) // Port on database-svc
	assert.Equal(t, corev1.ProtocolTCP, *egressRule.Ports[0].Protocol)
}

// --- Test Helpers ---

func TestParsePort(t *testing.T) {
	p, err := parsePort("80")
	assert.NoError(t, err)
	assert.Equal(t, 80, p)

	p, err = parsePort("65535")
	assert.NoError(t, err)
	assert.Equal(t, 65535, p)

	_, err = parsePort("0")
	assert.Error(t, err)

	_, err = parsePort("65536")
	assert.Error(t, err)

	_, err = parsePort("abc")
	assert.Error(t, err)

	_, err = parsePort("")
	assert.Error(t, err)
}

func TestParsePort_RejectsTrailingJunkAndDecimals(t *testing.T) {
	// The previous fmt.Sscanf("%d") implementation silently accepted
	// these inputs and returned the leading integer, dropping the rest.
	// That meant "8.5" → 8, "80junk" → 80, " 80" → 80, "0xff" → 0 — all
	// silent corruption of port data scraped from observed traffic.
	// strconv.Atoi rejects every one of these.
	cases := []struct {
		in   string
		desc string
	}{
		{"80junk", "trailing letters"},
		{"80a", "single trailing letter"},
		{" 80", "leading whitespace"},
		{"80 ", "trailing whitespace"},
		{"80 90", "space-separated multi-int"},
		{"8.5", "decimal — no truncation"},
		{"0xff", "hex literal — must reject (not parse as 0)"},
		{"08.0", "decimal with leading zeros"},
		{"\t80", "tab whitespace"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			_, err := parsePort(c.in)
			assert.Error(t, err, "input %q must be rejected: %s", c.in, c.desc)
		})
	}
}

func TestParsePort_AcceptsLeadingZeros(t *testing.T) {
	// "0080" is a valid integer per Atoi semantics (== 80). Atoi
	// doesn't treat leading zeros as octal. Pin this so a future
	// "stricter regex" refactor doesn't accidentally reject what is a
	// reasonable wire format from older eBPF probes.
	p, err := parsePort("0080")
	assert.NoError(t, err)
	assert.Equal(t, 80, p)
}

func TestProtocolPtr(t *testing.T) {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	sctp := corev1.ProtocolSCTP

	assert.Equal(t, &tcp, protocolPtr("TCP"))
	assert.Equal(t, &udp, protocolPtr("UDP"))
	assert.Equal(t, &sctp, protocolPtr("SCTP"))
	assert.Equal(t, &tcp, protocolPtr("UNKNOWN")) // Defaults to TCP
	assert.Equal(t, &tcp, protocolPtr(""))        // Defaults to TCP
}

func TestDeduplicatePorts(t *testing.T) {
	p80 := intstr.FromInt(80)
	p443 := intstr.FromInt(443)
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	ports := []networkingv1.NetworkPolicyPort{
		{Port: &p443, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &p80, Protocol: &tcp},
		{Port: &p443, Protocol: &tcp}, // Duplicate of first
		{Port: nil, Protocol: &tcp},   // Invalid (nil port)
		{Port: &p80, Protocol: nil},   // Invalid (nil protocol)
	}

	deduplicated := deduplicatePorts(ports)
	// Order assertion (not ElementsMatch) — the helper now sorts by
	// (port ASC, protocol ASC) so two regenerations of the same input
	// produce byte-identical YAML. ElementsMatch would silently let a
	// future regression slip through.
	want := []networkingv1.NetworkPolicyPort{
		{Port: &p80, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &p443, Protocol: &tcp},
	}
	assert.Equal(t, want, deduplicated)
}

func TestDeduplicatePorts_DeterministicOrderAcrossRuns(t *testing.T) {
	// Input deliberately scrambled so the dedup-by-first-seen order
	// would visibly differ from the sorted order — pins that the
	// sort, not the iteration order, controls the output. Run 20x to
	// catch any residual map-iteration coupling.
	p22 := intstr.FromInt(22)
	p80 := intstr.FromInt(80)
	p443 := intstr.FromInt(443)
	p5432 := intstr.FromInt(5432)
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	scrambled := []networkingv1.NetworkPolicyPort{
		{Port: &p5432, Protocol: &tcp},
		{Port: &p22, Protocol: &tcp},
		{Port: &p443, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &p80, Protocol: &tcp},
	}
	want := []networkingv1.NetworkPolicyPort{
		{Port: &p22, Protocol: &tcp},
		{Port: &p80, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &p443, Protocol: &tcp},
		{Port: &p5432, Protocol: &tcp},
	}
	first := deduplicatePorts(scrambled)
	assert.Equal(t, want, first)
	for i := 0; i < 20; i++ {
		got := deduplicatePorts(scrambled)
		assert.Equal(t, want, got, "run %d: order must match", i)
	}
}

func TestDeduplicatePorts_NumericBeforeNamedThenLexProtocol(t *testing.T) {
	// Named-port support (intstr.String): named ports must sort AFTER
	// numeric ones, with named-ports themselves in lex order. Within
	// the same port, TCP sorts before UDP (lex on protocol string).
	p80 := intstr.FromInt(80)
	pHTTP := intstr.FromString("http")
	pHTTPS := intstr.FromString("https")
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	in := []networkingv1.NetworkPolicyPort{
		{Port: &pHTTPS, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &pHTTP, Protocol: &tcp},
		{Port: &p80, Protocol: &tcp},
	}
	want := []networkingv1.NetworkPolicyPort{
		{Port: &p80, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
		{Port: &pHTTP, Protocol: &tcp},
		{Port: &pHTTPS, Protocol: &tcp},
	}
	assert.Equal(t, want, deduplicatePorts(in))
}

// --- Determinism: peer-IP iteration order ---

func TestSortedKeys_ReturnsAscendingOrder(t *testing.T) {
	// Pin the helper's contract: ascending lexicographic order of keys.
	// The policy transforms depend on this for deterministic YAML output;
	// any future refactor that swaps to a different sort tax would silently
	// reorder generated policies across runs.
	in := map[string][]networkingv1.NetworkPolicyPort{
		"10.0.0.5": nil,
		"10.0.0.1": nil,
		"10.0.0.3": nil,
		"10.0.0.2": nil,
		"10.0.0.4": nil,
	}
	got := sortedKeys(in)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	assert.Equal(t, want, got)

	// Twenty more invocations must produce the same output. Without
	// the explicit sort, Go's map iteration randomises per-process,
	// so even N=5 keys would shuffle visibly across runs.
	for i := 0; i < 20; i++ {
		again := sortedKeys(in)
		assert.Equal(t, want, again, "run %d must match", i)
	}
}

func TestTransformToNetworkPolicyIngressRules_DeterministicPeerOrdering(t *testing.T) {
	// Repro for the "policy YAML reshuffles between runs" bug. The
	// transform used to range over the peerRules map directly — Go
	// randomises per process, so two `kguardian generate
	// networkpolicy` invocations on the same input produced different
	// rule orderings, surfacing as spurious `kubectl diff` and noise
	// in git-tracked policy review.
	//
	// Build a multi-peer rules slice using IPBlock peers (so we don't
	// need the broker fake — IPBlock falls through createNetworkPolicyPeer
	// with no API calls). Run the transform 20 times; the From IP
	// sequence across the resulting IngressRule list must be identical
	// every call.
	p80 := intstr.FromInt(80)
	tcp := corev1.ProtocolTCP
	rules := []NetworkPolicyRule{
		{PeerIP: "8.8.8.8", Ports: []networkingv1.NetworkPolicyPort{{Port: &p80, Protocol: &tcp}}},
		{PeerIP: "1.1.1.1", Ports: []networkingv1.NetworkPolicyPort{{Port: &p80, Protocol: &tcp}}},
		{PeerIP: "9.9.9.9", Ports: []networkingv1.NetworkPolicyPort{{Port: &p80, Protocol: &tcp}}},
		{PeerIP: "2.2.2.2", Ports: []networkingv1.NetworkPolicyPort{{Port: &p80, Protocol: &tcp}}},
		{PeerIP: "4.4.4.4", Ports: []networkingv1.NetworkPolicyPort{{Port: &p80, Protocol: &tcp}}},
	}

	gen := &StandardPolicyGenerator{}

	first := gen.transformToNetworkPolicyIngressRules(rules)
	assert.Len(t, first, 5)
	want := []string{"1.1.1.1/32", "2.2.2.2/32", "4.4.4.4/32", "8.8.8.8/32", "9.9.9.9/32"}
	for i, w := range want {
		assert.NotNil(t, first[i].From[0].IPBlock, "rule %d: From[0].IPBlock should be set for an external IP peer", i)
		assert.Equal(t, w, first[i].From[0].IPBlock.CIDR, "rule %d: want CIDR %s", i, w)
	}

	for run := 0; run < 20; run++ {
		got := gen.transformToNetworkPolicyIngressRules(rules)
		assert.Equal(t, len(first), len(got), "run %d: length differs", run)
		for i := range got {
			assert.Equal(t, first[i].From[0].IPBlock.CIDR, got[i].From[0].IPBlock.CIDR,
				"run %d index %d: peer ordering must match", run, i)
		}
	}
}

func TestTransformToNetworkPolicyEgressRules_DeterministicPeerOrdering(t *testing.T) {
	// Mirror of the ingress test for the egress transform. Egress
	// rules ship in spec.egress — same git-diff / kubectl-diff impact.
	p443 := intstr.FromInt(443)
	tcp := corev1.ProtocolTCP
	rules := []NetworkPolicyRule{
		{PeerIP: "10.0.0.5", Ports: []networkingv1.NetworkPolicyPort{{Port: &p443, Protocol: &tcp}}},
		{PeerIP: "10.0.0.1", Ports: []networkingv1.NetworkPolicyPort{{Port: &p443, Protocol: &tcp}}},
		{PeerIP: "10.0.0.3", Ports: []networkingv1.NetworkPolicyPort{{Port: &p443, Protocol: &tcp}}},
		{PeerIP: "10.0.0.2", Ports: []networkingv1.NetworkPolicyPort{{Port: &p443, Protocol: &tcp}}},
	}
	gen := &StandardPolicyGenerator{}
	first := gen.transformToNetworkPolicyEgressRules(rules)
	want := []string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.5/32"}
	for i, w := range want {
		assert.NotNil(t, first[i].To[0].IPBlock, "rule %d: To[0].IPBlock should be set", i)
		assert.Equal(t, w, first[i].To[0].IPBlock.CIDR, "rule %d: want CIDR %s", i, w)
	}

	for run := 0; run < 20; run++ {
		got := gen.transformToNetworkPolicyEgressRules(rules)
		for i := range got {
			assert.Equal(t, first[i].To[0].IPBlock.CIDR, got[i].To[0].IPBlock.CIDR,
				"run %d index %d: peer ordering must match", run, i)
		}
	}
}

// --- GetType + addOrUpdateRule coverage ---

func TestStandardPolicyGenerator_GetType(t *testing.T) {
	g := &StandardPolicyGenerator{}
	if g.GetType() != StandardPolicy {
		t.Errorf("StandardPolicyGenerator.GetType: want %s, got %s", StandardPolicy, g.GetType())
	}
}

func TestStandardPolicy_AddOrUpdateRule_NewPeerCreatesRule(t *testing.T) {
	g := &StandardPolicyGenerator{}
	port := intstr.FromInt(8080)
	got := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	if len(got) != 1 {
		t.Fatalf("want 1 rule for new peer, got %d", len(got))
	}
	if got[0].PeerIP != "10.1.0.1" {
		t.Errorf("PeerIP: want 10.1.0.1, got %s", got[0].PeerIP)
	}
	if len(got[0].Ports) != 1 {
		t.Fatalf("want 1 port on new rule, got %d", len(got[0].Ports))
	}
}

func TestStandardPolicy_AddOrUpdateRule_ExistingPeerAddsPort(t *testing.T) {
	g := &StandardPolicyGenerator{}
	p80 := intstr.FromInt(80)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", p80, "TCP")

	p443 := intstr.FromInt(443)
	got := g.addOrUpdateRule(rules, "10.1.0.1", p443, "TCP")

	if len(got) != 1 {
		t.Fatalf("expected the rule to be merged, got %d entries", len(got))
	}
	if len(got[0].Ports) != 2 {
		t.Errorf("expected 2 ports on merged rule, got %d", len(got[0].Ports))
	}
}

func TestStandardPolicy_AddOrUpdateRule_DuplicatePortIsNoOp(t *testing.T) {
	// Same peer + port + protocol must NOT duplicate.
	g := &StandardPolicyGenerator{}
	port := intstr.FromInt(80)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	got := g.addOrUpdateRule(rules, "10.1.0.1", port, "TCP")

	if len(got) != 1 {
		t.Fatalf("want 1 rule, got %d", len(got))
	}
	if len(got[0].Ports) != 1 {
		t.Errorf("duplicate port (same peer, port, proto) must not be re-added; got %d ports", len(got[0].Ports))
	}
}

func TestStandardPolicy_AddOrUpdateRule_SamePortDifferentProtocolAdds(t *testing.T) {
	// Port 53 over TCP vs UDP are distinct rules — DNS is a real
	// case where this matters.
	g := &StandardPolicyGenerator{}
	port := intstr.FromInt(53)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	got := g.addOrUpdateRule(rules, "10.1.0.1", port, "UDP")

	if len(got) != 1 {
		t.Fatalf("want 1 rule (same peer), got %d", len(got))
	}
	if len(got[0].Ports) != 2 {
		t.Errorf("TCP/53 and UDP/53 must coexist on the same peer rule; got %d ports", len(got[0].Ports))
	}
}

func TestStandardPolicy_AddOrUpdateRule_MultiplePeersStaySeparate(t *testing.T) {
	g := &StandardPolicyGenerator{}
	port := intstr.FromInt(80)
	rules := g.addOrUpdateRule(nil, "10.1.0.1", port, "TCP")
	got := g.addOrUpdateRule(rules, "10.1.0.2", port, "TCP")

	if len(got) != 2 {
		t.Fatalf("two distinct peers should yield 2 rules, got %d", len(got))
	}
}
