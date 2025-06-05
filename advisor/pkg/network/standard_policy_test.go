package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xentra-ai/advisor/pkg/api"
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
		{SrcIP: "10.0.0.1", DstIP: "192.168.1.10", DstPort: "80", Protocol: corev1.ProtocolTCP},  // Ingress from client-pod
		{SrcIP: "192.168.1.10", DstIP: "10.0.0.2", DstPort: "443", Protocol: corev1.ProtocolTCP}, // Egress to backend-svc
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
		{SrcIP: "10.0.0.5", DstIP: "192.168.1.10", DstPort: "8080", Protocol: corev1.ProtocolTCP}, // Ingress from unknown IP
		{SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: "53", Protocol: corev1.ProtocolUDP},    // Egress to external IP
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
		{Port: &p80, Protocol: &tcp},
		{Port: &p443, Protocol: &tcp},
		{Port: &p80, Protocol: &tcp}, // Duplicate
		{Port: &p80, Protocol: &udp},
		{Port: nil, Protocol: &tcp}, // Invalid (nil port)
		{Port: &p80, Protocol: nil}, // Invalid (nil protocol)
	}

	deduplicated := deduplicatePorts(ports)
	assert.Len(t, deduplicated, 3)
	assert.ElementsMatch(t, []networkingv1.NetworkPolicyPort{
		{Port: &p80, Protocol: &tcp},
		{Port: &p443, Protocol: &tcp},
		{Port: &p80, Protocol: &udp},
	}, deduplicated)
}
