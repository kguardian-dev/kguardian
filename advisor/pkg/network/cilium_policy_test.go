package network

import (
	"testing"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/stretchr/testify/assert"
	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
)

func TestCiliumPolicyGenerator_Generate_NoTraffic(t *testing.T) {
	gen := NewCiliumPolicyGenerator()
	podDetail := mockPodDetail("test-pod", "default", "192.168.1.10", map[string]string{"app": "test"})
	var podTraffic []api.PodTraffic // Empty traffic

	policyInterface, err := gen.Generate("test-pod", podTraffic, podDetail)
	assert.NoError(t, err)
	assert.NotNil(t, policyInterface)

	policy, ok := policyInterface.(*ciliumv2.CiliumNetworkPolicy)
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

	policy, ok := policyInterface.(*ciliumv2.CiliumNetworkPolicy)
	assert.True(t, ok)
	assert.Equal(t, GetPolicyName("test-pod", "cilium-policy"), policy.Name)
	assert.Equal(t, podDetail.Namespace, policy.Namespace)
	assert.Contains(t, policy.Spec.Description, "Cilium network policy for pod test-pod")

	// Verify EndpointSelector has pod labels
	assert.NotEmpty(t, policy.Spec.EndpointSelector.LabelSelector)

	// Verify Ingress Rule
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	// Should use EndpointSelector for pod peer
	assert.Len(t, ingressRule.FromEndpoints, 1)
	assert.NotEmpty(t, ingressRule.FromEndpoints[0].LabelSelector)
	assert.Len(t, ingressRule.ToPorts, 1)
	assert.Equal(t, "80", ingressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, ciliumapi.L4Proto("TCP"), ingressRule.ToPorts[0].Ports[0].Protocol)

	// Verify Egress Rule
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	// Should use EndpointSelector for service peer
	assert.Len(t, egressRule.ToEndpoints, 1)
	assert.NotEmpty(t, egressRule.ToEndpoints[0].LabelSelector)
	assert.Len(t, egressRule.ToPorts, 1)
	assert.Equal(t, "443", egressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, ciliumapi.L4Proto("TCP"), egressRule.ToPorts[0].Ports[0].Protocol)
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
	policy, ok := policyInterface.(*ciliumv2.CiliumNetworkPolicy)
	assert.True(t, ok)

	// Verify Ingress Rule (should use CIDR)
	assert.Len(t, policy.Spec.Ingress, 1)
	ingressRule := policy.Spec.Ingress[0]
	assert.Empty(t, ingressRule.FromEndpoints) // No endpoint selectors
	assert.Len(t, ingressRule.FromCIDR, 1)
	assert.Equal(t, ciliumapi.CIDR("10.0.0.5/32"), ingressRule.FromCIDR[0])
	assert.Len(t, ingressRule.ToPorts, 1)
	assert.Equal(t, "8080", ingressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, ciliumapi.L4Proto("TCP"), ingressRule.ToPorts[0].Ports[0].Protocol)

	// Verify Egress Rule (should use CIDR)
	assert.Len(t, policy.Spec.Egress, 1)
	egressRule := policy.Spec.Egress[0]
	assert.Empty(t, egressRule.ToEndpoints) // No endpoint selectors
	assert.Len(t, egressRule.ToCIDR, 1)
	assert.Equal(t, ciliumapi.CIDR("8.8.8.8/32"), egressRule.ToCIDR[0])
	assert.Len(t, egressRule.ToPorts, 1)
	assert.Equal(t, "53", egressRule.ToPorts[0].Ports[0].Port)
	assert.Equal(t, ciliumapi.L4Proto("UDP"), egressRule.ToPorts[0].Ports[0].Protocol)
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
	policy, ok := policyInterface.(*ciliumv2.CiliumNetworkPolicy)
	assert.True(t, ok)
	assert.Contains(t, policy.Name, "deny-all")
	assert.NotNil(t, policy.Spec.EnableDefaultDeny.Ingress)
	assert.True(t, *policy.Spec.EnableDefaultDeny.Ingress)
}

func TestCiliumPolicyGenerator_GetType(t *testing.T) {
	gen := NewCiliumPolicyGenerator()
	assert.Equal(t, CiliumPolicy, gen.GetType())
}
