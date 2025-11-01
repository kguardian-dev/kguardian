package network

import (
	"testing"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/stretchr/testify/assert"
	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestIntegration_StandardAndCiliumPolicyGenerators(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodSpecFunc := api.GetPodSpecFunc
	origGetSvcSpecFunc := api.GetSvcSpecFunc
	defer func() {
		api.GetPodSpecFunc = origGetPodSpecFunc
		api.GetSvcSpecFunc = origGetSvcSpecFunc
	}()

	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		if ip == "10.1.0.50" {
			return mockPodDetail("frontend-pod", "web", ip, map[string]string{"app": "frontend", "tier": "web"}), nil
		}
		return nil, nil
	}
	api.GetSvcSpecFunc = func(ip string) (*api.SvcDetail, error) {
		if ip == "10.2.0.100" {
			return mockSvcDetail("database-svc", "data", ip, map[string]string{"app": "postgres", "tier": "database"}), nil
		}
		return nil, nil
	}
	// --- End Mocks ---

	// Common test data
	podDetail := mockPodDetail("api-server", "production", "10.0.5.25", map[string]string{
		"app":     "api-server",
		"version": "v1.2.3",
		"tier":    "backend",
	})

	podTraffic := []api.PodTraffic{
		{
			// INGRESS: frontend-pod -> api-server
			SrcPodName:  "api-server",
			SrcIP:       "10.0.5.25", // api-server's IP
			SrcPodPort:  "8080",      // port on api-server
			DstIP:       "10.1.0.50", // frontend-pod's IP (the caller)
			DstPort:     "8080",      // not used for ingress
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "INGRESS",
		},
		{
			// EGRESS: api-server -> database-svc
			SrcPodName:  "api-server",
			SrcIP:       "10.0.5.25",  // api-server's IP
			SrcPodPort:  "0",          // not used for egress
			DstIP:       "10.2.0.100", // database-svc's IP
			DstPort:     "5432",       // postgres port
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "EGRESS",
		},
		{
			// EGRESS: api-server -> external metrics endpoint
			SrcPodName:  "api-server",
			SrcIP:       "10.0.5.25", // api-server's IP
			SrcPodPort:  "0",         // not used for egress
			DstIP:       "52.1.2.3",  // external IP
			DstPort:     "443",       // HTTPS
			Protocol:    corev1.ProtocolTCP,
			TrafficType: "EGRESS",
		},
	}

	// Test Standard NetworkPolicy Generator
	t.Run("StandardPolicy", func(t *testing.T) {
		gen := NewStandardPolicyGenerator()
		result, err := gen.Generate("api-server", podTraffic, podDetail)
		assert.NoError(t, err)

		policy, ok := result.(*networkingv1.NetworkPolicy)
		assert.True(t, ok)
		assert.Equal(t, "api-server-standard-policy", policy.Name)
		assert.Equal(t, "production", policy.Namespace)

		// Should have both ingress and egress rules
		assert.Len(t, policy.Spec.Ingress, 1)
		assert.Len(t, policy.Spec.Egress, 2) // database + external

		// Check ingress rule (from frontend-pod)
		ingressRule := policy.Spec.Ingress[0]
		assert.Len(t, ingressRule.From, 1)
		assert.NotNil(t, ingressRule.From[0].PodSelector)
		assert.Equal(t, "frontend", ingressRule.From[0].PodSelector.MatchLabels["app"])

		// Check egress rules
		hasDBRule := false
		hasExternalRule := false
		for _, egressRule := range policy.Spec.Egress {
			assert.Len(t, egressRule.To, 1)
			if egressRule.To[0].PodSelector != nil {
				// Database service rule
				assert.Equal(t, "postgres", egressRule.To[0].PodSelector.MatchLabels["app"])
				hasDBRule = true
			} else if egressRule.To[0].IPBlock != nil {
				// External rule
				assert.Equal(t, "52.1.2.3/32", egressRule.To[0].IPBlock.CIDR)
				hasExternalRule = true
			}
		}
		assert.True(t, hasDBRule, "Should have database egress rule")
		assert.True(t, hasExternalRule, "Should have external egress rule")
	})

	// Test Cilium NetworkPolicy Generator
	t.Run("CiliumPolicy", func(t *testing.T) {
		gen := NewCiliumPolicyGenerator()
		result, err := gen.Generate("api-server", podTraffic, podDetail)
		assert.NoError(t, err)

		policy, ok := result.(*ciliumv2.CiliumNetworkPolicy)
		assert.True(t, ok)
		assert.Equal(t, "api-server-cilium-policy", policy.Name)
		assert.Equal(t, "production", policy.Namespace)

		// Should have both ingress and egress rules
		assert.Len(t, policy.Spec.Ingress, 1)
		assert.Len(t, policy.Spec.Egress, 2) // database + external

		// Check ingress rule (from frontend-pod)
		ingressRule := policy.Spec.Ingress[0]
		assert.Len(t, ingressRule.FromEndpoints, 1)
		assert.NotEmpty(t, ingressRule.FromEndpoints[0].LabelSelector)
		assert.Len(t, ingressRule.ToPorts, 1)
		assert.Equal(t, "8080", ingressRule.ToPorts[0].Ports[0].Port)

		// Check egress rules
		hasDBRule := false
		hasExternalRule := false
		for _, egressRule := range policy.Spec.Egress {
			if len(egressRule.ToEndpoints) > 0 {
				// Database service rule (using EndpointSelector)
				assert.NotEmpty(t, egressRule.ToEndpoints[0].LabelSelector)
				hasDBRule = true
			} else if len(egressRule.ToCIDR) > 0 {
				// External rule (using CIDR)
				assert.Contains(t, string(egressRule.ToCIDR[0]), "52.1.2.3/32")
				hasExternalRule = true
			}
		}
		assert.True(t, hasDBRule, "Should have database egress rule")
		assert.True(t, hasExternalRule, "Should have external egress rule")
	})

	// Verify both generators process the same traffic correctly
	t.Run("ConsistentTrafficProcessing", func(t *testing.T) {
		standardGen := NewStandardPolicyGenerator()
		ciliumGen := NewCiliumPolicyGenerator()

		stdResult, stdErr := standardGen.Generate("api-server", podTraffic, podDetail)
		ciliumResult, ciliumErr := ciliumGen.Generate("api-server", podTraffic, podDetail)

		assert.NoError(t, stdErr)
		assert.NoError(t, ciliumErr)

		// Both should generate policies with the same structure
		stdPolicy := stdResult.(*networkingv1.NetworkPolicy)
		ciliumPolicy := ciliumResult.(*ciliumv2.CiliumNetworkPolicy)

		// Same number of rules
		assert.Equal(t, len(stdPolicy.Spec.Ingress), len(ciliumPolicy.Spec.Ingress))
		assert.Equal(t, len(stdPolicy.Spec.Egress), len(ciliumPolicy.Spec.Egress))

		// Both target the same pod
		assert.Equal(t, stdPolicy.Spec.PodSelector.MatchLabels["app"], "api-server")
		assert.NotEmpty(t, ciliumPolicy.Spec.EndpointSelector.LabelSelector)
	})
}
