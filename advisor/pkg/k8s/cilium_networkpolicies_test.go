package k8s

import (
	"testing"

	api "github.com/cilium/cilium/pkg/policy/api"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/stretchr/testify/assert"
)

// createMockCiliumNetworkPolicy builds a synthetic policy for tests
// and CLI dry-runs. It's the only documented entry point for getting
// a known-shape CiliumNetworkPolicy without going through the full
// pod-traffic transform — drift here would silently break demos and
// CLI smoke checks.

func TestCreateMockCiliumNetworkPolicy_HasCorrectMeta(t *testing.T) {
	got := createMockCiliumNetworkPolicy("web", "prod")

	assert.Equal(t, "CiliumNetworkPolicy", got.TypeMeta.Kind)
	assert.Equal(t, "cilium.io/v2", got.TypeMeta.APIVersion)
	assert.Equal(t, "web-policy", got.ObjectMeta.Name)
	assert.Equal(t, "prod", got.ObjectMeta.Namespace)
}

func TestCreateMockCiliumNetworkPolicy_EndpointSelectorMatchesPodName(t *testing.T) {
	got := createMockCiliumNetworkPolicy("web", "prod")
	if got.Spec == nil {
		t.Fatal("Spec must not be nil")
	}
	assert.NotNil(t, got.Spec.EndpointSelector.LabelSelector)
	assert.Equal(t, "web", got.Spec.EndpointSelector.LabelSelector.MatchLabels["app"])
}

func TestCreateMockCiliumNetworkPolicy_BothDirectionsPopulated(t *testing.T) {
	got := createMockCiliumNetworkPolicy("web", "prod")
	if assert.Len(t, got.Spec.Ingress, 1) {
		ing := got.Spec.Ingress[0]
		assert.Len(t, ing.FromEndpoints, 1)
		assert.Len(t, ing.ToPorts, 1)
	}
	if assert.Len(t, got.Spec.Egress, 1) {
		eg := got.Spec.Egress[0]
		assert.Len(t, eg.ToEndpoints, 1)
		assert.Len(t, eg.ToPorts, 1)
	}
}

// Dedup helpers serialise via json.Marshal and key on the resulting
// string. Identical rules collapse; semantically distinct ones survive.

func TestDeduplicateCiliumIngressRules_KeepsDistinctRules(t *testing.T) {
	rules := []api.IngressRule{
		{IngressCommonRule: api.IngressCommonRule{
			FromEndpoints: []api.EndpointSelector{{
				LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "client-a"}},
			}},
		}},
		{IngressCommonRule: api.IngressCommonRule{
			FromEndpoints: []api.EndpointSelector{{
				LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "client-b"}},
			}},
		}},
	}
	got := deduplicateCiliumIngressRules(rules)
	assert.Len(t, got, 2, "distinct peer selectors must both survive")
}

func TestDeduplicateCiliumIngressRules_CollapsesDuplicates(t *testing.T) {
	dup := api.IngressRule{
		IngressCommonRule: api.IngressCommonRule{
			FromEndpoints: []api.EndpointSelector{{
				LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			}},
		},
	}
	got := deduplicateCiliumIngressRules([]api.IngressRule{dup, dup, dup})
	assert.Len(t, got, 1, "byte-identical rules must collapse to one")
}

func TestDeduplicateCiliumIngressRules_EmptyAndNil(t *testing.T) {
	// Implementation returns nil (not []api.IngressRule{}) when the
	// input is nil/empty. Document either contract — what matters is
	// no panic and a 0-length result.
	assert.Empty(t, deduplicateCiliumIngressRules(nil))
	assert.Empty(t, deduplicateCiliumIngressRules([]api.IngressRule{}))
}

func TestDeduplicateCiliumEgressRules_KeepsDistinctRules(t *testing.T) {
	rules := []api.EgressRule{
		{EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{{
				LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			}},
		}},
		{EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{{
				LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "cache"}},
			}},
		}},
	}
	got := deduplicateCiliumEgressRules(rules)
	assert.Len(t, got, 2)
}

func TestDeduplicateCiliumEgressRules_CollapsesDuplicates(t *testing.T) {
	dup := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{{
				LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			}},
		},
	}
	got := deduplicateCiliumEgressRules([]api.EgressRule{dup, dup})
	assert.Len(t, got, 1)
}
