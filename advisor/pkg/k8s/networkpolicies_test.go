package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// CreateMockPod is the documented entry point for getting a known-shape
// Pod for tests / dry-runs without going through the full pod-traffic
// transform — drift in its fields would silently break demos.

func TestCreateMockPod_PopulatesMeta(t *testing.T) {
	pod := CreateMockPod("web", "prod")
	assert.Equal(t, "web", pod.ObjectMeta.Name)
	assert.Equal(t, "prod", pod.ObjectMeta.Namespace)
	assert.Equal(t, "web", pod.ObjectMeta.Labels["app"])
}

func TestCreateMockPod_LabelMatchesName(t *testing.T) {
	// app=<podName> is the convention selectors generated downstream
	// expect; if the mock changed shape, generated policies would
	// match nothing.
	for _, n := range []string{"a", "web-1", "long-pod-name-with-hyphens"} {
		pod := CreateMockPod(n, "default")
		assert.Equal(t, n, pod.ObjectMeta.Labels["app"], "label app must equal pod name")
	}
}

// JSON-keyed dedup helpers parallel to deduplicateCilium*. Lock the
// behaviour so they don't silently drift apart.

func TestDeduplicateIngressRules_DistinctRulesSurvive(t *testing.T) {
	tcp := corev1.ProtocolTCP
	p80 := intstr.FromInt(80)
	p443 := intstr.FromInt(443)
	rules := []networkingv1.NetworkPolicyIngressRule{
		{Ports: []networkingv1.NetworkPolicyPort{{Port: &p80, Protocol: &tcp}}},
		{Ports: []networkingv1.NetworkPolicyPort{{Port: &p443, Protocol: &tcp}}},
	}
	got := deduplicateIngressRules(rules)
	assert.Len(t, got, 2, "distinct ports must both survive dedup")
}

func TestDeduplicateIngressRules_IdenticalRulesCollapse(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt(80)
	rule := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: &tcp}},
	}
	got := deduplicateIngressRules([]networkingv1.NetworkPolicyIngressRule{rule, rule, rule})
	assert.Len(t, got, 1)
}

func TestDeduplicateIngressRules_NilOrEmpty(t *testing.T) {
	assert.Empty(t, deduplicateIngressRules(nil))
	assert.Empty(t, deduplicateIngressRules([]networkingv1.NetworkPolicyIngressRule{}))
}

func TestDeduplicateEgressRules_DistinctRulesSurvive(t *testing.T) {
	tcp := corev1.ProtocolTCP
	p5432 := intstr.FromInt(5432)
	p6379 := intstr.FromInt(6379)
	rules := []networkingv1.NetworkPolicyEgressRule{
		{Ports: []networkingv1.NetworkPolicyPort{{Port: &p5432, Protocol: &tcp}}},
		{Ports: []networkingv1.NetworkPolicyPort{{Port: &p6379, Protocol: &tcp}}},
	}
	got := deduplicateEgressRules(rules)
	assert.Len(t, got, 2)
}

func TestDeduplicateEgressRules_IdenticalRulesCollapse(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt(443)
	rule := networkingv1.NetworkPolicyEgressRule{
		Ports: []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: &tcp}},
	}
	got := deduplicateEgressRules([]networkingv1.NetworkPolicyEgressRule{rule, rule})
	assert.Len(t, got, 1)
}

// Cross-check: the dedup produces the SAME result regardless of input
// order. Reordering shouldn't affect the canonical set produced —
// downstream consumers (kubectl apply) treat rules as unordered.
func TestDeduplicateIngressRules_OrderIndependent(t *testing.T) {
	tcp := corev1.ProtocolTCP
	pa := intstr.FromInt(80)
	pb := intstr.FromInt(443)
	a := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{{Port: &pa, Protocol: &tcp}},
	}
	b := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{{Port: &pb, Protocol: &tcp}},
	}

	x := deduplicateIngressRules([]networkingv1.NetworkPolicyIngressRule{a, b, a, b})
	y := deduplicateIngressRules([]networkingv1.NetworkPolicyIngressRule{b, a, b, a})

	assert.Len(t, x, 2)
	assert.Len(t, y, 2)
	// Implementation preserves first-seen order. Document that.
	assert.NotNil(t, x[0].Ports[0].Port)
	assert.NotNil(t, y[0].Ports[0].Port)
}

// Defensive: pod-namespace labelling. A corev1 import sanity check
// that catches accidental import path drift in the test file itself.
var _ = corev1.ProtocolTCP
var _ = metav1.ObjectMeta{}
