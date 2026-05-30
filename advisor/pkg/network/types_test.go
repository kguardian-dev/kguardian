package network

import (
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetPolicyName(t *testing.T) {
	assert.Equal(t, "test-pod-standard-policy", GetPolicyName("test-pod", "standard-policy"))
	assert.Equal(t, "another-pod-cilium-policy", GetPolicyName("another-pod", "cilium-policy"))
}

func TestCreateStandardLabels(t *testing.T) {
	expected := map[string]string{
		"app.kubernetes.io/name":      "my-pod",
		"app.kubernetes.io/component": "networkpolicy",
		"app.kubernetes.io/part-of":   "kguardian",
	}
	assert.Equal(t, expected, CreateStandardLabels("my-pod", "networkpolicy"))
}

func TestCreateTypeMeta(t *testing.T) {
	expected := metav1.TypeMeta{
		Kind:       "NetworkPolicy",
		APIVersion: "networking.k8s.io/v1",
	}
	assert.Equal(t, expected, CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"))
}

func TestCreateObjectMeta(t *testing.T) {
	labels := map[string]string{"app": "test"}
	expected := metav1.ObjectMeta{
		Name:      "test-name",
		Namespace: "test-ns",
		Labels:    labels,
	}
	assert.Equal(t, expected, CreateObjectMeta("test-name", "test-ns", labels))
}

func TestIsIngressTraffic(t *testing.T) {
	podDetail := &api.PodDetail{PodIP: "192.168.1.100"}

	ingressTraffic := api.PodTraffic{TrafficType: "INGRESS"}
	assert.True(t, IsIngressTraffic(ingressTraffic, podDetail))

	egressTraffic := api.PodTraffic{TrafficType: "EGRESS"}
	assert.False(t, IsIngressTraffic(egressTraffic, podDetail))

	otherTraffic := api.PodTraffic{TrafficType: "OTHER"}
	assert.False(t, IsIngressTraffic(otherTraffic, podDetail))
}

func TestIsEgressTraffic(t *testing.T) {
	podDetail := &api.PodDetail{PodIP: "192.168.1.100"}

	ingressTraffic := api.PodTraffic{TrafficType: "INGRESS"}
	assert.False(t, IsEgressTraffic(ingressTraffic, podDetail))

	egressTraffic := api.PodTraffic{TrafficType: "EGRESS"}
	assert.True(t, IsEgressTraffic(egressTraffic, podDetail))

	otherTraffic := api.PodTraffic{TrafficType: "OTHER"}
	assert.False(t, IsEgressTraffic(otherTraffic, podDetail))
}

func TestIsIngressTraffic_CaseInsensitive(t *testing.T) {
	// Pre-fix the comparison was strict ==, so a future writer
	// emitting "Ingress" or "ingress" would have been silently
	// classified as neither ingress nor egress — generating a
	// policy with zero matched rules. Same bug class as the
	// mcp-server case-mismatch. Pin every realistic spelling.
	podDetail := &api.PodDetail{PodIP: "192.168.1.100"}
	for _, spelling := range []string{"INGRESS", "ingress", "Ingress", "iNgReSs"} {
		assert.True(t, IsIngressTraffic(api.PodTraffic{TrafficType: spelling}, podDetail),
			"TrafficType=%q must classify as ingress (case-insensitive)", spelling)
	}
	// And ensure egress spellings DON'T match ingress.
	for _, spelling := range []string{"EGRESS", "egress", "Egress"} {
		assert.False(t, IsIngressTraffic(api.PodTraffic{TrafficType: spelling}, podDetail),
			"TrafficType=%q must NOT classify as ingress", spelling)
	}
}

func TestIsEgressTraffic_CaseInsensitive(t *testing.T) {
	podDetail := &api.PodDetail{PodIP: "192.168.1.100"}
	for _, spelling := range []string{"EGRESS", "egress", "Egress", "eGrEsS"} {
		assert.True(t, IsEgressTraffic(api.PodTraffic{TrafficType: spelling}, podDetail),
			"TrafficType=%q must classify as egress (case-insensitive)", spelling)
	}
	for _, spelling := range []string{"INGRESS", "ingress", "Ingress"} {
		assert.False(t, IsEgressTraffic(api.PodTraffic{TrafficType: spelling}, podDetail),
			"TrafficType=%q must NOT classify as egress", spelling)
	}
}
