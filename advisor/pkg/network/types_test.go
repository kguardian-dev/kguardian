package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
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
