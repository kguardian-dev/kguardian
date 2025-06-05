package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xentra-ai/advisor/pkg/api"
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
		"app.kubernetes.io/part-of":   "xentra-advisor",
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

	ingressTraffic := api.PodTraffic{DstIP: "192.168.1.100", SrcIP: "10.0.0.1"}
	assert.True(t, IsIngressTraffic(ingressTraffic, podDetail))

	egressTraffic := api.PodTraffic{SrcIP: "192.168.1.100", DstIP: "8.8.8.8"}
	assert.False(t, IsIngressTraffic(egressTraffic, podDetail))

	otherTraffic := api.PodTraffic{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	assert.False(t, IsIngressTraffic(otherTraffic, podDetail))
}

func TestIsEgressTraffic(t *testing.T) {
	podDetail := &api.PodDetail{PodIP: "192.168.1.100"}

	ingressTraffic := api.PodTraffic{DstIP: "192.168.1.100", SrcIP: "10.0.0.1"}
	assert.False(t, IsEgressTraffic(ingressTraffic, podDetail))

	egressTraffic := api.PodTraffic{SrcIP: "192.168.1.100", DstIP: "8.8.8.8"}
	assert.True(t, IsEgressTraffic(egressTraffic, podDetail))

	otherTraffic := api.PodTraffic{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	assert.False(t, IsEgressTraffic(otherTraffic, podDetail))
}
