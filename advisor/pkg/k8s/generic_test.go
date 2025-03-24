package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetResource(t *testing.T) {
	// Create test config - use nil to trigger the test mode paths
	// in the fetchXXX functions
	var config *Config = nil

	// Test SinglePod mode
	options := GenerateOptions{
		Mode:      SinglePod,
		PodName:   "test-pod",
		Namespace: "test-namespace",
	}

	pods := GetResource(options, config)
	assert.Len(t, pods, 1)
	assert.Equal(t, "test-pod", pods[0].Name)
	assert.Equal(t, "test-namespace", pods[0].Namespace)

	// Test AllPodsInNamespace mode
	options = GenerateOptions{
		Mode:      AllPodsInNamespace,
		Namespace: "test-namespace",
	}

	pods = GetResource(options, config)
	assert.Len(t, pods, 2)
	assert.Equal(t, "test-pod-1", pods[0].Name)
	assert.Equal(t, "test-pod-2", pods[1].Name)
	assert.Equal(t, "test-namespace", pods[0].Namespace)

	// Test AllPodsInAllNamespaces mode
	options = GenerateOptions{
		Mode: AllPodsInAllNamespaces,
	}

	pods = GetResource(options, config)
	assert.Len(t, pods, 2)
	assert.Equal(t, "test-pod-1", pods[0].Name)
	assert.Equal(t, "test-namespace-1", pods[0].Namespace)
	assert.Equal(t, "test-pod-2", pods[1].Name)
	assert.Equal(t, "test-namespace-2", pods[1].Namespace)
}
