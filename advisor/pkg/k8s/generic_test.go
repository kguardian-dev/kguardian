package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Helper function to create a mock pod for testing
func createMockPodForTest(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		// Add other necessary fields if needed by the code under test
	}
}

func TestGetResource(t *testing.T) {
	// Create a minimal non-nil config. No real clientset needed as we mock the funcs.
	config := &Config{}

	// --- Save original functions and defer restoration ---
	origGetPodFunc := getPodFunc
	origGetPodsInNamespaceFunc := getPodsInNamespaceFunc
	origGetAllPodsInAllNamespacesFunc := getAllPodsInAllNamespacesFunc
	defer func() {
		getPodFunc = origGetPodFunc
		getPodsInNamespaceFunc = origGetPodsInNamespaceFunc
		getAllPodsInAllNamespacesFunc = origGetAllPodsInAllNamespacesFunc
	}()
	// --- End save/restore ---

	// --- Test SinglePod mode ---
	optionsSingle := GenerateOptions{
		Mode:      SinglePod,
		PodName:   "test-pod",
		Namespace: "test-namespace",
	}
	// Mock GetPod for this case
	getPodFunc = func(ctx context.Context, cfg *Config, ns, name string) (*corev1.Pod, error) {
		assert.Equal(t, "test-namespace", ns)
		assert.Equal(t, "test-pod", name)
		return createMockPodForTest(name, ns), nil
	}
	podsSingle := GetResource(optionsSingle, config)
	assert.Len(t, podsSingle, 1)
	assert.Equal(t, "test-pod", podsSingle[0].Name)
	assert.Equal(t, "test-namespace", podsSingle[0].Namespace)
	// --- End Test SinglePod mode ---

	// --- Test AllPodsInNamespace mode ---
	optionsNamespace := GenerateOptions{
		Mode:      AllPodsInNamespace,
		Namespace: "test-namespace",
	}
	// Mock GetPodsInNamespace for this case
	getPodsInNamespaceFunc = func(ctx context.Context, cfg *Config, ns string) ([]corev1.Pod, error) {
		assert.Equal(t, "test-namespace", ns)
		return []corev1.Pod{
			*createMockPodForTest("test-pod-1", ns),
			*createMockPodForTest("test-pod-2", ns),
		}, nil
	}
	podsNamespace := GetResource(optionsNamespace, config)
	assert.Len(t, podsNamespace, 2)
	assert.Equal(t, "test-pod-1", podsNamespace[0].Name)
	assert.Equal(t, "test-pod-2", podsNamespace[1].Name)
	assert.Equal(t, "test-namespace", podsNamespace[0].Namespace)
	// --- End Test AllPodsInNamespace mode ---

	// --- Test AllPodsInAllNamespaces mode ---
	optionsAll := GenerateOptions{
		Mode: AllPodsInAllNamespaces,
	}
	// Mock GetAllPodsInAllNamespaces for this case
	getAllPodsInAllNamespacesFunc = func(ctx context.Context, cfg *Config) ([]corev1.Pod, error) {
		return []corev1.Pod{
			*createMockPodForTest("test-pod-a", "ns-a"),
			*createMockPodForTest("test-pod-b", "ns-b"),
		}, nil
	}
	podsAll := GetResource(optionsAll, config)
	assert.Len(t, podsAll, 2)
	assert.Equal(t, "test-pod-a", podsAll[0].Name)
	assert.Equal(t, "ns-a", podsAll[0].Namespace)
	assert.Equal(t, "test-pod-b", podsAll[1].Name)
	assert.Equal(t, "ns-b", podsAll[1].Namespace)
	// --- End Test AllPodsInAllNamespaces mode ---

	// --- Test Error Handling (Example for SinglePod) ---
	getPodFunc = func(ctx context.Context, cfg *Config, ns, name string) (*corev1.Pod, error) {
		return nil, assert.AnError // Simulate an error
	}
	// Assert that an empty slice is returned on error now
	podsError := GetResource(optionsSingle, config)
	assert.Empty(t, podsError, "Expected empty slice on GetPod error")

	// Add similar error tests for other modes if needed (they currently return empty slices, not panic)
	// --- End Test Error Handling ---
}
