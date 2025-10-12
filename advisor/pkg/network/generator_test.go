package network

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xentra-ai/advisor/pkg/api"
	"github.com/xentra-ai/advisor/pkg/common"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// --- Mock Implementations ---

type mockConfigProvider struct {
	clientset interface{}
	dryRun    bool
	outputDir string
}

func (m *mockConfigProvider) GetClientset() interface{} { return m.clientset }
func (m *mockConfigProvider) IsDryRun() bool            { return m.dryRun }
func (m *mockConfigProvider) GetOutputDir() string      { return m.outputDir }

type mockPolicyGenerator struct {
	policyType PolicyType
	policy     interface{}
	genError   error
}

func (m *mockPolicyGenerator) Generate(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, error) {
	if m.genError != nil {
		return nil, m.genError
	}
	// Return a simple mock policy object for testing purposes
	// We can make this more specific if needed for certain tests
	if m.policy != nil {
		return m.policy, nil
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%s-policy", podName, m.policyType)},
	}, nil
}
func (m *mockPolicyGenerator) GetType() PolicyType { return m.policyType }

func newTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test-pod",
			},
			UID: "12345",
		},
		Status: corev1.PodStatus{
			PodIP: "192.168.1.10",
		},
	}
}

// --- Test Cases ---

func TestNewPolicyService(t *testing.T) {
	config := &mockConfigProvider{}
	service := NewPolicyService(config, StandardPolicy)
	assert.NotNil(t, service)
	assert.Equal(t, config, service.config)
	assert.NotNil(t, service.generators)
	assert.Equal(t, StandardPolicy, service.defaultType)
}

func TestRegisterGenerator(t *testing.T) {
	service := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	stdGen := &mockPolicyGenerator{policyType: StandardPolicy}
	ciliumGen := &mockPolicyGenerator{policyType: CiliumPolicy}

	service.RegisterGenerator(stdGen)
	service.RegisterGenerator(ciliumGen)

	assert.Equal(t, stdGen, service.generators[StandardPolicy])
	assert.Equal(t, ciliumGen, service.generators[CiliumPolicy])
}

func TestGeneratePolicy_Success(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodTrafficFunc := api.GetPodTrafficFunc
	origGetPodSpecFunc := api.GetPodSpecFunc
	defer func() {
		api.GetPodTrafficFunc = origGetPodTrafficFunc
		api.GetPodSpecFunc = origGetPodSpecFunc
	}()

	mockPodTraffic := []api.PodTraffic{{SrcIP: "192.168.1.10"}}
	mockPodDetail := &api.PodDetail{Name: "test-pod", Namespace: "default"}

	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		assert.Equal(t, "test-pod", podName)
		return mockPodTraffic, nil
	}
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		assert.Equal(t, "192.168.1.10", ip)
		return mockPodDetail, nil
	}

	mockGen := &mockPolicyGenerator{policyType: StandardPolicy}
	service := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	service.RegisterGenerator(mockGen)
	// --- End Mocks ---

	output, err := service.GeneratePolicy(newTestPod(), StandardPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, StandardPolicy, output.Type)
	assert.Equal(t, "test-pod", output.PodName)
	assert.Equal(t, "default", output.Namespace)
	assert.NotNil(t, output.Policy)
	assert.NotEmpty(t, output.YAML)

	// Check if YAML is valid (basic check)
	var checkPolicy interface{}
	errYAML := yaml.Unmarshal(output.YAML, &checkPolicy)
	assert.NoError(t, errYAML)
}

func TestGeneratePolicy_ApiErrors(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodTrafficFunc := api.GetPodTrafficFunc
	origGetPodSpecFunc := api.GetPodSpecFunc
	defer func() {
		api.GetPodTrafficFunc = origGetPodTrafficFunc
		api.GetPodSpecFunc = origGetPodSpecFunc
	}()

	mockGen := &mockPolicyGenerator{policyType: StandardPolicy}
	service := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	service.RegisterGenerator(mockGen)
	// --- End Mocks ---

	// Test GetPodTraffic error
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return nil, assert.AnError
	}
	_, err := service.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.Error(t, err)

	// Restore GetPodTraffic, test GetPodSpec error
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{{SrcIP: "192.168.1.10"}}, nil
	}
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		return nil, assert.AnError
	}
	output, err := service.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Test PodDetail not found
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		return nil, nil // Not found, not an error
	}
	output, err = service.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Test No Traffic Data
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{}, nil // Empty slice
	}
	output, err = service.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestGeneratePolicy_GeneratorError(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodTrafficFunc := api.GetPodTrafficFunc
	origGetPodSpecFunc := api.GetPodSpecFunc
	defer func() {
		api.GetPodTrafficFunc = origGetPodTrafficFunc
		api.GetPodSpecFunc = origGetPodSpecFunc
	}()
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{{SrcIP: "192.168.1.10"}}, nil
	}
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		return &api.PodDetail{Name: "test-pod", Namespace: "default"}, nil
	}

	mockGenError := &mockPolicyGenerator{
		policyType: StandardPolicy,
		genError:   assert.AnError, // Simulate generator error
	}
	service := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	service.RegisterGenerator(mockGenError)
	// --- End Mocks ---

	_, err := service.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}

func TestGeneratePolicy_NoGeneratorFallback(t *testing.T) {
	// --- Setup Mocks ---
	origGetPodTrafficFunc := api.GetPodTrafficFunc
	origGetPodSpecFunc := api.GetPodSpecFunc
	defer func() {
		api.GetPodTrafficFunc = origGetPodTrafficFunc
		api.GetPodSpecFunc = origGetPodSpecFunc
	}()
	api.GetPodTrafficFunc = func(podName string) ([]api.PodTraffic, error) {
		return []api.PodTraffic{{SrcIP: "192.168.1.10"}}, nil
	}
	api.GetPodSpecFunc = func(ip string) (*api.PodDetail, error) {
		return &api.PodDetail{Name: "test-pod", Namespace: "default"}, nil
	}

	// Service with only Cilium generator registered
	mockCiliumGen := &mockPolicyGenerator{policyType: CiliumPolicy}
	service := NewPolicyService(&mockConfigProvider{}, CiliumPolicy) // Default is Cilium
	service.RegisterGenerator(mockCiliumGen)
	// --- End Mocks ---

	// Request Standard, should fall back to default (Cilium)
	output, err := service.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, CiliumPolicy, output.Type) // Check it used the fallback

	// Test case where NO generator is available (even default)
	serviceNoGen := NewPolicyService(&mockConfigProvider{}, StandardPolicy)
	_, err = serviceNoGen.GeneratePolicy(newTestPod(), StandardPolicy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no generator available")
}

func TestHandlePolicyOutput_DryRunNoDir(t *testing.T) {
	// --- Setup Mocks ---
	origCommonPrint := common.PrintDryRunMessageFunc // Use exported func var
	printCalled := false
	common.PrintDryRunMessageFunc = func(resourceType, name string, content []byte, outputDir string) {
		printCalled = true
		assert.Equal(t, "standard-networkpolicy", resourceType)
		assert.Equal(t, "test-pod", name)
		assert.NotEmpty(t, content)
		assert.Empty(t, outputDir)
	}
	defer func() { common.PrintDryRunMessageFunc = origCommonPrint }()

	mockConfig := &mockConfigProvider{dryRun: true, outputDir: ""}
	service := NewPolicyService(mockConfig, StandardPolicy)

	output := &PolicyOutput{
		PodName:   "test-pod",
		Namespace: "default",
		Type:      StandardPolicy,
		YAML:      []byte("kind: NetworkPolicy"),
	}
	// --- End Mocks ---

	err := service.HandlePolicyOutput(output)
	assert.NoError(t, err)
	assert.True(t, printCalled)
}

func TestHandlePolicyOutput_DryRunSaveFile(t *testing.T) {
	// --- Setup Mocks ---
	origCommonPrint := common.PrintDryRunMessageFunc // Use exported func var
	printCalled := false
	common.PrintDryRunMessageFunc = func(resourceType, name string, content []byte, outputDir string) {
		printCalled = true
		assert.Equal(t, "test-dir", outputDir)
	}
	defer func() { common.PrintDryRunMessageFunc = origCommonPrint }()

	origCommonSave := common.SaveToFileFunc // Use exported func var
	saveCalled := false
	common.SaveToFileFunc = func(outputDir, resourceType, namespace, name string, content []byte) (string, error) {
		saveCalled = true
		assert.Equal(t, "test-dir", outputDir)
		assert.Equal(t, "standard-networkpolicy", resourceType)
		assert.Equal(t, "default", namespace)
		assert.Equal(t, "test-pod", name)
		assert.Equal(t, []byte("kind: NetworkPolicy"), content)
		return "test-dir/file.yaml", nil
	}
	defer func() { common.SaveToFileFunc = origCommonSave }()

	mockConfig := &mockConfigProvider{dryRun: true, outputDir: "test-dir"}
	service := NewPolicyService(mockConfig, StandardPolicy)

	output := &PolicyOutput{
		PodName:   "test-pod",
		Namespace: "default",
		Type:      StandardPolicy,
		YAML:      []byte("kind: NetworkPolicy"),
	}
	// --- End Mocks ---

	err := service.HandlePolicyOutput(output)
	assert.NoError(t, err)
	assert.True(t, saveCalled)
	assert.True(t, printCalled)
}

func TestHandlePolicyOutput_ApplyMode(t *testing.T) {
	// --- Setup Mocks ---
	origCommonPrint := common.PrintDryRunMessageFunc // Use exported func var
	printCalled := false
	common.PrintDryRunMessageFunc = func(resourceType, name string, content []byte, outputDir string) {
		printCalled = true // Should NOT be called
	}
	defer func() { common.PrintDryRunMessageFunc = origCommonPrint }()

	origCommonSave := common.SaveToFileFunc // Use exported func var
	saveCalled := false
	common.SaveToFileFunc = func(outputDir, resourceType, namespace, name string, content []byte) (string, error) {
		saveCalled = true
		return "test-dir/file.yaml", nil
	}
	defer func() { common.SaveToFileFunc = origCommonSave }()

	mockConfig := &mockConfigProvider{dryRun: false, outputDir: "test-dir"}
	service := NewPolicyService(mockConfig, StandardPolicy)

	output := &PolicyOutput{
		PodName:   "test-pod",
		Namespace: "default",
		Type:      StandardPolicy,
		YAML:      []byte("kind: NetworkPolicy"),
	}
	// --- End Mocks ---

	err := service.HandlePolicyOutput(output)
	assert.NoError(t, err)
	assert.True(t, saveCalled)
	assert.False(t, printCalled)
	// TODO: Add assertions for Apply logic when implemented
}

func TestHandlePolicyOutput_SaveError(t *testing.T) {
	// --- Setup Mocks ---
	origCommonSave := common.SaveToFileFunc // Use exported func var
	common.SaveToFileFunc = func(outputDir, resourceType, namespace, name string, content []byte) (string, error) {
		return "", assert.AnError // Simulate save error
	}
	defer func() { common.SaveToFileFunc = origCommonSave }()

	mockConfig := &mockConfigProvider{dryRun: true, outputDir: "test-dir"}
	service := NewPolicyService(mockConfig, StandardPolicy)
	output := &PolicyOutput{YAML: []byte("test")}
	// --- End Mocks ---

	err := service.HandlePolicyOutput(output)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}

func TestInitOutputDirectory(t *testing.T) {
	// --- Setup Mocks ---
	origHandleDir := common.HandleOutputDirFunc // Use exported func var
	handleDirCalled := false
	var capturedDir string
	common.HandleOutputDirFunc = func(outputDir, resourceTypePlural string) error {
		handleDirCalled = true
		capturedDir = outputDir
		assert.Equal(t, "Network policies", resourceTypePlural)
		return nil
	}
	defer func() { common.HandleOutputDirFunc = origHandleDir }()
	// --- End Mocks ---

	// Test with dir
	mockConfigWithDir := &mockConfigProvider{outputDir: "out"}
	serviceWithDir := NewPolicyService(mockConfigWithDir, StandardPolicy)
	err := serviceWithDir.InitOutputDirectory()
	assert.NoError(t, err)
	assert.True(t, handleDirCalled)
	assert.Equal(t, "out", capturedDir)

	// Test without dir
	handleDirCalled = false // Reset flag
	mockConfigNoDir := &mockConfigProvider{outputDir: ""}
	serviceNoDir := NewPolicyService(mockConfigNoDir, StandardPolicy)
	err = serviceNoDir.InitOutputDirectory()
	assert.NoError(t, err)
	assert.True(t, handleDirCalled)
	assert.Equal(t, "", capturedDir)

	// Test HandleOutputDir error
	common.HandleOutputDirFunc = func(outputDir, resourceTypePlural string) error {
		return assert.AnError
	}
	err = serviceWithDir.InitOutputDirectory()
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}

// Note: Tests for GenerateAndHandlePolicy and BatchGenerateAndHandlePolicies
// would primarily test the flow control and error handling by combining mocks
// for GeneratePolicy and HandlePolicyOutput. They are omitted here for brevity
// but should be added for full coverage.
