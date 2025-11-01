package k8s

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// monkeyPatchGetFunction patches a function and returns a function to restore the original
//
//nolint:unused // Reserved for future testing use
func monkeyPatchGetFunction(original interface{}, replacement interface{}) func() {
	return func() {
		// In a real implementation, this would restore the original function
	}
}

func TestNewConfig(t *testing.T) {
	// Create a mock configFlags
	configFlags := genericclioptions.NewConfigFlags(true)

	// Mock the configFlags.ToRESTConfig function
	originalConfigFlagsToRESTConfig := configFlagsToRESTConfigFunc
	defer func() { configFlagsToRESTConfigFunc = originalConfigFlagsToRESTConfig }()

	configFlagsToRESTConfigFunc = func(configFlags *genericclioptions.ConfigFlags) (*rest.Config, error) {
		return &rest.Config{}, nil
	}

	// Mock the kubernetes.NewForConfig function
	originalK8sNewForConfig := kubernetesNewForConfigFunc
	defer func() { kubernetesNewForConfigFunc = originalK8sNewForConfig }()

	kubernetesNewForConfigFunc = func(c *rest.Config) (*kubernetes.Clientset, error) {
		return &kubernetes.Clientset{}, nil
	}

	// Test with configFlags
	config, err := NewConfig(configFlags)
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, configFlags, config.ConfigFlags)
}

func setupKubeconfigDirectory(t *testing.T) (string, string) {
	// Setup temporary kubeconfig file
	tempDir := t.TempDir()
	kubeconfigPath := filepath.Join(tempDir, "config")

	// Create the .kube directory
	kubeDir := filepath.Join(tempDir, ".kube")
	err := os.MkdirAll(kubeDir, 0755)
	assert.NoError(t, err)

	kubeConfigPath := filepath.Join(kubeDir, "config")

	// Write valid kubeconfig content
	validKubeconfig := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://example.com
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
    namespace: test-namespace
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	// Write to both locations
	err = os.WriteFile(kubeconfigPath, []byte(validKubeconfig), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(kubeConfigPath, []byte(validKubeconfig), 0644)
	assert.NoError(t, err)

	return tempDir, kubeconfigPath
}

func TestGetConfig(t *testing.T) {
	tempDir, kubeconfigPath := setupKubeconfigDirectory(t)

	// Save and restore environment variables
	oldHome := os.Getenv("HOME")
	oldKubeconfig := os.Getenv("KUBECONFIG")
	defer func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.Setenv("KUBECONFIG", oldKubeconfig)
	}()

	// Setup HOME for default kubeconfig path
	_ = os.Setenv("HOME", tempDir)

	// Mock ALL the necessary functions
	originalStat := osStatFunc
	defer func() { osStatFunc = originalStat }()

	osStatFunc = func(path string) (os.FileInfo, error) {
		// Return a mock FileInfo that shows the file exists
		return &mockFileInfo{}, nil
	}

	// Mock rest.InClusterConfig function
	originalInClusterConfig := inClusterConfigFunc
	defer func() { inClusterConfigFunc = originalInClusterConfig }()

	inClusterConfigFunc = func() (*rest.Config, error) {
		return nil, assert.AnError // Simulate not running in cluster
	}

	// Mock client creation function
	originalK8sNewForConfig := kubernetesNewForConfigFunc
	defer func() { kubernetesNewForConfigFunc = originalK8sNewForConfig }()

	kubernetesNewForConfigFunc = func(c *rest.Config) (*kubernetes.Clientset, error) {
		return &kubernetes.Clientset{}, nil
	}

	// Mock buildConfigFromFlags function
	originalBuildConfigFromFlags := buildConfigFromFlagsFunc
	defer func() { buildConfigFromFlagsFunc = originalBuildConfigFromFlags }()

	buildConfigFromFlagsFunc = func(masterUrl, kubeconfigPath string) (*rest.Config, error) {
		return &rest.Config{}, nil
	}

	// Mock nodeList function for connectivity check
	originalNodeList := listNodesFunc
	defer func() { listNodesFunc = originalNodeList }()

	// Mock node list to avoid actual API calls
	listNodesFunc = func(clientset *kubernetes.Clientset) (*corev1.NodeList, error) {
		// Return a mock node list with no error to simulate success
		return &corev1.NodeList{
			Items: []corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-node",
					},
				},
			},
		}, nil
	}

	// Mock clientcmd.NewNonInteractiveDeferredLoadingClientConfig
	originalLoadingClientConfig := nonInteractiveDeferredLoadingClientConfigFunc
	defer func() { nonInteractiveDeferredLoadingClientConfigFunc = originalLoadingClientConfig }()

	nonInteractiveDeferredLoadingClientConfigFunc = func(
		loadingRules *clientcmd.ClientConfigLoadingRules,
		overrides *clientcmd.ConfigOverrides) clientcmd.ClientConfig {
			return &testClientConfig{namespace: "test-namespace"}
	}

	// Test with KUBECONFIG env var
	_ = os.Setenv("KUBECONFIG", kubeconfigPath)
	config, err := GetConfig(false)
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Test with default path
	_ = os.Unsetenv("KUBECONFIG")
	config, err = GetConfig(false)
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Test in-cluster configuration
	inClusterConfigFunc = func() (*rest.Config, error) {
		return &rest.Config{}, nil // Simulate running in cluster
	}
	config, err = GetConfig(false)
	assert.NoError(t, err)
	assert.NotNil(t, config)
}

func TestGetCurrentNamespace(t *testing.T) {
	// Create a minimal config for testing
	config := &Config{
		Clientset: &kubernetes.Clientset{},
		Config:    &rest.Config{},
	}

	// Save and restore any real environment variables
	oldPodNamespace := os.Getenv("POD_NAMESPACE")
	oldKubeconfig := os.Getenv("KUBECONFIG")
	oldHome := os.Getenv("HOME")
	defer func() {
		_ = os.Setenv("POD_NAMESPACE", oldPodNamespace)
		_ = os.Setenv("KUBECONFIG", oldKubeconfig)
		_ = os.Setenv("HOME", oldHome)
	}()

	// Clear environment variables
	_ = os.Unsetenv("POD_NAMESPACE")
	_ = os.Unsetenv("KUBECONFIG")

	// Setup temp directory with kubeconfig
	tempDir, _ := setupKubeconfigDirectory(t)
	_ = os.Setenv("HOME", tempDir)

	// Mock os.Stat to ensure kubeconfig file is found
	originalStat := osStatFunc
	defer func() { osStatFunc = originalStat }()

	osStatFunc = func(path string) (os.FileInfo, error) {
		// Return a mock FileInfo that shows the file exists
		return &mockFileInfo{}, nil
	}

	// Mock clientcmd.NewNonInteractiveDeferredLoadingClientConfig
	originalLoadingClientConfig := nonInteractiveDeferredLoadingClientConfigFunc
	defer func() { nonInteractiveDeferredLoadingClientConfigFunc = originalLoadingClientConfig }()

	nonInteractiveDeferredLoadingClientConfigFunc = func(
		loadingRules *clientcmd.ClientConfigLoadingRules,
		overrides *clientcmd.ConfigOverrides) clientcmd.ClientConfig {
			return &testClientConfig{namespace: "default"}
	}

	// Test the GetCurrentNamespace function
	namespace, err := GetCurrentNamespace(config)
	assert.NoError(t, err)
	assert.Equal(t, "default", namespace)

	// Test with POD_NAMESPACE environment variable
	_ = os.Setenv("POD_NAMESPACE", "test-namespace")
	namespace, err = GetCurrentNamespace(config)
	assert.NoError(t, err)
	assert.Equal(t, "test-namespace", namespace)
}

// Test implementation of clientcmd.ClientConfig
type testClientConfig struct {
	namespace string
}

func (t *testClientConfig) RawConfig() (clientcmdapi.Config, error) {
	return clientcmdapi.Config{}, nil
}

func (t *testClientConfig) ClientConfig() (*rest.Config, error) {
	return &rest.Config{}, nil
}

func (t *testClientConfig) Namespace() (string, bool, error) {
	return t.namespace, true, nil
}

func (t *testClientConfig) ConfigAccess() clientcmd.ConfigAccess {
	return nil
}

// Mock FileInfo implementation
type mockFileInfo struct{}

func (m *mockFileInfo) Name() string       { return "mockfile" }
func (m *mockFileInfo) Size() int64        { return 100 }
func (m *mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() interface{}   { return nil }
