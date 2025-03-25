package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ConfigKey is used to store/retrieve *Config in context
type contextKey string

const ConfigKey contextKey = "k8sConfig"

// Config holds the Kubernetes configuration
type Config struct {
	Clientset   *kubernetes.Clientset
	ConfigFlags *genericclioptions.ConfigFlags
	Config      *rest.Config
	DryRun      bool
	OutputDir   string
}

// Function variables for testing
var (
	osStatFunc = func(path string) (os.FileInfo, error) {
		return os.Stat(path)
	}

	nonInteractiveDeferredLoadingClientConfigFunc = func(
		loadingRules *clientcmd.ClientConfigLoadingRules,
		overrides *clientcmd.ConfigOverrides) clientcmd.ClientConfig {
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	}

	configFlagsToRESTConfigFunc = func(configFlags *genericclioptions.ConfigFlags) (*rest.Config, error) {
		return configFlags.ToRESTConfig()
	}

	kubernetesNewForConfigFunc = func(c *rest.Config) (*kubernetes.Clientset, error) {
		return kubernetes.NewForConfig(c)
	}

	buildConfigFromFlagsFunc = func(masterUrl, kubeconfigPath string) (*rest.Config, error) {
		return clientcmd.BuildConfigFromFlags(masterUrl, kubeconfigPath)
	}

	inClusterConfigFunc = func() (*rest.Config, error) {
		return rest.InClusterConfig()
	}

	newDefaultClientConfigLoadingRulesFunc = func() *clientcmd.ClientConfigLoadingRules {
		return clientcmd.NewDefaultClientConfigLoadingRules()
	}

	listNodesFunc = func(clientset *kubernetes.Clientset) (*corev1.NodeList, error) {
		return clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{Limit: 1})
	}
)

// NewConfig returns a new Config struct initialized with a Kubernetes client
// This method is used when running as a kubectl plugin, where the ConfigFlags are provided
func NewConfig(configFlags *genericclioptions.ConfigFlags) (*Config, error) {
	config, err := configFlagsToRESTConfigFunc(configFlags)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetesNewForConfigFunc(config)
	if err != nil {
		return nil, err
	}

	return &Config{
		Clientset:   clientset,
		ConfigFlags: configFlags,
		Config:      config,
	}, nil
}

// GetConfig creates a new Kubernetes client configuration
// It attempts to load the configuration from:
// 1. In-cluster configuration (when running inside a pod)
// 2. Kubeconfig file specified by KUBECONFIG environment variable
// 3. Default kubeconfig at ~/.kube/config
// This method is used when running as a standalone application (not as kubectl plugin)
func GetConfig(dryRun bool) (*Config, error) {
	var config *rest.Config
	var err error
	var kubeconfigPath string // Declare this at the function scope

	// Try to use in-cluster config first
	config, err = inClusterConfigFunc()
	if err != nil {
		log.Debug().Msg("Not running in cluster, falling back to kubeconfig file")

		// Get the kubeconfig file path
		kubeconfigPath = os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get user home directory: %w", err)
			}
			kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
		}

		// Log the kubeconfig path we're using
		log.Info().Msgf("Using kubeconfig file: %s", kubeconfigPath)

		// Check if the kubeconfig file exists
		if _, err := osStatFunc(kubeconfigPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("kubeconfig file not found at %s: %w", kubeconfigPath, err)
		}

		// Load the kubeconfig file
		config, err = buildConfigFromFlagsFunc("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig file: %w", err)
		}
	} else {
		// We're running in-cluster
		log.Info().Msg("Running with in-cluster Kubernetes configuration")

		// Still get a kubeconfigPath for potential context information
		kubeconfigPath = os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			homeDir, err := os.UserHomeDir()
			if err == nil {
				kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
			}
		}
	}

	// Create the clientset
	clientset, err := kubernetesNewForConfigFunc(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	// Verify the connection
	_, err = listNodesFunc(clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes API: %w", err)
	}

	// If connection is successful and we have a kubeconfig path, get and log the current context
	if kubeconfigPath != "" {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		loadingRules.ExplicitPath = kubeconfigPath

		kubeConfig := nonInteractiveDeferredLoadingClientConfigFunc(
			loadingRules,
			&clientcmd.ConfigOverrides{})

		clientConfig, err := kubeConfig.RawConfig()
		if err == nil && clientConfig.CurrentContext != "" {
			log.Info().Msgf("Connected to Kubernetes context: %s", clientConfig.CurrentContext)
		}
	}

	return &Config{
		Config:      config,
		Clientset:   clientset,
		ConfigFlags: nil, // We're not using the genericclioptions.ConfigFlags here
		DryRun:      dryRun,
	}, nil
}

// GetCurrentNamespace returns the current namespace from the kubeconfig context
func GetCurrentNamespace(config *Config) (string, error) {
	if config == nil {
		return "", fmt.Errorf("nil Kubernetes configuration")
	}

	// If running in-cluster, get the namespace from the service account
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		log.Info().Msgf("Using namespace from POD_NAMESPACE env: %s", ns)
		return ns, nil
	}

	// Otherwise, try to get it from the kubeconfig
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
	}

	// Check if kubeconfig exists
	if _, err := osStatFunc(kubeconfigPath); os.IsNotExist(err) {
		log.Warn().Msgf("Kubeconfig file not found at %s, using default namespace", kubeconfigPath)
		return "default", nil
	}

	// Use client-go's helper to get the namespace from the current context
	clientConfig := nonInteractiveDeferredLoadingClientConfigFunc(
		newDefaultClientConfigLoadingRulesFunc(),
		&clientcmd.ConfigOverrides{})

	namespace, _, err := clientConfig.Namespace()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get namespace from current context")
		return "default", nil
	}

	if namespace != "" {
		log.Info().Msgf("Using namespace from current context: %s", namespace)
		return namespace, nil
	}

	// Default to "default" namespace
	log.Info().Msg("No namespace specified in context, using 'default'")
	return "default", nil
}
