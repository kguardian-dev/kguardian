package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Config stores Kubernetes client and other flag-based configurations
type Config struct {
	Clientset  *kubernetes.Clientset
	Kubeconfig string
	Namespace  string
	Config     *rest.Config
}

// NewConfig returns a new Config struct initialized with a Kubernetes client
func NewConfig(kubeconfig string, namespace string) (*Config, error) {
	// If kubeconfig flag is not set, fallback to environment variable
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	// If neither flag nor environment variable is set, fallback to default path
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println("Unable to get user home directory: ", err)
			os.Exit(1)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	currentConfig, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		fmt.Printf("Error reading kubeconfig: %v\n", err)
		return nil, err
	}

	// If namespace flag is not set, fallback to current context
	if namespace == "" {
		if context, ok := currentConfig.Contexts[currentConfig.CurrentContext]; ok {
			namespace = context.Namespace
			// If namespace flag is not set, and no current context, fallback to default namespace
			if namespace == "" {
				namespace = "default"
			}
		}
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Config{
		Clientset:  clientset,
		Kubeconfig: kubeconfig,
		Namespace:  namespace,
		Config:     config,
	}, nil
}
