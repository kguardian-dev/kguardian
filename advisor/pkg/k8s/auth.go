package k8s

import (
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ConfigKey is used to store/retrieve *Config in context
type contextKey string

const ConfigKey contextKey = "k8sConfig"

// Config stores Kubernetes client and other flag-based configurations
type Config struct {
	Clientset   *kubernetes.Clientset
	ConfigFlags *genericclioptions.ConfigFlags
	Config      *rest.Config
}

// NewConfig returns a new Config struct initialized with a Kubernetes client
func NewConfig(configFlags *genericclioptions.ConfigFlags) (*Config, error) {

	config, err := configFlags.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Config{
		Clientset:   clientset,
		ConfigFlags: configFlags,
		Config:      config,
	}, nil
}
