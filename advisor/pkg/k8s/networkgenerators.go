package k8s

import (
	"context"

	log "github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GenerateCiliumNetworkPoliciesForAllNamespaces generates Cilium network policies for all pods across all namespaces
func GenerateCiliumNetworkPoliciesForAllNamespaces(config *Config) {
	if config == nil {
		log.Error().Msg("Kubernetes configuration is nil")
		return
	}

	log.Info().Msg("Generating Cilium network policies for all pods in all namespaces")

	// Handle test mode
	if config.Clientset == nil {
		log.Warn().Msg("Running in test mode with nil Kubernetes clientset")
		// Create mock namespaces
		mockNamespaces := []string{"default", "kube-system", "app"}
		for _, ns := range mockNamespaces {
			log.Info().Msgf("Test mode: Processing namespace: %s", ns)
			GenerateCiliumNetworkPoliciesForNamespace(config, ns)
		}
		return
	}

	// Get all namespaces
	namespaces, err := config.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list namespaces")
		return
	}

	if len(namespaces.Items) == 0 {
		log.Info().Msg("No namespaces found")
		return
	}

	// Generate policies for each namespace
	for _, ns := range namespaces.Items {
		log.Info().Msgf("Processing namespace: %s", ns.Name)
		GenerateCiliumNetworkPoliciesForNamespace(config, ns.Name)
	}
}

// GenerateNetworkPoliciesForAllNamespaces generates Kubernetes network policies for all pods across all namespaces
func GenerateNetworkPoliciesForAllNamespaces(config *Config) {
	if config == nil {
		log.Error().Msg("Kubernetes configuration is nil")
		return
	}

	log.Info().Msg("Generating Kubernetes network policies for all pods in all namespaces")

	// Handle test mode
	if config.Clientset == nil {
		log.Warn().Msg("Running in test mode with nil Kubernetes clientset")
		// Create mock namespaces
		mockNamespaces := []string{"default", "kube-system", "app"}
		for _, ns := range mockNamespaces {
			log.Info().Msgf("Test mode: Processing namespace: %s", ns)
			GenerateNetworkPoliciesForNamespace(config, ns)
		}
		return
	}

	// Get all namespaces
	namespaces, err := config.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list namespaces")
		return
	}

	if len(namespaces.Items) == 0 {
		log.Info().Msg("No namespaces found")
		return
	}

	// Generate policies for each namespace
	for _, ns := range namespaces.Items {
		log.Info().Msgf("Processing namespace: %s", ns.Name)
		GenerateNetworkPoliciesForNamespace(config, ns.Name)
	}
}

// GenerateCiliumNetworkPoliciesForNamespace generates Cilium network policies for all pods in a specific namespace
func GenerateCiliumNetworkPoliciesForNamespace(config *Config, namespace string) {
	if config == nil {
		log.Error().Msg("Kubernetes configuration is nil")
		return
	}

	if namespace == "" {
		log.Error().Msg("Namespace is required")
		return
	}

	log.Info().Msgf("Generating Cilium network policies for all pods in namespace: %s", namespace)

	// Handle test mode
	if config.Clientset == nil {
		log.Warn().Msg("Running in test mode with nil Kubernetes clientset")
		// Create a mock test pod
		mockPodName := "example-pod"
		log.Info().Msgf("Test mode: Generating Cilium network policy for mock pod %s in namespace %s", mockPodName, namespace)
		CreateCiliumNetworkPolicy(config, namespace, mockPodName)
		return
	}

	// Get all pods in the namespace
	pods, err := config.Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to list pods in namespace %s", namespace)
		return
	}

	if len(pods.Items) == 0 {
		log.Info().Msgf("No pods found in namespace %s", namespace)
		return
	}

	// Generate policies for each pod
	for _, pod := range pods.Items {
		log.Info().Msgf("Processing pod: %s", pod.Name)
		CreateCiliumNetworkPolicy(config, namespace, pod.Name)
	}
}

// GenerateNetworkPoliciesForNamespace generates Kubernetes network policies for all pods in a specific namespace
func GenerateNetworkPoliciesForNamespace(config *Config, namespace string) {
	if config == nil {
		log.Error().Msg("Kubernetes configuration is nil")
		return
	}

	if namespace == "" {
		log.Error().Msg("Namespace is required")
		return
	}

	log.Info().Msgf("Generating Kubernetes network policies for all pods in namespace: %s", namespace)

	// Handle test mode
	if config.Clientset == nil {
		log.Warn().Msg("Running in test mode with nil Kubernetes clientset")
		// Create a mock test pod
		mockPodName := "example-pod"
		log.Info().Msgf("Test mode: Generating Kubernetes network policy for mock pod %s in namespace %s", mockPodName, namespace)
		CreateKubernetesNetworkPolicy(config, namespace, mockPodName)
		return
	}

	// Get all pods in the namespace
	pods, err := config.Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to list pods in namespace %s", namespace)
		return
	}

	if len(pods.Items) == 0 {
		log.Info().Msgf("No pods found in namespace %s", namespace)
		return
	}

	// Generate policies for each pod
	for _, pod := range pods.Items {
		log.Info().Msgf("Processing pod: %s", pod.Name)
		CreateKubernetesNetworkPolicy(config, namespace, pod.Name)
	}
}

// CreateCiliumNetworkPolicy generates a Cilium network policy for a specific pod
func CreateCiliumNetworkPolicy(config *Config, namespace string, podName string) {
	// Create a GenerateOptions instance
	options := GenerateOptions{
		Mode:      SinglePod,
		Namespace: namespace,
		PodName:   podName,
	}

	// Call the existing implementation
	GenerateCiliumNetworkPolicy(options, config)
}

// CreateKubernetesNetworkPolicy generates a Kubernetes network policy for a specific pod
func CreateKubernetesNetworkPolicy(config *Config, namespace string, podName string) {
	// Create a GenerateOptions instance
	options := GenerateOptions{
		Mode:      SinglePod,
		Namespace: namespace,
		PodName:   podName,
	}

	// Call the existing implementation
	GenerateNetworkPolicy(options, config)
}
