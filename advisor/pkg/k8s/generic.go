package k8s

import (
	"context"

	log "github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
)

// Version is set at build time using -ldflags
var Version = "development" // default value

// ModeType defines the mode of operation for generating network policies
type ModeType int

const (
	SinglePod ModeType = iota
	AllPodsInNamespace
	AllPodsInAllNamespaces
)

// GenerateOptions holds options for the GenerateNetworkPolicy function
type GenerateOptions struct {
	Mode      ModeType
	PodName   string // Used if Mode is SinglePod
	Namespace string // Used if Mode is AllPodsInNamespace or SinglePod
	OutputDir string
	// DefaultAction is used by generators that need an action parameter (e.g., seccomp)
	DefaultAction string
}

// Exportable function variables for testing - REMOVED

func GetResource(options GenerateOptions, config *Config) []corev1.Pod {
	var pods []corev1.Pod
	ctx := context.TODO() // Or pass a context if available

	switch options.Mode {
	case SinglePod:
		// Fetch the specified pod
		fetchedPod, err := GetPod(ctx, config, options.Namespace, options.PodName)
		if err != nil {
			// Log the error and return an empty slice instead of fatally exiting.
			log.Error().Err(err).Msgf("failed to get running pod %s in namespace %s", options.PodName, options.Namespace)
			return []corev1.Pod{}
		}
		pods = append(pods, *fetchedPod)

	case AllPodsInNamespace:
		// Fetch all running pods in the given namespace
		fetchedPods, err := GetPodsInNamespace(ctx, config, options.Namespace)
		if err != nil {
			log.Error().Err(err).Msgf("failed to fetch running pods in namespace %s", options.Namespace)
			// Return empty list on error, or handle differently as needed
			return []corev1.Pod{}
		}
		pods = append(pods, fetchedPods...)

	case AllPodsInAllNamespaces:
		// Fetch all running pods in all namespaces
		fetchedPods, err := GetAllPodsInAllNamespaces(ctx, config)
		if err != nil {
			log.Error().Err(err).Msgf("failed to fetch all running pods in all namespaces")
			// Return empty list on error, or handle differently as needed
			return []corev1.Pod{}
		}
		pods = append(pods, fetchedPods...)
	default:
		log.Error().Msgf("Unknown mode type: %v", options.Mode)
		return []corev1.Pod{}
	}
	return pods
}
