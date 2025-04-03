package k8s

import (
	"context"
	"fmt"

	log "github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Function variables for mocking in tests
var (
	getPodFunc                    = getPod                    // Internal function
	getPodsInNamespaceFunc        = getPodsInNamespace        // Internal function
	getAllPodsInAllNamespacesFunc = getAllPodsInAllNamespaces // Internal function
)

// GetPod fetches a single running pod by name and namespace.
func GetPod(ctx context.Context, config *Config, namespace, podName string) (*corev1.Pod, error) {
	return getPodFunc(ctx, config, namespace, podName)
}

// GetPodsInNamespace fetches all running pods in a specific namespace.
func GetPodsInNamespace(ctx context.Context, config *Config, namespace string) ([]corev1.Pod, error) {
	return getPodsInNamespaceFunc(ctx, config, namespace)
}

// GetAllPodsInAllNamespaces fetches all running pods across all namespaces.
func GetAllPodsInAllNamespaces(ctx context.Context, config *Config) ([]corev1.Pod, error) {
	return getAllPodsInAllNamespacesFunc(ctx, config)
}

// --- Internal implementations ---

// getPod is the internal implementation for GetPod
func getPod(ctx context.Context, config *Config, namespace, podName string) (*corev1.Pod, error) {
	if config == nil || config.Clientset == nil {
		return nil, ErrNoClientset
	}

	log.Debug().Msgf("Getting pod %s in namespace %s", podName, namespace)

	pod, err := config.Clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		log.Error().Err(err).Msgf("Error getting pod %s in namespace %s", podName, namespace)
		return nil, err
	}

	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod %s in namespace %s is not in Running state (current state: %s)", podName, namespace, pod.Status.Phase)
	}

	log.Debug().Msgf("Found running pod: %s", pod.Name)
	return pod, nil
}

// getPodsInNamespace is the internal implementation for GetPodsInNamespace
func getPodsInNamespace(ctx context.Context, config *Config, namespace string) ([]corev1.Pod, error) {
	if config == nil || config.Clientset == nil {
		return nil, ErrNoClientset
	}

	log.Debug().Msgf("Getting all running pods in namespace %s", namespace)

	podList, err := config.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msgf("Error listing pods in namespace %s", namespace)
		return nil, err
	}

	runningPods := []corev1.Pod{}
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			runningPods = append(runningPods, pod)
			log.Debug().Msgf("Found running pod: %s", pod.Name)
		}
	}

	log.Info().Msgf("Found %d running pods in namespace %s", len(runningPods), namespace)
	return runningPods, nil
}

// getAllPodsInAllNamespaces is the internal implementation for GetAllPodsInAllNamespaces
func getAllPodsInAllNamespaces(ctx context.Context, config *Config) ([]corev1.Pod, error) {
	if config == nil || config.Clientset == nil {
		return nil, ErrNoClientset
	}

	log.Debug().Msg("Getting all running pods in all namespaces")

	podList, err := config.Clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Error listing pods in all namespaces")
		return nil, err
	}

	runningPods := []corev1.Pod{}
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			runningPods = append(runningPods, pod)
			log.Debug().Msgf("Found running pod: %s/%s", pod.Namespace, pod.Name)
		}
	}

	log.Info().Msgf("Found %d running pods across all namespaces", len(runningPods))
	return runningPods, nil
}
