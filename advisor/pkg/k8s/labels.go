package k8s

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DetectLabels detects the labels of a pod.
func DetectSelectorLabels(clientset *kubernetes.Clientset, pod *v1.Pod) (map[string]string, error) {
	ctx := context.TODO()

	// Check if the Pod has an owner
	if len(pod.OwnerReferences) > 0 {
		owner := pod.OwnerReferences[0]

		// Based on the owner, get the controller object to check its labels
		switch owner.Kind {
		case "ReplicaSet":
			replicaSet, err := clientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			deployment, err := clientset.AppsV1().Deployments(pod.Namespace).Get(ctx, replicaSet.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return deployment.Spec.Selector.MatchLabels, nil

		case "StatefulSet":
			statefulSet, err := clientset.AppsV1().StatefulSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return statefulSet.Spec.Selector.MatchLabels, nil

		case "DaemonSet":
			daemonSet, err := clientset.AppsV1().DaemonSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return daemonSet.Spec.Selector.MatchLabels, nil

		// Add more controller kinds here if needed

		default:
			return nil, fmt.Errorf("unknown or unsupported owner kind: %s", owner.Kind)
		}
	}

	// If we reach here, the Pod has no owner and we return its own labels
	return pod.Labels, nil
}
