package k8s

import (
	"context"
	"fmt"

	log "github.com/rs/zerolog/log"
	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DetectLabels detects the labels of a pod.
//
// Takes the kubernetes.Interface (not the concrete *Clientset) so callers
// can pass either the real clientset or fake.Clientset for testing.
func detectSelectorLabels(clientset kubernetes.Interface, origin interface{}) (map[string]string, error) {
	// Use type assertion to check the specific type
	switch o := origin.(type) {
	case *v1.Pod:
		return GetOwnerRef(clientset, o)
	case *api.PodDetail:
		return GetOwnerRef(clientset, &o.Pod)
	case *api.SvcDetail:
		var svc v1.Service
		svc = o.Service
		return svc.Spec.Selector, nil
	default:
		return nil, fmt.Errorf("detectSelectorLabels: unknown type")
	}
}

// GetOwnerRef resolves the workload-controller selector labels for a Pod.
//
// Walks the pod's first owner reference (ReplicaSet → Deployment for the
// common case, plus StatefulSet/DaemonSet/Job direct paths). Pods with
// no owner refs return their own labels.
//
// Graceful degradation: if any controller in the chain has been GC'd
// (common during deployment rollouts — old ReplicaSets are routinely
// pruned by the deployment controller), fall back to the pod's own
// labels. The advisor processes historical traffic data, so referenced
// controllers may have been deleted long after the traffic was
// observed; previously a NotFound from any Get broke the entire
// netpol-generation batch. The pod's own labels are themselves valid
// NetworkPolicy selectors, so the generated policy still works — it
// just uses pod labels in place of the controller's selector labels.
//
// Takes kubernetes.Interface so it can be tested against fake.Clientset.
func GetOwnerRef(clientset kubernetes.Interface, pod *v1.Pod) (map[string]string, error) {
	ctx := context.TODO()

	// Check if the Pod has an owner
	if len(pod.OwnerReferences) > 0 {
		owner := pod.OwnerReferences[0]

		// Based on the owner, get the controller object to check its labels
		switch owner.Kind {
		case "ReplicaSet":
			replicaSet, err := clientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info().Msgf("ReplicaSet %s/%s GC'd; falling back to pod labels for %s", pod.Namespace, owner.Name, pod.Name)
					return pod.Labels, nil
				}
				return nil, err
			}
			// Bounds-check the RS's owner refs — a standalone RS (rare
			// but legal) has no owners. Use the RS's own selector
			// labels in that case rather than panicking on [0] indexing.
			if len(replicaSet.OwnerReferences) == 0 {
				if replicaSet.Spec.Selector != nil {
					return replicaSet.Spec.Selector.MatchLabels, nil
				}
				return pod.Labels, nil
			}
			deployment, err := clientset.AppsV1().Deployments(pod.Namespace).Get(ctx, replicaSet.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info().Msgf("Deployment %s/%s GC'd; falling back to ReplicaSet selector for %s",
						pod.Namespace, replicaSet.OwnerReferences[0].Name, pod.Name)
					if replicaSet.Spec.Selector != nil {
						return replicaSet.Spec.Selector.MatchLabels, nil
					}
					return pod.Labels, nil
				}
				return nil, err
			}
			return deployment.Spec.Selector.MatchLabels, nil

		case "StatefulSet":
			statefulSet, err := clientset.AppsV1().StatefulSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info().Msgf("StatefulSet %s/%s GC'd; falling back to pod labels for %s", pod.Namespace, owner.Name, pod.Name)
					return pod.Labels, nil
				}
				return nil, err
			}
			return statefulSet.Spec.Selector.MatchLabels, nil

		case "DaemonSet":
			daemonSet, err := clientset.AppsV1().DaemonSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info().Msgf("DaemonSet %s/%s GC'd; falling back to pod labels for %s", pod.Namespace, owner.Name, pod.Name)
					return pod.Labels, nil
				}
				return nil, err
			}
			return daemonSet.Spec.Selector.MatchLabels, nil

		case "Job":
			job, err := clientset.BatchV1().Jobs(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info().Msgf("Job %s/%s GC'd; falling back to pod labels for %s", pod.Namespace, owner.Name, pod.Name)
					return pod.Labels, nil
				}
				return nil, err
			}
			return job.Spec.Selector.MatchLabels, nil

		// Add more controller kinds here if needed

		default:
			// Unknown controller (Argo Rollout, custom CRD, etc.) —
			// gracefully fall back to pod labels rather than failing
			// the whole netpol-gen batch. Log so operators can see
			// when this kicks in.
			log.Warn().Msgf("Unsupported ownerReference kind %q for pod %s/%s; using pod labels", owner.Kind, pod.Namespace, pod.Name)
			return pod.Labels, nil
		}
	}
	return pod.Labels, nil
}
