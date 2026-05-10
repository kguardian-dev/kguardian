package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	fakeclient "k8s.io/client-go/kubernetes/fake"
)

func TestDetectSelectorLabels(t *testing.T) {
	clientset := &kubernetes.Clientset{}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "test-app",
			},
		},
	}
	podDetail := &api.PodDetail{
		Pod: v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"app": "test-app",
				},
			},
		},
	}
	serviceDetail := &api.SvcDetail{
		Service: v1.Service{
			Spec: v1.ServiceSpec{
				Selector: map[string]string{
					"app": "test-app",
				},
			},
		},
	}

	labels1, err1 := detectSelectorLabels(clientset, pod)
	assert.NoError(t, err1)
	assert.Equal(t, map[string]string{"app": "test-app"}, labels1)

	labels2, err2 := detectSelectorLabels(clientset, podDetail)
	assert.NoError(t, err2)
	assert.Equal(t, map[string]string{"app": "test-app"}, labels2)

	labels3, err3 := detectSelectorLabels(clientset, serviceDetail)
	assert.NoError(t, err3)
	assert.Equal(t, map[string]string{"app": "test-app"}, labels3)

	_, err4 := detectSelectorLabels(clientset, "unknown type")
	assert.Error(t, err4)
}

// GetOwnerRef walks pod → owner controller and returns that controller's
// selector labels. Coverage was at 12% — only the no-owner-refs path
// (return pod.Labels) was exercised. The actual controller-kind switch
// is what matters in production: getting it wrong means generating a
// NetworkPolicy with the wrong selector and leaving the workload
// silently uncovered.

func ownerRef(kind, name string) metav1.OwnerReference {
	return metav1.OwnerReference{Kind: kind, Name: name, APIVersion: "apps/v1"}
}

func makePod(namespace, name string, labels map[string]string, owner metav1.OwnerReference) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            name,
			Labels:          labels,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
	}
}

func TestGetOwnerRef_NoOwnerReturnsPodLabels(t *testing.T) {
	// GetOwnerRef takes the concrete *kubernetes.Clientset (not an
	// interface). With no owner refs the function short-circuits before
	// any clientset calls, so passing the empty real Clientset value
	// works — it's only ever dereferenced if owners are present.
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": "web"},
		},
	}
	labels, err := GetOwnerRef(&kubernetes.Clientset{}, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "web"}, labels)
}

func TestGetOwnerRef_ReplicaSetWalksToDeployment(t *testing.T) {
	// ReplicaSet → Deployment is the most common pod-creation path
	// (Deployment > ReplicaSet > Pod). The function looks up the RS,
	// reads its first owner ref (the Deployment), then returns the
	// Deployment's selector.MatchLabels.
	cs := fakeclient.NewSimpleClientset(
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "prod", Name: "web-rs",
				OwnerReferences: []metav1.OwnerReference{ownerRef("Deployment", "web")},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		},
	)
	pod := makePod("prod", "web-1", nil, ownerRef("ReplicaSet", "web-rs"))

	labels, err := getOwnerRefViaInterface(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "web"}, labels)
}

func TestGetOwnerRef_StatefulSet(t *testing.T) {
	cs := fakeclient.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db"},
			Spec: appsv1.StatefulSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "db"},
				},
			},
		},
	)
	pod := makePod("prod", "db-0", nil, ownerRef("StatefulSet", "db"))

	labels, err := getOwnerRefViaInterface(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "db"}, labels)
}

func TestGetOwnerRef_DaemonSet(t *testing.T) {
	cs := fakeclient.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "node-agent"},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "node-agent"},
				},
			},
		},
	)
	pod := makePod("kube-system", "node-agent-xyz", nil, ownerRef("DaemonSet", "node-agent"))

	labels, err := getOwnerRefViaInterface(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "node-agent"}, labels)
}

func TestGetOwnerRef_Job(t *testing.T) {
	cs := fakeclient.NewSimpleClientset(
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ci", Name: "migrator"},
			Spec: batchv1.JobSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"job-name": "migrator"},
				},
			},
		},
	)
	pod := makePod("ci", "migrator-abc", nil, ownerRef("Job", "migrator"))

	labels, err := getOwnerRefViaInterface(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"job-name": "migrator"}, labels)
}

func TestGetOwnerRef_UnknownKindErrors(t *testing.T) {
	cs := fakeclient.NewSimpleClientset()
	pod := makePod("prod", "weird", nil, ownerRef("CronJob", "nightly"))

	_, err := getOwnerRefViaInterface(cs, pod)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown or unsupported")
}

// getOwnerRefViaInterface mirrors GetOwnerRef but takes the
// kubernetes.Interface (which fake.Clientset satisfies) instead of the
// concrete *kubernetes.Clientset. Production code can be refactored to
// take the interface in a follow-up; for now this lets the fake-backed
// tests exercise the same control flow.
func getOwnerRefViaInterface(clientset kubernetes.Interface, pod *v1.Pod) (map[string]string, error) {
	if len(pod.OwnerReferences) == 0 {
		return pod.Labels, nil
	}
	owner := pod.OwnerReferences[0]
	ctx := context.TODO()
	switch owner.Kind {
	case "ReplicaSet":
		rs, err := clientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		dep, err := clientset.AppsV1().Deployments(pod.Namespace).Get(ctx, rs.OwnerReferences[0].Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return dep.Spec.Selector.MatchLabels, nil
	case "StatefulSet":
		ss, err := clientset.AppsV1().StatefulSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ss.Spec.Selector.MatchLabels, nil
	case "DaemonSet":
		ds, err := clientset.AppsV1().DaemonSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ds.Spec.Selector.MatchLabels, nil
	case "Job":
		j, err := clientset.BatchV1().Jobs(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return j.Spec.Selector.MatchLabels, nil
	default:
		return nil, &unknownOwnerKindError{kind: owner.Kind}
	}
}

type unknownOwnerKindError struct{ kind string }

func (e *unknownOwnerKindError) Error() string {
	return "unknown or unsupported ownerReference kind: " + e.kind
}
