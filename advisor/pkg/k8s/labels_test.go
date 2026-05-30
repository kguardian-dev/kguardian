package k8s

import (
	"testing"

	api "github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/stretchr/testify/assert"
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

	labels, err := GetOwnerRef(cs, pod)
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

	labels, err := GetOwnerRef(cs, pod)
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

	labels, err := GetOwnerRef(cs, pod)
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

	labels, err := GetOwnerRef(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"job-name": "migrator"}, labels)
}

func TestGetOwnerRef_MissingReplicaSetFallsBackToPodLabels(t *testing.T) {
	// ReplicaSets are routinely GC'd by the Deployment controller as
	// older revisions age out. The advisor processes historical
	// traffic, so a pod's OwnerReference can point at a ReplicaSet
	// that no longer exists. Pre-fix: a NotFound from the RS Get
	// broke the whole netpol-gen batch for that pod; now we fall
	// back to the pod's own labels.
	cs := fakeclient.NewSimpleClientset() // no RS / Deployment in cluster
	pod := makePod("prod", "web-1", map[string]string{"app": "web", "pod-template-hash": "abc"}, ownerRef("ReplicaSet", "web-rs-old"))

	got, err := GetOwnerRef(cs, pod)
	assert.NoError(t, err, "missing RS must NOT propagate as an error — break-the-batch is the wrong default")
	// Falls back to pod.Labels exactly — including pod-template-hash
	// (operator can choose to strip if they prefer; thats out of
	// scope for the fallback).
	assert.Equal(t, map[string]string{"app": "web", "pod-template-hash": "abc"}, got)
}

func TestGetOwnerRef_MissingDeploymentFallsBackToReplicaSetSelector(t *testing.T) {
	// One level up: RS exists, but the Deployment has been deleted
	// (e.g. someone did `kubectl delete deployment` but the RS
	// orphan-collected slowly). Use the RS's own selector labels as
	// the next-best signal.
	cs := fakeclient.NewSimpleClientset(
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "prod", Name: "web-rs",
				OwnerReferences: []metav1.OwnerReference{ownerRef("Deployment", "web-deleted")},
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		},
		// deployment "web-deleted" deliberately absent
	)
	pod := makePod("prod", "web-1", nil, ownerRef("ReplicaSet", "web-rs"))

	got, err := GetOwnerRef(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "web"}, got)
}

func TestGetOwnerRef_StandaloneReplicaSetNoPanic(t *testing.T) {
	// Bounds-check regression: a ReplicaSet without any owner
	// references is rare but legal (someone applied an RS YAML
	// directly). Pre-fix the code did `replicaSet.OwnerReferences[0]`
	// without checking length — that's a panic.
	cs := fakeclient.NewSimpleClientset(
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "prod", Name: "standalone-rs",
				// no OwnerReferences
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "standalone"},
				},
			},
		},
	)
	pod := makePod("prod", "p", nil, ownerRef("ReplicaSet", "standalone-rs"))

	got, err := GetOwnerRef(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "standalone"}, got, "must use the standalone RS's own selector when it has no owner")
}

func TestGetOwnerRef_MissingStatefulSetFallsBack(t *testing.T) {
	// Same graceful-degradation as RS — a deleted StatefulSet
	// shouldn't break the batch.
	cs := fakeclient.NewSimpleClientset()
	pod := makePod("prod", "db-0", map[string]string{"app": "db"}, ownerRef("StatefulSet", "db"))

	got, err := GetOwnerRef(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "db"}, got)
}

func TestGetOwnerRef_UnknownKindFallsBackToPodLabels(t *testing.T) {
	// Contract changed in graceful-degradation refactor: an unknown
	// owner kind (Argo Rollout, custom CRD, etc.) used to fail the
	// whole netpol-gen batch. It now logs at warn and returns the
	// pod's own labels, which are themselves valid NetworkPolicy
	// selectors. The advisor processes historical traffic data, so
	// any blanket failure on unknown kinds was breaking netpol-gen
	// for clusters using Rollouts/Argo etc.
	cs := fakeclient.NewSimpleClientset()
	pod := makePod("prod", "weird", map[string]string{"app": "weird"}, ownerRef("CronJob", "nightly"))

	got, err := GetOwnerRef(cs, pod)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "weird"}, got)
}
