package store

import (
	"sync"
	"testing"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	fakeclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// newTestStore returns a Store with no informers wired — only the
// in-memory caches and lifecycle methods. Sufficient for testing the
// add/update/delete plumbing and the tombstone helper without an
// envtest control plane.
func newTestStore() *Store {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel) // suppress test noise
	return &Store{
		log:                 log,
		policyMu:            sync.RWMutex{},
		policiesByNamespace: map[string][]*v1alpha1.AuditNetworkPolicy{},
	}
}

func makePolicyU(namespace, name, uid string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("kguardian.dev/v1alpha1")
	u.SetKind("AuditNetworkPolicy")
	u.SetNamespace(namespace)
	u.SetName(name)
	u.SetUID(types.UID(uid))
	_ = unstructured.SetNestedMap(u.Object, map[string]any{
		"podSelector": map[string]any{
			"matchLabels": map[string]any{"app": "web"},
		},
	}, "spec")
	return u
}

func makeClusterPolicyU(name, uid string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("kguardian.dev/v1alpha1")
	u.SetKind("AuditClusterNetworkPolicy")
	u.SetName(name)
	u.SetUID(types.UID(uid))
	_ = unstructured.SetNestedMap(u.Object, map[string]any{
		"podSelector": map[string]any{},
	}, "spec")
	return u
}

func TestPoliciesInNamespace_AddAndDelete(t *testing.T) {
	s := newTestStore()
	pa := makePolicyU("prod", "pa", "uid-a")
	pb := makePolicyU("prod", "pb", "uid-b")
	pc := makePolicyU("dev", "pc", "uid-c")

	s.onPolicyAddOrUpdate(pa)
	s.onPolicyAddOrUpdate(pb)
	s.onPolicyAddOrUpdate(pc)

	got := s.PoliciesInNamespace("prod")
	if len(got) != 2 {
		t.Fatalf("prod: want 2, got %d", len(got))
	}

	got = s.PoliciesInNamespace("dev")
	if len(got) != 1 {
		t.Fatalf("dev: want 1, got %d", len(got))
	}

	got = s.PoliciesInNamespace("nope")
	if got != nil {
		t.Errorf("missing ns: want nil, got %#v", got)
	}

	// Update — name collides, should replace not duplicate.
	s.onPolicyAddOrUpdate(makePolicyU("prod", "pa", "uid-a"))
	got = s.PoliciesInNamespace("prod")
	if len(got) != 2 {
		t.Errorf("after update: want 2, got %d", len(got))
	}

	// Delete one — namespace count drops by one.
	s.onPolicyDelete(pa)
	got = s.PoliciesInNamespace("prod")
	if len(got) != 1 || got[0].Name != "pb" {
		t.Errorf("after delete: want [pb], got %#v", got)
	}

	// Delete the last — namespace key should disappear.
	s.onPolicyDelete(pb)
	got = s.PoliciesInNamespace("prod")
	if got != nil {
		t.Errorf("after final delete: want nil, got %#v", got)
	}
}

func TestPolicyDelete_HandlesTombstone(t *testing.T) {
	// client-go sometimes delivers DeletedFinalStateUnknown on
	// reconnect. Verify the unwrap path keeps the cache consistent.
	s := newTestStore()
	pa := makePolicyU("prod", "pa", "uid-a")
	s.onPolicyAddOrUpdate(pa)

	tombstone := cache.DeletedFinalStateUnknown{
		Key: "prod/pa",
		Obj: pa,
	}
	s.onPolicyDelete(tombstone)
	if got := s.PoliciesInNamespace("prod"); got != nil {
		t.Errorf("tombstone delete: want nil cache, got %#v", got)
	}
}

func TestClusterPolicies_AddDelete(t *testing.T) {
	s := newTestStore()
	a := makeClusterPolicyU("a", "uid-a")
	b := makeClusterPolicyU("b", "uid-b")

	s.onClusterPolicyAddOrUpdate(a)
	s.onClusterPolicyAddOrUpdate(b)
	if got := s.ClusterPolicies(); len(got) != 2 {
		t.Fatalf("want 2 cluster policies, got %d", len(got))
	}

	// Update — replace not duplicate.
	s.onClusterPolicyAddOrUpdate(makeClusterPolicyU("a", "uid-a"))
	if got := s.ClusterPolicies(); len(got) != 2 {
		t.Errorf("after update: want 2, got %d", len(got))
	}

	// Delete via tombstone path.
	s.onClusterPolicyDelete(cache.DeletedFinalStateUnknown{Key: "a", Obj: a})
	got := s.ClusterPolicies()
	if len(got) != 1 || got[0].Name != "b" {
		t.Errorf("after tombstone delete: want [b], got %#v", got)
	}
}

func TestUnwrapTombstone(t *testing.T) {
	pa := makePolicyU("prod", "pa", "uid-a")
	if got := unwrapTombstone(pa); got != pa {
		t.Errorf("plain unstructured: want passthrough")
	}
	tombstone := cache.DeletedFinalStateUnknown{Key: "prod/pa", Obj: pa}
	if got := unwrapTombstone(tombstone); got != pa {
		t.Errorf("tombstone: want unwrapped object")
	}
	if got := unwrapTombstone("garbage"); got != nil {
		t.Errorf("unknown type: want nil, got %#v", got)
	}
}

// newTestStoreWithInformers returns a Store wired to real informers
// backed by a fake clientset. We never call Run() — instead we inject
// items into the informer's store directly so GetPod / GetNamespaceLabels
// have something to look up. This is the same pattern client-go's own
// tests use for reading-side coverage.
func newTestStoreWithInformers(t *testing.T) *Store {
	t.Helper()
	cs := fakeclient.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(cs, 0)

	s := &Store{
		log:                 logrus.New(),
		podInformer:         factory.Core().V1().Pods().Informer(),
		nsInformer:          factory.Core().V1().Namespaces().Informer(),
		stopCh:              make(chan struct{}),
		policiesByNamespace: map[string][]*v1alpha1.AuditNetworkPolicy{},
		policyMu:            sync.RWMutex{},
	}
	s.log.SetLevel(logrus.PanicLevel)
	return s
}

func TestGetPod_FoundInIndexer(t *testing.T) {
	s := newTestStoreWithInformers(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "web-1",
			Labels: map[string]string{"app": "web"},
		},
	}
	if err := s.podInformer.GetStore().Add(pod); err != nil {
		t.Fatalf("seed pod: %v", err)
	}

	got := s.GetPod("prod", "web-1")
	if got == nil {
		t.Fatal("expected pod, got nil")
	}
	if got.Labels["app"] != "web" {
		t.Errorf("labels round-trip: got %v", got.Labels)
	}
}

func TestGetPod_MissingPodReturnsNil(t *testing.T) {
	s := newTestStoreWithInformers(t)
	if got := s.GetPod("prod", "missing"); got != nil {
		t.Errorf("missing pod: want nil, got %#v", got)
	}
}

func TestGetPod_BlankInputsReturnNil(t *testing.T) {
	// Defensive: avoid forming the "/pod-name" key against the indexer
	// when callers haven't supplied both halves. Prevents accidental
	// matches against pods named "" in any namespace.
	s := newTestStoreWithInformers(t)
	if got := s.GetPod("", "web-1"); got != nil {
		t.Errorf("empty namespace: want nil, got %#v", got)
	}
	if got := s.GetPod("prod", ""); got != nil {
		t.Errorf("empty name: want nil, got %#v", got)
	}
}

func TestGetNamespaceLabels_FoundInIndexer(t *testing.T) {
	s := newTestStoreWithInformers(t)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prod",
			Labels: map[string]string{
				"team":                        "platform",
				"kubernetes.io/metadata.name": "prod",
			},
		},
	}
	if err := s.nsInformer.GetStore().Add(ns); err != nil {
		t.Fatalf("seed ns: %v", err)
	}

	got := s.GetNamespaceLabels("prod")
	if got == nil {
		t.Fatal("expected labels, got nil")
	}
	if got["team"] != "platform" {
		t.Errorf("team label: got %#v", got)
	}
}

func TestGetNamespaceLabels_MissingReturnsNil(t *testing.T) {
	s := newTestStoreWithInformers(t)
	if got := s.GetNamespaceLabels("nope"); got != nil {
		t.Errorf("missing ns: want nil, got %#v", got)
	}
}

func TestGetNamespaceLabels_EmptyNameReturnsNil(t *testing.T) {
	// As with GetPod, refuse to form a lookup key against the indexer
	// when the input is degenerate.
	s := newTestStoreWithInformers(t)
	if got := s.GetNamespaceLabels(""); got != nil {
		t.Errorf("empty name: want nil, got %#v", got)
	}
}

func TestGetNamespaceLabels_KnownButUnlabelled(t *testing.T) {
	// Default-created namespaces (kubectl create namespace foo with no
	// --labels) end up with ns.Labels == nil. The matcher uses nil to
	// mean "namespace UNKNOWN" and would short-circuit to NotApplicable
	// — wrong: the namespace is known, just unlabelled. An empty
	// namespaceSelector ({}, "match all") must still see this as a
	// match. The contract: known-but-unlabelled returns a non-nil
	// empty map, distinguishing it from the truly-unknown nil.
	s := newTestStoreWithInformers(t)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			// no Labels set → field is nil
		},
	}
	if err := s.nsInformer.GetStore().Add(ns); err != nil {
		t.Fatalf("seed ns: %v", err)
	}

	got := s.GetNamespaceLabels("default")
	if got == nil {
		t.Fatal("known-but-unlabelled namespace must NOT return nil; nil means unknown")
	}
	if len(got) != 0 {
		t.Errorf("known-but-unlabelled: want empty map, got %#v", got)
	}
}

func TestPoliciesInNamespace_SnapshotIsolated(t *testing.T) {
	// Caller shouldn't be able to mutate the store's internal slice.
	s := newTestStore()
	s.onPolicyAddOrUpdate(makePolicyU("prod", "pa", "uid-a"))

	got := s.PoliciesInNamespace("prod")
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	got[0] = nil // mutate the returned slice

	again := s.PoliciesInNamespace("prod")
	if again[0] == nil {
		t.Errorf("internal slice mutated by caller")
	}
}
