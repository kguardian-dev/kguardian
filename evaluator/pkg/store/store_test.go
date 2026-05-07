package store

import (
	"sync"
	"testing"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
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
