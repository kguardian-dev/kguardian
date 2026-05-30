package cmd

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newClusterPolicy(t *testing.T, name string, spec map[string]any) *unstructured.Unstructured {
	t.Helper()
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kguardian.dev/v1alpha1",
		"kind":       "AuditClusterNetworkPolicy",
		"metadata": map[string]any{
			"name": name,
			"uid":  "cluster-uid-1",
		},
		"spec": spec,
	}}
}

func TestExpandClusterPolicy_OneItemPerNamespace(t *testing.T) {
	cluster := newClusterPolicy(t, "baseline-deny", map[string]any{
		"namespaceSelector": map[string]any{
			"matchLabels": map[string]any{"team": "platform"},
		},
		"podSelector": map[string]any{},
		"policyTypes": []any{"Ingress"},
	})
	items, err := expandClusterPolicyToNamespaced(cluster, []string{"prod", "staging"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items (one per namespace), got %d", len(items))
	}
	got := map[string]bool{}
	for _, item := range items {
		got[item.GetNamespace()] = true
		if item.GetName() != "baseline-deny" {
			t.Errorf("name should carry over from cluster policy, got %s", item.GetName())
		}
	}
	if !got["prod"] || !got["staging"] {
		t.Errorf("missing one of the requested namespaces; got %#v", got)
	}
}

func TestExpandClusterPolicy_DropsNamespaceSelector(t *testing.T) {
	// networking.k8s.io/v1.NetworkPolicy.spec has NO namespaceSelector
	// field. Leaving it on the emitted item would produce a YAML the
	// apiserver rejects on strict-decode (or worse, silently ignores
	// it on a permissive cluster but the audit semantics are lost).
	cluster := newClusterPolicy(t, "x", map[string]any{
		"namespaceSelector": map[string]any{
			"matchLabels": map[string]any{"team": "platform"},
		},
		"podSelector": map[string]any{},
	})
	items, err := expandClusterPolicyToNamespaced(cluster, []string{"prod"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	spec := items[0].Object["spec"].(map[string]any)
	if _, ok := spec["namespaceSelector"]; ok {
		t.Errorf("namespaceSelector must be dropped from emitted spec; got %#v", spec)
	}
	if _, ok := spec["podSelector"]; !ok {
		t.Errorf("podSelector must survive (its in NetworkPolicySpec)")
	}
}

func TestExpandClusterPolicy_SpecsAreIndependent(t *testing.T) {
	// Cross-pollution check: mutating one items spec must not leak
	// into the others. Defensively deep-copying spec costs ~one
	// alloc per ns; the alternative is a future refactor that mutates
	// a shared map and silently corrupts every emitted item.
	cluster := newClusterPolicy(t, "x", map[string]any{
		"podSelector": map[string]any{
			"matchLabels": map[string]any{"app": "web"},
		},
	})
	items, err := expandClusterPolicyToNamespaced(cluster, []string{"a", "b"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	// Mutate item[0]'s nested spec.
	spec0 := items[0].Object["spec"].(map[string]any)
	ps0 := spec0["podSelector"].(map[string]any)
	ml0 := ps0["matchLabels"].(map[string]any)
	ml0["app"] = "MUTATED"

	// item[1] must still see the original value.
	spec1 := items[1].Object["spec"].(map[string]any)
	ps1 := spec1["podSelector"].(map[string]any)
	ml1 := ps1["matchLabels"].(map[string]any)
	if ml1["app"] != "web" {
		t.Errorf("specs must be independent across items; got cross-mutation: %#v", ml1)
	}
}

func TestExpandClusterPolicy_PreservesUserLabelsAndStripsKubectlAnnotation(t *testing.T) {
	cluster := newClusterPolicy(t, "x", map[string]any{"podSelector": map[string]any{}})
	cluster.SetLabels(map[string]string{"team": "platform"})
	cluster.SetAnnotations(map[string]string{
		"argocd.argoproj.io/sync-wave":                     "5",
		"kubectl.kubernetes.io/last-applied-configuration": "stale",
	})
	items, err := expandClusterPolicyToNamespaced(cluster, []string{"prod"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	got := items[0]
	if got.GetLabels()["team"] != "platform" {
		t.Errorf("user labels must propagate to each emitted item")
	}
	anns := got.GetAnnotations()
	if anns["argocd.argoproj.io/sync-wave"] != "5" {
		t.Errorf("user annotation must propagate")
	}
	if _, ok := anns["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Errorf("kubectl last-applied must be stripped on cluster expand too")
	}
}

func TestExpandClusterPolicy_NoSpecErrors(t *testing.T) {
	cluster := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kguardian.dev/v1alpha1",
		"kind":       "AuditClusterNetworkPolicy",
		"metadata":   map[string]any{"name": "broken"},
	}}
	_, err := expandClusterPolicyToNamespaced(cluster, []string{"prod"})
	if err == nil {
		t.Fatal("missing spec must error rather than silently emit a content-free policy")
	}
}

func TestExpandClusterPolicy_EmptyNamespacesYieldsEmpty(t *testing.T) {
	// promote-cluster --target-namespace='' (impossible via cobra but
	// possible via discovery returning []) must not emit a NetworkPolicy
	// with namespace="" — that would be invalid.
	cluster := newClusterPolicy(t, "x", map[string]any{"podSelector": map[string]any{}})
	items, err := expandClusterPolicyToNamespaced(cluster, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("empty namespaces input must yield empty output, got %d items", len(items))
	}
}

func TestUnstructuredToLabelSelector_ParsesMatchLabels(t *testing.T) {
	in := map[string]any{
		"matchLabels": map[string]any{
			"team": "platform",
			"env":  "prod",
		},
	}
	got := unstructuredToLabelSelector(in)
	if len(got.MatchLabels) != 2 {
		t.Fatalf("matchLabels count: want 2, got %d", len(got.MatchLabels))
	}
	if got.MatchLabels["team"] != "platform" || got.MatchLabels["env"] != "prod" {
		t.Errorf("matchLabels content wrong: %#v", got.MatchLabels)
	}
}

func TestUnstructuredToLabelSelector_ParsesMatchExpressions(t *testing.T) {
	// matchExpressions is the more complex path; pin In/NotIn/Exists/
	// DoesNotExist against the canonical wire shape.
	in := map[string]any{
		"matchExpressions": []any{
			map[string]any{"key": "tier", "operator": "In", "values": []any{"frontend", "backend"}},
			map[string]any{"key": "audit", "operator": "Exists"},
		},
	}
	got := unstructuredToLabelSelector(in)
	if len(got.MatchExpressions) != 2 {
		t.Fatalf("matchExpressions count: want 2, got %d", len(got.MatchExpressions))
	}
	first := got.MatchExpressions[0]
	if first.Key != "tier" || first.Operator != metav1.LabelSelectorOpIn {
		t.Errorf("first expression: %#v", first)
	}
	if len(first.Values) != 2 || first.Values[0] != "frontend" || first.Values[1] != "backend" {
		t.Errorf("first values: %#v", first.Values)
	}
	second := got.MatchExpressions[1]
	if second.Key != "audit" || second.Operator != metav1.LabelSelectorOpExists {
		t.Errorf("second expression: %#v", second)
	}
}

func TestUnstructuredToLabelSelector_EmptyInputProducesEmptySelector(t *testing.T) {
	// A {} selector matches everything per upstream convention. The
	// converter must not invent matchLabels / matchExpressions out of
	// thin air — the empty selector relies on both being nil/empty.
	got := unstructuredToLabelSelector(map[string]any{})
	if got.MatchLabels != nil && len(got.MatchLabels) != 0 {
		t.Errorf("empty input must yield empty/nil MatchLabels, got %#v", got.MatchLabels)
	}
	if got.MatchExpressions != nil && len(got.MatchExpressions) != 0 {
		t.Errorf("empty input must yield empty/nil MatchExpressions, got %#v", got.MatchExpressions)
	}
}

func TestDiscoverNamespacesForClusterPolicy_FiltersByLabel(t *testing.T) {
	// End-to-end-ish: the dynamic-client fake includes 3 namespaces,
	// 2 with team=platform and 1 with team=other. The cluster policy's
	// namespaceSelector matches team=platform; the discovery must
	// return exactly those 2 names.
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		corev1NamespaceGVR: "NamespaceList",
	}
	prod := unstructuredNamespace("prod", map[string]string{"team": "platform"})
	staging := unstructuredNamespace("staging", map[string]string{"team": "platform"})
	other := unstructuredNamespace("other", map[string]string{"team": "data"})
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, prod, staging, other)

	cluster := newClusterPolicy(t, "x", map[string]any{
		"namespaceSelector": map[string]any{
			"matchLabels": map[string]any{"team": "platform"},
		},
		"podSelector": map[string]any{},
	})
	got, err := discoverNamespacesForClusterPolicy(context.Background(), dyn, cluster)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	want := map[string]bool{"prod": true, "staging": true}
	if len(got) != 2 {
		t.Fatalf("expected 2 namespaces, got %d (%v)", len(got), got)
	}
	for _, ns := range got {
		if !want[ns] {
			t.Errorf("unexpected namespace in result: %s", ns)
		}
	}
}

func TestDiscoverNamespacesForClusterPolicy_NilSelectorMatchesAll(t *testing.T) {
	// nil/missing namespaceSelector → match every namespace.
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		corev1NamespaceGVR: "NamespaceList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind,
		unstructuredNamespace("a", nil),
		unstructuredNamespace("b", nil),
		unstructuredNamespace("c", map[string]string{"x": "y"}),
	)
	cluster := newClusterPolicy(t, "x", map[string]any{
		"podSelector": map[string]any{},
	})
	got, err := discoverNamespacesForClusterPolicy(context.Background(), dyn, cluster)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("nil selector should match all 3 namespaces, got %d (%v)", len(got), got)
	}
}

// unstructuredNamespace builds a v1.Namespace as Unstructured so the
// dynamicfake client can hand it back with labels intact.
func unstructuredNamespace(name string, labels map[string]string) *unstructured.Unstructured {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
	out := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name": ns.Name,
		},
	}}
	if labels != nil {
		out.SetLabels(labels)
	}
	return out
}
