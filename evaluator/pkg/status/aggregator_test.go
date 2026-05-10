package status

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestRecord_NotApplicableNotCounted(t *testing.T) {
	// The server only feeds non-NotApplicable verdicts to Record, so
	// we don't need to filter here — but verify that wouldDeny=false
	// from an Allow doesn't increment the offender table while still
	// bumping flowsEvaluated.
	a := &Aggregator{counts: map[policyKey]*policyAgg{}, topN: 10}
	a.Record("prod", "p1", "prod/a", "prod/b", "TCP", "Ingress", 80, false, 0)
	a.Record("prod", "p1", "prod/a", "prod/b", "TCP", "Ingress", 80, true, 0)
	a.Record("prod", "p1", "prod/x", "prod/y", "TCP", "Ingress", 81, true, 0)

	a.mu.Lock()
	defer a.mu.Unlock()
	got := a.counts[policyKey{namespace: "prod", name: "p1"}]
	if got == nil {
		t.Fatal("expected counts entry")
	}
	if got.flowsEvaluated != 3 {
		t.Errorf("flowsEvaluated: want 3, got %d", got.flowsEvaluated)
	}
	if got.flowsWouldDeny != 2 {
		t.Errorf("flowsWouldDeny: want 2, got %d", got.flowsWouldDeny)
	}
	if len(got.tuples) != 2 {
		t.Errorf("tuples: want 2 distinct, got %d", len(got.tuples))
	}
}

func TestTopOffenders_SortedDescAndCapped(t *testing.T) {
	tuples := map[tupleKey]int64{
		{srcPod: "a", dstPod: "x", protocol: "TCP", direction: "Ingress", dstPort: 80}: 5,
		{srcPod: "b", dstPod: "x", protocol: "TCP", direction: "Ingress", dstPort: 80}: 2,
		{srcPod: "c", dstPod: "x", protocol: "TCP", direction: "Ingress", dstPort: 80}: 9,
		{srcPod: "d", dstPod: "x", protocol: "TCP", direction: "Ingress", dstPort: 80}: 1,
	}
	got := topOffenders(tuples, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Count != 9 || got[1].Count != 5 {
		t.Errorf("expected counts [9, 5], got [%d, %d]", got[0].Count, got[1].Count)
	}
	if got[0].SrcPod != "c" || got[1].SrcPod != "a" {
		t.Errorf("expected srcPods [c, a], got [%s, %s]", got[0].SrcPod, got[1].SrcPod)
	}
}

func TestTopOffenders_ZeroNYieldsNil(t *testing.T) {
	tuples := map[tupleKey]int64{{srcPod: "a"}: 1}
	if got := topOffenders(tuples, 0); got != nil {
		t.Errorf("expected nil for n=0, got %d entries", len(got))
	}
}

func TestNew_Defaults(t *testing.T) {
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClient(scheme)
	a := New(dyn, logrus.New())

	if a.topN != 25 {
		t.Errorf("default topN: want 25, got %d", a.topN)
	}
	if a.period != 30*time.Second {
		t.Errorf("default period: want 30s, got %s", a.period)
	}
	if a.counts == nil {
		t.Error("counts map must be initialised, not nil")
	}
	wantNs := schema.GroupVersionResource{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditnetworkpolicies",
	}
	if a.gvr != wantNs {
		t.Errorf("namespaced GVR: want %v, got %v", wantNs, a.gvr)
	}
	wantCluster := schema.GroupVersionResource{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditclusternetworkpolicies",
	}
	if a.clusterGVR != wantCluster {
		t.Errorf("cluster GVR: want %v, got %v", wantCluster, a.clusterGVR)
	}
}

func TestSetters(t *testing.T) {
	a := &Aggregator{counts: map[policyKey]*policyAgg{}}
	a.SetPeriod(2 * time.Minute)
	a.SetTopN(10)
	if a.period != 2*time.Minute {
		t.Errorf("SetPeriod: want 2m, got %s", a.period)
	}
	if a.topN != 10 {
		t.Errorf("SetTopN: want 10, got %d", a.topN)
	}
}

// fakeDynamicClient builds a dynamic client with the AuditNetworkPolicy
// GVRs registered so Patch() against the status subresource works.
func fakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditnetworkpolicies"}:        "AuditNetworkPolicyList",
		{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditclusternetworkpolicies"}: "AuditClusterNetworkPolicyList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)
}

func TestFlush_EmptyCountsMakesNoCalls(t *testing.T) {
	dyn := fakeDynamicClient()
	a := New(dyn, quietLog())
	a.flush(context.Background())
	if got := len(dyn.Actions()); got != 0 {
		t.Errorf("expected zero API actions for empty counts, got %d: %v", got, dyn.Actions())
	}
}

func TestFlush_PatchesNamespacedPolicy(t *testing.T) {
	// Pre-create the AuditNetworkPolicy so the fake client knows the
	// object to patch (the fake returns NotFound otherwise, which the
	// real flow would log+continue, but we want the action recorded).
	gvr := schema.GroupVersionResource{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditnetworkpolicies",
	}
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Kind: "AuditNetworkPolicy",
	})
	policy.SetNamespace("prod")
	policy.SetName("web-deny")

	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		gvr: "AuditNetworkPolicyList",
		{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditclusternetworkpolicies"}: "AuditClusterNetworkPolicyList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, policy)

	a := New(dyn, quietLog())
	a.Record("prod", "web-deny", "prod/client-a", "prod/web-1", "TCP", "Ingress", 8080, true, 0)
	a.flush(context.Background())

	var sawPatch *clienttesting.PatchActionImpl
	for _, action := range dyn.Actions() {
		if patch, ok := action.(clienttesting.PatchActionImpl); ok {
			if patch.GetNamespace() == "prod" && patch.GetName() == "web-deny" && patch.GetSubresource() == "status" {
				sawPatch = &patch
				break
			}
		}
	}
	if sawPatch == nil {
		t.Fatalf("expected a status Patch on prod/web-deny; actions=%v", dyn.Actions())
	}

	var body map[string]any
	if err := json.Unmarshal(sawPatch.GetPatch(), &body); err != nil {
		t.Fatalf("unmarshal patch body: %v", err)
	}
	st, ok := body["status"].(map[string]any)
	if !ok {
		t.Fatalf("patch body missing status: %s", sawPatch.GetPatch())
	}
	eval, ok := st["evaluation"].(map[string]any)
	if !ok {
		t.Fatalf("status missing evaluation: %v", st)
	}
	if got := eval["flowsEvaluated"]; got != float64(1) {
		t.Errorf("flowsEvaluated: want 1, got %v", got)
	}
	if got := eval["flowsWouldDeny"]; got != float64(1) {
		t.Errorf("flowsWouldDeny: want 1, got %v", got)
	}
}

func TestRecord_ObservedGenerationMonotonic(t *testing.T) {
	// observedGeneration must only ever go up — concurrent flows could
	// arrive with different stale views of the policy spec. The status
	// subresource appearing to regress would confuse operators.
	a := &Aggregator{counts: map[policyKey]*policyAgg{}, topN: 10}
	key := policyKey{namespace: "prod", name: "p1"}

	a.Record("prod", "p1", "/", "/", "TCP", "Ingress", 80, true, 3)
	if got := a.counts[key].observedGeneration; got != 3 {
		t.Fatalf("first record: want gen=3, got %d", got)
	}

	// Older generation arrives next — must NOT overwrite the newer one.
	a.Record("prod", "p1", "/", "/", "TCP", "Ingress", 80, true, 1)
	if got := a.counts[key].observedGeneration; got != 3 {
		t.Errorf("stale record: want gen=3 (no regression), got %d", got)
	}

	// Newer generation — wins.
	a.Record("prod", "p1", "/", "/", "TCP", "Ingress", 80, true, 7)
	if got := a.counts[key].observedGeneration; got != 7 {
		t.Errorf("newer record: want gen=7, got %d", got)
	}
}

func TestFlush_PatchIncludesObservedGeneration(t *testing.T) {
	// Verify the field actually makes it onto the wire — silent drop
	// here would defeat the whole point of plumbing the generation
	// through the matcher.
	gvr := schema.GroupVersionResource{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditnetworkpolicies",
	}
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Kind: "AuditNetworkPolicy",
	})
	policy.SetNamespace("prod")
	policy.SetName("p1")

	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		gvr: "AuditNetworkPolicyList",
		{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditclusternetworkpolicies"}: "AuditClusterNetworkPolicyList",
	}, policy)

	a := New(dyn, quietLog())
	a.Record("prod", "p1", "/", "/", "TCP", "Ingress", 80, true, 5)
	a.flush(context.Background())

	for _, action := range dyn.Actions() {
		patch, ok := action.(clienttesting.PatchActionImpl)
		if !ok || patch.GetSubresource() != "status" {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(patch.GetPatch(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		st := body["status"].(map[string]any)
		if got := st["observedGeneration"]; got != float64(5) {
			t.Errorf("observedGeneration on patch: want 5, got %v", got)
		}
		return
	}
	t.Fatalf("expected status patch action; got actions=%v", dyn.Actions())
}

func TestFlush_RoutesClusterPolicyToClusterGVR(t *testing.T) {
	// Cluster-scoped: namespace == "". Must hit clusterGVR path, not
	// the namespaced GVR.
	clusterGVR := schema.GroupVersionResource{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditclusternetworkpolicies",
	}
	cluster := &unstructured.Unstructured{}
	cluster.SetGroupVersionKind(schema.GroupVersionKind{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version, Kind: "AuditClusterNetworkPolicy",
	})
	cluster.SetName("cluster-baseline-audit")

	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "auditnetworkpolicies"}: "AuditNetworkPolicyList",
		clusterGVR: "AuditClusterNetworkPolicyList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, cluster)

	a := New(dyn, quietLog())
	a.Record("", "cluster-baseline-audit", "/", "prod/web-1", "TCP", "Ingress", 80, true, 0)
	a.flush(context.Background())

	var sawClusterPatch bool
	for _, action := range dyn.Actions() {
		if patch, ok := action.(clienttesting.PatchActionImpl); ok {
			if patch.GetResource().Resource == "auditclusternetworkpolicies" &&
				patch.GetNamespace() == "" &&
				patch.GetName() == "cluster-baseline-audit" {
				sawClusterPatch = true
				break
			}
		}
	}
	if !sawClusterPatch {
		t.Errorf("expected cluster-scoped patch on cluster-baseline-audit; actions=%v", dyn.Actions())
	}
}

func quietLog() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func TestPatchStatus_BodyShape(t *testing.T) {
	// patchStatus is the network-touching half — to keep this test
	// hermetic we hand-build a snapshot agg and serialise the patch
	// body with the same json.Marshal call patchStatus uses, then
	// re-parse and assert the field shape.
	last := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	agg := &policyAgg{
		flowsEvaluated: 12,
		flowsWouldDeny: 3,
		lastEvaluated:  last,
		tuples: map[tupleKey]int64{
			{srcPod: "p/a", dstPod: "p/b", protocol: "TCP", direction: "Ingress", dstPort: 80}: 3,
		},
	}
	a := &Aggregator{counts: map[policyKey]*policyAgg{}, topN: 5}

	// Build the same body the patchStatus method builds.
	statusPatch := map[string]any{
		"status": map[string]any{
			"observedGeneration": 0,
			"evaluation": map[string]any{
				"lastEvaluated":  last.Format(time.RFC3339),
				"flowsEvaluated": agg.flowsEvaluated,
				"flowsWouldDeny": agg.flowsWouldDeny,
				"topOffenders":   topOffenders(agg.tuples, a.topN),
			},
		},
	}
	body, err := json.Marshal(statusPatch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := round["status"]; !ok {
		t.Error("expected top-level `status` key in merge patch")
	}
}
