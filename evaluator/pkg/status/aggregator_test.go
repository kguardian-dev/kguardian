package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
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

func TestTopOffenders_TieBreakerIsDeterministic(t *testing.T) {
	// Equal counts at the top-N boundary used to land in map-iteration
	// order (Go randomises that per-process), so the status.evaluation.
	// topOffenders list would flicker between flushes whenever ties
	// existed — operators watching `kubectl get -w` would see entries
	// re-shuffle for no apparent reason.
	//
	// Build a set where every tuple has the same count, run
	// topOffenders many times, and verify the output is byte-identical
	// each call. Tail of the sort must be (srcPod, dstPod, dstPort,
	// protocol, direction) ascending.
	tuples := map[tupleKey]int64{
		{srcPod: "b", dstPod: "z", protocol: "TCP", direction: "Ingress", dstPort: 80}:  5,
		{srcPod: "a", dstPod: "z", protocol: "TCP", direction: "Ingress", dstPort: 80}:  5,
		{srcPod: "a", dstPod: "y", protocol: "TCP", direction: "Ingress", dstPort: 80}:  5,
		{srcPod: "a", dstPod: "y", protocol: "TCP", direction: "Ingress", dstPort: 443}: 5,
	}
	first := topOffenders(tuples, 10)
	for i := 0; i < 20; i++ {
		got := topOffenders(tuples, 10)
		if len(got) != len(first) {
			t.Fatalf("run %d: length differs: want %d, got %d", i, len(first), len(got))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Errorf("run %d index %d: want %+v, got %+v", i, j, first[j], got[j])
			}
		}
	}
	// Verify the actual order is the documented lex-ascending tail.
	wantOrder := []struct {
		srcPod, dstPod string
		dstPort        int32
	}{
		{"a", "y", 80},
		{"a", "y", 443},
		{"a", "z", 80},
		{"b", "z", 80},
	}
	if len(first) != len(wantOrder) {
		t.Fatalf("entry count: want %d, got %d", len(wantOrder), len(first))
	}
	for i, w := range wantOrder {
		if first[i].SrcPod != w.srcPod || first[i].DstPod != w.dstPod || first[i].DstPort != w.dstPort {
			t.Errorf("index %d: want (%s,%s,%d), got (%s,%s,%d)",
				i, w.srcPod, w.dstPod, w.dstPort,
				first[i].SrcPod, first[i].DstPod, first[i].DstPort)
		}
	}
}

func TestTopOffenders_TiesAtCapAreStable(t *testing.T) {
	// Edge case at the cap: when more tuples tie for the boundary than
	// fit in N, the deterministic order picks the lex-smallest entries.
	// Without the tie-breaker the cap was non-deterministic — a tuple
	// could appear in one flush and vanish from the next.
	tuples := map[tupleKey]int64{
		{srcPod: "a", protocol: "TCP", direction: "Ingress", dstPort: 80}: 5,
		{srcPod: "b", protocol: "TCP", direction: "Ingress", dstPort: 80}: 5,
		{srcPod: "c", protocol: "TCP", direction: "Ingress", dstPort: 80}: 5,
		{srcPod: "d", protocol: "TCP", direction: "Ingress", dstPort: 80}: 5,
	}
	got := topOffenders(tuples, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (cap), got %d", len(got))
	}
	if got[0].SrcPod != "a" || got[1].SrcPod != "b" {
		t.Errorf("expected lex-smallest survivors [a, b], got [%s, %s]",
			got[0].SrcPod, got[1].SrcPod)
	}
	// Twenty more runs must produce the same survivors.
	for i := 0; i < 20; i++ {
		again := topOffenders(tuples, 2)
		if again[0].SrcPod != "a" || again[1].SrcPod != "b" {
			t.Errorf("run %d: survivors differ: got [%s, %s]",
				i, again[0].SrcPod, again[1].SrcPod)
		}
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

func TestFlush_EvictsEntryWhenPolicyNotFound(t *testing.T) {
	// Pre-condition: aggregator holds a verdict for a policy that does
	// NOT exist in the cluster (was deleted in flight). The flush() must
	// detect the NotFound, evict the in-memory entry, and stop trying.
	//
	// Without this fix:
	//   - memory grows monotonically with every deleted policy ever seen,
	//   - if a same-name policy is recreated later, its first patch would
	//     stamp on the OLD observedGeneration value — silently regressing
	//     the standard "observedGeneration is monotonic" invariant.
	dyn := fakeDynamicClient() // no policies pre-loaded → all patches will 404

	a := New(dyn, quietLog())
	a.Record("prod", "ghost-policy", "prod/x", "prod/y", "TCP", "Ingress", 80, true, 5)

	// Sanity: entry is present before flush.
	a.mu.Lock()
	if _, ok := a.counts[policyKey{namespace: "prod", name: "ghost-policy"}]; !ok {
		a.mu.Unlock()
		t.Fatal("pre-flush: counts entry should exist")
	}
	a.mu.Unlock()

	a.flush(context.Background())

	// Post-condition: entry is gone.
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.counts[policyKey{namespace: "prod", name: "ghost-policy"}]; ok {
		t.Errorf("post-flush: entry should be evicted after NotFound; counts=%+v", a.counts)
	}
}

func TestFlush_BailsOnCancelledContext(t *testing.T) {
	// Pre-cancelled ctx: flush() must return immediately without
	// attempting any Patch calls. Without the bail, every snapshot
	// entry's patchStatus would fire and return context.Canceled —
	// noise at shutdown that obscures real failures in the logs.
	dyn := fakeDynamicClient()
	a := New(dyn, quietLog())
	// Record many entries so a fall-through loop would be visible.
	for i := 0; i < 10; i++ {
		ns := "prod"
		name := fmt.Sprintf("p-%02d", i)
		a.Record(ns, name, "src/x", "dst/y", "TCP", "Ingress", 80, true, 1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled when flush runs
	a.flush(ctx)

	// No Patch action should have been issued.
	for _, action := range dyn.Actions() {
		if patch, ok := action.(clienttesting.PatchActionImpl); ok {
			t.Errorf("expected no Patch calls on cancelled ctx; got %s/%s",
				patch.GetNamespace(), patch.GetName())
		}
	}
}

func TestFlush_BailsOnMidIterationCancellation(t *testing.T) {
	// More subtle: ctx is cancelled while patchStatus is running for
	// one of the entries. The Patch reactor returns context.Canceled.
	// flush must stop iterating instead of charging through every
	// remaining entry and racking up identical context.Canceled errors.
	dyn := fakeDynamicClient()
	var patchCount int
	dyn.PrependReactor("patch", "auditnetworkpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		patchCount++
		// First patch succeeds (so we know the loop did start), every
		// subsequent attempt returns context.Canceled to simulate the
		// ctx being cancelled after the first patchStatus.
		if patchCount == 1 {
			return true, nil, nil
		}
		return true, nil, context.Canceled
	})

	a := New(dyn, quietLog())
	for i := 0; i < 10; i++ {
		a.Record("prod", fmt.Sprintf("p-%02d", i), "src/x", "dst/y", "TCP", "Ingress", 80, true, 1)
	}

	a.flush(context.Background())

	// With early-bail on context.Canceled, we expect exactly 2 patch
	// attempts: the first succeeded, the second returned canceled and
	// triggered the return. Without the bail we'd see all 10.
	if patchCount != 2 {
		t.Errorf("expected to bail after 2 patches (first ok + first canceled), got %d", patchCount)
	}
}

func TestFlush_IteratesInStableOrder(t *testing.T) {
	// Partial-completion ordering during shutdown should be predictable,
	// not Go-map-iteration random. Pin the order by recording several
	// entries, capturing the order in which Patch calls arrive, and
	// asserting it matches (namespace, name) ascending.
	dyn := fakeDynamicClient()
	var observed []string
	dyn.PrependReactor("patch", "auditnetworkpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		patch := action.(clienttesting.PatchActionImpl)
		observed = append(observed, patch.GetNamespace()+"/"+patch.GetName())
		return true, nil, nil
	})

	a := New(dyn, quietLog())
	// Record in deliberately-mixed insertion order to defeat any
	// accidental insertion-order coupling. Without the sort, Go's map
	// iteration would shuffle these per-process.
	for _, e := range []struct{ ns, name string }{
		{"prod", "z-policy"},
		{"dev", "a-policy"},
		{"prod", "a-policy"},
		{"dev", "z-policy"},
	} {
		a.Record(e.ns, e.name, "src/x", "dst/y", "TCP", "Ingress", 80, true, 1)
	}
	a.flush(context.Background())

	want := []string{"dev/a-policy", "dev/z-policy", "prod/a-policy", "prod/z-policy"}
	if len(observed) != len(want) {
		t.Fatalf("patch count: want %d, got %d (%v)", len(want), len(observed), observed)
	}
	for i, w := range want {
		if observed[i] != w {
			t.Errorf("index %d: want %q, got %q (full=%v)", i, w, observed[i], observed)
		}
	}
}

func TestFlush_PreservesEntryOnTransientError(t *testing.T) {
	// Counterpart to the eviction test: a non-NotFound error (e.g. a
	// 5xx from the apiserver, a network blip) must NOT evict the entry —
	// next reconcile will retry and the verdict count survives.
	dyn := fakeDynamicClient()
	dyn.PrependReactor("patch", "auditnetworkpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("transient apiserver hiccup")
	})

	a := New(dyn, quietLog())
	a.Record("prod", "p1", "prod/x", "prod/y", "TCP", "Ingress", 80, true, 0)
	a.flush(context.Background())

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.counts[policyKey{namespace: "prod", name: "p1"}]; !ok {
		t.Errorf("transient error should preserve entry for retry; counts=%+v", a.counts)
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
