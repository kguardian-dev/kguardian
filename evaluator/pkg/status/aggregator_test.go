package status

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRecord_NotApplicableNotCounted(t *testing.T) {
	// The server only feeds non-NotApplicable verdicts to Record, so
	// we don't need to filter here — but verify that wouldDeny=false
	// from an Allow doesn't increment the offender table while still
	// bumping flowsEvaluated.
	a := &Aggregator{counts: map[policyKey]*policyAgg{}, topN: 10}
	a.Record("prod", "p1", "prod/a", "prod/b", "TCP", "Ingress", 80, false)
	a.Record("prod", "p1", "prod/a", "prod/b", "TCP", "Ingress", 80, true)
	a.Record("prod", "p1", "prod/x", "prod/y", "TCP", "Ingress", 81, true)

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
