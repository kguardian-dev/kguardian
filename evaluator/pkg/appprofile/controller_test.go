package appprofile

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

type appliedPatch struct {
	namespace, name, subresource string
	patchType                    types.PatchType
	body                         map[string]any
}

// newTestController wires a Controller to a fake dynamic client holding
// objs and records every patch it sends.
func newTestController(t *testing.T, b Broker, objs ...runtime.Object) (*Controller, *[]appliedPatch, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{GVR: "ApplicationSecurityProfileList"}, objs...)
	var mu sync.Mutex
	patches := &[]appliedPatch{}
	dyn.PrependReactor("patch", "applicationsecurityprofiles", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pa := a.(clienttesting.PatchAction)
		var body map[string]any
		if err := json.Unmarshal(pa.GetPatch(), &body); err != nil {
			t.Fatalf("patch body is not JSON: %v", err)
		}
		mu.Lock()
		*patches = append(*patches, appliedPatch{pa.GetNamespace(), pa.GetName(), pa.GetSubresource(), pa.GetPatchType(), body})
		mu.Unlock()
		return true, &unstructured.Unstructured{Object: body}, nil
	})
	log := logrus.New()
	log.SetOutput(io.Discard)
	c := New(dyn, b, time.Hour, 0, log)
	c.now = func() time.Time { return now }
	return c, patches, dyn
}

func aspObject(name, kind, workload string, created time.Time, accepted *int64) *unstructured.Unstructured {
	spec := map[string]any{"workloadRef": map[string]any{"kind": kind, "name": workload}}
	if accepted != nil {
		spec["acceptedRevision"] = *accepted
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kguardian.dev/v1alpha1",
		"kind":       "ApplicationSecurityProfile",
		"metadata": map[string]any{
			"name":              name,
			"namespace":         "payments",
			"generation":        int64(1),
			"creationTimestamp": created.UTC().Format(time.RFC3339),
		},
		"spec": spec,
	}}
}

func syncInformer(t *testing.T, ctx context.Context, c *Controller) {
	t.Helper()
	go c.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		t.Fatal("informer did not sync")
	}
}

func TestReconcile_AppliesStatusOnlyWithServerSideApply(t *testing.T) {
	b := &fakeBroker{profile: profileFixture()}
	c, patches, _ := newTestController(t, b, aspObject("refunds", "Deployment", "refunds", now.Add(-time.Hour), nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncInformer(t, ctx, c)

	if err := c.reconcile(ctx, "payments/refunds"); err != nil {
		t.Fatal(err)
	}
	if len(*patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(*patches))
	}
	p := (*patches)[0]
	if p.patchType != types.ApplyPatchType || p.subresource != "status" {
		t.Errorf("want server-side apply on status, got %s on %q", p.patchType, p.subresource)
	}
	if p.namespace != "payments" || p.name != "refunds" {
		t.Errorf("target = %s/%s", p.namespace, p.name)
	}
	// Only identity + status: the evaluator must never own spec fields.
	for k := range p.body {
		switch k {
		case "apiVersion", "kind", "metadata", "status":
		default:
			t.Errorf("applied object carries %q; only status may be applied", k)
		}
	}
	md := p.body["metadata"].(map[string]any)
	if len(md) != 2 {
		t.Errorf("metadata must be name+namespace only, got %v", md)
	}
	st := p.body["status"].(map[string]any)
	posture := st["posture"].(map[string]any)
	if posture["status"] != "warn" || posture["coverage"] != "0.25" {
		t.Errorf("posture = %v", posture)
	}
	if _, ok := posture["unknownDimensions"].([]any); !ok {
		t.Errorf("unknownDimensions must be a list, got %T", posture["unknownDimensions"])
	}
	if b.calls[0] != "profile payments/Deployment/refunds" {
		t.Errorf("broker calls = %v", b.calls)
	}
}

func TestReconcile_DuplicateWorkloadRefLoserIsNotEvaluated(t *testing.T) {
	b := &fakeBroker{profile: profileFixture()}
	older := aspObject("refunds", "Deployment", "refunds", now.Add(-2*time.Hour), nil)
	newer := aspObject("refunds-copy", "Deployment", "refunds", now.Add(-time.Hour), nil)
	other := aspObject("refunds-job", "CronJob", "refunds", now, nil) // different kind: not a duplicate
	c, patches, _ := newTestController(t, b, older, newer, other)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncInformer(t, ctx, c)

	for _, k := range []string{"payments/refunds-copy", "payments/refunds", "payments/refunds-job"} {
		if err := c.reconcile(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	byName := map[string]map[string]any{}
	for _, p := range *patches {
		byName[p.name] = p.body["status"].(map[string]any)
	}
	loser := byName["refunds-copy"]
	if _, has := loser["posture"]; has {
		t.Error("duplicate must not report a posture")
	}
	conds := loser["conditions"].([]any)
	found := false
	for _, c := range conds {
		m := c.(map[string]any)
		if m["type"] == v1alpha1.ConditionProfileAvailable && m["reason"] == v1alpha1.ReasonDuplicateWorkloadRef {
			found = true
		}
	}
	if !found {
		t.Errorf("loser conditions = %v", conds)
	}
	for _, n := range []string{"refunds", "refunds-job"} {
		if _, has := byName[n]["posture"]; !has {
			t.Errorf("%s should be evaluated", n)
		}
	}
	// Two evaluated resources = two broker profile reads.
	profiles := 0
	for _, call := range b.calls {
		if len(call) > 7 && call[:7] == "profile" {
			profiles++
		}
	}
	if profiles != 2 {
		t.Errorf("broker profile reads = %d, want 2 (%v)", profiles, b.calls)
	}
}

func TestReconcile_DeletedObjectIsNoop(t *testing.T) {
	b := &fakeBroker{profile: profileFixture()}
	c, patches, _ := newTestController(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncInformer(t, ctx, c)
	if err := c.reconcile(ctx, "payments/gone"); err != nil {
		t.Fatal(err)
	}
	if len(*patches) != 0 || len(b.calls) != 0 {
		t.Errorf("patches=%d calls=%v", len(*patches), b.calls)
	}
}

func TestShouldEnqueueUpdate_IgnoresOwnStatusWrites(t *testing.T) {
	base := aspObject("a", "Deployment", "a", now, nil)
	base.SetResourceVersion("1")
	if !shouldEnqueueUpdate(base, base.DeepCopy()) {
		t.Error("periodic resync (same resourceVersion) must requeue")
	}
	statusWrite := base.DeepCopy()
	statusWrite.SetResourceVersion("2") // same generation
	if shouldEnqueueUpdate(base, statusWrite) {
		t.Error("status-only update must not requeue (would loop)")
	}
	specEdit := statusWrite.DeepCopy()
	specEdit.SetGeneration(2)
	specEdit.SetResourceVersion("3")
	if !shouldEnqueueUpdate(statusWrite, specEdit) {
		t.Error("spec edit must requeue")
	}
	if shouldEnqueueUpdate(nil, specEdit) {
		t.Error("non-unstructured objects are ignored")
	}
}

func TestStatusApplyObject_RoundTripsThroughTypedStatus(t *testing.T) {
	asp := aspFixture(nil)
	st, _ := computeStatus(context.Background(), &fakeBroker{profile: profileFixture()}, asp, now, testStaleAfter)
	u, err := statusApplyObject(asp, st)
	if err != nil {
		t.Fatal(err)
	}
	back, err := fromUnstructured(u)
	if err != nil {
		t.Fatal(err)
	}
	if back.Status.Posture.Status != "warn" || back.Status.Dimensions.Images.Status != "unknown" {
		t.Errorf("round trip = %+v", back.Status)
	}
	if back.Status.Conditions[0].LastTransitionTime.IsZero() {
		t.Error("conditions need lastTransitionTime (required by the CRD schema)")
	}
}
