package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

// --- slim transform ---------------------------------------------------

func slimOf(t *testing.T, kind Kind, u *unstructured.Unstructured) *unstructured.Unstructured {
	t.Helper()
	out, err := slimTransform(kind)(u)
	if err != nil {
		t.Fatal(err)
	}
	return out.(*unstructured.Unstructured)
}

func jsonLen(t *testing.T, v interface{}) int {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// The cached (slim) object must normalise to exactly the same payload as
// the full object, while being smaller and free of unused fields.
func TestSlimTransformPreservesPayloadSBOM(t *testing.T) {
	full := toUnstructured(t, "sbomreport-docs.yaml", "SbomReport")
	slim := slimOf(t, KindSBOM, full.DeepCopy())

	fr, _ := DecodeSbomReport(full.Object)
	sr, err := DecodeSbomReport(slim.Object)
	if err != nil {
		t.Fatal(err)
	}
	if sbomDigest(fr) != sbomDigest(sr) || sbomDigest(sr) != apiserverDigest {
		t.Fatalf("RepoDigest lost: %q", sbomDigest(sr))
	}
	if !reflect.DeepEqual(NormaliseSBOM(fr, apiserverDigest), NormaliseSBOM(sr, apiserverDigest)) {
		t.Error("slim SBOM normalises differently")
	}
	if !reflect.DeepEqual(workloadOf(fr.Metadata), workloadOf(sr.Metadata)) || sr.Metadata.UID == "" {
		t.Error("identity lost")
	}
	raw := jsonLen(t, slim.Object)
	for _, gone := range []string{"PkgID", "LayerDiffID", "dependsOn", "serialNumber", "ownerReferences", "Santiago", "SchemaVersion"} {
		if b, _ := json.Marshal(slim.Object); strings.Contains(string(b), gone) {
			t.Errorf("slim object still contains %q", gone)
		}
	}
	if raw >= jsonLen(t, full.Object) {
		t.Errorf("slim object not smaller: %d >= %d", raw, jsonLen(t, full.Object))
	}
	if slim.GetResourceVersion() != full.GetResourceVersion() {
		t.Error("resourceVersion must survive for the reflector")
	}
}

func TestSlimTransformPreservesPayloadVulns(t *testing.T) {
	for _, name := range []string{"vulnerabilityreport-docs-extended.yaml", "vulnerabilityreport-api-digest.yaml"} {
		full := toUnstructured(t, name, "VulnerabilityReport")
		slim := slimOf(t, KindVulnerabilities, full.DeepCopy())
		fr, _ := DecodeVulnerabilityReport(full.Object)
		sr, err := DecodeVulnerabilityReport(slim.Object)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(NormaliseVulnerabilities(fr, apiDigest, nil), NormaliseVulnerabilities(sr, apiDigest, nil)) {
			t.Errorf("%s: slim report normalises differently", name)
		}
		b, _ := json.Marshal(slim.Object)
		for _, gone := range []string{"description", "security.netapp.com", "managedFields"} {
			if strings.Contains(string(b), gone) {
				t.Errorf("%s: slim object still contains %q", name, gone)
			}
		}
	}
}

func TestSlimTransformPassesThroughOddObjects(t *testing.T) {
	tomb := cache.DeletedFinalStateUnknown{Key: "a/b"}
	if out, _ := slimTransform(KindSBOM)(tomb); out != tomb {
		t.Error("tombstone altered")
	}
	bad := &unstructured.Unstructured{Object: map[string]interface{}{"report": map[string]interface{}{"vulnerabilities": "nope"}}}
	if out, _ := slimTransform(KindVulnerabilities)(bad); out != bad {
		t.Error("undecodable object should be stored unchanged so the handler counts it")
	}
}

// --- discovery lifecycle ----------------------------------------------

// switchableDiscovery serves a mutable resource list and can fail calls.
type switchableDiscovery struct {
	mu        sync.Mutex
	resources []string
	failNext  int
	calls     atomic.Int32
}

func (d *switchableDiscovery) set(resources ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resources = resources
}

func (d *switchableDiscovery) ServerResourcesForGroupVersionWithContext(_ context.Context, gv string) (*metav1.APIResourceList, error) {
	d.calls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failNext > 0 {
		d.failNext--
		return nil, errors.New("apiserver unavailable")
	}
	if len(d.resources) == 0 {
		return nil, apierrors.NewNotFound(schema.GroupResource{}, gv)
	}
	l := &metav1.APIResourceList{GroupVersion: gv}
	for _, r := range d.resources {
		l.APIResources = append(l.APIResources, metav1.APIResource{Name: r, Namespaced: true})
	}
	return l, nil
}

func (d *switchableDiscovery) ServerGroupsAndResourcesWithContext(context.Context) ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return nil, nil, nil
}
func (d *switchableDiscovery) ServerPreferredResourcesWithContext(context.Context) ([]*metav1.APIResourceList, error) {
	return nil, nil
}
func (d *switchableDiscovery) ServerPreferredNamespacedResourcesWithContext(context.Context) ([]*metav1.APIResourceList, error) {
	return nil, nil
}

func newFakeDynamic(t *testing.T, objs ...runtime.Object) *fakedynamic.FakeDynamicClient {
	t.Helper()
	return fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		VulnerabilityReportGVR: "VulnerabilityReportList",
		SbomReportGVR:          "SbomReportList",
	}, objs...)
}

// Startup discovery failures are retried with backoff, and the source is
// not ready until discovery answers.
func TestWatcherRetriesDiscoveryBeforeReady(t *testing.T) {
	disc := &switchableDiscovery{failNext: 3}
	w := &Watcher{Discovery: disc, Tracker: NewTracker(nil), Sink: &recordingSink{}, Log: quietLog(),
		DiscoveryMinBackoff: 10 * time.Millisecond, DiscoveryMaxBackoff: 20 * time.Millisecond, RecheckPeriod: time.Hour}
	if w.Ready() {
		t.Fatal("ready before discovery")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	waitFor(t, w.Ready)
	if n := disc.calls.Load(); n != 4 {
		t.Errorf("discovery called %d times, want 4 (3 failures + success)", n)
	}
}

// CRDs installed after startup get watched on the next re-discovery.
func TestWatcherPicksUpCRDsInstalledLater(t *testing.T) {
	disc := &switchableDiscovery{}
	sink := &recordingSink{}
	m := metrics.New()
	dyn := newFakeDynamic(t, toUnstructured(t, "vulnerabilityreport-api-digest.yaml", "VulnerabilityReport"))
	w := &Watcher{Dynamic: dyn, Discovery: disc, Tracker: NewTracker(nil), Sink: sink, Log: quietLog(),
		Metrics: m, RecheckPeriod: 20 * time.Millisecond, ResyncPeriod: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	waitFor(t, w.Ready)
	if testutil.ToFloat64(m.SourceAvailable.WithLabelValues(SourceName)) != 0 || len(sink.snapshot()) != 0 {
		t.Fatal("idle source emitted or reported available")
	}

	disc.set("vulnerabilityreports")
	waitFor(t, func() bool { return len(sink.snapshot()) == 1 })
	if testutil.ToFloat64(m.SourceAvailable.WithLabelValues(SourceName)) != 1 {
		t.Error("source not reported available")
	}
	// The second CRD appearing restarts the informer set without
	// re-emitting what was already sent.
	disc.set("sbomreports", "vulnerabilityreports")
	waitFor(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.running != nil && len(w.running.gvrs) == 2
	})
	waitFor(t, w.Ready)
	if n := len(sink.snapshot()); n != 1 {
		t.Errorf("restart re-emitted: %d emissions", n)
	}
	// And removal idles it again.
	disc.set()
	waitFor(t, func() bool { return testutil.ToFloat64(m.SourceAvailable.WithLabelValues(SourceName)) == 0 })
}

// Missing RBAC: a Forbidden list keeps the pod NotReady.
func TestWatcherForbiddenListIsNotReady(t *testing.T) {
	dyn := newFakeDynamic(t)
	var lists atomic.Int32
	dyn.PrependReactor("list", "vulnerabilityreports", func(clienttesting.Action) (bool, runtime.Object, error) {
		lists.Add(1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: Group, Resource: "vulnerabilityreports"}, "", errors.New("RBAC"))
	})
	disc := &switchableDiscovery{resources: []string{"vulnerabilityreports"}}
	w := &Watcher{Dynamic: dyn, Discovery: disc, Tracker: NewTracker(nil), Sink: &recordingSink{}, Log: quietLog(),
		RecheckPeriod: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	waitFor(t, func() bool { return lists.Load() >= 1 })
	time.Sleep(200 * time.Millisecond)
	if w.Ready() {
		t.Error("ready although the list is forbidden")
	}
}

// fakeRV is a SharedIndexInformer whose only live method is the resource
// version, for exercising the failure-streak logic.
type fakeRV struct {
	cache.SharedIndexInformer
	mu sync.Mutex
	rv string
}

func (f *fakeRV) LastSyncResourceVersion() string { f.mu.Lock(); defer f.mu.Unlock(); return f.rv }
func (f *fakeRV) set(rv string)                   { f.mu.Lock(); f.rv = rv; f.mu.Unlock() }

func TestWatchedInformerFailureStreak(t *testing.T) {
	inf := &fakeRV{rv: "10"}
	wi := &watchedInformer{inf: inf}
	for i := 0; i < 2; i++ {
		wi.onError()
	}
	if !wi.healthy(3) {
		t.Error("2 errors < threshold 3 should still be healthy")
	}
	wi.onError()
	if wi.healthy(3) {
		t.Error("3 consecutive errors should be unhealthy")
	}
	inf.set("11") // a list/watch succeeded since
	if !wi.healthy(3) {
		t.Error("progress should clear the streak")
	}
	if wi.errors != 0 {
		t.Error("streak not reset")
	}
}
