package trivy

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

type recordingSink struct {
	mu sync.Mutex
	es []Emission
}

func (s *recordingSink) Enqueue(e Emission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.es = append(s.es, e)
}

func (s *recordingSink) snapshot() []Emission {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Emission(nil), s.es...)
}

func quietLog() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func discoveryWith(resources ...string) *fakediscovery.FakeDiscovery {
	d := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}
	if len(resources) > 0 {
		list := &metav1.APIResourceList{GroupVersion: Group + "/" + Version}
		for _, r := range resources {
			list.APIResources = append(list.APIResources, metav1.APIResource{Name: r, Namespaced: true})
		}
		d.Resources = []*metav1.APIResourceList{list}
	}
	return d
}

// Without Trivy Operator installed the source must idle, report itself
// unavailable and still let the process become ready (AT1.2).
func TestWatcherAbsentCRDsIsReadyAndIdle(t *testing.T) {
	m := metrics.New()
	sink := &recordingSink{}
	w := &Watcher{
		Discovery:     discoveryWith(),
		Tracker:       NewTracker(nil),
		Sink:          sink,
		Log:           quietLog(),
		Metrics:       m,
		RecheckPeriod: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	waitFor(t, w.Ready)
	if v := testutil.ToFloat64(m.SourceAvailable.WithLabelValues(SourceName)); v != 0 {
		t.Errorf("source_available = %v", v)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
	if len(sink.snapshot()) != 0 {
		t.Error("emitted without a source")
	}
}

func toUnstructured(t *testing.T, name, kind string) *unstructured.Unstructured {
	t.Helper()
	obj := loadObject(t, name)
	u := &unstructured.Unstructured{Object: obj}
	u.SetKind(kind)
	return u
}

// End to end through a fake API server: list/watch both report kinds,
// correlate, de-duplicate, and emit per digest.
func TestWatcherListsAndWatches(t *testing.T) {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		VulnerabilityReportGVR: "VulnerabilityReportList",
		SbomReportGVR:          "SbomReportList",
	}
	dyn := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds,
		toUnstructured(t, "vulnerabilityreport-apiserver-tagonly.yaml", "VulnerabilityReport"),
		toUnstructured(t, "sbomreport-docs.yaml", "SbomReport"),
		toUnstructured(t, "vulnerabilityreport-api-digest.yaml", "VulnerabilityReport"),
	)
	m := metrics.New()
	sink := &recordingSink{}
	w := &Watcher{
		Dynamic:      dyn,
		Discovery:    discoveryWith("vulnerabilityreports", "sbomreports"),
		Tracker:      NewTracker(nil),
		Sink:         sink,
		Log:          quietLog(),
		Metrics:      m,
		ResyncPeriod: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	waitFor(t, w.Ready)

	// apiserver: SBOM + vulns (tag-only report resolved via the SBOM);
	// api: vulns. Arrival order between the two informers is not fixed,
	// but the final per-digest set is.
	waitFor(t, func() bool { return len(sink.snapshot()) >= 3 })
	got := map[string]bool{}
	for _, e := range sink.snapshot() {
		got[string(e.Kind)+" "+e.Digest] = true
	}
	for _, want := range []string{
		"sbom " + apiserverDigest,
		"vulnerabilities " + apiserverDigest,
		"vulnerabilities " + apiDigest,
	} {
		if !got[want] {
			t.Errorf("missing emission %q; got %v", want, got)
		}
	}
	if v := testutil.ToFloat64(m.SourceAvailable.WithLabelValues(SourceName)); v != 1 {
		t.Errorf("source_available = %v", v)
	}

	// A watch event: a second workload on the api image adds no emission.
	before := len(sink.snapshot())
	replica := toUnstructured(t, "vulnerabilityreport-api-digest.yaml", "VulnerabilityReport")
	replica.SetName("replicaset-api-2-api")
	replica.SetUID("api-2")
	labels := replica.GetLabels()
	labels[LabelResourceName] = "api-2"
	replica.SetLabels(labels)
	if _, err := dyn.Resource(VulnerabilityReportGVR).Namespace("shop").Create(ctx, replica, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		return testutil.ToFloat64(m.ReportEvents.WithLabelValues(SourceName, string(KindVulnerabilities), "add")) >= 3
	})
	if after := len(sink.snapshot()); after != before {
		t.Errorf("replica with identical image re-emitted (%d -> %d)", before, after)
	}
	if v := testutil.ToFloat64(m.TrackedDigests.WithLabelValues(SourceName, string(KindVulnerabilities))); v != 2 {
		t.Errorf("tracked vuln digests = %v", v)
	}
}

func TestWatcherBadObjectIsCountedNotFatal(t *testing.T) {
	m := metrics.New()
	w := &Watcher{Tracker: NewTracker(nil), Sink: &recordingSink{}, Log: quietLog(), Metrics: m}
	bad := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "x", "namespace": "y"},
		"report":   map[string]interface{}{"vulnerabilities": "not-a-list"},
	}}
	w.handle(context.Background(), KindVulnerabilities, "add", bad)
	if v := testutil.ToFloat64(m.ReportEvents.WithLabelValues(SourceName, string(KindVulnerabilities), "decode_error")); v != 1 {
		t.Errorf("decode_error = %v", v)
	}
}

func TestStripUnused(t *testing.T) {
	u := toUnstructured(t, "vulnerabilityreport-api-digest.yaml", "VulnerabilityReport")
	u.SetAnnotations(map[string]string{
		"kubectl.kubernetes.io/last-applied-configuration": strings.Repeat("x", 100),
		"keep": "me",
	})
	if len(u.GetManagedFields()) == 0 {
		t.Fatal("fixture should carry managedFields")
	}
	out, err := stripUnused(u)
	if err != nil {
		t.Fatal(err)
	}
	s := out.(*unstructured.Unstructured)
	if len(s.GetManagedFields()) != 0 {
		t.Error("managedFields kept")
	}
	if a := s.GetAnnotations(); len(a) != 1 || a["keep"] != "me" {
		t.Errorf("annotations: %v", a)
	}
}

func TestFlexString(t *testing.T) {
	var v struct {
		A flexString `json:"a"`
		B flexString `json:"b"`
		C flexString `json:"c"`
	}
	if err := roundTrip(map[string]interface{}{"a": 1.4, "b": "1.16", "c": nil}, &v); err != nil {
		t.Fatal(err)
	}
	if v.A != "1.4" || v.B != "1.16" || v.C != "" {
		t.Errorf("%+v", v)
	}
}
