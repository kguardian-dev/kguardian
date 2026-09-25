package trivy

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

// SourceName labels this source in metrics and payloads.
const SourceName = "trivy-operator"

// Sink receives emissions. dispatch.Dispatcher implements it.
type Sink interface {
	Enqueue(Emission)
}

// Watcher list/watches Trivy Operator reports (get/list/watch only) and
// feeds them through a Tracker into a Sink.
//
// Lifecycle:
//   - Discovery is retried with exponential backoff until it answers; the
//     source is not ready before that.
//   - If the CRDs are not served (Trivy Operator not installed) the source
//     idles and is ready. Discovery re-runs every RecheckPeriod, and the
//     informers are (re)started whenever the set of served report
//     resources changes, so CRDs installed later get watched.
//   - While watching, the source is ready once every informer has synced
//     and none has failed WatchErrorThreshold times in a row. Missing RBAC
//     (a Forbidden list) therefore keeps the pod NotReady.
type Watcher struct {
	Dynamic   dynamic.Interface
	Discovery discovery.ServerResourcesInterfaceWithContext
	Tracker   *Tracker
	Sink      Sink
	Log       *logrus.Logger
	Metrics   *metrics.Metrics

	// ResyncPeriod re-delivers every cached report; it is also what
	// retries digest resolution for held-back reports. Default 10m.
	ResyncPeriod time.Duration
	// RecheckPeriod is how often discovery re-runs. Default 5m.
	RecheckPeriod time.Duration
	// DiscoveryMinBackoff/MaxBackoff bound the retry of a failing
	// discovery call. Defaults 1s and 2m.
	DiscoveryMinBackoff, DiscoveryMaxBackoff time.Duration
	// WatchErrorThreshold consecutive list/watch errors on one informer
	// mark the source not ready. Default 3.
	WatchErrorThreshold int

	discovered atomic.Bool
	mu         sync.Mutex
	running    *runningSet
}

type runningSet struct {
	gvrs      []schema.GroupVersionResource
	cancel    context.CancelFunc
	factory   dynamicinformer.DynamicSharedInformerFactory
	informers []*watchedInformer
}

// watchedInformer tracks consecutive list/watch failures of one informer.
// A failure streak ends when the informer's last-synced resourceVersion
// moves, i.e. a list or watch has succeeded since the last error.
type watchedInformer struct {
	inf cache.SharedIndexInformer

	mu        sync.Mutex
	errors    int
	rvAtError string
}

func (wi *watchedInformer) onError() {
	wi.mu.Lock()
	defer wi.mu.Unlock()
	wi.errors++
	wi.rvAtError = wi.inf.LastSyncResourceVersion()
}

func (wi *watchedInformer) healthy(threshold int) bool {
	wi.mu.Lock()
	defer wi.mu.Unlock()
	if wi.errors == 0 {
		return true
	}
	if wi.inf.LastSyncResourceVersion() != wi.rvAtError {
		wi.errors = 0
		return true
	}
	return wi.errors < threshold
}

func (w *Watcher) defaults() {
	if w.ResyncPeriod <= 0 {
		w.ResyncPeriod = 10 * time.Minute
	}
	if w.RecheckPeriod <= 0 {
		w.RecheckPeriod = 5 * time.Minute
	}
	if w.DiscoveryMinBackoff <= 0 {
		w.DiscoveryMinBackoff = time.Second
	}
	if w.DiscoveryMaxBackoff <= 0 {
		w.DiscoveryMaxBackoff = 2 * time.Minute
	}
	if w.WatchErrorThreshold <= 0 {
		w.WatchErrorThreshold = 3
	}
}

// Ready reports whether the source is usable: discovery has answered, and
// any running informers have synced and are not failing.
func (w *Watcher) Ready() bool {
	if !w.discovered.Load() {
		return false
	}
	w.mu.Lock()
	rs := w.running
	w.mu.Unlock()
	healthy := true
	if rs != nil {
		for _, wi := range rs.informers {
			if !wi.inf.HasSynced() {
				return false
			}
			if !wi.healthy(w.WatchErrorThreshold) {
				healthy = false
			}
		}
	}
	if w.Metrics != nil {
		v := 0.0
		if healthy {
			v = 1
		}
		w.Metrics.SourceHealthy.WithLabelValues(SourceName).Set(v)
	}
	return healthy
}

// Run blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	w.defaults()
	defer w.stop()
	backoff := w.DiscoveryMinBackoff
	for {
		served, err := w.servedResources(ctx)
		wait := w.RecheckPeriod
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			w.Log.WithError(err).WithField("retry_in", backoff.String()).
				Warn("trivy-operator: discovery failed; retrying")
			wait = backoff
			backoff = min(backoff*2, w.DiscoveryMaxBackoff)
		} else {
			backoff = w.DiscoveryMinBackoff
			w.reconcile(ctx, served)
			w.discovered.Store(true)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// reconcile (re)starts the informers when the served set changes.
func (w *Watcher) reconcile(ctx context.Context, served []schema.GroupVersionResource) {
	w.mu.Lock()
	cur := w.running
	w.mu.Unlock()
	if cur != nil && sameGVRs(cur.gvrs, served) {
		return
	}
	w.stop()
	w.setAvailable(len(served) > 0)
	if len(served) == 0 {
		w.Log.WithField("recheck", w.RecheckPeriod.String()).
			Info("trivy-operator: VulnerabilityReport/SbomReport CRDs not served; source idle")
		return
	}
	rs, err := w.start(ctx, served)
	if err != nil {
		w.Log.WithError(err).Error("trivy-operator: starting informers")
		return
	}
	w.mu.Lock()
	w.running = rs
	w.mu.Unlock()
}

func (w *Watcher) stop() {
	w.mu.Lock()
	rs := w.running
	w.running = nil
	w.mu.Unlock()
	if rs != nil {
		rs.cancel()
		rs.factory.Shutdown()
	}
}

func sameGVRs(a, b []schema.GroupVersionResource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (w *Watcher) setAvailable(ok bool) {
	if w.Metrics == nil {
		return
	}
	v := 0.0
	if ok {
		v = 1
	}
	w.Metrics.SourceAvailable.WithLabelValues(SourceName).Set(v)
}

// servedResources returns which of the two report GVRs the API server
// serves, sorted. A NotFound group version means "none".
func (w *Watcher) servedResources(ctx context.Context) ([]schema.GroupVersionResource, error) {
	list, err := w.Discovery.ServerResourcesForGroupVersionWithContext(ctx, Group+"/"+Version)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []schema.GroupVersionResource
	for _, r := range list.APIResources {
		switch r.Name {
		case VulnerabilityReportGVR.Resource:
			out = append(out, VulnerabilityReportGVR)
		case SbomReportGVR.Resource:
			out = append(out, SbomReportGVR)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out, nil
}

func (w *Watcher) start(parent context.Context, gvrs []schema.GroupVersionResource) (*runningSet, error) {
	ctx, cancel := context.WithCancel(parent)
	factory := dynamicinformer.NewDynamicSharedInformerFactory(w.Dynamic, w.ResyncPeriod)
	rs := &runningSet{gvrs: gvrs, cancel: cancel, factory: factory}
	for _, gvr := range gvrs {
		inf := factory.ForResource(gvr).Informer()
		kind := KindVulnerabilities
		if gvr == SbomReportGVR {
			kind = KindSBOM
		}
		// Reports are the largest objects this process caches: store only
		// the fields the tracker reads.
		if err := inf.SetTransform(slimTransform(kind)); err != nil {
			cancel()
			return nil, fmt.Errorf("setting transform for %s: %w", gvr.Resource, err)
		}
		wi := &watchedInformer{inf: inf}
		if err := inf.SetWatchErrorHandlerWithContext(func(ctx context.Context, r *cache.Reflector, err error) {
			wi.onError()
			cache.DefaultWatchErrorHandler(ctx, r, err)
		}); err != nil {
			cancel()
			return nil, fmt.Errorf("setting watch error handler for %s: %w", gvr.Resource, err)
		}
		if _, err := inf.AddEventHandler(w.handlers(ctx, kind)); err != nil {
			cancel()
			return nil, fmt.Errorf("adding handler for %s: %w", gvr.Resource, err)
		}
		rs.informers = append(rs.informers, wi)
		w.Log.WithField("resource", gvr.Resource).Info("trivy-operator: watching")
	}
	factory.Start(ctx.Done())
	return rs, nil
}

func (w *Watcher) handlers(ctx context.Context, kind Kind) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handle(ctx, kind, "add", obj) },
		UpdateFunc: func(_, obj interface{}) { w.handle(ctx, kind, "update", obj) },
		DeleteFunc: func(obj interface{}) { w.handle(ctx, kind, "delete", obj) },
	}
}

func (w *Watcher) handle(ctx context.Context, kind Kind, event string, obj interface{}) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	emissions, err := w.apply(ctx, kind, event, u.Object)
	if err != nil {
		w.count(kind, "decode_error")
		w.Log.WithError(err).WithFields(logrus.Fields{
			"namespace": u.GetNamespace(), "name": u.GetName(),
		}).Warn("trivy-operator: skipping report")
		return
	}
	w.count(kind, event)
	for _, e := range emissions {
		w.Sink.Enqueue(e)
	}
	w.updateGauges()
}

// apply routes one decoded event into the tracker. Split from handle so
// tests can drive it without informers.
func (w *Watcher) apply(ctx context.Context, kind Kind, event string, obj map[string]interface{}) ([]Emission, error) {
	switch kind {
	case KindVulnerabilities:
		r, err := DecodeVulnerabilityReport(obj)
		if err != nil {
			return nil, err
		}
		if event == "delete" {
			return w.Tracker.DeleteVulnerabilityReport(r), nil
		}
		return w.Tracker.UpsertVulnerabilityReport(ctx, r), nil
	case KindSBOM:
		r, err := DecodeSbomReport(obj)
		if err != nil {
			return nil, err
		}
		if event == "delete" {
			return w.Tracker.DeleteSbomReport(r), nil
		}
		return w.Tracker.UpsertSbomReport(ctx, r), nil
	}
	return nil, fmt.Errorf("unknown kind %q", kind)
}

func (w *Watcher) count(kind Kind, event string) {
	if w.Metrics != nil {
		w.Metrics.ReportEvents.WithLabelValues(SourceName, string(kind), event).Inc()
	}
}

func (w *Watcher) updateGauges() {
	if w.Metrics == nil {
		return
	}
	s := w.Tracker.Stats()
	w.Metrics.TrackedDigests.WithLabelValues(SourceName, string(KindVulnerabilities)).Set(float64(s.VulnDigests))
	w.Metrics.TrackedDigests.WithLabelValues(SourceName, string(KindSBOM)).Set(float64(s.SBOMDigests))
	w.Metrics.UnresolvedReports.WithLabelValues(SourceName, string(KindVulnerabilities)).Set(float64(s.UnresolvedVulns))
	w.Metrics.UnresolvedReports.WithLabelValues(SourceName, string(KindSBOM)).Set(float64(s.UnresolvedSBOMs))
}
