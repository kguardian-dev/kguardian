package trivy

import (
	"context"
	"fmt"
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
// If the CRDs are not served (Trivy Operator not installed) the watcher
// idles, reports the source unavailable, and re-checks discovery every
// RecheckPeriod. It never fails the process for a missing optional source.
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
	// RecheckPeriod is how often discovery is retried while the CRDs are
	// absent. Default 5m.
	RecheckPeriod time.Duration

	ready atomic.Bool
}

// Ready is true once the source has either synced its caches or
// established that the CRDs are absent.
func (w *Watcher) Ready() bool { return w.ready.Load() }

// Run blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	if w.ResyncPeriod <= 0 {
		w.ResyncPeriod = 10 * time.Minute
	}
	if w.RecheckPeriod <= 0 {
		w.RecheckPeriod = 5 * time.Minute
	}
	loggedAbsent := false
	for {
		served, err := w.servedResources(ctx)
		if err != nil {
			w.Log.WithError(err).Warn("trivy-operator: discovery failed; will retry")
		}
		if len(served) > 0 {
			w.setAvailable(true)
			return w.watch(ctx, served)
		}
		w.setAvailable(false)
		w.ready.Store(true) // nothing to sync: an absent optional source is a ready state
		if !loggedAbsent && err == nil {
			w.Log.WithField("recheck", w.RecheckPeriod.String()).
				Info("trivy-operator: VulnerabilityReport/SbomReport CRDs not served; source idle")
			loggedAbsent = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(w.RecheckPeriod):
		}
	}
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
// serves.
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
	return out, nil
}

func (w *Watcher) watch(ctx context.Context, gvrs []schema.GroupVersionResource) error {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(w.Dynamic, w.ResyncPeriod)
	var synced []cache.InformerSynced
	for _, gvr := range gvrs {
		inf := factory.ForResource(gvr).Informer()
		// Reports are the largest objects this process caches; drop the
		// fields it never reads before they are stored.
		if err := inf.SetTransform(stripUnused); err != nil {
			return fmt.Errorf("setting transform for %s: %w", gvr.Resource, err)
		}
		kind := KindVulnerabilities
		if gvr == SbomReportGVR {
			kind = KindSBOM
		}
		if _, err := inf.AddEventHandler(w.handlers(ctx, kind)); err != nil {
			return fmt.Errorf("adding handler for %s: %w", gvr.Resource, err)
		}
		synced = append(synced, inf.HasSynced)
		w.Log.WithField("resource", gvr.Resource).Info("trivy-operator: watching")
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), synced...) {
		return ctx.Err()
	}
	w.ready.Store(true)
	w.updateGauges()
	w.Log.Info("trivy-operator: caches synced")
	<-ctx.Done()
	factory.Shutdown()
	return nil
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

// stripUnused drops managedFields and the last-applied annotation from
// cached report objects.
func stripUnused(obj interface{}) (interface{}, error) {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		u.SetManagedFields(nil)
		if ann := u.GetAnnotations(); ann != nil {
			delete(ann, "kubectl.kubernetes.io/last-applied-configuration")
			u.SetAnnotations(ann)
		}
	}
	return obj, nil
}
