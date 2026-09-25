// Package metrics holds the component's Prometheus metrics on a private
// registry (no global default registry, so tests can build their own).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics is the set of collectors the component exports on /metrics.
type Metrics struct {
	Registry *prometheus.Registry

	// ReportEvents counts informer events per source, report kind and
	// event (add, update, delete, decode_error).
	ReportEvents *prometheus.CounterVec
	// SourceAvailable is 1 when a source's API is served (e.g. the Trivy
	// Operator CRDs are installed), else 0.
	SourceAvailable *prometheus.GaugeVec
	// TrackedDigests is the number of distinct image digests held per kind.
	TrackedDigests *prometheus.GaugeVec
	// UnresolvedReports counts reports held back because no digest could
	// be resolved for them.
	UnresolvedReports *prometheus.GaugeVec
	// Emissions counts payloads handed to the broker client, by kind and
	// result (ok, error).
	Emissions *prometheus.CounterVec
	// PendingEmissions is the size of the coalescing send queue.
	PendingEmissions prometheus.Gauge
}

// New builds and registers all collectors, plus the standard Go and
// process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		ReportEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_report_events_total",
			Help: "Source report events observed, by source, kind and event.",
		}, []string{"source", "kind", "event"}),
		SourceAvailable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_source_available",
			Help: "1 when the source's API is served in this cluster, else 0.",
		}, []string{"source"}),
		TrackedDigests: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_tracked_digests",
			Help: "Distinct image digests currently tracked, by source and kind.",
		}, []string{"source", "kind"}),
		UnresolvedReports: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_unresolved_reports",
			Help: "Reports held back because no image digest could be resolved.",
		}, []string{"source", "kind"}),
		Emissions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_emissions_total",
			Help: "Payloads handed to the broker client, by kind and result.",
		}, []string{"kind", "result"}),
		PendingEmissions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_pending_emissions",
			Help: "Payloads waiting in the coalescing send queue.",
		}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.ReportEvents, m.SourceAvailable, m.TrackedDigests,
		m.UnresolvedReports, m.Emissions, m.PendingEmissions,
	)
	return m
}
