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
	// Dropped counts payloads discarded as non-retryable, by kind and
	// reason (http_<code>, too_large, encoding).
	Dropped *prometheus.CounterVec
	// SourceHealthy is 0 while a source's watch is failing repeatedly.
	SourceHealthy *prometheus.GaugeVec
	// RegistryLookups counts uncached registry lookups by result (index,
	// manifest, unknown, skipped).
	RegistryLookups *prometheus.CounterVec
	// RegistryLookupsSkipped counts lookups refused by the address guard,
	// by reason.
	RegistryLookupsSkipped *prometheus.CounterVec
	// RegistrySBOMLookups counts registry SBOM lookups per digest by
	// result (found, none, error, skipped_<reason>, list_error).
	RegistrySBOMLookups *prometheus.CounterVec
	// Grype matching (vulnerability source B).
	GrypeDBBuilt      prometheus.Gauge
	GrypeMatchRuns    *prometheus.CounterVec
	GrypeMatches      prometheus.Counter
	GrypeMatchSeconds prometheus.Histogram
	GrypeSBOMsHeld    prometheus.Gauge
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
			Help: "Payloads handed to the broker client, by kind and result (ok, retry, dropped).",
		}, []string{"kind", "result"}),
		Dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_emissions_dropped_total",
			Help: "Payloads dropped as non-retryable, by kind and reason.",
		}, []string{"kind", "reason"}),
		RegistryLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_registry_lookups_total",
			Help: "Uncached registry digest lookups, by result (index, manifest, unknown, skipped).",
		}, []string{"result"}),
		RegistryLookupsSkipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_registry_lookups_skipped_total",
			Help: "Registry lookups refused by the address guard, by reason.",
		}, []string{"reason"}),
		RegistrySBOMLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_registry_sbom_lookups_total",
			Help: "Registry SBOM lookups per digest, by result.",
		}, []string{"result"}),
		GrypeDBBuilt: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_grype_db_built_timestamp_seconds",
			Help: "Build time of the loaded Grype database (Unix seconds); DB age is time() minus this.",
		}),
		GrypeMatchRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_grype_match_runs_total",
			Help: "SBOM match runs, by result (ok, error).",
		}, []string{"result"}),
		GrypeMatches: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kguardian_supplychain_grype_matches_total",
			Help: "Vulnerabilities returned by successful match runs.",
		}),
		GrypeMatchSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kguardian_supplychain_grype_match_duration_seconds",
			Help:    "Time to match one SBOM.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 12),
		}),
		GrypeSBOMsHeld: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_grype_sboms_held",
			Help: "SBOMs held for (re-)matching, one per digest.",
		}),
		SourceHealthy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_source_healthy",
			Help: "0 while a source's list/watch is failing repeatedly, else 1.",
		}, []string{"source"}),
		PendingEmissions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_pending_emissions",
			Help: "Payloads waiting in the coalescing send queue.",
		}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.ReportEvents, m.SourceAvailable, m.TrackedDigests,
		m.UnresolvedReports, m.Emissions, m.Dropped, m.SourceHealthy, m.RegistryLookups, m.RegistryLookupsSkipped, m.RegistrySBOMLookups,
		m.GrypeDBBuilt, m.GrypeMatchRuns, m.GrypeMatches, m.GrypeMatchSeconds, m.GrypeSBOMsHeld, m.PendingEmissions,
	)
	return m
}
