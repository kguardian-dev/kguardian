// Package server exposes the evaluator's HTTP surface:
//
//	GET  /healthz     liveness probe
//	GET  /readyz      readiness probe (informer caches synced)
//	POST /evaluate    body: matcher.Flow JSON; returns []matcher.Result
//
// The server is intentionally thin — informer caches and policy lookup
// live on the Store; the server just brokers HTTP <-> matcher.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/matcher"
	"github.com/kguardian-dev/kguardian/evaluator/pkg/policycoverage"
	"github.com/kguardian-dev/kguardian/evaluator/pkg/status"
	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
	networkingv1 "k8s.io/api/networking/v1"
)

// PolicyLookup is the slice of *store.Store the server actually uses.
// Extracted as an interface so handler logic can be tested with an
// in-memory fake (see pkg/server/server_test.go).
type PolicyLookup interface {
	matcher.Lookup
	PoliciesInNamespace(ns string) []*v1alpha1.AuditNetworkPolicy
	ClusterPolicies() []*v1alpha1.AuditClusterNetworkPolicy
	// Real networking.k8s.io policies, for classifying a reported drop
	// by whether one could have caused it. Separate from the
	// AuditNetworkPolicy accessors above: those are policies the
	// operator is trialling, these are the ones actually installed.
	NetworkPoliciesInNamespace(ns string) []*networkingv1.NetworkPolicy
	PolicyCoverageKnown() bool
}

// Server is the HTTP entry point.
type Server struct {
	addr   string
	store  PolicyLookup
	agg    *status.Aggregator
	log    *logrus.Logger
	ready  atomic.Bool
	srv    *http.Server
	denied atomic.Int64 // process-wide counter for /metrics-style debugging
	extra  map[string]http.Handler
}

// Handle registers an extra handler; call before Start.
func (s *Server) Handle(path string, h http.Handler) {
	if s.extra == nil {
		s.extra = map[string]http.Handler{}
	}
	s.extra[path] = h
}

// New constructs a Server. Call Start to begin serving.
func New(addr string, st PolicyLookup, agg *status.Aggregator, log *logrus.Logger) *Server {
	return &Server{addr: addr, store: st, agg: agg, log: log}
}

// SetReady marks the server ready (call after informer caches sync).
func (s *Server) SetReady() { s.ready.Store(true) }

// Start runs the HTTP server until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/evaluate", s.handleEvaluate)
	mux.HandleFunc("/policy-coverage", s.handlePolicyCoverage)
	for p, h := range s.extra {
		mux.Handle(p, h)
	}

	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.WithField("addr", s.addr).Info("evaluator HTTP server listening")
		err := s.srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"warming up"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

// EvaluateResponse is the wire format returned by POST /evaluate.
type EvaluateResponse struct {
	Results []matcher.Result `json:"results"`
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer func() { _ = r.Body.Close() }()
	// Cap the decoder so a chatty or buggy caller can't stream us
	// arbitrary bytes. A Flow is well under 4KB; 64KB leaves plenty
	// of headroom for future fields.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	var flow matcher.Flow
	if err := json.NewDecoder(r.Body).Decode(&flow); err != nil {
		http.Error(w, "invalid flow JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if flow.Timestamp.IsZero() {
		flow.Timestamp = time.Now().UTC()
	}

	policies := s.store.PoliciesInNamespace(flow.DstPodNamespace)
	// Egress flows target the *source* pod's namespace policies.
	if flow.SrcPodNamespace != "" && flow.SrcPodNamespace != flow.DstPodNamespace {
		policies = append(policies, s.store.PoliciesInNamespace(flow.SrcPodNamespace)...)
	}

	// Initialize as a non-nil empty slice so that JSON encoding produces
	// `"results":[]` rather than `"results":null` when no policies match
	// the flow (no AuditNetworkPolicy in either namespace AND no
	// AuditClusterNetworkPolicy that returns at least NotApplicable).
	// The broker deserialises results into Vec<VerdictResult>, which
	// rejects null but accepts an empty array.
	results := make([]matcher.Result, 0)
	for _, p := range policies {
		results = append(results, matcher.Match(flow, p, s.store)...)
	}
	// Cluster-scoped policies: every flow runs against every one;
	// MatchCluster returns NotApplicable when a policy's
	// namespaceSelector / podSelector doesn't cover the subject pod.
	for _, cp := range s.store.ClusterPolicies() {
		results = append(results, matcher.MatchCluster(flow, cp, s.store)...)
	}

	for _, r := range results {
		// Drop NotApplicable from aggregation — those are policies
		// the flow doesn't even target, and inflating "flowsEvaluated"
		// with them makes the % deny rate misleading.
		if r.Verdict == matcher.VerdictNotApplicable {
			continue
		}
		wouldDeny := r.Verdict == matcher.VerdictWouldDeny
		if s.agg != nil {
			s.agg.Record(
				r.PolicyNamespace, r.PolicyName,
				flow.SrcPodNamespace+"/"+flow.SrcPodName,
				flow.DstPodNamespace+"/"+flow.DstPodName,
				string(flow.Protocol), string(r.Direction),
				flow.DstPort, wouldDeny, r.PolicyGeneration,
			)
		}
		if wouldDeny {
			s.denied.Add(1)
			s.log.WithFields(logrus.Fields{
				"policy_namespace": r.PolicyNamespace,
				"policy_name":      r.PolicyName,
				"direction":        r.Direction,
				"src":              flow.SrcPodNamespace + "/" + flow.SrcPodName,
				"dst":              flow.DstPodNamespace + "/" + flow.DstPodName,
				"port":             flow.DstPort,
				"protocol":         flow.Protocol,
				"reason":           r.Reason,
			}).Info("audit policy would deny flow")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(EvaluateResponse{Results: results})
}

// PolicyCoverageResponse says whether a real NetworkPolicy could have
// caused a reported drop for a given pod and direction.
type PolicyCoverageResponse struct {
	// Cause is "no-policy", "policy-governs" or "unknown".
	Cause string `json:"cause"`
}

// handlePolicyCoverage answers "could a policy have caused this?" for
// one pod and direction.
//
// Separate from /evaluate on purpose. /evaluate asks whether a specific
// AuditNetworkPolicy would deny a specific flow, which is a per-flow
// question against policies the operator is trialling. This asks a
// coarser question against the policies actually installed: does
// anything govern this pod at all? A "no" is conclusive and is the
// answer that reclassifies a drop, and it needs none of the port,
// protocol or peer matching /evaluate does.
//
// Never fails on missing coverage. An unsynced or unreadable
// NetworkPolicy cache returns "unknown" with a 200, because the caller
// is annotating a stored row rather than making a decision, and a 500
// here would either lose the row or wedge the broker's ingest path.
func (s *Server) handlePolicyCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	ns := q.Get("namespace")
	name := q.Get("pod")
	dir := policycoverage.Direction(q.Get("direction"))
	if ns == "" || name == "" {
		http.Error(w, "namespace and pod are required", http.StatusBadRequest)
		return
	}
	if dir != policycoverage.Egress && dir != policycoverage.Ingress {
		http.Error(w, "direction must be Ingress or Egress", http.StatusBadRequest)
		return
	}

	known := s.store.PolicyCoverageKnown()
	pod := s.store.GetPod(ns, name)
	// A pod we have never seen is not the same as a pod no policy
	// governs: without its labels there is nothing to match a selector
	// against, so the honest answer is that we cannot tell.
	if pod == nil {
		known = false
	}
	governs := false
	if known {
		governs = policycoverage.Governs(s.store.NetworkPoliciesInNamespace(ns), pod, dir)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PolicyCoverageResponse{
		Cause: string(policycoverage.Classify(known, governs)),
	})
}
