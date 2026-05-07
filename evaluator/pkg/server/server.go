// Package server exposes the evaluator's HTTP surface:
//
//   GET  /healthz     liveness probe
//   GET  /readyz      readiness probe (informer caches synced)
//   POST /evaluate    body: matcher.Flow JSON; returns []matcher.Result
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
	"github.com/kguardian-dev/kguardian/evaluator/pkg/status"
	v1alpha1 "github.com/kguardian-dev/kguardian/evaluator/pkg/v1alpha1"
	"github.com/sirupsen/logrus"
)

// PolicyLookup is the slice of *store.Store the server actually uses.
// Extracted as an interface so handler logic can be tested with an
// in-memory fake (see pkg/server/server_test.go).
type PolicyLookup interface {
	matcher.Lookup
	PoliciesInNamespace(ns string) []*v1alpha1.AuditNetworkPolicy
	ClusterPolicies() []*v1alpha1.AuditClusterNetworkPolicy
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
	defer r.Body.Close()
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

	var results []matcher.Result
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
				flow.DstPort, wouldDeny,
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
