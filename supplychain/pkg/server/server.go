// Package server exposes the supplychain component's HTTP surface:
//
//	GET /healthz   liveness: the process is serving
//	GET /readyz    readiness: every enabled source has synced or has
//	               established that its API is absent
//	GET /metrics   Prometheus text format
//
// There is deliberately no data endpoint: findings flow out to the broker,
// which owns storage, auth and read APIs.
package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Server is the HTTP entry point.
type Server struct {
	addr     string
	ready    func() bool
	gatherer prometheus.Gatherer
	log      *logrus.Logger
}

// New returns a Server. ready reports readiness; gatherer serves /metrics.
func New(addr string, ready func() bool, gatherer prometheus.Gatherer, log *logrus.Logger) *Server {
	return &Server{addr: addr, ready: ready, gatherer: gatherer, log: log}
}

// Handler returns the HTTP handler (exposed for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.ready != nil && !s.ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.gatherer, promhttp.HandlerOpts{}))
	return mux
}

// Start serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.WithField("addr", s.addr).Info("supplychain HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
