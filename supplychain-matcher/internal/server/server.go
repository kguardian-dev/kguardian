// Package server is the matcher's localhost-only HTTP surface:
//
//	POST /match   gzip JSON wire.MatchRequest -> wire.MatchResponse
//	GET  /db      wire.DB (database status)
//	GET  /healthz liveness
//	GET  /readyz  200 once a database is loaded
//
// It must be bound to a loopback address (the caller refuses anything
// else), and every request from a non-loopback peer is rejected as well,
// so only containers in the same pod can reach it.
package server

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/engine"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/wire"
	"github.com/sirupsen/logrus"
)

// Limits on one request.
const (
	MaxCompressedBytes   = 32 << 20
	MaxDecompressedBytes = 128 << 20
	MaxComponents        = 50000
)

// Engine is the slice of *engine.Engine the server uses.
type Engine interface {
	Match(ctx context.Context, cs []wire.Component) ([]wire.Vulnerability, error)
	DB() wire.DB
	Loaded() bool
}

// Server serves the matcher API.
type Server struct {
	Engine       Engine
	Log          *logrus.Logger
	MatchTimeout time.Duration
}

// ErrNotLoopback is returned for a non-loopback listen address.
var ErrNotLoopback = errors.New("listen address must be a loopback IP (127.0.0.1 or ::1)")

// CheckListenAddr refuses anything but a literal loopback host.
func CheckListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return ErrNotLoopback
	}
	return nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.Engine.Loaded() {
			http.Error(w, "vulnerability database not loaded", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /db", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Engine.DB()) })
	mux.HandleFunc("POST /match", s.handleMatch)
	return loopbackOnly(mux)
}

func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !ap.Addr().Unmap().IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleMatch(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Encoding") != "gzip" {
		http.Error(w, "body must be gzip JSON", http.StatusUnsupportedMediaType)
		return
	}
	zr, err := gzip.NewReader(http.MaxBytesReader(w, r.Body, MaxCompressedBytes))
	if err != nil {
		http.Error(w, "bad gzip", http.StatusBadRequest)
		return
	}
	var req wire.MatchRequest
	dec := json.NewDecoder(io.LimitReader(zr, MaxDecompressedBytes))
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Components) > MaxComponents {
		http.Error(w, "too many components", http.StatusRequestEntityTooLarge)
		return
	}
	timeout := s.MatchTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	vulns, err := s.Engine.Match(ctx, req.Components)
	switch {
	case errors.Is(err, engine.ErrNotReady):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		s.Log.WithError(err).WithField("digest", req.Image.Digest).Warn("match failed")
		http.Error(w, "match failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if vulns == nil {
		vulns = []wire.Vulnerability{}
	}
	writeJSON(w, wire.MatchResponse{DB: s.Engine.DB(), Vulnerabilities: vulns})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Serve runs the server on addr (checked loopback) until ctx is done.
func (s *Server) Serve(ctx context.Context, addr string) error {
	if err := CheckListenAddr(addr); err != nil {
		return err
	}
	srv := &http.Server{
		Addr: addr, Handler: s.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute,
		WriteTimeout: 5 * time.Minute, IdleTimeout: 2 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() {
		s.Log.WithField("addr", addr).Info("matcher listening (loopback only)")
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
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}
