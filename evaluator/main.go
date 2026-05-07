// kguardian-evaluator: a sidecar service that watches AuditNetworkPolicy
// CRDs and evaluates observed flows (POSTed by the broker on /evaluate)
// against them, emitting "would deny" verdicts as logs and Prometheus
// metrics.
//
// MVP scope: HTTP server, in-memory CRD/pod/namespace cache, podSelector
// + namespaceSelector + numeric port matching. Status updates back onto
// the CRD and ipBlock / named-port matching are tracked as follow-ups.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/server"
	"github.com/kguardian-dev/kguardian/evaluator/pkg/store"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	log := logrus.New()
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		parsed, err := logrus.ParseLevel(lvl)
		if err == nil {
			log.SetLevel(parsed)
		}
	}
	log.SetFormatter(&logrus.JSONFormatter{})

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8082"
	}

	cfg, err := loadKubeConfig()
	if err != nil {
		return fmt.Errorf("loading kubeconfig: %w", err)
	}

	st, err := store.New(cfg, log)
	if err != nil {
		return fmt.Errorf("constructing store: %w", err)
	}

	ctx, cancel := signalContext()
	defer cancel()

	if err := st.Start(ctx); err != nil {
		return fmt.Errorf("starting informers: %w", err)
	}

	srv := server.New(addr, st, log)
	srv.SetReady() // caches are synced before we get here
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// loadKubeConfig prefers in-cluster config and falls back to the local
// KUBECONFIG / ~/.kube/config for development.
func loadKubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		cancel()
	}()
	return ctx, cancel
}
