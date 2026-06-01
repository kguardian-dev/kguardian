// kguardian-evaluator: a sidecar service that watches AuditNetworkPolicy
// CRDs and evaluates observed flows (POSTed by the broker on /evaluate)
// against them, emitting "would deny" verdicts as logs and Prometheus
// metrics.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/server"
	"github.com/kguardian-dev/kguardian/evaluator/pkg/status"
	"github.com/kguardian-dev/kguardian/evaluator/pkg/store"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
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
	// Trim before ParseLevel; an operator-pasted "info\n" (trailing
	// newline) or "  info" (leading space) would otherwise silently
	// fail-and-fallback to the default level, no signal in logs that
	// LOG_LEVEL was misconfigured. Same defensive-trim pattern
	// applied to the controllers env reads.
	if lvl := strings.TrimSpace(os.Getenv("LOG_LEVEL")); lvl != "" {
		parsed, err := logrus.ParseLevel(lvl)
		if err == nil {
			log.SetLevel(parsed)
		} else {
			log.Warnf("LOG_LEVEL=%q is not a valid logrus level; using default", lvl)
		}
	}
	log.SetFormatter(&logrus.JSONFormatter{})

	// Same trim defence for LISTEN_ADDR. An untrimmed ":8082 "
	// (trailing space) crashes net.Listen with a parse error far
	// from the env-var read site.
	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
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

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("constructing dynamic client: %w", err)
	}
	agg := status.New(dynClient, log)
	go agg.Run(ctx)

	srv := server.New(addr, st, agg, log)
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
