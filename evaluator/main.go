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
	"time"

	"github.com/kguardian-dev/kguardian/evaluator/pkg/appprofile"
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

	if err := startAppProfiles(ctx, dynClient, log); err != nil {
		return err
	}

	srv := server.New(addr, st, agg, log)
	srv.SetReady() // caches are synced before we get here
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// startAppProfiles runs the ApplicationSecurityProfile status controller
// when ASP_ENABLED=true (set by the chart's
// evaluator.applicationSecurityProfiles.enabled). Off by default: the CRD
// is only installed when the flag is on, and an informer on a missing CRD
// would just log list errors forever.
func startAppProfiles(ctx context.Context, dyn dynamic.Interface, log *logrus.Logger) error {
	if !envBool("ASP_ENABLED") {
		return nil
	}
	brokerURL := strings.TrimSpace(os.Getenv("BROKER_URL"))
	if brokerURL == "" {
		return fmt.Errorf("ASP_ENABLED=true requires BROKER_URL")
	}
	resync, err := envDuration("ASP_RESYNC_INTERVAL", 5*time.Minute, 30*time.Second)
	if err != nil {
		return err
	}
	// BROKER_AUTH_TOKEN is the broker's READ-scope token (empty when broker
	// auth is off). The profile routes are all GET, READ scope.
	client, err := appprofile.NewBrokerClient(brokerURL, os.Getenv("BROKER_AUTH_TOKEN"), 30*time.Second)
	if err != nil {
		return err
	}
	ctrl := appprofile.New(dyn, client, resync, log)
	go ctrl.Run(ctx)
	log.WithField("resync", resync.String()).WithField("broker", brokerURL).
		Info("applicationsecurityprofile status reporting enabled")
	return nil
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// envDuration parses a Go duration ("5m"), clamped up to floor.
func envDuration(name string, def, floor time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration (e.g. 5m): %w", name, v, err)
	}
	if d < floor {
		d = floor
	}
	return d, nil
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
