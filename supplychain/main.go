// kguardian-supplychain: supply-chain data for the workloads kguardian
// already profiles. One binary, two modes:
//
//	serve     the central Deployment. Reads vulnerability and SBOM sources
//	          (today: Trivy Operator reports), normalises them per image
//	          digest and hands them to the broker. Later: the Grype matcher
//	          and the attestation verifier.
//	node-sbom the optional per-node SBOM sidecar. Not implemented yet.
//
// Configuration is by environment variable; see supplychain/README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/dispatch"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/server"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `usage: kguardian-supplychain <command>

commands:
  serve      run the central supply-chain service
  node-sbom  run the per-node SBOM sidecar (not yet implemented)
  version    print the version
`

// errNotImplemented is returned by node-sbom until #1533 P1-4b lands.
var errNotImplemented = errors.New("node-sbom: not yet implemented; this mode will become the optional per-node SBOM sidecar (kguardian #1533). Run \"serve\" instead")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = serve()
	case "node-sbom":
		err = errNotImplemented
	case "version", "--version", "-v":
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "fatal: %v\n", err)
		return 1
	}
	return 0
}

// config is the serve-mode configuration, read from the environment.
type config struct {
	ListenAddr   string
	LogLevel     string
	TrivyEnabled bool
	TrivyResync  time.Duration
	TrivyRecheck time.Duration
	BrokerIngest bool
	BrokerURL    string
	BrokerToken  string
}

func loadConfig(getenv func(string) string) (config, error) {
	env := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	c := config{
		ListenAddr:  env("LISTEN_ADDR", ":8083"),
		LogLevel:    env("LOG_LEVEL", "info"),
		BrokerURL:   env("BROKER_URL", "http://kguardian-broker:9090"),
		BrokerToken: strings.TrimSpace(getenv("BROKER_AUTH_TOKEN")),
	}
	var err error
	if c.TrivyEnabled, err = strconv.ParseBool(env("TRIVY_OPERATOR_ENABLED", "true")); err != nil {
		return c, fmt.Errorf("TRIVY_OPERATOR_ENABLED: %w", err)
	}
	if c.BrokerIngest, err = strconv.ParseBool(env("BROKER_INGEST_ENABLED", "false")); err != nil {
		return c, fmt.Errorf("BROKER_INGEST_ENABLED: %w", err)
	}
	if c.TrivyResync, err = time.ParseDuration(env("TRIVY_RESYNC_PERIOD", "10m")); err != nil || c.TrivyResync <= 0 {
		return c, fmt.Errorf("TRIVY_RESYNC_PERIOD must be a positive duration")
	}
	if c.TrivyRecheck, err = time.ParseDuration(env("TRIVY_RECHECK_PERIOD", "5m")); err != nil || c.TrivyRecheck <= 0 {
		return c, fmt.Errorf("TRIVY_RECHECK_PERIOD must be a positive duration")
	}
	return c, nil
}

func newBrokerClient(c config, log *logrus.Logger) (broker.Client, error) {
	if !c.BrokerIngest {
		return broker.LoggingClient{Log: log}, nil
	}
	return broker.NewHTTPClient(c.BrokerURL, c.BrokerToken)
}

func serve() error {
	c, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	if lvl, err := logrus.ParseLevel(c.LogLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.Warnf("LOG_LEVEL=%q is not a valid logrus level; using info", c.LogLevel)
	}
	log.WithFields(logrus.Fields{
		"version":       version,
		"trivyOperator": c.TrivyEnabled,
		"brokerIngest":  c.BrokerIngest,
		"brokerAuth":    c.BrokerToken != "",
	}).Info("kguardian-supplychain starting")

	client, err := newBrokerClient(c, log)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	m := metrics.New()
	disp := dispatch.New(client, log, m)

	var readiness []func() bool
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	if c.TrivyEnabled {
		cfg, err := loadKubeConfig()
		if err != nil {
			return fmt.Errorf("loading kubeconfig: %w", err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("dynamic client: %w", err)
		}
		disc, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			return fmt.Errorf("discovery client: %w", err)
		}
		w := &trivy.Watcher{
			Dynamic:       dyn,
			Discovery:     disc,
			Tracker:       trivy.NewTracker(nil), // broker inventory resolver lands with #1533 P1-3
			Sink:          disp,
			Log:           log,
			Metrics:       m,
			ResyncPeriod:  c.TrivyResync,
			RecheckPeriod: c.TrivyRecheck,
		}
		readiness = append(readiness, w.Ready)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Run(ctx); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("trivy-operator source: %w", err)
			}
		}()
	} else {
		log.Info("no vulnerability source enabled; serving health and metrics only")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		disp.Run(ctx)
	}()

	srv := server.New(c.ListenAddr, func() bool {
		for _, r := range readiness {
			if !r() {
				return false
			}
		}
		return true
	}, m.Registry, log)
	go func() {
		if err := srv.Start(ctx); err != nil {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
	case err = <-errCh:
		cancel()
	}
	wg.Wait()
	return err
}

// loadKubeConfig prefers in-cluster config and falls back to the local
// KUBECONFIG / ~/.kube/config for development.
func loadKubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{}).ClientConfig()
}
