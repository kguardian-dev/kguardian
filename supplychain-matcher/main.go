// kguardian-supplychain-matcher: Grype vulnerability matching for the
// kguardian supplychain component, run as a second container in the
// supplychain pod only when supplychain.grype.enabled is set.
//
// It is a separate module and image so that Grype's dependency tree
// (about 800 Go modules) never ships in the default supplychain image and
// never shares a container with the broker or Kubernetes API tokens. It
// listens on loopback only, holds no credentials, and owns the Grype
// database on its own volume.
//
//	serve  run the matcher
//	probe  exit 0 if the local matcher answers /readyz (for exec probes:
//	       kubelet HTTP probes cannot reach a loopback-only listener)
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/engine"
	"github.com/kguardian-dev/kguardian/supplychain-matcher/internal/server"
	"github.com/sirupsen/logrus"
)

var version = "dev"

const usage = `usage: kguardian-supplychain-matcher <serve|probe [readyz|healthz]|version>
`

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		if err := serve(getenv); err != nil {
			_, _ = fmt.Fprintf(stderr, "fatal: %v\n", err)
			return 1
		}
		return 0
	case "probe":
		path := "readyz"
		if len(args) > 1 {
			path = args[1]
		}
		return probe(listenAddr(getenv), path, stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "%s (grype %s)\n", version, engine.GrypeVersion)
		return 0
	}
	_, _ = fmt.Fprint(stderr, usage)
	return 2
}

func env(getenv func(string) string, k, def string) string {
	if v := strings.TrimSpace(getenv(k)); v != "" {
		return v
	}
	return def
}

func listenAddr(getenv func(string) string) string {
	return env(getenv, "LISTEN_ADDR", "127.0.0.1:8090")
}

type config struct {
	Listen       string
	LogLevel     string
	Engine       engine.Config
	MatchTimeout time.Duration
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		Listen:   listenAddr(getenv),
		LogLevel: env(getenv, "LOG_LEVEL", "info"),
		Engine: engine.Config{
			DBDir: env(getenv, "GRYPE_DB_DIR", "/var/lib/grype"),
			URL:   env(getenv, "GRYPE_DB_URL", "https://grype.anchore.io/databases"),
		},
	}
	var err error
	if c.Engine.AutoUpdate, err = strconv.ParseBool(env(getenv, "GRYPE_DB_AUTO_UPDATE", "true")); err != nil {
		return c, fmt.Errorf("GRYPE_DB_AUTO_UPDATE: %w", err)
	}
	if c.Engine.UpdateInterval, err = time.ParseDuration(env(getenv, "GRYPE_DB_UPDATE_INTERVAL", "12h")); err != nil || c.Engine.UpdateInterval <= 0 {
		return c, fmt.Errorf("GRYPE_DB_UPDATE_INTERVAL must be a positive duration")
	}
	if c.Engine.MaxAge, err = time.ParseDuration(env(getenv, "GRYPE_DB_MAX_AGE", "120h")); err != nil || c.Engine.MaxAge < 0 {
		return c, fmt.Errorf("GRYPE_DB_MAX_AGE must be a duration (0 disables the check)")
	}
	if c.MatchTimeout, err = time.ParseDuration(env(getenv, "MATCH_TIMEOUT", "2m")); err != nil || c.MatchTimeout <= 0 {
		return c, fmt.Errorf("MATCH_TIMEOUT must be a positive duration")
	}
	if err := server.CheckListenAddr(c.Listen); err != nil {
		return c, fmt.Errorf("LISTEN_ADDR %q: %w", c.Listen, err)
	}
	return c, nil
}

func serve(getenv func(string) string) error {
	c, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	if lvl, err := logrus.ParseLevel(c.LogLevel); err == nil {
		log.SetLevel(lvl)
	}
	log.WithFields(logrus.Fields{
		"version": version, "grype": engine.GrypeVersion, "dbDir": c.Engine.DBDir,
		"dbURL": c.Engine.URL, "autoUpdate": c.Engine.AutoUpdate, "maxAge": c.Engine.MaxAge.String(),
	}).Info("kguardian-supplychain-matcher starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	eng := engine.New(c.Engine, log)
	go eng.Run(ctx)
	srv := &server.Server{Engine: eng, Log: log, MatchTimeout: c.MatchTimeout}
	return srv.Serve(ctx, c.Listen)
}

func probe(addr, path string, stderr io.Writer) int {
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://" + addr + "/" + strings.TrimPrefix(path, "/"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintln(stderr, resp.Status)
		return 1
	}
	return 0
}
