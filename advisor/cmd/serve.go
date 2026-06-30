package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	"github.com/kguardian-dev/kguardian/advisor/pkg/network"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// serveConfig is a no-op network.ConfigProvider for the HTTP service. The
// service only calls PolicyService.GeneratePolicy, which synthesises a policy
// from broker data and never touches the cluster clientset or output dir
// (those are only used by the CLI's file-writing / apply path).
type serveConfig struct{}

func (serveConfig) GetClientset() interface{} { return nil }
func (serveConfig) IsDryRun() bool            { return true }
func (serveConfig) GetOutputDir() string      { return "" }

const defaultServePort = "8083"

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run advisor as an HTTP service exposing policy/seccomp generation",
	Long: `Run advisor as a long-lived HTTP service (intended to run in-cluster).

It exposes the same NetworkPolicy / CiliumNetworkPolicy and seccomp-profile
synthesis as the CLI, over HTTP, so other components (e.g. the MCP server's
chat tools) can request a generated policy for a pod by name:

  GET /generate/networkpolicy?pod=<name>&type=kubernetes|cilium  -> YAML
  GET /generate/seccomp?pod=<name>                               -> JSON
  GET /healthz                                                   -> 200

Unlike the CLI it does not port-forward; set BROKER_URL to the in-cluster
broker (e.g. http://broker.kguardian.svc.cluster.local:9090).`,
	Run: func(_ *cobra.Command, _ []string) {
		setupLogger()

		// In-cluster the service reaches the broker directly (no port-forward).
		if v := strings.TrimSpace(os.Getenv("BROKER_URL")); v != "" {
			api.BrokerBaseURL = strings.TrimRight(v, "/")
		}
		// Forward the broker bearer token when the broker is deployed with auth.
		api.BrokerAuthToken = strings.TrimSpace(os.Getenv("BROKER_AUTH_TOKEN"))
		log.Info().Msgf("advisor serve: broker base URL %s (auth=%t)", api.BrokerBaseURL, api.BrokerAuthToken != "")

		port := strings.TrimSpace(os.Getenv("PORT"))
		if port == "" {
			port = defaultServePort
		}

		policyService := network.NewPolicyService(serveConfig{}, network.StandardPolicy)
		policyService.RegisterGenerator(network.NewStandardPolicyGenerator())
		policyService.RegisterGenerator(network.NewCiliumPolicyGenerator())

		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", handleHealthz)
		mux.HandleFunc("/generate/networkpolicy", networkPolicyHandler(policyService))
		mux.HandleFunc("/generate/seccomp", handleSeccompGenerate)

		srv := &http.Server{
			Addr:              ":" + port,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		// Start the server, then block on a termination signal and shut down
		// gracefully so in-flight generation requests drain on pod termination.
		serveErr := make(chan error, 1)
		go func() {
			log.Info().Msgf("advisor serve: listening on :%s", port)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serveErr <- err
			}
		}()

		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

		select {
		case err := <-serveErr:
			log.Fatal().Err(err).Msg("advisor serve: server failed")
		case sig := <-stop:
			log.Info().Msgf("advisor serve: received %s, shutting down", sig)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Error().Err(err).Msg("advisor serve: graceful shutdown failed")
			}
		}
	},
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// networkPolicyHandler returns an http.HandlerFunc that synthesises a network
// policy for the requested pod and returns it as YAML.
func networkPolicyHandler(svc *network.PolicyService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		pod := strings.TrimSpace(r.URL.Query().Get("pod"))
		if pod == "" {
			writeJSONError(w, http.StatusBadRequest, "missing required query parameter: pod")
			return
		}
		policyType, err := parsePolicyType(strings.TrimSpace(orDefault(r.URL.Query().Get("type"), "kubernetes")))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		output, err := svc.GeneratePolicy(pod, policyType)
		if err != nil {
			log.Warn().Err(err).Msgf("serve: failed to generate %s policy for pod %s", policyType, pod)
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(output.YAML)
	}
}

// handleSeccompGenerate builds a seccomp profile for the requested pod from its
// observed syscalls and returns it as JSON.
func handleSeccompGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pod := strings.TrimSpace(r.URL.Query().Get("pod"))
	if pod == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: pod")
		return
	}

	syscalls, err := api.GetPodSysCall(pod)
	if err != nil {
		log.Warn().Err(err).Msgf("serve: failed to fetch syscalls for pod %s", pod)
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	profile := k8s.BuildSeccompProfile(syscalls.Syscalls, syscalls.Arch, "SCMP_ACT_ERRNO")
	body, err := json.MarshalIndent(profile, "", "    ")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to marshal seccomp profile")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
