package main

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/kguardian-dev/kguardian/mcp-server/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize logger
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	logger.Init(logLevel)

	// Get configuration from environment
	brokerURL := os.Getenv("BROKER_URL")
	if brokerURL == "" {
		logger.Log.Error("BROKER_URL environment variable is required but not set")
		os.Exit(1)
	}
	if _, err := url.Parse(brokerURL); err != nil {
		logger.Log.WithField("broker_url", brokerURL).WithError(err).Error("BROKER_URL is not a valid URL")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	logger.Log.WithFields(logrus.Fields{
		"port":       port,
		"broker_url": brokerURL,
		"log_level":  logLevel,
	}).Info("Initializing kguardian MCP server")

	// shuttingDown is set to 1 when a shutdown signal is received so that the
	// health endpoint can start returning 503 before the server drains.
	var shuttingDown atomic.Bool

	// Server lifecycle context — cancelled when shutdown begins.
	_, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	// Create MCP server
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "kguardian-mcp",
			Version: "1.0.0",
		},
		nil,
	)

	// Register tools
	tools.RegisterTools(server, brokerURL)

	// Create HTTP handler using StreamableHTTPHandler
	mcpHandler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	// Wrap in ServeMux to add health endpoint for Kubernetes probes
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if shuttingDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write([]byte("shutting down")); err != nil {
				logger.Log.Errorf("health write: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			logger.Log.Errorf("health write: %v", err)
		}
	})
	mux.Handle("/", mcpHandler)

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second, // Allow enough time for broker queries and large responses
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Log.WithFields(logrus.Fields{
			"port":    port,
			"address": ":" + port,
		}).Info("kguardian MCP server starting")

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.WithField("error", err.Error()).Error("Failed to start HTTP server")
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	logger.Log.WithField("signal", sig.String()).Info("Received shutdown signal")

	// Signal health endpoint to return 503 and cancel the server lifecycle context.
	shuttingDown.Store(true)
	serverCancel()

	// Graceful shutdown with a 10-second timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Log.WithField("error", err.Error()).Error("Server forced to shutdown")
	}

	logger.Log.Info("Server stopped gracefully")
}
