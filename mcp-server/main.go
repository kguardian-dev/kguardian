package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
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
		brokerURL = "http://broker.kguardian.svc.cluster.local:9090"
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
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
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

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Log.WithField("error", err.Error()).Error("Server forced to shutdown")
	}

	logger.Log.Info("Server stopped gracefully")
}
