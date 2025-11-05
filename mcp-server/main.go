package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	// Get configuration from environment
	brokerURL := os.Getenv("BROKER_URL")
	if brokerURL == "" {
		brokerURL = "http://broker.kguardian.svc.cluster.local:9090"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

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
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("kguardian MCP server starting on port %s", port)
		log.Printf("Broker URL: %s", brokerURL)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
