package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

// ClusterTrafficInput defines the input parameters for the cluster traffic tool
type ClusterTrafficInput struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Optional Kubernetes namespace to filter results. If omitted, returns a summary of all namespaces."`
}

// ClusterTrafficOutput defines the output structure
type ClusterTrafficOutput struct {
	Data string `json:"data" jsonschema:"Cluster traffic summary in JSON format"`
}

// ClusterTrafficHandler handles the get_cluster_traffic tool
type ClusterTrafficHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h ClusterTrafficHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input ClusterTrafficInput,
) (*mcp.CallToolResult, ClusterTrafficOutput, error) {
	startTime := time.Now()
	logger.Log.WithField("namespace", input.Namespace).Info("Received get_cluster_traffic request")

	fetchStart := time.Now()
	data, err := h.client.GetAllPodTraffic(ctx)
	fetchDuration := time.Since(fetchStart)

	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":          err.Error(),
			"fetch_duration": fetchDuration.String(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching cluster traffic")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching cluster traffic: %v", err)}},
			IsError: true,
		}, ClusterTrafficOutput{}, nil
	}

	// Apply namespace filter if specified
	filtered := filterByNamespace(data, input.Namespace)

	// Compact into per-pod summary
	summary := compactTrafficSummary(filtered)
	if input.Namespace != "" {
		summary["filtered_namespace"] = input.Namespace
	}

	marshalStart := time.Now()
	jsonData, err := json.Marshal(summary)
	marshalDuration := time.Since(marshalStart)

	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":            err.Error(),
			"fetch_duration":   fetchDuration.String(),
			"marshal_duration": marshalDuration.String(),
			"total_duration":   time.Since(startTime).String(),
		}).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, ClusterTrafficOutput{}, nil
	}

	totalDuration := time.Since(startTime)
	logger.Log.WithFields(logrus.Fields{
		"namespace":        input.Namespace,
		"response_bytes":   len(jsonData),
		"fetch_duration":   fetchDuration.String(),
		"marshal_duration": marshalDuration.String(),
		"total_duration":   totalDuration.String(),
	}).Info("Successfully fetched cluster traffic")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, ClusterTrafficOutput{}, nil
}
