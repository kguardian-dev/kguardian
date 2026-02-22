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

// ClusterTrafficInput defines the input parameters (no params needed)
type ClusterTrafficInput struct{}

// ClusterTrafficOutput defines the output structure
type ClusterTrafficOutput struct {
	Data string `json:"data" jsonschema:"All pod traffic data in the cluster in JSON format"`
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
	logger.Log.Info("Received get_cluster_traffic request")

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

	marshalStart := time.Now()
	jsonData, err := json.MarshalIndent(data, "", "  ")
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
		"response_bytes":   len(jsonData),
		"fetch_duration":   fetchDuration.String(),
		"marshal_duration": marshalDuration.String(),
		"total_duration":   totalDuration.String(),
	}).Info("Successfully fetched cluster traffic")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, ClusterTrafficOutput{}, nil
}
