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

// ClusterPodsInput defines the input parameters (no params needed)
type ClusterPodsInput struct{}

// ClusterPodsOutput defines the output structure
type ClusterPodsOutput struct {
	Data string `json:"data" jsonschema:"All pod details in the cluster in JSON format"`
}

// ClusterPodsHandler handles the get_cluster_pods tool
type ClusterPodsHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h ClusterPodsHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input ClusterPodsInput,
) (*mcp.CallToolResult, ClusterPodsOutput, error) {
	startTime := time.Now()
	logger.Log.Info("Received get_cluster_pods request")

	data, err := h.client.GetAllPods(ctx)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching cluster pods")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching cluster pods: %v", err)}},
			IsError: true,
		}, ClusterPodsOutput{}, nil
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, ClusterPodsOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched cluster pods")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, ClusterPodsOutput{}, nil
}
