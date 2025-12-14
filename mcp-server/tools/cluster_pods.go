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

	data, err := h.client.GetAllPods()
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching cluster pods")
		return nil, ClusterPodsOutput{}, fmt.Errorf("error fetching cluster pods: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return nil, ClusterPodsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	logger.Log.WithFields(logrus.Fields{
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched cluster pods")

	return nil, ClusterPodsOutput{Data: string(jsonData)}, nil
}
