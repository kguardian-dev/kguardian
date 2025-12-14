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

// NetworkTrafficInput defines the input parameters for the network traffic tool
type NetworkTrafficInput struct {
	Namespace string `json:"namespace" jsonschema:"The Kubernetes namespace of the pod"`
	PodName   string `json:"pod_name" jsonschema:"The name of the pod"`
}

// NetworkTrafficOutput defines the output for the network traffic tool
type NetworkTrafficOutput struct {
	Data string `json:"data" jsonschema:"Network traffic data in JSON format"`
}

// NetworkTrafficHandler handles the get_pod_network_traffic tool
type NetworkTrafficHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h NetworkTrafficHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input NetworkTrafficInput,
) (*mcp.CallToolResult, NetworkTrafficOutput, error) {
	startTime := time.Now()
	logger.Log.WithFields(logrus.Fields{
		"namespace": input.Namespace,
		"pod_name":  input.PodName,
	}).Info("Received get_pod_network_traffic request")

	// Fetch data from broker
	data, err := h.client.GetPodNetworkTraffic(input.Namespace, input.PodName)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"namespace":      input.Namespace,
			"pod_name":       input.PodName,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching network traffic")
		return nil, NetworkTrafficOutput{}, fmt.Errorf("error fetching network traffic: %w", err)
	}

	// Convert to JSON string
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return nil, NetworkTrafficOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	logger.Log.WithFields(logrus.Fields{
		"namespace":      input.Namespace,
		"pod_name":       input.PodName,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched network traffic")

	return nil, NetworkTrafficOutput{
		Data: string(jsonData),
	}, nil
}
