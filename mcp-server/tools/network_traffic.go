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
	PodName   string `json:"pod_name" jsonschema:"The name of the pod to query traffic for"`
	Namespace string `json:"namespace,omitempty" jsonschema:"Optional Kubernetes namespace the pod belongs to"`
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
	logger.Log.WithField("pod_name", input.PodName).Info("Received get_pod_network_traffic request")

	if input.PodName == "" {
		logger.Log.Error("pod_name is required but not provided")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "pod_name is required"}},
			IsError: true,
		}, NetworkTrafficOutput{}, nil
	}

	if err := ValidatePodName(input.PodName); err != nil {
		logger.Log.WithField("pod_name", input.PodName).Error("Invalid pod_name parameter")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("invalid pod_name: %v", err)}},
			IsError: true,
		}, NetworkTrafficOutput{}, nil
	}

	if input.Namespace != "" {
		if err := ValidateNamespace(input.Namespace); err != nil {
			logger.Log.WithField("namespace", input.Namespace).Error("Invalid namespace parameter")
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("invalid namespace: %v", err)}},
				IsError: true,
			}, NetworkTrafficOutput{}, nil
		}
	}

	// Fetch data from broker
	data, err := h.client.GetPodNetworkTraffic(ctx, input.PodName)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"pod_name":       input.PodName,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching network traffic")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching network traffic: %v", err)}},
			IsError: true,
		}, NetworkTrafficOutput{}, nil
	}

	// Convert to JSON string
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, NetworkTrafficOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"pod_name":       input.PodName,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched network traffic")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, NetworkTrafficOutput{}, nil
}
