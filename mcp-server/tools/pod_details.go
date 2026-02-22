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

// PodDetailsInput defines the input parameters for getting pod details by IP
type PodDetailsInput struct {
	IP string `json:"ip" jsonschema:"The IP address of the pod to query"`
}

// PodDetailsOutput defines the output structure
type PodDetailsOutput struct {
	Data string `json:"data" jsonschema:"Pod details in JSON format"`
}

// PodDetailsHandler handles the get_pod_details tool
type PodDetailsHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h PodDetailsHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input PodDetailsInput,
) (*mcp.CallToolResult, PodDetailsOutput, error) {
	startTime := time.Now()
	logger.Log.WithField("ip", input.IP).Info("Received get_pod_details request")

	if input.IP == "" {
		logger.Log.Error("IP address is required but not provided")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "IP address is required"}},
			IsError: true,
		}, PodDetailsOutput{}, nil
	}

	data, err := h.client.GetPodByIP(ctx, input.IP)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"ip":             input.IP,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching pod details")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching pod details: %v", err)}},
			IsError: true,
		}, PodDetailsOutput{}, nil
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, PodDetailsOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"ip":             input.IP,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched pod details")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, PodDetailsOutput{}, nil
}
