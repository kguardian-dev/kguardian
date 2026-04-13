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

// ServiceDetailsInput defines the input parameters for getting service details by IP
type ServiceDetailsInput struct {
	IP string `json:"ip" jsonschema:"The IP address of the service to query"`
}

// ServiceDetailsOutput defines the output structure
type ServiceDetailsOutput struct {
	Data string `json:"data" jsonschema:"Service details in JSON format"`
}

// ServiceDetailsHandler handles the get_service_details tool
type ServiceDetailsHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h ServiceDetailsHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input ServiceDetailsInput,
) (*mcp.CallToolResult, ServiceDetailsOutput, error) {
	startTime := time.Now()
	logger.Log.WithField("ip", input.IP).Info("Received get_service_details request")

	if input.IP == "" {
		logger.Log.Error("IP address is required but not provided")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "IP address is required"}},
			IsError: true,
		}, ServiceDetailsOutput{}, nil
	}

	if err := ValidateIP(input.IP); err != nil {
		logger.Log.WithField("ip", input.IP).Error("Invalid IP address parameter")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("invalid ip: %v", err)}},
			IsError: true,
		}, ServiceDetailsOutput{}, nil
	}

	data, err := h.client.GetServiceByIP(ctx, input.IP)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"ip":             input.IP,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching service details")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching service details: %v", err)}},
			IsError: true,
		}, ServiceDetailsOutput{}, nil
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, ServiceDetailsOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"ip":             input.IP,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched service details")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, ServiceDetailsOutput{}, nil
}
