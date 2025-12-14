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
		return nil, ServiceDetailsOutput{}, fmt.Errorf("IP address is required")
	}

	data, err := h.client.GetServiceByIP(input.IP)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"ip":             input.IP,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching service details")
		return nil, ServiceDetailsOutput{}, fmt.Errorf("error fetching service details: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return nil, ServiceDetailsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	logger.Log.WithFields(logrus.Fields{
		"ip":             input.IP,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched service details")

	return nil, ServiceDetailsOutput{Data: string(jsonData)}, nil
}
