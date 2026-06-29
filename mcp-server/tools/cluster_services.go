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

// ClusterServicesInput defines the input parameters for the service inventory tool
type ClusterServicesInput struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Optional Kubernetes namespace to filter results. If omitted, returns services across all namespaces."`
}

// ClusterServicesOutput defines the output structure
type ClusterServicesOutput struct {
	Data string `json:"data" jsonschema:"Service inventory in JSON format"`
}

// ClusterServicesHandler handles the list_services tool
type ClusterServicesHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h ClusterServicesHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input ClusterServicesInput,
) (*mcp.CallToolResult, ClusterServicesOutput, error) {
	startTime := time.Now()
	logger.Log.WithField("namespace", input.Namespace).Debug("Received list_services request")

	data, err := h.client.GetAllServices(ctx)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching services")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching services: %v", err)}},
			IsError: true,
		}, ClusterServicesOutput{}, nil
	}

	// Apply the optional namespace filter, then strip the full
	// Kubernetes Service object down to identity + selector + ports
	// (compactSvc), matching get_service_details so the inventory
	// view and the single-IP lookup return the same shape.
	filtered := filterByNamespace(data, input.Namespace)
	compacted := compactSvc(filtered)

	jsonData, err := json.Marshal(compacted)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, ClusterServicesOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"namespace":      input.Namespace,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched services")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, ClusterServicesOutput{}, nil
}
