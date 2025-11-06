package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	if input.IP == "" {
		return nil, ServiceDetailsOutput{}, fmt.Errorf("IP address is required")
	}

	data, err := h.client.GetServiceByIP(input.IP)
	if err != nil {
		return nil, ServiceDetailsOutput{}, fmt.Errorf("error fetching service details: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, ServiceDetailsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	return nil, ServiceDetailsOutput{Data: string(jsonData)}, nil
}
