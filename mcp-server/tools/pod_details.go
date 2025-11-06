package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	if input.IP == "" {
		return nil, PodDetailsOutput{}, fmt.Errorf("IP address is required")
	}

	data, err := h.client.GetPodByIP(input.IP)
	if err != nil {
		return nil, PodDetailsOutput{}, fmt.Errorf("error fetching pod details: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, PodDetailsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	return nil, PodDetailsOutput{Data: string(jsonData)}, nil
}
