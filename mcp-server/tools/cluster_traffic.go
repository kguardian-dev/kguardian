package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ClusterTrafficInput defines the input parameters (no params needed)
type ClusterTrafficInput struct{}

// ClusterTrafficOutput defines the output structure
type ClusterTrafficOutput struct {
	Data string `json:"data" jsonschema:"All pod traffic data in the cluster in JSON format"`
}

// ClusterTrafficHandler handles the get_cluster_traffic tool
type ClusterTrafficHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h ClusterTrafficHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input ClusterTrafficInput,
) (*mcp.CallToolResult, ClusterTrafficOutput, error) {
	data, err := h.client.GetAllPodTraffic()
	if err != nil {
		return nil, ClusterTrafficOutput{}, fmt.Errorf("error fetching cluster traffic: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, ClusterTrafficOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	return nil, ClusterTrafficOutput{Data: string(jsonData)}, nil
}
