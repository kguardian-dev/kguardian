package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	data, err := h.client.GetAllPods()
	if err != nil {
		return nil, ClusterPodsOutput{}, fmt.Errorf("error fetching cluster pods: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, ClusterPodsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	return nil, ClusterPodsOutput{Data: string(jsonData)}, nil
}
