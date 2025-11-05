package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NetworkTrafficInput defines the input parameters for the network traffic tool
type NetworkTrafficInput struct {
	Namespace string `json:"namespace" jsonschema:"description=The Kubernetes namespace of the pod,required=true"`
	PodName   string `json:"pod_name" jsonschema:"description=The name of the pod,required=true"`
}

// NetworkTrafficOutput defines the output for the network traffic tool
type NetworkTrafficOutput struct {
	Data string `json:"data" jsonschema:"description=Network traffic data in JSON format"`
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
	// Fetch data from broker
	data, err := h.client.GetPodNetworkTraffic(input.Namespace, input.PodName)
	if err != nil {
		return nil, NetworkTrafficOutput{}, fmt.Errorf("error fetching network traffic: %w", err)
	}

	// Convert to JSON string
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, NetworkTrafficOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	return nil, NetworkTrafficOutput{
		Data: string(jsonData),
	}, nil
}
