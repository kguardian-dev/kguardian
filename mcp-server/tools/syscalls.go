package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SyscallsInput defines the input parameters for the syscalls tool
type SyscallsInput struct {
	Namespace string `json:"namespace" jsonschema:"The Kubernetes namespace of the pod"`
	PodName   string `json:"pod_name" jsonschema:"The name of the pod"`
}

// SyscallsOutput defines the output for the syscalls tool
type SyscallsOutput struct {
	Data string `json:"data" jsonschema:"Syscall data in JSON format"`
}

// SyscallsHandler handles the get_pod_syscalls tool
type SyscallsHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h SyscallsHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input SyscallsInput,
) (*mcp.CallToolResult, SyscallsOutput, error) {
	// Fetch data from broker
	data, err := h.client.GetPodSyscalls(input.Namespace, input.PodName)
	if err != nil {
		return nil, SyscallsOutput{}, fmt.Errorf("error fetching syscalls: %w", err)
	}

	// Convert to JSON string
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, SyscallsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	return nil, SyscallsOutput{
		Data: string(jsonData),
	}, nil
}
