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
	startTime := time.Now()
	logger.Log.WithFields(logrus.Fields{
		"namespace": input.Namespace,
		"pod_name":  input.PodName,
	}).Info("Received get_pod_syscalls request")

	// Fetch data from broker
	data, err := h.client.GetPodSyscalls(input.Namespace, input.PodName)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"namespace":      input.Namespace,
			"pod_name":       input.PodName,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching syscalls")
		return nil, SyscallsOutput{}, fmt.Errorf("error fetching syscalls: %w", err)
	}

	// Convert to JSON string
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return nil, SyscallsOutput{}, fmt.Errorf("error marshaling response: %w", err)
	}

	logger.Log.WithFields(logrus.Fields{
		"namespace":      input.Namespace,
		"pod_name":       input.PodName,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched syscalls")

	return nil, SyscallsOutput{
		Data: string(jsonData),
	}, nil
}
