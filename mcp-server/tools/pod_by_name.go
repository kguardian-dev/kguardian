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

// PodByNameInput defines the input parameters for the pod-by-name tool
type PodByNameInput struct {
	PodName string `json:"pod_name" jsonschema:"The name of the pod to look up"`
}

// PodByNameOutput defines the output structure
type PodByNameOutput struct {
	Data string `json:"data" jsonschema:"Pod details in JSON format"`
}

// PodByNameHandler handles the get_pod_details_by_name tool
type PodByNameHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h PodByNameHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input PodByNameInput,
) (*mcp.CallToolResult, PodByNameOutput, error) {
	startTime := time.Now()
	logger.Log.WithField("pod_name", input.PodName).Debug("Received get_pod_details_by_name request")

	if input.PodName == "" {
		logger.Log.Error("pod_name is required but not provided")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "pod_name is required"}},
			IsError: true,
		}, PodByNameOutput{}, nil
	}

	data, err := h.client.GetPodByName(ctx, input.PodName)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"pod_name":       input.PodName,
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching pod details by name")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching pod details: %v", err)}},
			IsError: true,
		}, PodByNameOutput{}, nil
	}

	// Strip heavyweight fields (pod_obj) the same way get_pod_details
	// does — the LLM needs identity (name, namespace, IP, node,
	// workload labels), not the full Kubernetes Pod spec/status.
	compacted := compactPodsSummary(data)

	jsonData, err := json.Marshal(compacted)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, PodByNameOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"pod_name":       input.PodName,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched pod details by name")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, PodByNameOutput{}, nil
}
