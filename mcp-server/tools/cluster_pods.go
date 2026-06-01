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

// ClusterPodsInput defines the input parameters for the cluster pods tool
type ClusterPodsInput struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Optional Kubernetes namespace to filter results. If omitted, returns pods from all namespaces."`
}

// ClusterPodsOutput defines the output structure
type ClusterPodsOutput struct {
	Data string `json:"data" jsonschema:"Compact pod list in JSON format"`
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
	startTime := time.Now()
	logger.Log.WithField("namespace", input.Namespace).Debug("Received get_cluster_pods request")

	data, err := h.client.GetAllPods(ctx)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching cluster pods")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching cluster pods: %v", err)}},
			IsError: true,
		}, ClusterPodsOutput{}, nil
	}

	// Apply namespace filter if specified
	filtered := filterByNamespace(data, input.Namespace)

	// Drop dead pods. /pod/info returns every pod_details row
	// regardless of liveness; the LLM's "list pods" use case wants
	// the live ones, not a long tail of restarted-and-gone
	// historical entries. Operators who genuinely need dead pods
	// can ask the broker directly — the MCP tool deliberately
	// scopes to the LLM's primary use case.
	alive := filterAlivePods(filtered)

	// Strip heavyweight fields (pod_obj, service_spec)
	compacted := compactPodsSummary(alive)

	jsonData, err := json.Marshal(compacted)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, ClusterPodsOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"namespace":      input.Namespace,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched cluster pods")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, ClusterPodsOutput{}, nil
}
