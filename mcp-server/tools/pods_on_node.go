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

// PodsOnNodeInput defines the input for the node-scoped pod tool.
type PodsOnNodeInput struct {
	Node string `json:"node" jsonschema:"The name of the Kubernetes node to list pods for"`
}

// PodsOnNodeOutput holds the compacted pod records.
type PodsOnNodeOutput struct {
	Data string `json:"data" jsonschema:"Pods on the node, in JSON format"`
}

// PodsOnNodeHandler handles the get_pods_on_node tool.
type PodsOnNodeHandler struct {
	client *BrokerClient
}

// Call implements the tool handler.
func (h PodsOnNodeHandler) Call(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input PodsOnNodeInput,
) (*mcp.CallToolResult, PodsOnNodeOutput, error) {
	start := time.Now()
	logger.Log.WithField("node", input.Node).Debug("Received get_pods_on_node request")

	if input.Node == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "node is required"}},
			IsError: true,
		}, PodsOnNodeOutput{}, nil
	}

	data, err := h.client.GetPodsOnNode(ctx, input.Node)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"node":           input.Node,
			"error":          err.Error(),
			"total_duration": time.Since(start).String(),
		}).Error("Error fetching pods on node")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching pods on node: %v", err)}},
			IsError: true,
		}, PodsOnNodeOutput{}, nil
	}

	// Live pods only, with heavyweight pod_obj stripped — same shape as
	// get_cluster_pods so the LLM sees a consistent pod record everywhere.
	compacted := compactPodsSummary(filterAlivePods(data))

	jsonData, err := json.Marshal(compacted)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, PodsOnNodeOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"node":           input.Node,
		"response_bytes": len(jsonData),
		"total_duration": time.Since(start).String(),
	}).Info("Successfully fetched pods on node")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, PodsOnNodeOutput{}, nil
}
