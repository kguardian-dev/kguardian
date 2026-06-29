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

// AuditVerdictsInput defines the input parameters for the audit verdicts tool.
// All fields are optional; an empty request returns the most recent verdicts
// across all policies (newest first, capped by the broker's default limit).
type AuditVerdictsInput struct {
	Policy    string `json:"policy,omitempty" jsonschema:"Optional policy name to filter by (matches an AuditNetworkPolicy or AuditClusterNetworkPolicy by name)."`
	Namespace string `json:"namespace,omitempty" jsonschema:"Optional policy namespace to filter to a single namespace's AuditNetworkPolicy verdicts. Omit to span all namespaces (cluster-scoped verdicts are included). To see ONLY cluster-scoped verdicts, set cluster_scoped instead of using this field."`
	Verdict   string `json:"verdict,omitempty" jsonschema:"Optional verdict filter: 'Allow' or 'WouldDeny'. Use 'WouldDeny' to see flows that the policy would block if enforced."`
	Direction string `json:"direction,omitempty" jsonschema:"Optional direction filter: 'Ingress' or 'Egress'."`
	Limit     int    `json:"limit,omitempty" jsonschema:"Optional cap on rows returned. Defaults to 100, hard cap 500. Results are ordered newest-first."`
	// ClusterScoped exposes the broker's "namespace= (empty)" mode, which a
	// plain namespace string can't reach (empty == unset for a Go string).
	ClusterScoped bool `json:"cluster_scoped,omitempty" jsonschema:"Set true to return ONLY cluster-scoped AuditClusterNetworkPolicy verdicts. Takes precedence over namespace."`
}

// AuditVerdictsOutput defines the output structure
type AuditVerdictsOutput struct {
	Data string `json:"data" jsonschema:"Audit verdict records in JSON format"`
}

// AuditVerdictsHandler handles the get_audit_verdicts tool
type AuditVerdictsHandler struct {
	client *BrokerClient
}

// Call implements the tool handler
func (h AuditVerdictsHandler) Call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input AuditVerdictsInput,
) (*mcp.CallToolResult, AuditVerdictsOutput, error) {
	startTime := time.Now()
	logger.Log.WithFields(logrus.Fields{
		"policy":         input.Policy,
		"namespace":      input.Namespace,
		"verdict":        input.Verdict,
		"direction":      input.Direction,
		"limit":          input.Limit,
		"cluster_scoped": input.ClusterScoped,
	}).Debug("Received get_audit_verdicts request")

	data, err := h.client.GetAuditVerdicts(ctx, input.Policy, input.Namespace, input.Verdict, input.Direction, input.Limit, input.ClusterScoped)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"error":          err.Error(),
			"total_duration": time.Since(startTime).String(),
		}).Error("Error fetching audit verdicts")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error fetching audit verdicts: %v", err)}},
			IsError: true,
		}, AuditVerdictsOutput{}, nil
	}

	// No compaction: audit verdict rows are already a flat, compact
	// shape (policy/src/dst/port/protocol/reason/verdict/observed_at)
	// and the broker bounds the row count server-side, so the result
	// is LLM-sized without further stripping.
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Log.WithField("error", err.Error()).Error("Error marshaling response")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling response: %v", err)}},
			IsError: true,
		}, AuditVerdictsOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"response_bytes": len(jsonData),
		"total_duration": time.Since(startTime).String(),
	}).Info("Successfully fetched audit verdicts")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(jsonData)}},
	}, AuditVerdictsOutput{}, nil
}
