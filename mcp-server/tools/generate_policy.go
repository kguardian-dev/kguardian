package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

// GenerateNetworkPolicyInput defines the input for the network policy generator.
type GenerateNetworkPolicyInput struct {
	PodName    string `json:"pod_name" jsonschema:"The name of the pod to generate a least-privilege network policy for"`
	PolicyType string `json:"policy_type,omitempty" jsonschema:"Policy flavour: 'kubernetes' (standard NetworkPolicy, default) or 'cilium' (CiliumNetworkPolicy)"`
}

// GenerateNetworkPolicyOutput holds the generated policy YAML.
type GenerateNetworkPolicyOutput struct {
	Data string `json:"data" jsonschema:"Generated network policy in YAML format"`
}

// GenerateNetworkPolicyHandler handles the generate_network_policy tool.
type GenerateNetworkPolicyHandler struct {
	advisor *AdvisorClient
}

// Call implements the tool handler.
func (h GenerateNetworkPolicyHandler) Call(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input GenerateNetworkPolicyInput,
) (*mcp.CallToolResult, GenerateNetworkPolicyOutput, error) {
	start := time.Now()
	logger.Log.WithFields(logrus.Fields{"pod_name": input.PodName, "policy_type": input.PolicyType}).
		Debug("Received generate_network_policy request")

	if input.PodName == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "pod_name is required"}},
			IsError: true,
		}, GenerateNetworkPolicyOutput{}, nil
	}

	policyType := normalizePolicyType(input.PolicyType)

	yaml, err := h.advisor.GenerateNetworkPolicy(ctx, input.PodName, policyType)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"pod_name":       input.PodName,
			"policy_type":    policyType,
			"error":          err.Error(),
			"total_duration": time.Since(start).String(),
		}).Error("Error generating network policy")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error generating network policy: %v", err)}},
			IsError: true,
		}, GenerateNetworkPolicyOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"pod_name":       input.PodName,
		"policy_type":    policyType,
		"response_bytes": len(yaml),
		"total_duration": time.Since(start).String(),
	}).Info("Successfully generated network policy")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: yaml}},
	}, GenerateNetworkPolicyOutput{}, nil
}

// normalizePolicyType maps user-supplied aliases to the advisor's accepted
// values, defaulting to "kubernetes". Unknown values are passed through so the
// advisor returns its own clear validation error.
func normalizePolicyType(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "", "kubernetes", "k8s", "standard":
		return "kubernetes"
	case "cilium":
		return "cilium"
	default:
		return in
	}
}

// GenerateSeccompProfileInput defines the input for the seccomp generator.
type GenerateSeccompProfileInput struct {
	PodName string `json:"pod_name" jsonschema:"The name of the pod to generate a seccomp profile for"`
}

// GenerateSeccompProfileOutput holds the generated profile JSON.
type GenerateSeccompProfileOutput struct {
	Data string `json:"data" jsonschema:"Generated seccomp profile in JSON format"`
}

// GenerateSeccompProfileHandler handles the generate_seccomp_profile tool.
type GenerateSeccompProfileHandler struct {
	advisor *AdvisorClient
}

// Call implements the tool handler.
func (h GenerateSeccompProfileHandler) Call(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input GenerateSeccompProfileInput,
) (*mcp.CallToolResult, GenerateSeccompProfileOutput, error) {
	start := time.Now()
	logger.Log.WithField("pod_name", input.PodName).Debug("Received generate_seccomp_profile request")

	if input.PodName == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "pod_name is required"}},
			IsError: true,
		}, GenerateSeccompProfileOutput{}, nil
	}

	profile, err := h.advisor.GenerateSeccompProfile(ctx, input.PodName)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"pod_name":       input.PodName,
			"error":          err.Error(),
			"total_duration": time.Since(start).String(),
		}).Error("Error generating seccomp profile")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error generating seccomp profile: %v", err)}},
			IsError: true,
		}, GenerateSeccompProfileOutput{}, nil
	}

	logger.Log.WithFields(logrus.Fields{
		"pod_name":       input.PodName,
		"response_bytes": len(profile),
		"total_duration": time.Since(start).String(),
	}).Info("Successfully generated seccomp profile")

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: profile}},
	}, GenerateSeccompProfileOutput{}, nil
}
