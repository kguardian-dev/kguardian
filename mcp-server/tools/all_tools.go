package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolDef holds a tool definition with its name and description.
// This is the single source of truth for all tool metadata.
type toolDef struct {
	Name        string
	Description string
}

// toolDefs is the canonical list of tool definitions used by both
// GetAllToolDefs (for introspection) and RegisterAllTools (for registration).
var toolDefs = []toolDef{
	{
		Name:        "get_pod_network_traffic",
		Description: "Get network traffic for a specific pod by name. Returns source/destination IPs, ports, protocols, ingress/egress types, and packet decisions. Use when the user asks about a specific pod's connections or traffic. Requires only pod_name (not namespace-scoped — the broker resolves by name cluster-wide).",
	},
	{
		Name:        "get_pod_syscalls",
		Description: "Get system calls made by a specific pod. Returns syscall names, frequencies, and architecture. Use when the user asks about a pod's syscalls, seccomp profile, or suspicious behavior. Requires only pod_name (not namespace-scoped).",
	},
	{
		Name:        "get_pod_details",
		Description: "Look up a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Use when the user has an IP address and wants to identify which pod it belongs to. Requires only ip.",
	},
	{
		Name:        "get_service_details",
		Description: "Look up a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service spec. Use when the user has a service IP and wants to identify the service. Requires only ip.",
	},
	{
		Name:        "get_cluster_traffic",
		Description: "Get a summary of network traffic across the cluster. Returns per-pod traffic counts (ingress/egress/peer counts), not raw records. Accepts an optional namespace parameter to filter results to a single namespace. Use when the user asks about overall traffic patterns or 'what pods are communicating'.",
	},
	{
		Name:        "get_cluster_pods",
		Description: "List pods in the cluster with compact metadata (name, namespace, IP, node, status). Heavyweight fields like pod_obj are stripped. Accepts an optional namespace parameter to filter results. Use when the user asks 'what pods are running' or needs a pod inventory.",
	},
}

// GetAllToolDefs returns the canonical list of tool definitions.
// Useful for introspection and testing.
func GetAllToolDefs() []toolDef {
	result := make([]toolDef, len(toolDefs))
	copy(result, toolDefs)
	return result
}

// RegisterAllTools registers all tools with the MCP server using the
// canonical tool definitions from toolDefs.
func RegisterAllTools(server *mcp.Server, brokerURL string) {
	client := NewBrokerClient(brokerURL)

	// Build a lookup map from the canonical definitions.
	defs := make(map[string]string, len(toolDefs))
	for _, d := range toolDefs {
		defs[d.Name] = d.Description
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_network_traffic",
		Description: defs["get_pod_network_traffic"],
	}, NetworkTrafficHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_syscalls",
		Description: defs["get_pod_syscalls"],
	}, SyscallsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_details",
		Description: defs["get_pod_details"],
	}, PodDetailsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_service_details",
		Description: defs["get_service_details"],
	}, ServiceDetailsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cluster_traffic",
		Description: defs["get_cluster_traffic"],
	}, ClusterTrafficHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cluster_pods",
		Description: defs["get_cluster_pods"],
	}, ClusterPodsHandler{client: client}.Call)
}
