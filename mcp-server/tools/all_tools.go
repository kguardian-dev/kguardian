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
		Description: "Get network traffic data for a specific pod by pod name. Returns source/destination IPs, ports, protocols, traffic types (ingress/egress), and packet decisions (allowed/dropped). Essential for generating network policies and understanding pod communication patterns. Note: queries are cluster-wide by pod name, not namespace-scoped.",
	},
	{
		Name:        "get_pod_syscalls",
		Description: "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies and architecture. Critical for security analysis, generating seccomp profiles, and identifying suspicious behavior. Note: queries are cluster-wide by pod name, not namespace-scoped.",
	},
	{
		Name:        "get_pod_details",
		Description: "Get detailed information about a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Useful for correlating IP addresses to pod identities. Note: queries are cluster-wide by pod name, not namespace-scoped.",
	},
	{
		Name:        "get_service_details",
		Description: "Get detailed information about a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service object. Essential for understanding service-to-service communication. Note: queries are cluster-wide by pod name, not namespace-scoped.",
	},
	{
		Name:        "get_cluster_traffic",
		Description: "Get all network traffic data across the entire cluster. Returns comprehensive traffic information for all monitored pods. Use this for cluster-wide network analysis, identifying communication patterns, and detecting anomalies. WARNING: This returns large datasets. Note: queries are cluster-wide by pod name, not namespace-scoped.",
	},
	{
		Name:        "get_cluster_pods",
		Description: "Get detailed information about all pods in the cluster. Returns pod names, namespaces, IPs, and full Kubernetes objects. Useful for cluster inventory and identifying monitored workloads. WARNING: This returns large datasets. Note: queries are cluster-wide by pod name, not namespace-scoped.",
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
