package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AllTools returns a slice of all tool registrations for the MCP server.
// This file is managed by kmcp and serves as the central registry for all tools.
type ToolRegistration struct {
	Tool    *mcp.Tool
	Handler interface{}
}

// GetAllTools returns all registered tools for the kguardian MCP server
func GetAllTools(brokerURL string) []ToolRegistration {
	client := NewBrokerClient(brokerURL)

	return []ToolRegistration{
		{
			Tool: &mcp.Tool{
				Name:        "get_pod_network_traffic",
				Description: "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, traffic types (ingress/egress), and packet decisions (allowed/dropped). Essential for generating network policies and understanding pod communication patterns.",
			},
			Handler: NetworkTrafficHandler{client: client}.Call,
		},
		{
			Tool: &mcp.Tool{
				Name:        "get_pod_syscalls",
				Description: "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies and architecture. Critical for security analysis, generating seccomp profiles, and identifying suspicious behavior.",
			},
			Handler: SyscallsHandler{client: client}.Call,
		},
		{
			Tool: &mcp.Tool{
				Name:        "get_pod_details",
				Description: "Get detailed information about a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Useful for correlating IP addresses to pod identities.",
			},
			Handler: PodDetailsHandler{client: client}.Call,
		},
		{
			Tool: &mcp.Tool{
				Name:        "get_service_details",
				Description: "Get detailed information about a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service object. Essential for understanding service-to-service communication.",
			},
			Handler: ServiceDetailsHandler{client: client}.Call,
		},
		{
			Tool: &mcp.Tool{
				Name:        "get_cluster_traffic",
				Description: "Get all network traffic data across the entire cluster. Returns comprehensive traffic information for all monitored pods. Use this for cluster-wide network analysis, identifying communication patterns, and detecting anomalies. WARNING: This returns large datasets.",
			},
			Handler: ClusterTrafficHandler{client: client}.Call,
		},
		{
			Tool: &mcp.Tool{
				Name:        "get_cluster_pods",
				Description: "Get detailed information about all pods in the cluster. Returns pod names, namespaces, IPs, and full Kubernetes objects. Useful for cluster inventory and identifying monitored workloads. WARNING: This returns large datasets.",
			},
			Handler: ClusterPodsHandler{client: client}.Call,
		},
	}
}

// RegisterAllTools registers all tools with the MCP server
func RegisterAllTools(server *mcp.Server, brokerURL string) {
	client := NewBrokerClient(brokerURL)

	// Register network traffic tool
	networkTrafficHandler := NetworkTrafficHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_network_traffic",
		Description: "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, traffic types (ingress/egress), and packet decisions (allowed/dropped). Essential for generating network policies and understanding pod communication patterns.",
	}, networkTrafficHandler.Call)

	// Register syscalls tool
	syscallsHandler := SyscallsHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_syscalls",
		Description: "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies and architecture. Critical for security analysis, generating seccomp profiles, and identifying suspicious behavior.",
	}, syscallsHandler.Call)

	// Register pod details tool
	podDetailsHandler := PodDetailsHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_details",
		Description: "Get detailed information about a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Useful for correlating IP addresses to pod identities.",
	}, podDetailsHandler.Call)

	// Register service details tool
	serviceDetailsHandler := ServiceDetailsHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_service_details",
		Description: "Get detailed information about a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service object. Essential for understanding service-to-service communication.",
	}, serviceDetailsHandler.Call)

	// Register cluster traffic tool
	clusterTrafficHandler := ClusterTrafficHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cluster_traffic",
		Description: "Get all network traffic data across the entire cluster. Returns comprehensive traffic information for all monitored pods. Use this for cluster-wide network analysis, identifying communication patterns, and detecting anomalies. WARNING: This returns large datasets.",
	}, clusterTrafficHandler.Call)

	// Register cluster pods tool
	clusterPodsHandler := ClusterPodsHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cluster_pods",
		Description: "Get detailed information about all pods in the cluster. Returns pod names, namespaces, IPs, and full Kubernetes objects. Useful for cluster inventory and identifying monitored workloads. WARNING: This returns large datasets.",
	}, clusterPodsHandler.Call)
}
