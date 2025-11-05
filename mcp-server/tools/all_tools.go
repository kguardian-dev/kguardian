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
				Description: "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, and connection counts.",
			},
			Handler: NetworkTrafficHandler{client: client}.Call,
		},
		{
			Tool: &mcp.Tool{
				Name:        "get_pod_syscalls",
				Description: "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies. Useful for security analysis and seccomp profile generation.",
			},
			Handler: SyscallsHandler{client: client}.Call,
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
		Description: "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, and connection counts.",
	}, networkTrafficHandler.Call)

	// Register syscalls tool
	syscallsHandler := SyscallsHandler{client: client}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_syscalls",
		Description: "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies. Useful for security analysis and seccomp profile generation.",
	}, syscallsHandler.Call)
}
