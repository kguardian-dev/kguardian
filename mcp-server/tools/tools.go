package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools registers all kguardian MCP tools with the server
func RegisterTools(server *mcp.Server, brokerURL string) {
	// Create broker client for tools to use
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
