package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools registers all kguardian MCP tools with the server.
// This is a compatibility wrapper that delegates to RegisterAllTools.
// Deprecated: Use RegisterAllTools directly for better kmcp integration.
func RegisterTools(server *mcp.Server, brokerURL string) {
	RegisterAllTools(server, brokerURL)
}
