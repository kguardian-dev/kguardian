package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools registers all kguardian MCP tools with the server.
// It delegates to RegisterAllTools which is the single source of truth
// for all tool definitions and handler registrations.
func RegisterTools(server *mcp.Server, brokerURL string) {
	RegisterAllTools(server, brokerURL)
}
