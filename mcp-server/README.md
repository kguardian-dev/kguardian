# kguardian MCP Server

Model Context Protocol (MCP) server for kguardian - provides tools for querying Kubernetes security and network telemetry data.

## Overview

This MCP server exposes kguardian's broker API as MCP tools, allowing LLMs to query:
- Pod network traffic data
- System call (syscall) usage patterns
- Packet drop events
- Security analysis aggregations

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────┐
│  LLM Client │─────▶│ MCP Server  │─────▶│    Broker    │
│  (AI Apps)  │      │    (Go)     │      │   (Rust)     │
└─────────────┘      └─────────────┘      └──────────────┘
                                                  │
                                                  ▼
                                           ┌─────────────┐
                                           │ PostgreSQL  │
                                           │   (Data)    │
                                           └─────────────┘
```

## Available Tools

### `get_pod_network_traffic`
Get network traffic data for a specific pod.

**Parameters:**
- `namespace` (string, required): Kubernetes namespace
- `pod_name` (string, required): Pod name

**Returns:** JSON with source/destination IPs, ports, protocols, and connection counts.

### `get_pod_syscalls`
Get system call data for a specific pod.

**Parameters:**
- `namespace` (string, required): Kubernetes namespace
- `pod_name` (string, required): Pod name

**Returns:** JSON with syscalls and their frequencies.

## Development

### Prerequisites
- Go 1.23+
- kmcp CLI (recommended) - Install from https://kagent.dev/docs/kmcp
- Docker (for building images)
- Kubernetes cluster (for deployment)

### Quick Start with kmcp

```bash
# Run locally with hot reload
kmcp run --project-dir .

# This automatically:
# - Builds the server
# - Opens MCP Inspector for testing
# - Watches for code changes
```

### Manual Development

```bash
# Install dependencies
go mod download

# Run server
go run main.go

# Build binary
go build -o bin/kguardian-mcp .
```

### Configuration

Set the broker URL and port via environment variables:
```bash
export BROKER_URL=http://broker.kguardian.svc.cluster.local:9090
export PORT=8081
export LOG_LEVEL=debug  # Optional: debug, info, warn, error
```

### Adding New Tools

With kmcp:
```bash
# Scaffold a new tool
kmcp add-tool get_pod_metrics --project-dir .

# This creates:
# - tools/get_pod_metrics.go with boilerplate
# - Auto-updates tools/all_tools.go
```

Manually:
1. Create `tools/your_tool.go` with Input/Output structs
2. Implement the `Call` method
3. Register in `tools/all_tools.go`

## Docker

### Build Image
```bash
docker build -t kguardian-mcp-server .
```

### Run Container
```bash
docker run -e BROKER_URL=http://broker:9090 kguardian-mcp-server
```

## Deployment

The MCP server supports multiple deployment methods. See [DEPLOYMENT.md](./DEPLOYMENT.md) for comprehensive deployment guides.

### Quick Deploy with kmcp

```bash
# Install kmcp controller
kmcp install

# Deploy MCP server
kubectl apply -f deploy/mcpserver.yaml

# Verify
kubectl get mcpserver -n kguardian
```

### Deploy with Helm

```bash
# Standard deployment
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --set mcpServer.enabled=true \
  --namespace kguardian --create-namespace

# With kmcp controller (recommended)
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --set mcpServer.enabled=true \
  --set mcpServer.useKmcp=true \
  --namespace kguardian --create-namespace
```

### Benefits of kmcp Deployment

- ✅ **Transport Flexibility**: Switch between HTTP, SSE, stdio, WebSocket without code changes
- ✅ **Better DX**: Built-in testing with MCP Inspector
- ✅ **Kubernetes-Native**: MCPServer CRD managed by controller
- ✅ **Easy Scaling**: Autoscaling and multi-tenant support
- ✅ **Observability**: Built-in metrics and tracing integration

## License

BUSL-1.1 - See LICENSE file
