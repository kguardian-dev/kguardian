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

The kguardian MCP server provides 6 comprehensive tools for querying Kubernetes security and network telemetry:

### `get_pod_network_traffic`
Get network traffic data for a specific pod.

**Parameters:**
- `namespace` (string, required): Kubernetes namespace
- `pod_name` (string, required): Pod name

**Returns:** JSON with:
- Source/destination IPs and ports
- IP protocols (TCP, UDP, etc.)
- Traffic types (ingress/egress)
- Packet decisions (allowed/dropped)
- Timestamps

**Use Cases:**
- Generate Kubernetes NetworkPolicies
- Understand pod communication patterns
- Identify unexpected network connections
- Debug connectivity issues

### `get_pod_syscalls`
Get system call data for a specific pod.

**Parameters:**
- `namespace` (string, required): Kubernetes namespace
- `pod_name` (string, required): Pod name

**Returns:** JSON with:
- Syscall names and frequencies
- CPU architecture (amd64, arm64, etc.)
- Timestamps

**Use Cases:**
- Generate seccomp profiles
- Security analysis and threat detection
- Identify suspicious system call patterns
- Baseline normal pod behavior

### `get_pod_details`
Get detailed information about a pod by its IP address.

**Parameters:**
- `ip` (string, required): Pod IP address

**Returns:** JSON with:
- Pod name and namespace
- Pod IP address
- Full Kubernetes pod object (labels, annotations, containers, etc.)
- Timestamp

**Use Cases:**
- Correlate IP addresses to pod identities
- Lookup pod metadata from traffic logs
- Investigate specific pods by IP

### `get_service_details`
Get detailed information about a Kubernetes service by its cluster IP.

**Parameters:**
- `ip` (string, required): Service cluster IP address

**Returns:** JSON with:
- Service name and namespace
- Service IP and ports
- Full Kubernetes service object (selectors, type, etc.)
- Timestamp

**Use Cases:**
- Understand service-to-service communication
- Map service IPs to service names
- Analyze load balancer configurations

### `get_cluster_traffic`
Get all network traffic data across the entire cluster.

**Parameters:** None

**Returns:** JSON array with all pod traffic data (see `get_pod_network_traffic` structure)

**Use Cases:**
- Cluster-wide network analysis
- Identify cross-namespace communication patterns
- Detect network anomalies
- Generate comprehensive NetworkPolicy sets

**WARNING:** This returns large datasets. Use with caution in large clusters.

### `get_cluster_pods`
Get detailed information about all pods in the cluster.

**Parameters:** None

**Returns:** JSON array with all pod details (see `get_pod_details` structure)

**Use Cases:**
- Cluster inventory and discovery
- Identify monitored workloads
- Bulk pod analysis
- Generate reports

**WARNING:** This returns large datasets. Use with caution in large clusters.

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

## Integration with LLM Bridge

The kguardian MCP server is designed to work seamlessly with the kguardian LLM bridge, providing AI-powered security analysis:

### How it Works

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────┐
│  AI Client  │─────▶│  LLM Bridge  │─────▶│ MCP Server  │─────▶│  Broker  │
│  (ChatGPT,  │      │ (TypeScript) │      │    (Go)     │      │  (Rust)  │
│   Claude)   │      └──────────────┘      └─────────────┘      └──────────┘
└─────────────┘              │                                          │
                             │                                          ▼
                             │                                   ┌──────────────┐
                             │                                   │  PostgreSQL  │
                             │                                   │  (Telemetry) │
                             │                                   └──────────────┘
                             ▼
                      ┌──────────────┐
                      │  LLM Model   │
                      │  (Analysis)  │
                      └──────────────┘
```

### Example AI Queries

With the LLM bridge, you can ask natural language questions like:

- **Security Analysis:**
  - "What pods are making suspicious syscalls?"
  - "Show me any pods with unexpected network connections"
  - "Are there any security risks in namespace production?"

- **Network Policy Generation:**
  - "Generate a NetworkPolicy for the frontend pods"
  - "What network policies should I create for my microservices?"
  - "Show me which pods can communicate and create policies for them"

- **Troubleshooting:**
  - "Why can't pod A reach pod B?"
  - "What services is my pod talking to?"
  - "Find all pods communicating with external IPs"

- **Compliance & Auditing:**
  - "Generate a seccomp profile for all pods in namespace banking"
  - "Show me which pods are running with elevated privileges"
  - "List all network traffic to/from sensitive namespaces"

### Configuration

The LLM bridge automatically discovers and uses all MCP tools. No additional configuration needed beyond:

1. Deploy MCP server with kmcp or Helm
2. Configure LLM bridge with MCP server URL
3. Start asking questions!

See the [LLM Bridge documentation](../llm-bridge/README.md) for setup details.

## License

BUSL-1.1 - See LICENSE file
