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
- kmcp CLI (optional, for scaffolding)

### Install Dependencies
```bash
go mod download
```

### Run Development Server
```bash
go run main.go
```

### Build
```bash
go build -o bin/kguardian-mcp .
```

### Configuration

Set the broker URL and port via environment variables:
```bash
export BROKER_URL=http://broker.kguardian.svc.cluster.local:9090
export PORT=8081
```

## Docker

### Build Image
```bash
docker build -t kguardian-mcp-server .
```

### Run Container
```bash
docker run -e BROKER_URL=http://broker:9090 kguardian-mcp-server
```

## Kubernetes Deployment

The MCP server is deployed as part of the kguardian Helm chart. See `charts/kguardian/values.yaml` for configuration options.

## License

BUSL-1.1 - See LICENSE file
