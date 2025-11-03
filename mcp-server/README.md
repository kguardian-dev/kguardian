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
│  (AI Apps)  │      │ (TypeScript)│      │   (Rust)     │
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

### `get_pod_packet_drops`
Get packet drop events for a pod.

**Parameters:**
- `namespace` (string, required): Kubernetes namespace
- `pod_name` (string, required): Pod name

**Returns:** JSON with packet drop reasons and statistics.

### `list_all_pods`
List all monitored pods across namespaces.

**Parameters:** None

**Returns:** List of pods with names, namespaces, and IPs.

### `search_pods_by_namespace`
Search for pods within a namespace.

**Parameters:**
- `namespace` (string, required): Namespace to search

**Returns:** Pods in the specified namespace.

### `analyze_security_events`
Analyze security events across the cluster.

**Parameters:**
- `namespace` (string, optional): Filter by namespace

**Returns:** Aggregated security analysis.

## Development

### Prerequisites
- Node.js 20+
- npm

### Install Dependencies
```bash
npm install
```

### Run Development Server
```bash
npm run dev
```

### Build
```bash
npm run build
```

### Configuration

Set the broker URL via environment variable:
```bash
export BROKER_URL=http://broker.kguardian.svc.cluster.local:9090
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
