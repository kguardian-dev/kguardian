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

The kguardian MCP server provides tools for querying Kubernetes security and network telemetry:

### `get_pod_network_traffic`
Get network traffic data for a specific pod.

**Parameters:**
- `pod_name` (string, required): Pod name. Not namespace-scoped — the broker's pod_traffic table is keyed on pod_name alone, so pass just the name and you get every record associated with it.

**Returns:** JSON array of records, each with:
- pod identity columns (`pod_name`, `pod_namespace`, `pod_ip`, `pod_port`)
- `ip_protocol` ("TCP", "UDP", or "SCTP" — UPPERCASE on the wire)
- `traffic_type` ("INGRESS" or "EGRESS" — UPPERCASE on the wire)
- `traffic_in_out_ip` and `traffic_in_out_port` (the peer-side address; destination for egress, source for ingress)
- `decision` ("ALLOW" or "DROP" — UPPERCASE on the wire)
- `time_stamp`

**Use Cases:**
- Generate Kubernetes NetworkPolicies
- Understand pod communication patterns
- Identify unexpected network connections
- Debug connectivity issues

### `get_pod_syscalls`
Get system call data for a specific pod.

**Parameters:**
- `pod_name` (string, required): Pod name. Not namespace-scoped — same rationale as `get_pod_network_traffic`.

**Returns:** JSON with:
- `pod_name`, `pod_namespace`
- `syscalls` (comma-separated string of syscall names observed)
- `arch` (e.g. `amd64`, `arm64`)
- `time_stamp`

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
Get a per-pod summary of network traffic across the cluster. The response is COMPACTED (per-pod ingress/egress counts + unique-peer counts), not the raw record stream — large clusters would blow past LLM context budgets otherwise.

**Parameters:**
- `namespace` (string, optional): Restrict the summary to a single Kubernetes namespace. Omit to summarise across all namespaces.

**Returns:** JSON object with:
- `total_records` (count of traffic rows the summary aggregated)
- `pod_count` (number of distinct pod names in scope)
- `pods` map keyed by pod name → `{ ingress_count, egress_count, unique_peer_count }`
- `filtered_namespace` (echoed back when the namespace filter was set)

**Use Cases:**
- Cluster-wide network analysis
- Identify cross-namespace communication patterns
- Detect network anomalies
- Generate comprehensive NetworkPolicy sets

### `get_cluster_pods`
List pods in the cluster with compact metadata. Returns ALIVE pods only by default (dead historical rows from pod restarts are filtered out). Heavyweight fields (`pod_obj`, `service_spec`) are stripped to keep responses LLM-friendly.

**Parameters:**
- `namespace` (string, optional): Restrict the list to a single namespace. Omit to list pods across all namespaces.

**Returns:** JSON array of compacted pod records, each with:
- `pod_name`, `pod_namespace`, `pod_ip`
- `node_name`, `is_dead`
- `pod_identity` (the controller's heuristic workload-name label, e.g. `app.kubernetes.io/name`)
- `workload_selector_labels` (the resolved selector map from the parent Deployment/StatefulSet/DaemonSet — useful for constructing NetworkPolicy selectors)

**Use Cases:**
- Cluster inventory and discovery
- Identify monitored workloads
- Bulk pod analysis
- Generate reports

### `get_pod_details_by_name`
Look up a single pod by its name (the broker resolves the name cluster-wide). Returns the same compacted identity shape as `get_pod_details`, with `pod_obj` stripped. Prefer this over `get_pod_details` when you have a pod name rather than an IP.

**Parameters:**
- `pod_name` (string, required): The name of the pod to look up.

**Returns:** A compacted pod record (`pod_name`, `pod_namespace`, `pod_ip`, `node_name`, `is_dead`, `pod_identity`, `workload_selector_labels`).

**Use Cases:**
- Resolve a pod name seen in a traffic record to its namespace/IP/node
- Find the workload selector labels for NetworkPolicy construction

### `list_services`
List Kubernetes services across the cluster with compact metadata. Returns the same shape as `get_service_details` (full `service_spec` stripped; `selector` and `ports` lifted), for every service rather than a single known IP.

**Parameters:**
- `namespace` (string, optional): Restrict the list to a single namespace. Omit to list services across all namespaces.

**Returns:** JSON array of compacted service records, each with `svc_name`, `svc_namespace`, `svc_ip`, `service_selector`, `service_ports`.

**Use Cases:**
- Service inventory and discovery
- Map cluster IPs to services when interpreting egress traffic

### `get_pods_on_node`
List the pods recorded on a specific Kubernetes node (compact metadata: name, namespace, IP, node, workload labels; live pods only).

**Parameters:**
- `node` (string, required): The node name to list pods for.

**Returns:** JSON array of compacted pod records, same shape as `get_cluster_pods`.

**Use Cases:**
- Blast-radius analysis ("what runs on node X?")
- Identify workloads sharing a node

### `get_audit_verdicts`
Get network-policy evaluation verdicts produced by the audit pipeline — observed flows scored as `Allow` or `WouldDeny` against `AuditNetworkPolicy` / `AuditClusterNetworkPolicy` resources. Rows are returned newest-first. This is the primary tool for security questions about what traffic a policy would block.

**Parameters (all optional):**
- `policy` (string): Filter to a single policy by name. Pair with `namespace` for an `AuditNetworkPolicy`; leave `namespace` empty for an `AuditClusterNetworkPolicy`.
- `namespace` (string): Filter by policy namespace.
- `verdict` (string): `Allow` or `WouldDeny`. Use `WouldDeny` to surface flows that would be blocked if the policy were enforced.
- `direction` (string): `Ingress` or `Egress`.
- `limit` (number): Cap rows returned. Defaults to 100, hard cap 500.

**Returns:** JSON array of verdict records, each with `policy_name`, `policy_namespace`, `direction`, `src_namespace`/`src_pod`, `dst_namespace`/`dst_pod`, `dst_port`, `protocol`, `reason`, `verdict`, and `observed_at`.

**Use Cases:**
- "What traffic would be denied by policy X?"
- "Why is this flow blocked?" / "Show recent policy violations"
- Validate an audit-mode policy before promoting it to enforcement

> **Note:** Requires the broker's audit pipeline to be enabled (`EVALUATOR_URL` set on the broker). With audit disabled, no verdicts are recorded and this tool returns an empty list.

### `generate_network_policy`
Generate a least-privilege Kubernetes NetworkPolicy (or CiliumNetworkPolicy) for a pod from its observed traffic. The synthesis is performed by the **advisor service** (`advisor serve`); this tool proxies to it and returns the YAML verbatim.

**Parameters:**
- `pod_name` (string, required): The pod to generate a policy for.
- `policy_type` (string, optional): `kubernetes` (standard NetworkPolicy, default) or `cilium`.

**Returns:** Ready-to-apply policy YAML.

### `generate_seccomp_profile`
Generate a least-privilege seccomp profile (JSON) for a pod from its observed syscalls. Proxies to the advisor service.

**Parameters:**
- `pod_name` (string, required): The pod to generate a profile for.

**Returns:** Seccomp profile JSON (allow-lists observed syscalls, denies the rest).

> **Note:** The two `generate_*` tools require the **advisor service** to be reachable. Set `ADVISOR_URL` on the MCP server (default `http://kguardian-advisor.kguardian.svc.cluster.local:8083`). The advisor service must be deployed (`advisor serve`, with `BROKER_URL` pointing at the broker).

## Development

### Prerequisites
- Go 1.25+
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
export BROKER_URL=http://kguardian-broker.kguardian.svc.cluster.local:9090
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

The MCP server is deployed via the kguardian Helm chart. See [DEPLOYMENT.md](./DEPLOYMENT.md) for details.

```bash
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --set mcpServer.enabled=true \
  --namespace kguardian --create-namespace
```

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

1. Deploy the MCP server via the Helm chart (`mcpServer.enabled=true`)
2. Configure LLM bridge with MCP server URL
3. Start asking questions!

See the [LLM Bridge documentation](../llm-bridge/README.md) for setup details.

## License

BUSL-1.1 - See LICENSE file
