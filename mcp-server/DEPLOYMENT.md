# kguardian MCP Server Deployment Guide

This guide covers deployment options for the kguardian MCP server using both traditional Kubernetes manifests and the kmcp controller.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment Methods](#deployment-methods)
  - [Method 1: Using kmcp Controller (Recommended)](#method-1-using-kmcp-controller-recommended)
  - [Method 2: Using Helm Chart](#method-2-using-helm-chart)
  - [Method 3: Using Kustomize](#method-3-using-kustomize)
- [Configuration](#configuration)
- [Transport Options](#transport-options)
- [Monitoring and Observability](#monitoring-and-observability)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required
- Kubernetes cluster (v1.24+)
- `kubectl` configured
- kguardian broker deployed and accessible

### Optional (for kmcp)
- kmcp CLI installed
- kmcp controller installed in cluster

---

## Deployment Methods

### Method 1: Using kmcp Controller (Recommended)

kmcp provides the best developer experience with transport flexibility and native Kubernetes integration.

#### Install kmcp Controller

```bash
# Install kmcp controller to your cluster
kmcp install

# Verify installation
kubectl get pods -n kmcp-system
```

#### Deploy MCP Server

```bash
# Deploy using MCPServer CRD
kubectl apply -f deploy/mcpserver.yaml

# Verify deployment
kubectl get mcpserver -n kguardian
kubectl get pods -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian
```

#### Check Status

```bash
# Get MCP server status
kubectl describe mcpserver kguardian-mcp-server -n kguardian

# View logs
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian -f
```

#### Test the Server

```bash
# Port-forward to access locally
kubectl port-forward svc/kguardian-mcp-server 8081:8081 -n kguardian

# In another terminal, test with curl
curl http://localhost:8081

# Or open MCP Inspector
kmcp run --remote http://localhost:8081
```

---

### Method 2: Using Helm Chart

The Helm chart supports both standard deployments and kmcp-managed deployments.

#### Standard Deployment (without kmcp)

```bash
# Install with standard Kubernetes Deployment
helm upgrade --install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --create-namespace \
  --set mcpServer.enabled=true \
  --set mcpServer.useKmcp=false
```

#### kmcp-Managed Deployment

```bash
# First, install kmcp controller
kmcp install

# Then install with MCPServer CRD
helm upgrade --install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --create-namespace \
  --set mcpServer.enabled=true \
  --set mcpServer.useKmcp=true \
  --set mcpServer.kmcp.transport.type=streamable-http
```

#### With Multiple Transports

```bash
helm upgrade --install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --create-namespace \
  --set mcpServer.enabled=true \
  --set mcpServer.useKmcp=true \
  --set mcpServer.kmcp.transport.type=streamable-http \
  --set-json mcpServer.kmcp.transport.alternativeTransports='[{"type":"sse","path":"/sse"}]'
```

---

### Method 3: Using Kustomize

Kustomize overlays provide environment-specific configurations.

#### Development Environment

```bash
# Deploy to dev environment
kubectl apply -k deploy/overlays/dev

# Verify
kubectl get mcpserver -n kguardian-dev
```

#### Production Environment

```bash
# Deploy to production
kubectl apply -k deploy/overlays/production

# Verify with autoscaling
kubectl get mcpserver -n kguardian
kubectl get hpa -n kguardian
```

#### Custom Environment

Create your own overlay:

```bash
# Create custom overlay
mkdir -p deploy/overlays/staging
cat > deploy/overlays/staging/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../

namespace: kguardian-staging

images:
  - name: ghcr.io/kguardian-dev/kguardian/mcp-server
    newTag: v1.2.0

patchesStrategicMerge:
  - |-
    apiVersion: mcp.kagent.dev/v1alpha1
    kind: MCPServer
    metadata:
      name: kguardian-mcp-server
    spec:
      replicas: 2
      transport:
        type: streamable-http
      env:
        - name: LOG_LEVEL
          value: info
EOF

# Apply
kubectl apply -k deploy/overlays/staging
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BROKER_URL` | kguardian broker endpoint | `http://kguardian-broker.kguardian.svc.cluster.local:9090` |
| `PORT` | HTTP server port | `8081` |
| `LOG_LEVEL` | Log verbosity (debug, info, warn, error) | `info` |

### Using Secrets

```bash
# Create secret for broker authentication
kubectl create secret generic kguardian-mcp-secrets \
  --from-literal=BROKER_API_KEY=your-api-key \
  -n kguardian

# Reference in MCPServer
kubectl patch mcpserver kguardian-mcp-server -n kguardian --type=merge -p '
spec:
  envFrom:
    - secretRef:
        name: kguardian-mcp-secrets
'
```

---

## Transport Options

kmcp allows changing transport without code changes. The MCP server supports:

### 1. StreamableHTTP (Default)
Best for web clients and HTTP-based integrations.

```yaml
spec:
  transport:
    type: streamable-http
    port: 8081
```

### 2. Server-Sent Events (SSE)
For long-lived streaming connections.

```yaml
spec:
  transport:
    type: sse
    port: 8081
    path: /sse
```

### 3. stdio
For local CLI tools and desktop applications.

```yaml
spec:
  transport:
    type: stdio
```

### 4. Multiple Transports Simultaneously

```yaml
spec:
  transport:
    type: streamable-http
    port: 8081
  alternativeTransports:
    - type: stdio
    - type: sse
      path: /sse
```

### Switching Transports

```bash
# Switch to SSE without redeploying code
kubectl patch mcpserver kguardian-mcp-server -n kguardian --type=merge -p '
spec:
  transport:
    type: sse
    port: 8081
'

# kmcp controller handles the transition automatically
kubectl rollout status deployment/kguardian-mcp-server -n kguardian
```

---

## Monitoring and Observability

### Health Checks

```bash
# Check liveness
kubectl exec -it deployment/kguardian-mcp-server -n kguardian -- curl localhost:8081/

# Check readiness
kubectl get pods -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian
```

### Logs

```bash
# View logs
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian -f

# Set debug logging
kubectl patch mcpserver kguardian-mcp-server -n kguardian --type=merge -p '
spec:
  env:
    - name: LOG_LEVEL
      value: debug
'
```

### Metrics (if enabled)

```bash
# Port-forward metrics endpoint
kubectl port-forward svc/kguardian-mcp-server 9090:9090 -n kguardian

# Scrape metrics
curl http://localhost:9090/metrics
```

---

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian

# Describe pod for events
kubectl describe pod -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian

# Check logs
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian --previous
```

### Connection to Broker Failing

```bash
# Test broker connectivity from MCP server pod
kubectl exec -it deployment/kguardian-mcp-server -n kguardian -- \
  curl -v http://kguardian-broker.kguardian.svc.cluster.local:9090/health

# Check network policies
kubectl get networkpolicies -n kguardian
```

### Tools Not Registering

```bash
# Check MCP server startup logs for panic
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian | grep panic

# Verify tool registration
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian | grep "RegisterTools"
```

### kmcp Controller Issues

```bash
# Check kmcp controller status
kubectl get pods -n kmcp-system

# Check kmcp controller logs
kubectl logs -n kmcp-system -l app=kmcp-controller -f

# Verify CRD installation
kubectl get crd mcpservers.mcp.kagent.dev
```

---

## Advanced Topics

### Multi-Tenant Deployment

Deploy separate MCP servers per tenant:

```bash
# Tenant A
kubectl create namespace tenant-a
kubectl apply -f - <<EOF
apiVersion: mcp.kagent.dev/v1alpha1
kind: MCPServer
metadata:
  name: kguardian-mcp-server
  namespace: tenant-a
spec:
  image:
    repository: ghcr.io/kguardian-dev/kguardian/mcp-server
    tag: v1.0.0
  env:
    - name: BROKER_URL
      value: http://kguardian-broker.tenant-a.svc.cluster.local:9090
EOF

# Tenant B
kubectl create namespace tenant-b
kubectl apply -f - <<EOF
apiVersion: mcp.kagent.dev/v1alpha1
kind: MCPServer
metadata:
  name: kguardian-mcp-server
  namespace: tenant-b
spec:
  image:
    repository: ghcr.io/kguardian-dev/kguardian/mcp-server
    tag: v1.0.0
  env:
    - name: BROKER_URL
      value: http://kguardian-broker.tenant-b.svc.cluster.local:9090
EOF
```

### GitOps with Flux/ArgoCD

Create a GitOps-friendly structure:

```yaml
# apps/kguardian-mcp/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - https://github.com/kguardian-dev/kguardian//mcp-server/deploy?ref=v1.0.0

patches:
  - target:
      kind: MCPServer
      name: kguardian-mcp-server
    patch: |-
      - op: replace
        path: /spec/image/tag
        value: v1.0.0
```

---

## Migration from Standard Deployment to kmcp

If you're currently using standard Kubernetes Deployment:

```bash
# 1. Install kmcp controller
kmcp install

# 2. Update Helm values
helm upgrade kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --reuse-values \
  --set mcpServer.useKmcp=true

# 3. Verify migration
kubectl get mcpserver -n kguardian
kubectl get deployment kguardian-mcp-server -n kguardian  # Should not exist

# 4. Test connectivity
kubectl port-forward svc/kguardian-mcp-server 8081:8081 -n kguardian
```

---

## Support

- **Documentation**: https://kguardian.dev/docs
- **Issues**: https://github.com/kguardian-dev/kguardian/issues
- **kmcp Docs**: https://kagent.dev/docs/kmcp
