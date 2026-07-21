# kguardian MCP Server Deployment

The MCP server is deployed through the kguardian Helm chart — there is no standalone manifest.

## Deploy

```bash
helm upgrade --install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --create-namespace \
  --set mcpServer.enabled=true
```

This creates a Deployment and a `kguardian-mcp-server` Service on port 8081.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `BROKER_URL` | kguardian broker endpoint | `http://kguardian-broker.kguardian.svc.cluster.local:9090` |
| `PORT` | HTTP server port | `8081` |
| `LOG_LEVEL` | Log verbosity (debug, info, warn, error) | `info` |

## Health Check

```bash
kubectl exec -it deployment/kguardian-mcp-server -n kguardian -- \
  curl localhost:8081/healthz
```

The health endpoint is `GET /healthz` (not `/`).

## Troubleshooting

### Pod not starting

```bash
kubectl get pods -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian
kubectl describe pod -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian --previous
```

### Connection to broker failing

```bash
# Test broker connectivity from the MCP server pod
kubectl exec -it deployment/kguardian-mcp-server -n kguardian -- \
  curl -v http://kguardian-broker.kguardian.svc.cluster.local:9090/health

# Check network policies
kubectl get networkpolicies -n kguardian
```

### Tools not registering

```bash
# Check startup logs for a panic
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian | grep panic

# Verify tool registration (tools are wired in RegisterAllTools)
kubectl logs -l app.kubernetes.io/name=kguardian-mcp-server -n kguardian | grep -i register
```

## Support

- **Documentation**: https://docs.kguardian.dev
- **Issues**: https://github.com/kguardian-dev/kguardian/issues
