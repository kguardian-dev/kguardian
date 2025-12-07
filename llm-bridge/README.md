# kguardian LLM Bridge

A dedicated microservice that bridges the kguardian frontend with multiple LLM providers (OpenAI, Anthropic, Gemini, GitHub Copilot).

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────────┐
│   Frontend  │─────▶│ LLM Bridge  │─────▶│  LLM Provider    │
│   (React)   │      │(TypeScript) │      │  (OpenAI/Claude/ │
│             │      │             │      │  Gemini/Copilot) │
└─────────────┘      └─────────────┘      └──────────────────┘
                            │                      │
                            │                      │
                            ▼                      ▼
                     ┌─────────────┐      ┌──────────────┐
                     │ MCP Server  │      │  Tool Calls  │
                     │    (Go)     │      │ (6 MCP Tools)│
                     │             │      │              │
                     └─────────────┘      └──────────────┘
                            │                      │
                            ▼                      │
                     ┌─────────────┐               │
                     │   Broker    │◀──────────────┘
                     │   (Rust)    │
                     └─────────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │ PostgreSQL  │
                     │   (Data)    │
                     └─────────────┘
```

## Why a Separate Service?

**Security**: API keys isolated from main broker
**Separation of Concerns**: Broker stays focused on telemetry data
**Scalability**: Scale AI workload independently
**Flexibility**: Easy to swap/update LLM logic
**Frontend Direct Connection**: Simpler architecture

## Features

- ✅ **Multi-Provider Support**: OpenAI, Anthropic, Gemini, GitHub Copilot
- ✅ **MCP Integration**: Uses Model Context Protocol (MCP) to access cluster data via MCP server
- ✅ **Function Calling**: LLMs can call 6 MCP tools for real-time cluster data
- ✅ **Automatic Provider Selection**: Uses first available API key
- ✅ **Health Checks**: Monitor service and provider availability
- ✅ **Error Handling**: Comprehensive error messages with graceful fallbacks
- ✅ **TypeScript**: Full type safety with MCP SDK integration

## Supported LLM Providers

### OpenAI (GPT-4, GPT-4o)
- **Env Var**: `OPENAI_API_KEY`
- **Default Model**: `gpt-4o`
- **Best For**: Fast, general-purpose queries

### Anthropic Claude
- **Env Var**: `ANTHROPIC_API_KEY`
- **Default Model**: `claude-sonnet-4-5-20250929`
- **Best For**: Complex security analysis, best reasoning

### Google Gemini
- **Env Var**: `GOOGLE_API_KEY`
- **Default Model**: `gemini-2.0-flash-exp`
- **Best For**: Cost-effective, free tier available

### GitHub Copilot
- **Env Var**: `GITHUB_TOKEN`
- **Default Model**: `gpt-4o`
- **Best For**: If you already have Copilot subscription

## Available Tools

The bridge connects to the MCP server which provides 6 comprehensive tools that LLMs can call:

1. **get_pod_network_traffic** - Query network connections for a specific pod
2. **get_pod_syscalls** - Get system calls made by a specific pod
3. **get_pod_details** - Get detailed pod information by IP address
4. **get_service_details** - Get Kubernetes service information by cluster IP
5. **get_cluster_traffic** - Get all network traffic across the entire cluster
6. **get_cluster_pods** - Get detailed information about all pods in the cluster

For detailed tool specifications, parameters, and use cases, see the [MCP Server documentation](../mcp-server/README.md#available-tools).

## Development

### Prerequisites
- Node.js 20+
- npm
- Access to kguardian broker

### Install Dependencies
```bash
npm install
```

### Configure Environment
```bash
cp .env.example .env
# Edit .env and add at least one API key
```

### Run Development Server
```bash
npm run dev
```

### Build
```bash
npm run build
```

### Start Production Server
```bash
npm start
```

## Docker

### Build Image
```bash
docker build -t kguardian-llm-bridge .
```

### Run Container
```bash
docker run -p 8080:8080 \
  -e BROKER_URL=http://broker:9090 \
  -e OPENAI_API_KEY=sk-... \
  kguardian-llm-bridge
```

## API Endpoints

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "brokerUrl": "http://broker:9090",
  "availableProviders": ["openai", "anthropic"],
  "hasProvider": true
}
```

### POST /api/chat

Send a chat message to the AI assistant.

**Request:**
```json
{
  "message": "What pods have the most network traffic?",
  "provider": "anthropic",  // optional: openai, anthropic, gemini, copilot
  "model": "claude-sonnet-4-5-20250929",  // optional: override default
  "conversationId": "abc123",  // optional: for conversation context
  "systemPrompt": "Custom system prompt"  // optional
}
```

**Response:**
```json
{
  "message": "Based on the network traffic data...",
  "provider": "anthropic",
  "model": "claude-sonnet-4-5-20250929",
  "conversationId": "abc123"
}
```

**Error Response:**
```json
{
  "error": "No LLM provider configured",
  "details": "Please configure at least one API key"
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 8080) |
| `BROKER_URL` | Yes | kguardian broker URL |
| `MCP_SERVER_URL` | No | MCP server URL (default: http://kguardian-mcp-server.kguardian.svc.cluster.local:8081) |
| `OPENAI_API_KEY` | No* | OpenAI API key |
| `ANTHROPIC_API_KEY` | No* | Anthropic API key |
| `GOOGLE_API_KEY` | No* | Google Gemini API key |
| `GITHUB_TOKEN` | No* | GitHub token for Copilot |

*At least one LLM provider API key is required

## Kubernetes Deployment

The service is deployed as part of the kguardian Helm chart:

```yaml
llmBridge:
  enabled: true
  image:
    repository: ghcr.io/kguardian-dev/llm-bridge
    tag: latest
  env:
    - name: BROKER_URL
      value: "http://broker.kguardian.svc.cluster.local:9090"
    - name: OPENAI_API_KEY
      valueFrom:
        secretKeyRef:
          name: kguardian-secrets
          key: openai-api-key
          optional: true
```

## Testing

### Local Testing
```bash
# Start the service
npm run dev

# In another terminal, test the API
curl -X POST http://localhost:8080/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What pods are being monitored?"
  }'
```

### Health Check
```bash
curl http://localhost:8080/health
```

## Troubleshooting

### No providers available
- Ensure at least one API key environment variable is set
- Check the `/health` endpoint to see which providers are configured

### Connection to broker fails
- Verify `BROKER_URL` is correct
- Ensure broker service is running
- Check network policies allow egress from llm-bridge to broker

### Connection to MCP server fails
- Verify `MCP_SERVER_URL` is correct
- Ensure MCP server is running: `kubectl get pods -n kguardian | grep mcp-server`
- Check MCP server logs: `kubectl logs -n kguardian deployment/kguardian-mcp-server`
- Verify network policies allow llm-bridge → mcp-server communication
- Look for MCP connection messages in llm-bridge startup logs

### Tools not working / LLM can't access data
- Check that MCP server successfully connected (look for "✓ Connected to MCP server" in logs)
- Verify MCP server can reach broker
- Test tool calls manually using the MCP Inspector (if using kmcp)
- Check that all 6 tools are registered: Review MCP server logs for tool registration messages

### LLM API errors
- Verify API keys are valid and have credits
- Check LLM provider status pages
- Review error details in response

## Security

- API keys are stored as Kubernetes Secrets
- Service runs as non-root user
- CORS enabled for frontend access
- All communication over HTTPS in production
- API keys never exposed to frontend

## Performance

- Typical response time: 2-5 seconds
- Function calling adds ~1-2 seconds per tool call
- Concurrent request handling with Express
- Health checks every 30 seconds

## License

BUSL-1.1 - See LICENSE file
