# kguardian LLM Bridge

A microservice that connects the kguardian frontend to LLM providers (OpenAI, Anthropic, Gemini, GitHub Copilot) and gives the model access to cluster data through the MCP server.

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────────┐
│   Frontend  │─────▶│ LLM Bridge  │─────▶│  LLM Provider    │
│   (React)   │ SSE  │(TypeScript) │      │  (OpenAI/Claude/ │
│             │      │             │      │  Gemini/Copilot) │
└─────────────┘      └─────────────┘      └──────────────────┘
                            │
                            ▼
                     ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
                     │ MCP Server  │─────▶│   Broker    │─────▶│ PostgreSQL  │
                     │    (Go)     │      │   (Rust)    │      │             │
                     └─────────────┘      └─────────────┘      └─────────────┘
```

The bridge exists so LLM API keys stay isolated from the Broker, the AI workload can scale independently, and the Broker stays focused on telemetry. It selects the first provider with a configured API key, exposes streaming chat over SSE, and lets the model call the MCP server's 12 tools for live (polled) cluster data. See [mcp-server/README.md](../mcp-server/README.md#available-tools) for the full tool list.

Its only upstream is the MCP server (`MCP_SERVER_URL`) — the bridge never talks to the Broker directly.

## Supported LLM Providers

### OpenAI (GPT-4, GPT-4o)
- **Env Var**: `OPENAI_API_KEY`
- **Default Model**: `gpt-4o`

### Anthropic Claude
- **Env Var**: `ANTHROPIC_API_KEY`
- **Default Model**: `claude-opus-4-8`

### Google Gemini
- **Env Var**: `GOOGLE_API_KEY`
- **Default Model**: `gemini-2.0-flash-exp`

### GitHub Copilot
- **Env Var**: `GITHUB_TOKEN`
- **Default Model**: `gpt-4o`

## Development

### Prerequisites
- Node.js 20+
- npm
- A reachable MCP server

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
docker build -t ghcr.io/kguardian-dev/kguardian/llm-bridge .
```

### Run Container
```bash
docker run -p 8080:8080 \
  -e MCP_SERVER_URL=http://kguardian-mcp-server:8081 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  ghcr.io/kguardian-dev/kguardian/llm-bridge
```

## API Endpoints

Both chat endpoints are rate-limited to **20 requests per minute** per client.

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "hasProvider": true
}
```

### POST /api/chat/stream

Streaming chat over Server-Sent Events — this is what the frontend uses. Same request body as `/api/chat`; the response is an SSE stream of incremental message events, including tool-call rounds, with keepalives while the model works.

### POST /api/chat

Non-streaming chat; returns the full response as one JSON object.

**Request:**
```json
{
  "message": "What pods have the most network traffic?",
  "provider": "anthropic",  // optional: openai, anthropic, gemini, copilot
  "model": "claude-opus-4-8",  // optional: override default
  "conversationId": "abc123",  // optional: for conversation context
  "systemPrompt": "Custom system prompt"  // optional
}
```

**Response:**
```json
{
  "message": "Based on the network traffic data...",
  "provider": "anthropic",
  "model": "claude-opus-4-8",
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

Upstream provider rate limits and overloads are surfaced as `429`/`503` so clients can back off.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 8080) |
| `MCP_SERVER_URL` | No | MCP server URL (default: `http://kguardian-mcp-server.kguardian.svc.cluster.local:8081`) |
| `ALLOWED_ORIGIN` | No | CORS allowed origin (default: `*`) |
| `LOG_LEVEL` | No | Log level (default: `info`) |
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
    repository: ghcr.io/kguardian-dev/kguardian/llm-bridge
    tag: "1.4.1"
  env:
    - name: ANTHROPIC_API_KEY
      valueFrom:
        secretKeyRef:
          name: kguardian-secrets
          key: anthropic-api-key
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
- Check the `/health` endpoint (`hasProvider` should be `true`)

### Connection to MCP server fails
- Verify `MCP_SERVER_URL` is correct
- Ensure MCP server is running: `kubectl get pods -n kguardian | grep mcp-server`
- Check MCP server logs: `kubectl logs -n kguardian deployment/kguardian-mcp-server`
- Verify network policies allow llm-bridge → mcp-server communication
- Look for MCP connection messages in llm-bridge startup logs

### Tools not working / LLM can't access data
- Check that MCP server successfully connected (look for "Connected to MCP server" in logs)
- Verify MCP server can reach the Broker
- Check that all 12 tools are registered: review MCP server logs for tool registration messages

### LLM API errors
- Verify API keys are valid and have credits
- Check LLM provider status pages
- Review error details in response

## Security

- API keys are stored as Kubernetes Secrets and never exposed to the frontend
- Service runs as non-root user
- CORS restricted via `ALLOWED_ORIGIN`

## License

BUSL-1.1 - See LICENSE file
