# kguardian LLM Bridge

A microservice that connects the kguardian frontend to LLM providers (OpenAI, Anthropic, Gemini, GitHub Copilot) and gives the model access to cluster data. All 12 assistant tools, plus NetworkPolicy and seccomp profile generation, run in-process — there's no separate backend service for the model to call.

The same 12 tools can optionally be served to *external* MCP clients (Claude Code, for one) over StreamableHTTP at `POST /mcp` on this service's existing port. That endpoint is off by default; see [MCP Endpoint](#mcp-endpoint) below and the [Connect an MCP client guide](https://docs.kguardian.dev/guides/mcp-endpoint) for the client-side setup.

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────────┐
│   Frontend  │─────▶│ LLM Bridge  │─────▶│  LLM Provider    │
│   (React)   │ SSE  │(TypeScript) │      │  (OpenAI/Claude/ │
│             │      │             │      │  Gemini/Copilot) │
└─────────────┘      └──────┬──────┘      └──────────────────┘
                             │ tool calls, in-process
                             ▼
                      ┌─────────────┐      ┌─────────────┐
                      │   Broker    │─────▶│ PostgreSQL  │
                      │   (Rust)    │      │             │
                      └─────────────┘      └─────────────┘
```

The bridge exists so LLM API keys stay isolated from the Broker, the AI workload can scale independently, and the Broker stays focused on telemetry. It selects the first provider with a configured API key and exposes streaming chat over SSE. When the model calls a tool, the bridge executes it in-process (`src/tools/execute.ts`): the 10 read tools fetch and compact data straight from the Broker (`src/tools/backendClient.ts`, `src/tools/compaction.ts`), and the 2 generation tools (`generate_network_policy`, `generate_seccomp_profile`) build the policy/profile locally from the same observed-traffic and observed-syscall data, using the same algorithms as the advisor CLI (`src/tools/generators/`). See `src/tools/registry.ts` for the full tool list and descriptions.

Its only upstream is the Broker (`BROKER_URL`) — there's no MCP transport hop and no advisor service call; tool execution and policy/seccomp generation both happen inside this process.

## Supported LLM Providers

Every provider takes three env vars: an API key (which also gates whether the provider is offered at all), an optional base URL, and an optional default model. The first provider with a non-empty API key wins unless the request names one.

| Provider | API key | Base URL (default) | Model (default) |
|---|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `OPENAI_BASE_URL` (`https://api.openai.com/v1`) | `OPENAI_MODEL` (`gpt-4o`) |
| Anthropic Claude | `ANTHROPIC_API_KEY` | `ANTHROPIC_BASE_URL` (`https://api.anthropic.com`) | `ANTHROPIC_MODEL` (`claude-opus-4-8`) |
| Google Gemini | `GOOGLE_API_KEY` | `GEMINI_BASE_URL` (`https://generativelanguage.googleapis.com`) | `GEMINI_MODEL` (`gemini-2.0-flash`) |
| GitHub Copilot | `GITHUB_TOKEN` | `COPILOT_BASE_URL` (`https://api.githubcopilot.com`) | `COPILOT_MODEL` (`gpt-4o`) |

Gemini's asymmetry is intentional: the key is `GOOGLE_API_KEY` — Google's own SDK env var name, kept so an existing value carries over — while the base URL and model are `GEMINI_*`. A whitespace-only value counts as unset for all three columns, so `ANTHROPIC_API_KEY="  "` disables the provider rather than producing a 401 later.

`ANTHROPIC_BASE_URL` is not new: the Anthropic SDK already picked it up implicitly. It is now passed explicitly so all four providers read their base from one place, a typo is reported against the env var name instead of surfacing as an SDK connection error, and whitespace-only counts as unset.

### OpenAI-compatible gateways (LiteLLM, vLLM, proxies)

Set the base URL to run the assistant against a gateway instead of the vendor API:

```bash
OPENAI_API_KEY=sk-litellm-virtual-key
OPENAI_BASE_URL=http://litellm.litellm.svc.cluster.local:4000/v1
OPENAI_MODEL=my-gateway-model-name
```

Two things decide whether this works.

**The API key is still required.** Provider availability is gated on the key alone (`availableProvidersFromEnv` in `src/index.ts`), not on the base URL. A LiteLLM user must set `OPENAI_API_KEY` to their LiteLLM virtual key — or to any non-empty dummy value if the gateway is unauthenticated. Leave it unset and `/health` reports `hasProvider: false`, chat requests fail with `503 No LLM provider configured`, and nothing in the error mentions the base URL you carefully configured. This is the most common first-run mistake.

**The request path is appended verbatim.** kguardian never inserts, removes, or rewrites a `/v1` segment; only a trailing slash is stripped so `.../v1` and `.../v1/` behave the same. The base URL you set plus the provider's own path is the exact URL called:

| Provider | Appended path |
|---|---|
| openai, copilot | `/chat/completions` |
| gemini | `/v1beta/models/<model>:generateContent` |
| anthropic | handled by the Anthropic SDK (`/v1/messages`) |

So if your gateway serves `/v1/chat/completions`, include `/v1` in `OPENAI_BASE_URL`; if it serves `/chat/completions`, do not. LiteLLM answers on both, which is why a value that "works" on LiteLLM can 404 on vLLM or an enterprise proxy — those usually expose only the `/v1` form. Guessing would silently rewrite a URL you deliberately chose, so kguardian errors instead:

- A value that is not a usable `http(s)` URL fails before any request is sent, and the message names the env var: `OPENAI_BASE_URL is not a valid URL: "localhost:4000". Expected an http(s) base URL such as …`. A missing scheme is caught here too.
- A `404` or `405` response appends the URL that was actually called and the var to fix: `(POST http://litellm…:4000/chat/completions returned 404 — check OPENAI_BASE_URL …)`. Other statuses (401, 429, model-not-found) keep the upstream message unadorned. This hint is added by the openai, copilot, and gemini paths; the Anthropic provider surfaces the SDK's own error.

## Development

### Prerequisites
- Node.js 20+
- npm
- A reachable Broker

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
  -e BROKER_URL=http://kguardian-broker:9090 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  ghcr.io/kguardian-dev/kguardian/llm-bridge
```

## API Endpoints

Three routes are registered: `GET /health`, `POST /api/chat/stream`, and — only when `MCP_ENABLED` is set — `POST /mcp`. There is no non-streaming `/api/chat` route.

### GET /health

Health check. Read by the chart's liveness and readiness probes and by the frontend's provider gate.

**Response:**
```json
{
  "status": "healthy",
  "hasProvider": true,
  "mcp": false
}
```

`hasProvider` is true when at least one provider API key is set to a non-empty value. `mcp` reports whether the MCP endpoint is routed.

### POST /api/chat/stream

Streaming chat over Server-Sent Events — this is what the frontend uses. The response is a stream of `text`, `thinking`, `tool_use`, `tool_result`, and a terminal `done` (or `error`) event, with `: ping` keepalives while the model works. Anthropic streams natively; the other providers run to completion and arrive as a single `text` chunk.

Rate-limited to **20 requests per minute** per client. (`/mcp` is not covered by this limiter — it has its own, far higher one; see below.)

**Request:**
```json
{
  "message": "What pods have the most network traffic?",
  "provider": "anthropic",
  "model": "claude-opus-4-8",
  "context": "optional free-text context, max 2000 chars",
  "history": [{ "role": "user", "content": "earlier turn" }]
}
```

Only `message` is required (1–50000 characters). `provider` is one of `openai`, `anthropic`, `gemini`, `copilot`; omitted, the first provider with a configured key is used.

**Error response** (before the stream opens — a failure mid-stream arrives as an SSE `error` event instead):
```json
{
  "error": "No LLM provider configured",
  "details": "Please configure at least one API key: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GITHUB_TOKEN"
}
```

Upstream provider rate limits and overloads are surfaced with an actionable message so clients can back off.

## MCP Endpoint

`POST /mcp` serves the same 12 tools to external MCP clients over StreamableHTTP, on this service's existing port — no second listener, Service, or Deployment. It is **off by default**: without `MCP_ENABLED` the route is never mounted and the path 404s exactly as if the build never had it.

This is not the return of the retired standalone Go `mcp-server` (removed in PR #1197). It is the same in-process registry (`src/tools/registry.ts`) that the provider loops already use, re-served over HTTP — `tools/list` passes each tool's `parameters` through verbatim, so an external client and the LLM see byte-identical definitions.

The server identifies itself as `kguardian` at the llm-bridge version and advertises the `tools` capability only — no MCP resources, no prompts.

**Transport.** Stateless: each POST is served by its own short-lived server and transport, because the chart runs two replicas behind a ClusterIP Service with no session affinity and a server-side session created on one replica would not exist on the other. Consequences worth knowing:

- A request needs **both** `Content-Type: application/json` and `Accept: application/json, text/event-stream`. Missing either, the SDK answers `406`. Responses come back as SSE.
- `GET` and `DELETE /mcp` return **405 by design**, with `Allow: POST`. A GET would open a server-notification stream this server never writes to, pinning a socket for the life of the client. The MCP spec permits 405 here and clients — Claude Code included — treat it as "not offered" and carry on. It is not a bug.

**Auth.** Set `MCP_AUTH_TOKEN` and every request must carry `Authorization: Bearer <token>`; anything else gets a `401` with a `WWW-Authenticate: Bearer realm="kguardian-mcp"` header and a deliberately uninformative body. Comparison is constant-time. Unset (or whitespace-only) means no auth — acceptable only when something else fronts the Service, because the endpoint hands cluster telemetry to any caller that reaches it with no LLM in the path.

**Rate limit.** `MCP_RATE_LIMIT_PER_MIN`, default **300**. Far above the chat route's 20/min because one client session is many round-trips — `initialize`, `tools/list`, then a POST per tool call, and an agent investigating a dropped flow burns 30–60 calls in seconds. The counter is per-replica (in-memory), so with `replicaCount: 2` the cluster-wide ceiling is roughly double. It is a runaway-client guard, not a quota.

**CORS.** `ALLOWED_ORIGIN` defaults to `*`, which is what lets a browser-based client send the `mcp-protocol-version` and `authorization` headers through preflight. Locking it to the UI's origin blocks MCP clients from every other origin — fine for the intended non-browser, port-forwarded clients, but a real constraint.

Smoke-test it by hand:

```bash
curl -sN -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

For connecting Claude Code or another MCP client, see the [Connect an MCP client guide](https://docs.kguardian.dev/guides/mcp-endpoint).

## Environment Variables

Every value below is trimmed before use, and a whitespace-only value counts as unset — so `ANTHROPIC_API_KEY="  "` disables that provider rather than sending a blank credential.

### Service

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: `8080`) |
| `BROKER_URL` | No | Broker URL (default: `http://kguardian-broker.kguardian.svc.cluster.local:9090`) |
| `BROKER_AUTH_TOKEN` | No | Bearer token sent to the Broker, if the Broker requires auth |
| `ALLOWED_ORIGIN` | No | CORS allowed origin (default: `*`) |
| `LOG_LEVEL` | No | Log level (default: `info`) |

### Providers

At least one API key is required, and the key alone decides whether a provider is offered — setting only a base URL leaves the provider unavailable.

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | No* | OpenAI API key (or your gateway's virtual key) |
| `OPENAI_BASE_URL` | No | Base URL for OpenAI-compatible endpoints (default: `https://api.openai.com/v1`) |
| `OPENAI_MODEL` | No | Default model (default: `gpt-4o`) |
| `ANTHROPIC_API_KEY` | No* | Anthropic API key |
| `ANTHROPIC_BASE_URL` | No | Base URL for the Anthropic API (default: `https://api.anthropic.com`) |
| `ANTHROPIC_MODEL` | No | Default model (default: `claude-opus-4-8`) |
| `GOOGLE_API_KEY` | No* | Google Gemini API key |
| `GEMINI_BASE_URL` | No | Base URL for the Gemini API (default: `https://generativelanguage.googleapis.com`) |
| `GEMINI_MODEL` | No | Default model (default: `gemini-2.0-flash`) |
| `GITHUB_TOKEN` | No* | GitHub token for Copilot |
| `COPILOT_BASE_URL` | No | Base URL for the Copilot API (default: `https://api.githubcopilot.com`) |
| `COPILOT_MODEL` | No | Default model (default: `gpt-4o`) |

*At least one LLM provider API key is required.

### MCP endpoint

| Variable | Required | Description |
|----------|----------|-------------|
| `MCP_ENABLED` | No | Serve `/mcp` when `true` or `1`. Anything else — including unset — leaves the route unmounted, and the path 404s |
| `MCP_AUTH_TOKEN` | No | Shared secret required as `Authorization: Bearer <token>`. Unset means no auth |
| `MCP_RATE_LIMIT_PER_MIN` | No | Per-IP, per-replica request ceiling for `/mcp` (default: `300`). A non-numeric or non-positive value falls back to the default |

## Kubernetes Deployment

The service is deployed as part of the kguardian Helm chart. The chart's own default image tag tracks the released llm-bridge, so leave it unpinned unless you are deliberately holding a version back.

The shortest path is `ai.provider` + `ai.secret`, which writes the right API key env var for you:

```yaml
ai:
  enabled: true
  provider: anthropic          # openai | anthropic | gemini | copilot
  secret: kguardian-anthropic  # Secret holding the key under `api-key`
```

Add `ai.baseUrl` / `ai.model` to point that provider at a gateway, and `ai.mcp.*` to serve the MCP endpoint. For per-provider secrets, extra env vars, or a multi-provider setup, use `llmBridge.secrets.*` and `llmBridge.env` instead:

```yaml
llmBridge:
  enabled: true
  env:
    - name: OPENAI_BASE_URL
      value: http://litellm.litellm.svc.cluster.local:4000/v1
```

The full values reference is in [`charts/kguardian/values.yaml`](../charts/kguardian/values.yaml); the operator-facing walkthrough is on the [docs site](https://docs.kguardian.dev/installation#ai-assistant).

## Testing

### Local Testing
```bash
# Start the service
npm run dev

# In another terminal, open a streaming chat (SSE — events print as they arrive)
curl -N -X POST http://localhost:8080/api/chat/stream \
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
- **Using a gateway?** Setting `OPENAI_BASE_URL` alone is not enough — `OPENAI_API_KEY` must also be set (to your gateway's virtual key, or any non-empty dummy value if the gateway is unauthenticated). Provider availability is gated on the key alone

### Gateway returns 404 or 405
- The error names the exact URL called and the env var to fix. Compare that URL against what your gateway serves: kguardian appends the request path to your base URL verbatim and never adds or strips `/v1`
- If the gateway serves `/v1/chat/completions`, `OPENAI_BASE_URL` must end in `/v1`. LiteLLM accepts both forms, so a value that works there can 404 against vLLM or a proxy that exposes only the `/v1` form
- An invalid or scheme-less base URL fails before any request is sent, with a message naming the variable

### MCP client can't connect
- `curl -s localhost:8080/health` — `mcp` must be `true`. If it is `false`, `MCP_ENABLED` is unset (or set to something other than `true`/`1`) and `/mcp` 404s
- A `401` means `MCP_AUTH_TOKEN` is set and the client is not sending a matching `Authorization: Bearer <token>`
- A `406` means the request is missing `Content-Type: application/json` or `Accept: application/json, text/event-stream` — both are required
- A `405` on `GET`/`DELETE` is expected and not a fault; only `POST` is served
- The startup log states the posture outright: `MCP endpoint: enabled at /mcp (auth: …, rate limit: …/min)` or `MCP endpoint: disabled (set MCP_ENABLED=true to serve tools at /mcp)`

### Tools not working / LLM can't access data
- Verify `BROKER_URL` is correct and reachable from the llm-bridge pod
- Ensure the Broker is running: `kubectl get pods -n kguardian | grep broker`
- Check the Broker logs: `kubectl logs -n kguardian deployment/kguardian-broker`
- Verify network policies allow llm-bridge → broker communication
- Check the llm-bridge logs for `tool <name> failed` entries — each failing tool call is logged with the underlying error

### LLM API errors
- Verify API keys are valid and have credits
- Check LLM provider status pages
- Review error details in response

## Security

- API keys are stored as Kubernetes Secrets and never exposed to the frontend
- Service runs as non-root user
- CORS restricted via `ALLOWED_ORIGIN`
- The MCP endpoint is off by default. Enabled, it serves cluster telemetry — pod traffic, syscalls, audit verdicts — to any caller that reaches it, with no LLM in the path and no per-tool authorization. A workload inside the cluster can already read that data from the Broker, whose auth is off by default, so `/mcp` does not newly expose it in-cluster. What it adds is a path out of the cluster, since it is built to be consumed from a workstation over `kubectl port-forward`. Set `MCP_AUTH_TOKEN`, or front the Service with a default-deny NetworkPolicy or a mesh with mTLS

## License

BUSL-1.1 - See LICENSE file
