import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import express, { Request, Response } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { ZodError } from "zod";
import { ChatRequestSchema, LLMProvider, type ErrorResponse } from "./types/index.js";
import { McpClient } from "./mcpClient.js";
import { log } from "./logger.js";
import { callOpenAI, callCopilot } from "./providers/openai.js";
import { callAnthropic, streamAnthropic, type StreamEvent } from "./providers/anthropic.js";
import { callGemini } from "./providers/gemini.js";
import { MCP_PATH, mcpConfigFromEnv } from "./mcp/config.js";
import { createMcpRouter } from "./mcp/router.js";
import type { ChatRequest, ChatResponse } from "./types/index.js";

// Load environment variables
dotenv.config();

// Exported for integration tests (the main-module guard prevents the server
// from auto-starting on import).
export const app = express();
// Trim env reads so a pasted "8080\n" or "  8080" doesn't propagate
// downstream. Node's listen() is lenient about whitespace via
// parseInt, but `cors({ origin })` compares the env value to the
// request Origin header verbatim — a whitespace-padded env value
// silently breaks the CORS check (no header ever matches " https://
// example.com "). Same defensive-trim pattern from the controller /
// evaluator / mcp-server env reads.
const port = (process.env.PORT?.trim() || "8080");
const allowedOrigin = process.env.ALLOWED_ORIGIN?.trim() || '*';
const mcpConfig = mcpConfigFromEnv(process.env);

// Middleware. `cors()` is deliberately first: with the default
// `allowedHeaders` unset it reflects the browser's
// Access-Control-Request-Headers back, which is what lets a browser-based
// MCP client send `mcp-protocol-version` (and `authorization`) without the
// preflight being rejected. Setting ALLOWED_ORIGIN to the UI's origin locks
// that down and would block MCP clients from any other origin — the endpoint
// is intended for non-browser clients reached over port-forward, so that is
// the right default, but it is a real constraint to document.
app.use(cors({ origin: allowedOrigin }));
app.use(express.json({ limit: '100kb' }));

// Initialize the in-process assistant. Note: the class is named "McpClient"
// for historical reasons; it no longer talks to a separate MCP server —
// all 12 tools execute in-process (src/tools/*), reaching the broker
// directly. No constructor arg needed.
const mcpClient = new McpClient();

/**
 * Compute available providers from a key-value env map. Pure — takes
 * the env in as a parameter so it's unit-testable without touching
 * process.env. The exported `availableProvidersFromEnv` form lets
 * tests pass arbitrary maps; the internal `getAvailableProviders`
 * binds it to the live process env.
 *
 * Whitespace-only values count as MISSING. The native `if (env.X)`
 * check treated `"  "` as truthy, so an operator setting
 * ANTHROPIC_API_KEY="  " to "disable" the provider got /health
 * reporting it as available, requests routing to it, and then a
 * 401 from the Anthropic API at runtime. Trimming pre-check makes
 * the disable-by-whitespace pattern Just Work.
 */
export function availableProvidersFromEnv(
  env: Record<string, string | undefined>,
): LLMProvider[] {
  const providers: LLMProvider[] = [];
  if (env.OPENAI_API_KEY?.trim()) providers.push(LLMProvider.OPENAI);
  if (env.ANTHROPIC_API_KEY?.trim()) providers.push(LLMProvider.ANTHROPIC);
  if (env.GOOGLE_API_KEY?.trim()) providers.push(LLMProvider.GEMINI);
  if (env.GITHUB_TOKEN?.trim()) providers.push(LLMProvider.COPILOT);
  return providers;
}

function getAvailableProviders(): LLMProvider[] {
  return availableProvidersFromEnv(process.env);
}

// Provider resolution shared by the JSON and SSE chat routes. Returns either
// the resolved provider or a ready-to-send error (status + body) so both
// routes apply identical "no provider" / "provider not configured" handling.
type ProviderResolution =
  | { ok: true; provider: LLMProvider }
  | { ok: false; status: number; body: ErrorResponse };

function resolveProvider(chatRequest: ChatRequest): ProviderResolution {
  const availableProviders = getAvailableProviders();
  if (availableProviders.length === 0) {
    return {
      ok: false,
      status: 503,
      body: {
        error: "No LLM provider configured",
        details:
          "Please configure at least one API key: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GITHUB_TOKEN",
      },
    };
  }
  const provider = chatRequest.provider || availableProviders[0];
  if (!availableProviders.includes(provider)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: `Provider ${provider} not configured`,
        details: `Available providers: ${availableProviders.join(", ")}`,
      },
    };
  }
  return { ok: true, provider };
}

// Non-streaming dispatch to a provider. Used by the JSON route directly and by
// the SSE route for providers that don't have a native streaming path yet.
function callProvider(provider: LLMProvider, chatRequest: ChatRequest): Promise<ChatResponse> {
  switch (provider) {
    case LLMProvider.OPENAI:
      return callOpenAI(chatRequest, mcpClient);
    case LLMProvider.ANTHROPIC:
      return callAnthropic(chatRequest, mcpClient);
    case LLMProvider.GEMINI:
      return callGemini(chatRequest, mcpClient);
    case LLMProvider.COPILOT:
      return callCopilot(chatRequest, mcpClient);
    default:
      return Promise.reject(new Error(`Unknown provider: ${provider}`));
  }
}

// Health check endpoint. `status` and `hasProvider` are load-bearing — the
// chart's liveness/readiness probes and the frontend's provider gate read
// them — so `mcp` is added alongside rather than reshaping the body.
app.get("/health", (req: Request, res: Response) => {
  const availableProviders = getAvailableProviders();
  res.json({
    status: "healthy",
    hasProvider: availableProviders.length > 0,
    mcp: mcpConfig.enabled,
  });
});

// External MCP endpoint. Mounted only when enabled, so /mcp 404s on a default
// install exactly as if the route did not exist — no "deployed but off"
// endpoint answering with a 403 and inviting probing. Placed after the JSON
// body parser (the transport is handed the already-parsed body) and before
// the chat routes, though it carries its own rate limiter and auth so the
// ordering is not load-bearing.
if (mcpConfig.enabled) {
  app.use(MCP_PATH, createMcpRouter(mcpConfig));
}

// Rate limiting for chat endpoint
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many requests' },
});

// Streaming chat endpoint (Server-Sent Events). Emits incremental `text`,
// summarized `thinking`, and `tool_use`/`tool_result` activity events, then a
// terminal `done` (or `error`). Anthropic streams natively; other providers
// run non-streaming and arrive as a single `text` chunk, so the frontend can
// use one consistent stream transport for every provider.
app.post("/api/chat/stream", chatLimiter, async (req: Request, res: Response) => {
  let chatRequest: ChatRequest;
  let provider: LLMProvider;

  // Pre-stream validation + provider resolution still use JSON errors, since
  // the SSE headers have not been written yet.
  try {
    chatRequest = ChatRequestSchema.parse(req.body);
    const resolution = resolveProvider(chatRequest);
    if (!resolution.ok) {
      return res.status(resolution.status).json(resolution.body);
    }
    provider = resolution.provider;
  } catch (error) {
    if (error instanceof ZodError) {
      return res.status(400).json({
        error: "Invalid request format",
        details: error.issues.map((e: any) => e.message).join(", "),
      } as ErrorResponse);
    }
    log.error("Error validating stream request:", error);
    return res.status(500).json({ error: "An unexpected error occurred" } as ErrorResponse);
  }

  // Open the SSE stream.
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    // Disable proxy buffering (nginx) so events flush to the client live.
    "X-Accel-Buffering": "no",
  });

  const emit = (event: StreamEvent): void => {
    res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
  };

  // Abort the in-flight model stream if the client disconnects.
  const abort = new AbortController();
  res.on("close", () => abort.abort());

  // SSE keepalive. During a tool round no events flow for the whole MCP
  // round-trip; an idle intermediary (nginx ingress default proxy-read-timeout
  // is 60s) would close the connection and break the stream. A periodic comment
  // ping keeps it alive — comments (lines starting ":") are ignored by the
  // EventSource client and don't affect the event data.
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) res.write(": ping\n\n");
  }, 15000);

  log.debug(`Processing streaming chat request with provider: ${provider}`);

  try {
    if (provider === LLMProvider.ANTHROPIC) {
      await streamAnthropic(chatRequest, mcpClient, emit, abort.signal);
    } else {
      // Providers without a native streaming path: run to completion and emit
      // the answer as a single text chunk plus the terminal done event.
      const response = await callProvider(provider, chatRequest);
      emit({ type: "text", delta: response.message });
      emit({ type: "done", model: response.model });
    }
  } catch (error) {
    // Map upstream rate-limit / overload to a clear, actionable message rather
    // than leaking a raw SDK string. A client disconnect does NOT reach here —
    // streamAnthropic returns cleanly on abort.
    const status = (error as { status?: number })?.status;
    const detail =
      status === 429
        ? "The AI provider is rate-limiting requests right now. Please retry in a few seconds."
        : status === 529 || status === 503
          ? "The AI provider is temporarily overloaded. Please retry in a few seconds."
          : error instanceof Error
            ? error.message
            : "An internal error occurred";
    log.error("Streaming chat error:", detail);
    // Headers are already sent, so surface the failure over SSE rather than
    // as an HTTP status. Guard the write in case the client already closed.
    if (!res.writableEnded) {
      emit({ type: "error", error: detail });
    }
  } finally {
    clearInterval(heartbeat);
    res.end();
  }
});

// Start server — but only when this module is the process entrypoint.
// Unit tests import `availableProvidersFromEnv` from this file; if the
// server (and its open socket handle) started on import, the test
// process would never exit and `npm test` would hang. The main-module
// guard keeps `node dist/index.js` / `tsx src/index.ts` behaviour
// identical while making the module import-safe.
function startServer() {
  const server = app.listen(port, () => {
    const availableProviders = getAvailableProviders();
    log.info(`LLM Bridge listening on port ${port}`);
    log.info(`Broker URL: ${process.env.BROKER_URL || "(default)"}`);
    log.info(`Available providers: ${availableProviders.join(", ") || "NONE"}`);
    // State the MCP posture explicitly at startup. "Is it on, and does it
    // want a token?" is the first thing an operator debugging a client
    // connection needs, and inferring it from the absence of a log line is
    // exactly the "silently deployed-but-off" failure this project has been
    // burned by before.
    if (mcpConfig.enabled) {
      log.info(
        `MCP endpoint: enabled at ${MCP_PATH} ` +
        `(auth: ${mcpConfig.authToken ? "bearer token required" : "none"}, ` +
        `rate limit: ${mcpConfig.rateLimitPerMin}/min)`,
      );
    } else {
      log.info("MCP endpoint: disabled (set MCP_ENABLED=true to serve tools at /mcp)");
    }

    if (availableProviders.length === 0) {
      log.warn("WARNING: No LLM provider API keys configured!");
      log.warn("Set at least one: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GITHUB_TOKEN");
    }
  });

  // Graceful shutdown
  const shutdown = () => {
    server.close();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

const isMain = process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  startServer();
}
