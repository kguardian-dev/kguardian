import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import express, { Request, Response } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { ZodError } from "zod";
import { ChatRequestSchema, LLMProvider, type ErrorResponse } from "./types/index.js";
import { BrokerClient } from "./brokerClient.js";
import { log } from "./logger.js";
import { callOpenAI } from "./providers/openai.js";
import { callAnthropic, streamAnthropic, type StreamEvent } from "./providers/anthropic.js";
import { callGemini } from "./providers/gemini.js";
import { callCopilot } from "./providers/copilot.js";
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

// Middleware
app.use(cors({ origin: allowedOrigin }));
app.use(express.json({ limit: '100kb' }));

// Initialize broker client. Note: the class is named "BrokerClient"
// for historical reasons; today all tool calls route through the MCP
// server. The MCP server URL is read inside BrokerClient from
// MCP_SERVER_URL or its hardcoded default — no constructor arg needed.
const brokerClient = new BrokerClient();

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
      return callOpenAI(chatRequest, brokerClient);
    case LLMProvider.ANTHROPIC:
      return callAnthropic(chatRequest, brokerClient);
    case LLMProvider.GEMINI:
      return callGemini(chatRequest, brokerClient);
    case LLMProvider.COPILOT:
      return callCopilot(chatRequest, brokerClient);
    default:
      return Promise.reject(new Error(`Unknown provider: ${provider}`));
  }
}

// Health check endpoint
app.get("/health", (req: Request, res: Response) => {
  const availableProviders = getAvailableProviders();
  res.json({
    status: "healthy",
    hasProvider: availableProviders.length > 0,
  });
});

// Rate limiting for chat endpoint
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many requests' },
});

// Chat endpoint
app.post("/api/chat", chatLimiter, async (req: Request, res: Response<any>) => {
  try {
    // Validate request
    const chatRequest = ChatRequestSchema.parse(req.body);

    // Determine provider to use
    const resolution = resolveProvider(chatRequest);
    if (!resolution.ok) {
      return res.status(resolution.status).json(resolution.body);
    }
    const provider = resolution.provider;

    // Debug not info — this fires per chat request; a chat session
    // can produce dozens. The provider routing is part of normal
    // operation, not a per-request operator alert.
    log.debug(`Processing chat request with provider: ${provider}`);

    const response = await callProvider(provider, chatRequest);
    res.json(response);
  } catch (error) {
    log.error("Error processing chat request:", error);

    if (error instanceof ZodError) {
      return res.status(400).json({
        error: "Invalid request format",
        details: error.issues.map((e: any) => e.message).join(", "),
      } as ErrorResponse);
    }

    if (error instanceof Error) {
      log.error("Chat error details:", error.message, error.stack);
      return res.status(500).json({
        error: "An internal error occurred while processing the chat request",
      } as ErrorResponse);
    }

    res.status(500).json({
      error: "An unexpected error occurred",
    } as ErrorResponse);
  }
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

  log.debug(`Processing streaming chat request with provider: ${provider}`);

  try {
    if (provider === LLMProvider.ANTHROPIC) {
      await streamAnthropic(chatRequest, brokerClient, emit, abort.signal);
    } else {
      // Providers without a native streaming path: run to completion and emit
      // the answer as a single text chunk plus the terminal done event.
      const response = await callProvider(provider, chatRequest);
      emit({ type: "text", delta: response.message });
      emit({ type: "done", model: response.model, conversationId: response.conversationId });
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : "An internal error occurred";
    log.error("Streaming chat error:", detail);
    // Headers are already sent, so surface the failure over SSE rather than
    // as an HTTP status. Guard the write in case the client already closed.
    if (!res.writableEnded) {
      emit({ type: "error", error: detail });
    }
  } finally {
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
    log.info(`MCP Server URL: ${process.env.MCP_SERVER_URL || "(default)"}`);
    log.info(`Available providers: ${availableProviders.join(", ") || "NONE"}`);

    if (availableProviders.length === 0) {
      log.warn("WARNING: No LLM provider API keys configured!");
      log.warn("Set at least one: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GITHUB_TOKEN");
    }
  });

  // Graceful shutdown
  const shutdown = () => {
    brokerClient.close();
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
