import express, { Request, Response } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { ZodError } from "zod";
import { ChatRequestSchema, LLMProvider, type ErrorResponse } from "./types/index.js";
import { BrokerClient } from "./brokerClient.js";
import { log } from "./logger.js";
import { callOpenAI } from "./providers/openai.js";
import { callAnthropic } from "./providers/anthropic.js";
import { callGemini } from "./providers/gemini.js";
import { callCopilot } from "./providers/copilot.js";

// Load environment variables
dotenv.config();

const app = express();
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
    const availableProviders = getAvailableProviders();

    if (availableProviders.length === 0) {
      return res.status(503).json({
        error: "No LLM provider configured",
        details: "Please configure at least one API key: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GITHUB_TOKEN",
      } as ErrorResponse);
    }

    const provider = chatRequest.provider || availableProviders[0];

    // Verify the requested provider is available
    if (!availableProviders.includes(provider)) {
      return res.status(400).json({
        error: `Provider ${provider} not configured`,
        details: `Available providers: ${availableProviders.join(", ")}`,
      } as ErrorResponse);
    }

    // Debug not info — this fires per chat request; a chat session
    // can produce dozens. The provider routing is part of normal
    // operation, not a per-request operator alert.
    log.debug(`Processing chat request with provider: ${provider}`);

    // Route to appropriate provider
    let response;
    switch (provider) {
      case LLMProvider.OPENAI:
        response = await callOpenAI(chatRequest, brokerClient);
        break;
      case LLMProvider.ANTHROPIC:
        response = await callAnthropic(chatRequest, brokerClient);
        break;
      case LLMProvider.GEMINI:
        response = await callGemini(chatRequest, brokerClient);
        break;
      case LLMProvider.COPILOT:
        response = await callCopilot(chatRequest, brokerClient);
        break;
      default:
        return res.status(400).json({
          error: `Unknown provider: ${provider}`,
        } as ErrorResponse);
    }

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

// Start server
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
