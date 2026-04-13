import express, { Request, Response } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { ZodError, ZodIssue } from "zod";
import { ChatRequestSchema, LLMProvider, type ChatResponse, type ErrorResponse } from "./types/index.js";
import { BrokerClient } from "./brokerClient.js";
import { callOpenAI } from "./providers/openai.js";
import { callAnthropic } from "./providers/anthropic.js";
import { callGemini } from "./providers/gemini.js";
import { callCopilot } from "./providers/copilot.js";

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 8080;
const brokerUrl =
  process.env.BROKER_URL || "http://broker.kguardian.svc.cluster.local:9090";

// Middleware
// P1-1: Default to localhost instead of wildcard to avoid open CORS
const allowedOrigin = process.env.ALLOWED_ORIGIN;
if (!allowedOrigin) {
  console.warn('WARNING: ALLOWED_ORIGIN not set, defaulting to http://localhost:3000');
}
app.use(cors({ origin: allowedOrigin || 'http://localhost:3000' }));
app.use(express.json({ limit: '100kb' }));

// Initialize broker client
const brokerClient = new BrokerClient(brokerUrl);

// Determine available providers
function getAvailableProviders(): LLMProvider[] {
  const providers: LLMProvider[] = [];
  if (process.env.OPENAI_API_KEY) providers.push(LLMProvider.OPENAI);
  if (process.env.ANTHROPIC_API_KEY) providers.push(LLMProvider.ANTHROPIC);
  if (process.env.GOOGLE_API_KEY) providers.push(LLMProvider.GEMINI);
  if (process.env.GITHUB_TOKEN) providers.push(LLMProvider.COPILOT);
  return providers;
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
const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX || '60', 10);
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
});

// Chat endpoint
app.post("/api/chat", chatLimiter, async (req: Request, res: Response<ChatResponse | ErrorResponse>) => {
  try {
    // Validate request
    const chatRequest = ChatRequestSchema.parse(req.body);

    // Determine provider to use
    const availableProviders = getAvailableProviders();

    // P1-2: Return generic error — do not reveal which providers are configured
    if (availableProviders.length === 0) {
      return res.status(503).json({
        error: "No LLM provider available",
      } as ErrorResponse);
    }

    const provider = chatRequest.provider || availableProviders[0];

    // P1-2: Return generic error — do not reveal which providers are available
    if (!availableProviders.includes(provider)) {
      return res.status(503).json({
        error: "No LLM provider available",
      } as ErrorResponse);
    }

    if (process.env.DEBUG) {
      console.log(`Processing chat request with provider: ${provider}`);
    }

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
        return res.status(503).json({
          error: "No LLM provider available",
        } as ErrorResponse);
    }

    res.json(response);
  } catch (error) {
    console.error("Error processing chat request:", error);

    if (error instanceof ZodError) {
      return res.status(400).json({
        error: "Invalid request format",
        details: error.issues.map((e: ZodIssue) => e.message).join(", "),
      } as ErrorResponse);
    }

    if (error instanceof Error) {
      console.error("Chat error details:", error.message, error.stack);
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
  console.log(`LLM Bridge listening on port ${port}`);
  console.log(`Broker URL: ${brokerUrl}`);

  // P1-2: Guard provider availability details behind DEBUG flag
  if (process.env.DEBUG) {
    const availableProviders = getAvailableProviders();
    console.log(`Available providers: ${availableProviders.join(", ") || "NONE"}`);
  }

  if (getAvailableProviders().length === 0) {
    console.warn("WARNING: No LLM provider API keys configured!");
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
