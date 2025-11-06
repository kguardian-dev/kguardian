import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import { ZodError } from "zod";
import { ChatRequestSchema, LLMProvider, type ErrorResponse } from "./types/index.js";
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
app.use(cors());
app.use(express.json());

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
    brokerUrl,
    availableProviders,
    hasProvider: availableProviders.length > 0,
  });
});

// Chat endpoint
app.post("/api/chat", async (req: Request, res: Response<any>) => {
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

    console.log(`Processing chat request with provider: ${provider}`);

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
    console.error("Error processing chat request:", error);

    if (error instanceof ZodError) {
      return res.status(400).json({
        error: "Invalid request format",
        details: error.errors.map((e) => e.message).join(", "),
      } as ErrorResponse);
    }

    if (error instanceof Error) {
      return res.status(500).json({
        error: error.message,
        details: error.stack,
      } as ErrorResponse);
    }

    res.status(500).json({
      error: "An unexpected error occurred",
    } as ErrorResponse);
  }
});

// Start server
app.listen(port, () => {
  const availableProviders = getAvailableProviders();
  console.log(`LLM Bridge listening on port ${port}`);
  console.log(`Broker URL: ${brokerUrl}`);
  console.log(`Available providers: ${availableProviders.join(", ") || "NONE"}`);

  if (availableProviders.length === 0) {
    console.warn("WARNING: No LLM provider API keys configured!");
    console.warn("Set at least one: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GITHUB_TOKEN");
  }
});
