import { z } from "zod";

// LLM Provider types
export enum LLMProvider {
  OPENAI = "openai",
  ANTHROPIC = "anthropic",
  GEMINI = "gemini",
  COPILOT = "copilot",
}

// Request/Response schemas
export const ChatRequestSchema = z.object({
  message: z.string().min(1),
  provider: z.nativeEnum(LLMProvider).optional(),
  model: z.string().optional(),
  conversationId: z.string().optional(),
  systemPrompt: z.string().optional(),
});

export type ChatRequest = z.infer<typeof ChatRequestSchema>;

export interface ChatResponse {
  message: string;
  provider: LLMProvider;
  model: string;
  conversationId?: string;
}

export interface ErrorResponse {
  error: string;
  details?: string;
}

// Broker API tool definitions
export interface ToolCall {
  name: string;
  arguments: Record<string, any>;
}

export interface ToolResult {
  data: any;
  error?: string;
}
