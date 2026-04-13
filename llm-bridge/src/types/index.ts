import { z } from "zod";

// LLM Provider types
export enum LLMProvider {
  OPENAI = "openai",
  ANTHROPIC = "anthropic",
  GEMINI = "gemini",
  COPILOT = "copilot",
}

// Message history
export const MessageSchema = z.object({
  role: z.enum(['user', 'assistant', 'system']),
  content: z.string().max(50000),
});

export type Message = z.infer<typeof MessageSchema>;

// Request/Response schemas
export const ChatRequestSchema = z.object({
  message: z.string().min(1).max(50000),
  provider: z.nativeEnum(LLMProvider).optional(),
  model: z.string().optional(),
  conversationId: z.string().optional(),
  context: z.string().max(2000).optional(),
  history: z.array(MessageSchema).max(100).optional(),
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

/** JSON-serialisable scalar values */
export type JsonScalar = string | number | boolean | null;

/** Recursive JSON value type */
export type JsonValue =
  | JsonScalar
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface ToolCall {
  name: string;
  arguments: Record<string, JsonValue>;
}

export interface ToolResult {
  data: JsonValue | object;
  error?: string;
}

/** JSON Schema object describing tool parameters */
export interface JsonSchemaObject {
  type: "object";
  properties: Record<string, { type: string; description?: string }>;
  required: string[];
}

/** Tool definition used when building provider request payloads */
export interface ToolDefinition {
  name: string;
  description: string;
  parameters: JsonSchemaObject;
}
