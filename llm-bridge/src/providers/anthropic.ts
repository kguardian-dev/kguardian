import Anthropic from "@anthropic-ai/sdk";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";
import { log } from "../logger.js";
import { serializeToolResult } from "./truncate.js";

// Upper bound on tool-calling round-trips before we force a final answer.
const MAX_TOOL_ROUNDS = 10;

// Default model. Bare alias (no date suffix) so it always resolves to the
// current Opus 4.8 snapshot. Callers may override via request.model.
const DEFAULT_MODEL = "claude-opus-4-8";

// Output cap for the non-streaming path. 8K leaves room for tables and policy
// snippets without risking the SDK's non-streaming timeout guard.
const MAX_TOKENS = 8192;

// Output cap for the streaming path. Streaming removes the HTTP-timeout
// concern, so we give adaptive thinking + answer generous headroom.
const STREAM_MAX_TOKENS = 16000;

// ---------------------------------------------------------------------------
// Streaming event contract (provider -> transport). Kept transport-agnostic so
// the HTTP layer decides how to serialise (SSE) and the provider stays testable.
// ---------------------------------------------------------------------------
export type StreamEvent =
  | { type: "text"; delta: string }
  | { type: "thinking"; delta: string }
  | { type: "tool_use"; name: string; id: string }
  | { type: "tool_result"; name: string; ok: boolean }
  | { type: "done"; model: string; conversationId?: string }
  | { type: "error"; error: string };

export type Emit = (event: StreamEvent) => void;

// ---------------------------------------------------------------------------
// Shared setup helpers (used by both the streaming and non-streaming entry
// points so the model, prompt-caching, tool, and message wiring stay identical).
// ---------------------------------------------------------------------------

function requireApiKey(): string {
  // Trim before the empty-check so an operator-set "  " (whitespace intended
  // to disable the provider) is treated as unset rather than sent verbatim
  // and surfacing as a 401 deep in the call chain.
  const apiKey = process.env.ANTHROPIC_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not configured");
  }
  return apiKey;
}

/**
 * System prompt as a single cacheable block. Render order is
 * tools -> system -> messages, so a cache_control breakpoint on the system
 * block caches the tool definitions AND the system prompt together. That
 * prefix is identical on every round of the tool loop (and across requests
 * sharing the same context within the cache TTL), so rounds 2..N read it from
 * cache instead of reprocessing it.
 */
function buildSystem(request: ChatRequest): Anthropic.TextBlockParam[] {
  const context = BrokerClient.parseContext(request.context);
  const systemPrompt = BrokerClient.getSystemPrompt(context);
  return [{ type: "text", text: systemPrompt, cache_control: { type: "ephemeral" } }];
}

async function buildTools(): Promise<Anthropic.Tool[]> {
  const toolDefs = await BrokerClient.getToolsCached();
  return toolDefs.map((tool) => ({
    name: tool.name,
    description: tool.description,
    input_schema: tool.parameters as Anthropic.Tool.InputSchema,
  }));
}

function buildMessages(request: ChatRequest): Anthropic.MessageParam[] {
  // Seed with prior history (system turns are folded into the top-level system
  // prompt, so they are filtered out here) plus the new user message.
  const messages: Anthropic.MessageParam[] = [];
  if (request.history && request.history.length > 0) {
    for (const msg of request.history) {
      if (msg.role === "system") continue;
      messages.push({ role: msg.role, content: msg.content });
    }
  }
  messages.push({ role: "user", content: request.message });
  return messages;
}

function toolUsesOf(message: Anthropic.Message): Anthropic.ToolUseBlock[] {
  return message.content.filter(
    (block): block is Anthropic.ToolUseBlock => block.type === "tool_use",
  );
}

/**
 * Execute the model's tool calls via the broker/MCP client and build the
 * tool_result blocks to feed back. Pushes the assistant turn (verbatim, so
 * tool_use and thinking blocks are echoed as the API requires) onto messages.
 * When `emit` is supplied, surfaces tool_use/tool_result activity events.
 */
async function runToolRound(
  message: Anthropic.Message,
  toolUses: Anthropic.ToolUseBlock[],
  brokerClient: BrokerClient,
  messages: Anthropic.MessageParam[],
  emit?: Emit,
): Promise<void> {
  messages.push({ role: "assistant", content: message.content });

  if (emit) {
    for (const toolUse of toolUses) {
      emit({ type: "tool_use", name: toolUse.name, id: toolUse.id });
    }
  }

  const toolResults: Anthropic.ToolResultBlockParam[] = await Promise.all(
    toolUses.map(async (toolUse) => {
      const result = await brokerClient.executeTool({
        name: toolUse.name,
        arguments: toolUse.input as Record<string, unknown>,
      });
      if (emit) {
        emit({ type: "tool_result", name: toolUse.name, ok: !result.error });
      }
      return {
        type: "tool_result" as const,
        tool_use_id: toolUse.id,
        content: serializeToolResult(result),
      };
    }),
  );

  messages.push({ role: "user", content: toolResults });
}

// ---------------------------------------------------------------------------
// Non-streaming entry point (used by the JSON /api/chat endpoint).
// ---------------------------------------------------------------------------

/**
 * Drive a chat turn against Claude via the official Anthropic SDK, executing
 * MCP tools in a manual agentic loop. The loop is retained (rather than the
 * SDK tool runner) because tool execution is routed through the broker/MCP
 * client and results are truncated before being fed back to the model.
 */
export async function callAnthropic(
  request: ChatRequest,
  brokerClient: BrokerClient,
): Promise<ChatResponse> {
  const apiKey = requireApiKey();
  // The SDK reads ANTHROPIC_BASE_URL from the environment when baseURL is not
  // passed, and handles retries (429/5xx/network) and timeout scaling.
  const client = new Anthropic({ apiKey });

  const model = request.model || DEFAULT_MODEL;
  const system = buildSystem(request);
  const tools = await buildTools();
  const messages = buildMessages(request);

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let message: Anthropic.Message;
    try {
      message = await client.messages.create({ model, max_tokens: MAX_TOKENS, system, messages, tools });
    } catch (error) {
      throw toCleanError(error);
    }

    const toolUses = toolUsesOf(message);
    if (toolUses.length === 0) {
      return finalize(message, request);
    }
    await runToolRound(message, toolUses, brokerClient, messages);
  }

  // Max rounds reached — one final call without tools to force a textual
  // answer (the system+messages cache prefix still applies).
  let finalMessage: Anthropic.Message;
  try {
    finalMessage = await client.messages.create({ model, max_tokens: MAX_TOKENS, system, messages });
  } catch (error) {
    throw toCleanError(error);
  }
  return finalize(finalMessage, request);
}

// ---------------------------------------------------------------------------
// Streaming entry point (used by the SSE /api/chat/stream endpoint).
// ---------------------------------------------------------------------------

/**
 * Stream a chat turn, emitting incremental text, summarized thinking, and
 * tool-activity events. Adaptive thinking is enabled (display: "summarized")
 * because streaming surfaces the think-time as live progress rather than a
 * silent pause. `signal` aborts the in-flight model stream on client disconnect.
 */
export async function streamAnthropic(
  request: ChatRequest,
  brokerClient: BrokerClient,
  emit: Emit,
  signal?: AbortSignal,
): Promise<void> {
  const apiKey = requireApiKey();
  const client = new Anthropic({ apiKey });

  const model = request.model || DEFAULT_MODEL;
  const system = buildSystem(request);
  const tools = await buildTools();
  const messages = buildMessages(request);

  const runStream = async (withTools: boolean): Promise<Anthropic.Message> => {
    const stream = client.messages.stream(
      {
        model,
        max_tokens: STREAM_MAX_TOKENS,
        system,
        messages,
        thinking: { type: "adaptive", display: "summarized" },
        ...(withTools ? { tools } : {}),
      },
      { signal },
    );

    for await (const event of stream) {
      if (event.type !== "content_block_delta") continue;
      if (event.delta.type === "text_delta") {
        emit({ type: "text", delta: event.delta.text });
      } else if (event.delta.type === "thinking_delta") {
        emit({ type: "thinking", delta: event.delta.thinking });
      }
    }
    return stream.finalMessage();
  };

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let message: Anthropic.Message;
    try {
      message = await runStream(true);
    } catch (error) {
      throw toCleanError(error);
    }

    const toolUses = toolUsesOf(message);
    if (toolUses.length === 0) {
      emit({ type: "done", model: message.model, conversationId: request.conversationId });
      return;
    }
    await runToolRound(message, toolUses, brokerClient, messages, emit);
  }

  // Max rounds reached — final pass without tools.
  let finalMessage: Anthropic.Message;
  try {
    finalMessage = await runStream(false);
  } catch (error) {
    throw toCleanError(error);
  }
  emit({ type: "done", model: finalMessage.model, conversationId: request.conversationId });
}

// ---------------------------------------------------------------------------
// Result + error helpers.
// ---------------------------------------------------------------------------

/** Extract the text answer from a completed message into the wire contract. */
function finalize(message: Anthropic.Message, request: ChatRequest): ChatResponse {
  const text = message.content
    .filter((block): block is Anthropic.TextBlock => block.type === "text")
    .map((block) => block.text)
    .join("\n")
    .trim();

  const fallback =
    message.stop_reason === "refusal"
      ? "I can't help with that request."
      : "No response from Claude";

  return {
    message: text || fallback,
    provider: LLMProvider.ANTHROPIC,
    model: message.model,
    conversationId: request.conversationId,
  };
}

/** Normalise SDK/transport errors into a single Error with a clean message. */
function toCleanError(error: unknown): Error {
  if (error instanceof Anthropic.APIError) {
    const detail = error.message || `status ${error.status}`;
    log.error("Anthropic API Error:", detail);
    return new Error(`Anthropic API error: ${detail}`, { cause: error });
  }
  const detail = error instanceof Error ? error.message : String(error);
  log.error("Anthropic request failed:", detail);
  return new Error(`Anthropic request failed: ${detail}`, { cause: error });
}
