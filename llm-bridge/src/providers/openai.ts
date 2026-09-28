import axios, { type AxiosResponse } from "axios";
import type { Readable } from "node:stream";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { McpClient } from "../mcpClient.js";
import { log } from "../logger.js";
import { serializeToolResult } from "./truncate.js";
import { resolveBaseUrl, endpointHint } from "./baseUrl.js";
import type { Emit, ProviderError } from "./events.js";
import { parseSse, withIdleTimeout } from "./sse.js";

interface OpenAIToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

interface OpenAIMessage {
  role: string;
  content: string | null;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
  name?: string;
}

interface OpenAITool {
  type: string;
  function: {
    name: string;
    description: string;
    parameters: any;
  };
}

const MAX_TOOL_ROUNDS = 10;

const REQUEST_TIMEOUT_MS = 120000;

// Streams are bounded per gap, not per response: a model may take minutes to
// answer, but a gateway that sends nothing at all for this long is gone.
const STREAM_IDLE_TIMEOUT_MS = 120000;

// The request path both providers speak. Appended to the configured base URL
// verbatim — see baseUrl.ts for why kguardian never adjusts the /v1 segment.
const CHAT_COMPLETIONS_PATH = "/chat/completions";

// OpenAI and GitHub Copilot speak the identical /chat/completions wire
// protocol — same request body, tool-call shape, and response envelope. They
// differ only in endpoint, credential, and default model, so one
// implementation serves both; a per-provider config is the only variance.
// That variance is now operator-supplied as well: pointing OPENAI_BASE_URL at
// a self-hosted gateway makes a third "provider" out of the same code.
interface OpenAICompatConfig {
  provider: LLMProvider;
  label: string;
  endpoint: string;
  baseUrlName: string;
  apiKey: string | undefined;
  keyName: string;
  defaultModel: string;
}

// Note the asymmetry in the two default bases: OpenAI's version segment lives
// in the base (`/v1`) because that is the base OpenAI itself documents and
// what every OpenAI-compatible gateway expects operators to copy, whereas
// Copilot serves /chat/completions straight off the host. Both are just "the
// part before the request path", so the same append rule covers them.
const PROVIDERS: Record<"openai" | "copilot", () => OpenAICompatConfig> = {
  openai: () => ({
    provider: LLMProvider.OPENAI,
    label: "OpenAI",
    endpoint: resolveBaseUrl("OPENAI_BASE_URL", "https://api.openai.com/v1") + CHAT_COMPLETIONS_PATH,
    baseUrlName: "OPENAI_BASE_URL",
    // Trim before empty-check; whitespace-only counts as not-configured.
    // See anthropic.ts for the disable-by-whitespace rationale.
    apiKey: process.env.OPENAI_API_KEY?.trim(),
    keyName: "OPENAI_API_KEY",
    // "gpt-4o" is meaningless to a gateway routing to a local model, so the
    // default is overridable too. request.model still wins over both.
    defaultModel: process.env.OPENAI_MODEL?.trim() || "gpt-4o",
  }),
  copilot: () => ({
    provider: LLMProvider.COPILOT,
    label: "Copilot",
    endpoint:
      resolveBaseUrl("COPILOT_BASE_URL", "https://api.githubcopilot.com") + CHAT_COMPLETIONS_PATH,
    baseUrlName: "COPILOT_BASE_URL",
    apiKey: process.env.GITHUB_TOKEN?.trim(),
    keyName: "GITHUB_TOKEN",
    defaultModel: process.env.COPILOT_MODEL?.trim() || "gpt-4o",
  }),
};

/**
 * Build the provider-labelled error, appending the base-URL hint when the
 * status says the path itself was wrong. Every failure in this file goes
 * through here so a misconfigured gateway is reported the same way wherever
 * it lands, and the upstream status rides along for the transport to map.
 */
function providerError(
  cfg: OpenAICompatConfig,
  detail: string,
  status?: number,
  cause?: unknown,
): ProviderError {
  const hint = endpointHint(cfg.baseUrlName, cfg.endpoint, status);
  log.error(`${cfg.label} API Error:`, `${detail}${hint}`);
  const error: ProviderError = new Error(`${cfg.label} API error: ${detail}${hint}`, { cause });
  if (status !== undefined) error.status = status;
  return error;
}

/** Normalise an axios failure (HTTP error response or transport error). */
function toProviderError(cfg: OpenAICompatConfig, error: any): ProviderError {
  const detail = error.response?.data?.error?.message || error.message;
  return providerError(cfg, detail, error.response?.status, error);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// Error objects arrive as `{ message, code }` from OpenAI-compatible gateways,
// with `code` sometimes the upstream HTTP status (OpenRouter) and sometimes a
// string (OpenAI). Only a numeric code is meaningful as a status.
function upstreamErrorText(error: any): string {
  if (typeof error === "string") return error;
  if (typeof error?.message === "string" && error.message) return error.message;
  return JSON.stringify(error);
}

function upstreamErrorStatus(error: any): number | undefined {
  if (typeof error?.code === "number") return error.code;
  if (typeof error?.status === "number") return error.status;
  return undefined;
}

interface PreparedTurn {
  cfg: OpenAICompatConfig;
  model: string;
  messages: OpenAIMessage[];
  tools: OpenAITool[];
  headers: Record<string, string>;
}

async function prepareTurn(
  request: ChatRequest,
  makeConfig: () => OpenAICompatConfig,
): Promise<PreparedTurn> {
  // Built inside the async body on purpose: resolving the base URL can throw
  // on a malformed value, and the callers below are plain (non-async)
  // functions, so building the config in them would throw synchronously past
  // the promise the callers of `callOpenAI` are awaiting.
  const cfg = makeConfig();

  if (!cfg.apiKey) {
    throw new Error(`${cfg.keyName} not configured`);
  }

  const model = request.model || cfg.defaultModel;
  const context = McpClient.parseContext(request.context);
  const systemPrompt = McpClient.getSystemPrompt(context);

  const messages: OpenAIMessage[] = [{ role: "system", content: systemPrompt }];
  if (request.history && request.history.length > 0) {
    messages.push(...request.history.map((msg) => ({ role: msg.role, content: msg.content })));
  }
  messages.push({ role: "user", content: request.message });

  const toolDefs = await McpClient.getToolsCached();
  const tools: OpenAITool[] = toolDefs.map((tool) => ({
    type: "function",
    function: { name: tool.name, description: tool.description, parameters: tool.parameters },
  }));

  const headers = {
    Authorization: `Bearer ${cfg.apiKey}`,
    "Content-Type": "application/json",
  };

  return { cfg, model, messages, tools, headers };
}

/**
 * Execute the model's tool calls and append the assistant turn plus one
 * `tool` message per call, in the order the model issued them. When `emit`
 * is supplied, surfaces tool_use/tool_result activity events.
 */
async function runToolRound(
  assistant: OpenAIMessage,
  mcpClient: McpClient,
  messages: OpenAIMessage[],
  emit?: Emit,
): Promise<void> {
  messages.push(assistant);
  const toolCalls = assistant.tool_calls ?? [];

  if (emit) {
    for (const call of toolCalls) {
      emit({ type: "tool_use", name: call.function.name, id: call.id });
    }
  }

  const toolResults = await Promise.all(
    toolCalls.map(async (call): Promise<OpenAIMessage> => {
      const name = call.function.name;
      const reply = (content: string): OpenAIMessage => ({ tool_call_id: call.id, role: "tool", name, content });
      let parsedArgs: Record<string, any>;
      try {
        // Some models send "" rather than "{}" for a tool that takes nothing.
        parsedArgs = JSON.parse(call.function.arguments || "{}");
      } catch {
        emit?.({ type: "tool_result", name, ok: false });
        return reply("Failed to parse tool arguments");
      }
      const result = await mcpClient.executeTool({ name, arguments: parsedArgs });
      emit?.({ type: "tool_result", name, ok: !result.error });
      return reply(serializeToolResult(result));
    }),
  );
  messages.push(...toolResults);
}

// Non-streaming entry point.
async function callOpenAICompatible(
  request: ChatRequest,
  mcpClient: McpClient,
  makeConfig: () => OpenAICompatConfig,
): Promise<ChatResponse> {
  const { cfg, model, messages, tools, headers } = await prepareTurn(request, makeConfig);

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let response;
    try {
      response = await axios.post(
        cfg.endpoint,
        { model, messages, tools, tool_choice: "auto" },
        { headers, timeout: REQUEST_TIMEOUT_MS },
      );
    } catch (error: any) {
      throw toProviderError(cfg, error);
    }

    const message = response.data.choices[0].message;

    // No tool calls — return final text response.
    if (!message.tool_calls || message.tool_calls.length === 0) {
      return { message: message.content, provider: cfg.provider, model: response.data.model };
    }

    await runToolRound(
      { role: message.role, content: message.content || null, tool_calls: message.tool_calls },
      mcpClient,
      messages,
    );
  }

  // Max rounds reached — one final tool-less request for a summary.
  let finalResponse;
  try {
    finalResponse = await axios.post(cfg.endpoint, { model, messages }, { headers, timeout: REQUEST_TIMEOUT_MS });
  } catch (error: any) {
    throw toProviderError(cfg, error);
  }
  return { message: finalResponse.data.choices[0].message.content, provider: cfg.provider, model: finalResponse.data.model };
}

export function callOpenAI(request: ChatRequest, mcpClient: McpClient): Promise<ChatResponse> {
  return callOpenAICompatible(request, mcpClient, PROVIDERS.openai);
}

// GitHub Copilot uses the OpenAI-compatible chat/completions API.
export function callCopilot(request: ChatRequest, mcpClient: McpClient): Promise<ChatResponse> {
  return callOpenAICompatible(request, mcpClient, PROVIDERS.copilot);
}

// Streaming entry point (used by the SSE /api/chat/stream endpoint).

/** One model turn as assembled from a stream (or from a whole JSON body). */
interface StreamedMessage {
  content: string;
  toolCalls: OpenAIToolCall[];
  finishReason: string | null;
  model?: string;
}

/**
 * Human-readable stand-in when a turn carries no usable text, mirroring the
 * Anthropic path: `length` means the answer was cut off, `content_filter`
 * that the model declined, and anything else that nothing came back.
 */
function fallbackFor(cfg: OpenAICompatConfig, finishReason: string | null): string {
  switch (finishReason) {
    case "length":
      return "The response was cut off because it hit the length limit. Please narrow the question or ask for a shorter answer.";
    case "content_filter":
      return "I can't help with that request.";
    default:
      return `No response from ${cfg.label}`;
  }
}

/**
 * Stream a chat turn over `stream: true` chat completions, emitting text (and
 * reasoning, when the gateway exposes it) as it is generated and tool
 * activity as each round runs. `signal` aborts the in-flight request on
 * client disconnect; an abort ends the turn quietly rather than as an error.
 */
async function streamOpenAICompatible(
  request: ChatRequest,
  mcpClient: McpClient,
  makeConfig: () => OpenAICompatConfig,
  emit: Emit,
  signal?: AbortSignal,
): Promise<void> {
  const { cfg, model, messages, tools, headers } = await prepareTurn(request, makeConfig);

  const runStream = async (withTools: boolean): Promise<StreamedMessage> => {
    let response: AxiosResponse<Readable>;
    try {
      response = await axios.post(
        cfg.endpoint,
        { model, messages, ...(withTools ? { tools, tool_choice: "auto" } : {}), stream: true },
        {
          headers,
          timeout: REQUEST_TIMEOUT_MS,
          responseType: "stream",
          // Error statuses are read below so the upstream message survives.
          validateStatus: () => true,
          signal,
        },
      );
    } catch (error: any) {
      if (signal?.aborted) throw error;
      throw toProviderError(cfg, error);
    }
    return readStreamedMessage(cfg, response, emit, signal);
  };

  const finish = (message: StreamedMessage): void => {
    // Text that was produced already streamed; only a silent turn needs the
    // explanatory fallback so the user never gets a blank answer.
    if (!message.content.trim()) {
      emit({ type: "text", delta: fallbackFor(cfg, message.finishReason) });
    }
    emit({ type: "done", model: message.model || model });
  };

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    // Client disconnected between rounds — stop before doing (or paying for)
    // more model/tool work.
    if (signal?.aborted) return;

    let message: StreamedMessage;
    try {
      message = await runStream(true);
    } catch (error) {
      if (signal?.aborted) return;
      throw error;
    }
    if (signal?.aborted) return;

    if (message.toolCalls.length === 0) {
      finish(message);
      return;
    }
    await runToolRound(
      { role: "assistant", content: message.content || null, tool_calls: message.toolCalls },
      mcpClient,
      messages,
      emit,
    );
  }

  // Max rounds reached — final pass without tools.
  if (signal?.aborted) return;
  let finalMessage: StreamedMessage;
  try {
    finalMessage = await runStream(false);
  } catch (error) {
    if (signal?.aborted) return;
    throw error;
  }
  if (signal?.aborted) return;
  finish(finalMessage);
}

/**
 * Consume one chat-completions response. An error status is read in full so
 * the gateway's own message is reported; a JSON body (a gateway that ignored
 * `stream: true`) is accepted as a whole turn; otherwise the SSE deltas are
 * emitted as they arrive and the tool calls assembled from their fragments.
 */
async function readStreamedMessage(
  cfg: OpenAICompatConfig,
  response: AxiosResponse<Readable>,
  emit: Emit,
  signal?: AbortSignal,
): Promise<StreamedMessage> {
  const body = response.data;
  const onAbort = (): void => {
    body.destroy();
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    if (response.status >= 400) {
      const raw = await readAll(cfg, body, signal);
      let detail = `Request failed with status code ${response.status}`;
      try {
        const parsed = JSON.parse(raw);
        if (parsed?.error) detail = upstreamErrorText(parsed.error);
      } catch {
        // Not JSON; keep the status line.
      }
      throw providerError(cfg, detail, response.status);
    }

    const contentType = String(response.headers["content-type"] ?? "");
    if (!contentType.includes("text/event-stream")) {
      return fromCompleteResponse(cfg, await readAll(cfg, body, signal), contentType, emit);
    }
    return await fromEventStream(cfg, body, emit, signal);
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}

async function readAll(cfg: OpenAICompatConfig, body: Readable, signal?: AbortSignal): Promise<string> {
  const decoder = new TextDecoder("utf-8");
  let out = "";
  try {
    for await (const chunk of withIdleTimeout(body, STREAM_IDLE_TIMEOUT_MS)) {
      out += decoder.decode(chunk as Uint8Array, { stream: true });
    }
  } catch (error) {
    // A client abort destroyed the body; the caller ends the turn quietly.
    if (signal?.aborted) throw error;
    throw providerError(cfg, `response ended unexpectedly (${errorText(error)})`, undefined, error);
  }
  return out + decoder.decode();
}

function fromCompleteResponse(
  cfg: OpenAICompatConfig,
  raw: string,
  contentType: string,
  emit: Emit,
): StreamedMessage {
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw providerError(
      cfg,
      `expected an event stream or JSON from ${cfg.endpoint} but got ${contentType || "an untyped body"}`,
    );
  }
  if (parsed?.error) {
    throw providerError(cfg, upstreamErrorText(parsed.error), upstreamErrorStatus(parsed.error));
  }
  const choice = parsed?.choices?.[0] ?? {};
  const message = choice.message ?? {};
  const content = typeof message.content === "string" ? message.content : "";
  if (content) emit({ type: "text", delta: content });
  const toolCalls: OpenAIToolCall[] = Array.isArray(message.tool_calls)
    ? message.tool_calls.map((call: any, i: number) => ({
        id: typeof call?.id === "string" && call.id ? call.id : `call_${i}`,
        type: "function" as const,
        function: {
          name: String(call?.function?.name ?? ""),
          arguments: argumentsText(call?.function?.arguments),
        },
      }))
    : [];
  return { content, toolCalls, finishReason: choice.finish_reason ?? null, model: parsed?.model };
}

async function fromEventStream(
  cfg: OpenAICompatConfig,
  body: Readable,
  emit: Emit,
  signal?: AbortSignal,
): Promise<StreamedMessage> {
  const calls = new Map<number, OpenAIToolCall>();
  let content = "";
  let finishReason: string | null = null;
  let model: string | undefined;

  const payloads = parseSse(withIdleTimeout(body, STREAM_IDLE_TIMEOUT_MS))[Symbol.asyncIterator]();
  try {
    for (;;) {
      // Payloads already buffered from the last chunk must not outlive an abort.
      if (signal?.aborted) throw signal.reason;
      let next: IteratorResult<string>;
      try {
        next = await payloads.next();
      } catch (error) {
        if (signal?.aborted) throw error;
        throw providerError(cfg, `stream ended unexpectedly (${errorText(error)})`, undefined, error);
      }
      if (next.done) break;
      const data = next.value;
      if (data.trim() === "[DONE]") break;

      let chunk: any;
      try {
        chunk = JSON.parse(data);
      } catch {
        throw providerError(cfg, `malformed stream chunk: ${data.slice(0, 200)}`);
      }
      // Gateways report a mid-stream failure as an error frame instead of an
      // HTTP status; surface it rather than ending with a half answer.
      if (chunk?.error) {
        throw providerError(cfg, upstreamErrorText(chunk.error), upstreamErrorStatus(chunk.error));
      }
      if (typeof chunk?.model === "string" && chunk.model) model = chunk.model;

      const choice = chunk?.choices?.[0];
      if (!choice) continue;
      const delta = choice.delta ?? {};

      const reasoning = delta.reasoning_content ?? delta.reasoning;
      if (typeof reasoning === "string" && reasoning) {
        emit({ type: "thinking", delta: reasoning });
      }
      if (typeof delta.content === "string" && delta.content) {
        content += delta.content;
        emit({ type: "text", delta: delta.content });
      }
      if (Array.isArray(delta.tool_calls)) {
        mergeToolCallDeltas(calls, delta.tool_calls);
      }
      if (typeof choice.finish_reason === "string" && choice.finish_reason) {
        finishReason = choice.finish_reason;
      }
    }
  } finally {
    // Whether the turn ended at [DONE], on an error frame or on an abort,
    // closing the iterator chain destroys the body and releases the socket;
    // a gateway that keeps the connection open would otherwise leak it.
    await payloads.return(undefined).catch(() => undefined);
  }

  if (finishReason === "error") {
    throw providerError(cfg, "the model stopped with an error");
  }

  const toolCalls = [...calls.entries()]
    .sort(([a], [b]) => a - b)
    .map(([slot, call]) => ({ ...call, id: call.id || `call_${slot}` }));
  return { content, toolCalls, finishReason, model };
}

/**
 * Fold one chunk's `tool_calls` deltas into the calls assembled so far. The
 * id and name arrive once (some gateways repeat them, so assign rather than
 * append) while the JSON arguments arrive in fragments that concatenate.
 */
function mergeToolCallDeltas(calls: Map<number, OpenAIToolCall>, deltas: any[]): void {
  deltas.forEach((delta, position) => {
    const slot = slotFor(calls, delta, position);
    let call = calls.get(slot);
    if (!call) {
      call = { id: "", type: "function", function: { name: "", arguments: "" } };
      calls.set(slot, call);
    }
    if (typeof delta?.id === "string" && delta.id) call.id = delta.id;
    if (typeof delta?.function?.name === "string" && delta.function.name) call.function.name = delta.function.name;
    if (delta?.function?.arguments !== undefined && delta.function.arguments !== null) {
      call.function.arguments += argumentsText(delta.function.arguments);
    }
  });
}

// Fragments of one call share an `index`. Gateways that omit it send a whole
// call per chunk, so fall back to matching the id, then to the position.
function slotFor(calls: Map<number, OpenAIToolCall>, delta: any, position: number): number {
  if (typeof delta?.index === "number") return delta.index;
  if (typeof delta?.id === "string" && delta.id) {
    for (const [slot, call] of calls) {
      if (call.id === delta.id) return slot;
    }
    return calls.size === 0 ? 0 : Math.max(...calls.keys()) + 1;
  }
  return position;
}

// Arguments are a JSON string on the wire; a gateway that pre-parses them is
// folded back so the tool round can parse uniformly.
function argumentsText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  return JSON.stringify(value);
}

export function streamOpenAI(
  request: ChatRequest,
  mcpClient: McpClient,
  emit: Emit,
  signal?: AbortSignal,
): Promise<void> {
  return streamOpenAICompatible(request, mcpClient, PROVIDERS.openai, emit, signal);
}

export function streamCopilot(
  request: ChatRequest,
  mcpClient: McpClient,
  emit: Emit,
  signal?: AbortSignal,
): Promise<void> {
  return streamOpenAICompatible(request, mcpClient, PROVIDERS.copilot, emit, signal);
}
