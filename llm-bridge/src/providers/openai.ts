import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { McpClient } from "../mcpClient.js";
import { log } from "../logger.js";
import { serializeToolResult } from "./truncate.js";
import { resolveBaseUrl, endpointHint } from "./baseUrl.js";

interface OpenAIMessage {
  role: string;
  content: string | null;
  tool_calls?: any[];
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
 * Normalise a request failure into the provider-labelled error, appending the
 * base-URL hint when the status says the path itself was wrong. Shared by the
 * tool loop and the final summary request so a misconfigured gateway is
 * reported the same way wherever the failure lands.
 */
function toProviderError(cfg: OpenAICompatConfig, error: any): Error {
  const detail = error.response?.data?.error?.message || error.message;
  const hint = endpointHint(cfg.baseUrlName, cfg.endpoint, error.response?.status);
  log.error(`${cfg.label} API Error:`, `${detail}${hint}`);
  return new Error(`${cfg.label} API error: ${detail}${hint}`, { cause: error });
}

async function callOpenAICompatible(
  request: ChatRequest,
  mcpClient: McpClient,
  makeConfig: () => OpenAICompatConfig,
): Promise<ChatResponse> {
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

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let response;
    try {
      response = await axios.post(
        cfg.endpoint,
        { model, messages, tools, tool_choice: "auto" },
        { headers, timeout: 120000 },
      );
    } catch (error: any) {
      throw toProviderError(cfg, error);
    }

    const message = response.data.choices[0].message;

    // No tool calls — return final text response.
    if (!message.tool_calls || message.tool_calls.length === 0) {
      return { message: message.content, provider: cfg.provider, model: response.data.model };
    }

    messages.push({ role: message.role, content: message.content || null, tool_calls: message.tool_calls });

    const toolResults = await Promise.all(
      message.tool_calls.map(async (toolCall: any) => {
        let parsedArgs: Record<string, any>;
        try {
          parsedArgs = JSON.parse(toolCall.function.arguments);
        } catch {
          return { tool_call_id: toolCall.id, role: "tool", name: toolCall.function.name, content: "Failed to parse tool arguments" };
        }
        const result = await mcpClient.executeTool({ name: toolCall.function.name, arguments: parsedArgs });
        return { tool_call_id: toolCall.id, role: "tool", name: toolCall.function.name, content: serializeToolResult(result) };
      }),
    );
    messages.push(...(toolResults as OpenAIMessage[]));
  }

  // Max rounds reached — one final tool-less request for a summary.
  let finalResponse;
  try {
    finalResponse = await axios.post(cfg.endpoint, { model, messages }, { headers, timeout: 120000 });
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
