import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { McpClient } from "../mcpClient.js";
import { log } from "../logger.js";
import { serializeToolResult } from "./truncate.js";

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

// OpenAI and GitHub Copilot speak the identical /chat/completions wire
// protocol — same request body, tool-call shape, and response envelope. They
// differ only in endpoint, credential, and default model, so one
// implementation serves both; a per-provider config is the only variance.
interface OpenAICompatConfig {
  provider: LLMProvider;
  label: string;
  endpoint: string;
  apiKey: string | undefined;
  keyName: string;
  defaultModel: string;
}

const PROVIDERS: Record<"openai" | "copilot", () => OpenAICompatConfig> = {
  openai: () => ({
    provider: LLMProvider.OPENAI,
    label: "OpenAI",
    endpoint: "https://api.openai.com/v1/chat/completions",
    // Trim before empty-check; whitespace-only counts as not-configured.
    // See anthropic.ts for the disable-by-whitespace rationale.
    apiKey: process.env.OPENAI_API_KEY?.trim(),
    keyName: "OPENAI_API_KEY",
    defaultModel: "gpt-4o",
  }),
  copilot: () => ({
    provider: LLMProvider.COPILOT,
    label: "Copilot",
    endpoint: "https://api.githubcopilot.com/chat/completions",
    apiKey: process.env.GITHUB_TOKEN?.trim(),
    keyName: "GITHUB_TOKEN",
    defaultModel: "gpt-4o",
  }),
};

async function callOpenAICompatible(
  request: ChatRequest,
  mcpClient: McpClient,
  cfg: OpenAICompatConfig,
): Promise<ChatResponse> {
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
      log.error(`${cfg.label} API Error:`, error.response?.data?.error?.message || error.message);
      throw new Error(`${cfg.label} API error: ${error.response?.data?.error?.message || error.message}`, { cause: error });
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
  const finalResponse = await axios.post(cfg.endpoint, { model, messages }, { headers, timeout: 120000 });
  return { message: finalResponse.data.choices[0].message.content, provider: cfg.provider, model: finalResponse.data.model };
}

export function callOpenAI(request: ChatRequest, mcpClient: McpClient): Promise<ChatResponse> {
  return callOpenAICompatible(request, mcpClient, PROVIDERS.openai());
}

// GitHub Copilot uses the OpenAI-compatible chat/completions API.
export function callCopilot(request: ChatRequest, mcpClient: McpClient): Promise<ChatResponse> {
  return callOpenAICompatible(request, mcpClient, PROVIDERS.copilot());
}
