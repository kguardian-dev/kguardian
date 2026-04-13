import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";
import { serializeToolResult } from "./truncate.js";

interface AnthropicTool {
  name: string;
  description: string;
  input_schema: object;
}

interface AnthropicTextBlock {
  type: "text";
  text: string;
}

interface AnthropicToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

type AnthropicContentBlock = AnthropicTextBlock | AnthropicToolUseBlock;

interface AnthropicUserMessage {
  role: "user";
  content: string | AnthropicToolResultBlock[];
}

interface AnthropicAssistantMessage {
  role: "assistant";
  content: AnthropicContentBlock[];
}

interface AnthropicToolResultBlock {
  type: "tool_result";
  tool_use_id: string;
  content: string;
}

type AnthropicMessage = AnthropicUserMessage | AnthropicAssistantMessage;

const MAX_TOOL_ROUNDS = 10;

export async function callAnthropic(
  request: ChatRequest,
  brokerClient: BrokerClient
): Promise<ChatResponse> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not configured");
  }

  const model = request.model || "claude-sonnet-4-5-20250929";
  const context = BrokerClient.parseContext(request.context);
  const systemPrompt = BrokerClient.getSystemPrompt(context);

  // Build tools from cached MCP definitions
  const toolDefs = await BrokerClient.getToolsCached();
  const tools: AnthropicTool[] = toolDefs.map((tool) => ({
    name: tool.name,
    description: tool.description,
    input_schema: tool.parameters,
  }));

  // Build messages with history
  const messages: AnthropicMessage[] = [];

  // Add conversation history if provided
  if (request.history && request.history.length > 0) {
    for (const msg of request.history) {
      if (msg.role === 'system') continue;
      if (msg.role === 'assistant') {
        messages.push({
          role: 'assistant',
          content: [{ type: 'text', text: msg.content }],
        });
      } else {
        messages.push({
          role: 'user',
          content: msg.content,
        });
      }
    }
  }

  // Add current user message
  messages.push({
    role: "user",
    content: request.message,
  });

  const headers = {
    "x-api-key": apiKey,
    "anthropic-version": "2023-06-01",
    "Content-Type": "application/json",
  };

  // Multi-round tool calling loop
  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let response;
    try {
      response = await axios.post(
        "https://api.anthropic.com/v1/messages",
        { model, max_tokens: 4096, system: systemPrompt, messages, tools },
        { headers, timeout: 120000 }
      );
    } catch (error: unknown) {
      const axiosErr = error as { response?: { data?: { error?: { message?: string } } }; message?: string };
      console.error("Anthropic API Error:", axiosErr.response?.data?.error?.message || axiosErr.message);
      throw new Error(`Anthropic API error: ${axiosErr.response?.data?.error?.message || axiosErr.message}`);
    }

    const content = response.data.content as AnthropicContentBlock[];

    // Check if there are tool uses
    const toolUses = content.filter(
      (block): block is AnthropicToolUseBlock => block.type === "tool_use"
    );

    if (toolUses.length === 0) {
      // No tool calls — return text response
      const textContent = content.find(
        (block): block is AnthropicTextBlock => block.type === "text"
      );
      return {
        message: textContent?.text || "No response from Claude",
        provider: LLMProvider.ANTHROPIC,
        model: response.data.model,
        conversationId: request.conversationId,
      };
    }

    // Append assistant message with full content (text + tool_use blocks)
    messages.push({
      role: "assistant",
      content: content,
    });

    // Execute tool calls and build tool results
    const toolResults: AnthropicToolResultBlock[] = await Promise.all(
      toolUses.map(async (toolUse: AnthropicToolUseBlock) => {
        const result = await brokerClient.executeTool({
          name: toolUse.name,
          arguments: toolUse.input as Record<string, import("../types/index.js").JsonValue>,
        });
        return {
          type: "tool_result" as const,
          tool_use_id: toolUse.id,
          content: serializeToolResult(result),
        };
      })
    );

    // Append tool results as a user message
    messages.push({
      role: "user",
      content: toolResults,
    });
  }

  // Max rounds reached — request a final response without tools
  const finalResponse = await axios.post(
    "https://api.anthropic.com/v1/messages",
    { model, max_tokens: 4096, system: systemPrompt, messages },
    { headers, timeout: 120000 }
  );

  const finalContent = (finalResponse.data.content as AnthropicContentBlock[]).find(
    (block): block is AnthropicTextBlock => block.type === "text"
  );

  return {
    message: finalContent?.text || "No response from Claude",
    provider: LLMProvider.ANTHROPIC,
    model: finalResponse.data.model,
    conversationId: request.conversationId,
  };
}
