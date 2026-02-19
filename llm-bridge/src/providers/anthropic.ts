import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

interface AnthropicTool {
  name: string;
  description: string;
  input_schema: any;
}

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
  const systemPrompt =
    request.systemPrompt || BrokerClient.getSystemPrompt();

  // Build tools
  const tools: AnthropicTool[] = BrokerClient.getToolDefinitions().map(
    (tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.parameters,
    })
  );

  // Build messages with history
  const messages: any[] = [];

  // Add conversation history if provided
  if (request.history && request.history.length > 0) {
    messages.push(...request.history.filter(msg => msg.role !== 'system').map(msg => ({
      role: msg.role,
      content: msg.content,
    })));
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
    } catch (error: any) {
      console.error("Anthropic API Error:", error.response?.data?.error?.message || error.message);
      throw new Error(`Anthropic API error: ${error.response?.data?.error?.message || error.message}`);
    }

    const content = response.data.content;

    // Check if there are tool uses
    const toolUses = content.filter((block: any) => block.type === "tool_use");

    if (toolUses.length === 0) {
      // No tool calls — return text response
      const textContent = content.find((block: any) => block.type === "text");
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
    const toolResults = await Promise.all(
      toolUses.map(async (toolUse: any) => {
        const result = await brokerClient.executeTool({
          name: toolUse.name,
          arguments: toolUse.input,
        });
        return {
          type: "tool_result",
          tool_use_id: toolUse.id,
          content: result.error ? result.error : JSON.stringify(result.data),
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

  const finalContent = finalResponse.data.content.find(
    (block: any) => block.type === "text"
  );

  return {
    message: finalContent?.text || "No response from Claude",
    provider: LLMProvider.ANTHROPIC,
    model: finalResponse.data.model,
    conversationId: request.conversationId,
  };
}
