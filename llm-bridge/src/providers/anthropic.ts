import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

interface AnthropicTool {
  name: string;
  description: string;
  input_schema: any;
}

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

  const payload = {
    model,
    max_tokens: 4096,
    system: systemPrompt,
    messages: [
      {
        role: "user",
        content: request.message,
      },
    ],
    tools,
  };

  const response = await axios.post(
    "https://api.anthropic.com/v1/messages",
    payload,
    {
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
      },
    }
  );

  const content = response.data.content;

  // Check if there are tool uses
  const toolUses = content.filter((block: any) => block.type === "tool_use");

  if (toolUses.length > 0) {
    // Execute tool calls
    const toolResults = await Promise.all(
      toolUses.map(async (toolUse: any) => {
        const result = await brokerClient.executeTool({
          name: toolUse.name,
          arguments: toolUse.input,
        });
        return {
          type: "tool_result",
          tool_use_id: toolUse.id,
          content: result.error || JSON.stringify(result.data),
        };
      })
    );

    // Make a follow-up request with tool results
    const followUpPayload = {
      model,
      max_tokens: 4096,
      system: systemPrompt,
      messages: [
        {
          role: "user",
          content: request.message,
        },
        {
          role: "assistant",
          content: content,
        },
        {
          role: "user",
          content: toolResults,
        },
      ],
      tools,
    };

    const followUpResponse = await axios.post(
      "https://api.anthropic.com/v1/messages",
      followUpPayload,
      {
        headers: {
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
          "Content-Type": "application/json",
        },
      }
    );

    const finalContent = followUpResponse.data.content.find(
      (block: any) => block.type === "text"
    );

    return {
      message: finalContent?.text || "No response from Claude",
      provider: LLMProvider.ANTHROPIC,
      model: response.data.model,
      conversationId: request.conversationId,
    };
  }

  // No tool calls, return text response
  const textContent = content.find((block: any) => block.type === "text");
  return {
    message: textContent?.text || "No response from Claude",
    provider: LLMProvider.ANTHROPIC,
    model: response.data.model,
    conversationId: request.conversationId,
  };
}
