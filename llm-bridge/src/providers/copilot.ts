import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

interface CopilotMessage {
  role: string;
  content: string | null;
  tool_calls?: any[];
  tool_call_id?: string;
  name?: string;
}

const MAX_TOOL_ROUNDS = 10;

// GitHub Copilot uses OpenAI-compatible API
export async function callCopilot(
  request: ChatRequest,
  brokerClient: BrokerClient
): Promise<ChatResponse> {
  const apiKey = process.env.GITHUB_TOKEN;
  if (!apiKey) {
    throw new Error("GITHUB_TOKEN not configured");
  }

  const model = request.model || "gpt-4o";
  const basePrompt = BrokerClient.getSystemPrompt();
  const systemPrompt = request.context
    ? `${basePrompt}\n\nUser context: ${request.context}`
    : basePrompt;

  // Build messages with history
  const messages: CopilotMessage[] = [
    { role: "system", content: systemPrompt },
  ];

  // Add conversation history if provided
  if (request.history && request.history.length > 0) {
    messages.push(...request.history.map(msg => ({
      role: msg.role,
      content: msg.content,
    })));
  }

  // Add current user message
  messages.push({ role: "user", content: request.message });

  // Build tools (OpenAI format)
  const tools = BrokerClient.getToolDefinitions().map((tool) => ({
    type: "function",
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    },
  }));

  const headers = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };

  // Multi-round tool calling loop
  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let response;
    try {
      response = await axios.post(
        "https://api.githubcopilot.com/chat/completions",
        { model, messages, tools, tool_choice: "auto" },
        { headers, timeout: 120000 }
      );
    } catch (error: any) {
      console.error("Copilot API Error:", error.response?.data?.error?.message || error.message);
      throw new Error(`Copilot API error: ${error.response?.data?.error?.message || error.message}`);
    }

    const choice = response.data.choices[0];
    const message = choice.message;

    // No tool calls — return final text response
    if (!message.tool_calls || message.tool_calls.length === 0) {
      return {
        message: message.content,
        provider: LLMProvider.COPILOT,
        model: response.data.model,
        conversationId: request.conversationId,
      };
    }

    // Append assistant message with tool calls
    messages.push({
      role: message.role,
      content: message.content || null,
      tool_calls: message.tool_calls,
    });

    // Execute tool calls and append results
    const toolResults = await Promise.all(
      message.tool_calls.map(async (toolCall: any) => {
        let parsedArgs: Record<string, any>;
        try {
          parsedArgs = JSON.parse(toolCall.function.arguments);
        } catch {
          return {
            tool_call_id: toolCall.id,
            role: "tool",
            name: toolCall.function.name,
            content: "Failed to parse tool arguments",
          };
        }

        const result = await brokerClient.executeTool({
          name: toolCall.function.name,
          arguments: parsedArgs,
        });

        let content: string;
        if (result.error) {
          content = `Error: ${result.error}`;
        } else if (result.data) {
          content = typeof result.data === 'string' ? result.data : JSON.stringify(result.data);
        } else {
          content = 'No data returned';
        }

        return {
          tool_call_id: toolCall.id,
          role: "tool",
          name: toolCall.function.name,
          content,
        };
      })
    );

    messages.push(...(toolResults as CopilotMessage[]));
  }

  // Max rounds reached — make one final request without tools
  const finalResponse = await axios.post(
    "https://api.githubcopilot.com/chat/completions",
    { model, messages },
    { headers, timeout: 120000 }
  );

  return {
    message: finalResponse.data.choices[0].message.content,
    provider: LLMProvider.COPILOT,
    model: finalResponse.data.model,
    conversationId: request.conversationId,
  };
}
