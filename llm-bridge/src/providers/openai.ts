import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";
import { serializeToolResult } from "./truncate.js";

interface OpenAIToolCall {
  id: string;
  type: string;
  function: {
    name: string;
    arguments: string;
  };
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
    parameters: object;
  };
}

const MAX_TOOL_ROUNDS = 10;

export async function callOpenAI(
  request: ChatRequest,
  brokerClient: BrokerClient
): Promise<ChatResponse> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY not configured");
  }

  const model = request.model || "gpt-4o";
  const context = BrokerClient.parseContext(request.context);
  const systemPrompt = BrokerClient.getSystemPrompt(context);

  // Build messages with history
  const messages: OpenAIMessage[] = [
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

  // Build tools from cached MCP definitions
  const toolDefs = await BrokerClient.getToolsCached();
  const tools: OpenAITool[] = toolDefs.map((tool) => ({
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
        "https://api.openai.com/v1/chat/completions",
        { model, messages, tools, tool_choice: "auto" },
        { headers, timeout: 120000 }
      );
    } catch (error: unknown) {
      const axiosErr = error as { response?: { data?: { error?: { message?: string } } }; message?: string };
      console.error("OpenAI API Error:", axiosErr.response?.data || axiosErr.message);
      throw new Error(`OpenAI API error: ${axiosErr.response?.data?.error?.message || axiosErr.message}`);
    }

    const choice = response.data.choices[0];
    const message = choice.message;

    // No tool calls — return final text response
    if (!message.tool_calls || message.tool_calls.length === 0) {
      return {
        message: message.content,
        provider: LLMProvider.OPENAI,
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
      (message.tool_calls as OpenAIToolCall[]).map(async (toolCall: OpenAIToolCall) => {
        let parsedArgs: Record<string, unknown>;
        try {
          parsedArgs = JSON.parse(toolCall.function.arguments) as Record<string, unknown>;
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
          arguments: parsedArgs as Record<string, import("../types/index.js").JsonValue>,
        });

        return {
          tool_call_id: toolCall.id,
          role: "tool",
          name: toolCall.function.name,
          content: serializeToolResult(result),
        };
      })
    );

    messages.push(...(toolResults as OpenAIMessage[]));
  }

  // Max rounds reached — make one final request without tools to get a summary
  const finalResponse = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    { model, messages },
    { headers, timeout: 120000 }
  );

  return {
    message: finalResponse.data.choices[0].message.content,
    provider: LLMProvider.OPENAI,
    model: finalResponse.data.model,
    conversationId: request.conversationId,
  };
}
