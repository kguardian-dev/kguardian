import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

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

export async function callOpenAI(
  request: ChatRequest,
  brokerClient: BrokerClient
): Promise<ChatResponse> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY not configured");
  }

  const model = request.model || "gpt-4o";
  const systemPrompt =
    request.systemPrompt || BrokerClient.getSystemPrompt();

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

  // Build tools
  const tools: OpenAITool[] = BrokerClient.getToolDefinitions().map(
    (tool) => ({
      type: "function",
      function: {
        name: tool.name,
        description: tool.description,
        parameters: tool.parameters,
      },
    })
  );

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
        { headers }
      );
    } catch (error: any) {
      console.error("OpenAI API Error:", error.response?.data || error.message);
      throw new Error(`OpenAI API error: ${error.response?.data?.error?.message || error.message}`);
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
      message.tool_calls.map(async (toolCall: any) => {
        const result = await brokerClient.executeTool({
          name: toolCall.function.name,
          arguments: JSON.parse(toolCall.function.arguments),
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

    messages.push(...(toolResults as OpenAIMessage[]));
  }

  // Max rounds reached — make one final request without tools to get a summary
  const finalResponse = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    { model, messages },
    { headers }
  );

  return {
    message: finalResponse.data.choices[0].message.content,
    provider: LLMProvider.OPENAI,
    model: finalResponse.data.model,
    conversationId: request.conversationId,
  };
}
