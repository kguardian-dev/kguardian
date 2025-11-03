import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

interface OpenAIMessage {
  role: string;
  content: string;
}

interface OpenAITool {
  type: string;
  function: {
    name: string;
    description: string;
    parameters: any;
  };
}

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

  // Build messages
  const messages: OpenAIMessage[] = [
    { role: "system", content: systemPrompt },
    { role: "user", content: request.message },
  ];

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

  const payload = {
    model,
    messages,
    tools,
    tool_choice: "auto",
  };

  const response = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    payload,
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
    }
  );

  const choice = response.data.choices[0];
  const message = choice.message;

  // Handle tool calls if present
  if (message.tool_calls && message.tool_calls.length > 0) {
    const toolResults = await Promise.all(
      message.tool_calls.map(async (toolCall: any) => {
        const result = await brokerClient.executeTool({
          name: toolCall.function.name,
          arguments: JSON.parse(toolCall.function.arguments),
        });
        return {
          tool_call_id: toolCall.id,
          role: "tool",
          name: toolCall.function.name,
          content: result.error || JSON.stringify(result.data),
        };
      })
    );

    // Make a second request with tool results
    const followUpMessages = [
      ...messages,
      message,
      ...toolResults,
    ];

    const followUpResponse = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model,
        messages: followUpMessages,
        tools,
      },
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
      }
    );

    const finalMessage = followUpResponse.data.choices[0].message.content;
    return {
      message: finalMessage,
      provider: LLMProvider.OPENAI,
      model: response.data.model,
      conversationId: request.conversationId,
    };
  }

  return {
    message: message.content,
    provider: LLMProvider.OPENAI,
    model: response.data.model,
    conversationId: request.conversationId,
  };
}
