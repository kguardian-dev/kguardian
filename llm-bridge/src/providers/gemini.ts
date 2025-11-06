import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

export async function callGemini(
  request: ChatRequest,
  brokerClient: BrokerClient
): Promise<ChatResponse> {
  const apiKey = process.env.GOOGLE_API_KEY;
  if (!apiKey) {
    throw new Error("GOOGLE_API_KEY not configured");
  }

  const model = request.model || "gemini-2.0-flash-exp";
  const systemPrompt =
    request.systemPrompt || BrokerClient.getSystemPrompt();

  // Build function declarations
  const functionDeclarations = BrokerClient.getToolDefinitions().map(
    (tool) => ({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    })
  );

  // Combine system prompt with user message
  const userMessage = `${systemPrompt}\n\nUser: ${request.message}`;

  const payload = {
    contents: [
      {
        role: "user",
        parts: [{ text: userMessage }],
      },
    ],
    tools: [{ functionDeclarations }],
  };

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  const response = await axios.post(url, payload, {
    headers: {
      "Content-Type": "application/json",
    },
  });

  const candidate = response.data.candidates[0];
  const content = candidate.content;

  // Check for function calls
  const functionCalls = content.parts.filter(
    (part: any) => part.functionCall
  );

  if (functionCalls.length > 0) {
    // Execute function calls
    const functionResponses = await Promise.all(
      functionCalls.map(async (part: any) => {
        const result = await brokerClient.executeTool({
          name: part.functionCall.name,
          arguments: part.functionCall.args,
        });
        return {
          functionResponse: {
            name: part.functionCall.name,
            response: {
              data: result.error || result.data,
            },
          },
        };
      })
    );

    // Make a follow-up request with function results
    const followUpPayload = {
      contents: [
        {
          role: "user",
          parts: [{ text: userMessage }],
        },
        {
          role: "model",
          parts: content.parts,
        },
        {
          role: "user",
          parts: functionResponses,
        },
      ],
      tools: [{ functionDeclarations }],
    };

    const followUpResponse = await axios.post(url, followUpPayload, {
      headers: {
        "Content-Type": "application/json",
      },
    });

    const finalCandidate = followUpResponse.data.candidates[0];
    const textPart = finalCandidate.content.parts.find(
      (part: any) => part.text
    );

    return {
      message: textPart?.text || "No response from Gemini",
      provider: LLMProvider.GEMINI,
      model,
      conversationId: request.conversationId,
    };
  }

  // No function calls, return text response
  const textPart = content.parts.find((part: any) => part.text);
  return {
    message: textPart?.text || "No response from Gemini",
    provider: LLMProvider.GEMINI,
    model,
    conversationId: request.conversationId,
  };
}
