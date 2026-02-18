import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";

const MAX_TOOL_ROUNDS = 10;

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

  // Build contents with history
  const contents: any[] = [];

  // Add conversation history if provided
  if (request.history && request.history.length > 0) {
    for (const msg of request.history) {
      if (msg.role === 'system') continue;
      contents.push({
        role: msg.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: msg.content }],
      });
    }
  }

  // Add current user message
  contents.push({
    role: "user",
    parts: [{ text: request.message }],
  });

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
  const headers = {
    "Content-Type": "application/json",
    "x-goog-api-key": apiKey,
  };

  // Multi-round tool calling loop
  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const response = await axios.post(
      url,
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents,
        tools: [{ functionDeclarations }],
      },
      { headers }
    );

    const candidate = response.data.candidates[0];
    const content = candidate.content;

    // Check for function calls
    const functionCalls = content.parts.filter(
      (part: any) => part.functionCall
    );

    if (functionCalls.length === 0) {
      // No function calls — return text response
      const textPart = content.parts.find((part: any) => part.text);
      return {
        message: textPart?.text || "No response from Gemini",
        provider: LLMProvider.GEMINI,
        model,
        conversationId: request.conversationId,
      };
    }

    // Append model response with function calls
    contents.push({
      role: "model",
      parts: content.parts,
    });

    // Execute function calls and build responses
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

    // Append function responses as user turn
    contents.push({
      role: "user",
      parts: functionResponses,
    });
  }

  // Max rounds reached — request final response without tools
  const finalResponse = await axios.post(
    url,
    {
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents,
    },
    { headers }
  );

  const finalCandidate = finalResponse.data.candidates[0];
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
