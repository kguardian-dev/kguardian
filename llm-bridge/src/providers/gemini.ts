import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { BrokerClient } from "../brokerClient.js";
import { serializeToolResult } from "./truncate.js";

interface GeminiFunctionCall {
  name: string;
  args: Record<string, unknown>;
}

interface GeminiTextPart {
  text: string;
}

interface GeminiFunctionCallPart {
  functionCall: GeminiFunctionCall;
}

interface GeminiFunctionResponsePart {
  functionResponse: {
    name: string;
    response: unknown;
  };
}

type GeminiPart = GeminiTextPart | GeminiFunctionCallPart | GeminiFunctionResponsePart;

interface GeminiContent {
  role: string;
  parts: GeminiPart[];
}

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
  const context = BrokerClient.parseContext(request.context);
  const systemPrompt = BrokerClient.getSystemPrompt(context);

  // Build function declarations from cached MCP definitions
  const toolDefs = await BrokerClient.getToolsCached();
  const functionDeclarations = toolDefs.map((tool) => ({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters,
  }));

  // Build contents with history
  const contents: GeminiContent[] = [];

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
    let response;
    try {
      response = await axios.post(
        url,
        {
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents,
          tools: [{ functionDeclarations }],
        },
        { headers, timeout: 120000 }
      );
    } catch (error: unknown) {
      const axiosErr = error as { response?: { data?: { error?: { message?: string } } }; message?: string };
      console.error("Gemini API Error:", axiosErr.response?.data?.error?.message || axiosErr.message);
      throw new Error(`Gemini API error: ${axiosErr.response?.data?.error?.message || axiosErr.message}`);
    }

    const candidate = response.data.candidates[0];
    const content = candidate.content as GeminiContent;

    // Check for function calls
    const functionCalls = content.parts.filter(
      (part): part is GeminiFunctionCallPart => "functionCall" in part
    );

    if (functionCalls.length === 0) {
      // No function calls — return text response
      const textPart = content.parts.find(
        (part): part is GeminiTextPart => "text" in part
      );
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
    const functionResponses: GeminiFunctionResponsePart[] = await Promise.all(
      functionCalls.map(async (part: GeminiFunctionCallPart) => {
        const result = await brokerClient.executeTool({
          name: part.functionCall.name,
          arguments: part.functionCall.args as Record<string, import("../types/index.js").JsonValue>,
        });
        return {
          functionResponse: {
            name: part.functionCall.name,
            response: (() => {
              const serialized = serializeToolResult(result);
              try { return JSON.parse(serialized); } catch { return { data: serialized }; }
            })(),
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
    { headers, timeout: 120000 }
  );

  const finalCandidate = finalResponse.data.candidates[0];
  const textPart = (finalCandidate.content as GeminiContent).parts.find(
    (part): part is GeminiTextPart => "text" in part
  );

  return {
    message: textPart?.text || "No response from Gemini",
    provider: LLMProvider.GEMINI,
    model,
    conversationId: request.conversationId,
  };
}
