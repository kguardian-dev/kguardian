import axios from "axios";
import type { ChatRequest, ChatResponse } from "../types/index.js";
import { LLMProvider } from "../types/index.js";
import { McpClient } from "../mcpClient.js";
import { log } from "../logger.js";
import { serializeToolResult } from "./truncate.js";
import { resolveBaseUrl, endpointHint } from "./baseUrl.js";

const MAX_TOOL_ROUNDS = 10;

// Base URL of the Gemini API, overridable via GEMINI_BASE_URL for gateways
// that expose Gemini's native protocol (LiteLLM's passthrough lives at
// http://litellm:4000/gemini, so that whole prefix is the base). The version
// segment stays in the appended path here, matching Google's own base-URL
// convention — see baseUrl.ts for the append-verbatim rule.
const GEMINI_DEFAULT_BASE = "https://generativelanguage.googleapis.com";

/**
 * Normalise a request failure into the Gemini-labelled error, appending the
 * base-URL hint when the status says the path itself was wrong. Shared by the
 * tool loop and the final summary request so a misconfigured gateway is
 * reported the same way wherever the failure lands.
 */
function toGeminiError(url: string, error: any): Error {
  const detail = error.response?.data?.error?.message || error.message;
  const hint = endpointHint("GEMINI_BASE_URL", url, error.response?.status);
  log.error("Gemini API Error:", `${detail}${hint}`);
  return new Error(`Gemini API error: ${detail}${hint}`, { cause: error });
}

export async function callGemini(
  request: ChatRequest,
  mcpClient: McpClient
): Promise<ChatResponse> {
  // Trim before empty-check; whitespace-only counts as not-configured.
  const apiKey = process.env.GOOGLE_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("GOOGLE_API_KEY not configured");
  }

  // Stable GA model. Was "gemini-2.0-flash-exp" — an experimental preview id
  // that can be withdrawn without notice; pin the GA alias instead. GEMINI_MODEL
  // moves that default for operators whose gateway serves a different model id;
  // request.model still wins over both.
  const model = request.model || process.env.GEMINI_MODEL?.trim() || "gemini-2.0-flash";
  const context = McpClient.parseContext(request.context);
  const systemPrompt = McpClient.getSystemPrompt(context);

  // Build function declarations from cached MCP definitions
  const toolDefs = await McpClient.getToolsCached();
  const functionDeclarations = toolDefs.map((tool) => ({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters,
  }));

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

  const baseUrl = resolveBaseUrl("GEMINI_BASE_URL", GEMINI_DEFAULT_BASE);
  const url = `${baseUrl}/v1beta/models/${model}:generateContent`;
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
    } catch (error: any) {
      throw toGeminiError(url, error);
    }

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
        const result = await mcpClient.executeTool({
          name: part.functionCall.name,
          arguments: part.functionCall.args,
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
  let finalResponse;
  try {
    finalResponse = await axios.post(
      url,
      {
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents,
      },
      { headers, timeout: 120000 }
    );
  } catch (error: any) {
    throw toGeminiError(url, error);
  }

  const finalCandidate = finalResponse.data.candidates[0];
  const textPart = finalCandidate.content.parts.find(
    (part: any) => part.text
  );

  return {
    message: textPart?.text || "No response from Gemini",
    provider: LLMProvider.GEMINI,
    model,
  };
}
