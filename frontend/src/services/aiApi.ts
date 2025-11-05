import axios from 'axios';

// LLM Bridge URL - use relative path for proxy in production, or direct URL in development
// In production (Vite preview), this proxies through /llm-api to the llm-bridge service
// In development, this can connect directly to localhost:8080 or use the dev proxy
const LLM_BRIDGE_URL = import.meta.env.PROD ? '/llm-api' : (import.meta.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080');

export type LLMProvider = 'openai' | 'anthropic' | 'gemini' | 'copilot';

export interface ChatMessage {
  message: string;
  conversation_id?: string;
  provider?: LLMProvider;
  model?: string;
  system_prompt?: string;
}

export interface ChatResponse {
  message: string;
  provider: LLMProvider;
  model: string;
  conversation_id?: string;
}

/**
 * Send a chat message to the AI assistant
 * @param message The user's message
 * @param provider Optional: Specify which LLM provider to use (openai, anthropic, gemini, copilot)
 * @param conversationId Optional: Continue an existing conversation
 * @returns The AI's response
 */
export async function sendChatMessage(
  message: string,
  provider?: LLMProvider,
  conversationId?: string
): Promise<ChatResponse> {
  try {
    const response = await axios.post<ChatResponse>(`${LLM_BRIDGE_URL}/api/chat`, {
      message,
      provider,
      conversationId,
    });

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const errorMessage = error.response?.data?.error || error.message;
      const details = error.response?.data?.details;
      throw new Error(
        `Failed to get AI response: ${errorMessage}${details ? ` - ${details}` : ''}`
      );
    }
    throw new Error('An unexpected error occurred while calling the AI API');
  }
}
