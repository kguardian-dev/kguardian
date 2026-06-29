import axios from 'axios';

// LLM Bridge URL - use relative path for proxy in production, or direct URL in development
// In production (Vite preview), this proxies through /llm-api to the llm-bridge service
// In development, this can connect directly to localhost:8080 or use the dev proxy
const LLM_BRIDGE_URL = import.meta.env.PROD ? '/llm-api' : (import.meta.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080');

export type LLMProvider = 'openai' | 'anthropic' | 'gemini' | 'copilot';

export interface HistoryMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface ChatMessage {
  message: string;
  conversation_id?: string;
  provider?: LLMProvider;
  model?: string;
  context?: string;
  history?: HistoryMessage[];
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
 * @param history Optional: Previous conversation messages for context
 * @param provider Optional: Specify which LLM provider to use (openai, anthropic, gemini, copilot)
 * @param conversationId Optional: Continue an existing conversation
 * @param context Optional: JSON string with structured context (namespace, podNames)
 * @returns The AI's response
 */
/**
 * Callbacks invoked as a streamed chat response arrives. Every field is
 * optional so callers subscribe only to the events they render.
 */
export interface StreamHandlers {
  onText?: (delta: string) => void;
  onThinking?: (delta: string) => void;
  onToolUse?: (name: string) => void;
  onToolResult?: (name: string, ok: boolean) => void;
  onDone?: (info: { model: string; conversationId?: string }) => void;
  onError?: (error: string) => void;
}

export interface StreamOptions {
  provider?: LLMProvider;
  conversationId?: string;
  signal?: AbortSignal;
}

/**
 * Stream a chat response over Server-Sent Events from the llm-bridge.
 * Parses the SSE frames and dispatches typed events to `handlers`. Resolves
 * when the stream ends; never throws for normal API failures (those arrive via
 * `handlers.onError`), only silently returns on an aborted request.
 */
export async function streamChatMessage(
  message: string,
  history: HistoryMessage[] | undefined,
  context: string | undefined,
  handlers: StreamHandlers,
  options: StreamOptions = {}
): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${LLM_BRIDGE_URL}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        history,
        context,
        provider: options.provider,
        conversationId: options.conversationId,
      }),
      signal: options.signal,
    });
  } catch (error) {
    if ((error as Error)?.name === 'AbortError') return;
    handlers.onError?.((error as Error)?.message || 'Failed to reach the AI service');
    return;
  }

  // Pre-stream failures (validation, no provider) come back as JSON, not SSE.
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      detail = body.error + (body.details ? ` - ${body.details}` : '');
    } catch {
      // non-JSON body; keep the status line
    }
    handlers.onError?.(detail);
    return;
  }

  if (!response.body) {
    handlers.onError?.('No response stream from the AI service');
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  const dispatch = (frame: string): void => {
    const dataLine = frame
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('');
    if (!dataLine) return;

    let event: Record<string, unknown>;
    try {
      event = JSON.parse(dataLine);
    } catch {
      return;
    }

    switch (event.type) {
      case 'text':
        handlers.onText?.(event.delta as string);
        break;
      case 'thinking':
        handlers.onThinking?.(event.delta as string);
        break;
      case 'tool_use':
        handlers.onToolUse?.(event.name as string);
        break;
      case 'tool_result':
        handlers.onToolResult?.(event.name as string, event.ok as boolean);
        break;
      case 'done':
        handlers.onDone?.({ model: event.model as string, conversationId: event.conversationId as string | undefined });
        break;
      case 'error':
        handlers.onError?.(event.error as string);
        break;
    }
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sep: number;
      while ((sep = buffer.indexOf('\n\n')) !== -1) {
        dispatch(buffer.slice(0, sep));
        buffer = buffer.slice(sep + 2);
      }
    }
    if (buffer.trim()) dispatch(buffer);
  } catch (error) {
    if ((error as Error)?.name === 'AbortError') return;
    handlers.onError?.((error as Error)?.message || 'The AI stream was interrupted');
  } finally {
    // Always release the reader lock / signal the body to stop, so an aborted
    // or errored stream doesn't leak the reader and underlying connection.
    reader.cancel().catch(() => {});
  }
}

export async function sendChatMessage(
  message: string,
  history?: HistoryMessage[],
  provider?: LLMProvider,
  conversationId?: string,
  context?: string
): Promise<ChatResponse> {
  try {
    const response = await axios.post<ChatResponse>(`${LLM_BRIDGE_URL}/api/chat`, {
      message,
      history,
      provider,
      conversationId,
      context,
    });

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const errorMessage = error.response?.data?.error || error.message;
      const details = error.response?.data?.details;
      throw new Error(
        `Failed to get AI response: ${errorMessage}${details ? ` - ${details}` : ''}`,
        { cause: error }
      );
    }
    throw new Error('An unexpected error occurred while calling the AI API', { cause: error });
  }
}
