// LLM Bridge URL - use relative path for proxy in production, or direct URL in development
// In production (Vite preview), this proxies through /llm-api to the llm-bridge service
// In development, this can connect directly to localhost:8080 or use the dev proxy
const LLM_BRIDGE_URL = import.meta.env.PROD ? '/llm-api' : (import.meta.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080');

export type LLMProvider = 'openai' | 'anthropic' | 'gemini' | 'copilot';

export interface HistoryMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

/**
 * Callbacks invoked as a streamed chat response arrives. Every field is
 * optional so callers subscribe only to the events they render.
 */
export interface StreamHandlers {
  onText?: (delta: string) => void;
  onThinking?: (delta: string) => void;
  onToolUse?: (name: string) => void;
  onToolResult?: (name: string, ok: boolean) => void;
  onDone?: (info: { model: string }) => void;
  onError?: (error: string) => void;
}

export interface StreamOptions {
  provider?: LLMProvider;
  signal?: AbortSignal;
}

// What llm-bridge accepts (llm-bridge/src/index.ts, src/types/index.ts): a
// JSON body of at most 100 KiB, at most 100 history messages, each at most
// 50,000 characters. A request over any of them is refused outright, so a long
// conversation would fail on every turn until the user cleared it.
const BRIDGE_MAX_BODY_BYTES = 100 * 1024;
const BRIDGE_MAX_CONTENT_CHARS = 50_000;
/** History sent with a message: the newest 25 exchanges at most. */
export const MAX_HISTORY_MESSAGES = 50;
const CLIPPED = '\n\n[… the rest of this message was not sent]';
/** Room left in the body for JSON punctuation and the fields around the history. */
const BODY_SLACK_BYTES = 256;

/** llm-bridge refuses a request whose `context` is longer (ChatRequestSchema, llm-bridge/src/types/index.ts). */
export const BRIDGE_MAX_CONTEXT_CHARS = 2000;
/** The bridge's system prompt names at most 20 pods; more would be dropped there. */
const CONTEXT_MAX_PODS = 20;

/**
 * The page context sent with a message: the namespace and the first pod
 * names, as many whole names as fit the bridge's limit, so long names never
 * make every message fail.
 */
export function chatContext(namespace: string | undefined, podNames: readonly string[] | undefined): string | undefined {
  const pods = podNames?.slice(0, CONTEXT_MAX_PODS);
  const encode = (n: number) => JSON.stringify({ namespace: namespace || undefined, podNames: pods?.slice(0, n) });
  let n = pods?.length ?? 0;
  while (n > 0 && encode(n).length > BRIDGE_MAX_CONTEXT_CHARS) n--;
  const context = encode(n);
  return context.length <= BRIDGE_MAX_CONTEXT_CHARS ? context : undefined;
}

const jsonBytes = (value: unknown): number => new TextEncoder().encode(JSON.stringify(value)).length;

/** The longest start of `text` whose JSON-encoded form, with the clip marker, fits `maxBytes`. */
function clipToBytes(text: string, maxBytes: number): string {
  if (jsonBytes(text) <= maxBytes) return text;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (jsonBytes(text.slice(0, mid) + CLIPPED) <= maxBytes) lo = mid;
    else hi = mid - 1;
  }
  return text.slice(0, lo) + CLIPPED;
}

const clipToChars = ({ role, content }: HistoryMessage): HistoryMessage => ({
  role,
  content: content.length > BRIDGE_MAX_CONTENT_CHARS
    ? content.slice(0, BRIDGE_MAX_CONTENT_CHARS - CLIPPED.length) + CLIPPED
    : content,
});

/** A history entry's share of the body, with the comma that separates it. */
const entryBytes = (m: HistoryMessage): number => jsonBytes(m) + 1;

/**
 * The newest part of `history` that llm-bridge accepts next to a request
 * whose other fields take `reservedBytes`: at most MAX_HISTORY_MESSAGES,
 * each clipped to the per-message limit, the oldest dropped first until the
 * body fits. The newest exchange is clipped rather than dropped when it alone
 * is too big, leaving room for its question. The result starts on a user
 * turn, as the providers expect.
 */
export function boundHistory(history: HistoryMessage[], reservedBytes: number): HistoryMessage[] {
  let budget = BRIDGE_MAX_BODY_BYTES - reservedBytes - BODY_SLACK_BYTES;
  const kept: HistoryMessage[] = [];
  for (let i = history.length - 1; i >= 0 && kept.length < MAX_HISTORY_MESSAGES; i--) {
    const message = clipToChars(history[i]);
    const room = kept.length === 0 && i > 0
      ? budget - Math.min(entryBytes(clipToChars(history[i - 1])), Math.floor(budget / 2))
      : budget;
    if (entryBytes(message) > room) {
      const overhead = entryBytes({ role: message.role, content: '' });
      if (kept.length > 1 || room - overhead < 1024) break;
      message.content = clipToBytes(message.content, room - overhead);
    }
    budget -= entryBytes(message);
    kept.push(message);
  }
  kept.reverse();
  while (kept.length > 0 && kept[0].role !== 'user') kept.shift();
  return kept;
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
  const request = { message, history: [] as HistoryMessage[], context, provider: options.provider };
  request.history = boundHistory(history ?? [], jsonBytes(request));
  let response: Response;
  try {
    response = await fetch(`${LLM_BRIDGE_URL}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
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
  // The bridge ends every stream with a done or an error frame. A body that
  // ends without one was cut short on the way (a proxy timeout, a restart).
  let ended = false;

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
        ended = true;
        handlers.onDone?.({ model: event.model as string });
        break;
      case 'error':
        ended = true;
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
    if (!ended && !options.signal?.aborted) handlers.onError?.('The reply was cut off before it finished');
  } catch (error) {
    if ((error as Error)?.name === 'AbortError') return;
    handlers.onError?.((error as Error)?.message || 'The AI stream was interrupted');
  } finally {
    // Always release the reader lock / signal the body to stop, so an aborted
    // or errored stream doesn't leak the reader and underlying connection.
    reader.cancel().catch(() => {});
  }
}
