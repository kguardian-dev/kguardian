import { afterEach, describe, expect, it, vi } from 'vitest';
import { boundHistory, BRIDGE_MAX_CONTEXT_CHARS, chatContext, MAX_HISTORY_MESSAGES, streamChatMessage, type HistoryMessage } from './aiApi';

// llm-bridge: express.json({ limit: '100kb' }), history.max(100), content.max(50000).
const BRIDGE_MAX_BODY_BYTES = 100 * 1024;
const bytes = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).length;

function fetchReturning(body: string) {
  // The parameters type mock.calls for the tests that read the request.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return vi.fn(async (_url: string, _init?: RequestInit) => new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(body));
        controller.close();
      },
    }),
    { status: 200, headers: { 'Content-Type': 'text/event-stream' } },
  ));
}

const frame = (event: object) => `data: ${JSON.stringify(event)}\n\n`;

const turns = (n: number, content = (i: number) => `message ${i}`): HistoryMessage[] =>
  Array.from({ length: n }, (_, i) => ({ role: i % 2 ? 'assistant' : 'user', content: content(i) }));

afterEach(() => vi.unstubAllGlobals());

describe('streamChatMessage', () => {
  it('reports a stream that ends without a done or error frame as cut off', async () => {
    vi.stubGlobal('fetch', fetchReturning(frame({ type: 'text', delta: 'The pods with the most' })));
    const onText = vi.fn();
    const onDone = vi.fn();
    const onError = vi.fn();
    await streamChatMessage('q', [], undefined, { onText, onDone, onError });
    expect(onText).toHaveBeenCalledWith('The pods with the most');
    expect(onDone).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith('The reply was cut off before it finished');
  });

  it('does not report a finished stream as cut off', async () => {
    vi.stubGlobal('fetch', fetchReturning(frame({ type: 'text', delta: 'All done.' }) + frame({ type: 'done', model: 'm' })));
    const onError = vi.fn();
    await streamChatMessage('q', [], undefined, { onError });
    expect(onError).not.toHaveBeenCalled();
  });

  it('sends a history the bridge accepts, however long the conversation', async () => {
    const fetchMock = fetchReturning(frame({ type: 'done', model: 'm' }));
    vi.stubGlobal('fetch', fetchMock);
    await streamChatMessage('next question', turns(140, (i) => `message ${i} ${'x'.repeat(3000)}`), undefined, {});
    const init = fetchMock.mock.calls[0][1]!;
    const sent = JSON.parse(init.body as string) as { history: HistoryMessage[] };
    expect(sent.history.length).toBeLessThanOrEqual(100);
    expect(new TextEncoder().encode(init.body as string).length).toBeLessThanOrEqual(BRIDGE_MAX_BODY_BYTES);
    // The newest turns are the ones kept.
    expect(sent.history.at(-1)!.content).toMatch(/^message 139 /);
  });
});

describe('boundHistory', () => {
  it('keeps at most MAX_HISTORY_MESSAGES of the newest turns, starting on a user turn', () => {
    const kept = boundHistory(turns(120), 0);
    expect(MAX_HISTORY_MESSAGES).toBeLessThan(100);
    expect(kept.length).toBeLessThanOrEqual(MAX_HISTORY_MESSAGES);
    expect(kept[0].role).toBe('user');
    expect(kept.at(-1)!.content).toBe('message 119');
  });

  it('clips a message over the bridge limit of 50,000 characters', () => {
    const kept = boundHistory([
      { role: 'user', content: 'write me a profile' },
      { role: 'assistant', content: 'y'.repeat(60_000) },
    ], 0);
    expect(kept).toHaveLength(2);
    expect(kept[1].content.length).toBeLessThanOrEqual(50_000);
    expect(kept[1].content.startsWith('yyyy')).toBe(true);
    expect(kept[1].content).toMatch(/not sent/);
  });

  it('drops the oldest turns to fit the request body limit', () => {
    const history = turns(20, (i) => `${i} ${'z'.repeat(20_000)}`);
    const reserved = 5_000;
    const kept = boundHistory(history, reserved);
    expect(bytes(kept) + reserved).toBeLessThanOrEqual(BRIDGE_MAX_BODY_BYTES);
    expect(kept.length).toBeGreaterThan(0);
    expect(kept[0].role).toBe('user');
    expect(kept.at(-1)!.content.startsWith('19 ')).toBe(true);
  });

  it('counts multi-byte characters by their encoded size, and clips the newest exchange rather than dropping it', () => {
    const history = turns(10, () => '€'.repeat(20_000)); // 3 bytes each in UTF-8: each message alone is over half the body
    const kept = boundHistory(history, 0);
    expect(bytes(kept)).toBeLessThanOrEqual(BRIDGE_MAX_BODY_BYTES);
    expect(kept.map((m) => m.role)).toEqual(['user', 'assistant']);
    expect(kept[1].content).toMatch(/^€+\n\n\[… the rest of this message was not sent\]$/);
  });
});

describe('chatContext', () => {
  it('sends the namespace and up to 20 pod names when they fit', () => {
    const names = Array.from({ length: 25 }, (_, i) => `web-${i}`);
    expect(JSON.parse(chatContext('prod', names)!)).toEqual({ namespace: 'prod', podNames: names.slice(0, 20) });
    expect(JSON.parse(chatContext(undefined, undefined)!)).toEqual({});
  });

  it('drops whole pod names from the end until it fits the bridge limit', () => {
    const names = Array.from({ length: 20 }, (_, i) => `${'p'.repeat(250)}${i}`);
    const context = chatContext('prod', names)!;
    expect(context.length).toBeLessThanOrEqual(BRIDGE_MAX_CONTEXT_CHARS);
    const parsed = JSON.parse(context);
    expect(parsed.podNames).toEqual(names.slice(0, parsed.podNames.length));
    // One more name would not have fitted.
    expect(JSON.stringify({ ...parsed, podNames: names.slice(0, parsed.podNames.length + 1) }).length).toBeGreaterThan(BRIDGE_MAX_CONTEXT_CHARS);
  });

  it('sends no context rather than one the bridge would refuse', () => {
    expect(chatContext('n'.repeat(3000), ['a'])).toBeUndefined();
  });
});
