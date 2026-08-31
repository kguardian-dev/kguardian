import { afterEach, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { streamChatMessage } from './aiApi';

// G3 SSE stream contract — consumer side.
//
// Replays the exact recording the llm-bridge emitter test produced
// (llm-bridge/contract/sse_session.golden.txt) through the real parser and
// asserts the handler-level event sequence matches the canonical decoded list
// (sse_events.golden.json). The two sides of the wire test against the same
// bytes: if either endpoint changes the contract, one of the two suites goes
// red. Regenerate the recordings from the llm-bridge side only
// (UPDATE_GOLDEN=1 npm test there), never by hand.

const contractDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../llm-bridge/contract');
const golden = (name: string) => fs.readFileSync(path.join(contractDir, name), 'utf8');

function fetchStreaming(body: string) {
  return vi.fn(async () => new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        // Deliver in 40-byte chunks so the parser's incremental buffering is
        // exercised, not just the whole-body happy path.
        const bytes = new TextEncoder().encode(body);
        for (let i = 0; i < bytes.length; i += 40) controller.enqueue(bytes.slice(i, i + 40));
        controller.close();
      },
    }),
    { status: 200, headers: { 'Content-Type': 'text/event-stream' } },
  ));
}

// Project a canonical wire event to the handler-level view the UI consumes.
// (tool_use `id` is deliberately not surfaced to the UI.)
type WireEvent = { type: string; delta?: string; name?: string; ok?: boolean; model?: string; error?: string };
function handlerView(e: WireEvent): unknown {
  switch (e.type) {
    case 'text': return { type: 'text', delta: e.delta };
    case 'thinking': return { type: 'thinking', delta: e.delta };
    case 'tool_use': return { type: 'tool_use', name: e.name };
    case 'tool_result': return { type: 'tool_result', name: e.name, ok: e.ok };
    case 'done': return { type: 'done', model: e.model };
    case 'error': return { type: 'error', error: e.error };
    default: throw new Error(`unknown wire event type: ${e.type}`);
  }
}

function collectingHandlers(events: unknown[]) {
  return {
    onText: (delta: string) => events.push({ type: 'text', delta }),
    onThinking: (delta: string) => events.push({ type: 'thinking', delta }),
    onToolUse: (name: string) => events.push({ type: 'tool_use', name }),
    onToolResult: (name: string, ok: boolean) => events.push({ type: 'tool_result', name, ok }),
    onDone: (info: { model: string }) => events.push({ type: 'done', model: info.model }),
    onError: (error: string) => events.push({ type: 'error', error }),
  };
}

afterEach(() => vi.unstubAllGlobals());

test('G3: parser decodes the recorded session into the canonical event sequence', async () => {
  const events: unknown[] = [];
  vi.stubGlobal('fetch', fetchStreaming(golden('sse_session.golden.txt')));

  await streamChatMessage('how many pods?', [], undefined, collectingHandlers(events));

  const expected = (JSON.parse(golden('sse_events.golden.json')) as WireEvent[]).map(handlerView);
  expect(events).toEqual(expected);
});

test('G3: parser surfaces the recorded upstream-overload error frame', async () => {
  const events: unknown[] = [];
  vi.stubGlobal('fetch', fetchStreaming(golden('sse_error.golden.txt')));

  await streamChatMessage('hi', [], undefined, collectingHandlers(events));

  const errors = events.filter((e) => (e as WireEvent).type === 'error');
  expect(errors).toHaveLength(1);
  expect((errors[0] as WireEvent).error).toBeTruthy();
});
