// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { SeccompApi } from '../services/seccompApi';
import { useSeccompProfileDetail, useSeccompProfiles } from './useSeccompProfiles';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// Switching from workload A to B while A's read was in flight: B answered
// first, then A's late answer overwrote it, so A's profile was shown (and
// exported) under B's name.
test('a late answer for the previous workload never replaces the current one', async () => {
  const resolvers: Record<string, (r: Response) => void> = {};
  const fetchImpl = vi.fn((url: string) => new Promise<Response>((res) => { resolvers[url.split('/').pop()!] = res; }));
  const api = new SeccompApi({ fetchImpl: fetchImpl as unknown as typeof fetch });
  const { result, rerender } = renderHook(({ n }) => useSeccompProfileDetail(api, 'ns', 'Deployment', n), { initialProps: { n: 'a' } });
  await waitFor(() => expect(resolvers.a).toBeDefined());
  rerender({ n: 'b' });
  await waitFor(() => expect(resolvers.b).toBeDefined());
  await act(async () => { resolvers.b(new Response(JSON.stringify({ name: 'b' }), { status: 200 })); });
  await act(async () => { resolvers.a(new Response(JSON.stringify({ name: 'a' }), { status: 200 })); });
  expect((result.current.detail as unknown as { name: string }).name).toBe('b');
  expect(result.current.loading).toBe(false);
});

test('a late failure for the previous workload does not put its error on the current one', async () => {
  const resolvers: Record<string, (r: Response) => void> = {};
  const fetchImpl = vi.fn((url: string) => new Promise<Response>((res) => { resolvers[url.split('/').pop()!] = res; }));
  const api = new SeccompApi({ fetchImpl: fetchImpl as unknown as typeof fetch });
  const { result, rerender } = renderHook(({ n }) => useSeccompProfileDetail(api, 'ns', 'Deployment', n), { initialProps: { n: 'a' } });
  await waitFor(() => expect(resolvers.a).toBeDefined());
  rerender({ n: 'b' });
  await waitFor(() => expect(resolvers.b).toBeDefined());
  await act(async () => { resolvers.b(new Response(JSON.stringify({ name: 'b' }), { status: 200 })); });
  await act(async () => { resolvers.a(new Response(JSON.stringify({ error: 'boom' }), { status: 500 })); });
  expect(result.current.error).toBeNull();
  expect((result.current.detail as unknown as { name: string }).name).toBe('b');
});

// SeccompApi was the one fetch client without a timeout: a single stalled
// list read held the in-flight guard forever, every later poll was skipped,
// and the seccomp panel sat on its skeleton with no error.
test('a list read that never answers times out with an error, and the next poll reads again', async () => {
  const reads: Promise<Response>[] = [];
  const fetchImpl = vi.fn((_: RequestInfo | URL, init?: RequestInit) => {
    const read = new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)));
    reads.push(read);
    return read;
  });
  const { seccompApi } = await import('../services/seccompApi');
  const internals = seccompApi as unknown as { fetchImpl: typeof fetch; timeoutMs: number };
  const saved = { fetchImpl: internals.fetchImpl, timeoutMs: internals.timeoutMs };
  Object.assign(internals, { fetchImpl, timeoutMs: 20 });
  const { result, unmount } = renderHook(() => useSeccompProfiles(50));
  try {
    await waitFor(() => expect(result.current.error).toMatch(/did not answer/));
    expect(result.current.loading).toBe(false);
    await waitFor(() => expect(fetchImpl.mock.calls.length).toBeGreaterThan(1));
  } finally {
    // Stop the poll, and let the read still in flight time out, before the
    // real client comes back and before jsdom is torn down: a poll or a
    // timeout firing after teardown was an unhandled "window is not defined".
    unmount();
    await act(async () => { await Promise.allSettled(reads); });
    Object.assign(internals, saved);
  }
  expect(fetchImpl.mock.calls.length).toBe(reads.length);
});

test('after unmount the list poll starts no read and a late answer writes nothing', async () => {
  vi.useFakeTimers();
  let answer: ((r: Response) => void) | undefined;
  const fetchImpl = vi.fn(() => new Promise<Response>((resolve) => { answer = resolve; }));
  const { seccompApi } = await import('../services/seccompApi');
  const internals = seccompApi as unknown as { fetchImpl: typeof fetch };
  const saved = internals.fetchImpl;
  internals.fetchImpl = fetchImpl as unknown as typeof fetch;
  const errors = vi.spyOn(console, 'error');
  try {
    const { unmount } = renderHook(() => useSeccompProfiles(1000));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    unmount();
    await act(async () => { answer!(new Response('[]', { status: 200 })); await vi.advanceTimersByTimeAsync(5000); });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(errors).not.toHaveBeenCalled();
  } finally {
    internals.fetchImpl = saved;
  }
});
