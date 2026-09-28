// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { ProfileApi } from '../services/profileApi';
import { useElapsedSeconds, useWorkloadProfile } from './useWorkloadProfile';
import { checkoutProfile } from '../fixtures/profile';

afterEach(() => vi.useRealTimers());

const W = ['payments', 'Deployment', 'checkout'] as const;
const OK = JSON.stringify(checkoutProfile);
const TIMEOUT = 'canceling statement due to statement timeout';

/** A ProfileApi whose fetch answers with the status `next()` returns at call time. */
function answering(next: () => { status: number; body: string }) {
  const calls: number[] = [];
  const fetchImpl = (async () => {
    calls.push(Date.now());
    const { status, body } = next();
    return new Response(body, { status });
  }) as unknown as typeof fetch;
  return { api: new ProfileApi({ fetchImpl }), calls };
}

/** A ProfileApi whose reads hang until the test answers them. */
function deferred() {
  const pending: Array<(r: Response) => void> = [];
  const fetchImpl = (() => new Promise<Response>((resolve) => pending.push(resolve))) as unknown as typeof fetch;
  return { api: new ProfileApi({ fetchImpl }), pending, answer: (status: number, body: string) => pending.shift()!(new Response(body, { status })) };
}

const pass = async (ms: number) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
};

test('after a 500 the poll backs off, doubling per failure; a success restores the plain interval', async () => {
  vi.useFakeTimers({ now: 0 });
  let answer = { status: 500, body: TIMEOUT };
  const { api, calls } = answering(() => answer);
  const { result } = renderHook(() => useWorkloadProfile(...W, 0, 1000, api));
  await pass(0);
  expect(calls).toEqual([0]);
  expect(result.current.loading).toBe(false);
  expect(result.current.error).toBeInstanceOf(Error);
  // One failure: the next read waits 2 × pollMs, not pollMs.
  await pass(1999);
  expect(calls).toEqual([0]);
  await pass(1);
  expect(calls).toEqual([0, 2000]);
  // Two failures: 4 × pollMs.
  await pass(3999);
  expect(calls).toEqual([0, 2000]);
  await pass(1);
  expect(calls).toEqual([0, 2000, 6000]);
  // Three failures: 8 × pollMs; the Broker recovers meanwhile.
  answer = { status: 200, body: OK };
  await pass(8000);
  expect(calls).toEqual([0, 2000, 6000, 14000]);
  expect(result.current.profile).not.toBeNull();
  expect(result.current.error).toBeNull();
  // Back to every pollMs.
  await pass(2000);
  expect(calls).toEqual([0, 2000, 6000, 14000, 15000, 16000]);
});

test('a 404 is not backed off: the workload may appear, and waiting does not help', async () => {
  vi.useFakeTimers({ now: 0 });
  const { api, calls } = answering(() => ({ status: 404, body: JSON.stringify({ error: 'workload_not_found', message: 'no such workload' }) }));
  renderHook(() => useWorkloadProfile(...W, 0, 1000, api));
  await pass(2000);
  expect(calls).toEqual([0, 1000, 2000]);
});

test('a poll is skipped while a read is still in flight', async () => {
  vi.useFakeTimers();
  const { api, pending } = deferred();
  renderHook(() => useWorkloadProfile(...W, 0, 1000, api));
  await pass(3500);
  expect(pending).toHaveLength(1);
});

test('Retry (reload) drops the back-off, reads at once and shows the skeleton while it does', async () => {
  vi.useFakeTimers();
  const { api, pending, answer } = deferred();
  const { result } = renderHook(() => useWorkloadProfile(...W, 0, 1000, api));
  await pass(0);
  answer(500, TIMEOUT);
  await pass(0);
  expect(result.current.loading).toBe(false);
  expect(result.current.error).toBeInstanceOf(Error);
  // Backing off: the 1 s tick reads nothing.
  await pass(1000);
  expect(pending).toHaveLength(0);
  act(() => {
    void result.current.reload();
  });
  expect(pending).toHaveLength(1);
  expect(result.current.loading).toBe(true);
  answer(200, OK);
  await pass(0);
  expect(result.current.loading).toBe(false);
  expect(result.current.profile).not.toBeNull();
  // And the plain poll is back.
  await pass(1000);
  expect(pending).toHaveLength(1);
});

test('the header refresh resets the back-off too', async () => {
  vi.useFakeTimers({ now: 0 });
  const { api, calls } = answering(() => ({ status: 500, body: TIMEOUT }));
  const { rerender } = renderHook(({ tick }) => useWorkloadProfile(...W, tick, 1000, api), { initialProps: { tick: 0 } });
  await pass(0);
  expect(calls).toEqual([0]);
  await pass(500);
  rerender({ tick: 1 });
  await pass(0);
  expect(calls).toEqual([0, 500]);
});

test('useElapsedSeconds counts whole seconds while active and restarts from 0', () => {
  vi.useFakeTimers();
  const { result, rerender } = renderHook(({ active }) => useElapsedSeconds(active), { initialProps: { active: true } });
  expect(result.current).toBe(0);
  act(() => vi.advanceTimersByTime(3000));
  expect(result.current).toBe(3);
  rerender({ active: false });
  expect(result.current).toBe(0);
  rerender({ active: true });
  expect(result.current).toBe(0);
  act(() => vi.advanceTimersByTime(1000));
  expect(result.current).toBe(1);
});
