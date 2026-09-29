// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { ProfileApi } from '../services/profileApi';
import { useElapsedSeconds, useProfileDiff, useProfileVersions, useWorkloadProfile } from './useWorkloadProfile';
import { checkoutDiff2to4, checkoutProfile } from '../fixtures/profile';

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

/** A ProfileApi whose reads hang until the test answers them by URL. */
function deferredByUrl() {
  const pending: Array<{ url: string; resolve: (r: Response) => void }> = [];
  const fetchImpl = ((input: RequestInfo | URL) => new Promise<Response>((resolve) => pending.push({ url: String(input), resolve }))) as unknown as typeof fetch;
  const answer = (match: RegExp, body: unknown, status = 200) => {
    const i = pending.findIndex((p) => match.test(p.url));
    if (i < 0) throw new Error(`no pending read matches ${match}: ${pending.map((p) => p.url).join(', ')}`);
    const [p] = pending.splice(i, 1);
    p.resolve(new Response(JSON.stringify(body), { status }));
  };
  return { api: new ProfileApi({ fetchImpl }), pending, answer };
}

const version = (revision: number) => ({
  revision,
  createdAt: '2026-09-01T00:00:00Z',
  contentHash: `sha256:${revision}`,
  dimensionHashes: {},
  changedDimensions: [],
  posture: { status: 'ok', coverage: 1 },
});
const versionList = (name: string, revisions: number[], nextBefore: number | null) => ({
  namespace: 'payments',
  kind: 'Deployment',
  name,
  items: revisions.map(version),
  nextBefore,
});

test('useProfileVersions: another workload drops the old list at once, and a "Load older" still in flight for the old one is not appended', async () => {
  const { api, answer } = deferredByUrl();
  const { result, rerender } = renderHook(({ name }) => useProfileVersions('payments', 'Deployment', name, 0, api), { initialProps: { name: 'checkout' } });
  await act(async () => answer(/checkout\/profile\/versions$/, versionList('checkout', [9, 8], 8)));
  expect(result.current.data?.items.map((v) => v.revision)).toEqual([9, 8]);
  act(() => {
    void result.current.loadMore();
  });
  expect(result.current.loadingMore).toBe(true);

  rerender({ name: 'refunds' });
  // The old workload's versions are not shown under the new one while it loads.
  expect(result.current.data).toBeNull();
  expect(result.current.loading).toBe(true);
  expect(result.current.loadingMore).toBe(false);

  // The old page answers late: dropped.
  await act(async () => answer(/checkout\/profile\/versions\?before=8/, versionList('checkout', [7, 6], null)));
  expect(result.current.data).toBeNull();
  await act(async () => answer(/refunds\/profile\/versions$/, versionList('refunds', [3], null)));
  expect(result.current.data?.name).toBe('refunds');
  expect(result.current.data?.items.map((v) => v.revision)).toEqual([3]);
  expect(result.current.loadingMore).toBe(false);
});

test('useProfileDiff: a new revision pair clears the previous diff while it loads, and a late answer for the old pair is dropped', async () => {
  const { api, answer } = deferredByUrl();
  const { result, rerender } = renderHook(({ from, to }) => useProfileDiff(...W, from, to, true, api), { initialProps: { from: 2, to: 4 } });
  await act(async () => answer(/diff\?from=2&to=4$/, checkoutDiff2to4.body));
  expect(result.current.diff?.to.revision).toBe(4);

  rerender({ from: 1, to: 3 });
  // The pickers now name v1 → v3: the v2 → v4 diff must not stay under them.
  expect(result.current.diff).toBeNull();
  expect(result.current.loading).toBe(true);

  // A pair the user has moved on from answers after the new one: dropped.
  rerender({ from: 2, to: 3 });
  await act(async () => answer(/diff\?from=1&to=3$/, { ...checkoutDiff2to4.body, from: { ...checkoutDiff2to4.body.from, revision: 1 }, to: { ...checkoutDiff2to4.body.to, revision: 3 } }));
  expect(result.current.diff).toBeNull();
  expect(result.current.loading).toBe(true);
  await act(async () => answer(/diff\?from=2&to=3$/, { ...checkoutDiff2to4.body, to: { ...checkoutDiff2to4.body.to, revision: 3 } }));
  expect(result.current.diff?.from?.revision).toBe(2);
  expect(result.current.diff?.to.revision).toBe(3);
  expect(result.current.loading).toBe(false);
});

test('useProfileDiff: a refresh of the same pair keeps the diff on screen until the new one lands', async () => {
  const { api, answer } = deferredByUrl();
  const { result } = renderHook(() => useProfileDiff(...W, 2, 4, true, api));
  await act(async () => answer(/diff\?from=2&to=4$/, checkoutDiff2to4.body));
  act(() => {
    void result.current.reload();
  });
  expect(result.current.loading).toBe(true);
  expect(result.current.diff?.to.revision).toBe(4);
});
