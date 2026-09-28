// @vitest-environment jsdom
import { expect, test, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { SeccompApiError, type SeccompApi } from '../services/seccompApi';
import type { WorkloadProfileDetail } from '../types/seccompWorkload';
import { SECCOMP_FALLBACK_CONCURRENCY, SECCOMP_FALLBACK_LIMIT, useSeccompProfileFallback, type WorkloadRef } from './useSeccompProfiles';

const wl = (i: number): WorkloadRef => ({ namespace: 'ns', kind: 'Deployment', name: `w${i}` });
const detail = (name: string): WorkloadProfileDetail => ({
  namespace: 'ns', kind: 'Deployment', name, hash: 'h', syscallCount: 1, architectures: [], updatedAt: 't', cr: null,
  profile: { defaultAction: 'SCMP_ACT_LOG', syscalls: [] } as unknown as WorkloadProfileDetail['profile'],
});

function fakeApi(answer: (name: string) => Promise<WorkloadProfileDetail>) {
  const calls: string[] = [];
  let inFlight = 0;
  let peak = 0;
  const getProfile = vi.fn(async (_ns: string, _kind: string, name: string) => {
    calls.push(name);
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    try {
      return await answer(name);
    } finally {
      inFlight -= 1;
    }
  });
  return { api: { getProfile } as unknown as SeccompApi, calls, peak: () => peak };
}

test('reads each shown workload once, a few at a time, at most the limit; 404 is "no profile", other failures stay unknown', async () => {
  const { api, calls, peak } = fakeApi(async (name) => {
    await new Promise((r) => setTimeout(r, 1));
    if (name === 'w1') throw new SeccompApiError(404, 'no profile', null);
    if (name === 'w2') throw new SeccompApiError(500, 'canceling statement due to statement timeout', null);
    return detail(name);
  });
  const many = Array.from({ length: SECCOMP_FALLBACK_LIMIT + 10 }, (_, i) => wl(i));
  const { result } = renderHook(() => useSeccompProfileFallback(api, true, many));
  await waitFor(() => expect(result.current.size).toBe(SECCOMP_FALLBACK_LIMIT - 1));
  expect(calls).toHaveLength(SECCOMP_FALLBACK_LIMIT);
  expect(new Set(calls).size).toBe(calls.length);
  expect(peak()).toBeLessThanOrEqual(SECCOMP_FALLBACK_CONCURRENCY);
  expect(peak()).toBeGreaterThan(1);
  expect(result.current.get('ns/Deployment/w0')?.name).toBe('w0');
  expect(result.current.get('ns/Deployment/w1')).toBeNull();
  expect(result.current.has('ns/Deployment/w2')).toBe(false);
});

test('disabled reads nothing; a changed list reads only new workloads; the refresh tick forgets and re-reads', async () => {
  const { api, calls } = fakeApi(async (n) => detail(n));
  const { result, rerender } = renderHook(({ enabled, wls, tick }) => useSeccompProfileFallback(api, enabled, wls, tick), {
    initialProps: { enabled: false, wls: [wl(0), wl(1)], tick: 0 },
  });
  await new Promise((r) => setTimeout(r, 10));
  expect(calls).toEqual([]);
  rerender({ enabled: true, wls: [wl(0), wl(1)], tick: 0 });
  await waitFor(() => expect(result.current.size).toBe(2));
  rerender({ enabled: true, wls: [wl(1), wl(2)], tick: 0 });
  await waitFor(() => expect(result.current.size).toBe(3));
  expect(calls).toEqual(['w0', 'w1', 'w2']);
  rerender({ enabled: true, wls: [wl(1), wl(2)], tick: 1 });
  // Nothing from before the refresh is shown as current.
  expect(result.current.size).toBe(0);
  await waitFor(() => expect(result.current.size).toBe(2));
  expect(calls).toEqual(['w0', 'w1', 'w2', 'w1', 'w2']);
});

/** Reads that hang until the test releases them, so the in-flight set is observable. */
function gatedApi() {
  const calls: string[] = [];
  const open: Array<() => void> = [];
  let inFlight = 0;
  let peak = 0;
  const getProfile = vi.fn(
    (_ns: string, _kind: string, name: string) =>
      new Promise<WorkloadProfileDetail>((resolve) => {
        calls.push(name);
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        open.push(() => {
          inFlight -= 1;
          resolve(detail(name));
        });
      }),
  );
  const release = async (n = open.length) => {
    for (let i = 0; i < n; i++) open.shift()!();
    await new Promise((r) => setTimeout(r, 0));
  };
  return { api: { getProfile } as unknown as SeccompApi, calls, release, peak: () => peak };
}

test('the limit holds across list changes: a new list of workloads does not start a second wave alongside the first', async () => {
  const { api, calls, release, peak } = gatedApi();
  const first = Array.from({ length: 10 }, (_, i) => wl(i));
  const second = Array.from({ length: 10 }, (_, i) => wl(100 + i));
  const { result, rerender } = renderHook(({ wls }) => useSeccompProfileFallback(api, true, wls), { initialProps: { wls: first } });
  expect(calls).toHaveLength(SECCOMP_FALLBACK_CONCURRENCY);
  rerender({ wls: second });
  // Still only the first wave in flight; the rest of the old list is dropped unread.
  expect(calls).toHaveLength(SECCOMP_FALLBACK_CONCURRENCY);
  while (calls.length < SECCOMP_FALLBACK_CONCURRENCY + second.length) {
    await act(async () => release(1));
  }
  await act(async () => release());
  expect(peak()).toBe(SECCOMP_FALLBACK_CONCURRENCY);
  expect(calls.filter((c) => Number(c.slice(1)) < 100)).toHaveLength(SECCOMP_FALLBACK_CONCURRENCY);
  expect(calls.filter((c) => Number(c.slice(1)) >= 100)).toHaveLength(second.length);
  await waitFor(() => expect(result.current.size).toBe(SECCOMP_FALLBACK_CONCURRENCY + second.length));
});

test('after unmount the reads already in flight finish and no further read is issued', async () => {
  const { api, calls, release } = gatedApi();
  const many = Array.from({ length: 12 }, (_, i) => wl(i));
  const { unmount } = renderHook(() => useSeccompProfileFallback(api, true, many));
  expect(calls).toHaveLength(SECCOMP_FALLBACK_CONCURRENCY);
  unmount();
  await act(async () => release());
  await new Promise((r) => setTimeout(r, 10));
  expect(calls).toHaveLength(SECCOMP_FALLBACK_CONCURRENCY);
});

test('a refresh tick while reads are in flight re-reads those workloads for the new window instead of losing them', async () => {
  const { api, calls, release } = gatedApi();
  const wls = [wl(0), wl(1)];
  const { result, rerender } = renderHook(({ tick }) => useSeccompProfileFallback(api, true, wls, tick), { initialProps: { tick: 0 } });
  expect(calls).toEqual(['w0', 'w1']);
  rerender({ tick: 1 });
  expect(result.current.size).toBe(0);
  // The old window's answers are not shown; the same workloads are read again for the new one.
  await act(async () => release());
  await waitFor(() => expect(calls).toEqual(['w0', 'w1', 'w0', 'w1']));
  expect(result.current.size).toBe(0);
  await act(async () => release());
  await waitFor(() => expect(result.current.size).toBe(2));
});
