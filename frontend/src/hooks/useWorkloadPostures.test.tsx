// @vitest-environment jsdom
import { expect, test } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useWorkloadPostures } from './useWorkloadProfile';
import { answer, replayApi } from '../fixtures/replay';
import type { PostureStatus } from '../types/profile';
import { listPage1, listPage2, listSearchLedger, listStatusRisk } from '../fixtures/profile';

// Driven by the captured GET /workloads pages (limit=2 → nextAfter → page 2).

test('fetches one page, then the next only on loadMore', async () => {
  const { api, calls } = replayApi();
  const { result } = renderHook(() => useWorkloadPostures(undefined, undefined, undefined, 0, api, 2));
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(calls).toEqual(['GET /workloads?limit=2']);
  expect([...result.current.byKey.keys()]).toEqual(listPage1.body.items.map((i) => `${i.namespace}/${i.kind}/${i.name}`));
  expect(result.current.hasMore).toBe(true);

  await act(async () => {
    await result.current.loadMore();
  });
  expect(calls).toHaveLength(2);
  expect(result.current.byKey.size).toBe(listPage1.body.items.length + listPage2.body.items.length);
  // The captured page 2 still has a nextAfter.
  expect(result.current.hasMore).toBe(listPage2.body.nextAfter !== null);
});

test('status and search are server-side filters', async () => {
  // The captured bodies for ?status=risk and ?search=LEDG, answered for the
  // exact request lines the hook sends (it always sends its page size).
  const { api, calls } = replayApi([
    answer('GET /workloads?limit=100&status=risk', listStatusRisk.body),
    answer('GET /workloads?limit=100&search=LEDG', listSearchLedger.body),
  ]);
  const { result, rerender } = renderHook(({ status, search }) => useWorkloadPostures(undefined, status, search, 0, api), {
    initialProps: { status: 'risk' as PostureStatus | undefined, search: undefined as string | undefined },
  });
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(calls).toEqual(['GET /workloads?limit=100&status=risk']);
  expect([...result.current.byKey.values()].map((i) => i.posture.status)).toEqual(['risk']);
  expect(result.current.hasMore).toBe(false);

  rerender({ status: undefined, search: 'LEDG' });
  await waitFor(() => expect(calls.at(-1)).toBe('GET /workloads?limit=100&search=LEDG'));
  await waitFor(() => expect([...result.current.byKey.values()].map((i) => i.name)).toEqual(listSearchLedger.body.items.map((i) => i.name)));
});

test('disabled (seccomp mode) makes no request', async () => {
  const { api, calls } = replayApi();
  renderHook(() => useWorkloadPostures(undefined, undefined, undefined, 0, api, 100, false));
  await new Promise((r) => setTimeout(r, 20));
  expect(calls).toEqual([]);
});
