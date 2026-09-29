// @vitest-environment jsdom
import { expect, test } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useWorkloadPostures } from './useWorkloadProfile';
import { ProfileApi } from '../services/profileApi';
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

  expect(result.current.pages).toBe(1);

  await act(async () => {
    await result.current.loadMore();
  });
  expect(calls).toHaveLength(2);
  expect(result.current.pages).toBe(2);
  expect(result.current.byKey.size).toBe(listPage1.body.items.length + listPage2.body.items.length);
  // The captured page 2 still has a nextAfter.
  expect(result.current.hasMore).toBe(listPage2.body.nextAfter !== null);
});

test('status and search are server-side filters', async () => {
  // The captured bodies for ?status=risk and ?search=LEDG, answered for the
  // exact request lines the hook sends (it always sends its page size).
  const { api, calls } = replayApi([
    answer('GET /workloads?limit=500&status=risk', listStatusRisk.body),
    answer('GET /workloads?limit=500&search=LEDG', listSearchLedger.body),
  ]);
  const { result, rerender } = renderHook(({ status, search }) => useWorkloadPostures(undefined, status, search, 0, api), {
    initialProps: { status: 'risk' as PostureStatus | undefined, search: undefined as string | undefined },
  });
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(calls).toEqual(['GET /workloads?limit=500&status=risk']);
  expect([...result.current.byKey.values()].map((i) => i.posture.status)).toEqual(['risk']);
  expect(result.current.hasMore).toBe(false);

  rerender({ status: undefined, search: 'LEDG' });
  await waitFor(() => expect(calls.at(-1)).toBe('GET /workloads?limit=500&search=LEDG'));
  await waitFor(() => expect([...result.current.byKey.values()].map((i) => i.name)).toEqual(listSearchLedger.body.items.map((i) => i.name)));
});

test('disabled (seccomp mode) makes no request', async () => {
  const { api, calls } = replayApi();
  renderHook(() => useWorkloadPostures(undefined, undefined, undefined, 0, api, 100, false));
  await new Promise((r) => setTimeout(r, 20));
  expect(calls).toEqual([]);
});

/** A ProfileApi whose reads hang until the test answers them, oldest first. */
function deferredApi() {
  const pending: Array<{ line: string; resolve: (r: Response) => void }> = [];
  const fetchImpl = ((input: RequestInfo | URL) =>
    new Promise<Response>((resolve) => {
      const url = new URL(String(input), 'http://x');
      pending.push({ line: `GET ${url.pathname.replace(/^\/api/, '')}${url.search}`, resolve });
    })) as unknown as typeof fetch;
  const page = (items: unknown[], nextAfter: string | null) => new Response(JSON.stringify({ items, nextAfter }), { status: 200 });
  return { api: new ProfileApi({ fetchImpl }), pending, page };
}

test('a first page that supersedes an in-flight loadMore clears loadingMore, so paging can continue', async () => {
  const { api, pending, page } = deferredApi();
  const { result, rerender } = renderHook(({ search }) => useWorkloadPostures(undefined, undefined, search, 0, api, 2), {
    initialProps: { search: undefined as string | undefined },
  });
  await waitFor(() => expect(pending).toHaveLength(1));
  await act(async () => pending.shift()!.resolve(page(listPage1.body.items, 'payments/Deployment/checkout')));
  await waitFor(() => expect(result.current.loading).toBe(false));
  act(() => {
    void result.current.loadMore();
  });
  expect(result.current.loadingMore).toBe(true);
  const stale = pending.shift()!;
  expect(stale.line).toContain('after=');
  // The filter changes while that page is still in flight: a new first page takes over.
  rerender({ search: 'zz' });
  await waitFor(() => expect(pending).toHaveLength(1));
  expect(result.current.loadingMore).toBe(false);
  await act(async () => pending.shift()!.resolve(page(listPage1.body.items, 'payments/Deployment/checkout')));
  await act(async () => stale.resolve(page(listPage2.body.items, null)));
  await waitFor(() => expect(result.current.loading).toBe(false));
  // The stale answer changed nothing, and nothing is stuck "loading more".
  expect(result.current.loadingMore).toBe(false);
  expect(result.current.hasMore).toBe(true);
  expect(result.current.pages).toBe(1);
  act(() => {
    void result.current.loadMore();
  });
  expect(result.current.loadingMore).toBe(true);
  await waitFor(() => expect(pending.at(-1)!.line).toContain('search=zz&after='));
});

test('a loadMore while a first page is in flight is ignored, so it cannot supersede the new filter\'s page', async () => {
  const { api, pending, page } = deferredApi();
  const { result, rerender } = renderHook(({ search }) => useWorkloadPostures(undefined, undefined, search, 0, api, 2), {
    initialProps: { search: undefined as string | undefined },
  });
  await waitFor(() => expect(pending).toHaveLength(1));
  await act(async () => pending.shift()!.resolve(page(listPage1.body.items, 'payments/Deployment/checkout')));
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.hasMore).toBe(true);
  // The filter changes: the first page for it is in flight, and the old cursor still says "more".
  rerender({ search: 'zz' });
  await waitFor(() => expect(pending).toHaveLength(1));
  expect(result.current.loading).toBe(true);
  act(() => {
    void result.current.loadMore();
  });
  // Nothing was issued for the stale cursor.
  expect(pending).toHaveLength(1);
  expect(result.current.loadingMore).toBe(false);
  await act(async () => pending.shift()!.resolve(page(listSearchLedger.body.items, null)));
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect([...result.current.byKey.keys()]).toEqual(listSearchLedger.body.items.map((i) => `${i.namespace}/${i.kind}/${i.name}`));
  expect(result.current.pages).toBe(1);
  expect(result.current.hasMore).toBe(false);
});

test('a new filter drops the previous filter\'s rows at once, and a failed first page leaves none behind', async () => {
  const { api, pending, page } = deferredApi();
  const { result, rerender } = renderHook(({ status }) => useWorkloadPostures(undefined, status, undefined, 0, api, 2), {
    initialProps: { status: 'ok' as PostureStatus | undefined },
  });
  await waitFor(() => expect(pending).toHaveLength(1));
  await act(async () => pending.shift()!.resolve(page(listPage1.body.items, 'payments/Deployment/checkout')));
  await waitFor(() => expect(result.current.byKey.size).toBe(listPage1.body.items.length));

  rerender({ status: 'risk' });
  await waitFor(() => expect(pending).toHaveLength(1));
  // The OK rows are not answers for Risk, not even while Risk loads.
  expect(result.current.byKey.size).toBe(0);
  expect(result.current.hasMore).toBe(false);
  await act(async () => pending.shift()!.resolve(new Response('canceling statement due to statement timeout', { status: 500 })));
  await waitFor(() => expect(result.current.error).not.toBeNull());
  expect(result.current.byKey.size).toBe(0);
  expect(result.current.pages).toBe(0);
});

test('a refresh that fails drops the rows it could not confirm', async () => {
  const { api, pending, page } = deferredApi();
  const { result, rerender } = renderHook(({ tick }) => useWorkloadPostures(undefined, 'risk', undefined, tick, api, 2), {
    initialProps: { tick: 0 },
  });
  await waitFor(() => expect(pending).toHaveLength(1));
  await act(async () => pending.shift()!.resolve(page(listPage1.body.items, null)));
  await waitFor(() => expect(result.current.byKey.size).toBe(listPage1.body.items.length));

  rerender({ tick: 1 });
  await waitFor(() => expect(pending).toHaveLength(1));
  // Same filter: the rows stay on screen while the refresh is in flight.
  expect(result.current.byKey.size).toBe(listPage1.body.items.length);
  await act(async () => pending.shift()!.resolve(new Response('timeout', { status: 500 })));
  await waitFor(() => expect(result.current.error).not.toBeNull());
  expect(result.current.byKey.size).toBe(0);
});
