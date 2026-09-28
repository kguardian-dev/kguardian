// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { useRunningSignatures } from './useSignatures';
import { VulnApi } from '../services/vulnApi';
import { vulnCapture } from '../fixtures/vulns';
import type { RunningSignaturePage } from '../types/attestations';

afterEach(cleanup);

const feed = vulnCapture<RunningSignaturePage>('attestations-running').body;

/** The captured feed in pages of two, each held until the test releases it; `fails` makes that page a 503. */
function heldFeed(fails: (after: number) => boolean = () => false) {
  const held: Array<() => void> = [];
  const calls: string[] = [];
  const fetchImpl = ((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://x');
    calls.push(url.search);
    const after = Number(url.searchParams.get('after') ?? 0);
    const page: RunningSignaturePage = { items: feed.items.slice(after, after + 2), nextAfter: after + 2 < feed.items.length ? String(after + 2) : null };
    return new Promise<Response>((resolve) => held.push(() => resolve(fails(after) ? new Response('busy', { status: 503 }) : new Response(JSON.stringify(page), { status: 200 }))));
  }) as typeof fetch;
  const release = () =>
    act(async () => {
      held.shift()?.();
      await new Promise((r) => setTimeout(r, 0));
    });
  const releaseAll = async () => {
    for (let i = 0; i < 20; i++) {
      while (held.length) await release();
      await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
    }
  };
  return { api: new VulnApi({ fetchImpl }), held, calls, release, releaseAll };
}

test('F-23: a scope change mid-read stops paging the old scope', async () => {
  const f = heldFeed();
  const { rerender, result } = renderHook(({ ns }: { ns: string }) => useRunningSignatures(ns, 0, f.api), { initialProps: { ns: 'a' } });
  await waitFor(() => expect(f.held).toHaveLength(1));
  await f.release();
  await waitFor(() => expect(f.calls.filter((c) => c.includes('namespace=a'))).toHaveLength(2));
  rerender({ ns: 'b' });
  await waitFor(() => expect(f.calls.filter((c) => c.includes('namespace=b'))).toHaveLength(1));
  await f.releaseAll();
  expect(result.current.items).toHaveLength(feed.items.length);
  expect(result.current.loading).toBe(false);
  // The old scope was abandoned after its second page: nothing more was read for it.
  expect(f.calls.filter((c) => c.includes('namespace=a'))).toHaveLength(2);
});

test('F-23: unmounting mid-read stops paging', async () => {
  const f = heldFeed();
  const { unmount } = renderHook(() => useRunningSignatures('a', 0, f.api));
  await waitFor(() => expect(f.held).toHaveLength(1));
  await f.release();
  await waitFor(() => expect(f.calls).toHaveLength(2));
  unmount();
  await f.releaseAll();
  expect(f.calls).toHaveLength(2);
});

test('a first read that fails midway keeps the pages read so far as a partial set, flagged as such', async () => {
  const f = heldFeed((after) => after === 4);
  const { result } = renderHook(() => useRunningSignatures(undefined, 0, f.api));
  await f.releaseAll();
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.items).toHaveLength(4);
  expect(result.current.error).not.toBeNull();
  expect(result.current.partial).toBe(true);
  expect(result.current.progress).toBeNull();
});
