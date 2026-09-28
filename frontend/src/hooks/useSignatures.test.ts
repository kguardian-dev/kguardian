import { expect, test } from 'vitest';
import { readRunningSignatures, RUNNING_MAX_PAGES, RUNNING_PAGE_SIZE } from './useSignatures';
import { VulnApi } from '../services/vulnApi';
import { vulnCapture } from '../fixtures/vulns';
import type { RunningSignaturePage } from '../types/attestations';

const feed = vulnCapture<RunningSignaturePage>('attestations-running').body;

/** A Broker serving the captured feed in pages of `size`, or a page that never ends when `endless`. */
function broker(size: number, endless = false) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://x');
    calls.push(url.search);
    const start = Number(url.searchParams.get('after') ?? 0);
    const items = endless ? feed.items : feed.items.slice(start, start + size);
    const nextAfter = endless || start + size < feed.items.length ? String(start + size) : null;
    return new Response(JSON.stringify({ items, nextAfter } satisfies RunningSignaturePage), { status: 200 });
  }) as typeof fetch;
  return { api: new VulnApi({ fetchImpl }), calls };
}

test('IMG-05: the running feed is read to completion, page by page, reporting progress after each page', async () => {
  const b = broker(3);
  const seen: Array<[number, number, boolean]> = [];
  const r = await readRunningSignatures(b.api, undefined, { onPage: (items, p, last) => seen.push([p.pages, items.length, last]) });
  expect(r.items).toHaveLength(feed.items.length);
  expect(r.truncated).toBe(false);
  expect(b.calls).toEqual([`?limit=${RUNNING_PAGE_SIZE}`, `?limit=${RUNNING_PAGE_SIZE}&after=3`, `?limit=${RUNNING_PAGE_SIZE}&after=6`]);
  expect(seen).toEqual([[1, 3, false], [2, 6, false], [3, 8, true]]);
});

test('a feed longer than the cap stops at RUNNING_MAX_PAGES and says it is truncated', async () => {
  const b = broker(8, true);
  const r = await readRunningSignatures(b.api);
  expect(b.calls).toHaveLength(RUNNING_MAX_PAGES);
  expect(r.truncated).toBe(true);
  // 2,005 running containers (11 pages) fit comfortably; the cap is for a runaway cursor.
  expect(RUNNING_MAX_PAGES * RUNNING_PAGE_SIZE).toBeGreaterThanOrEqual(10_000);
});
