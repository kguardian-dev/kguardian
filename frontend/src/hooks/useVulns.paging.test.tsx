// @vitest-environment jsdom
import { describe, expect, test } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useCveList, useImageList, useImageVulns } from './useVulns';
import { VulnApi } from '../services/vulnApi';

// "Load more" racing a filter change or a Refresh: a first page in flight
// owns the list, so neither spinner is left on and no refresh is dropped.

const cve = (id: string) => ({ id, severity: 'HIGH', packages: [], sources: [], images: 1, workloads: 1, runningWorkloads: 1, namespaces: [], weakestJoin: 'image_id', tier: 'P1' });
const image = (digest: string) => ({ digest, repository: 'r', tags: [], sources: [], workloads: 1 });
const finding = (id: string) => ({ id, package: { name: 'p', type: null, purl: null }, installedVersion: '1', severity: 'HIGH' });

type Route = 'first' | 'more';
/** Answers every read at once, except those `hold` picks, which wait for `release()`. */
function api(body: (route: Route, u: URL) => unknown, hold: (route: Route, n: number) => boolean) {
  const held: Array<() => void> = [];
  const counts: Record<Route, number> = { first: 0, more: 0 };
  const fetchImpl = ((input: RequestInfo | URL) => {
    const u = new URL(String(input), 'http://x');
    // The Images list's per-digest enrichment reads (sha256:1, sha256:2): not what is under test.
    if (/^\/api\/images\/sha256:\d/.test(u.pathname)) return Promise.resolve(new Response('', { status: 404 }));
    const route: Route = u.searchParams.get('after') ? 'more' : 'first';
    const res = () => new Response(JSON.stringify(body(route, u)));
    if (hold(route, counts[route]++)) return new Promise<Response>((r) => held.push(() => r(res())));
    return Promise.resolve(res());
  }) as typeof fetch;
  const release = async () => {
    await act(async () => {
      held.splice(0).forEach((f) => f());
      await new Promise((r) => setTimeout(r, 10));
    });
  };
  return { api: new VulnApi({ fetchImpl }), release };
}

const cvePage = (route: Route) => ({ items: [cve(route === 'more' ? 'CVE-2' : 'CVE-1')], nextAfter: 'c1', computedAt: 't', staleSeconds: 0 });
const imagePage = (route: Route) => ({ items: [image(route === 'more' ? 'sha256:2' : 'sha256:1')], nextAfter: 'c1' });
const vulnsPage = (route: Route) => ({ digest: 'd', reports: [], items: [finding(route === 'more' ? 'CVE-2' : 'CVE-1')], nextAfter: 'c1' });

describe('useCveList', () => {
  test('a filter change while Load more is in flight: the new list is not left loading more', async () => {
    const { api: a, release } = api(cvePage, (route) => route === 'more');
    const { result, rerender } = renderHook(({ sev }: { sev?: ['CRITICAL'] }) => useCveList({ severity: sev }, 0, a), { initialProps: {} });
    await waitFor(() => expect(result.current.loading).toBe(false));
    act(() => void result.current.loadMore());
    expect(result.current.loadingMore).toBe(true);
    rerender({ sev: ['CRITICAL'] });
    await waitFor(() => expect(result.current.loading).toBe(false));
    await release();
    expect(result.current.loadingMore).toBe(false);
    // The old list's page 2 is not appended to the new list.
    expect(result.current.items.map((c) => c.id)).toEqual(['CVE-1']);
  });

  test('Load more during a same-query Refresh: the refresh lands and nothing is left loading', async () => {
    const { api: a, release } = api(cvePage, (route, n) => route === 'first' && n === 1);
    const { result, rerender } = renderHook(({ t }) => useCveList({}, t, a), { initialProps: { t: 0 } });
    await waitFor(() => expect(result.current.loading).toBe(false));
    rerender({ t: 1 });
    await waitFor(() => expect(result.current.loading).toBe(true));
    await act(async () => { await result.current.loadMore(); });
    await release();
    expect(result.current.loading).toBe(false);
    expect(result.current.loadingMore).toBe(false);
    expect(result.current.items.map((c) => c.id)).toEqual(['CVE-1']);
  });
});

describe('useImageList', () => {
  test('a scope change while Load more is in flight: the new list is not left loading more', async () => {
    const { api: a, release } = api(imagePage, (route) => route === 'more');
    const { result, rerender } = renderHook(({ ns }: { ns?: string }) => useImageList(ns, 0, a), { initialProps: {} });
    await waitFor(() => expect(result.current.loading).toBe(false));
    act(() => void result.current.loadMore());
    expect(result.current.loadingMore).toBe(true);
    rerender({ ns: 'payments' });
    await waitFor(() => expect(result.current.loading).toBe(false));
    await release();
    expect(result.current.loadingMore).toBe(false);
    expect(result.current.items.map((i) => i.digest)).toEqual(['sha256:1']);
  });

  test('Load more during a Refresh: the refresh lands and nothing is left loading', async () => {
    const { api: a, release } = api(imagePage, (route, n) => route === 'first' && n === 1);
    const { result, rerender } = renderHook(({ t }) => useImageList(undefined, t, a), { initialProps: { t: 0 } });
    await waitFor(() => expect(result.current.loading).toBe(false));
    rerender({ t: 1 });
    await waitFor(() => expect(result.current.loading).toBe(true));
    await act(async () => { await result.current.loadMore(); });
    await release();
    expect(result.current.loading).toBe(false);
    expect(result.current.loadingMore).toBe(false);
    expect(result.current.items.map((i) => i.digest)).toEqual(['sha256:1']);
  });
});

describe('useImageVulns', () => {
  test('another image while Load more is in flight: the new one is not left loading more', async () => {
    const { api: a, release } = api(vulnsPage, (route) => route === 'more');
    const { result, rerender } = renderHook(({ d }) => useImageVulns(d, a), { initialProps: { d: 'sha256:a' } });
    await waitFor(() => expect(result.current.loading).toBe(false));
    act(() => void result.current.loadMore());
    expect(result.current.loadingMore).toBe(true);
    rerender({ d: 'sha256:b' });
    await waitFor(() => expect(result.current.loading).toBe(false));
    await release();
    expect(result.current.loadingMore).toBe(false);
    expect(result.current.items.map((f) => f.id)).toEqual(['CVE-1']);
  });

  test('Load more during a reload: the reload lands and nothing is left loading', async () => {
    const { api: a, release } = api(vulnsPage, (route, n) => route === 'first' && n === 1);
    const { result } = renderHook(() => useImageVulns('sha256:a', a));
    await waitFor(() => expect(result.current.loading).toBe(false));
    act(() => void result.current.reload());
    await waitFor(() => expect(result.current.loading).toBe(true));
    await act(async () => { await result.current.loadMore(); });
    await release();
    expect(result.current.loading).toBe(false);
    expect(result.current.loadingMore).toBe(false);
  });
});
