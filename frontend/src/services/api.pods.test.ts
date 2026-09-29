import { afterEach, expect, test, vi } from 'vitest';
import { AxiosError } from 'axios';
import { apiClient } from './api';
import { BROKER_STATEMENT_TIMEOUT_MS } from './readTimeout';

// `/pod/info` is the heaviest response the broker produces, and a page load
// asked for it more than once: usePodData wants the listing, useNamespaces
// derives namespaces from the same listing, and the policy generators ask
// again. Un-coalesced those overlap, and the broker serialises the whole
// inventory once per caller. On a 43k-pod cluster that was two concurrent
// 72 MB responses per page load, which OOM-killed the broker at 4 GiB.

afterEach(() => vi.restoreAllMocks());

const POD = { pod_name: 'api-1', pod_ip: '10.0.0.1', pod_namespace: 'payments' };

/** Spy on the client's own axios instance; no extra dependency needed. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const axiosOf = (c: unknown) => (c as any).client as { get: (url: string) => Promise<unknown> };

/** A `get` that resolves on a later tick, so concurrent calls genuinely overlap. */
const deferredGet = (payload: unknown, onCall: () => void) => () => {
  onCall();
  return new Promise((resolve) => setTimeout(() => resolve({ data: payload }), 5));
};

test('concurrent callers share one request to the broker', async () => {
  let calls = 0;
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation(
    deferredGet([POD], () => { calls += 1; }) as never,
  );

  const [a, b, c] = await Promise.all([
    apiClient.getAllPods(),
    apiClient.getAllPods(),
    apiClient.getAllPods(),
  ]);

  expect(calls).toBe(1);
  // Every caller still gets the data, not an empty array.
  for (const r of [a, b, c]) expect(r).toHaveLength(1);
});

test('a later call fetches again: this is coalescing, not caching', async () => {
  // A time-based cache would make Refresh and namespace switches return stale
  // data. Only overlapping requests are shared.
  let calls = 0;
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation(
    deferredGet([POD], () => { calls += 1; }) as never,
  );

  await apiClient.getAllPods();
  await apiClient.getAllPods();

  expect(calls).toBe(2);
});

test('a failed request does not poison the next one', async () => {
  // The broker dying mid-load is exactly the case that matters here.
  vi.spyOn(console, 'error').mockImplementation(() => {});
  let calls = 0;
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((() => {
    calls += 1;
    return calls === 1
      ? Promise.reject(new Error('broker unavailable'))
      : Promise.resolve({ data: [POD] });
  }) as never);

  await expect(apiClient.getAllPods()).rejects.toThrow('broker unavailable');
  expect(await apiClient.getAllPods()).toHaveLength(1);
  expect(calls).toBe(2);
});

// A timeout, a 503 shed or a dropped connection used to come back as `[]`,
// and the map read that as "No workloads in <ns>". A Refresh that failed
// replaced a loaded graph with the same false empty state. The listing now
// rejects like the per-pod reads, so the caller can show the error.
test('a failed pod listing rejects instead of reading as an empty cluster', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('timeout of 10000ms exceeded') as never);

  await expect(apiClient.getAllPods()).rejects.toThrow('timeout of 10000ms exceeded');
});

test('every caller sharing a failed listing sees the failure', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation(
    (() => new Promise((_, reject) => setTimeout(() => reject(new Error('Service Unavailable')), 5))) as never,
  );

  const results = await Promise.allSettled([apiClient.getAllPods(), apiClient.getAllPods()]);
  expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
});

// Same for the service listing: `[]` silently dropped every Service
// attribution on the map and told the policy generators there were none.
test('a failed service listing rejects instead of reading as no services', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('Service Unavailable') as never);

  await expect(apiClient.getAllServices()).rejects.toThrow('Service Unavailable');
});

// The listing is the heaviest response the broker produces, and the broker
// may spend its whole statement timeout building it. A client that gives up
// first turns every slow read into a failure while the query keeps running.
test('the pod and service listings wait past the broker statement timeout', async () => {
  const configs: { url: string; timeout?: number }[] = [];
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((async (url: string, config?: { timeout?: number }) => {
    configs.push({ url, timeout: config?.timeout });
    return { data: [] };
  }) as never);

  await apiClient.getAllPods();
  await apiClient.getAllServices();

  for (const c of configs) expect(c.timeout).toBeGreaterThan(BROKER_STATEMENT_TIMEOUT_MS);
  expect(configs.map((c) => c.url)).toEqual(['/pod/info', '/svc/info']);
});

test('the namespace fallback rethrows a failed pod listing, so the caller keeps the namespace it had', async () => {
  // Same contract as a failed /pod/namespaces: a failure is not a list of one
  // `default`, which would rewrite a deep link's namespace.
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((async (url: string) => {
    if (url === '/pod/namespaces') {
      throw new AxiosError('Not Found', 'ERR_BAD_REQUEST', undefined, undefined, { status: 404 } as never);
    }
    throw new Error('broker down');
  }) as never);

  await expect(apiClient.getNamespaces()).rejects.toThrow('broker down');
});
