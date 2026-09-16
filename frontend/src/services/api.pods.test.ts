import { afterEach, expect, test, vi } from 'vitest';
import { apiClient } from './api';

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

  expect(await apiClient.getAllPods()).toEqual([]);
  expect(await apiClient.getAllPods()).toHaveLength(1);
  expect(calls).toBe(2);
});

test('namespace derivation reuses the in-flight listing rather than refetching', async () => {
  // useNamespaces and usePodData both mount at once; this is the overlap that
  // doubled the broker's peak memory on every page load.
  let calls = 0;
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation(
    deferredGet([POD, { ...POD, pod_name: 'w-1', pod_namespace: 'other' }], () => { calls += 1; }) as never,
  );

  const [pods, namespaces] = await Promise.all([
    apiClient.getAllPods(),
    apiClient.getNamespaces(),
  ]);

  expect(calls).toBe(1);
  expect(pods).toHaveLength(2);
  expect(namespaces).toEqual(expect.arrayContaining(['payments', 'other']));
});
