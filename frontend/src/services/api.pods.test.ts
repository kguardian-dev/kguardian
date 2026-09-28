import { afterEach, expect, test, vi } from 'vitest';
import { AxiosError } from 'axios';
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

test('mounting the map and the picker together costs one pod listing and one namespace read', async () => {
  // useNamespaces and usePodData mount at once. The picker no longer derives
  // its list from the pod inventory, so that overlap is one /pod/info plus
  // one small /pod/namespaces, never a second copy of the whole inventory.
  const urls: string[] = [];
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation(((url: string) => {
    urls.push(url);
    const payload = url === '/pod/namespaces'
      ? ['payments', 'other']
      : [POD, { ...POD, pod_name: 'w-1', pod_namespace: 'other' }];
    return new Promise((resolve) => setTimeout(() => resolve({ data: payload }), 5));
  }) as never);

  const [pods, namespaces] = await Promise.all([
    apiClient.getAllPods(),
    apiClient.getNamespaces(),
  ]);

  expect(urls.filter((u) => u === '/pod/info')).toHaveLength(1);
  expect(urls.filter((u) => u === '/pod/namespaces')).toHaveLength(1);
  expect(pods).toHaveLength(2);
  expect(namespaces).toEqual(['other', 'payments']);
});

test('the namespace picker reads /pod/namespaces, never the pod inventory', async () => {
  // On a busy cluster /pod/info outgrows the client timeout and the picker
  // used to fall back to just "default". The namespaces endpoint is one
  // DISTINCT over the live rows, so the picker no longer depends on it.
  const urls: string[] = [];
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((async (url: string) => {
    urls.push(url);
    return { data: ['payments', 'default', 'argocd'] };
  }) as never);

  await expect(apiClient.getNamespaces()).resolves.toEqual(['default', 'argocd', 'payments']);
  expect(urls).toEqual(['/pod/namespaces']);
});

test('a broker without /pod/namespaces falls back to deriving them from live pods', async () => {
  const urls: string[] = [];
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((async (url: string) => {
    urls.push(url);
    if (url === '/pod/namespaces') {
      throw new AxiosError('Not Found', 'ERR_BAD_REQUEST', undefined, undefined, { status: 404 } as never);
    }
    return { data: [POD, { ...POD, pod_name: 'old-1', pod_namespace: 'retired', is_dead: true }] };
  }) as never);

  await expect(apiClient.getNamespaces()).resolves.toEqual(['payments']);
  expect(urls).toEqual(['/pod/namespaces', '/pod/info']);
});

test('any other failure of /pod/namespaces is rethrown, so the caller keeps the namespace it had', async () => {
  // A 503 shed or a statement timeout used to come back as `['default']`,
  // which replaced a deep link's namespace and rewrote its URL to default.
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('broker down') as never);

  await expect(apiClient.getNamespaces()).rejects.toThrow('broker down');
});
