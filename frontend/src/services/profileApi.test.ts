import { expect, test, vi } from 'vitest';
import { ProfileApi, ProfileApiError } from './profileApi';
import { replayApi } from '../fixtures/replay';
import {
  err400BadOrder,
  err400BadStatus,
  err404RevisionNotFound,
  err404WorkloadNotFound,
  listPage1,
  listPage2,
  listSearchLedger,
} from '../fixtures/profile';

const kindOf = (e: unknown) => (e instanceof ProfileApiError ? e.kind : 'not-a-profile-error');

test('captured error bodies classify per the contract', async () => {
  const { api } = replayApi();
  expect(kindOf(await api.getProfile('payments', 'Deployment', 'does-not-exist').catch((e: unknown) => e))).toBe('workload_not_found');
  expect(kindOf(await api.getDiff('payments', 'Deployment', 'checkout', { from: 1, to: 3 }).catch((e: unknown) => e))).toBe('revision_not_found');
  const badOrder = await api.getDiff('payments', 'Deployment', 'checkout', { from: 4, to: 3 }).catch((e: unknown) => e);
  expect(kindOf(badOrder)).toBe('bad_request');
  expect((badOrder as Error).message).toBe(err400BadOrder.body.message);
  expect(kindOf(await api.listWorkloads({ status: 'great' as never }).catch((e: unknown) => e))).toBe('bad_request');
  // The captures these came from, so a re-capture that changes a code fails here.
  expect([err404WorkloadNotFound, err404RevisionNotFound, err400BadOrder, err400BadStatus].map((c) => [c.status, c.body.error])).toEqual([
    [404, 'workload_not_found'],
    [404, 'revision_not_found'],
    [400, 'bad_request'],
    [400, 'bad_request'],
  ]);
});

test('non-contract failures: a bare 404 is an older Broker, 503 is busy, 500 an error, a network failure an error', async () => {
  const cases: Array<[number, string, string]> = [
    [404, '', 'unsupported'],
    [503, 'busy', 'busy'],
    [500, 'db error', 'error'],
  ];
  for (const [status, body, kind] of cases) {
    const client = new ProfileApi({ fetchImpl: (async () => new Response(body, { status })) as unknown as typeof fetch });
    expect(kindOf(await client.getProfile('a', 'b', 'c').catch((e: unknown) => e))).toBe(kind);
  }
  const offline = new ProfileApi({ fetchImpl: (async () => Promise.reject(new TypeError('Failed to fetch'))) as unknown as typeof fetch });
  await expect(offline.getProfile('a', 'b', 'c')).rejects.toMatchObject({ kind: 'error' });
});

test('paging follows the captured nextAfter to the next captured page', async () => {
  const { api, calls } = replayApi();
  const p1 = await api.listWorkloads({ limit: 2 });
  expect(p1).toEqual(listPage1.body);
  expect(p1.nextAfter).toBe('observability/DaemonSet/node-exporter');
  const p2 = await api.listWorkloads({ limit: 2, after: p1.nextAfter! });
  expect(p2).toEqual(listPage2.body);
  expect(calls).toEqual(['GET /workloads?limit=2', 'GET /workloads?limit=2&after=observability%2FDaemonSet%2Fnode-exporter']);
  expect(listPage2.request).toBe('GET /workloads?limit=2&after=observability/DaemonSet/node-exporter');
});

test('search is sent as the contract query param', async () => {
  const { api } = replayApi();
  expect(await api.listWorkloads({ search: 'LEDG' })).toEqual(listSearchLedger.body);
});

test('paths and queries: segments encoded, unset params omitted', async () => {
  const calls: string[] = [];
  const client = new ProfileApi({
    fetchImpl: vi.fn(async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ items: [], nextBefore: null }), { status: 200 });
    }) as unknown as typeof fetch,
  });
  await client.listVersions('payments', 'Deployment', 'a/b', { before: 3 });
  await client.getDiff('payments', 'Deployment', 'checkout', { to: 3 });
  await client.listWorkloads({ limit: 100, namespace: 'payments', status: 'risk', search: 'led', after: 'payments/Deployment/api' });
  expect(calls).toEqual([
    '/api/workloads/payments/Deployment/a%2Fb/profile/versions?before=3',
    '/api/workloads/payments/Deployment/checkout/profile/diff?to=3',
    '/api/workloads?limit=100&namespace=payments&status=risk&search=led&after=payments%2FDeployment%2Fapi',
  ]);
});

test('a read that never answers becomes a retryable timeout, not an endless skeleton', async () => {
  const hang = ((_: RequestInfo | URL, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)))) as typeof fetch;
  const api = new ProfileApi({ fetchImpl: hang, timeoutMs: 20 });
  const err = await api.listWorkloads().catch((e) => e as ProfileApiError);
  expect(err.kind).toBe('timeout');
  expect(err.message).toMatch(/did not answer/);
});
