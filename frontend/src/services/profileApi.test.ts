import { expect, test, vi } from 'vitest';
import { ProfileApi, ProfileApiError } from './profileApi';
import { workloadsPage } from '../fixtures/profile';

const respond = (status: number, body: unknown) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });

function api(handler: (url: string) => Response) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    calls.push(String(input));
    return handler(String(input));
  }) as unknown as typeof fetch;
  return { client: new ProfileApi({ fetchImpl }), calls };
}

test('error codes classify per the contract', async () => {
  const cases: Array<[number, unknown, string]> = [
    [404, { error: 'workload_not_found', message: 'x' }, 'workload_not_found'],
    [404, { error: 'revision_not_found', message: 'x' }, 'revision_not_found'],
    [404, 'Not Found', 'unsupported'],
    [503, 'busy', 'busy'],
    [400, { error: 'bad_request', message: 'from must be < to' }, 'bad_request'],
    [500, 'db error', 'error'],
  ];
  for (const [status, body, kind] of cases) {
    const { client } = api(() => respond(status, body));
    const err = await client.getProfile('payments', 'Deployment', 'checkout').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProfileApiError);
    expect((err as ProfileApiError).kind).toBe(kind);
  }
  const { client } = api(() => respond(400, { error: 'bad_request', message: 'from must be < to' }));
  await expect(client.getDiff('a', 'b', 'c', { from: 3, to: 2 })).rejects.toThrow('from must be < to');
});

test('a network failure is an error, not a crash', async () => {
  const client = new ProfileApi({ fetchImpl: (async () => Promise.reject(new TypeError('Failed to fetch'))) as unknown as typeof fetch });
  await expect(client.getProfile('a', 'b', 'c')).rejects.toMatchObject({ kind: 'error' });
});

test('paths and queries: segments encoded, unset params omitted', async () => {
  const { client, calls } = api((u) => respond(200, u.includes('/versions') ? { items: [], nextBefore: null } : {}));
  await client.listVersions('payments', 'Deployment', 'a/b', { before: 3 });
  await client.getDiff('payments', 'Deployment', 'checkout', { to: 3 });
  expect(calls).toEqual([
    '/api/workloads/payments/Deployment/a%2Fb/profile/versions?before=3',
    '/api/workloads/payments/Deployment/checkout/profile/diff?to=3',
  ]);
});

test('listAllWorkloads follows nextAfter to the end, and stops at the page cap', async () => {
  const first = { items: workloadsPage.items.slice(0, 2), nextAfter: 'observability/Deployment/grafana' };
  const second = { items: workloadsPage.items.slice(2), nextAfter: null };
  const { client, calls } = api((u) => respond(200, u.includes('after=') ? second : first));
  const all = await client.listAllWorkloads({ namespace: 'payments' });
  expect(all.items).toHaveLength(workloadsPage.items.length);
  expect(all.truncated).toBe(false);
  expect(calls[0]).toBe('/api/workloads?limit=500&namespace=payments');
  expect(calls[1]).toContain('after=observability%2FDeployment%2Fgrafana');

  const endless = api(() => respond(200, first));
  const capped = await endless.client.listAllWorkloads({}, 3);
  expect(capped.truncated).toBe(true);
  expect(endless.calls).toHaveLength(3);
});
