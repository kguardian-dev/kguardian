import { afterEach, describe, expect, test, vi } from 'vitest';
import { SeccompApi, SeccompApiError } from './seccompApi';

type Call = { url: string; init: RequestInit };

function mockFetch(responses: Array<{ status: number; body?: unknown; type?: string }>) {
  const calls: Call[] = [];
  const queue = [...responses];
  const impl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const next = queue.shift() ?? { status: 200, body: {} };
    const text = next.body === undefined ? '' : typeof next.body === 'string' ? next.body : JSON.stringify(next.body);
    return new Response(text, { status: next.status, headers: { 'Content-Type': next.type ?? 'application/json' } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

afterEach(() => vi.restoreAllMocks());

describe('SeccompApi (read-only)', () => {
  test('lists profiles through the shared /api base', async () => {
    const { impl, calls } = mockFetch([{ status: 200, body: [{ namespace: 'a', kind: 'Deployment', name: 'x' }] }]);
    const rows = await new SeccompApi({ fetchImpl: impl }).listProfiles();
    expect(rows).toHaveLength(1);
    expect(calls[0].url).toBe('/api/seccomp/profiles');
    expect(calls[0].init.method).toBe('GET');
  });

  test('null list body degrades to []', async () => {
    const { impl } = mockFetch([{ status: 200, body: 'null' }]);
    expect(await new SeccompApi({ fetchImpl: impl }).listProfiles()).toEqual([]);
  });

  test('getProfile encodes path segments', async () => {
    const { impl, calls } = mockFetch([{ status: 200, body: { name: 'web/1', profile: { defaultAction: 'SCMP_ACT_LOG' } } }]);
    const d = await new SeccompApi({ fetchImpl: impl }).getProfile('team a', 'Deployment', 'web/1');
    expect(calls[0].url).toBe('/api/seccomp/profiles/team%20a/Deployment/web%2F1');
    expect(d.profile.defaultAction).toBe('SCMP_ACT_LOG');
  });

  test('export returns the YAML text verbatim and passes name/defaultAction/format', async () => {
    const yaml = '# capture: full\napiVersion: kguardian.dev/v1alpha1\nkind: SeccompProfile\n';
    const { impl, calls } = mockFetch([{ status: 200, body: yaml, type: 'application/yaml' }]);
    const api = new SeccompApi({ fetchImpl: impl });
    const out = await api.exportProfile('ns', 'Deployment', 'web', { name: 'my web', defaultAction: 'SCMP_ACT_ERRNO' });
    expect(out).toBe(yaml);
    expect(calls[0].url).toBe('/api/seccomp/profiles/ns/Deployment/web/export?name=my+web&defaultAction=SCMP_ACT_ERRNO');
    expect((calls[0].init.headers as Record<string, string>).Accept).toBe('application/yaml');
    await api.exportProfile('ns', 'Deployment', 'web', { format: 'json' });
    expect(calls[1].url).toBe('/api/seccomp/profiles/ns/Deployment/web/export?format=json');
    expect((calls[1].init.headers as Record<string, string>).Accept).toBe('application/json');
  });

  test('JSON error bodies surface `error`; non-JSON bodies become the message', async () => {
    const { impl } = mockFetch([
      { status: 400, body: { error: 'invalid defaultAction' } },
      { status: 404, body: 'no seccomp profile for that workload', type: 'text/plain' },
    ]);
    const api = new SeccompApi({ fetchImpl: impl });
    const e1 = await api.exportProfile('ns', 'Deployment', 'web', { defaultAction: 'nope' }).catch((e) => e);
    expect(e1).toBeInstanceOf(SeccompApiError);
    expect(e1.status).toBe(400);
    expect(e1.message).toBe('invalid defaultAction');
    const e2 = await api.getProfile('ns', 'Deployment', 'web').catch((e) => e);
    expect(e2.status).toBe(404);
    expect(e2.message).toBe('no seccomp profile for that workload');
  });

  test('exportEdited POSTs the staged edits and returns the document text', async () => {
    const yaml = 'apiVersion: kguardian.dev/v1alpha1\n';
    const { impl, calls } = mockFetch([{ status: 200, body: yaml, type: 'application/yaml' }]);
    const out = await new SeccompApi({ fetchImpl: impl }).exportEdited('ns', 'Deployment', 'web', {
      name: 'deployment-web',
      defaultAction: 'SCMP_ACT_LOG',
      add: ['clock_settime'],
      remove: ['futex'],
    });
    expect(out).toBe(yaml);
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].url).toBe('/api/seccomp/profiles/ns/Deployment/web/export');
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ name: 'deployment-web', defaultAction: 'SCMP_ACT_LOG', add: ['clock_settime'], remove: ['futex'] });
    expect((calls[0].init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
  });

  test('only the export render uses POST; nothing else is a write', async () => {
    const { impl, calls } = mockFetch([{ status: 200, body: [] }, { status: 200, body: { profile: {} } }, { status: 200, body: '' }]);
    const api = new SeccompApi({ fetchImpl: impl });
    await api.listProfiles();
    await api.getProfile('a', 'b', 'c');
    await api.exportProfile('a', 'b', 'c');
    expect(calls.every((c) => c.init.method === 'GET')).toBe(true);
    expect(calls.every((c) => c.init.body === undefined)).toBe(true);
  });

  test('uses the global fetch when none is injected', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('[]', { status: 200 }));
    await new SeccompApi().listProfiles();
    expect(spy).toHaveBeenCalledWith('/api/seccomp/profiles', expect.objectContaining({ method: 'GET' }));
  });
});
