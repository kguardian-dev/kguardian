import { describe, expect, test } from 'vitest';
import { VulnApi, VulnApiError } from './vulnApi';
import { cvePage, replayVulnApi } from '../fixtures/vulns';

const withStatus = (status: number, body = '') => new VulnApi({ fetchImpl: (async () => new Response(body, { status })) as typeof fetch });
const kindOf = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as VulnApiError).kind;
  }
};

describe('VulnApi error kinds', () => {
  test('401 and 403 are auth, never an empty result', async () => {
    expect(await kindOf(withStatus(401).listCves())).toBe('auth');
    expect(await kindOf(withStatus(403).getExposure('CVE-2099-0001'))).toBe('auth');
  });
  test('404 on a list route is an older Broker; on a detail read it is not found', async () => {
    expect(await kindOf(withStatus(404).listCves())).toBe('unsupported');
    expect(await kindOf(withStatus(404).listImages())).toBe('unsupported');
    expect(await kindOf(withStatus(404).getExposure('CVE-2099-0001'))).toBe('not_found');
  });
  test('503 is busy, 400 bad request, 500 error, a network failure error', async () => {
    expect(await kindOf(withStatus(503).listCves())).toBe('busy');
    expect(await kindOf(withStatus(400, 'bad digest').getImageVulns('latest'))).toBe('bad_request');
    expect(await kindOf(withStatus(500).listCves())).toBe('error');
    const down = new VulnApi({ fetchImpl: (async () => { throw new TypeError('fetch failed'); }) as typeof fetch });
    expect(await kindOf(down.listCves())).toBe('error');
  });
});

describe('VulnApi against the captures', () => {
  test('the list parses to the captured page, and the query is what the Broker was sent', async () => {
    const { api, calls } = replayVulnApi();
    const page = await api.listCves({ severity: ['CRITICAL'] });
    expect(calls).toEqual(['GET /vulnerabilities?severity=CRITICAL']);
    expect(page.items.every((c) => c.severity === 'CRITICAL')).toBe(true);
    expect((await api.listCves()).items.map((c) => c.id)).toEqual(cvePage.items.map((c) => c.id));
  });
  test('the captured 404 exposure and 400 digest map to their kinds', async () => {
    const { api } = replayVulnApi();
    expect(await kindOf(api.getExposure('CVE-2099-9999'))).toBe('not_found');
    expect(await kindOf(api.getImageVulns('latest'))).toBe('bad_request');
  });
});

describe('VulnApi paths pass the /api proxy', () => {
  test('a digest path keeps its colon literal and is allowed by brokerProxyDecision', async () => {
    const { brokerProxyDecision } = await import('../../vite.config');
    const urls: string[] = [];
    const api = new VulnApi({ fetchImpl: (async (u: RequestInfo | URL) => { urls.push(String(u)); return new Response('{}', { status: 200 }); }) as typeof fetch });
    const digest = 'sha256:1eb73105a1fe5826de974a647f3d2e72905e16803a8ca2b9c891bf3545bc242c';
    await api.getImage(digest);
    await api.getImageVulns(digest, { limit: 1 });
    await api.getImageSbom(digest, { limit: 1 });
    await api.getExposure('GHSA-abcd-efgh-ijkl');
    for (const u of urls) {
      expect(u).not.toContain('%');
      expect(brokerProxyDecision('GET', u).allow).toBe(true);
    }
    // Anything else is still escaped, so a crafted id cannot add a segment.
    expect(await (async () => { await api.getExposure('../x'); return urls.at(-1); })()).toContain('..%2Fx');
  });
});

describe('VulnApi timeout', () => {
  test('a read that never answers becomes a retryable "did not answer" error, not an endless skeleton', async () => {
    const hang = ((_: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)))) as typeof fetch;
    const api = new VulnApi({ fetchImpl: hang, timeoutMs: 20 });
    const err = await api.getExposure('CVE-2099-0001').catch((e) => e as VulnApiError);
    expect(err.kind).toBe('timeout');
    expect(err.message).toMatch(/did not answer/);
  });
});
