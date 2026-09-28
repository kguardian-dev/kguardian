import { describe, expect, it } from 'vitest';
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { loadNodeStatus, type NodeStatusResponse } from './nodeReporting';

const ok: NodeStatusResponse = {
  staleAfterSecs: 900,
  nodes: [{ node: 'ip-a', lastPodPostAt: '2026-09-28T07:37:12Z', alivePods: 0, lastHeartbeatAt: '2026-09-28T12:36:00Z', stale: true }],
};

/** What axios throws for a non-2xx: `isAxiosError` set, `response.status` filled. */
function httpError(status: number, data: unknown = {}) {
  const config = { headers: {} } as InternalAxiosRequestConfig;
  const response = { status, statusText: String(status), headers: {}, config, data } as AxiosResponse;
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', config, undefined, response);
}

const rejecting = (status: number, data?: unknown) => async () => {
  throw httpError(status, data);
};

describe('loadNodeStatus', () => {
  it('asks the api base for /node/status and accepts the expected shape', async () => {
    let url = '';
    const result = await loadNodeStatus(async (u) => {
      url = u;
      return { data: ok };
    });
    expect(url.endsWith('/node/status')).toBe(true);
    expect(result).toEqual({ kind: 'ok', status: ok });
  });

  it('treats only a 404 as an older broker', async () => {
    expect(await loadNodeStatus(rejecting(404))).toEqual({ kind: 'unsupported' });
  });

  it('keeps polling through a busy broker (503, with or without a Retry-After body) and a 500', async () => {
    expect(await loadNodeStatus(rejecting(503, { error: 'database busy', retryAfterSecs: 5 }))).toEqual({ kind: 'error' });
    expect(await loadNodeStatus(rejecting(503))).toEqual({ kind: 'error' });
    expect(await loadNodeStatus(rejecting(500))).toEqual({ kind: 'error' });
  });

  it('treats a network failure and a malformed 200 as errors, never as unsupported', async () => {
    expect(
      await loadNodeStatus(async () => {
        throw new Error('Network Error');
      }),
    ).toEqual({ kind: 'error' });
    expect(await loadNodeStatus(async () => ({ data: { nodes: 'nope' } }))).toEqual({ kind: 'error' });
    expect(await loadNodeStatus(async () => ({ data: { staleAfterSecs: 900 } }))).toEqual({ kind: 'error' });
    expect(await loadNodeStatus(async () => ({ data: null }))).toEqual({ kind: 'error' });
    expect(await loadNodeStatus(async () => ({ data: '<html>' }))).toEqual({ kind: 'error' });
  });
});
