import { afterEach, expect, test, vi } from 'vitest';
import { apiClient } from './api';

// getAuditVerdicts used to swallow failures into [], so a broker outage
// rendered the Audit Verdicts panel's "no verdicts" empty state and the
// panel's own error state was unreachable.

afterEach(() => vi.restoreAllMocks());

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const axiosOf = (c: unknown) => (c as any).client as { get: (...args: unknown[]) => Promise<unknown> };

test('getAuditVerdicts rejects on failure instead of returning an empty list', async () => {
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('Network Error'));
  await expect(apiClient.getAuditVerdicts({ limit: 401 })).rejects.toThrow('Network Error');
});

test('a successful empty response is still an empty list', async () => {
  vi.spyOn(axiosOf(apiClient), 'get').mockResolvedValue({ data: [] } as never);
  await expect(apiClient.getAuditVerdicts()).resolves.toEqual([]);
});

test('only the filters given reach the broker', async () => {
  const get = vi.spyOn(axiosOf(apiClient), 'get').mockResolvedValue({ data: [] } as never);
  await apiClient.getAuditVerdicts({ limit: 401, direction: 'Egress' });
  expect(get).toHaveBeenCalledWith('/audit/verdicts', { params: { limit: 401, direction: 'Egress' } });
});
