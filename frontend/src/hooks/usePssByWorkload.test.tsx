// @vitest-environment jsdom
import { expect, test } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import type { ProfileApi } from '../services/profileApi';
import type { WorkloadListItem } from '../types/profile';
import { listNamespacePayments } from '../fixtures/profile';
import { usePssByWorkload } from './useVulns';

test('a workload whose snapshots all failed is skipped; the other workloads\' PSS levels still land', async () => {
  const computed = listNamespacePayments.body.items;
  // Broker 1.20+: listed with computedAt null and no dimensions at all.
  const failed: WorkloadListItem = {
    clusterId: computed[0].clusterId, namespace: 'payments', kind: 'Deployment', name: 'never-computed',
    revision: null, contentHash: null, computedAt: null, lastChangedAt: null,
    lastError: 'canceling statement due to statement timeout', failedAt: '2026-09-29T02:11:03.123456Z',
  };
  const api = { listWorkloads: async () => ({ items: [failed, ...computed], nextAfter: null }) } as unknown as ProfileApi;
  const { result } = renderHook(() => usePssByWorkload(['payments'], api));
  await waitFor(() => expect(result.current).not.toBeNull());
  const map = result.current!;
  expect(map.has('payments/Deployment/never-computed')).toBe(false);
  for (const w of computed) {
    expect(map.get(`${w.namespace}/${w.kind}/${w.name}`)).toEqual({ level: w.dimensions!.podSecurity.level, confidence: w.dimensions!.podSecurity.levelConfidence });
  }
  expect(map.size).toBe(computed.length);
});
