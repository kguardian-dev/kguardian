// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import type { ComputeContainer } from '../types/compute';
import type { PodInfo } from '../types';

// The seam that makes COMPUTE_BACKFILL_MAX_PODS tolerable: expanding a card
// seeds that pod's sparkline from stored history, whatever the eager cap did.
// The compute hook is stubbed so this pins the wiring, not the backfill.

const seedPod = vi.fn();
const computeState = {
  containersByPodUid: new Map<string, ComputeContainer[]>(),
  containersByPodName: new Map<string, ComputeContainer[]>(),
  nodesByName: new Map(),
  findings: [],
  findingsMeta: { truncated: false, victimsEvaluated: null, historyDisabled: false },
  history: new Map(),
  enabled: false,
  supported: true,
  error: null,
  seedPod,
};

vi.mock('./useComputeData', () => ({ useComputeData: () => computeState }));

const pod = (over: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: 'api-1', pod_namespace: 'payments', pod_ip: '10.0.0.1', pod_identity: 'api',
  node_name: 'worker-1', is_dead: false, started_at: null, time_stamp: null,
  ...over,
} as PodInfo);

const container = (over: Partial<ComputeContainer> = {}): ComputeContainer => ({
  container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1',
  cgroup_id: 1, ts: 't', interval_ms: 5000,
  cpu_usage_millis: 100, cpu_quota_usec: null, cpu_period_usec: 100000, cpu_request_millis: 250, cpu_limit_millis: 500,
  cpu_nr_periods: 0, cpu_nr_throttled: 0, cpu_throttled_usec: 0, cpu_psi_some10: 0, cpu_psi_full10: 0,
  mem_current: 1000, mem_working_set: 800, mem_limit: 4000, mem_request: 2000, mem_psi_some10: 0, mem_psi_full10: 0,
  mem_events_high: 0, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 0, mem_pgmajfault: 0,
  runq_count: null, runq_p50_us: null, runq_p95_us: null, runq_p99_us: null, runq_max_us: null, runq_overflow: null,
  blame: null, updated_at: 't',
  ...over,
});

vi.mock('../services/api', () => ({
  apiClient: {
    getAllPods: vi.fn(async () => [pod(), pod({ pod_name: 'api-2', pod_ip: '10.0.0.2' })]),
    getAllServices: vi.fn(async () => []),
    getPodTrafficByName: vi.fn(async () => []),
    getPodSyscalls: vi.fn(async () => []),
  },
}));

let usePodData: typeof import('./usePodData').usePodData;

beforeEach(async () => {
  seedPod.mockClear();
  // Both replicas of the `api` identity report compute rows, under one node.
  computeState.containersByPodUid = new Map([
    ['uid-a', [container()]],
    ['uid-b', [container({ container_uid: 'uid-b/app', pod_uid: 'uid-b', pod_name: 'api-2' })]],
  ]);
  computeState.containersByPodName = new Map([
    ['payments/api-1', [container()]],
    ['payments/api-2', [container({ container_uid: 'uid-b/app', pod_uid: 'uid-b', pod_name: 'api-2' })]],
  ]);
  ({ usePodData } = await import('./usePodData'));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('usePodData seeds compute history on expansion', () => {
  test('a collapsed card seeds nothing; expanding one seeds every replica uid', async () => {
    const { result } = renderHook(() => usePodData('payments'));
    await waitFor(() => expect(result.current.pods).toHaveLength(1));
    expect(seedPod).not.toHaveBeenCalled();

    const id = result.current.pods[0].id;
    await act(async () => { result.current.togglePodExpansion(id); });
    await waitFor(() => expect(seedPod).toHaveBeenCalled());
    // An identity group is one card over several pods, so several uids.
    expect(new Set(seedPod.mock.calls.map((c) => c[0]))).toEqual(new Set(['uid-a', 'uid-b']));
  });

  test('collapsing stops seeding it again', async () => {
    const { result } = renderHook(() => usePodData('payments'));
    await waitFor(() => expect(result.current.pods).toHaveLength(1));
    const id = result.current.pods[0].id;

    await act(async () => { result.current.togglePodExpansion(id); });
    await waitFor(() => expect(seedPod).toHaveBeenCalled());
    seedPod.mockClear();

    await act(async () => { result.current.togglePodExpansion(id); });
    expect(seedPod).not.toHaveBeenCalled();
  });
});
