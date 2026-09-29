// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { AxiosError } from 'axios';
import type { PodInfo } from '../types';

// The per-pod reads used nested limiters: 10 identity groups at a time, each
// with 10 traffic and 10 syscall reads of its own, so a replica-heavy
// namespace had up to 200 requests in flight. And because a failed read is a
// marker rather than a rejection, a Broker shedding every read with 503 still
// received all 2 × N of them (600 for 300 pods).

vi.mock('./useComputeData', () => ({
  useComputeData: () => ({
    containersByPodUid: new Map(), containersByPodName: new Map(), nodesByName: new Map(),
    findings: [], findingsMeta: { truncated: false, victimsEvaluated: null, historyDisabled: false },
    history: new Map(), enabled: false, supported: true, error: null, unavailable: false, polledAt: 0, seedPod: () => {},
  }),
}));

const state = { inFlight: 0, maxInFlight: 0, calls: 0, shed: false };
const read = () => {
  state.calls += 1;
  state.inFlight += 1;
  state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
  return new Promise<never[]>((resolve, reject) =>
    setTimeout(() => {
      state.inFlight -= 1;
      if (state.shed) reject(new AxiosError('Service Unavailable', 'ERR_BAD_RESPONSE', undefined, undefined, { status: 503 } as never));
      else resolve([]);
    }, 1),
  );
};

// 20 workloads × 10 replicas.
const PODS: PodInfo[] = Array.from({ length: 200 }, (_, i) => ({
  pod_name: `w${i % 20}-${i}`, pod_namespace: 'big', pod_ip: `10.0.${i >> 8}.${i & 255}`,
  pod_identity: `w${i % 20}`, node_name: 'n', is_dead: false, time_stamp: 't',
}) as PodInfo);

vi.mock('../services/api', () => ({
  apiClient: {
    getAllPods: async () => PODS,
    getAllServices: async () => [],
    getPodTrafficByName: () => read(),
    getPodSyscalls: () => read(),
  },
}));

let usePodData: typeof import('./usePodData').usePodData;

beforeEach(async () => {
  Object.assign(state, { inFlight: 0, maxInFlight: 0, calls: 0, shed: false });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  ({ usePodData } = await import('./usePodData'));
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

test('every per-pod read in a namespace shares one limit', async () => {
  const { result } = renderHook(() => usePodData('big'));
  await waitFor(() => expect(result.current.loading).toBe(false), { timeout: 5_000 });
  expect(state.calls).toBe(400); // every read still happens when the Broker answers
  expect(state.maxInFlight).toBeLessThanOrEqual(20);
  expect(result.current.pods).toHaveLength(20);
  expect(result.current.failedReads).toEqual({ traffic: 0, syscalls: 0 });
});

test('once the Broker sheds a read with 503, the reads not yet sent are marked failed, not sent', async () => {
  state.shed = true;
  const { result } = renderHook(() => usePodData('big'));
  await waitFor(() => expect(result.current.loading).toBe(false), { timeout: 5_000 });
  // About one wave, not all 400.
  expect(state.calls).toBeLessThanOrEqual(20);
  // Every read that was not answered is still counted as failed, never as empty.
  expect(result.current.failedReads).toEqual({ traffic: 200, syscalls: 200 });
  expect(result.current.pods.every((p) => p.trafficError && p.syscallsError)).toBe(true);
});
