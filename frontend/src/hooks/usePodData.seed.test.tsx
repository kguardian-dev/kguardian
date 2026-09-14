// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import type { ComputeContainer } from '../types/compute';
import type { PodInfo } from '../types';

// Seeding happens on SELECTION and nowhere else: selection is what opens a
// card (NetworkGraph derives `isExpanded` from it), the sparklines are the
// only consumer of seeded history, and they render only in an open card's
// body. The compute hook is stubbed so this pins the wiring, not the seeding
// itself.
//
// These drive the hook's `selectedPodId` argument rather than a toggle,
// because the expanded flag on a pod object is no longer authoritative —
// seeding off it would read nothing and the only symptom would be an open
// card whose sparklines stayed empty.

const seedPod = vi.fn();
const computeState = {
  containersByPodUid: new Map<string, ComputeContainer[]>(),
  containersByPodName: new Map<string, ComputeContainer[]>(),
  nodesByName: new Map(),
  findings: [],
  findingsMeta: { truncated: false, victimsEvaluated: null, historyDisabled: false },
  history: new Map(),
  enabled: true,
  supported: true,
  error: null,
  polledAt: Date.parse('2026-09-14T10:00:00Z'),
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
    getAllPods: vi.fn(async () => [
      pod(),
      pod({ pod_name: 'api-2', pod_ip: '10.0.0.2' }),
      pod({ pod_name: 'worker-1', pod_ip: '10.0.0.3', pod_identity: 'worker' }),
    ]),
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
  computeState.containersByPodUid.set('uid-c', [container({ container_uid: 'uid-c/app', pod_uid: 'uid-c', pod_name: 'worker-1' })]);
  computeState.containersByPodName = new Map([
    ['payments/api-1', [container()]],
    ['payments/api-2', [container({ container_uid: 'uid-b/app', pod_uid: 'uid-b', pod_name: 'api-2' })]],
    ['payments/worker-1', [container({ container_uid: 'uid-c/app', pod_uid: 'uid-c', pod_name: 'worker-1' })]],
  ]);
  ({ usePodData } = await import('./usePodData'));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('usePodData seeds compute history on selection', () => {
  test('no selection seeds nothing; selecting a card seeds the uid its chart reads', async () => {
    const { result, rerender } = renderHook(
      ({ sel }: { sel: string | null }) => usePodData('payments', sel),
      { initialProps: { sel: null as string | null } },
    );
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    expect(seedPod).not.toHaveBeenCalled();

    const id = result.current.pods[0].id;
    await act(async () => { rerender({ sel: id }); });
    await waitFor(() => expect(seedPod).toHaveBeenCalled());
    // One card, one chart, one read — even though the identity group has two
    // replicas, the chart can only ever show the first.
    expect(new Set(seedPod.mock.calls.map((c) => c[0]))).toEqual(new Set(['uid-a']));
  });

  // At most one card is open, so selecting another must not leave the previous
  // one's read behind: the whole read budget for this feature is one pod.
  test('selecting a second card seeds only that card', async () => {
    const { result, rerender } = renderHook(
      ({ sel }: { sel: string | null }) => usePodData('payments', sel),
      { initialProps: { sel: null as string | null } },
    );
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    const [first, second] = result.current.pods.map((p) => p.id);

    await act(async () => { rerender({ sel: first }); });
    await waitFor(() => expect(seedPod).toHaveBeenCalled());
    seedPod.mockClear();

    await act(async () => { rerender({ sel: second }); });
    await waitFor(() => expect(seedPod).toHaveBeenCalled());
    expect(new Set(seedPod.mock.calls.map((c) => c[0]))).toEqual(new Set(['uid-c']));
  });

  // An external peer or a synthesised culprit card can be selected on the map
  // but has no local pod row, so there is no history to read and no crash.
  test('selecting a card this namespace does not own seeds nothing', async () => {
    const { result, rerender } = renderHook(
      ({ sel }: { sel: string | null }) => usePodData('payments', sel),
      { initialProps: { sel: null as string | null } },
    );
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    await act(async () => { rerender({ sel: 'internet-1.2.3.4-out' }); });
    await act(async () => { await Promise.resolve(); });
    expect(seedPod).not.toHaveBeenCalled();
  });

  test('selecting seeds nothing when compute is disabled cluster-wide', async () => {
    computeState.enabled = false;
    try {
      const { result, rerender } = renderHook(
        ({ sel }: { sel: string | null }) => usePodData('payments', sel),
        { initialProps: { sel: null as string | null } },
      );
      await waitFor(() => expect(result.current.pods).toHaveLength(2));
      await act(async () => { rerender({ sel: result.current.pods[0].id }); });
      await act(async () => { await Promise.resolve(); });
      expect(seedPod).not.toHaveBeenCalled(); // no pod carries a chart to fill
    } finally {
      computeState.enabled = true;
    }
  });

  // Two cards drawn in one pass must put the same instant at the same x, so
  // their charts are comparable; a per-pod `Date.now()` would skew them.
  test('every card in a render pass shares one time origin', async () => {
    // A wall clock that moves on every read: the window must come from the
    // poll's instant, shared by construction, not from a per-card reading.
    let tick = Date.parse('2026-09-14T11:00:00Z');
    vi.spyOn(Date, 'now').mockImplementation(() => (tick += 1_000));
    const { result } = renderHook(() => usePodData('payments'));
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    const windows = result.current.pods.map((p) => p.compute?.sparkWindow);
    expect(windows[0]).toBeDefined();
    expect(windows[0]).toEqual(windows[1]);
    expect(windows[0]).toEqual({ from: computeState.polledAt - 60 * 60_000, to: computeState.polledAt });
  });

  test('deselecting stops seeding it again', async () => {
    const { result, rerender } = renderHook(
      ({ sel }: { sel: string | null }) => usePodData('payments', sel),
      { initialProps: { sel: null as string | null } },
    );
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    const id = result.current.pods[0].id;

    await act(async () => { rerender({ sel: id }); });
    await waitFor(() => expect(seedPod).toHaveBeenCalled());
    seedPod.mockClear();

    await act(async () => { rerender({ sel: null }); });
    expect(seedPod).not.toHaveBeenCalled();
  });
});
