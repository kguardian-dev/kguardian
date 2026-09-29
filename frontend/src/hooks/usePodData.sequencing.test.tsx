// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import type { NetworkTraffic, PodInfo, SyscallInfo } from '../types';

// F-02 (MAP-01, MAP-08, TOOL-15): two overlapping runs shared one pod listing
// and the superseded one's `finally` cleared `loading` while the real one
// still had its traffic reads in flight, so the map showed "No workloads in
// argocd" for a namespace with 20 pods, and a namespace switch kept the old
// graph on screen under the new name until the new reads landed.
//
// F-08 (MAP-03, TOOL-01): a per-pod read that timed out came back as `[]`, so
// the pod looked flow-less: the Traffic filter hid its card and the Policy
// Builder read it as 0 connections.

vi.mock('./useComputeData', () => ({
  useComputeData: () => ({
    containersByPodUid: new Map(),
    containersByPodName: new Map(),
    nodesByName: new Map(),
    findings: [],
    findingsMeta: { truncated: false, victimsEvaluated: null, historyDisabled: false },
    history: new Map(),
    enabled: false,
    supported: true,
    error: null,
    unavailable: false,
    polledAt: 0,
    seedPod: () => {},
  }),
}));

type Deferred<T> = { resolve: (v: T) => void; reject: (e: unknown) => void };
const traffic = new Map<string, Deferred<NetworkTraffic[]>>();
const getAllPods = vi.fn<() => Promise<PodInfo[]>>();

vi.mock('../services/api', () => ({
  apiClient: {
    getAllPods: () => getAllPods(),
    getAllServices: vi.fn(async () => []),
    // Traffic reads stay pending until the test settles them by pod name.
    getPodTrafficByName: (name: string) =>
      new Promise<NetworkTraffic[]>((resolve, reject) => traffic.set(name, { resolve, reject })),
    getPodSyscalls: vi.fn(async (): Promise<SyscallInfo[]> => []),
  },
}));

const pod = (name: string, ns: string, identity = name): PodInfo =>
  ({ pod_name: name, pod_namespace: ns, pod_ip: '10.0.0.1', pod_identity: identity, node_name: 'w', is_dead: false, time_stamp: 't' }) as PodInfo;

const ALL_PODS = [pod('a-1', 'alpha', 'a'), pod('a-2', 'alpha', 'a'), pod('b-1', 'beta', 'b'), pod('c-1', 'beta', 'c')];
const flow = { uuid: 'u', traffic_type: 'EGRESS', time_stamp: 't' } as unknown as NetworkTraffic;

const settleTraffic = async (name: string, rows: NetworkTraffic[] | Error) => {
  await waitFor(() => expect(traffic.has(name)).toBe(true));
  await act(async () => {
    const d = traffic.get(name)!;
    if (rows instanceof Error) d.reject(rows);
    else d.resolve(rows);
    await Promise.resolve();
  });
};

let usePodData: typeof import('./usePodData').usePodData;

beforeEach(async () => {
  traffic.clear();
  getAllPods.mockReset();
  getAllPods.mockImplementation(async () => ALL_PODS);
  ({ usePodData } = await import('./usePodData'));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('usePodData sequences its runs', () => {
  test('a superseded run neither clears loading nor writes its pods', async () => {
    const { result, rerender } = renderHook(({ ns }: { ns: string }) => usePodData(ns), { initialProps: { ns: 'alpha' } });
    await waitFor(() => expect(traffic.has('a-1')).toBe(true));
    expect(result.current.loading).toBe(true);

    // The user switches namespace while alpha's traffic reads are in flight.
    rerender({ ns: 'beta' });
    await waitFor(() => expect(traffic.has('b-1')).toBe(true));

    // alpha's run completes first. It is stale: nothing it did may land.
    await settleTraffic('a-1', [flow]);
    await settleTraffic('a-2', [flow]);
    await act(async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); });
    expect(result.current.loading).toBe(true);
    expect(result.current.pods).toEqual([]);

    // beta's run lands: its pods, and only then does loading clear.
    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', []);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.pods.map((p) => p.id)).toEqual(['beta-b', 'beta-c']);
    expect(result.current.error).toBeNull();
  });

  test('a namespace switch drops the previous pods at once, so the skeleton shows and not the old graph', async () => {
    const { result, rerender } = renderHook(({ ns }: { ns: string }) => usePodData(ns), { initialProps: { ns: 'alpha' } });
    await settleTraffic('a-1', [flow]);
    await settleTraffic('a-2', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.pods).toHaveLength(1);

    rerender({ ns: 'beta' });
    // Before a single beta read has answered: no alpha cards, loading again.
    await waitFor(() => expect(result.current.loading).toBe(true));
    expect(result.current.pods).toEqual([]);

    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    expect(result.current.loading).toBe(false);
  });

  // A→B→A: the first A run lands after the second A run has started. It is
  // superseded, so it must not mark A as loaded (or clear loading) while the
  // run that actually owns A is still reading.
  test('a superseded run for the same namespace as the current one writes nothing either', async () => {
    const { result, rerender } = renderHook(({ ns }: { ns: string }) => usePodData(ns), { initialProps: { ns: 'alpha' } });
    await waitFor(() => expect(traffic.has('a-1')).toBe(true));
    const firstRun = { a1: traffic.get('a-1')!, a2: traffic.get('a-2')! };

    rerender({ ns: 'beta' });
    await waitFor(() => expect(traffic.has('b-1')).toBe(true));
    rerender({ ns: 'alpha' });
    // The third run has registered its own alpha reads.
    await waitFor(() => expect(traffic.get('a-1')).not.toBe(firstRun.a1));

    await act(async () => {
      firstRun.a1.resolve([flow]);
      firstRun.a2.resolve([flow]);
      for (let i = 0; i < 20; i++) await Promise.resolve();
    });
    expect(result.current.loading).toBe(true);
    expect(result.current.pods).toEqual([]);

    await settleTraffic('a-1', [flow]);
    await settleTraffic('a-2', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.pods.map((p) => p.id)).toEqual(['alpha-a']);
  });

  // The error path settles the run too: otherwise the derived loading flag
  // would hold the skeleton up forever instead of showing the error banner.
  test('a run that ends in error clears loading and surfaces the error', async () => {
    getAllPods.mockRejectedValueOnce(new Error('pod listing failed'));
    const { result } = renderHook(() => usePodData('beta'));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('pod listing failed');
    expect(result.current.pods).toEqual([]);
    expect(getAllPods).toHaveBeenCalledTimes(1); // no retry loop either
  });

  test('refresh reloads in place: the graph stays on screen while the run is in flight', async () => {
    const { result } = renderHook(() => usePodData('beta'));
    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));
    traffic.clear();

    act(() => result.current.refreshData());
    await waitFor(() => expect(result.current.loading).toBe(true));
    expect(result.current.pods).toHaveLength(2);
    expect(getAllPods).toHaveBeenCalledTimes(2);
  });

  // The listing rejects on failure (api.ts). A failed Refresh must not
  // replace a loaded graph with nothing: the cards stay, the error is set.
  test('a refresh whose pod listing fails keeps the loaded pods and surfaces the error', async () => {
    const { result } = renderHook(() => usePodData('beta'));
    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));

    getAllPods.mockRejectedValueOnce(new Error('timeout of 35000ms exceeded'));
    act(() => result.current.refreshData());
    await waitFor(() => expect(result.current.error).toBe('timeout of 35000ms exceeded'));
    expect(result.current.loading).toBe(false);
    expect(result.current.pods.map((p) => p.id)).toEqual(['beta-b', 'beta-c']);
  });
});

describe('usePodData marks failed reads instead of hiding them', () => {
  test('a pod whose traffic read failed keeps its card, flagged, and is counted', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { result } = renderHook(() => usePodData('beta'));
    await settleTraffic('b-1', new Error('timeout of 10000ms exceeded'));
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));

    const byId = new Map(result.current.pods.map((p) => [p.id, p]));
    expect(byId.get('beta-b')).toMatchObject({ traffic: [], trafficError: true, syscallsError: false });
    expect(byId.get('beta-c')).toMatchObject({ traffic: [flow], trafficError: false, syscallsError: false });
    expect(result.current.failedReads).toEqual({ traffic: 1, syscalls: 0 });
    // A failed per-pod read is partial data, not a failed load.
    expect(result.current.error).toBeNull();
  });

  test('one failed replica flags the whole identity and keeps the replicas that answered', async () => {
    const { result } = renderHook(() => usePodData('alpha'));
    await settleTraffic('a-1', [flow]);
    await settleTraffic('a-2', new Error('timeout of 10000ms exceeded'));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.pods[0]).toMatchObject({ id: 'alpha-a', traffic: [flow], trafficError: true });
    expect(result.current.failedReads.traffic).toBe(1);
  });
});

describe('usePodData is gated on a view that reads it', () => {
  test('disabled: nothing is fetched and loading is false; enabling fetches once; coming back does not refetch', async () => {
    const { result, rerender } = renderHook(({ on }: { on: boolean }) => usePodData('beta', null, { enabled: on }), { initialProps: { on: false } });
    await act(async () => { await Promise.resolve(); });
    expect(getAllPods).not.toHaveBeenCalled();
    expect(result.current.loading).toBe(false);

    rerender({ on: true });
    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
    expect(getAllPods).toHaveBeenCalledTimes(1);

    rerender({ on: false });
    rerender({ on: true });
    await act(async () => { await Promise.resolve(); });
    expect(getAllPods).toHaveBeenCalledTimes(1); // beta is already here
    expect(result.current.pods).toHaveLength(2);
  });

  test('a namespace picked while disabled is fetched when a view needs pods again', async () => {
    const { result, rerender } = renderHook(
      ({ ns, on }: { ns: string; on: boolean }) => usePodData(ns, null, { enabled: on }),
      { initialProps: { ns: 'alpha', on: true } },
    );
    await settleTraffic('a-1', [flow]);
    await settleTraffic('a-2', [flow]);
    await waitFor(() => expect(result.current.pods).toHaveLength(1));

    rerender({ ns: 'beta', on: false });
    await act(async () => { await Promise.resolve(); });
    expect(getAllPods).toHaveBeenCalledTimes(1);

    rerender({ ns: 'beta', on: true });
    await waitFor(() => expect(getAllPods).toHaveBeenCalledTimes(2));
    expect(result.current.pods).toEqual([]); // alpha's cards do not stand in for beta
    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.pods).toHaveLength(2));
  });

  // The frame between the namespace list arriving and the run starting: the
  // effect that starts the run has not run in that render, so `loading` must
  // already be derived from "this namespace has not settled yet".
  test('the first render after enabling, and after a namespace change, reports loading before the run starts', async () => {
    const seen: { ns: string; on: boolean; loading: boolean }[] = [];
    const { result, rerender } = renderHook(
      ({ ns, on }: { ns: string; on: boolean }) => {
        const r = usePodData(ns, null, { enabled: on });
        seen.push({ ns, on, loading: r.loading });
        return r;
      },
      { initialProps: { ns: 'beta', on: false } },
    );
    expect(result.current.loading).toBe(false);

    rerender({ ns: 'beta', on: true });
    // Every render since the flip, the very first included, read as loading.
    expect(seen.filter((s) => s.on).every((s) => s.loading)).toBe(true);
    await settleTraffic('b-1', [flow]);
    await settleTraffic('c-1', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));

    seen.length = 0;
    rerender({ ns: 'alpha', on: true });
    expect(seen.every((s) => s.loading)).toBe(true);
    await settleTraffic('a-1', [flow]);
    await settleTraffic('a-2', [flow]);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.pods.map((p) => p.id)).toEqual(['alpha-a']);
  });

  test('refreshData is a no-op while disabled', async () => {
    const { result } = renderHook(() => usePodData('beta', null, { enabled: false }));
    act(() => result.current.refreshData());
    await act(async () => { await Promise.resolve(); });
    expect(getAllPods).not.toHaveBeenCalled();
    expect(result.current.loading).toBe(false);
  });
});
