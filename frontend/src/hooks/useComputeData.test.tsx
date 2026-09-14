// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { COMPUTE_MISSED_POLLS_BEFORE_DROP, COMPUTE_SEED_RETRY_MS, useComputeData } from './useComputeData';
import { ComputeUnsupportedError } from '../services/api';
import type { ComputeContainer, ComputeFindingsResponse, ComputeHistoryRow, ComputeLatestResponse, ComputeNode } from '../types/compute';

// Contract (design D8 / wire contract): 5 s poll of latest, 15 s poll of
// findings, paused while the tab is hidden, an hour-long time series per pod
// summing the pod's containers — seeded from /compute/history when a card is
// expanded — and `enabled=false` when no node reports.

/** A minute boundary, so bucket rollovers in these tests land where they read. */
const T0 = Date.parse('2026-09-14T10:00:00Z');
const minutesBefore = (n: number) => new Date(T0 - n * 60_000).toISOString();

const node = (over: Partial<ComputeNode> = {}): ComputeNode => ({
  node: 'worker-1', ts: 't', interval_ms: 5000, ctxt_per_sec: 1000,
  compute_enabled: true, compute_supported: true, contention_loaded: false,
  cpu_some10: 0, cpu_full10: 0, mem_some10: 0, mem_full10: 0,
  cpu_cores: 8, memory_bytes: 32 * 1024 ** 3,
  bpf_runq_enqueued: 0, bpf_runq_hist: 0, bpf_pair: 0, unknown_blame_share: 0, updated_at: 't',
  ...over,
});

const container = (over: Partial<ComputeContainer> = {}): ComputeContainer => ({
  container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1',
  cgroup_id: 1, ts: 't', interval_ms: 5000,
  cpu_usage_millis: 100, cpu_quota_usec: null, cpu_period_usec: 100000, cpu_request_millis: 250, cpu_limit_millis: 500,
  cpu_nr_periods: 50, cpu_nr_throttled: 0, cpu_throttled_usec: 0, cpu_psi_some10: 0, cpu_psi_full10: 0,
  mem_current: 1000, mem_working_set: 800, mem_limit: 4000, mem_request: 2000, mem_psi_some10: 0, mem_psi_full10: 0,
  mem_events_high: 0, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 0, mem_pgmajfault: 0,
  runq_count: null, runq_p50_us: null, runq_p95_us: null, runq_p99_us: null, runq_max_us: null, runq_overflow: null,
  blame: null, updated_at: 't',
  ...over,
});

const historyRow = (over: Partial<ComputeHistoryRow> = {}): ComputeHistoryRow => ({
  id: 1, container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1',
  ts: minutesBefore(1), resolution_secs: 60,
  cpu_usage_millis_avg: 0, cpu_usage_millis_max: 0, cpu_usage_millis_last: 0,
  cpu_quota_usec: null, cpu_period_usec: 100000, cpu_request_millis: 250, cpu_limit_millis: 500,
  cpu_nr_periods: 0, cpu_nr_throttled: 0, cpu_throttled_usec: 0,
  cpu_psi_some10_avg: 0, cpu_psi_some10_max: 0, cpu_psi_full10_avg: 0, cpu_psi_full10_max: 0,
  mem_current_avg: 0, mem_current_max: 0, mem_current_last: 0,
  mem_working_set_avg: 0, mem_working_set_max: 0, mem_working_set_last: 0,
  mem_limit: 4000, mem_request: 2000,
  mem_psi_some10_avg: 0, mem_psi_some10_max: 0, mem_psi_full10_avg: 0, mem_psi_full10_max: 0,
  mem_events_high: 0, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 0, mem_pgmajfault: 0,
  runq_count: null, runq_p50_us: null, runq_p95_us: null, runq_p99_us: null, runq_max_us: null, runq_overflow: null,
  runq_hist: null,
  ...over,
});

function fakeApi(
  latest: () => ComputeLatestResponse,
  findings: () => ComputeFindingsResponse = () => ({ findings: [] }),
  nodes: () => ComputeNode[] = () => [],
  history: (podUid: string) => ComputeHistoryRow[] = () => [],
) {
  return {
    getComputeLatest: vi.fn(async () => latest()),
    getComputeFindings: vi.fn(async () => findings()),
    getComputeNodes: vi.fn(async () => nodes()),
    getComputeHistory: vi.fn(async (podUid: string) => history(podUid)),
  };
}

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

/** `flush` is one poll deep; the history backfill the poll kicks off is
 *  several microtask hops further, and runs in waves of COMPUTE_BACKFILL_CONCURRENCY. */
const settle = async () => {
  await act(async () => {
    for (let i = 0; i < 100; i++) await Promise.resolve();
  });
};

let hiddenValue = false;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(T0);
  hiddenValue = false;
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => hiddenValue });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('useComputeData', () => {
  test('polls latest every 5 s and findings every 15 s', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(api.getComputeLatest).toHaveBeenCalledTimes(1);
    expect(api.getComputeLatest).toHaveBeenCalledWith('payments');
    expect(api.getComputeFindings).toHaveBeenCalledTimes(1);
    expect(api.getComputeFindings).toHaveBeenCalledWith({ namespace: 'payments' });

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(2);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(4);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(2);
  });

  test('pauses while the document is hidden and refreshes at once when shown again', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(api.getComputeLatest).toHaveBeenCalledTimes(1);

    hiddenValue = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(1);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(1);

    hiddenValue = false;
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); });
    await flush();
    expect(api.getComputeLatest).toHaveBeenCalledTimes(2);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(2);
  });
























  test('drops the history of a pod that stopped reporting, but not on one missed poll', async () => {
    let gone = false;
    const api = fakeApi(() => ({ containers: gone ? [] : [container()], nodes: [node()] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.history.has('uid-a')).toBe(true);

    // One absent poll is retention pruning, a truncated row cap, a missed
    // heartbeat — not a dead pod. Its hour of history survives.
    gone = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(result.current.history.has('uid-a')).toBe(true);
    gone = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(result.current.history.has('uid-a')).toBe(true);

    // Gone for good: dropped, so a recycled uid inherits nothing.
    gone = true;
    for (let i = 0; i < COMPUTE_MISSED_POLLS_BEFORE_DROP; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    expect(result.current.history.has('uid-a')).toBe(false);
  });

  test('enabled=false when there are no node rows', async () => {
    const api = fakeApi(() => ({ containers: [], nodes: [] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(false);
  });

  test('enabled=false when every node reports compute_enabled=false', async () => {
    const api = fakeApi(() => ({ containers: [], nodes: [node({ compute_enabled: false }), node({ node: 'worker-2', compute_enabled: false })] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(false);
  });

  test('enabled=true when at least one node has compute on', async () => {
    const api = fakeApi(() => ({ containers: [], nodes: [node({ compute_enabled: false }), node({ node: 'worker-2' })] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(true);
  });

  test('a namespace change resets rows and history and refetches', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    const { result, rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await flush();
    expect(result.current.history.size).toBe(1);
    rerender({ ns: 'batch' });
    await flush();
    expect(api.getComputeLatest).toHaveBeenLastCalledWith('batch');
    expect(api.getComputeFindings).toHaveBeenLastCalledWith({ namespace: 'batch' });
    // The fresh namespace's first poll starts a new buffer (1 sample, not 2).
    expect(result.current.history.get('uid-a')!.length).toBe(1);
  });

  test('surfaces a transient API error without dropping the last good data, keeps polling, clears on recovery', async () => {
    let fail = false;
    const api = {
      getComputeLatest: vi.fn(async () => {
        if (fail) throw new Error('boom');
        return { containers: [container()], nodes: [node()] };
      }),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    fail = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(result.current.error).toBe('boom');
    expect(result.current.supported).toBe(true);
    expect(result.current.containersByPodUid.size).toBe(1);
    fail = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(3);
    expect(result.current.error).toBeNull();
  });

  // Fix #2: an older broker (404 on /compute/*) must not be hammered every
  // 5 s / 15 s with a console.error each time.
  test('404 on a compute endpoint: supported=false, both polls stop, one debug line, no error', async () => {
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const api = {
      getComputeLatest: vi.fn(async () => { throw new ComputeUnsupportedError('/compute/latest'); }),
      getComputeFindings: vi.fn(async () => { throw new ComputeUnsupportedError('/compute/findings'); }),
      getComputeNodes: vi.fn(async () => { throw new ComputeUnsupportedError('/compute/nodes'); }),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.supported).toBe(false);
    expect(result.current.enabled).toBe(false);
    expect(result.current.error).toBeNull();
    const latestCalls = api.getComputeLatest.mock.calls.length;
    const findingsCalls = api.getComputeFindings.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(latestCalls);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(findingsCalls);
    expect(debug).toHaveBeenCalledTimes(1);
    expect(debug.mock.calls[0][0]).toMatch(/compute polling stopped/);
    expect(error).not.toHaveBeenCalled();
  });

  test('a namespace change after 404 tries once more (a cheap retry signal)', async () => {
    vi.spyOn(console, 'debug').mockImplementation(() => {});
    const api = fakeApi(() => { throw new ComputeUnsupportedError('/compute/latest'); });
    const { result, rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await flush();
    expect(result.current.supported).toBe(false);
    const calls = api.getComputeLatest.mock.calls.length;
    rerender({ ns: 'batch' });
    await flush();
    expect(api.getComputeLatest.mock.calls.length).toBe(calls + 1);
    expect(result.current.supported).toBe(false);
  });

  // Fix #5: a response from the previous namespace that lands after the
  // switch must be discarded, and the new namespace's first poll must not be
  // blocked by the old in-flight one.
  test('stale response from the previous namespace is discarded', async () => {
    const pending: Array<(r: ComputeLatestResponse) => void> = [];
    const api = {
      getComputeLatest: vi.fn((ns: string) => new Promise<ComputeLatestResponse>((resolve) => {
        if (ns === 'payments') pending.push(resolve);
        else resolve({ containers: [container({ pod_uid: 'uid-batch', namespace: 'batch', pod_name: 'etl-1' })], nodes: [node()] });
      })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
    };
    const { result, rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await flush();
    expect(pending).toHaveLength(1); // payments' first poll is still in flight
    rerender({ ns: 'batch' });
    await flush();
    // batch's poll was not blocked by payments' in-flight one and has landed.
    expect(result.current.containersByPodUid.has('uid-batch')).toBe(true);
    // Now the old payments response arrives — and changes nothing.
    await act(async () => { pending[0]({ containers: [container()], nodes: [node()] }); await Promise.resolve(); });
    expect(result.current.containersByPodUid.has('uid-a')).toBe(false);
    expect(result.current.containersByPodUid.has('uid-batch')).toBe(true);
    expect(result.current.history.has('uid-a')).toBe(false);
  });

  test('a tab opened in the background loads /compute/nodes on first show, once', async () => {
    hiddenValue = true;
    const api = fakeApi(() => ({ containers: [], nodes: [node()] }), () => ({ findings: [] }), () => [node({ node: 'worker-9', compute_enabled: false })]);
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(api.getComputeNodes).not.toHaveBeenCalled();
    hiddenValue = false;
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); });
    await flush();
    expect(api.getComputeNodes).toHaveBeenCalledTimes(1);
    expect(result.current.nodesByName.get('worker-9')?.compute_enabled).toBe(false);
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); });
    await flush();
    expect(api.getComputeNodes).toHaveBeenCalledTimes(1); // one-shot per namespace session
  });

  // Fix #4: /compute/nodes once per namespace load, so a node with no pod
  // rows in this namespace still has a known state; live rows win.
  test('findings metadata (truncated / victims_evaluated / history_disabled) is normalised and reset per namespace', async () => {
    let meta: ComputeFindingsResponse = { findings: [], truncated: true, victims_evaluated: 500 };
    const api = fakeApi(() => ({ containers: [], nodes: [node()] }), () => meta);
    const { result, rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await flush();
    expect(result.current.findingsMeta).toEqual({ truncated: true, victimsEvaluated: 500, historyDisabled: false });
    meta = { findings: [], history_disabled: true }; // optional fields absent on the wire
    rerender({ ns: 'batch' });
    await flush();
    expect(result.current.findingsMeta).toEqual({ truncated: false, victimsEvaluated: null, historyDisabled: true });
  });

  test('merges the one-shot /compute/nodes rows under the namespace-scoped live rows', async () => {
    const api = fakeApi(
      () => ({ containers: [], nodes: [node({ node: 'worker-1', cpu_cores: 16 })] }),
      () => ({ findings: [] }),
      () => [node({ node: 'worker-1', cpu_cores: 8 }), node({ node: 'worker-9', compute_supported: false })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(api.getComputeNodes).toHaveBeenCalledTimes(1);
    expect(result.current.nodesByName.get('worker-1')?.cpu_cores).toBe(16); // live row wins
    expect(result.current.nodesByName.get('worker-9')?.compute_supported).toBe(false);
    expect(result.current.enabled).toBe(true);
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(api.getComputeNodes).toHaveBeenCalledTimes(1); // once, not polled
    expect(result.current.nodesByName.has('worker-9')).toBe(true); // survives the poll
  });

  // ── Seeding from /compute/history, on demand only ──
  //
  // The sparklines are the only consumer of seeded buckets and render solely
  // under `isExpanded`, so a read is issued when a card is opened and never
  // speculatively for a namespace.









  test('seedPod does nothing when the broker reports history_disabled', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      () => ({ findings: [], history_disabled: true }),
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(result.current.findingsMeta.historyDisabled).toBe(true);
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).not.toHaveBeenCalled();
  });





  test('a failing seed never escapes as an unhandled rejection', async () => {
    const rejections: unknown[] = [];
    const onRejection = (e: PromiseRejectionEvent) => { rejections.push(e.reason); e.preventDefault(); };
    window.addEventListener('unhandledrejection', onRejection);
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => { throw new Error('read budget exhausted'); },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    window.removeEventListener('unhandledrejection', onRejection);
    expect(rejections).toEqual([]);
    expect(result.current.error).toBeNull();
  });


  test('each poll appends a sample at the instant it landed, summing the containers', async () => {
    let cpu = 0;
    const api = fakeApi(() => {
      cpu += 10;
      return {
        containers: [
          container({ cpu_usage_millis: cpu, mem_working_set: 100 }),
          container({ container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis: 5, mem_working_set: 50 }),
        ],
        nodes: [node()],
      };
    });
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.history.get('uid-a')!.values()).toEqual([{ at: T0, cpuMillis: 15, workingSetBytes: 150 }]);

    // Three more polls: four points, five seconds apart, none merged.
    for (let i = 0; i < 3; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.map((x) => x.at)).toEqual([T0, T0 + 5_000, T0 + 10_000, T0 + 15_000]);
    expect(samples[3].cpuMillis).toBe(cpu + 5);
  });

  test('samples older than the window are dropped as the series advances', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    const { result } = renderHook(() => useComputeData('payments', { api, pollMs: 10 * 60_000 }));
    await flush();
    for (let i = 0; i < 7; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(10 * 60_000); });
    }
    const samples = result.current.history.get('uid-a')!.values();
    const newest = samples[samples.length - 1].at;
    expect(newest - samples[0].at).toBeLessThanOrEqual(60 * 60_000);
    expect(samples.every((x) => x.at >= newest - 60 * 60_000)).toBe(true);
  });

  // ── Seeding from /compute/history, on demand and repeatable ──

  test('seedPod fills the series from history, each row at its own instant', async () => {
    const api = fakeApi(
      () => ({ containers: [container({ cpu_usage_millis: 300, mem_working_set: 900 })], nodes: [node()] }),
      undefined,
      undefined,
      () => [
        historyRow({ ts: minutesBefore(3), cpu_usage_millis_last: 10, mem_working_set_last: 100 }),
        historyRow({ ts: minutesBefore(3), container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 5, mem_working_set_last: 50 }),
        historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 20, mem_working_set_last: 200 }),
      ],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).not.toHaveBeenCalled(); // nothing expanded

    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledWith('uid-a', 60);
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.map((x) => x.at)).toEqual([T0 - 180_000, T0 - 120_000, T0]);
    expect(samples[0]).toMatchObject({ cpuMillis: 15, workingSetBytes: 150 }); // both containers
    expect(samples[2]).toMatchObject({ cpuMillis: 300, workingSetBytes: 900 }); // the live sample
  });

  test('an open card does not re-read while the series is already continuous', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7 })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    for (let i = 0; i < 10; i++) {
      await act(async () => { result.current.seedPod('uid-a'); });
      await settle();
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);
  });

  // The bug this design removes: a hidden tab leaves a hole the broker can
  // fill, and a series that could only be seeded once would draw it as an
  // outage for the rest of the session.
  test('a hole left by a hidden tab is seeded again when the card is open', async () => {
    const seeded: string[] = [];
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => {
        seeded.push('read');
        // The broker has the minutes the paused tab missed.
        return Array.from({ length: 20 }, (_, i) =>
          historyRow({ ts: new Date(T0 + (i + 1) * 60_000).toISOString(), cpu_usage_millis_last: 50 + i }));
      },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(seeded).toHaveLength(1);

    hiddenValue = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(21 * 60_000); });
    hiddenValue = false;
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); });
    await settle();
    // A live sample 21 minutes after the last one: a hole nothing has filled.
    expect(result.current.history.get('uid-a')!.length).toBe(2);

    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(seeded).toHaveLength(2);
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.length).toBeGreaterThan(20); // the missed minutes are back
    const gaps = samples.slice(1).map((x, i) => x.at - samples[i].at);
    expect(Math.max(...gaps)).toBeLessThanOrEqual(60_000); // and the hole is closed
  });

  test('a shed read backs off, then succeeds — it is never written off for good', async () => {
    let shed = true;
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => {
        if (shed) throw new Error('503 read budget exhausted');
        return [historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7 })];
      },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);
    expect(result.current.error).toBeNull(); // the banner is about the live poll
    expect(result.current.supported).toBe(true);

    // Asked again immediately: still backing off.
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    shed = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(COMPUTE_SEED_RETRY_MS); });
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);
    expect(result.current.history.get('uid-a')!.values().map((x) => x.cpuMillis)).toContain(7);
  });

  test('consecutive failures back off further each time', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => { throw new Error('503'); },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    const attempt = async (waitMs: number) => {
      await act(async () => { await vi.advanceTimersByTimeAsync(waitMs); });
      await act(async () => { result.current.seedPod('uid-a'); });
      await settle();
      return api.getComputeHistory.mock.calls.length;
    };
    expect(await attempt(0)).toBe(1);
    expect(await attempt(COMPUTE_SEED_RETRY_MS)).toBe(2); // 10 s later
    expect(await attempt(COMPUTE_SEED_RETRY_MS)).toBe(2); // 20 s needed now
    expect(await attempt(COMPUTE_SEED_RETRY_MS)).toBe(3);
  });

  test('a landing read clears only its own in-flight mark', async () => {
    let gone = false;
    const pending: Array<(rows: ComputeHistoryRow[]) => void> = [];
    const api = {
      getComputeLatest: vi.fn(async () => ({ containers: gone ? [] : [container()], nodes: [node()] })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
      getComputeHistory: vi.fn(() => new Promise<ComputeHistoryRow[]>((resolve) => pending.push(resolve))),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); }); // read 1, pending
    await settle();

    gone = true;
    for (let i = 0; i < COMPUTE_MISSED_POLLS_BEFORE_DROP; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    gone = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); }); // read 2, pending
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);

    await act(async () => { pending[0]([]); }); // read 1 lands, for a pod long gone
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2); // read 2 is still in flight
  });

  test('a read that lands after the pod was replaced does not seed the new series', async () => {
    let gone = false;
    const pending: Array<(rows: ComputeHistoryRow[]) => void> = [];
    const api = {
      getComputeLatest: vi.fn(async () => ({ containers: gone ? [] : [container()], nodes: [node()] })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
      getComputeHistory: vi.fn(() => new Promise<ComputeHistoryRow[]>((resolve) => pending.push(resolve))),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();

    gone = true;
    for (let i = 0; i < COMPUTE_MISSED_POLLS_BEFORE_DROP; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    expect(result.current.history.has('uid-a')).toBe(false);
    gone = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();

    await act(async () => { pending[0]([historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 999 })]); });
    await settle();
    expect(result.current.history.get('uid-a')!.values().some((x) => x.cpuMillis === 999)).toBe(false);
  });

  test('a slow read keeps the live samples collected while it was in flight', async () => {
    const pending: Array<(rows: ComputeHistoryRow[]) => void> = [];
    const api = {
      getComputeLatest: vi.fn(async () => ({ containers: [container()], nodes: [node()] })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
      getComputeHistory: vi.fn(() => new Promise<ComputeHistoryRow[]>((resolve) => pending.push(resolve))),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    for (let i = 0; i < 3; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    expect(result.current.history.get('uid-a')!.length).toBe(4);

    await act(async () => { pending[0]([historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7 })]); });
    await settle();
    expect(result.current.history.get('uid-a')!.values().map((x) => x.at)).toEqual([
      T0 - 120_000, T0, T0 + 5_000, T0 + 10_000, T0 + 15_000,
    ]);
  });

  test('seedPod does nothing when the broker reports history_disabled', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      () => ({ findings: [], history_disabled: true }),
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(result.current.findingsMeta.historyDisabled).toBe(true);
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).not.toHaveBeenCalled();
  });

  test('404 on /compute/history leaves the live poll running and the map populated', async () => {
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => { throw new ComputeUnsupportedError('/compute/history'); },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(result.current.supported).toBe(true);
    expect(result.current.enabled).toBe(true);
    expect(result.current.error).toBeNull();
    expect(result.current.containersByPodUid.size).toBe(1);
    expect(debug).toHaveBeenCalledTimes(1);
    expect(debug.mock.calls[0][0]).toMatch(/live samples only/);
    expect(error).not.toHaveBeenCalled();

    const latestCalls = api.getComputeLatest.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeLatest.mock.calls.length).toBeGreaterThan(latestCalls);
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1); // seeding is over for this session
  });

  test('a namespace change lets its pods be seeded again', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7 })],
    );
    const { result, rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    rerender({ ns: 'batch' });
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);
  });

  test('a failing seed never escapes as an unhandled rejection', async () => {
    const rejections: unknown[] = [];
    const onRejection = (e: PromiseRejectionEvent) => { rejections.push(e.reason); e.preventDefault(); };
    window.addEventListener('unhandledrejection', onRejection);
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => { throw new Error('read budget exhausted'); },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    window.removeEventListener('unhandledrejection', onRejection);
    expect(rejections).toEqual([]);
    expect(result.current.error).toBeNull();
  });

});
