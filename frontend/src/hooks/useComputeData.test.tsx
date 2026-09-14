// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { COMPUTE_BACKFILL_MAX_ATTEMPTS, COMPUTE_BACKFILL_MAX_PODS, COMPUTE_MISSED_POLLS_BEFORE_DROP, useComputeData } from './useComputeData';
import { ComputeUnsupportedError } from '../services/api';
import type { ComputeContainer, ComputeFindingsResponse, ComputeHistoryRow, ComputeLatestResponse, ComputeNode } from '../types/compute';

// Contract (design D8 / wire contract): 5 s poll of latest, 15 s poll of
// findings, paused while the tab is hidden, 60 one-minute buckets per pod
// summing the pod's containers — seeded once from /compute/history so an
// expanded node opens on real trend — and `enabled=false` when no node reports.

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

  test('folds the 5 s polls into one-minute buckets, summing the pod containers', async () => {
    let cpu = 0;
    const api = fakeApi(() => {
      cpu += 10;
      return {
        containers: [
          container({ container_uid: 'uid-a/app', cpu_usage_millis: cpu, mem_working_set: 100 }),
          container({ container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis: 5, mem_working_set: 50 }),
        ],
        nodes: [node()],
      };
    });
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(true);
    expect(result.current.containersByPodUid.get('uid-a')).toHaveLength(2);
    expect(result.current.containersByPodName.get('payments/api-1')).toHaveLength(2);
    const first = result.current.history.get('uid-a')!.values();
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ at: T0, cpuMillis: 15, workingSetBytes: 150 });

    // Eleven more polls inside the same minute upsert that one bucket; the
    // newest poll is what the gauges read.
    for (let i = 0; i < 11; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    const sameMinute = result.current.history.get('uid-a')!.values();
    expect(sameMinute).toHaveLength(1);
    expect(sameMinute[0]).toMatchObject({ at: T0, cpuMillis: cpu + 5 });

    // The twelfth crosses the minute: a new bucket, one minute along.
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    const rolled = result.current.history.get('uid-a')!.values();
    expect(rolled).toHaveLength(2);
    expect(rolled[0].at).toBe(T0);
    expect(rolled[1]).toMatchObject({ at: T0 + 60_000, cpuMillis: cpu + 5 });
  });

  test('keeps the last 60 buckets — an hour — oldest first', async () => {
    let cpu = 0;
    // One poll per bucket: the fold is the same, without 720 polls of it.
    const api = fakeApi(() => {
      cpu += 10;
      return { containers: [container({ cpu_usage_millis: cpu, mem_working_set: 100 })], nodes: [node()] };
    });
    const { result } = renderHook(() => useComputeData('payments', { api, pollMs: 60_000 }));
    await flush();
    for (let i = 0; i < 70; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    }
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples).toHaveLength(60);
    expect(samples[59]).toMatchObject({ at: T0 + 70 * 60_000, cpuMillis: cpu });
    expect(samples[0]).toMatchObject({ at: T0 + 11 * 60_000, cpuMillis: cpu - 59 * 10 });
  });

  // A hidden tab pauses the poll. Six hours later the buffer must not still
  // be holding six-hour-old buckets under a "last 60 minutes" heading —
  // capacity alone never evicts them, because nothing pushed them out.
  test('drops buckets that aged out while polling was paused', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    for (let i = 0; i < 3; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    }
    expect(result.current.history.get('uid-a')!.length).toBe(4);

    hiddenValue = true;
    const paused = api.getComputeLatest.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(6 * 60 * 60_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(paused); // paused, as designed

    hiddenValue = false;
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); });
    await flush();
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples).toHaveLength(1); // the resume sample only
    expect(samples[0].at).toBe(T0 + 6 * 60 * 60_000 + 3 * 60_000);
  });

  // The point of the feature: expanding a node must show a trend at once,
  // not an empty chart that draws itself over the next five minutes.
  test('seeds a pod buffer from /compute/history, summing containers per bucket', async () => {
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
    expect(api.getComputeHistory).toHaveBeenCalledWith('uid-a', 60);
    const samples = result.current.history.get('uid-a')!.values();
    // A minute row is stamped at the END of the minute it folds, so a row at
    // T0-3min carries the minute starting at T0-4min.
    expect(samples.map((s) => s.at)).toEqual([T0 - 240_000, T0 - 180_000, T0]);
    expect(samples[0]).toMatchObject({ cpuMillis: 15, workingSetBytes: 150 }); // both containers
    expect(samples[1]).toMatchObject({ cpuMillis: 20, workingSetBytes: 200 });
    expect(samples[2]).toMatchObject({ cpuMillis: 300, workingSetBytes: 900 }); // the live bucket
  });

  test('a history bucket for the live minute loses to the live sample', async () => {
    const api = fakeApi(
      () => ({ containers: [container({ cpu_usage_millis: 300, mem_working_set: 900 })], nodes: [node()] }),
      undefined,
      undefined,
      // A fold that closed half a minute into the current bucket: it covers
      // the tail of the previous minute and the live one.
      () => [historyRow({ ts: new Date(T0 + 30_000).toISOString(), cpu_usage_millis_last: 11, mem_working_set_last: 22 })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.map((s) => s.at)).toEqual([T0]);
    expect(samples[0]).toMatchObject({ cpuMillis: 300, workingSetBytes: 900 }); // live wins the collision
  });

  // History reads run four at a time against a budgeted endpoint, so the last
  // can land minutes after the first. The seed has to merge against the
  // buffer as it is AT COMMIT TIME: buckets the live poll collected while the
  // read was in flight are the newest data there is, and `pushBucketed` can
  // never put them back once something newer has replaced them.
  test('a slow history read does not discard live buckets collected while it was in flight', async () => {
    // Two pods, so one read can land well before the batch commits — the
    // window in which the live poll keeps filling the first pod's buffer.
    const pending: Array<(rows: ComputeHistoryRow[]) => void> = [];
    const api = {
      getComputeLatest: vi.fn(async () => ({
        containers: [container(), container({ container_uid: 'uid-b/app', pod_uid: 'uid-b', pod_name: 'api-2' })],
        nodes: [node()],
      })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
      getComputeHistory: vi.fn(() => new Promise<ComputeHistoryRow[]>((resolve) => pending.push(resolve))),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(pending).toHaveLength(2); // uid-a, uid-b

    await act(async () => {
      pending[0]([historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7, mem_working_set_last: 70 })]);
    });
    await settle();

    // Three more minutes of live polling before the second read lands.
    for (let i = 0; i < 3; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    }
    expect(result.current.history.get('uid-a')!.length).toBe(4);

    await act(async () => { pending[1]([]); }); // the batch commits here
    await settle();
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.map((s) => s.at)).toEqual([
      T0 - 180_000, T0, T0 + 60_000, T0 + 120_000, T0 + 180_000, // seeded, then the four live
    ]);
    expect(samples[0].cpuMillis).toBe(7); // the seeded minute
    expect(samples[4].at).toBe(T0 + 180_000); // the newest live bucket survived the commit
  });

  test('a history read that lands after the pod was replaced does not seed the new buffer', async () => {
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

    // The pod goes away long enough to be dropped, then a new pod arrives on
    // the same uid and gets a fresh buffer.
    gone = true;
    for (let i = 0; i < COMPUTE_MISSED_POLLS_BEFORE_DROP; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    expect(result.current.history.has('uid-a')).toBe(false);
    gone = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();

    // The first pod's history finally arrives: the new pod must not inherit it.
    await act(async () => {
      pending[0]([historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 999 })]);
    });
    await settle();
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.some((s) => s.cpuMillis === 999)).toBe(false);
  });

  // Without an in-flight guard every 5 s poll re-issues a read for a pod
  // whose first one is still pending and spends another attempt on it, so
  // three polls exhaust the retry budget before anything has failed.
  test('does not re-issue a history read while one is still in flight', async () => {
    const pending: Array<{ reject: (e: unknown) => void }> = [];
    const api = {
      getComputeLatest: vi.fn(async () => ({ containers: [container()], nodes: [node()] })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
      getComputeHistory: vi.fn(() => new Promise<ComputeHistoryRow[]>((_resolve, reject) => pending.push({ reject }))),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    // Four more polls while the first read is outstanding.
    for (let i = 0; i < 4; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
      await settle();
    }
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    // The read finally sheds. The pod has spent ONE attempt, not five, so
    // the next poll still retries it.
    await act(async () => { pending[0].reject(new Error('503 shed')); });
    await settle();
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);
    expect(result.current.supported).toBe(true);
  });

  // The call sites are deliberately un-awaited and the limiter is fail-fast,
  // so a failing seed must stay a no-op. Every reachable failure is already
  // caught per pod; the outer guard exists so that stays true if it is not.
  test('a failing backfill never escapes as an unhandled rejection', async () => {
    const rejections: unknown[] = [];
    const onRejection = (e: PromiseRejectionEvent) => { rejections.push(e.reason); e.preventDefault(); };
    window.addEventListener('unhandledrejection', onRejection);
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
    // The limiter is fail-fast and rethrows; nothing may leak from the
    // deliberately un-awaited call sites.
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => { throw new Error('read budget exhausted'); },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    await settle();
    window.removeEventListener('unhandledrejection', onRejection);
    expect(rejections).toEqual([]);
    expect(result.current.error).toBeNull();
    expect(debug.mock.calls.every((c) => !String(c[0]).includes('backfill failed'))).toBe(true);
  });

  // Once the cap is reached the scan must keep going for pods already
  // counted, or a retry is skipped purely because new pods sort ahead of it.
  test('the cap blocks new pods without skipping retries for counted ones', async () => {
    let crowded = false;
    let shed = true;
    const api = fakeApi(
      () => ({
        containers: [
          // The new pods come FIRST, so a `break` at the cap never reaches
          // uid-a — which was counted on the first poll and is owed a retry.
          ...(crowded
            ? Array.from({ length: COMPUTE_BACKFILL_MAX_PODS }, (_, i) =>
                container({ container_uid: `uid-0${i}/app`, pod_uid: `uid-0${i}`, pod_name: `aaa-${i}` }))
            : []),
          container(),
        ],
        nodes: [node()],
      }),
      undefined,
      undefined,
      (podUid) => {
        if (podUid === 'uid-a' && shed) throw new Error('503 shed');
        return [];
      },
    );
    renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory.mock.calls.filter((c) => c[0] === 'uid-a').length).toBe(1);

    crowded = true;
    shed = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();
    expect(api.getComputeHistory.mock.calls.filter((c) => c[0] === 'uid-a').length).toBe(2);
  });

  // Seeding on demand is what makes the eager cap tolerable: a card the user
  // opens must fill from stored history even when the cap excluded its pod.
  test('seedPod seeds a pod the cap excluded, with exactly one read', async () => {
    const overCap = Array.from({ length: COMPUTE_BACKFILL_MAX_PODS + 1 }, (_, i) =>
      container({ container_uid: `uid-${i}/app`, pod_uid: `uid-${i}`, pod_name: `api-${i}` }));
    const last = `uid-${COMPUTE_BACKFILL_MAX_PODS}`;
    const api = fakeApi(
      () => ({ containers: overCap, nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7, mem_working_set_last: 70 })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(COMPUTE_BACKFILL_MAX_PODS);
    expect(api.getComputeHistory.mock.calls.some((c) => c[0] === last)).toBe(false);
    expect(result.current.history.get(last)!.length).toBe(1); // live only

    await act(async () => { result.current.seedPod(last); });
    await settle();
    expect(api.getComputeHistory.mock.calls.filter((c) => c[0] === last).length).toBe(1);
    const samples = result.current.history.get(last)!.values();
    expect(samples.map((s) => s.cpuMillis)).toContain(7);
    expect(samples.length).toBe(2); // the seeded minute plus the live one
  });

  test('seedPod is a no-op for a pod already seeded', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ cpu_usage_millis_last: 7 })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1); // the eager backfill

    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);
  });

  test('seedPod does not double-fetch a pod whose read is already in flight', async () => {
    const pending: Array<(rows: ComputeHistoryRow[]) => void> = [];
    const api = {
      getComputeLatest: vi.fn(async () => ({ containers: [container()], nodes: [node()] })),
      getComputeFindings: vi.fn(async () => ({ findings: [] })),
      getComputeNodes: vi.fn(async () => []),
      getComputeHistory: vi.fn(() => new Promise<ComputeHistoryRow[]>((resolve) => pending.push(resolve))),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1); // eager read, still pending

    await act(async () => { result.current.seedPod('uid-a'); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    // And once it lands, the expansion still has its history.
    await act(async () => { pending[0]([historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7 })]); });
    await settle();
    expect(result.current.history.get('uid-a')!.values().map((s) => s.cpuMillis)).toContain(7);
  });

  // A clock step that leaves the buffer empty costs an hour that a windowed
  // broker read paid for; the pod must become seedable again.
  test('re-opens seeding for a pod whose series restarted after a clock step', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7 })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);
    expect(result.current.history.get('uid-a')!.length).toBe(2);

    vi.setSystemTime(T0 - 30 * 60_000); // NTP correction, half an hour back
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();
    expect(result.current.history.get('uid-a')!.length).toBe(1); // the series restarted
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2); // and is seeded again
  });

  test('seeds each pod once per namespace session, and starts over on a namespace change', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ cpu_usage_millis_last: 7 })],
    );
    const { rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    // Three more polls of the same pod: seeded already, so no second read.
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    rerender({ ns: 'batch' });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);
  });

  test('caps the backfill, so a big namespace does not fire a read per pod', async () => {
    const many = Array.from({ length: COMPUTE_BACKFILL_MAX_PODS + 10 }, (_, i) =>
      container({ container_uid: `uid-${i}/app`, pod_uid: `uid-${i}`, pod_name: `api-${i}` }));
    const api = fakeApi(() => ({ containers: many, nodes: [node()] }));
    renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(COMPUTE_BACKFILL_MAX_PODS);
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(COMPUTE_BACKFILL_MAX_PODS); // and stays capped
  });

  // A broker that serves /compute/latest but predates /compute/history. The
  // seed is optional decoration; killing `supported` for it would take every
  // gauge, micro bar, status dot and finding off the map with it.
  // The cap has to count pods EVER asked for, not pods currently tracked:
  // bookkeeping for a pod that goes away is dropped so it can be seeded if it
  // returns, so a churning namespace would otherwise never reach the cap and
  // would keep issuing history reads for the life of the session.
  test('the backfill cap holds under pod churn', async () => {
    let wave = 0;
    const api = fakeApi(() => ({
      containers: Array.from({ length: 10 }, (_, i) =>
        container({ container_uid: `uid-${wave}-${i}/app`, pod_uid: `uid-${wave}-${i}`, pod_name: `api-${i}` })),
      nodes: [node()],
    }));
    renderHook(() => useComputeData('payments', { api }));
    await settle();

    // Six complete turnovers — 70 distinct pods, well past the 40-pod cap.
    for (let next = 1; next <= 6; next++) {
      wave = next;
      for (let poll = 0; poll <= COMPUTE_MISSED_POLLS_BEFORE_DROP; poll++) {
        await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
        await settle();
      }
    }
    expect(api.getComputeHistory.mock.calls.length).toBe(COMPUTE_BACKFILL_MAX_PODS);
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
    expect(result.current.supported).toBe(true);
    expect(result.current.enabled).toBe(true);
    expect(result.current.error).toBeNull();
    expect(result.current.containersByPodUid.size).toBe(1);
    expect(debug).toHaveBeenCalledTimes(1);
    expect(debug.mock.calls[0][0]).toMatch(/live samples only/);
    expect(error).not.toHaveBeenCalled();

    // The 5 s poll keeps running, the sparkline keeps filling from it, and
    // history is not asked again this session.
    const latestCalls = api.getComputeLatest.mock.calls.length;
    const historyCalls = api.getComputeHistory.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    await settle();
    expect(api.getComputeLatest.mock.calls.length).toBeGreaterThan(latestCalls);
    expect(api.getComputeHistory).toHaveBeenCalledTimes(historyCalls);
    expect(result.current.history.get('uid-a')!.length).toBe(2);
    expect(result.current.supported).toBe(true);
  });

  // retentionDays: 0 — every history read is charged a permit and comes back
  // empty, so 40 of them per namespace buy nothing and can shed other reads.
  test('does not backfill when the findings poll reports history_disabled', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      () => ({ findings: [], history_disabled: true }),
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(result.current.findingsMeta.historyDisabled).toBe(true);
    expect(api.getComputeHistory).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    await settle();
    expect(api.getComputeHistory).not.toHaveBeenCalled();
    expect(result.current.history.get('uid-a')!.length).toBeGreaterThan(0); // live still fills
  });

  test('a pod that stops reporting and comes back is seeded again', async () => {
    let gone = false;
    const api = fakeApi(
      () => ({ containers: gone ? [] : [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ cpu_usage_millis_last: 7 })],
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(1);

    gone = true;
    for (let i = 0; i < COMPUTE_MISSED_POLLS_BEFORE_DROP; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    await settle();
    expect(result.current.history.has('uid-a')).toBe(false);

    gone = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);
  });

  // `history` is a dependency of the pods memo in usePodData, so each commit
  // rebuilds every pod's compute data and repaints the map.
  test('commits the whole backfill batch once, not once per pod', async () => {
    const many = Array.from({ length: 12 }, (_, i) =>
      container({ container_uid: `uid-${i}/app`, pod_uid: `uid-${i}`, pod_name: `api-${i}` }));
    const api = fakeApi(
      () => ({ containers: many, nodes: [node()] }),
      undefined,
      undefined,
      () => [historyRow({ cpu_usage_millis_last: 7 })],
    );
    const seen = new Set<unknown>();
    renderHook(() => {
      const data = useComputeData('payments', { api });
      seen.add(data.history);
      return data;
    });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(12);
    // The initial empty map, the poll's, and one for the whole batch.
    expect(seen.size).toBe(3);
  });

  test('a failed history read leaves that pod live-only and the map untouched', async () => {
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => { throw new Error('read budget exhausted'); },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(result.current.error).toBeNull(); // the banner is about the live poll
    expect(result.current.supported).toBe(true);
    expect(result.current.history.get('uid-a')!.values()).toEqual([
      { at: T0, cpuMillis: 100, workingSetBytes: 800 },
    ]);

    // It keeps filling from the poll, and the retries are bounded rather
    // than one per 5 s poll forever.
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    await settle();
    expect(result.current.history.get('uid-a')!.length).toBe(2);
    expect(api.getComputeHistory).toHaveBeenCalledTimes(COMPUTE_BACKFILL_MAX_ATTEMPTS);
  });

  // The broker sheds a read that does not fit its budget with a retryable
  // 503, and that is likeliest exactly at namespace load. Giving up on the
  // first one would deny the whole namespace its history for the session.
  test('retries a shed history read and seeds the pod when it succeeds', async () => {
    let sheds = 1;
    const api = fakeApi(
      () => ({ containers: [container()], nodes: [node()] }),
      undefined,
      undefined,
      () => {
        if (sheds-- > 0) throw new Error('503 read budget exhausted');
        return [historyRow({ ts: minutesBefore(2), cpu_usage_millis_last: 7, mem_working_set_last: 70 })];
      },
    );
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await settle();
    expect(result.current.history.get('uid-a')!.length).toBe(1); // live only, so far

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    await settle();
    expect(api.getComputeHistory).toHaveBeenCalledTimes(2);
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples.map((s) => s.cpuMillis)).toContain(7); // the seed landed on the retry
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
});
