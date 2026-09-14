import { describe, expect, test } from 'vitest';
import {
  COMPUTE_BUCKET_MS,
  COMPUTE_HISTORY_SAMPLES,
  COMPUTE_HISTORY_WINDOW_LABEL,
  COMPUTE_HISTORY_WINDOW_MINUTES,
  COMPUTE_STATE_OFF,
  COMPUTE_STATE_PENDING,
  COMPUTE_STATE_UNSUPPORTED,
  NODE_HEIGHT_BASE,
  NODE_HEIGHT_EXPANDED,
  NODE_HEIGHT_GAUGE_ROW,
  NODE_HEIGHT_SPARKLINES,
  RingBuffer,
  buildPodComputeData,
  bucketStart,
  containersForNode,
  denseSeries,
  formatBytes,
  formatMicros,
  formatMillicores,
  hasComputeGauges,
  historySamples,
  nodeComputeState,
  nodeHeight,
  pickDenominator,
  podLevelSample,
  pushBucketed,
  seedHistory,
  statusFromFindings,
  statusTooltip,
  throttledRatio,
} from './compute';
import type { ComputeContainer, ComputeFinding, ComputeHistoryRow, ComputeNode, ComputeSample } from '../types/compute';
import type { PodInfo } from '../types';

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
const node = (over: Partial<ComputeNode> = {}): ComputeNode => ({
  node: 'worker-1', ts: 't', interval_ms: 5000, ctxt_per_sec: 0,
  compute_enabled: true, compute_supported: true, contention_loaded: false,
  cpu_some10: 0, cpu_full10: 0, mem_some10: 0, mem_full10: 0, cpu_cores: 4, memory_bytes: 8000,
  bpf_runq_enqueued: 0, bpf_runq_hist: 0, bpf_pair: 0, unknown_blame_share: 0, updated_at: 't', ...over,
});
const finding = (severity: ComputeFinding['severity'], kind: ComputeFinding['kind'] = 'cpu-throttled'): ComputeFinding => ({
  kind, severity,
  victim: { pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', container_uid: 'uid-a/app', node: 'worker-1' },
  culprit: null,
  evidence: { window_minutes: 5, cpu_psi_some10_max: 0, cpu_psi_full10_max: 0, runq_p99_us_max: null, throttled_ratio: 0.3, mem_psi_some10_max: 0, node_mem_some10_max: 0, refault_delta: 0, mem_events_high_delta: 0 },
  first_seen: 't', last_seen: 't', message: 'm',
});

describe('nodeHeight (design D8: a function of expansion AND compute presence)', () => {
  test('collapsed, no compute = the pre-feature height', () => {
    expect(nodeHeight({ isExpanded: false, hasCompute: false })).toBe(100);
    expect(NODE_HEIGHT_BASE).toBe(100);
  });
  test('each state adds its rows, in a strict order', () => {
    const c = nodeHeight({ isExpanded: false, hasCompute: false });
    const cg = nodeHeight({ isExpanded: false, hasCompute: true });
    const e = nodeHeight({ isExpanded: true, hasCompute: false });
    const eg = nodeHeight({ isExpanded: true, hasCompute: true });
    expect(cg).toBe(c + NODE_HEIGHT_GAUGE_ROW);
    expect(e).toBe(c + NODE_HEIGHT_EXPANDED);
    expect(eg).toBe(c + NODE_HEIGHT_GAUGE_ROW + NODE_HEIGHT_EXPANDED + NODE_HEIGHT_SPARKLINES);
    expect(c).toBeLessThan(cg);
    expect(cg).toBeLessThan(e);
    expect(e).toBeLessThan(eg);
  });
});

describe('RingBuffer', () => {
  test('keeps the last N, oldest first', () => {
    const b = new RingBuffer<number>(3);
    [1, 2, 3, 4, 5].forEach((n) => b.push(n));
    expect(b.values()).toEqual([3, 4, 5]);
    expect(b.length).toBe(3);
    expect(b.last()).toBe(5);
  });
  test('values() is a copy', () => {
    const b = new RingBuffer<number>(3);
    b.push(1);
    const v = b.values();
    v.push(99);
    expect(b.values()).toEqual([1]);
  });
  test('replaceLast overwrites the newest without growing, and is a no-op when empty', () => {
    const b = new RingBuffer<number>(3);
    b.replaceLast(9);
    expect(b.values()).toEqual([]);
    b.push(1);
    b.push(2);
    b.replaceLast(22);
    expect(b.values()).toEqual([1, 22]);
  });
});

// The window the sparklines draw: 60 one-minute buckets, seeded from the
// broker's minute history rows and kept current by the 5 s poll.
describe('history bucketing', () => {
  const T0 = Date.parse('2026-09-14T10:00:00Z');
  const sample = (at: number, cpuMillis: number, workingSetBytes = 0): ComputeSample => ({ at, cpuMillis, workingSetBytes });

  test('the window constants and label agree', () => {
    expect(COMPUTE_BUCKET_MS).toBe(60_000);
    expect(COMPUTE_HISTORY_SAMPLES).toBe(60);
    expect(COMPUTE_HISTORY_WINDOW_MINUTES).toBe(60); // what the backfill asks for
    expect(COMPUTE_HISTORY_WINDOW_LABEL).toBe('last 60 minutes');
  });

  test('bucketStart floors to the minute', () => {
    expect(bucketStart(T0)).toBe(T0);
    expect(bucketStart(T0 + 59_999)).toBe(T0);
    expect(bucketStart(T0 + 60_000)).toBe(T0 + 60_000);
  });

  test('pushBucketed upserts inside a bucket and pushes on rollover', () => {
    const b = new RingBuffer<ComputeSample>(3);
    pushBucketed(b, sample(T0 + 1_000, 10));
    pushBucketed(b, sample(T0 + 6_000, 20));
    expect(b.values()).toEqual([sample(T0, 20)]); // same minute: last poll wins, keyed by bucket
    pushBucketed(b, sample(T0 + 61_000, 30));
    expect(b.values()).toEqual([sample(T0, 20), sample(T0 + 60_000, 30)]);
  });

  // Capacity alone cannot bound a window: a sparse series holds `capacity`
  // buckets spanning far more than `capacity` minutes, and a buffer that
  // stopped being pushed keeps whatever it had for as long as nobody pushes.
  test('pushBucketed evicts by age, not only by count', () => {
    const b = new RingBuffer<ComputeSample>(60);
    pushBucketed(b, sample(T0, 1));
    pushBucketed(b, sample(T0 + 60_000, 2));
    pushBucketed(b, sample(T0 + 6 * 60 * 60_000, 3)); // six hours later
    expect(b.values()).toEqual([sample(T0 + 6 * 60 * 60_000, 3)]);
  });

  test('pushBucketed keeps exactly the last hour of a sparse series', () => {
    const b = new RingBuffer<ComputeSample>(60);
    // One sample every five minutes: 60 of them would span five hours.
    for (let i = 0; i < 60; i++) pushBucketed(b, sample(T0 + i * 5 * 60_000, i));
    const kept = b.values();
    const newest = kept[kept.length - 1].at;
    expect(kept).toHaveLength(12); // only the last hour's worth
    expect(kept[0].at).toBeGreaterThanOrEqual(newest - 59 * 60_000);
  });

  // An NTP correction or a laptop waking moves the clock back. Dropping
  // every "past" sample would freeze the chart AND the gauge reading beside
  // it for as long as the step, with nothing to show why.
  test('a backward clock step discards only the buckets it put in the future', () => {
    const b = new RingBuffer<ComputeSample>(60);
    for (let i = 0; i < 10; i++) pushBucketed(b, sample(T0 + i * 60_000, i));
    // Two minutes back: an hour of seeded history must not be the price.
    expect(pushBucketed(b, sample(T0 + 7 * 60_000, 99))).toBe('upserted');
    expect(b.values().map((s) => s.cpuMillis)).toEqual([0, 1, 2, 3, 4, 5, 6, 99]);
    expect(pushBucketed(b, sample(T0 + 8 * 60_000, 100))).toBe('pushed'); // carries on
    expect(b.length).toBe(9);
  });

  test('a step past everything held restarts the series and says so', () => {
    const b = new RingBuffer<ComputeSample>(60);
    pushBucketed(b, sample(T0, 1));
    pushBucketed(b, sample(T0 + 60_000, 2));
    expect(pushBucketed(b, sample(T0 - 10 * 60_000, 3))).toBe('restarted');
    expect(b.values()).toEqual([sample(T0 - 10 * 60_000, 3)]);
  });

  test('pushBucketed drops a sample older than the newest bucket', () => {
    const b = new RingBuffer<ComputeSample>(3);
    pushBucketed(b, sample(T0 + 60_000, 10));
    expect(pushBucketed(b, sample(T0, 99))).toBe('dropped'); // jitter / a late arrival
    expect(b.values()).toEqual([sample(T0 + 60_000, 10)]);
  });

  const row = (over: Partial<ComputeHistoryRow>): ComputeHistoryRow => ({
    id: 1, container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1',
    ts: new Date(T0).toISOString(), resolution_secs: 60,
    cpu_usage_millis_avg: 0, cpu_usage_millis_max: 0, cpu_usage_millis_last: 0,
    cpu_quota_usec: null, cpu_period_usec: 100000, cpu_request_millis: null, cpu_limit_millis: null,
    cpu_nr_periods: 0, cpu_nr_throttled: 0, cpu_throttled_usec: 0,
    cpu_psi_some10_avg: 0, cpu_psi_some10_max: 0, cpu_psi_full10_avg: 0, cpu_psi_full10_max: 0,
    mem_current_avg: 0, mem_current_max: 0, mem_current_last: 0,
    mem_working_set_avg: 0, mem_working_set_max: 0, mem_working_set_last: 0,
    mem_limit: null, mem_request: null,
    mem_psi_some10_avg: 0, mem_psi_some10_max: 0, mem_psi_full10_avg: 0, mem_psi_full10_max: 0,
    mem_events_high: 0, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 0, mem_pgmajfault: 0,
    runq_count: null, runq_p50_us: null, runq_p95_us: null, runq_p99_us: null, runq_max_us: null, runq_overflow: null, runq_hist: null,
    ...over,
  });

  test('historySamples sums the pod containers per bucket, oldest first, on `_last`', () => {
    const samples = historySamples([
      row({ ts: new Date(T0 + 60_000).toISOString(), cpu_usage_millis_last: 7, mem_working_set_last: 70, cpu_usage_millis_avg: 999 }),
      row({ cpu_usage_millis_last: 10, mem_working_set_last: 100 }),
      row({ container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 5, mem_working_set_last: 50 }),
      row({ ts: 'not-a-timestamp', cpu_usage_millis_last: 1_000 }), // never NaNs the series
    ]);
    // Minute rows are stamped at the END of the minute they fold, so a row
    // at T0 carries the minute that ended there — the bucket before it.
    expect(samples).toEqual([sample(T0 - 60_000, 15, 150), sample(T0, 7, 70)]);
  });

  // The controller closes a fold on its Nth sample, not on a wall-clock
  // boundary (`MinuteFold::finish` stamps the last sample's ts), so stamps
  // drift across minute boundaries. Flooring them would invent holes where
  // two consecutive rows straddle a boundary, and collide two rows into one
  // bucket just as often — both of which the sparkline would draw as fact.
  test('historySamples follows drifting minute stamps without holes or collisions', () => {
    const at = (hhmmss: string) => Date.parse(`2026-09-14T${hhmmss}Z`);
    const samples = historySamples([
      row({ ts: new Date(at('10:05:59')).toISOString(), cpu_usage_millis_last: 1 }),
      row({ ts: new Date(at('10:07:00')).toISOString(), cpu_usage_millis_last: 2 }),
      row({ ts: new Date(at('10:07:58')).toISOString(), cpu_usage_millis_last: 3 }),
    ]);
    // Consecutive rows → consecutive minutes, each keeping its OWN
    // measurement: every row lands in the single bucket holding its
    // midpoint, so nothing is overwritten by a neighbour and no minute
    // shows a value that was never measured for it.
    expect(samples.map((s) => s.at)).toEqual([at('10:05:00'), at('10:06:00'), at('10:07:00')]);
    expect(samples.map((s) => s.cpuMillis)).toEqual([1, 2, 3]);
  });

  // The broker emits `Z` today, but its own deserialiser accepts zone-less
  // stamps, so the contract is asymmetric — and `Date.parse` would read one
  // as local time, silently moving every sample by the viewer's offset.
  test('historySamples reads a zone-less broker stamp as UTC', () => {
    const withZone = historySamples([row({ ts: '2026-09-14T10:05:30Z', cpu_usage_millis_last: 5 })]);
    const zoneLess = historySamples([row({ ts: '2026-09-14T10:05:30', cpu_usage_millis_last: 5 })]);
    expect(zoneLess).toEqual(withZone);
    expect(zoneLess[0].at).toBe(Date.parse('2026-09-14T10:05:00Z'));
  });

  // A fold closes on its Nth sample, so each one spans 60 s plus the lag it
  // accumulated and the stamps creep forward. Every ~30th pair of midpoints
  // steps over a bucket; left unclaimed it renders as a break in the line —
  // an outage on a pod that never had one.
  test('historySamples closes the holes drift opens, without moving measurements', () => {
    const first = Date.parse('2026-09-14T10:00:29Z');
    // 62 s apart: the sampler running a couple of seconds behind the minute.
    const rows = Array.from({ length: 40 }, (_, i) =>
      row({ ts: new Date(first + i * 62_000).toISOString(), cpu_usage_millis_last: i }));
    const samples = historySamples(rows);

    // Every minute between the first and last is present: no phantom gaps.
    const ats = samples.map((s) => s.at);
    for (let i = 1; i < ats.length; i++) expect(ats[i] - ats[i - 1]).toBe(60_000);
    expect(ats.length).toBeGreaterThan(40); // drift means more minutes than rows

    // And every row's own measurement still appears exactly where it was
    // measured — the fills only closed minutes no row claimed.
    const byBucket = new Map(samples.map((s) => [s.at, s.cpuMillis]));
    for (const [i, r] of rows.entries()) {
      const mid = Date.parse(r.ts) - 30_000;
      expect(byBucket.get(Math.floor(mid / 60_000) * 60_000)).toBe(i);
    }
  });

  test('historySamples leaves a real outage empty', () => {
    const at = (hhmm: string) => Date.parse(`2026-09-14T${hhmm}:00Z`);
    const samples = historySamples([
      row({ ts: new Date(at('10:01')).toISOString(), cpu_usage_millis_last: 1 }),
      row({ ts: new Date(at('10:35')).toISOString(), cpu_usage_millis_last: 2 }), // node was away
    ]);
    expect(samples.map((s) => s.at)).toEqual([at('10:00'), at('10:34')]);
    expect(samples).toHaveLength(2); // the 33 minutes between stay empty
  });

  test('a five-minute average never displaces the minute row for the same minute', () => {
    const minute = row({ ts: new Date(T0 + 90_000).toISOString(), cpu_usage_millis_last: 9, mem_working_set_last: 90 });
    const coarse = row({ ts: new Date(T0).toISOString(), resolution_secs: 300, cpu_usage_millis_avg: 40, mem_working_set_avg: 400 });
    // The broker promises no order for rows of mixed resolution, so neither
    // order may decide which value a minute shows.
    for (const rows of [[coarse, minute], [minute, coarse]]) {
      const byBucket = new Map(historySamples(rows).map((s) => [s.at, s.cpuMillis]));
      expect(byBucket.get(T0 + 60_000)).toBe(9); // the minute row's own value
      expect(byBucket.get(T0)).toBe(40); // minutes only the coarse row covers
    }
  });

  // At the downsample boundary a minute row's repair window can reach into a
  // minute a five-minute row actually measured. The measurement wins: a fill
  // is a value stretched from a neighbouring minute, whatever its resolution.
  test('a minute row may not overwrite a minute the coarse row itself claimed', () => {
    const coarse = row({ ts: new Date(T0).toISOString(), resolution_secs: 300, cpu_usage_millis_avg: 40 });
    // Window [T0+2m30s, T0+3m30s): claims T0+3m, and its fill reaches T0+2m —
    // which is the bucket the five-minute row's own midpoint claimed.
    const minute = row({ ts: new Date(T0 + 3 * 60_000 + 30_000).toISOString(), cpu_usage_millis_last: 9 });
    for (const rows of [[coarse, minute], [minute, coarse]]) {
      const byBucket = new Map(historySamples(rows).map((x) => [x.at, x.cpuMillis]));
      expect(byBucket.get(T0 + 2 * 60_000)).toBe(40); // the coarse row's claim
      expect(byBucket.get(T0 + 3 * 60_000)).toBe(9); // the minute row's own
    }
  });

  // Reachable when an operator lowers `history.minuteResolutionHours` below
  // the window: the row's ts opens the five minutes it summarises.
  test('historySamples spreads a five-minute row over the buckets it covers, on `_avg`', () => {
    const samples = historySamples([
      row({ resolution_secs: 300, cpu_usage_millis_avg: 40, cpu_usage_millis_last: 999, mem_working_set_avg: 400 }),
      row({ ts: new Date(T0 + 5 * 60_000).toISOString(), cpu_usage_millis_last: 9, mem_working_set_last: 90 }),
    ]);
    expect(samples.map((s) => s.at)).toEqual([0, 1, 2, 3, 4].map((i) => T0 + i * 60_000));
    expect(samples.slice(0, 4).every((s) => s.cpuMillis === 40 && s.workingSetBytes === 400)).toBe(true);
    // The minute row ending at T0+5min covers the T0+4min bucket, on `_last`.
    expect(samples[4]).toEqual(sample(T0 + 4 * 60_000, 9, 90));
  });

  test('historySamples replaces, not sums, two rows for one container in a bucket', () => {
    const samples = historySamples([
      row({ ts: new Date(T0 + 30_000).toISOString(), cpu_usage_millis_last: 10, mem_working_set_last: 100 }),
      row({ ts: new Date(T0 + 45_000).toISOString(), cpu_usage_millis_last: 12, mem_working_set_last: 120 }),
      row({ ts: new Date(T0 + 30_000).toISOString(), container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 5, mem_working_set_last: 50 }),
    ]);
    // Both app rows fall in the bucket at T0; the newer wins, and the sidecar
    // sums on top of it — 12 + 5, never 10 + 12 + 5.
    expect(samples).toEqual([sample(T0, 17, 170)]);
  });

  test('seedHistory merges history under the live buckets and trims to the window', () => {
    const live = new RingBuffer<ComputeSample>(3);
    pushBucketed(live, sample(T0, 300, 900));
    const seeded = seedHistory(
      live,
      [
        sample(T0 - 5 * 60_000, 1), // outside a 3-bucket window
        sample(T0 - 2 * 60_000, 2),
        sample(T0 - 60_000, 3),
        sample(T0, 99), // the live minute: the poll's value is the fresher read
      ],
      T0,
      3,
    );
    expect(seeded.values()).toEqual([sample(T0 - 2 * 60_000, 2), sample(T0 - 60_000, 3), sample(T0, 300, 900)]);
    expect(seeded.capacity).toBe(3);
  });

  // A sparkline plots by index, so the series handed to it must be dense:
  // one slot per minute, `null` where nothing was sampled.
  test('denseSeries gives one slot per minute, ending at the current bucket', () => {
    const series = denseSeries([sample(T0 - 2 * 60_000, 1, 10), sample(T0, 3, 30)], T0, 4);
    expect(series.cpuMillis).toEqual([null, 1, null, 3]);
    expect(series.workingSetBytes).toEqual([null, 10, null, 30]);
    expect(series.latest).toEqual(sample(T0, 3, 30));
  });

  test('denseSeries keeps an outage a hole instead of sliding points forward', () => {
    // Reported, then away for 35 minutes, then back.
    const series = denseSeries([sample(T0 - 40 * 60_000, 5), sample(T0 - 5 * 60_000, 9)], T0);
    expect(series.cpuMillis).toHaveLength(60);
    expect(series.cpuMillis[19]).toBe(5); // still 40 minutes back, not adjacent to the newest
    expect(series.cpuMillis[54]).toBe(9);
    expect(series.cpuMillis.slice(20, 54).every((v) => v === null)).toBe(true);
    expect(series.cpuMillis[59]).toBeNull(); // nothing reported this minute
  });

  test('denseSeries drops samples that aged out of the window, latest included', () => {
    const series = denseSeries([sample(T0 - 6 * 60 * 60_000, 42)], T0);
    expect(series.cpuMillis.every((v) => v === null)).toBe(true);
    expect(series.latest).toBeUndefined();
  });

  test('seedHistory never seeds ahead of the client clock (a broker running fast)', () => {
    const live = new RingBuffer<ComputeSample>(60);
    pushBucketed(live, sample(T0, 300));
    // Rows stamped two minutes into the browser's future: left there, every
    // later poll would be dropped as out of order behind them.
    const seeded = seedHistory(live, [sample(T0 - 60_000, 1), sample(T0 + 120_000, 2)], T0);
    expect(seeded.values()).toEqual([sample(T0 - 60_000, 1), sample(T0, 300)]);
    expect(seeded.last()!.at).toBe(T0);
  });

  // Clamped forward, not discarded: those are the newest and most
  // interesting minutes, and dropping them opens the card on a gap right
  // before the live sample.
  test('seedHistory folds a fast broker’s newest rows onto the current bucket', () => {
    const seeded = seedHistory(undefined, [sample(T0 - 60_000, 1), sample(T0 + 60_000, 2), sample(T0 + 120_000, 3)], T0);
    expect(seeded.values()).toEqual([sample(T0 - 60_000, 1), sample(T0, 3)]); // newest wins the clamp
  });

  // The gauge reads the newest sample as "now". A seeded `_last` clamped past
  // the live bucket would become that, and disagree with the live poll.
  test('seedHistory never lets a seeded bucket outrank the newest live one', () => {
    const live = new RingBuffer<ComputeSample>(60);
    pushBucketed(live, sample(T0 - 60_000, 300)); // the last poll, a minute ago
    const seeded = seedHistory(live, [sample(T0 + 120_000, 11)], T0); // broker ahead
    expect(seeded.last()).toEqual(sample(T0 - 60_000, 300));
  });

  test('seedHistory keeps the buffer\u2019s own capacity, and its window with it', () => {
    const small = new RingBuffer<ComputeSample>(3);
    pushBucketed(small, sample(T0, 100));
    const seeded = seedHistory(small, [sample(T0 - 5 * 60_000, 1), sample(T0 - 60_000, 2)], T0);
    expect(seeded.capacity).toBe(3);
    // The cut-off follows that capacity: the sample five minutes back is
    // outside a three-bucket window and must not be seeded into it.
    expect(seeded.values()).toEqual([sample(T0 - 60_000, 2), sample(T0, 100)]);
  });

  test('seedHistory on a pod with no live buffer yet keeps the newest capacity buckets', () => {
    const seeded = seedHistory(undefined, [sample(T0 - 2 * 60_000, 1), sample(T0 - 60_000, 2), sample(T0, 3)], T0, 2);
    expect(seeded.values()).toEqual([sample(T0 - 60_000, 2), sample(T0, 3)]);
  });
});

describe('podLevelSample', () => {
  test('sums the containers cpu millis and working set', () => {
    const s = podLevelSample([container({ cpu_usage_millis: 100, mem_working_set: 10 }), container({ cpu_usage_millis: 50, mem_working_set: 5 })], 123);
    expect(s).toEqual({ at: 123, cpuMillis: 150, workingSetBytes: 15 });
  });
});

describe('pickDenominator (limit → request → node)', () => {
  test('limit when every container has one', () => {
    expect(pickDenominator([500, 200], [100, 100], 4000)).toEqual({ value: 700, kind: 'limit' });
  });
  test('request when a container has no limit', () => {
    expect(pickDenominator([500, null], [100, 100], 4000)).toEqual({ value: 200, kind: 'request' });
  });
  test('node capacity when neither is complete', () => {
    expect(pickDenominator([null], [null], 4000)).toEqual({ value: 4000, kind: 'node' });
  });
  test('null when nothing is known', () => {
    expect(pickDenominator([null], [null], null)).toBeNull();
    expect(pickDenominator([], [], null)).toBeNull();
  });
});

describe('statusFromFindings / nodeComputeState / statusTooltip', () => {
  test('worst severity wins: critical → critical, high/medium → warning, none → ok', () => {
    expect(statusFromFindings([])).toBe('ok');
    expect(statusFromFindings([finding('medium')])).toBe('warning');
    expect(statusFromFindings([finding('medium'), finding('high')])).toBe('warning');
    expect(statusFromFindings([finding('high'), finding('critical')])).toBe('critical');
  });
  test('node row gates: no row → pending, off → off, unsupported → unsupported', () => {
    // Fix #4: an absent node row is "not reported (yet)", never "feature off".
    expect(nodeComputeState(undefined)).toBe('pending');
    expect(nodeComputeState(node({ compute_enabled: false }))).toBe('off');
    expect(nodeComputeState(node({ compute_supported: false }))).toBe('unsupported');
    expect(nodeComputeState(node())).toBe('ok');
  });
  test('unsupported, off and pending explain themselves differently', () => {
    expect(statusTooltip('unsupported')).toMatch(/cgroup v1/);
    expect(statusTooltip('off')).toMatch(/compute\.enabled/);
    expect(statusTooltip('pending')).toMatch(/not yet sampled, or opted out with kguardian\.dev\/compute: off/);
    expect(new Set([statusTooltip('unsupported'), statusTooltip('off'), statusTooltip('pending')]).size).toBe(3);
    expect(statusTooltip('critical', [finding('critical', 'noisy-neighbor')])).toBe('Compute critical: noisy-neighbor');
  });
});

describe('buildPodComputeData', () => {
  test('no rows on a reporting node → the shared PENDING constant (fix #4)', () => {
    const d = buildPodComputeData({ containers: [], nodesByName: new Map([['worker-1', node()]]), findings: [], samples: [], nodeState: 'ok' });
    expect(d).toBe(COMPUTE_STATE_PENDING);
    expect(d.status).toBe('pending');
    expect(hasComputeGauges(d)).toBe(false);
  });
  test('no rows, node unknown → pending, never off', () => {
    expect(buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [] })).toBe(COMPUTE_STATE_PENDING);
  });
  test('no rows on an off / unsupported node → the shared constants, same identity every tick (fix #8)', () => {
    const off1 = buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [], nodeState: 'off' });
    const off2 = buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [], nodeState: 'off' });
    expect(off1).toBe(COMPUTE_STATE_OFF);
    expect(off1).toBe(off2);
    expect(Object.isFrozen(off1)).toBe(true);
    const u = buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [], nodeState: 'unsupported' });
    expect(u).toBe(COMPUTE_STATE_UNSUPPORTED);
    expect(u.status).toBe('unsupported');
    expect(hasComputeGauges(u)).toBe(false);
    expect(u.cpuPct).toBeNull();
  });
  test('percentages against the picked denominator, sparklines from the samples', () => {
    const rows = [container({ cpu_limit_millis: 500, mem_limit: null, mem_request: 2000 })];
    const now = Date.parse('2026-09-14T10:00:00Z');
    const samples = [
      { at: now - 60_000, cpuMillis: 100, workingSetBytes: 500 },
      { at: now, cpuMillis: 250, workingSetBytes: 1000 },
    ];
    const d = buildPodComputeData({ containers: rows, nodesByName: new Map([['worker-1', node()]]), findings: [finding('high')], samples, now })!;
    expect(d.cpuPct).toBe(50);
    expect(d.cpuDenominator).toBe('limit');
    expect(d.memPct).toBe(50);
    expect(d.memDenominator).toBe('request');
    // Dense: one slot per minute of the window, the two samples at the end.
    expect(d.sparkCpu).toHaveLength(60);
    expect(d.sparkCpu.slice(-2)).toEqual([100, 250]);
    expect(d.sparkMem.slice(-2)).toEqual([500, 1000]);
    expect(d.sparkCpu.slice(0, 58).every((v) => v === null)).toBe(true);
    expect(d.status).toBe('warning');
    expect(hasComputeGauges(d)).toBe(true);
  });
  test('falls back to node capacity (cores × 1000) when nothing is set', () => {
    const rows = [container({ cpu_limit_millis: null, cpu_request_millis: null, mem_limit: null, mem_request: null, cpu_usage_millis: 400, mem_working_set: 4000 })];
    const d = buildPodComputeData({ containers: rows, nodesByName: new Map([['worker-1', node()]]), findings: [], samples: [] })!;
    expect(d.cpuDenominator).toBe('node');
    expect(d.cpuCapacityMillis).toBe(4000);
    expect(d.cpuPct).toBe(10);
    expect(d.memDenominator).toBe('node');
    expect(d.memPct).toBe(50);
  });
  test('dropped BPF inserts on the node: probeDrops set, status at least warning, tooltip appended', () => {
    const nodes = new Map([['worker-1', node({ bpf_hist_update_failures: 3, bpf_pair_update_failures: 5 })]]);
    const d = buildPodComputeData({ containers: [container()], nodesByName: nodes, findings: [], samples: [] });
    expect(d.probeDrops).toEqual({ hist: 3, pair: 5 });
    expect(d.status).toBe('warning');
    expect(statusTooltip(d.status, d.findings, d.probeDrops)).toBe('Compute warning; probe map full: 3 histogram / 5 pair inserts dropped');
    // A critical finding is not downgraded; zero / absent counters mean no drops.
    const c = buildPodComputeData({ containers: [container()], nodesByName: nodes, findings: [finding('critical')], samples: [] });
    expect(c.status).toBe('critical');
    const clean = buildPodComputeData({ containers: [container()], nodesByName: new Map([['worker-1', node({ bpf_hist_update_failures: 0, bpf_pair_update_failures: null })]]), findings: [], samples: [] });
    expect(clean.probeDrops).toBeNull();
    expect(clean.status).toBe('ok');
    expect(buildPodComputeData({ containers: [container()], nodesByName: new Map([['worker-1', node()]]), findings: [], samples: [] }).probeDrops).toBeNull();
  });
  test('an off node overrides findings on the dot; rows on an unknown node are ok, not pending', () => {
    const d = buildPodComputeData({ containers: [container()], nodesByName: new Map(), findings: [finding('critical')], samples: [], nodeState: 'off' });
    expect(d.status).toBe('off');
    const p = buildPodComputeData({ containers: [container()], nodesByName: new Map(), findings: [], samples: [] });
    expect(p.status).toBe('ok');
  });
});

describe('containersForNode', () => {
  const pod = (name: string, uid?: string): PodInfo => ({
    pod_name: name, pod_ip: '', pod_namespace: 'payments', time_stamp: 't', node_name: 'n', is_dead: false,
    pod_obj: uid ? { metadata: { uid } } : undefined,
  });
  test('matches by uid when the record carries one, else by ns/name; de-duplicates', () => {
    const rowA = container({ container_uid: 'uid-a/app', pod_uid: 'uid-a', pod_name: 'api-1' });
    const rowB = container({ container_uid: 'uid-b/app', pod_uid: 'uid-b', pod_name: 'api-2' });
    const byUid = new Map([['uid-a', [rowA]]]);
    const byName = new Map([['payments/api-1', [rowA]], ['payments/api-2', [rowB]]]);
    const out = containersForNode({ pod: pod('api-1', 'uid-a'), pods: [pod('api-1', 'uid-a'), pod('api-2')] }, byUid, byName);
    expect(out.map((c) => c.container_uid)).toEqual(['uid-a/app', 'uid-b/app']);
  });
});

describe('formatting', () => {
  test('millicores, bytes, micros, throttle ratio', () => {
    expect(formatMillicores(250)).toBe('250m');
    expect(formatMillicores(1900)).toBe('1.90 cores');
    expect(formatMillicores(null)).toBe('—');
    expect(formatBytes(171000000)).toBe('163 MiB');
    expect(formatBytes(1300 * 1024 * 1024)).toBe('1.3 GiB');
    expect(formatMicros(24000)).toBe('24.0 ms');
    expect(formatMicros(90)).toBe('90 µs');
    expect(throttledRatio(container({ cpu_throttled_usec: 1_250_000, cpu_nr_periods: 50, cpu_period_usec: 100_000 }))).toBe(0.25);
    expect(throttledRatio(container({ cpu_nr_periods: 0 }))).toBeNull();
  });
});
