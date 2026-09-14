import { describe, expect, test } from 'vitest';
import {
  COMPUTE_HISTORY_WINDOW_LABEL,
  COMPUTE_HISTORY_WINDOW_MINUTES,
  COMPUTE_HISTORY_WINDOW_MS,
  COMPUTE_STATE_OFF,
  COMPUTE_STATE_PENDING,
  COMPUTE_STATE_UNSUPPORTED,
  NODE_HEIGHT_BASE,
  NODE_HEIGHT_EXPANDED,
  NODE_HEIGHT_GAUGE_ROW,
  NODE_HEIGHT_SPARKLINES,
  RingBuffer,
  buildPodComputeData,
  containersForNode,
  appendSample,
  formatBytes,
  formatMicros,
  formatMillicores,
  hasComputeGauges,
  historySamples,
  nodeComputeState,
  nodeHeight,
  pickDenominator,
  podLevelSample,
  needsSeed,
  seedSamples,
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
});

// Samples carry the instant they were observed and are drawn against real
// time, so nothing is folded onto a grid and no value is ever placed at a
// time it was not measured.
describe('compute history as a time series', () => {
  const T0 = Date.parse('2026-09-14T10:00:00Z');
  const sample = (at: number, cpuMillis: number, workingSetBytes = 0): ComputeSample => ({ at, cpuMillis, workingSetBytes });

  test('the window constants and label agree', () => {
    expect(COMPUTE_HISTORY_WINDOW_MINUTES).toBe(60);
    expect(COMPUTE_HISTORY_WINDOW_MS).toBe(60 * 60_000);
    expect(COMPUTE_HISTORY_WINDOW_LABEL).toBe('last 60 minutes');
  });

  test('appendSample keeps samples at their own instants, however often they arrive', () => {
    const buf = new RingBuffer<ComputeSample>();
    // A 5 s poll: dense points, none of them rounded or merged.
    for (let i = 0; i < 4; i++) appendSample(buf, sample(T0 + i * 5_000, i));
    expect(buf.values().map((s) => s.at)).toEqual([T0, T0 + 5_000, T0 + 10_000, T0 + 15_000]);
  });

  test('dropWhile removes the leading run and nothing else', () => {
    const b = new RingBuffer<number>();
    [1, 2, 3, 4, 1].forEach((n) => b.push(n));
    b.dropWhile((n) => n < 3);
    expect(b.values()).toEqual([3, 4, 1]); // stops at the first keeper
  });

  test('appendSample trims by age to the window', () => {
    const buf = new RingBuffer<ComputeSample>();
    appendSample(buf, sample(T0, 1));
    appendSample(buf, sample(T0 + 30 * 60_000, 2));
    appendSample(buf, sample(T0 + 61 * 60_000, 3)); // the first is now over an hour old
    expect(buf.values().map((s) => s.cpuMillis)).toEqual([2, 3]);
  });

  // Invariant: the series must stay ordered, and a value must never be drawn
  // at a time it was not measured — so points from the abandoned timeline go.
  test('a backward clock step drops the samples now in the future, keeping the rest', () => {
    const buf = new RingBuffer<ComputeSample>();
    for (let i = 0; i < 10; i++) appendSample(buf, sample(T0 + i * 60_000, i));
    appendSample(buf, sample(T0 + 7 * 60_000 + 1, 99)); // clock corrected back ~3 minutes
    const values = buf.values();
    expect(values.map((s) => s.cpuMillis)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 99]);
    expect(values.every((s, i, all) => i === 0 || all[i - 1].at <= s.at)).toBe(true);
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

  test('a minute row is plotted at its own ts, drift and all', () => {
    // Consecutive folds drifting past the minute boundary: no compensation,
    // no grid — each value sits where it was actually read.
    const stamps = ['10:05:59', '10:07:00', '10:07:58'].map((t) => Date.parse(`2026-09-14T${t}Z`));
    const samples = historySamples(stamps.map((ts, i) => row({ ts: new Date(ts).toISOString(), cpu_usage_millis_last: i })));
    expect(samples.map((s) => s.at)).toEqual(stamps);
    expect(samples.map((s) => s.cpuMillis)).toEqual([0, 1, 2]);
  });

  // A five-minute row is floored to its boundary by the broker's rollup, and
  // aggregates END-stamped minute rows from inside it — so it summarises
  // roughly [ts - 60s, ts + 300s), whose middle is ts + 120s.
  test('a five-minute row is plotted once, at the middle of what it summarises', () => {
    const samples = historySamples([
      row({ ts: new Date(T0).toISOString(), resolution_secs: 300, cpu_usage_millis_avg: 40, cpu_usage_millis_last: 999 }),
    ]);
    expect(samples).toEqual([sample(T0 + 120_000, 40)]); // `_avg`, once — never spread
  });

  test('a pod\u2019s containers are summed per observation, not drawn separately', () => {
    const ts = new Date(T0).toISOString();
    const samples = historySamples([
      row({ ts, cpu_usage_millis_last: 10, mem_working_set_last: 100 }),
      row({ ts, container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 5, mem_working_set_last: 50 }),
      // The next fold, a minute later.
      row({ ts: new Date(T0 + 60_000).toISOString(), cpu_usage_millis_last: 20, mem_working_set_last: 200 }),
      row({ ts: new Date(T0 + 60_000).toISOString(), container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 6, mem_working_set_last: 60 }),
    ]);
    expect(samples).toEqual([sample(T0, 15, 150), sample(T0 + 60_000, 26, 260)]);
  });

  test('containers whose stamps differ slightly are still one observation', () => {
    const samples = historySamples([
      row({ ts: new Date(T0).toISOString(), cpu_usage_millis_last: 10 }),
      row({ ts: new Date(T0 + 400).toISOString(), container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 5 }),
    ]);
    expect(samples).toEqual([sample(T0 + 400, 15)]);
  });

  // pod_compute_history has no unique index and the controller re-POSTs a
  // batch whose response was lost, so the same row can arrive twice.
  test('a duplicated row is dropped, not allowed to split the pod apart', () => {
    const ts = new Date(T0).toISOString();
    const samples = historySamples([
      row({ ts, cpu_usage_millis_last: 100 }),
      row({ ts, container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 20 }),
      row({ ts, container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 20 }), // re-POST
    ]);
    expect(samples).toEqual([sample(T0, 120)]); // never 20, and never 140
  });

  test('two rows for one container are two observations, never one doubled', () => {
    // A re-ingest, or a controller that wrote twice inside the tolerance.
    const samples = historySamples([
      row({ ts: new Date(T0).toISOString(), cpu_usage_millis_last: 10 }),
      row({ ts: new Date(T0 + 500).toISOString(), cpu_usage_millis_last: 12 }),
    ]);
    expect(samples).toEqual([sample(T0, 10), sample(T0 + 500, 12)]);
  });

  test('a sidecar that reported once is summed once, never stretched', () => {
    const app = Array.from({ length: 5 }, (_, i) =>
      row({ ts: new Date(T0 + i * 60_000).toISOString(), cpu_usage_millis_last: 1 }));
    const sidecar = row({ ts: new Date(T0 + 2 * 60_000).toISOString(), container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis_last: 50 });
    const samples = historySamples([...app, sidecar]);
    expect(samples.map((s) => s.cpuMillis)).toEqual([1, 1, 51, 1, 1]);
  });

  test('historySamples reads a zone-less broker stamp as UTC', () => {
    const withZone = historySamples([row({ ts: '2026-09-14T10:05:30Z', cpu_usage_millis_last: 5 })]);
    const zoneLess = historySamples([row({ ts: '2026-09-14T10:05:30', cpu_usage_millis_last: 5 })]);
    expect(zoneLess).toEqual(withZone);
    expect(zoneLess[0].at).toBe(Date.parse('2026-09-14T10:05:30Z'));
  });

  test('an unparseable stamp is skipped, never drawn', () => {
    expect(historySamples([row({ ts: 'not-a-timestamp', cpu_usage_millis_last: 1000 })])).toEqual([]);
  });

  test('seedSamples merges history under the live samples, keeping both', () => {
    const live = new RingBuffer<ComputeSample>();
    appendSample(live, sample(T0, 300));
    const seeded = seedSamples(live, [sample(T0 - 120_000, 1), sample(T0 - 60_000, 2)]);
    expect(seeded.values()).toEqual([sample(T0 - 120_000, 1), sample(T0 - 60_000, 2), sample(T0, 300)]);
  });

  test('seedSamples is idempotent, so a later fetch can refill a hole', () => {
    const live = new RingBuffer<ComputeSample>();
    appendSample(live, sample(T0, 300));
    const once = seedSamples(live, [sample(T0 - 60_000, 2)]);
    const twice = seedSamples(once, [sample(T0 - 60_000, 2), sample(T0 - 120_000, 1)]);
    expect(twice.values()).toEqual([sample(T0 - 120_000, 1), sample(T0 - 60_000, 2), sample(T0, 300)]);
  });

  // The gauge's "now" is the newest sample, and that number comes from the
  // live poll or not at all.
  test('seedSamples drops seeded points newer than the newest live sample', () => {
    const live = new RingBuffer<ComputeSample>();
    appendSample(live, sample(T0, 300));
    const seeded = seedSamples(live, [sample(T0 - 60_000, 1), sample(T0 + 120_000, 11)]); // broker ahead
    expect(seeded.last()).toEqual(sample(T0, 300));
    expect(seeded.values().some((s) => s.cpuMillis === 11)).toBe(false);
  });

  test('seedSamples trims to the window and keeps the live read of a shared instant', () => {
    const live = new RingBuffer<ComputeSample>();
    appendSample(live, sample(T0, 300));
    const seeded = seedSamples(live, [sample(T0 - 61 * 60_000, 1), sample(T0, 999)]);
    expect(seeded.values()).toEqual([sample(T0, 300)]);
  });

  test('needsSeed asks when nothing has been asked yet', () => {
    expect(needsSeed([], T0, null)).toBe(true);
    expect(needsSeed([sample(T0, 1)], T0, null)).toBe(true);
  });

  test('needsSeed stops asking about time already covered by a read', () => {
    const dense = Array.from({ length: 10 }, (_, i) => sample(T0 + i * 5_000, i));
    expect(needsSeed(dense, T0 + 45_000, T0 + 45_000)).toBe(false);
    // A hole OLDER than the read is one the broker does not have — a
    // controller restart, a node reboot. Asking again fetches the same rows.
    const holed = [sample(T0 - 30 * 60_000, 1), sample(T0, 2)];
    expect(needsSeed(holed, T0, T0)).toBe(false);
  });

  // The regression that came back once already: after a pause longer than the
  // window every sample has aged out, so the series holds one current point
  // with no hole in it — and an hour of un-asked time behind it.
  test('needsSeed asks after a pause that emptied the window', () => {
    const askedAt = T0;
    const afterPause = [sample(T0 + 90 * 60_000, 1)]; // all that survived the trim
    expect(needsSeed(afterPause, T0 + 90 * 60_000, askedAt)).toBe(true);
  });

  test('needsSeed asks about a hole that opened since the last read', () => {
    const askedAt = T0;
    const samples = [sample(T0, 1), sample(T0 + 20 * 60_000, 2)];
    expect(needsSeed(samples, T0 + 20 * 60_000, askedAt)).toBe(true);
  });

  test('needsSeed asks when the poll itself has stopped reporting', () => {
    expect(needsSeed([sample(T0, 1)], T0 + 10 * 60_000, T0)).toBe(true);
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
    // Points carry their own instants, and the window is the hour to `now`.
    expect(d.sparkCpu).toEqual([{ at: now - 60_000, value: 100 }, { at: now, value: 250 }]);
    expect(d.sparkMem).toEqual([{ at: now - 60_000, value: 500 }, { at: now, value: 1000 }]);
    expect(d.sparkWindow).toEqual({ from: now - 60 * 60_000, to: now });
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
