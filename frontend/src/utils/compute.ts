// Pure helpers behind the live compute gauges (design D8). Everything the
// PodNode, DataTable and Findings surfaces derive from `pod_compute_latest`
// rows lives here so it can be tested without React Flow.

import type { PodInfo, PodNodeData } from '../types';
import type {
  ComputeContainer,
  ComputeDenominator,
  ComputeFinding,
  ComputeFindingKind,
  ComputeHistoryRow,
  ComputeNode,
  ComputeSample,
  ComputeSeverity,
  ComputeStatus,
  PodComputeData,
  ProbeDrops,
} from '../types/compute';
import { parseBrokerTime, podUid } from './peerResolution';

/**
 * Width of one client-side history bucket.
 *
 * The series has two sources — the 5 s `/compute/latest` poll and the
 * broker's stored `/compute/history/{pod_uid}` rows — and they only share an
 * x-axis on a common grid. A minute is that grid: it is the finest
 * resolution the broker keeps (`resolution_secs = 60`, un-downsampled for
 * `compute.history.minuteResolutionHours`, default 24 h), so nothing is lost
 * by bucketing to it and the seeded and live halves of a sparkline are
 * spaced identically.
 */
export const COMPUTE_BUCKET_MS = 60_000;

/** Client-side history depth per pod (D8: "last 60 samples kept client-side"
 *  — 60 one-minute buckets, so the window is the last hour rather than the
 *  last five minutes of uninterrupted polling). */
export const COMPUTE_HISTORY_SAMPLES = 60;

/** The span the sparklines cover, and what the backfill asks the broker for.
 *  One bucket is one minute, so it is the bucket count. */
export const COMPUTE_HISTORY_WINDOW_MINUTES = COMPUTE_HISTORY_SAMPLES;

/** Sparkline title copy, derived so the label cannot drift from the window. */
export const COMPUTE_HISTORY_WINDOW_LABEL = `last ${COMPUTE_HISTORY_WINDOW_MINUTES} minutes`;

/** How far a sample may fall behind the newest bucket and still be treated
 *  as ordinary jitter rather than the clock itself having moved back
 *  (`pushBucketed`). One bucket of slack absorbs two `Date.now()` reads
 *  landing either side of a boundary without a step being mistaken for it. */
export const COMPUTE_CLOCK_STEP_MS = COMPUTE_BUCKET_MS;

/** Start of the bucket a timestamp falls in (samples are keyed by it). */
export const bucketStart = (at: number): number => Math.floor(at / COMPUTE_BUCKET_MS) * COMPUTE_BUCKET_MS;

/** Fixed-capacity FIFO of the last N samples, oldest first. */
export class RingBuffer<T> {
  private items: T[] = [];
  readonly capacity: number;
  constructor(capacity: number = COMPUTE_HISTORY_SAMPLES) {
    this.capacity = capacity;
  }

  push(item: T): void {
    this.items.push(item);
    if (this.items.length > this.capacity) this.items.splice(0, this.items.length - this.capacity);
  }

  /** Overwrite the newest item in place (a bucket upsert); no-op when empty. */
  replaceLast(item: T): void {
    if (this.items.length > 0) this.items[this.items.length - 1] = item;
  }

  /** Drop every item the predicate rejects (used to evict by age, which
   *  capacity alone cannot do — see `pushBucketed`). */
  retain(keep: (item: T) => boolean): void {
    this.items = this.items.filter(keep);
  }

  /** Oldest → newest snapshot (a copy; safe to hand to React). */
  values(): T[] {
    return [...this.items];
  }

  get length(): number {
    return this.items.length;
  }

  last(): T | undefined {
    return this.items[this.items.length - 1];
  }
}

/** A pod's compute is the sum of its containers' CPU millis / working set. */
export function podLevelSample(containers: readonly ComputeContainer[], at: number): ComputeSample {
  let cpuMillis = 0;
  let workingSetBytes = 0;
  for (const c of containers) {
    cpuMillis += Number.isFinite(c.cpu_usage_millis) ? c.cpu_usage_millis : 0;
    workingSetBytes += Number.isFinite(c.mem_working_set) ? c.mem_working_set : 0;
  }
  return { at, cpuMillis, workingSetBytes };
}

/** What a `pushBucketed` call did. `restarted` means the clock moved back
 *  far enough that every bucket held was in the future and the series began
 *  again — the one outcome that costs seeded history. */
export type BucketPush = 'pushed' | 'upserted' | 'dropped' | 'restarted';

/**
 * Fold a live sample into its bucket. The twelve 5 s polls that land inside
 * one minute overwrite the same entry — last one wins, so the newest poll is
 * still the value the gauges read — and only a rollover pushes a new bucket
 * (evicting the oldest). That is what keeps the x-axis uniform once history
 * is seeded, and the window an hour wide instead of five minutes of polling.
 *
 * A sample a bucket or so behind the newest (ordinary jitter between two
 * `Date.now()` reads either side of a boundary) is dropped rather than
 * appended out of order: the series must stay monotonic in time for the
 * sparkline to mean anything. A sample much further behind is not jitter but
 * the clock itself moving — an NTP correction, a laptop waking — and there
 * dropping is the worst answer: every later sample would be "in the past"
 * too, freezing the chart and the gauge beside it with no sign of why. The
 * buckets that the step put in the future are discarded and the series
 * carries on; everything older than the step survives.
 *
 * Buckets are also evicted by AGE here, not just by the buffer's capacity:
 * a pod that reported for five minutes and then went quiet for six hours (a
 * hidden tab, a node away) would otherwise keep those five buckets — under a
 * heading that says the last hour — because nothing ever pushed them out.
 */
export function pushBucketed(buf: RingBuffer<ComputeSample>, sample: ComputeSample): BucketPush {
  const at = bucketStart(sample.at);
  const last = buf.last();
  let restarted = false;
  if (last && at < last.at) {
    if (last.at - at <= COMPUTE_CLOCK_STEP_MS) return 'dropped'; // jitter: keep the series monotonic
    // The clock moved back. Only the buckets now in the FUTURE are wrong, so
    // only those go: a two-minute correction costs two minutes, not the hour
    // of seeded history that a windowed broker read paid for. If that leaves
    // nothing, the caller is told, and can seed the pod again.
    buf.retain((s) => s.at <= at);
    restarted = buf.length === 0;
  }
  // Every push, not only when the whole buffer is stale: a sparse series
  // (minutes with no sample) can hold `capacity` buckets spanning far more
  // than `capacity` minutes, so counting alone never bounds the window.
  const oldest = at - (buf.capacity - 1) * COMPUTE_BUCKET_MS;
  if (last) buf.retain((s) => s.at >= oldest);
  const bucketed: ComputeSample = { ...sample, at };
  if (buf.last()?.at === at) {
    buf.replaceLast(bucketed);
    return restarted ? 'restarted' : 'upserted';
  }
  buf.push(bucketed);
  return restarted ? 'restarted' : 'pushed';
}

const BUCKET_SECS = COMPUTE_BUCKET_MS / 1000;

/**
 * Which buckets one history row belongs in, and why the two resolutions are
 * treated differently.
 *
 * - A MINUTE row is closed by the controller on its Nth sample, NOT on a
 *   wall-clock boundary (`MinuteFold::finish` stamps `ts: latest.ts`, the
 *   instant of the last 5 s sample folded in), so its `ts` is the END of the
 *   minute it covers and it drifts against the grid. It goes to the single
 *   bucket holding its window's MIDPOINT — the minute it mostly describes.
 *   Flooring `ts` would invent a hole every time drift pushed a stamp past a
 *   boundary; filling every overlapped bucket would be worse still, writing
 *   one row's measurement into a neighbour's minute and letting the next row
 *   overwrite it, so roughly half the plotted minutes would show a value
 *   that was never measured for them.
 * - A DOWNSAMPLED row is written by the broker's five-minute rollup, which
 *   floors (`floor(epoch/300)*300`), so its `ts` is the START of an exact,
 *   non-overlapping window. It spreads across every minute it summarises:
 *   its `_avg` IS the value of each of those minutes, there is no neighbour
 *   to misattribute to, and a midpoint alone would leave four minutes in
 *   five empty for no reason.
 */
function rowBuckets(row: ComputeHistoryRow): number[] | null {
  // `parseBrokerTime`, never `Date.parse`: the broker's own deserialiser
  // accepts a zone-less stamp, and `Date.parse` would read one as LOCAL
  // time — east of UTC every seeded sample would fall outside the window
  // and vanish, west of it they would pile onto one bucket, silently.
  const ts = parseBrokerTime(row.ts);
  if (ts === null) return null; // an unparseable ts must not NaN the series
  const secs = Number.isFinite(row.resolution_secs) && row.resolution_secs > 0 ? row.resolution_secs : BUCKET_SECS;
  if (secs <= BUCKET_SECS) return [bucketStart(ts - (secs * 1000) / 2)];
  // Bounded so an absurd `resolution_secs` cannot fan out over the window.
  const span = Math.min(secs, COMPUTE_HISTORY_SAMPLES * BUCKET_SECS) * 1000;
  const buckets: number[] = [];
  // `end` is exclusive: a window ending on a boundary stops at the minute
  // before it, not at the one starting there.
  for (let at = bucketStart(ts); at <= bucketStart(ts + span - 1); at += COMPUTE_BUCKET_MS) buckets.push(at);
  return buckets;
}

/**
 * Per-container `/compute/history` rows → pod-level samples, one per bucket,
 * oldest first. Values are summed across the pod's containers within a
 * bucket, exactly as `podLevelSample` sums a live poll's rows — but keyed by
 * `container_uid` first, so two rows for one container in one bucket (drift,
 * a finer `resolution_secs`, a re-ingested row) replace each other instead of
 * double-counting that container.
 *
 * A minute row contributes `_last`, so a seeded bucket and a live bucket mean
 * the same thing — the value at the end of that minute — and the newest
 * bucket, which the gauges read as "now", stays an instantaneous number. A
 * downsampled row contributes `_avg` to every bucket it covers instead: its
 * `_last` is one instant out of five minutes, while the average is the honest
 * value to repeat across them.
 */
export function historySamples(rows: readonly ComputeHistoryRow[]): ComputeSample[] {
  const byBucket = new Map<number, Map<string, { cpuMillis: number; workingSetBytes: number; secs: number }>>();
  for (const r of rows) {
    const buckets = rowBuckets(r);
    if (!buckets) continue;
    const secs = Number.isFinite(r.resolution_secs) && r.resolution_secs > 0 ? r.resolution_secs : BUCKET_SECS;
    const coarse = secs > BUCKET_SECS;
    const rawCpu = coarse ? r.cpu_usage_millis_avg : r.cpu_usage_millis_last;
    const rawMem = coarse ? r.mem_working_set_avg : r.mem_working_set_last;
    const value = {
      cpuMillis: Number.isFinite(rawCpu) ? rawCpu : 0,
      workingSetBytes: Number.isFinite(rawMem) ? rawMem : 0,
      secs,
    };
    for (const at of buckets) {
      let containers = byBucket.get(at);
      if (!containers) {
        containers = new Map();
        byBucket.set(at, containers);
      }
      // A five-minute average must never displace the minute row for the
      // same minute. Nothing in the history handler promises an order for
      // rows of mixed resolution, so the finer one is preferred explicitly
      // rather than by whichever happened to be read last. Equal resolution
      // keeps last-write-wins, which is how drifting minute rows resolve.
      const held = containers.get(r.container_uid);
      if (held && held.secs < secs) continue;
      containers.set(r.container_uid, value);
    }
  }
  const samples: ComputeSample[] = [];
  for (const [at, containers] of byBucket) {
    let cpuMillis = 0;
    let workingSetBytes = 0;
    for (const c of containers.values()) {
      cpuMillis += c.cpuMillis;
      workingSetBytes += c.workingSetBytes;
    }
    samples.push({ at, cpuMillis, workingSetBytes });
  }
  return samples.sort((a, b) => a.at - b.at);
}

/**
 * A pod's buffer rebuilt from seeded history merged with whatever the live
 * poll has already collected — the backfill lands after the first poll, so
 * both always exist.
 *
 * Live buckets win a collision: they are the fresher read of the same
 * minute, and the newest of them is what the gauges show. Buckets older than
 * the window are dropped instead of relying on capacity to evict them, so a
 * pod with sparse history cannot keep an hour-old bucket on screen just
 * because nothing pushed it out.
 *
 * Seeded buckets are clamped forward to the CLIENT's current bucket, not
 * discarded: the row timestamps are the broker's clock and `now` is the
 * browser's, so a broker running a couple of minutes ahead would otherwise
 * cost every seed its newest and most interesting minutes — the card would
 * open on a gap immediately before the live sample. Clamping folds them onto
 * the current bucket (newest last, so it wins), where the live sample then
 * overwrites them on the very next poll.
 */
export function seedHistory(
  existing: RingBuffer<ComputeSample> | undefined,
  seeded: readonly ComputeSample[],
  now: number,
  // The existing buffer's own capacity: resizing it here would compute the
  // `oldest` cut-off for a window the caller never asked for.
  capacity: number = existing?.capacity ?? COMPUTE_HISTORY_SAMPLES,
): RingBuffer<ComputeSample> {
  const newest = bucketStart(now);
  const oldest = newest - (capacity - 1) * COMPUTE_BUCKET_MS;
  // Keyed by `s.at` itself — the field the sparkline reads — so a key and its
  // payload can never disagree about which minute a sample belongs to.
  const byBucket = new Map<number, ComputeSample>();
  for (const s of seeded) {
    if (s.at < oldest) continue;
    const at = Math.min(s.at, newest);
    byBucket.set(at, at === s.at ? s : { ...s, at });
  }
  for (const s of existing?.values() ?? []) if (s.at >= oldest) byBucket.set(s.at, s);
  const buf = new RingBuffer<ComputeSample>(capacity);
  for (const s of [...byBucket.values()].sort((a, b) => a.at - b.at)) buf.push(s);
  return buf;
}

/**
 * The capacity a gauge is normalised against, in D8 priority order: the
 * pod's summed limits when EVERY container has one, else its summed
 * requests when every container has one, else the node's capacity. Mixed
 * pods (one container limited, one not) fall through — a partial sum would
 * read as a bound the pod does not actually have.
 */
export function pickDenominator(
  perContainer: readonly (number | null | undefined)[],
  requests: readonly (number | null | undefined)[],
  nodeCapacity: number | null | undefined,
): { value: number; kind: ComputeDenominator } | null {
  const sumIfAll = (xs: readonly (number | null | undefined)[]): number | null => {
    if (xs.length === 0) return null;
    let total = 0;
    for (const x of xs) {
      if (x === null || x === undefined || !(x > 0)) return null;
      total += x;
    }
    return total;
  };
  const limit = sumIfAll(perContainer);
  if (limit !== null) return { value: limit, kind: 'limit' };
  const request = sumIfAll(requests);
  if (request !== null) return { value: request, kind: 'request' };
  if (nodeCapacity !== null && nodeCapacity !== undefined && nodeCapacity > 0) return { value: nodeCapacity, kind: 'node' };
  return null;
}

/** Percentage (0..∞, callers clamp for drawing) or null without a denominator. */
export function percentOf(value: number, denominator: { value: number } | null): number | null {
  if (!denominator || denominator.value <= 0) return null;
  return (value / denominator.value) * 100;
}

const SEVERITY_RANK: Record<ComputeSeverity, number> = { critical: 3, high: 2, medium: 1 };

/** The worst finding's severity → dot state; no findings → ok. */
export function statusFromFindings(findings: readonly ComputeFinding[]): Extract<ComputeStatus, 'ok' | 'warning' | 'critical'> {
  let worst: ComputeSeverity | null = null;
  for (const f of findings) {
    if (worst === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  if (worst === 'critical') return 'critical';
  if (worst === 'high' || worst === 'medium') return 'warning';
  return 'ok';
}

export type NodeComputeState = 'ok' | 'unsupported' | 'off' | 'pending';

/**
 * Node-level gate (D10): a node row with `compute_enabled=false` renders its
 * pods as `off`; `compute_supported=false` (cgroup v1 / no PSI) as
 * `unsupported`. No node row at all is `pending` — the node has not
 * reported (yet); it is NOT evidence the feature is off.
 */
export function nodeComputeState(node: ComputeNode | undefined): NodeComputeState {
  if (!node) return 'pending';
  if (!node.compute_enabled) return 'off';
  if (!node.compute_supported) return 'unsupported';
  return 'ok';
}

/** Dropped BPF map inserts on a node, or null when none / not reported. */
export function probeDropsFor(node: ComputeNode | undefined): ProbeDrops | null {
  const hist = node?.bpf_hist_update_failures ?? 0;
  const pair = node?.bpf_pair_update_failures ?? 0;
  return hist > 0 || pair > 0 ? { hist, pair } : null;
}

export const probeDropsText = (d: ProbeDrops): string => `probe map full: ${d.hist} histogram / ${d.pair} pair inserts dropped`;

/** Tooltip copy for the header dot, so `unsupported` and `off` read apart. */
export function statusTooltip(status: ComputeStatus, findings: readonly ComputeFinding[] = [], probeDrops?: ProbeDrops | null): string {
  const base = statusTooltipBase(status, findings);
  return probeDrops ? `${base}; ${probeDropsText(probeDrops)}` : base;
}

function statusTooltipBase(status: ComputeStatus, findings: readonly ComputeFinding[]): string {
  switch (status) {
    case 'off':
      return 'Compute gauges off: compute.enabled is false on this node, or the controller predates the feature';
    case 'unsupported':
      return 'Compute gauges unsupported on this node (cgroup v1 or no PSI)';
    case 'pending':
      // The broker does not expose the opt-out annotation, so an opted-out
      // pod is indistinguishable from one not sampled yet: say both.
      return 'No compute sample for this pod (not yet sampled, or opted out with kguardian.dev/compute: off)';
    case 'ok':
      return 'Compute: no active findings';
    default: {
      // No findings here means the status came from somewhere else (probe
      // drops, appended by the caller) — do not claim findings that do not exist.
      const kinds = [...new Set(findings.map((f) => f.kind))].join(', ');
      return kinds ? `Compute ${status}: ${kinds}` : `Compute ${status}`;
    }
  }
}

/** The pod uid a compute row keys on, when the stored manifest carries it. */
export function podKeysFor(pod: PodInfo): { uid: string | undefined; name: string; namespace: string | null } {
  return { uid: podUid(pod), name: pod.pod_name, namespace: pod.pod_namespace };
}

/**
 * Compute rows for a graph node: matched by pod uid when the pod record
 * carries one, else by `namespace/pod_name` — a compute row always carries
 * both, a PodInfo only sometimes carries the uid.
 */
export function containersForNode(
  node: Pick<PodNodeData, 'pod' | 'pods'>,
  containersByPodUid: ReadonlyMap<string, ComputeContainer[]>,
  containersByPodName: ReadonlyMap<string, ComputeContainer[]>,
): ComputeContainer[] {
  const members = node.pods && node.pods.length > 0 ? node.pods : [node.pod];
  const out: ComputeContainer[] = [];
  const seen = new Set<string>();
  for (const m of members) {
    const { uid, name, namespace } = podKeysFor(m);
    const rows = (uid && containersByPodUid.get(uid)) || containersByPodName.get(`${namespace ?? ''}/${name}`) || [];
    for (const r of rows) {
      if (!seen.has(r.container_uid)) {
        seen.add(r.container_uid);
        out.push(r);
      }
    }
  }
  return out;
}

/** `<ns>/<pod_name>` — the fallback join key for rows and pods. */
export const podNameKey = (namespace: string | null | undefined, name: string): string => `${namespace ?? ''}/${name}`;

/**
 * The sparkline series for a pod: exactly `capacity` slots ending at the
 * bucket `now` falls in, `null` for a minute no sample covers.
 *
 * It has to be dense because a sparkline plots by ARRAY INDEX, not by time.
 * Handing it a sparse series would slide everything before a gap to the
 * right — a node down for 35 minutes would draw its older points 35 minutes
 * too recent and the outage itself as one one-minute step, which is exactly
 * the lie the minute grid exists to prevent. Samples outside the window are
 * left out rather than plotted, so a buffer that stopped updating (a tab
 * hidden for hours) drains off the left edge instead of showing hours-old
 * values as the present.
 */
export function denseSeries(
  samples: readonly ComputeSample[],
  now: number,
  capacity: number = COMPUTE_HISTORY_SAMPLES,
): { cpuMillis: (number | null)[]; workingSetBytes: (number | null)[]; latest: ComputeSample | undefined } {
  const newest = bucketStart(now);
  const oldest = newest - (capacity - 1) * COMPUTE_BUCKET_MS;
  const cpuMillis: (number | null)[] = new Array(capacity).fill(null);
  const workingSetBytes: (number | null)[] = new Array(capacity).fill(null);
  let latest: ComputeSample | undefined;
  for (const s of samples) {
    if (s.at < oldest || s.at > newest) continue;
    const slot = Math.round((s.at - oldest) / COMPUTE_BUCKET_MS);
    cpuMillis[slot] = s.cpuMillis;
    workingSetBytes[slot] = s.workingSetBytes;
    if (!latest || s.at >= latest.at) latest = s;
  }
  return { cpuMillis, workingSetBytes, latest };
}

export interface BuildPodComputeInput {
  containers: readonly ComputeContainer[];
  nodesByName: ReadonlyMap<string, ComputeNode>;
  /** Findings whose victim is one of this pod's containers. */
  findings: readonly ComputeFinding[];
  /** Oldest-first client-side samples for this pod. */
  samples: readonly ComputeSample[];
  /** Whether the pod's node reported compute at all (see nodeComputeState). */
  nodeState?: NodeComputeState;
  /** End of the sparkline window; defaults to now (tests pin it). */
  now?: number;
}

const frozenArray = <T,>(): T[] => Object.freeze([]) as unknown as T[];
const emptyState = (status: ComputeStatus): PodComputeData =>
  Object.freeze({
    cpuPct: null, memPct: null, cpuDenominator: null, memDenominator: null,
    status, findings: frozenArray<ComputeFinding>(), sparkCpu: frozenArray<number>(), sparkMem: frozenArray<number>(),
    cpuMillis: null, memBytes: null, cpuCapacityMillis: null, memCapacityBytes: null,
    containers: frozenArray<ComputeContainer>(),
  });

// Shared, frozen "no rows" states. Returned by identity so a pod without
// rows keeps the same `compute` object across polls and PodNode's memo
// (which compares by identity) does not repaint it every 5 s.
export const COMPUTE_STATE_OFF: PodComputeData = emptyState('off');
export const COMPUTE_STATE_UNSUPPORTED: PodComputeData = emptyState('unsupported');
export const COMPUTE_STATE_PENDING: PodComputeData = emptyState('pending');

/**
 * Everything PodNode needs, from a pod's rows. Without rows the result is
 * one of the shared constants above: `off` / `unsupported` only when the
 * node row says so, `pending` when the node has not reported or the pod has
 * no sample yet. Callers leave `compute` undefined entirely when the feature
 * is off cluster-wide (hook `enabled=false`).
 */
export function buildPodComputeData(input: BuildPodComputeInput): PodComputeData {
  const { containers, nodesByName, findings, samples } = input;
  const nodeName = containers[0]?.node;
  const nodeRow = nodeName ? nodesByName.get(nodeName) : undefined;
  const nodeState = input.nodeState ?? nodeComputeState(nodeRow);

  if (containers.length === 0) {
    if (nodeState === 'off') return COMPUTE_STATE_OFF;
    if (nodeState === 'unsupported') return COMPUTE_STATE_UNSUPPORTED;
    return COMPUTE_STATE_PENDING;
  }

  const now = input.now ?? Date.now();
  const series = denseSeries(samples, now);
  // The newest sample INSIDE the window, else the live rows: a buffer whose
  // newest bucket has aged out must not keep reporting it as the current value.
  const latest = series.latest ?? podLevelSample(containers, now);
  const cpuDen = pickDenominator(
    containers.map((c) => c.cpu_limit_millis),
    containers.map((c) => c.cpu_request_millis),
    nodeRow?.cpu_cores != null ? nodeRow.cpu_cores * 1000 : null,
  );
  const memDen = pickDenominator(
    containers.map((c) => c.mem_limit),
    containers.map((c) => c.mem_request),
    nodeRow?.memory_bytes ?? null,
  );

  // Rows exist, so the node is reporting: `pending` cannot apply here. A
  // node dropping BPF inserts cannot be trusted for blame, so it is at
  // least a warning even with no finding.
  const probeDrops = probeDropsFor(nodeRow);
  const fromFindings = statusFromFindings(findings);
  const status: ComputeStatus =
    nodeState === 'off' || nodeState === 'unsupported' ? nodeState
    : probeDrops && fromFindings === 'ok' ? 'warning'
    : fromFindings;

  return {
    cpuPct: percentOf(latest.cpuMillis, cpuDen),
    memPct: percentOf(latest.workingSetBytes, memDen),
    cpuDenominator: cpuDen?.kind ?? null,
    memDenominator: memDen?.kind ?? null,
    status,
    findings: [...findings],
    sparkCpu: series.cpuMillis,
    sparkMem: series.workingSetBytes,
    cpuMillis: latest.cpuMillis,
    memBytes: latest.workingSetBytes,
    cpuCapacityMillis: cpuDen?.value ?? null,
    memCapacityBytes: memDen?.value ?? null,
    containers: [...containers],
    probeDrops,
  };
}

/** Throttled share of the sample's CFS periods (D3), 0..1, or null without periods. */
export function throttledRatio(c: Pick<ComputeContainer, 'cpu_throttled_usec' | 'cpu_nr_periods' | 'cpu_period_usec'>): number | null {
  const denom = c.cpu_nr_periods * c.cpu_period_usec;
  if (!(denom > 0)) return null;
  return Math.min(1, c.cpu_throttled_usec / denom);
}

/** The `noisy-neighbor` finding naming a pod culprit, if any (the "Starved by" chip). */
export function starvedBy(findings: readonly ComputeFinding[]): ComputeFinding | undefined {
  return findings.find((f) => f.kind === 'noisy-neighbor' && f.culprit !== null);
}

/** The `cpu-throttled` finding, if any (the "Throttled NN%" chip). */
export function throttledFinding(findings: readonly ComputeFinding[]): ComputeFinding | undefined {
  return findings.find((f) => f.kind === 'cpu-throttled');
}

// Header status dot per compute state (design D8). ok/warning/critical take
// the semantic tokens; unsupported/off take a muted token so "no gauge" never
// reads as "healthy" — the tooltip says which of the two it is.
export const COMPUTE_DOT_CLASS: Record<ComputeStatus, string> = {
  ok: 'bg-hubble-success',
  warning: 'bg-hubble-warning',
  critical: 'bg-hubble-error',
  unsupported: 'bg-hubble-border-strong',
  off: 'bg-hubble-border',
  pending: 'bg-hubble-border animate-pulse',
};

/**
 * What a culprit's `blame_share` is a share OF — it differs by kind (see the
 * type comment on `ComputeFindingCulprit.blame_share`).
 */
export function blameShareLabel(kind: ComputeFindingKind, share: number): string {
  const pct = `${Math.round(share * 100)}%`;
  return kind === 'memory-pressure' ? `${pct} of node memory overage` : `${pct} of its CPU wait`;
}

/** Culprit usage for labels; an opted-out culprit has none. */
export const CULPRIT_USAGE_UNKNOWN = 'usage unknown (opted out of sampling)';
export function culpritUsageLabel(usageMillis: number | null): string {
  return usageMillis === null ? CULPRIT_USAGE_UNKNOWN : `using ${formatMillicores(usageMillis)}`;
}

export const COMPUTE_KIND_LABEL: Record<ComputeFindingKind, string> = {
  'noisy-neighbor': 'Noisy neighbour',
  'cpu-throttled': 'CPU throttled',
  'cpu-contended': 'CPU contended',
  'memory-pressure': 'Memory pressure',
  'memory-limit-thrash': 'Memory limit thrash',
};

// ── Formatting ──

export function formatMillicores(millis: number | null | undefined): string {
  if (millis === null || millis === undefined || !Number.isFinite(millis)) return '—';
  if (millis >= 1000) return `${(millis / 1000).toFixed(millis >= 10_000 ? 0 : 2)} cores`;
  return `${Math.round(millis)}m`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function formatPercent(pct: number | null | undefined, digits = 0): string {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return '—';
  return `${pct.toFixed(digits)}%`;
}

export function formatMicros(us: number | null | undefined): string {
  if (us === null || us === undefined || !Number.isFinite(us)) return '—';
  if (us >= 1_000_000) return `${(us / 1_000_000).toFixed(2)} s`;
  if (us >= 1000) return `${(us / 1000).toFixed(us >= 100_000 ? 0 : 1)} ms`;
  return `${Math.round(us)} µs`;
}

/** Denominator wording for tooltips: "of 500m limit". */
export function denominatorLabel(kind: ComputeDenominator | null): string {
  switch (kind) {
    case 'limit': return 'limit';
    case 'request': return 'request';
    case 'node': return 'node capacity';
    default: return 'no capacity known';
  }
}

// ── Graph layout ──

/** Collapsed card, no gauges (the pre-feature `NODE_HEIGHT`). */
export const NODE_HEIGHT_BASE = 100;
/** The micro bar row under the title. */
export const NODE_HEIGHT_GAUGE_ROW = 14;
/** Expanded body (stat chips + Build Policy). */
export const NODE_HEIGHT_EXPANDED = 90;
/** Two sparklines + labels + chips in the expanded body. */
export const NODE_HEIGHT_SPARKLINES = 120;

/**
 * Estimated card height for ELK (D8): the base collapsed card, plus the
 * gauge row when the pod has compute data, plus the expanded body, plus the
 * sparklines when both expanded and gauged. Used at BOTH ELK call sites.
 */
export function nodeHeight(opts: { isExpanded: boolean; hasCompute: boolean }): number {
  let h = NODE_HEIGHT_BASE;
  if (opts.hasCompute) h += NODE_HEIGHT_GAUGE_ROW;
  if (opts.isExpanded) h += NODE_HEIGHT_EXPANDED;
  if (opts.isExpanded && opts.hasCompute) h += NODE_HEIGHT_SPARKLINES;
  return h;
}

/** Whether a node shows gauges (its status dot is not `off` / `unsupported` with no data). */
export function hasComputeGauges(compute: PodComputeData | undefined): boolean {
  return !!compute && compute.containers.length > 0;
}
