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
  SparkPoint,
} from '../types/compute';
import { parseBrokerTime, podUid } from './peerResolution';

/** How far back the sparklines reach, and what a seed asks the broker for. */
export const COMPUTE_HISTORY_WINDOW_MINUTES = 60;
export const COMPUTE_HISTORY_WINDOW_MS = COMPUTE_HISTORY_WINDOW_MINUTES * 60_000;

/** Sparkline title copy, derived so the label cannot drift from the window. */
export const COMPUTE_HISTORY_WINDOW_LABEL = `last ${COMPUTE_HISTORY_WINDOW_MINUTES} minutes`;

/**
 * Samples kept per pod. A memory bound, not a resolution: the window is what
 * decides which samples are kept, and an hour of 5 s polls is 720 of them,
 * so this only bites if a broker returns far more history rows than an hour
 * can hold.
 */
export const COMPUTE_MAX_SAMPLES = 2_000;

/**
 * Longer than this between two consecutive samples and the line breaks
 * rather than joining them.
 *
 * Two and a half times the one-minute history cadence: dense 5 s live
 * samples and minute-spaced seeded ones both stay connected, and a pod that
 * reported nothing for over two minutes reads as the gap it is. Five-minute
 * rows (only reachable when an operator downsamples sooner than this window)
 * therefore draw as separate points, which is what a five-minute average
 * observed once actually is.
 */
export const COMPUTE_SPARK_GAP_MS = 150_000;

/**
 * How close two containers' history rows must be to count as one observation
 * of the pod.
 *
 * A fold stamps every container in it with the same instant
 * (`MinuteFold::finish` builds one batch for all of them), so this is a
 * tolerance for re-ingest and nothing more. It exists ONLY to sum a pod's
 * containers: summing them as separate points would draw each container's
 * share as if it were the pod's total.
 */
export const COMPUTE_SAMPLE_MERGE_MS = 2_000;

/** Fixed-capacity FIFO of the last N samples, oldest first. */
export class RingBuffer<T> {
  private items: T[] = [];
  readonly capacity: number;
  constructor(capacity: number = COMPUTE_MAX_SAMPLES) {
    this.capacity = capacity;
  }

  push(item: T): void {
    this.items.push(item);
    if (this.items.length > this.capacity) this.items.splice(0, this.items.length - this.capacity);
  }

  /** Drop every item the predicate rejects (used to trim by age, which
   *  capacity alone cannot do — see `appendSample`). */
  retain(keep: (item: T) => boolean): void {
    this.items = this.items.filter(keep);
  }

  /** Drop the leading run the predicate rejects. Equivalent to `retain` on a
   *  series ordered by the value the predicate tests — which `appendSample`
   *  guarantees — without rebuilding the array on every poll. */
  dropWhile(drop: (item: T) => boolean): void {
    let i = 0;
    while (i < this.items.length && drop(this.items[i])) i++;
    if (i > 0) this.items.splice(0, i);
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

/**
 * Append a live sample to a pod's series and trim it to the window.
 *
 * Samples carry the instant they were observed and are drawn against real
 * time, so a 5 s poll is simply densely spaced points on the right of the
 * chart and nothing has to be folded onto a grid to fit.
 *
 * The series is kept strictly time-ordered. When the clock steps BACKWARD —
 * an NTP correction, a laptop waking — the samples that are now in the
 * future are dropped rather than left behind the new ones: they describe a
 * timeline that no longer exists, and a series that is not ordered cannot be
 * drawn. Everything older than the step survives, and seeding can refill
 * whatever went with it.
 */
export function appendSample(buf: RingBuffer<ComputeSample>, sample: ComputeSample): void {
  const last = buf.last();
  if (last && sample.at < last.at) buf.retain((s) => s.at <= sample.at);
  buf.push(sample);
  const oldest = sample.at - COMPUTE_HISTORY_WINDOW_MS;
  buf.dropWhile((s) => s.at < oldest);
}

/**
 * `/compute/history` rows → pod-level samples, oldest first, each at the
 * instant it was actually observed.
 *
 * Every row becomes ONE point:
 *
 * - A MINUTE row contributes `_last` at its own `ts`. The controller closes a
 *   fold on its Nth sample and stamps it with the last sample folded in
 *   (`MinuteFold::finish`), so `ts` IS when that value was read. Plotting it
 *   there means the drift of those stamps needs no compensation at all — the
 *   points are simply spaced as irregularly as the sampler was.
 * - A DOWNSAMPLED row contributes `_avg` at the middle of the span it
 *   summarises. The broker's rollup floors its `ts` to the 5-minute boundary
 *   (`retention.rs`) and groups the minute rows stamped inside it — and those
 *   are end-stamped, so the measurements actually run from about a minute
 *   BEFORE that boundary to its end: `[ts - 60s, ts + resolution)`, whose
 *   middle is `ts + (resolution - 60s) / 2`.
 *
 * A pod's containers are then summed: rows from one fold share an instant, so
 * points within `COMPUTE_SAMPLE_MERGE_MS` of each other, one per container,
 * are one observation of the pod (see `podLevelSample` for the live
 * equivalent). A second row for a container closes the group, so nothing is
 * double-counted.
 */
export function historySamples(rows: readonly ComputeHistoryRow[]): ComputeSample[] {
  const points: { at: number; containerUid: string; cpuMillis: number; workingSetBytes: number }[] = [];
  for (const row of rows) {
    // `parseBrokerTime`, never `Date.parse`: the broker's own deserialiser
    // accepts a zone-less stamp, and `Date.parse` would read one as LOCAL
    // time, moving every seeded sample by the viewer's offset.
    const ts = parseBrokerTime(row.ts);
    if (ts === null) continue; // an unparseable ts must not NaN the series
    const secs = Number.isFinite(row.resolution_secs) && row.resolution_secs > 0 ? row.resolution_secs : 60;
    const coarse = secs > 60;
    const rawCpu = coarse ? row.cpu_usage_millis_avg : row.cpu_usage_millis_last;
    const rawMem = coarse ? row.mem_working_set_avg : row.mem_working_set_last;
    points.push({
      at: coarse ? ts + ((secs - 60) * 1000) / 2 : ts,
      containerUid: row.container_uid,
      cpuMillis: Number.isFinite(rawCpu) ? rawCpu : 0,
      workingSetBytes: Number.isFinite(rawMem) ? rawMem : 0,
    });
  }
  points.sort((a, b) => a.at - b.at);
  // `pod_compute_history` has no unique index and the controller re-POSTs a
  // batch whose response was lost, so the same container can appear twice at
  // one instant. Dropping the repeat here keeps the pod's containers in one
  // group: letting it split them would emit two samples at that instant, and
  // the pod would plot as whichever container landed in the second one.
  const seen = new Set<string>();
  const distinct = points.filter((p) => {
    const key = `${p.containerUid}@${p.at}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const samples: ComputeSample[] = [];
  let group: typeof points = [];
  const close = () => {
    if (group.length === 0) return;
    let cpuMillis = 0;
    let workingSetBytes = 0;
    for (const p of group) {
      cpuMillis += p.cpuMillis;
      workingSetBytes += p.workingSetBytes;
    }
    // The instant the last of the group was observed: by then every
    // container's contribution to this sum had been read.
    samples.push({ at: group[group.length - 1].at, cpuMillis, workingSetBytes });
    group = [];
  };
  for (const p of distinct) {
    const spans = group.length > 0 && p.at - group[0].at > COMPUTE_SAMPLE_MERGE_MS;
    const repeats = group.some((g) => g.containerUid === p.containerUid);
    if (spans || repeats) close();
    group.push(p);
  }
  close();
  return samples;
}

/**
 * Whether fetching this pod's history could add anything to its series.
 *
 * The question is not "does the series have a hole" — it is "is there time we
 * have not asked about that the series does not cover". `askedAt` is when the
 * last successful read was issued, and a read returns the whole window as of
 * then, so everything up to it is already known: a hole older than `askedAt`
 * is a hole the broker does not have (a controller restart, a node reboot),
 * and asking again would fetch the same rows forever against an endpoint that
 * sheds.
 *
 * Everything AFTER `askedAt` is unknown, and that is what makes a pause
 * recoverable: a tab hidden for longer than the window leaves a series
 * holding a single current sample, with no hole in it to find, yet an hour of
 * un-asked time behind it that the broker can fill. Measuring from `askedAt`
 * rather than from the samples in hand is what tells those two apart.
 */
export function needsSeed(
  samples: readonly ComputeSample[],
  now: number,
  askedAt: number | null,
  gapMs: number = COMPUTE_SPARK_GAP_MS,
): boolean {
  if (askedAt === null) return true; // never asked: whatever the poll has is all there is
  let previous = askedAt;
  for (const s of samples) {
    if (s.at <= askedAt) continue; // already covered by that read
    if (s.at - previous > gapMs) return true;
    previous = s.at;
  }
  return now - previous > gapMs;
}

/**
 * A pod's series with seeded history merged in: a union by timestamp, with
 * the live samples winning any instant both describe.
 *
 * Merging rather than replacing is what makes re-seeding safe, and being safe
 * to repeat is what lets a hole be refilled later instead of being drawn as
 * an outage forever. Live samples collected while the read was in flight are
 * kept for the same reason.
 *
 * Seeded points NEWER than the newest live sample are dropped, not clamped
 * onto it: the broker's clock is not the browser's, and the newest sample is
 * what the gauge reports as "now". That number comes from the live poll or
 * not at all — a seeded `_last` must never sit at the right edge claiming to
 * be the present.
 */
export function seedSamples(
  existing: RingBuffer<ComputeSample> | undefined,
  seeded: readonly ComputeSample[],
): RingBuffer<ComputeSample> {
  const live = existing?.values() ?? [];
  const newestLive = live.length > 0 ? live[live.length - 1].at : null;
  const byInstant = new Map<number, ComputeSample>();
  for (const s of seeded) {
    if (newestLive !== null && s.at > newestLive) continue;
    byInstant.set(s.at, s);
  }
  for (const s of live) byInstant.set(s.at, s); // the live read of an instant wins
  const merged = [...byInstant.values()].sort((a, b) => a.at - b.at);
  const newest = merged.length > 0 ? merged[merged.length - 1].at : 0;
  const buf = new RingBuffer<ComputeSample>(existing?.capacity ?? COMPUTE_MAX_SAMPLES);
  for (const s of merged) {
    if (s.at >= newest - COMPUTE_HISTORY_WINDOW_MS) buf.push(s);
  }
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
 * The points a sparkline draws for one pod: every sample inside the window,
 * each carrying the instant it was observed.
 *
 * No slots and no padding — the chart maps x from the timestamp, so an
 * irregular series stays irregular instead of being folded onto a grid that
 * would have to invent a value, or a hole, for every minute it did not
 * describe.
 */
export function windowedSamples(
  samples: readonly ComputeSample[],
  now: number,
  windowMs: number = COMPUTE_HISTORY_WINDOW_MS,
): { points: ComputeSample[]; from: number; to: number; latest: ComputeSample | undefined } {
  const from = now - windowMs;
  const points = samples.filter((s) => s.at >= from && s.at <= now);
  return { points, from, to: now, latest: points[points.length - 1] };
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
  /** End of the sparkline window. One value for a whole render pass, so two
   *  cards drawn together share a time origin; defaults to now. */
  now?: number;
}

const frozenArray = <T,>(): T[] => Object.freeze([]) as unknown as T[];
/** A pod with no rows draws no chart, so its window is never read. */
const EMPTY_WINDOW = Object.freeze({ from: 0, to: 0 });
const emptyState = (status: ComputeStatus): PodComputeData =>
  Object.freeze({
    cpuPct: null, memPct: null, cpuDenominator: null, memDenominator: null,
    status, findings: frozenArray<ComputeFinding>(),
    sparkCpu: frozenArray<SparkPoint>(), sparkMem: frozenArray<SparkPoint>(), sparkWindow: EMPTY_WINDOW,
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
  const series = windowedSamples(samples, now);
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
    sparkCpu: series.points.map((s) => ({ at: s.at, value: s.cpuMillis })),
    sparkMem: series.points.map((s) => ({ at: s.at, value: s.workingSetBytes })),
    sparkWindow: { from: series.from, to: series.to },
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
