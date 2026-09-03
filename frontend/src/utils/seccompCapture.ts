import type { PodInfo } from '../types';
import {
  CAPTURE_ANNOTATION,
  CAPTURE_HELM_VALUE,
  type CaptureInfo,
  type CaptureLevel,
  type WorkloadProfileSummary,
} from '../types/seccompWorkload';

/**
 * Tier ordering for "lowest across pods", matching the broker's worst-first
 * order exactly: full < high < medium < low < unknown < custom. `unknown` (no
 * tier reported) sits below every real tier; `custom` is unordered and ranks
 * worst. A profile is never assumed complete.
 */
const TIER_RANK: Record<CaptureLevel, number> = {
  full: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
  custom: 5,
};

export function normalizeLevel(raw: string | null | undefined): CaptureLevel {
  const v = (raw ?? '').trim().toLowerCase();
  return v in TIER_RANK ? (v as CaptureLevel) : 'unknown';
}

/** What each tier drops, in one operator-facing phrase. */
export const CAPTURE_LEVEL_DESCRIPTION: Record<CaptureLevel, string> = {
  full: 'No filter — every syscall is recorded.',
  high: 'Hot-path noise excluded (read/write/futex/epoll/mmap/…).',
  medium: 'Only security-relevant, network, file-mutation, and process-lifecycle syscalls.',
  low: 'Only the security-relevant subset (exec, socket, mount, ptrace, …).',
  custom: 'Operator-supplied SYSCALL_CUSTOM_LIST only.',
  unknown: 'Tier not reported (older controller) — treated as incomplete.',
};

/**
 * Derive a `CaptureInfo` from a workload's pod rows when the broker summary
 * does not carry one (older broker, or the per-pod generator that works off
 * pod details rather than the profile list). Same rule as the broker: the
 * level is the lowest across pods; complete only if every pod is `full`.
 */
export function captureFromPods(pods: Pick<PodInfo, 'pod_name' | 'capture_level' | 'is_dead'>[]): CaptureInfo {
  const live = pods.filter((p) => !p.is_dead);
  const rows = (live.length > 0 ? live : pods).map((p) => ({
    name: p.pod_name,
    level: normalizeLevel(p.capture_level),
  }));
  if (rows.length === 0) {
    return { level: 'unknown', complete: false, pods: [] };
  }
  const lowest = rows.reduce<CaptureLevel>(
    (acc, r) => (TIER_RANK[r.level as CaptureLevel] > TIER_RANK[acc] ? (r.level as CaptureLevel) : acc),
    'full',
  );
  return {
    level: lowest,
    complete: rows.every((r) => r.level === 'full'),
    pods: rows,
  };
}

/** Prefer the broker's answer; fall back to pod rows; never assume full. */
export function resolveCapture(summary: WorkloadProfileSummary | null | undefined, pods?: PodInfo[]): CaptureInfo {
  if (summary?.capture) {
    return {
      level: normalizeLevel(summary.capture.level),
      complete: Boolean(summary.capture.complete),
      pods: (summary.capture.pods ?? []).map((p) => ({ name: p.name, level: normalizeLevel(p.level) })),
    };
  }
  if (pods && pods.length > 0) return captureFromPods(pods);
  return { level: 'unknown', complete: false, pods: [] };
}

export interface CaptureWarning {
  /** Short headline, e.g. "Partial capture — low tier on 2 pods". */
  title: string;
  /** Why it matters. */
  consequence: string;
  /** How to fix it — the annotation and the Helm value. */
  fix: string;
  /** Pods below `full`, worst first. */
  affectedPods: { name: string; level: CaptureLevel | string }[];
}

/**
 * The headline requirement: when a profile was built from anything other
 * than `full` capture, say so unmistakably, name the tier and the pods, say
 * what will break, and say how to raise the tier. Returns null when capture
 * is complete.
 */
export function describePartialCapture(capture: CaptureInfo | null | undefined): CaptureWarning | null {
  if (!capture || capture.complete) return null;
  const level = normalizeLevel(capture.level);
  const affected = capture.pods
    .filter((p) => normalizeLevel(p.level) !== 'full')
    .sort((a, b) => TIER_RANK[normalizeLevel(b.level)] - TIER_RANK[normalizeLevel(a.level)] || a.name.localeCompare(b.name));
  const n = affected.length;
  const noLivePods = capture.pods.length === 0;
  const podPhrase = noLivePods ? 'no live pods' : `${n} pod${n === 1 ? '' : 's'}`;
  const tierPhrase = level === 'unknown' ? 'unknown tier' : `${level} tier`;
  const why = noLivePods
    ? 'No live pod reported a capture tier (scaled to zero, between CronJob runs, or an older controller), so completeness cannot be confirmed.'
    : CAPTURE_LEVEL_DESCRIPTION[level];
  return {
    title: `Partial capture — ${tierPhrase}, ${podPhrase}`,
    consequence:
      'Profile is incomplete and will block syscalls the app uses. ' +
      `${why} Only the full tier records everything a seccomp allow-list needs.`,
    fix:
      `Raise the tier for this workload with the pod-template annotation ${CAPTURE_ANNOTATION}: full, ` +
      `or cluster-wide with Helm ${CAPTURE_HELM_VALUE}=full, then let the profile re-accrue before publishing.`,
    affectedPods: affected,
  };
}

export type CrStatus = 'none' | 'audit' | 'enforcing';

/** Blocking default actions — anything that isn't allow-and-log. */
const BLOCKING_ACTIONS = new Set(['SCMP_ACT_ERRNO', 'SCMP_ACT_KILL', 'SCMP_ACT_KILL_PROCESS', 'SCMP_ACT_KILL_THREAD', 'SCMP_ACT_TRAP']);

export function isBlockingAction(action: string | null | undefined): boolean {
  return BLOCKING_ACTIONS.has((action ?? '').toUpperCase());
}

/**
 * none → no SeccompProfile CR references this workload; nothing is on any
 * node. audit → a CR is deployed with SCMP_ACT_LOG (logged, never blocked).
 * enforcing → the deployed CR's defaultAction blocks.
 */
export function crStatus(summary: Pick<WorkloadProfileSummary, 'cr'>): CrStatus {
  if (!summary.cr) return 'none';
  return isBlockingAction(summary.cr.defaultAction) ? 'enforcing' : 'audit';
}

/** `securityContext` fragment referencing the CR's node file. */
export function securityContextSnippet(summary: Pick<WorkloadProfileSummary, 'recommendedSnippet' | 'namespace' | 'suggestedName' | 'cr'>): string {
  const path =
    summary.recommendedSnippet?.seccompProfile.localhostProfile ??
    `kguardian/${summary.namespace}/${summary.cr?.name ?? summary.suggestedName ?? 'profile'}.json`;
  return ['securityContext:', '  seccompProfile:', '    type: Localhost', `    localhostProfile: ${path}`].join('\n');
}
