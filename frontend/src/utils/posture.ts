import type { DimensionName, FindingSeverity, PostureStatus, PssLevel, LevelConfidence, ProfileDrift, DriftNotEvaluated } from '../types/profile';
import type { Severity } from './severity';

/**
 * How a posture status is drawn. The one rule this exists to hold: `unknown`
 * is its own neutral state ("No data", dashed, a question glyph). It is never
 * green, never blank, never "none" — a workload kguardian knows nothing about
 * must not read as clean.
 *
 * ok uses the theme-aware enforcing green (the good posture state), warn the
 * medium severity tone, risk the critical tone.
 */
export const STATUS_LABEL: Record<PostureStatus, string> = {
  ok: 'OK',
  warn: 'Warn',
  risk: 'Risk',
  unknown: 'No data',
};

export const STATUS_PILL_CLASS: Record<PostureStatus, string> = {
  ok: 'bg-state-enforcing/15 text-state-enforcing border-state-enforcing/30',
  warn: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  risk: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  unknown: 'bg-transparent text-tertiary border-dashed border-hubble-border-strong',
};

export const STATUS_TEXT_CLASS: Record<PostureStatus, string> = {
  ok: 'text-state-enforcing',
  warn: 'text-severity-medium',
  risk: 'text-severity-critical',
  unknown: 'text-tertiary',
};

const STATUSES: readonly PostureStatus[] = ['ok', 'warn', 'risk', 'unknown'];

/** A broker string outside the enum is treated as unknown, never as ok. */
export function asStatus(s: unknown): PostureStatus {
  return typeof s === 'string' && (STATUSES as readonly string[]).includes(s) ? (s as PostureStatus) : 'unknown';
}

export const DIMENSION_LABEL: Record<DimensionName, string> = {
  network: 'Network',
  syscalls: 'Syscalls',
  podSecurity: 'Pod security',
  images: 'Images',
  compute: 'Compute',
};

/** Label of a finding's dimension, including drift (not a core dimension). */
export function findingDimensionLabel(d: string): string {
  if (d === 'drift') return 'Drift';
  return (DIMENSION_LABEL as Record<string, string>)[d] ?? d;
}

/** Human text for why a drift check was not evaluated (contract v1.7). An unknown reason is a capture gap. */
export function driftNotEvaluatedText(reason: string): string {
  switch (reason) {
    case 'no_inventory':
      return 'no runtime inventory for this workload';
    case 'no_runtime_data':
      return 'no runtime capture heartbeat for this container';
    case 'truncated':
      return 'more running containers than one read covers';
    case 'no_running_containers':
      return 'no container is running';
    case 'no_image_inventory':
      return 'no image inventory for this workload';
    case 'no_export':
      return 'the workload has never been exported (no baseline to compare with)';
    case 'no_baseline':
      return 'no earlier securityContext to compare with';
    case 'no_container_data':
      return 'no container securityContext reported';
    case 'not_reported':
      return 'not evaluated (this broker does not say why)';
    default:
      return `runtime capture gap (${reason})`;
  }
}

/** Finding severity → the severity.ts scale (info is drawn as low). */
export function findingSeverity(s: FindingSeverity): Severity {
  return s === 'info' ? 'low' : s;
}

export const PSS_LABEL: Record<PssLevel, string> = {
  privileged: 'Privileged',
  baseline: 'Baseline',
  restricted: 'Restricted',
};

/**
 * PSS level wording. `upper_bound` means unevaluated checks could still
 * lower it, so it reads "at most"; only `confirmed` is stated flat.
 */
export function pssLevelText(level: PssLevel | null, confidence: LevelConfidence | null): string {
  if (!level) return 'No data';
  return confidence === 'upper_bound' ? `${PSS_LABEL[level]} (at most)` : PSS_LABEL[level];
}

/** "3d 4h ago" / "12m ago" — compact, for evidence ages. */
export function formatAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d}d ${rh}h ago` : `${d}d ago`;
}

/** Absolute timestamp for tooltips / version lists (UTC, minute precision). */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

/** sha256:9f2c0d1e… — the first 12 hex digits. */
export function shortDigest(d: string): string {
  const [algo, hex] = d.includes(':') ? d.split(':', 2) : ['', d];
  return `${algo ? `${algo}:` : ''}${hex.slice(0, 12)}${hex.length > 12 ? '…' : ''}`;
}

/** Render a reported value for display; `null` is "unset", never "false". */
export function fieldValue(v: unknown): string {
  if (v === null || v === undefined) return 'unset';
  if (Array.isArray(v)) return v.length ? v.join(', ') : '[]';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

/** The drift checks every broker since contract v1.4 runs. */
const DRIFT_CHECKS_V14 = ['tagMoved', 'imageChangedSinceExport', 'securityContextRegression'] as const;

/**
 * Drift checks not evaluated. A v1.7+ broker lists them (notEvaluated); a
 * v1.4-v1.6 broker only sends `evaluated`, so the v1.4 checks it did not
 * evaluate are gaps too (reason `not_reported`).
 */
export function driftGapsOf(drift: ProfileDrift | undefined): DriftNotEvaluated[] {
  if (!drift) return [];
  if (drift.notEvaluated) return drift.notEvaluated;
  return DRIFT_CHECKS_V14.filter((t) => !drift.evaluated.includes(t)).map((type) => ({ type, container: null, reason: 'not_reported' }));
}

