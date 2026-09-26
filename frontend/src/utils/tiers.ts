import type { ExposedVia, VulnSeverity } from '../types/vulns';
import type { LevelConfidence, PssLevel } from '../types/profile';

/**
 * Risk tiers for a vulnerability (UX spec section 3). Tiers, not a score:
 * every tier comes with the factor chips that produced it, so the ranking
 * is auditable.
 *
 *   P0  in use AND (KEV or EPSS >= 10%) AND exposed
 *   P1  in use AND critical/high; or the P0 factors but not exposed
 *   P2  in use, medium/low; or high with no fix and not exposed
 *   Background  installed but never observed loaded
 *
 * Honesty rules, which are what this module exists to hold:
 *  - "in use" is unknown until P1-5. Unknown degrades UPWARD: tier as if
 *    loaded. Background is only ever reached from a definite `false`.
 *  - exposure unknown (null, or not assessed in this view) also degrades
 *    upward: only a definite `false` lowers a tier.
 *  - nothing is ever labelled safe; the lowest tier with any finding is P2.
 */

export type RiskTierName = 'P0' | 'P1' | 'P2' | 'Background';

export interface TierInput {
  severity: VulnSeverity;
  /** null = the source does not say. */
  kev: boolean | null;
  /** 0..1; null = unknown. */
  epss: number | null;
  fixable: boolean;
  /** Fixed versions to show on the chip, when known. */
  fixedVersions?: string[];
  /**
   * true / false: observed; null: nothing observed (unknown);
   * undefined: not assessed in this view (list rows have no exposure).
   */
  exposed?: boolean | null;
  exposedVia?: ExposedVia[];
  windowHours?: number;
  inUse: boolean | null;
  score?: number | null;
  /**
   * The workload's Pod Security Standards level (workload profile). A chip
   * only: it does not move the tier. null = no profile (unknown);
   * undefined = not assessed in this view (CVE list rows span workloads).
   */
  privileged?: { level: PssLevel | null; confidence: LevelConfidence | null } | null;
}

export type FactorTone = 'risk' | 'warn' | 'neutral' | 'unknown' | 'good';

export interface Factor {
  key: string;
  label: string;
  tone: FactorTone;
  title?: string;
}

export interface TierResult {
  tier: RiskTierName;
  /** One sentence: why this tier. */
  reason: string;
  factors: Factor[];
}

/** EPSS at or above this is a P0 factor (a setting in the UX spec; fixed here). */
export const EPSS_P0_THRESHOLD = 0.1;

export const IN_USE_UNKNOWN_LABEL = 'Loaded: unknown';
export const IN_USE_UNKNOWN_TITLE =
  'Loaded-package data is not available yet (kguardian cannot tell which packages a workload loads). Tiered as if loaded: unknown is never treated as safe.';

export function privilegedFactor(p: TierInput['privileged']): Factor | null {
  if (p === undefined) return null;
  if (p === null || p.level === null) {
    return { key: 'privileged', tone: 'unknown', label: 'Privileged: unknown', title: 'No Pod Security Standards level for this workload yet.' };
  }
  const atMost = p.confidence === 'upper_bound';
  if (p.level === 'privileged') {
    return {
      key: 'privileged', tone: atMost ? 'warn' : 'risk', label: atMost ? 'Privileged (at most)' : 'Privileged',
      title: `Pod Security Standards level: privileged${atMost ? ' at most (some checks could not be evaluated)' : ''}. A compromise of this container reaches further.`,
    };
  }
  return {
    key: 'privileged', tone: 'neutral', label: 'Not privileged',
    title: `Pod Security Standards level: ${p.level}${atMost ? ' at most (some checks could not be evaluated)' : ''}.`,
  };
}

const VIA_LABEL: Record<ExposedVia, string> = {
  public_ip: 'public IP',
  other_namespace: 'other namespace',
  unattributed: 'unattributed peer',
  node: 'node',
};

export function exposedViaText(via: ExposedVia[]): string {
  // Most alarming first.
  const order: ExposedVia[] = ['public_ip', 'unattributed', 'other_namespace', 'node'];
  return order.filter((v) => via.includes(v)).map((v) => VIA_LABEL[v]).join(', ');
}

export function exposureFactor(exposed: boolean | null | undefined, via: ExposedVia[] = [], windowHours = 168): Factor | null {
  const days = Math.round(windowHours / 24);
  if (exposed === true) {
    return {
      key: 'exposure', tone: 'risk', label: `Exposed: ${exposedViaText(via) || 'outside ingress'}`,
      title: `Observed ingress from outside the workload's namespace in the last ${days}d. Observed flows only.`,
    };
  }
  if (exposed === false) {
    return {
      key: 'exposure', tone: 'neutral', label: `No outside ingress seen (${days}d)`,
      title: 'Ingress was observed and none came from outside the namespace. Not proof it is unreachable: a Service nobody called this week reads the same.',
    };
  }
  if (exposed === null) {
    return {
      key: 'exposure', tone: 'unknown', label: 'Exposure unknown',
      title: 'No ingress flows observed for this workload in the window, so exposure is unknown. Nothing observed is not the same as nothing reachable.',
    };
  }
  return null;
}

export function computeTier(i: TierInput): TierResult {
  const factors: Factor[] = [];
  if (i.kev === true) factors.push({ key: 'kev', tone: 'risk', label: 'KEV', title: 'Listed in CISA Known Exploited Vulnerabilities' });
  if (i.epss !== null) {
    const pct = i.epss * 100;
    factors.push({
      key: 'epss', tone: i.epss >= EPSS_P0_THRESHOLD ? 'risk' : 'neutral',
      label: `EPSS ${pct >= 1 ? pct.toFixed(0) : pct.toFixed(1)}%`,
      title: 'EPSS: estimated probability of exploitation in the next 30 days',
    });
  }
  if (i.score != null) factors.push({ key: 'cvss', tone: 'neutral', label: `CVSS ${i.score.toFixed(1)}` });
  if (i.fixable) {
    const v = i.fixedVersions?.length ? i.fixedVersions.join(' / ') : '';
    factors.push({ key: 'fix', tone: 'good', label: v ? `Fix: ${v}` : 'Fix available', title: i.fixedVersions && i.fixedVersions.length > 1 ? 'Sources give different fixed versions; kguardian does not pick one.' : undefined });
  } else {
    factors.push({ key: 'fix', tone: 'warn', label: 'No fix yet' });
  }
  const exp = exposureFactor(i.exposed, i.exposedVia, i.windowHours);
  if (exp) factors.push(exp);
  const priv = privilegedFactor(i.privileged);
  if (priv) factors.push(priv);
  if (i.inUse === null) factors.push({ key: 'inuse', tone: 'unknown', label: IN_USE_UNKNOWN_LABEL, title: IN_USE_UNKNOWN_TITLE });
  else if (i.inUse === true) factors.push({ key: 'inuse', tone: 'risk', label: 'Loaded' });
  else factors.push({ key: 'inuse', tone: 'neutral', label: 'Not observed loaded', title: 'Installed but not observed loaded in the observation window. Not proof it is unreachable.' });

  if (i.inUse === false) {
    return { tier: 'Background', reason: 'Installed but not observed loaded in the window (not proof it is unreachable).', factors };
  }
  const hot = i.kev === true || (i.epss ?? 0) >= EPSS_P0_THRESHOLD;
  const inUseWord = i.inUse === null ? 'loaded unknown (treated as loaded)' : 'loaded';
  if (hot && i.exposed !== false) {
    const why = i.kev === true ? 'KEV' : `EPSS >= ${EPSS_P0_THRESHOLD * 100}%`;
    const exposure = i.exposed === true ? 'exposed' : 'exposure not confirmed (treated as exposed)';
    return { tier: 'P0', reason: `${why}, ${exposure}, ${inUseWord}.`, factors };
  }
  if (hot) return { tier: 'P1', reason: `KEV/EPSS factors, but no outside ingress seen; ${inUseWord}.`, factors };
  if (i.severity === 'CRITICAL') return { tier: 'P1', reason: `Critical, ${inUseWord}.`, factors };
  if (i.severity === 'HIGH') {
    if (!i.fixable && i.exposed === false) return { tier: 'P2', reason: 'High, no fix yet, no outside ingress seen.', factors };
    return { tier: 'P1', reason: `High, ${inUseWord}.`, factors };
  }
  if (i.severity === 'UNKNOWN') return { tier: 'P2', reason: 'Severity not given by the source; review it.', factors };
  return { tier: 'P2', reason: `${i.severity.charAt(0)}${i.severity.slice(1).toLowerCase()}, ${inUseWord}.`, factors };
}

/** Chips a row that spans workloads can show (exposure and privilege are per workload). */
export const LIST_FACTORS = ['inuse', 'kev', 'epss', 'cvss', 'fix'];
/** Every chip, in reading order, for a per-workload row. */
export const WORKLOAD_FACTORS = ['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix', 'privileged'];

export const TIER_RANK: Record<RiskTierName, number> = { P0: 3, P1: 2, P2: 1, Background: 0 };

export function worstTier(tiers: readonly RiskTierName[]): RiskTierName | null {
  let w: RiskTierName | null = null;
  for (const t of tiers) if (w === null || TIER_RANK[t] > TIER_RANK[w]) w = t;
  return w;
}
