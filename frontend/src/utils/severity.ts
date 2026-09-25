/**
 * The one place a severity or risk tier becomes a colour.
 *
 * Every ranked thing in the UI (sensitive syscalls, compute findings, and the
 * CVE / supply-chain findings to come) resolves its pill through here, onto
 * the dedicated `severity-*` / `tier-*` tokens in index.css. Two rules this
 * exists to hold:
 *   - "medium" is never brand indigo — that colour means selection and the
 *     in-cluster workload spine, and medium is the most common label on screen.
 *   - "critical" never shares its red with a good posture state (a control
 *     that is Enforcing), see seccomp StatePill.
 *
 * Class strings are written out in full (not built from fragments) so
 * Tailwind's scanner sees every one of them.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type RiskTier = 'P0' | 'P1' | 'P2';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];
export const RISK_TIERS: readonly RiskTier[] = ['P0', 'P1', 'P2'];

/** Rank for sorting, worst first when sorted descending. */
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Pill / badge classes (tinted fill, solid text, tinted border). */
export const SEVERITY_BADGE_CLASS: Record<Severity, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
};

/** Plain text tone, e.g. a stat tile value or section icon. */
export const SEVERITY_TEXT_CLASS: Record<Severity, string> = {
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  medium: 'text-severity-medium',
  low: 'text-severity-low',
};

/** Solid swatch, e.g. a status dot. */
export const SEVERITY_DOT_CLASS: Record<Severity, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
};

export const TIER_BADGE_CLASS: Record<RiskTier, string> = {
  P0: 'bg-tier-p0/15 text-tier-p0 border-tier-p0/30',
  P1: 'bg-tier-p1/15 text-tier-p1 border-tier-p1/30',
  P2: 'bg-tier-p2/15 text-tier-p2 border-tier-p2/30',
};

/** The severity each tier is drawn in (tier tokens alias these in index.css). */
export const TIER_SEVERITY: Record<RiskTier, Severity> = { P0: 'critical', P1: 'high', P2: 'medium' };

/** Worst severity in a list, or null for an empty one. */
export function worstSeverity(list: readonly Severity[]): Severity | null {
  let worst: Severity | null = null;
  for (const s of list) if (worst === null || SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s;
  return worst;
}
