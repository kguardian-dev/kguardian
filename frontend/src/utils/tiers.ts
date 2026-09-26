import type { ExposedVia, InUseDetail } from '../types/vulns';
import type { LevelConfidence, PssLevel } from '../types/profile';

/**
 * Risk tiers, as the Broker ranks them (#1678, docs "Risk tiers"). The UI
 * never computes a tier: it renders `tier` and turns `tierFactors` into
 * chips. A Broker that predates tiers sends neither, and the UI says
 * "tier unknown" rather than guessing one.
 *
 * Next to the Broker's factors the rows show facts from the same response
 * (EPSS value, CVSS score, fixed versions, observed exposure, PSS level).
 * Facts never carry a threshold judgement of their own: only a Broker
 * factor colours EPSS as a risk.
 */

export type RiskTierName = 'P0' | 'P1' | 'P2' | 'Background';
const TIERS: readonly RiskTierName[] = ['P0', 'P1', 'P2', 'Background'];

/** The Broker's tier, or null when the response has none (older Broker). */
export function brokerTier(t: unknown): RiskTierName | null {
  return typeof t === 'string' && (TIERS as readonly string[]).includes(t) ? (t as RiskTierName) : null;
}

export const TIER_RANK: Record<RiskTierName, number> = { P0: 3, P1: 2, P2: 1, Background: 0 };
/** Sort key, most urgent first; an unknown tier is never ranked below a known one. */
export const tierRank = (t: RiskTierName | null) => (t === null ? 4 : TIER_RANK[t]);

export const TIER_UNKNOWN_TITLE = 'This Broker does not rank findings into tiers (it predates in-use tiers). Unknown, not low.';

export type FactorTone = 'risk' | 'warn' | 'neutral' | 'unknown' | 'good';

export interface Factor {
  key: string;
  label: string;
  tone: FactorTone;
  title?: string;
}

/** Chips a row that spans workloads can show (exposure and privilege are per workload). */
export const LIST_FACTORS = ['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix'];
/** Every chip, in reading order, for a per-workload row. */
export const WORKLOAD_FACTORS = ['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix', 'privileged'];

export const IN_USE_UNKNOWN_LABEL = 'Loaded: unknown';
export const IN_USE_UNKNOWN_TITLE = 'No runtime evidence either way for this package. Unknown is ranked as if loaded, never as safe.';

const UNKNOWN_REASON: Record<string, string> = {
  language_package: 'an interpreted-language package: nothing is mapped or executed, so it cannot be observed',
  no_runtime_data: 'no runtime capture for the container yet',
  capture_gap: 'the capture has a gap',
  host_network: 'a host-network container',
  no_package_files: 'no SBOM lists the package files',
};

/** The Broker's in-use state as a chip (`inUseState` or a `in_use:<state>` factor). */
export function inUseFactor(state: string | null | undefined, detail?: InUseDetail | null): Factor {
  const window = detail?.windowHours ? ` over ${Math.round(detail.windowHours / 24) || 1}d` : '';
  switch (state) {
    case 'executed':
      return { key: 'inuse', tone: 'risk', label: 'Executed', title: `A binary this package owns was executed.${detail?.coverage === 'static_binary' ? ' Linked into a running binary; the vulnerable function may not be reached.' : ''}` };
    case 'loaded':
      return { key: 'inuse', tone: 'risk', label: 'Loaded', title: 'A shared library this package owns was mapped.' };
    case 'installed_not_observed':
      return { key: 'inuse', tone: 'neutral', label: 'Not observed loaded', title: `Capture covered the container${window} and nothing this package owns ran. Not proof it is unreachable.` };
    default: {
      const why = detail?.reason ? UNKNOWN_REASON[detail.reason] ?? detail.reason : null;
      return { key: 'inuse', tone: 'unknown', label: IN_USE_UNKNOWN_LABEL, title: why ? `Unknown: ${why}. Ranked as if loaded.` : IN_USE_UNKNOWN_TITLE };
    }
  }
}

/**
 * `tierFactors` (#1678 vocabulary: in_use:<state>, kev, epss>=<t>,
 * severity:<s>, exposed | internal | exposure:unknown, no_fix) as chips.
 * An unrecognised factor is shown as sent, never dropped.
 */
export function brokerFactors(factors: readonly string[] | null | undefined, detail?: InUseDetail | null): Factor[] {
  const out: Factor[] = [];
  for (const raw of factors ?? []) {
    if (raw.startsWith('in_use:')) out.push(inUseFactor(raw.slice(7), detail));
    else if (raw === 'kev') out.push({ key: 'kev', tone: 'risk', label: 'KEV', title: 'Listed in CISA Known Exploited Vulnerabilities' });
    else if (raw.startsWith('epss>=')) {
      const t = Number(raw.slice(6));
      out.push({ key: 'epss', tone: 'risk', label: `EPSS ≥ ${Number.isFinite(t) ? `${Math.round(t * 100)}%` : raw.slice(6)}`, title: "At or above the Broker's EPSS threshold" });
    } else if (raw.startsWith('severity:')) out.push({ key: 'severity', tone: 'neutral', label: raw.slice(9) });
    else if (raw === 'exposed') out.push({ key: 'exposure', tone: 'risk', label: 'Exposed', title: 'Observed ingress from outside the namespace' });
    else if (raw === 'internal') out.push({ key: 'exposure', tone: 'neutral', label: 'No outside ingress seen', title: 'Ingress was observed and none came from outside the namespace. Not proof it is unreachable.' });
    else if (raw === 'exposure:unknown') out.push({ key: 'exposure', tone: 'unknown', label: 'Exposure unknown', title: 'No ingress observed. The Broker counts unknown exposure as exposed unless configured otherwise.' });
    else if (raw === 'no_fix') out.push({ key: 'fix', tone: 'warn', label: 'No fix yet' });
    else out.push({ key: raw, tone: 'neutral', label: raw });
  }
  return out;
}

export interface Facts {
  kev?: boolean | null;
  epss?: number | null;
  score?: number | null;
  fixable?: boolean;
  fixedVersions?: string[];
}

/** Facts from the response, as chips. No thresholds here: that is the Broker's call. */
export function factChips(f: Facts): Factor[] {
  const out: Factor[] = [];
  if (f.kev === true) out.push({ key: 'kev', tone: 'risk', label: 'KEV', title: 'Listed in CISA Known Exploited Vulnerabilities' });
  if (f.epss != null) {
    const pct = f.epss * 100;
    out.push({ key: 'epss', tone: 'neutral', label: `EPSS ${pct >= 1 ? pct.toFixed(0) : pct.toFixed(1)}%`, title: 'EPSS: estimated probability of exploitation in the next 30 days' });
  }
  if (f.score != null) out.push({ key: 'cvss', tone: 'neutral', label: `CVSS ${f.score.toFixed(1)}` });
  if (f.fixable === true) {
    const v = f.fixedVersions?.length ? f.fixedVersions.join(' / ') : '';
    out.push({ key: 'fix', tone: 'good', label: v ? `Fix: ${v}` : 'Fix available', title: f.fixedVersions && f.fixedVersions.length > 1 ? 'Sources give different fixed versions; kguardian does not pick one.' : undefined });
  } else if (f.fixable === false) {
    out.push({ key: 'fix', tone: 'warn', label: 'No fix yet' });
  }
  return out;
}

/**
 * One chip per key: the Broker's factor decides the tone (it produced the
 * tier), the fact supplies the more specific label (EPSS 34% over EPSS ≥
 * 10%). `override` replaces a key outright (a workload's own exposure).
 */
export function mergeFactors(broker: Factor[], facts: Factor[], override: Factor[] = []): Factor[] {
  const byKey = new Map<string, Factor>();
  for (const f of facts) byKey.set(f.key, f);
  for (const b of broker) {
    const fact = byKey.get(b.key);
    byKey.set(b.key, fact ? { ...fact, tone: b.tone, title: [b.title, fact.title].filter(Boolean).join('. ') || undefined } : b);
  }
  for (const o of override) byKey.set(o.key, o);
  return [...byKey.values()];
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

/** One workload's observed exposure (the exposure read), as a chip. */
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

/** The workload's Pod Security Standards level (workload profile) as a chip; not a tier factor. */
export function privilegedFactor(p: { level: PssLevel | null; confidence: LevelConfidence | null } | null | undefined): Factor | null {
  if (p === undefined) return null;
  if (p === null || p.level === null) {
    return { key: 'privileged', tone: 'unknown', label: 'Privileged: unknown', title: 'No Pod Security Standards level for this workload yet.' };
  }
  const atMost = p.confidence === 'upper_bound';
  if (p.level === 'privileged') {
    return {
      key: 'privileged', tone: atMost ? 'warn' : 'risk', label: atMost ? 'Privileged (at most)' : 'Privileged',
      title: `Pod Security Standards level: privileged${atMost ? ' at most (some checks could not be evaluated)' : ''}. A compromise of this container reaches further. Shown for context; the Broker does not use it in the tier.`,
    };
  }
  return {
    key: 'privileged', tone: 'neutral', label: 'Not privileged',
    title: `Pod Security Standards level: ${p.level}${atMost ? ' at most (some checks could not be evaluated)' : ''}.`,
  };
}
