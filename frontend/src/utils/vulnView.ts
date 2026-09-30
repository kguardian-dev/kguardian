import type { CveSummary, ExposedWorkload, Exposure, Finding, JoinKind, Report, SbomTrust, VulnSeverity } from '../types/vulns';
import type { Severity } from './severity';
import { brokerFactors, brokerTier, epssPercent, exposureFactor, factChips, inUseFactor, mergeFactors, nodeOnlyExposure, privilegedFactor, TIER_RANK, tierRank, type Factor, type RiskTierName } from './tiers';

/** View helpers for the supply-chain UI (kept out of component files). */

/** VulnSeverity → the shared severity scale; NONE reads as low, UNKNOWN has its own neutral look. */
export function toSeverity(s: VulnSeverity): Severity | null {
  switch (s) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW':
    case 'NONE': return 'low';
    default: return null;
  }
}

/** The Broker's severity rank (`severity_rank`): findings come most severe first in this order. */
export const VULN_SEVERITY_RANK: Record<VulnSeverity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 };

/** How a report was matched to what runs; tag-only is a weaker, flagged match. */
export const JOIN_LABEL: Record<JoinKind, { label: string; title: string; weak: boolean }> = {
  image_id: { label: 'Exact digest', title: "The kubelet's image digest equals the reported digest.", weak: false },
  platform_manifest: { label: 'Exact (index → manifest)', title: 'The running platform manifest is listed under the reported multi-arch index.', weak: false },
  workload_tag: { label: 'Tag only', title: 'Matched by workload, container and repository:tag only. The tag may have moved since the scan.', weak: true },
  report_digest: { label: 'Report digest', title: 'Exact, but this digest is not known to run here.', weak: false },
};

export function sourceLabel(s: string): string {
  return s === 'trivy-operator' ? 'Trivy Operator' : s === 'grype' ? 'Grype' : s === 'registry' ? 'Registry SBOM' : s === 'node' ? 'Node catalog' : s;
}

export type JumpTarget =
  | { kind: 'cve'; id: string }
  | { kind: 'digest'; digest: string }
  | { kind: 'partial-digest' };

/**
 * What a command-palette query points at: a vulnerability id (CVE or GHSA),
 * a full image digest, or the start of one (which cannot be resolved: the
 * inventory is keyed by full digest).
 */
export function jumpTarget(query: string): JumpTarget | null {
  const q = query.trim();
  const cve = /^(cve-\d{4}-\d{4,})$/i.exec(q);
  if (cve) return { kind: 'cve', id: cve[1].toUpperCase() };
  const ghsa = /^(ghsa(?:-[23456789cfghjmpqrvwx]{4}){3})$/i.exec(q);
  if (ghsa) return { kind: 'cve', id: `GHSA${ghsa[1].slice(4).toLowerCase()}` };
  const d = /^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$/i.exec(q);
  if (d) return { kind: 'digest', digest: d[1].toLowerCase() };
  if (/^sha(256|512):[0-9a-f]{4,}$/i.test(q)) return { kind: 'partial-digest' };
  return null;
}

/**
 * A `cve` / `digest` URL param spelled the way the Broker keys it, as the
 * command palette does (jumpTarget): a pasted `cve-2024-3094` or an
 * upper-case digest would otherwise read as "affects nothing" or "not in
 * the inventory". Anything else is passed on as given, for the drawer to
 * report.
 */
export function canonicalCveId(id: string): string {
  const t = jumpTarget(id);
  return t?.kind === 'cve' ? t.id : id;
}
/**
 * Two vulnerability ids name the same one: compared ignoring case, as the
 * Broker compares them (`vuln_id`), so a GHSA a report spells in another
 * case is still that advisory.
 */
export function sameVulnId(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
export function canonicalDigest(digest: string): string {
  const t = jumpTarget(digest);
  return t?.kind === 'digest' ? t.digest : digest;
}

/** The supply-chain reads return naive UTC timestamps; mark them UTC before parsing. */
export function asUtc(t: string | null | undefined): string | null {
  if (!t) return null;
  return /[zZ]|[+-]\d\d:\d\d$/.test(t) ? t : `${t}Z`;
}

/** Only http(s) links from third-party text are rendered as links. */
export function safeHttpUrl(u: string | null | undefined): string | null {
  if (!u) return null;
  try {
    const url = new URL(u);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/** Fixed versions of the CVE's packages in one image (all sources, none picked). */
export function fixedVersionsFor(e: Exposure, digest: string): string[] {
  const img = e.images.find((i) => i.digest === digest);
  return [...new Set((img?.packages ?? []).flatMap((p) => p.fixedVersions))];
}

/** A CVE list row: the Broker's in-use state and exposure counts, plus facts. No tier factors on this read. */
export function cveRowFactors(c: CveSummary): Factor[] {
  const exposure: Factor[] =
    c.exposedWorkloads != null && c.exposedWorkloads > 0
      ? [{ key: 'exposure', tone: 'risk', label: `${c.exposedWorkloads} exposed`, title: `${c.exposedWorkloads} affected workload${c.exposedWorkloads === 1 ? '' : 's'} with observed ingress from outside the namespace` }]
      : [];
  return mergeFactors([], [inUseFactor(c.inUseState), ...exposure, ...factChips({ kev: c.kev, epss: c.maxEpss, score: c.maxScore, fixable: c.fixable })]);
}

/** One finding: the Broker's tier factors, with facts for the specific labels. */
export function findingFactors(f: Finding): Factor[] {
  const broker = brokerFactors(f.tierFactors, f.inUseDetail).filter((x) => x.key !== 'severity');
  const facts = factChips(f);
  if (!f.tierFactors) facts.unshift(inUseFactor(f.inUseState, f.inUseDetail));
  return mergeFactors(broker, facts);
}

/** The family a tier factor belongs to: one package's `in_use:loaded` and another's `in_use:executed` are the same question. */
const factorFamily = (raw: string) =>
  raw.startsWith('in_use:') ? 'in_use' : raw.startsWith('epss>=') ? 'epss' : raw.startsWith('severity:') ? 'severity' : raw === 'exposed' || raw === 'internal' || raw.startsWith('exposure:') ? 'exposure' : raw;

/**
 * One image's findings of one CVE (one per package and version that
 * carries it) as the single finding the drawer shows for that image: the
 * most urgent one, whose factors explain its tier, plus any factor family
 * only the others have (another package's `no_fix`). KEV and EPSS are the
 * worst any of them reports. Fixable only when every package has a fix
 * (upgrading one leaves the CVE in the other, as `no_fix` says), with every
 * package's fixed versions, none picked. null when there are none.
 */
export function mergeFindings(matches: readonly Finding[]): Finding | null {
  if (matches.length === 0) return null;
  const sorted = [...matches].sort((a, b) => tierRank(brokerTier(b.tier)) - tierRank(brokerTier(a.tier)));
  const [worst, ...rest] = sorted;
  if (rest.length === 0) return worst;
  const factors = [...(worst.tierFactors ?? [])];
  const families = new Set(factors.map(factorFamily));
  for (const f of rest) {
    for (const raw of f.tierFactors ?? []) {
      if (families.has(factorFamily(raw))) continue;
      families.add(factorFamily(raw));
      factors.push(raw);
    }
  }
  const kevs = sorted.map((f) => f.kev);
  const epss = sorted.map((f) => f.epss).filter((x): x is number => x !== null);
  const scores = sorted.map((f) => f.score).filter((x): x is number => x !== null);
  return {
    ...worst,
    kev: kevs.includes(true) ? true : kevs.includes(null) ? null : false,
    epss: epss.length ? Math.max(...epss) : null,
    score: scores.length ? Math.max(...scores) : null,
    fixable: sorted.every((f) => f.fixable),
    fixedVersions: [...new Set(sorted.flatMap((f) => f.fixedVersions))],
    ...(worst.tierFactors || factors.length ? { tierFactors: factors } : {}),
  };
}

/**
 * One affected workload in the CVE drawer. The tier and its factors are
 * the Broker's for this CVE in the workload's image (worst over every
 * container running it); in-use, exposure and privilege are this
 * workload's own.
 */
export function workloadFactors(w: ExposedWorkload, e: Exposure, imageFinding: Finding | null, privileged: Parameters<typeof privilegedFactor>[0]): Factor[] {
  const broker = brokerFactors(imageFinding?.tierFactors, imageFinding?.inUseDetail).filter((x) => x.key !== 'severity');
  // Fixable in this image, not in any image: every package carrying the CVE here has a fix (the merged finding says so when it was read).
  const packages = e.images.find((i) => i.digest === w.imageDigest)?.packages;
  const facts = factChips({
    kev: imageFinding?.kev,
    epss: imageFinding?.epss,
    score: imageFinding?.score,
    fixable: imageFinding ? imageFinding.fixable : packages?.length ? packages.every((p) => p.fixedVersions.length > 0) : undefined,
    fixedVersions: fixedVersionsFor(e, w.imageDigest),
  });
  const own = [inUseFactor(w.inUseState), exposureFactor(w.network ? w.network.exposed : null, w.network?.exposedVia, w.network?.windowHours), privilegedFactor(privileged)].filter(
    (x): x is Factor => x !== null,
  );
  return mergeFactors(broker, facts, own);
}

const workloadId = (w: { namespace: string; kind: string; name: string }) => `${w.namespace}/${w.kind}/${w.name}`;

export interface ImpactCounts {
  images: number;
  /** Exposure rows: one per workload container, running or not. */
  containers: number;
  /** Distinct running workloads (a finished init container of a running Deployment is one row, not a second workload). */
  running: number;
  /** Running workloads the Broker flags exposed: a subset of `running`. */
  exposed: number;
  /** Running workloads with observed ingress from another namespace, an unattributed peer or a public IP: the funnel's "with outside ingress". */
  beyondNodes: number;
  /** Running workloads whose only outside ingress came from node addresses (kubelet probes, or NodePort traffic after SNAT), whichever way the Broker flags them. */
  nodeOnly: number;
  /** Running workloads with no observed ingress at all. */
  unknownExposure: number;
}

const isNodeOnly = (w: ExposedWorkload) => w.network?.exposed != null && nodeOnlyExposure(w.network.exposedVia);

/** The drawer's impact funnel; everything after containers counts distinct running workloads, so it never widens. */
export function impactCounts(e: Exposure): ImpactCounts {
  const running = new Set<string>();
  const exposed = new Set<string>();
  const beyondNodes = new Set<string>();
  const nodeOnly = new Set<string>();
  const unknown = new Set<string>();
  for (const w of e.workloads) {
    if (!w.running) continue;
    const id = workloadId(w);
    running.add(id);
    if (w.network?.exposed == null) unknown.add(id);
    else if (isNodeOnly(w)) nodeOnly.add(id);
    else if (w.network.exposed) beyondNodes.add(id);
    if (w.network?.exposed === true) exposed.add(id);
  }
  // A workload reads as its most exposed row.
  for (const id of beyondNodes) nodeOnly.delete(id);
  for (const id of [...beyondNodes, ...nodeOnly, ...exposed]) unknown.delete(id);
  return { images: e.images.length, containers: e.workloads.length, running: running.size, exposed: exposed.size, beyondNodes: beyondNodes.size, nodeOnly: nodeOnly.size, unknownExposure: unknown.size };
}

/** Exposed workloads named in the AI prompt; the rest is a count. */
export const PROMPT_WORKLOADS_MAX = 10;

const namedList = (names: string[]) => {
  const named = names.slice(0, PROMPT_WORKLOADS_MAX);
  const more = names.length - named.length;
  return `${named.join(', ') || 'none seen'}${more > 0 ? `, +${more} more` : ''}`;
};

/**
 * The context block "Ask AI" hands the assistant for one CVE: the facts the
 * drawer shows, stated with the same honesty (unknown stays unknown).
 * `factors` are the headline's merged chips (worst over every row), so the
 * prompt agrees with what the drawer says; without them the first image's
 * own tier factors stand in.
 */
export function cveAiPrompt(e: Exposure, f: Finding | null, tier: string | null = null, factors: readonly Factor[] = []): string {
  const impact = impactCounts(e);
  const names = (pick: (w: ExposedWorkload) => boolean) => [...new Set(e.workloads.filter((w) => w.running && pick(w)).map((w) => `${w.namespace}/${w.name}`))];
  const exposedNames = names((w) => w.network?.exposed === true && !isNodeOnly(w));
  const nodeNames = names(isNodeOnly);
  const fixes = [...new Set(e.images.flatMap((i) => i.packages.flatMap((p) => p.fixedVersions)))];
  const why = factors.length ? factors.map((x) => x.label).join(', ') : f?.tierFactors?.join(', ');
  const facts = factors.length ? '' : `${f?.kev ? ', in CISA KEV' : ''}${f?.epss != null ? `, EPSS ${epssPercent(f.epss)}` : ''}`;
  return [
    `Context: ${e.id} (${e.severity.toLowerCase()}${facts}; kguardian tier ${tier ?? 'unknown'}${why ? ` from ${why}` : ''}).`,
    `Affects ${impact.images} image(s) and ${impact.containers} workload container(s); ${impact.running} distinct workload(s) running.`,
    `Observed outside ingress on ${impact.beyondNodes} running workload(s): ${namedList(exposedNames)}; exposure unknown for ${impact.unknownExposure}.`,
    ...(impact.nodeOnly > 0 ? [`Ingress from nodes only (kubelet probes, or NodePort traffic after SNAT) on ${impact.nodeOnly} running workload(s): ${namedList(nodeNames)}.`] : []),
    `Fix: ${e.fixable ? fixes.join(' / ') || 'available' : 'no fix yet'}.`,
    e.inUse === null
      ? `In use: unknown (treated as in use)${f?.inUseDetail?.reason ? `, reason: ${f.inUseDetail.reason}` : ''}.`
      : `In use: ${e.inUseState}${e.inUse ? '' : ' (installed, not seen running over the covered window; not proof it is unreachable)'}.`,
    '',
    `Question: which of these workloads should I fix first, and how do I contain ${e.id} until then?`,
  ].join('\n');
}

/**
 * The SBOM a matcher worked from when `/sbom` lists none under the digest:
 * the report names its `sbomSources` and their trust. Findings were computed
 * from it, so the image is not "No SBOM"; the Broker just does not serve that
 * SBOM under the running digest.
 */
export function sbomFromMatcher(vulnReports: readonly Report[] | null | undefined): Array<{ matcher: string; sbomSource: string; trust: SbomTrust | null }> {
  const out: Array<{ matcher: string; sbomSource: string; trust: SbomTrust | null }> = [];
  for (const r of vulnReports ?? []) for (const s of r.sbomSources ?? []) out.push({ matcher: r.source, sbomSource: s, trust: r.sbomTrust });
  return out;
}

/** Header lines of a generated policy, with the per-image "not covered:" lines set aside once there are more than `inlineMax`. */
export function groupNotCovered(header: readonly string[], inlineMax = 10): { lines: string[]; notCovered: string[] } {
  const notCovered = header.filter((l) => l.startsWith('not covered:'));
  if (notCovered.length <= inlineMax) return { lines: [...header], notCovered: [] };
  return { lines: header.filter((l) => !l.startsWith('not covered:')), notCovered };
}

/** Worse first: a headline chip keeps the worst state any row has for that factor. */
const TONE_RANK: Record<Factor['tone'], number> = { risk: 4, unknown: 3, warn: 2, neutral: 1, good: 0 };
const HEADLINE_KEYS = ['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix'];

export interface CveHeadline {
  /** Reads still in flight: the headline shows pending, not a partial answer. */
  pending: boolean;
  /** The highest known tier over every row (and the Broker's CVE-row tier); null if none is known. */
  tier: RiskTierName | null;
  /** Per factor, the worst state any row has. Never better than a row. */
  factors: Factor[];
  /** Rows with no tier (not computed, not read, or not found in the image). */
  unknownRows: number;
  /** Image reads that failed. */
  failedReads: number;
  /** Images whose findings were not all read (more pages than the drawer reads). */
  incompleteReads: number;
}

/**
 * The CVE drawer headline: the worst case over ALL the CVE's workload
 * rows. An unknown row is counted and shown, never hidden behind a lower
 * known tier, and nothing is shown until every read has settled.
 */
export function cveHeadline(
  rows: ReadonlyArray<{ tier: RiskTierName | null; factors: Factor[] }>,
  opts: { pending: number; failed: number; incomplete?: number; summaryTier?: string | null },
): CveHeadline {
  let tier: RiskTierName | null = brokerTier(opts.summaryTier);
  let unknownRows = 0;
  const worst = new Map<string, Factor>();
  for (const r of rows) {
    if (r.tier === null) unknownRows += 1;
    else if (tier === null || TIER_RANK[r.tier] > TIER_RANK[tier]) tier = r.tier;
    for (const f of r.factors) {
      if (!HEADLINE_KEYS.includes(f.key)) continue;
      const cur = worst.get(f.key);
      if (!cur || TONE_RANK[f.tone] > TONE_RANK[cur.tone]) worst.set(f.key, f);
    }
  }
  return { pending: opts.pending > 0, tier, factors: [...worst.values()], unknownRows, failedReads: opts.failed, incompleteReads: opts.incomplete ?? 0 };
}
