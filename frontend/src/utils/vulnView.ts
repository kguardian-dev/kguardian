import type { CveSummary, ExposedWorkload, Exposure, Finding, JoinKind, VulnSeverity } from '../types/vulns';
import type { Severity } from './severity';
import { brokerFactors, exposureFactor, factChips, inUseFactor, mergeFactors, privilegedFactor, type Factor } from './tiers';

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

/** How a report was matched to what runs; tag-only is a weaker, flagged match. */
export const JOIN_LABEL: Record<JoinKind, { label: string; title: string; weak: boolean }> = {
  image_id: { label: 'Exact digest', title: "The kubelet's image digest equals the reported digest.", weak: false },
  platform_manifest: { label: 'Exact (index → manifest)', title: 'The running platform manifest is listed under the reported multi-arch index.', weak: false },
  workload_tag: { label: 'Tag only', title: 'Matched by workload, container and repository:tag only. The tag may have moved since the scan.', weak: true },
  report_digest: { label: 'Report digest', title: 'Exact, but this digest is not known to run here.', weak: false },
};

export function sourceLabel(s: string): string {
  return s === 'trivy-operator' ? 'Trivy Operator' : s === 'grype' ? 'Grype' : s === 'registry' ? 'Registry SBOM' : s;
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
      ? [{ key: 'exposure', tone: 'risk', label: `Exposed: ${c.exposedWorkloads} workload${c.exposedWorkloads === 1 ? '' : 's'}`, title: 'Affected workloads with observed ingress from outside their namespace' }]
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

/**
 * One affected workload in the CVE drawer. The tier and its factors are
 * the Broker's for this CVE in the workload's image (worst over every
 * container running it); in-use, exposure and privilege are this
 * workload's own.
 */
export function workloadFactors(w: ExposedWorkload, e: Exposure, imageFinding: Finding | null, privileged: Parameters<typeof privilegedFactor>[0]): Factor[] {
  const broker = brokerFactors(imageFinding?.tierFactors, imageFinding?.inUseDetail).filter((x) => x.key !== 'severity');
  const facts = factChips({
    kev: imageFinding?.kev,
    epss: imageFinding?.epss,
    score: imageFinding?.score,
    fixable: e.fixable,
    fixedVersions: fixedVersionsFor(e, w.imageDigest),
  });
  const own = [inUseFactor(w.inUseState), exposureFactor(w.network ? w.network.exposed : null, w.network?.exposedVia, w.network?.windowHours), privilegedFactor(privileged)].filter(
    (x): x is Factor => x !== null,
  );
  return mergeFactors(broker, facts, own);
}

/**
 * The context block "Ask AI" hands the assistant for one CVE: the facts the
 * drawer shows, stated with the same honesty (unknown stays unknown).
 */
export function cveAiPrompt(e: Exposure, f: Finding | null, tier: string | null = null): string {
  const running = e.workloads.filter((w) => w.running);
  const exposed = e.workloads.filter((w) => w.network?.exposed === true);
  const unknown = e.workloads.filter((w) => w.network?.exposed == null);
  const fixes = [...new Set(e.images.flatMap((i) => i.packages.flatMap((p) => p.fixedVersions)))];
  return [
    `Context: ${e.id} (${e.severity.toLowerCase()}${f?.kev ? ', in CISA KEV' : ''}${f?.epss != null ? `, EPSS ${(f.epss * 100).toFixed(1)}%` : ''}; kguardian tier ${tier ?? 'unknown'}${f?.tierFactors?.length ? ` from ${f.tierFactors.join(', ')}` : ''}).`,
    `Affects ${e.images.length} image(s) and ${e.workloads.length} workload container(s), ${running.length} running.`,
    `Observed outside ingress: ${exposed.map((w) => `${w.namespace}/${w.name}`).join(', ') || 'none seen'}; exposure unknown for ${unknown.length}.`,
    `Fix: ${e.fixable ? fixes.join(' / ') || 'available' : 'no fix yet'}.`,
    e.inUse === null ? 'Loaded-package data is not available yet, so treat every affected workload as if it loads the package.' : `Observed loaded: ${e.inUse ? 'yes' : 'no'} (${e.inUseState}).`,
    '',
    `Question: which of these workloads should I fix first, and how do I contain ${e.id} until then?`,
  ].join('\n');
}
