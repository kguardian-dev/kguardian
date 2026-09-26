import { useCallback, useEffect, useRef, useState } from 'react';
import { vulnApi as defaultVulnApi, type VulnApi } from '../services/vulnApi';
import { profileApi as defaultProfileApi, type ProfileApi } from '../services/profileApi';
import type { LensBadge, MapLens, PodNodeData } from '../types';
import type { CveSummary, Exposure, ImageUser, Report } from '../types/vulns';
import type { WorkloadListItem } from '../types/profile';
import { withConcurrencyLimit } from '../utils/concurrency';
import { STATUS_LABEL } from '../utils/posture';
import { EPSS_P0_THRESHOLD, TIER_RANK } from '../utils/tiers';
import { workloadTier } from '../utils/vulnView';
import { workloadKey, workloadOf } from '../utils/workloads';

/** At most this many CVEs' exposures are read to draw the Vulnerabilities lens. */
export const LENS_CVE_CAP = 30;
/** At most this many image digests are read per namespace (one page). */
export const LENS_IMAGE_CAP = 100;
export const LENS_CONCURRENCY = 3;

/** CVEs that can tier P0 or P1: the only ones the Vulnerabilities lens reads exposure for. */
export function lensCandidate(c: CveSummary): boolean {
  return c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.kev === true || (c.maxEpss ?? 0) >= EPSS_P0_THRESHOLD;
}

export interface HotCves {
  tier: 'P0' | 'P1';
  ids: string[];
}

/** Per-workload P0/P1 CVEs on running images, from the CVEs' exposures (key ns/kind/name). */
export function hotCvesByWorkload(exposures: Array<{ summary: CveSummary; exposure: Exposure }>): Map<string, HotCves> {
  const out = new Map<string, HotCves>();
  for (const { summary, exposure } of exposures) {
    for (const w of exposure.workloads) {
      if (!w.running) continue;
      const t = workloadTier(w, exposure, null, summary);
      if (t.tier !== 'P0' && t.tier !== 'P1') continue;
      const key = workloadKey(w.namespace, w.kind, w.name);
      const g = out.get(key) ?? { tier: t.tier, ids: [] };
      if (!g.ids.includes(exposure.id)) g.ids.push(exposure.id);
      if (TIER_RANK[t.tier] > TIER_RANK[g.tier]) g.tier = t.tier;
      out.set(key, g);
    }
  }
  return out;
}

/** What one namespace's image inventory says about each workload's running images. */
export interface WorkloadImages {
  /** Distinct running digests. */
  digests: string[];
  /** Digests with at least one vulnerability report. */
  withVulnData: number;
  /** Digests with an SBOM from any source / a verified one. */
  withSbom: number;
  withVerifiedSbom: number;
}

export interface ImageFacts {
  digest: string;
  workloads: ImageUser[];
  vulnReports: Report[] | null;
  sbomReports: Report[] | null;
}

/** Fold per-digest facts into per-workload running-image coverage (key ns/kind/name). */
export function imagesByWorkload(images: ImageFacts[]): Map<string, WorkloadImages> {
  const out = new Map<string, WorkloadImages>();
  for (const img of images) {
    for (const w of img.workloads) {
      if (!w.running) continue;
      const key = workloadKey(w.namespace, w.workloadKind, w.workloadName);
      const acc = out.get(key) ?? { digests: [], withVulnData: 0, withSbom: 0, withVerifiedSbom: 0 };
      if (acc.digests.includes(img.digest)) continue;
      acc.digests.push(img.digest);
      if (img.vulnReports && img.vulnReports.length > 0) acc.withVulnData += 1;
      if (img.sbomReports && img.sbomReports.length > 0) acc.withSbom += 1;
      if (img.sbomReports?.some((r) => r.sbomTrust === 'verified')) acc.withVerifiedSbom += 1;
      out.set(key, acc);
    }
  }
  return out;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Vulnerabilities lens badge. Never "clean": the best a card gets is "no P0/P1 found". */
export function vulnBadge(hot: HotCves | undefined, imgs: WorkloadImages | undefined, assessedAll: boolean): LensBadge {
  const partial = imgs && imgs.withVulnData < imgs.digests.length;
  const partialNote = partial ? ` ${plural(imgs.digests.length - imgs.withVulnData, 'running image')} of ${imgs.digests.length} ${imgs.digests.length - imgs.withVulnData === 1 ? 'has' : 'have'} no vulnerability data (unknown).` : '';
  if (hot) {
    return {
      lens: 'vulns', tone: hot.tier === 'P0' ? 'p0' : 'p1', text: `${hot.tier} · ${hot.ids.length}`,
      label: `${plural(hot.ids.length, 'P0/P1 vulnerability', 'P0/P1 vulnerabilities')} on running images, worst ${hot.tier}: ${hot.ids.slice(0, 5).join(', ')}${hot.ids.length > 5 ? ', …' : ''}.${partialNote}`,
    };
  }
  if (!imgs || imgs.digests.length === 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'no data', label: 'No running image of this workload is in the image inventory: vulnerabilities unknown.' };
  }
  if (imgs.withVulnData === 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'no data', label: 'No source has reported on the images this workload runs: vulnerabilities unknown, not clean.' };
  }
  if (partial) {
    return { lens: 'vulns', tone: 'unknown', text: 'partial', label: `No P0/P1 found in the reported images.${partialNote}` };
  }
  return {
    lens: 'vulns', tone: 'neutral', text: 'no P0/P1',
    label: assessedAll
      ? 'Reported on; no P0/P1 vulnerability found on its running images. Lower tiers may exist.'
      : `Reported on; no P0/P1 among the first ${LENS_CVE_CAP} high-risk CVEs assessed. More were not assessed.`,
  };
}

/** Supply chain lens badge: SBOM presence and trust. Signatures are not checked yet and never shown as signed. */
export function supplyBadge(imgs: WorkloadImages | undefined): LensBadge {
  const sig = ' Signatures: not checked.';
  if (!imgs || imgs.digests.length === 0) {
    return { lens: 'supply', tone: 'unknown', text: 'no data', label: `No running image of this workload is in the image inventory.${sig}` };
  }
  const n = imgs.digests.length;
  if (imgs.withVerifiedSbom === n) {
    return { lens: 'supply', tone: 'good', text: 'SBOM verified', label: `Every running image has an SBOM from a verified attestation.${sig}` };
  }
  if (imgs.withSbom === n) {
    return { lens: 'supply', tone: 'neutral', text: 'SBOM', label: `Every running image has an SBOM; ${imgs.withVerifiedSbom === 0 ? 'none' : `${imgs.withVerifiedSbom} of ${n}`} verified.${sig}` };
  }
  if (imgs.withSbom === 0) {
    return { lens: 'supply', tone: 'unknown', text: 'no SBOM', label: `No SBOM from any source for its ${plural(n, 'running image')}.${sig}` };
  }
  return { lens: 'supply', tone: 'unknown', text: `SBOM ${imgs.withSbom}/${n}`, label: `${imgs.withSbom} of ${n} running images have an SBOM.${sig}` };
}

/** Coverage lens badge: how much of the workload kguardian can see (the profile's posture coverage). */
export function coverageBadge(p: WorkloadListItem | undefined): LensBadge {
  if (!p) {
    return { lens: 'coverage', tone: 'unknown', text: 'no profile', label: 'No workload profile yet: coverage unknown.' };
  }
  const pct = Math.round(p.posture.coverage * 100);
  const dims = (['network', 'syscalls', 'podSecurity', 'images'] as const)
    .map((d) => `${d === 'podSecurity' ? 'pod security' : d} ${STATUS_LABEL[p.dimensions[d].status].toLowerCase()}`)
    .join(', ');
  const tone: LensBadge['tone'] = p.posture.status === 'risk' ? 'risk' : p.posture.status === 'warn' ? 'warn' : p.posture.status === 'ok' ? 'good' : 'unknown';
  return {
    lens: 'coverage', tone, text: `${pct}% seen`,
    label: `Posture ${STATUS_LABEL[p.posture.status].toLowerCase()}, ${pct}% of dimensions have data (${dims}).${p.posture.unknownDimensions.length ? ' Unknown dimensions are excluded, never counted as clean.' : ''}`,
  };
}

/** Workload badges → map node ids (a node groups a workload's pods). Every in-cluster card gets one: no badge would read as clean. */
export function badgesByNode(lens: Exclude<MapLens, 'traffic'>, byWorkload: Map<string, LensBadge>, nodes: PodNodeData[]): Map<string, LensBadge> {
  const out = new Map<string, LensBadge>();
  const fallback: Record<Exclude<MapLens, 'traffic'>, LensBadge> = {
    vulns: vulnBadge(undefined, undefined, true),
    supply: supplyBadge(undefined),
    coverage: coverageBadge(undefined),
  };
  for (const n of nodes) {
    if (n.isExternal) continue;
    let badge: LensBadge | undefined;
    for (const p of n.pods.length > 0 ? n.pods : [n.pod]) {
      const w = workloadOf(p);
      badge = w ? byWorkload.get(workloadKey(w.namespace, w.kind, w.name)) : undefined;
      if (badge) break;
    }
    out.set(n.id, badge ?? fallback[lens]);
  }
  return out;
}

async function readImages(api: VulnApi, namespace: string, withSbom: boolean): Promise<{ images: ImageFacts[]; truncated: boolean }> {
  const page = await api.listImages({ namespace, limit: LENS_IMAGE_CAP });
  const images = await withConcurrencyLimit(
    page.items.map((img) => async (): Promise<ImageFacts> => {
      const [d, v, s] = await Promise.all([
        api.getImage(img.digest).catch(() => null),
        api.getImageVulns(img.digest, { limit: 1 }).then((p) => p.reports).catch(() => null),
        withSbom ? api.getImageSbom(img.digest, { limit: 1 }).then((p) => p.reports).catch(() => null) : Promise.resolve(null),
      ]);
      return { digest: img.digest, workloads: d?.workloads ?? [], vulnReports: v, sbomReports: s };
    }),
    LENS_CONCURRENCY,
  );
  return { images, truncated: page.nextAfter !== null };
}

export interface MapLensState {
  byWorkload: Map<string, LensBadge>;
  loading: boolean;
  error: unknown;
  /** Something was capped: say so in the legend. */
  truncated: boolean;
}

/**
 * Badges for one namespace's workloads under the chosen lens. Reads only
 * while a non-traffic lens is on; bounded (one image page, LENS_CVE_CAP
 * exposures, LENS_CONCURRENCY reads in flight).
 */
export function useMapLens(
  namespace: string,
  lens: MapLens,
  refreshTick = 0,
  apis: { vulnApi?: VulnApi; profileApi?: ProfileApi } = {},
): MapLensState {
  const vulnApi = apis.vulnApi ?? defaultVulnApi;
  const profileApi = apis.profileApi ?? defaultProfileApi;
  const [state, setState] = useState<MapLensState>({ byWorkload: new Map(), loading: false, error: null, truncated: false });
  const seq = useRef(0);

  const load = useCallback(async () => {
    const id = ++seq.current;
    const current = () => id === seq.current;
    if (lens === 'traffic') {
      setState({ byWorkload: new Map(), loading: false, error: null, truncated: false });
      return;
    }
    setState((s) => ({ ...s, byWorkload: s.byWorkload, loading: true, error: null }));
    try {
      const out = new Map<string, LensBadge>();
      let truncated = false;
      if (lens === 'coverage') {
        const page = await profileApi.listWorkloads({ namespace, limit: 500 });
        for (const p of page.items) out.set(workloadKey(p.namespace, p.kind, p.name), coverageBadge(p));
        truncated = page.nextAfter !== null;
      } else if (lens === 'supply') {
        const { images, truncated: t } = await readImages(vulnApi, namespace, true);
        for (const [k, v] of imagesByWorkload(images)) out.set(k, supplyBadge(v));
        truncated = t;
      } else {
        const [{ images, truncated: t }, cves] = await Promise.all([
          readImages(vulnApi, namespace, false),
          vulnApi.listCves({ namespace, running: true, limit: 200 }),
        ]);
        const candidates = cves.items.filter(lensCandidate);
        const picked = candidates.slice(0, LENS_CVE_CAP);
        const exposures = (
          await withConcurrencyLimit(
            picked.map((summary) => async () => {
              // A CVE whose images left the inventory since the summary: skip it, don't fail the lens.
              const exposure = await vulnApi.getExposure(summary.id).catch(() => null);
              return exposure ? { summary, exposure } : null;
            }),
            LENS_CONCURRENCY,
          )
        ).filter((x): x is { summary: CveSummary; exposure: Exposure } => x !== null);
        const assessedAll = candidates.length === picked.length && cves.nextAfter === null && exposures.length === picked.length;
        const hot = hotCvesByWorkload(exposures);
        const imgs = imagesByWorkload(images);
        for (const k of new Set([...hot.keys(), ...imgs.keys()])) out.set(k, vulnBadge(hot.get(k), imgs.get(k), assessedAll));
        truncated = t || !assessedAll;
      }
      if (!current()) return;
      setState({ byWorkload: out, loading: false, error: null, truncated });
    } catch (err) {
      if (current()) setState({ byWorkload: new Map(), loading: false, error: err, truncated: false });
    }
  }, [lens, namespace, vulnApi, profileApi]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch while a lens is on / namespace / refresh
    void load();
  }, [load, refreshTick]);

  return state;
}
