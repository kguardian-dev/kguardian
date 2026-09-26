import { useCallback, useEffect, useRef, useState } from 'react';
import { vulnApi as defaultVulnApi, type VulnApi } from '../services/vulnApi';
import { profileApi as defaultProfileApi, type ProfileApi } from '../services/profileApi';
import type { LensBadge, MapLens, PodNodeData } from '../types';
import type { Finding, ImageUser, Report } from '../types/vulns';
import type { WorkloadListItem } from '../types/profile';
import { withConcurrencyLimit } from '../utils/concurrency';
import { STATUS_LABEL } from '../utils/posture';
import { workloadKey, workloadOf } from '../utils/workloads';

/** At most this many image digests are read per namespace (one page). */
export const LENS_IMAGE_CAP = 100;
/** P0/P1 findings read per image (one page). */
export const LENS_FINDINGS_CAP = 100;
export const LENS_CONCURRENCY = 3;

/**
 * What one image read says. For the Vulnerabilities lens, `hot` is the
 * image's P0/P1 findings as the Broker tiers them (`tier=P0,P1`), and
 * `tiered` whether the Broker ranks tiers at all: an older Broker ignores
 * the filter and sends findings without `tier`.
 */
export interface ImageFacts {
  digest: string;
  workloads: ImageUser[];
  vulnReports: Report[] | null;
  sbomReports: Report[] | null;
  hot?: Finding[] | null;
  /** true: findings carry `tier`; false: they do not (older Broker); null: nothing to tell by. */
  tiered?: boolean | null;
  hotTruncated?: boolean;
  /** The vulnerability / SBOM read for this digest failed: unknown, never "none". */
  vulnFailed?: boolean;
  sbomFailed?: boolean;
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
  /** P0 / P1 CVE ids over the running images (the Broker's tiers). */
  p0: string[];
  p1: string[];
  /** Running images whose findings carry no tier (older Broker). */
  untiered: number;
  /** A P0/P1 page was cut short. */
  hotTruncated: boolean;
  /** Running images whose vulnerability / SBOM read failed. */
  vulnFailed: number;
  sbomFailed: number;
}

/** Fold per-digest facts into per-workload running-image coverage (key ns/kind/name). */
export function imagesByWorkload(images: ImageFacts[]): Map<string, WorkloadImages> {
  const out = new Map<string, WorkloadImages>();
  for (const img of images) {
    for (const w of img.workloads) {
      if (!w.running) continue;
      const key = workloadKey(w.namespace, w.workloadKind, w.workloadName);
      const acc = out.get(key) ?? { digests: [], withVulnData: 0, withSbom: 0, withVerifiedSbom: 0, p0: [], p1: [], untiered: 0, hotTruncated: false, vulnFailed: 0, sbomFailed: 0 };
      if (acc.digests.includes(img.digest)) continue;
      acc.digests.push(img.digest);
      if (img.vulnReports && img.vulnReports.length > 0) acc.withVulnData += 1;
      if (img.sbomReports && img.sbomReports.length > 0) acc.withSbom += 1;
      if (img.sbomReports?.some((r) => r.sbomTrust === 'verified')) acc.withVerifiedSbom += 1;
      if (img.tiered === false) acc.untiered += 1;
      for (const f of img.hot ?? []) {
        const list = f.tier === 'P0' ? acc.p0 : f.tier === 'P1' ? acc.p1 : null;
        if (list && !list.includes(f.id)) list.push(f.id);
      }
      acc.hotTruncated ||= img.hotTruncated === true;
      if (img.vulnFailed) acc.vulnFailed += 1;
      if (img.sbomFailed) acc.sbomFailed += 1;
      out.set(key, acc);
    }
  }
  return out;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * Vulnerabilities lens badge from the Broker's tiers. Never "clean": the
 * best a card gets is "no P0/P1". A finding's tier is the worst over every
 * container running its image, so a shared image carries its worst user's
 * tier to every workload running it.
 */
export function vulnBadge(imgs: WorkloadImages | undefined): LensBadge {
  if (!imgs || imgs.digests.length === 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'no data', label: 'No running image of this workload is in the image inventory: vulnerabilities unknown.' };
  }
  const n = imgs.digests.length;
  const missing = n - imgs.withVulnData;
  const partialNote = missing > 0 ? ` ${plural(missing, 'running image')} of ${n} ${missing === 1 ? 'has' : 'have'} no vulnerability data (unknown).` : '';
  const scope = ' Tiers are the Broker\'s, worst over every workload running the image.';
  const failedNote = imgs.vulnFailed > 0 ? ` The vulnerability read failed for ${plural(imgs.vulnFailed, 'running image')}: unknown.` : '';
  const worst = imgs.p0.length ? 'P0' : imgs.p1.length ? 'P1' : null;
  if (worst) {
    const ids = [...imgs.p0, ...imgs.p1.filter((id) => !imgs.p0.includes(id))];
    const count = `${ids.length}${imgs.hotTruncated ? '+' : ''}`;
    return {
      // The count is P0 and P1 together; the colour is the worst of them.
      lens: 'vulns', tone: worst === 'P0' ? 'p0' : 'p1', text: `P0/P1 · ${count}`,
      label: `${count} P0/P1 vulnerabilit${ids.length === 1 ? 'y' : 'ies'} on running images, worst ${worst}: ${ids.slice(0, 5).join(', ')}${ids.length > 5 ? ', …' : ''}.${partialNote}${failedNote}${scope}`,
    };
  }
  if (imgs.vulnFailed > 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'read failed', label: `Unknown: the vulnerability read failed for ${plural(imgs.vulnFailed, 'running image')} of ${n}. Retry with Refresh.` };
  }
  if (imgs.untiered > 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'tier ?', label: 'No tier yet: not computed, or this Broker predates tiers. P0/P1 unknown here, not low.' };
  }
  if (imgs.withVulnData === 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'no data', label: 'No source has reported on the images this workload runs: vulnerabilities unknown, not clean.' };
  }
  if (missing > 0) {
    return { lens: 'vulns', tone: 'unknown', text: 'partial', label: `No P0/P1 in the reported images.${partialNote}` };
  }
  return { lens: 'vulns', tone: 'neutral', text: 'no P0/P1', label: `Reported on; the Broker ranks no finding on its running images P0 or P1. Lower tiers may exist.${scope}` };
}

/** Supply chain lens badge: SBOM presence and trust. Signatures are not checked yet and never shown as signed. */
export function supplyBadge(imgs: WorkloadImages | undefined): LensBadge {
  const sig = ' Signatures: not checked.';
  if (!imgs || imgs.digests.length === 0) {
    return { lens: 'supply', tone: 'unknown', text: 'no data', label: `No running image of this workload is in the image inventory.${sig}` };
  }
  const n = imgs.digests.length;
  if (imgs.sbomFailed > 0 && imgs.withSbom + imgs.sbomFailed >= n && imgs.withVerifiedSbom < n) {
    return { lens: 'supply', tone: 'unknown', text: 'read failed', label: `Unknown: the SBOM read failed for ${plural(imgs.sbomFailed, 'running image')} of ${n}. Retry with Refresh.${sig}` };
  }
  if (imgs.withVerifiedSbom === n) {
    return { lens: 'supply', tone: 'good', text: 'SBOM verified', label: `Every running image has an SBOM from a verified attestation.${sig}` };
  }
  if (imgs.withSbom === n) {
    return { lens: 'supply', tone: 'neutral', text: 'SBOM', label: `Every running image has an SBOM; ${imgs.withVerifiedSbom === 0 ? 'none' : `${imgs.withVerifiedSbom} of ${n}`} verified.${sig}` };
  }
  if (imgs.withSbom === 0 && imgs.sbomFailed === 0) {
    return { lens: 'supply', tone: 'unknown', text: 'no SBOM', label: `No SBOM from any source for its ${plural(n, 'running image')}.${sig}` };
  }
  return {
    lens: 'supply', tone: 'unknown', text: `SBOM ${imgs.withSbom}/${n}`,
    label: `${imgs.withSbom} of ${n} running images have an SBOM${imgs.sbomFailed ? `; the read failed for ${imgs.sbomFailed} (unknown)` : ''}.${sig}`,
  };
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

/** Why a card may have no badge of its own: nothing to say, a read failed, or the read was capped. */
export interface LensGaps {
  /** Some per-image reads failed, so an unmatched workload may be one of them. */
  readFailures: number;
  /** A page was capped, so an unmatched workload may simply not have been read. */
  truncated: boolean;
}

/**
 * Workload badges → map node ids (a node groups a workload's pods). Every
 * in-cluster card gets one: no badge would read as clean. A card with no
 * badge of its own is "no data" only when every read succeeded and nothing
 * was capped; otherwise it is unknown because it was not read.
 */
export function badgesByNode(lens: Exclude<MapLens, 'traffic'>, byWorkload: Map<string, LensBadge>, nodes: PodNodeData[], gaps: LensGaps = { readFailures: 0, truncated: false }): Map<string, LensBadge> {
  const out = new Map<string, LensBadge>();
  const fallback: LensBadge =
    gaps.readFailures > 0
      ? { lens, tone: 'unknown', text: 'read failed', label: `Unknown: ${plural(gaps.readFailures, 'read')} failed, and this workload may be behind one. Retry with Refresh.` }
      : gaps.truncated
        ? { lens, tone: 'unknown', text: 'not read', label: 'Unknown: the lens reads a capped page, and this workload was not in it.' }
        : { vulns: vulnBadge(undefined), supply: supplyBadge(undefined), coverage: coverageBadge(undefined) }[lens];
  for (const n of nodes) {
    if (n.isExternal) continue;
    let badge: LensBadge | undefined;
    for (const p of n.pods.length > 0 ? n.pods : [n.pod]) {
      const w = workloadOf(p);
      badge = w ? byWorkload.get(workloadKey(w.namespace, w.kind, w.name)) : undefined;
      if (badge) break;
    }
    out.set(n.id, badge ?? fallback);
  }
  return out;
}

async function readImages(api: VulnApi, namespace: string, mode: 'vulns' | 'supply'): Promise<{ images: ImageFacts[]; truncated: boolean; readFailures: number }> {
  const page = await api.listImages({ namespace, limit: LENS_IMAGE_CAP });
  let readFailures = 0;
  const images = await withConcurrencyLimit(
    page.items.map((img) => async (): Promise<ImageFacts> => {
      const [d, v, s] = await Promise.allSettled([
        api.getImage(img.digest),
        mode === 'vulns' ? api.getImageVulns(img.digest, { tier: ['P0', 'P1'], limit: LENS_FINDINGS_CAP }) : api.getImageVulns(img.digest, { limit: 1 }),
        mode === 'supply' ? api.getImageSbom(img.digest, { limit: 1 }).then((p) => p.reports) : Promise.resolve(null),
      ]);
      // A failed read is unknown, never "none": it is counted, and the
      // workloads it would have covered say "read failed".
      readFailures += [d, v, s].filter((r) => r.status === 'rejected').length;
      const vv = v.status === 'fulfilled' ? v.value : null;
      const facts: ImageFacts = {
        digest: img.digest,
        workloads: d.status === 'fulfilled' ? d.value.workloads : [],
        vulnReports: vv?.reports ?? null,
        sbomReports: s.status === 'fulfilled' ? s.value : null,
        vulnFailed: v.status === 'rejected',
        sbomFailed: s.status === 'rejected',
      };
      if (mode === 'vulns' && vv) {
        const tiered = vv.items.length === 0 ? null : vv.items.every((f) => f.tier != null);
        // An older Broker ignored the filter: its findings are not P0/P1 by anyone's ranking.
        facts.hot = tiered ? vv.items : [];
        facts.tiered = tiered;
        facts.hotTruncated = tiered === true && vv.nextAfter !== null;
      }
      return facts;
    }),
    LENS_CONCURRENCY,
  );
  return { images, truncated: page.nextAfter !== null, readFailures };
}

export interface MapLensState {
  byWorkload: Map<string, LensBadge>;
  loading: boolean;
  error: unknown;
  /** Something was capped: say so in the legend. */
  truncated: boolean;
  /** Per-image reads that failed: those cards say "read failed". */
  readFailures: number;
}

/**
 * Badges for one namespace's workloads under the chosen lens. Reads only
 * while a non-traffic lens is on; bounded (one image page, LENS_FINDINGS_CAP
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
  const [state, setState] = useState<MapLensState>({ byWorkload: new Map(), loading: false, error: null, truncated: false, readFailures: 0 });
  const seq = useRef(0);

  const load = useCallback(async () => {
    const id = ++seq.current;
    const current = () => id === seq.current;
    if (lens === 'traffic') {
      setState({ byWorkload: new Map(), loading: false, error: null, truncated: false, readFailures: 0 });
      return;
    }
    setState((s) => ({ ...s, byWorkload: s.byWorkload, loading: true, error: null }));
    try {
      const out = new Map<string, LensBadge>();
      let truncated = false;
      let readFailures = 0;
      if (lens === 'coverage') {
        const page = await profileApi.listWorkloads({ namespace, limit: 500 });
        for (const p of page.items) out.set(workloadKey(p.namespace, p.kind, p.name), coverageBadge(p));
        truncated = page.nextAfter !== null;
      } else {
        const { images, truncated: t, readFailures: f } = await readImages(vulnApi, namespace, lens);
        for (const [k, v] of imagesByWorkload(images)) {
          const b = lens === 'supply' ? supplyBadge(v) : vulnBadge(v);
          // A capped image page may have left some of this workload's images
          // unread: "nothing urgent" is then not a finished assessment.
          out.set(k, t && b.tone === 'neutral' ? { ...b, tone: 'unknown', label: `${b.label} Not every image was read (capped), so this is incomplete.` } : b);
        }
        truncated = t || images.some((i) => i.hotTruncated);
        readFailures = f;
      }
      if (!current()) return;
      setState({ byWorkload: out, loading: false, error: null, truncated, readFailures });
    } catch (err) {
      if (current()) setState({ byWorkload: new Map(), loading: false, error: err, truncated: false, readFailures: 0 });
    }
  }, [lens, namespace, vulnApi, profileApi]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch while a lens is on / namespace / refresh
    void load();
  }, [load, refreshTick]);

  return state;
}
