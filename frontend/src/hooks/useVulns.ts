import { useCallback, useEffect, useRef, useState } from 'react';
import { vulnApi, type CveListQuery, type VulnApi } from '../services/vulnApi';
import type { CveSummary, Exposure, Finding, ImageDetail, ImageSummary, Report } from '../types/vulns';
import { withConcurrencyLimit } from '../utils/concurrency';
import { brokerTier, tierRank } from '../utils/tiers';
import { profileApi, type ProfileApi } from '../services/profileApi';
import type { LevelConfidence, PssLevel } from '../types/profile';
import { workloadKey } from '../utils/workloads';

/** Drop a response for a request the user has already moved away from. */
function useLatest() {
  const seq = useRef(0);
  return useCallback(() => {
    const id = ++seq.current;
    return () => id === seq.current;
  }, []);
}

export const CVE_PAGE_SIZE = 50;

/**
 * `GET /vulnerabilities`, one server page at a time (filters server-side),
 * with `loadMore`. The summary is rebuilt by the Broker on an interval;
 * `computedAt` / `staleSeconds` say how fresh it is (null until the first
 * rebuild, which is "not computed yet", not "no CVEs").
 */
export function useCveList(q: Omit<CveListQuery, 'after' | 'limit'>, refreshTick = 0, api: VulnApi = vulnApi) {
  const [items, setItems] = useState<CveSummary[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [computedAt, setComputedAt] = useState<string | null>(null);
  const [staleSeconds, setStaleSeconds] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  const key = JSON.stringify(q);

  const load = useCallback(async () => {
    const current = begin();
    setLoading(true);
    try {
      const p = await api.listCves({ ...(JSON.parse(key) as CveListQuery), limit: CVE_PAGE_SIZE });
      if (!current()) return;
      setItems(p.items);
      setNextAfter(p.nextAfter);
      setComputedAt(p.computedAt);
      setStaleSeconds(p.staleSeconds);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, key, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / filter change / refresh
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!nextAfter) return;
    const current = begin();
    setLoadingMore(true);
    try {
      const p = await api.listCves({ ...(JSON.parse(key) as CveListQuery), limit: CVE_PAGE_SIZE, after: nextAfter });
      if (!current()) return;
      setItems((prev) => [...prev, ...p.items]);
      setNextAfter(p.nextAfter);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [api, key, nextAfter, begin]);

  return { items, computedAt, staleSeconds, loading, loadingMore, error, hasMore: nextAfter !== null, loadMore, reload: load };
}

/** Images per CVE whose findings the drawer reads (tier, factors, KEV/EPSS). */
export const CVE_IMAGE_READS = 10;

/**
 * One CVE for the triage drawer: its exposure (images → workloads →
 * running, with observed network exposure), plus the CVE's finding in each
 * affected image (first CVE_IMAGE_READS): the Broker's tier and tier
 * factors, KEV, EPSS, title and link, which the exposure read does not
 * carry. `finding` is the most urgent one.
 */
export function useCveDetail(id: string | null, api: VulnApi = vulnApi) {
  const [exposure, setExposure] = useState<Exposure | null>(null);
  const [findings, setFindings] = useState<Map<string, Finding | null>>(new Map());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const load = useCallback(async () => {
    if (!id) return;
    const current = begin();
    setLoading(true);
    setExposure(null);
    setFindings(new Map());
    try {
      const e = await api.getExposure(id);
      if (!current()) return;
      setExposure(e);
      setError(null);
      const reads = await withConcurrencyLimit(
        e.images.slice(0, CVE_IMAGE_READS).map((img) => async () => {
          try {
            const v = await api.getImageVulns(img.digest, { limit: 500 });
            return [img.digest, v.items.find((f) => f.id === id) ?? null] as const;
          } catch {
            // Best effort: that image's tier and KEV / EPSS read as unknown.
            return [img.digest, null] as const;
          }
        }),
        3,
      );
      if (current()) setFindings(new Map(reads));
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, id, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch when the drawer opens / id changes
    void load();
  }, [load]);

  let finding: Finding | null = null;
  for (const f of findings.values()) {
    if (f && (!finding || tierRank(brokerTier(f.tier)) > tierRank(brokerTier(finding.tier)))) finding = f;
  }
  return { exposure, findings, finding, loading, error, reload: load };
}

export const IMAGE_PAGE_SIZE = 25;
/** Per-digest reads in flight at once while enriching an Images page. */
export const IMAGE_ENRICH_CONCURRENCY = 3;

/**
 * What the Images table adds to each inventory row (three reads per
 * digest). Each read settles on its own: a failed SBOM read leaves the
 * workloads and vulnerability columns intact, and says "Unknown" in its
 * own column only.
 */
export interface ImageEnrichment {
  workloads: ImageDetail['workloads'] | null;
  workloadsTruncated: boolean;
  workloadsError: unknown;
  /** Vulnerability reports; [] = no vulnerability data (unknown). */
  vulnReports: Report[] | null;
  vulnError: unknown;
  /** SBOM reports (every source, with trust); [] = no SBOM. */
  sbomReports: Report[] | null;
  sbomError: unknown;
}

/**
 * `GET /images` one page (25 digests) at a time, each digest enriched with
 * its workloads, vulnerability reports and SBOM reports, at most
 * IMAGE_ENRICH_CONCURRENCY reads in flight. Enrichment is cached per digest
 * for the session and refreshed on the header Refresh.
 */
export function useImageList(namespace: string | undefined, refreshTick = 0, api: VulnApi = vulnApi) {
  const [items, setItems] = useState<ImageSummary[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [enriched, setEnriched] = useState<Map<string, ImageEnrichment>>(new Map());
  // Two clocks: `begin` drops a stale page response; `listGen` only moves
  // on a fresh load (scope change / refresh), so "Load more" does not
  // cancel the enrichment of rows already on screen.
  const begin = useLatest();
  const listGen = useRef(0);

  const enrich = useCallback(
    async (rows: ImageSummary[], current: () => boolean) => {
      const tasks = rows.map((r) => async () => {
        const [d, v, sb] = await Promise.allSettled([api.getImage(r.digest), api.getImageVulns(r.digest, { limit: 1 }), api.getImageSbom(r.digest, { limit: 1 })]);
        const e: ImageEnrichment = {
          workloads: d.status === 'fulfilled' ? d.value.workloads : null,
          workloadsTruncated: d.status === 'fulfilled' ? d.value.truncated : false,
          workloadsError: d.status === 'rejected' ? d.reason ?? 'read failed' : null,
          vulnReports: v.status === 'fulfilled' ? v.value.reports : null,
          vulnError: v.status === 'rejected' ? v.reason ?? 'read failed' : null,
          sbomReports: sb.status === 'fulfilled' ? sb.value.reports : null,
          sbomError: sb.status === 'rejected' ? sb.reason ?? 'read failed' : null,
        };
        if (current()) setEnriched((prev) => new Map(prev).set(r.digest, e));
      });
      await withConcurrencyLimit(tasks, IMAGE_ENRICH_CONCURRENCY);
    },
    [api],
  );

  const load = useCallback(async () => {
    const current = begin();
    const gen = ++listGen.current;
    setLoading(true);
    try {
      const p = await api.listImages({ limit: IMAGE_PAGE_SIZE, ...(namespace ? { namespace } : {}) });
      if (!current()) return;
      setItems(p.items);
      setNextAfter(p.nextAfter);
      setEnriched(new Map());
      setError(null);
      setLoading(false);
      await enrich(p.items, () => gen === listGen.current);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, namespace, begin, enrich]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / scope change / refresh
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!nextAfter) return;
    const current = begin();
    const gen = listGen.current;
    setLoadingMore(true);
    try {
      const p = await api.listImages({ limit: IMAGE_PAGE_SIZE, after: nextAfter, ...(namespace ? { namespace } : {}) });
      if (!current()) return;
      setItems((prev) => [...prev, ...p.items]);
      setNextAfter(p.nextAfter);
      setLoadingMore(false);
      await enrich(p.items, () => gen === listGen.current);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [api, namespace, nextAfter, begin, enrich]);

  return { items, enriched, loading, loadingMore, error, hasMore: nextAfter !== null, loadMore, reload: load };
}

/** One image's findings, paged (the image drawer and the workload tab). */
export function useImageVulns(digest: string | null, api: VulnApi = vulnApi, pageSize = 100) {
  const [reports, setReports] = useState<Report[] | null>(null);
  const [items, setItems] = useState<Finding[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();

  const load = useCallback(async () => {
    if (!digest) return;
    const current = begin();
    setLoading(true);
    try {
      const p = await api.getImageVulns(digest, { limit: pageSize });
      if (!current()) return;
      setReports(p.reports);
      setItems(p.items);
      setNextAfter(p.nextAfter);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, digest, pageSize, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on digest change
    void load();
  }, [load]);

  const loadMore = useCallback(async () => {
    if (!digest || !nextAfter) return;
    const current = begin();
    setLoadingMore(true);
    try {
      const p = await api.getImageVulns(digest, { limit: pageSize, after: nextAfter });
      if (!current()) return;
      setItems((prev) => [...prev, ...p.items]);
      setNextAfter(p.nextAfter);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [api, digest, nextAfter, pageSize, begin]);

  return { reports, items, loading, loadingMore, error, hasMore: nextAfter !== null, loadMore, reload: load };
}

export type PssByWorkload = Map<string, { level: PssLevel | null; confidence: LevelConfidence | null }>;

/**
 * Pod Security Standards level per workload (key ns/kind/name) for the
 * given namespaces, from the workload profile list: the "Privileged" chip.
 * `null` until loaded (chips omitted); a workload missing from the result
 * reads as unknown, and so does every workload when the read fails.
 */
export function usePssByWorkload(namespaces: readonly string[], api: ProfileApi = profileApi): PssByWorkload | null {
  const [map, setMap] = useState<PssByWorkload | null>(null);
  const key = [...new Set(namespaces)].sort().join(',');
  useEffect(() => {
    let cancelled = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- reset while the namespaces change
    setMap(null);
    if (!key) return;
    void (async () => {
      const out: PssByWorkload = new Map();
      await withConcurrencyLimit(
        key.split(',').map((namespace) => async () => {
          try {
            const page = await api.listWorkloads({ namespace, limit: 500 });
            for (const w of page.items) {
              out.set(workloadKey(w.namespace, w.kind, w.name), { level: w.dimensions.podSecurity.level, confidence: w.dimensions.podSecurity.levelConfidence });
            }
          } catch {
            /* unknown for this namespace */
          }
        }),
        3,
      );
      if (!cancelled) setMap(out);
    })();
    return () => {
      cancelled = true;
    };
  }, [api, key]);
  return map;
}
