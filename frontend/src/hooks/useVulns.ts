import { useCallback, useEffect, useRef, useState } from 'react';
import { vulnApi, VulnApiError, type CveListQuery, type VulnApi } from '../services/vulnApi';
import type { CatalogCoverage, CveSummary, ExposedImage, Exposure, Finding, ImageDetail, ImageSummary, Report, SbomPage } from '../types/vulns';
import { withConcurrencyLimit } from '../utils/concurrency';
import { profileApi, type ProfileApi } from '../services/profileApi';
import type { LevelConfidence, PssLevel } from '../types/profile';
import { workloadKey } from '../utils/workloads';
import { mergeFindings, sameVulnId, VULN_SEVERITY_RANK } from '../utils/vulnView';

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
 * rebuild, which is "not computed yet", not "no CVEs"). `order` is `tier`
 * when the Broker ranks the whole list by tier, null from an older Broker.
 * A Load more whose cursor the Broker refuses as one from an older list
 * order (it was upgraded meanwhile) quietly reads the first page again.
 */
export function useCveList(q: Omit<CveListQuery, 'after' | 'limit'>, refreshTick = 0, api: VulnApi = vulnApi) {
  const [items, setItems] = useState<CveSummary[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [computedAt, setComputedAt] = useState<string | null>(null);
  const [staleSeconds, setStaleSeconds] = useState<number | null>(null);
  // When `staleSeconds` was true (this browser's clock), so the age can keep counting.
  const [receivedAt, setReceivedAt] = useState<number | null>(null);
  // The order the Broker says the list is in: `tier`, or null (an older Broker, most severe first).
  const [order, setOrder] = useState<'tier' | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  const key = JSON.stringify(q);
  const loadedFor = useRef<string | null>(null);
  // A first page in flight owns the sequence: a page-more issued meanwhile would supersede it and page the wrong list.
  const firstPageInFlight = useRef(false);

  const load = useCallback(async () => {
    const current = begin();
    firstPageInFlight.current = true;
    setLoading(true);
    // A new first page supersedes any page-more in flight, whose own reset is skipped.
    setLoadingMore(false);
    // Another scope's or filter's rows are not this one's; a same-query Refresh keeps them until the new page lands.
    if (loadedFor.current !== key) {
      loadedFor.current = key;
      setItems([]);
      setNextAfter(null);
      setError(null);
    }
    try {
      const p = await api.listCves({ ...(JSON.parse(key) as CveListQuery), limit: CVE_PAGE_SIZE });
      if (!current()) return;
      setItems(p.items);
      setNextAfter(p.nextAfter);
      setComputedAt(p.computedAt);
      setStaleSeconds(p.staleSeconds);
      setReceivedAt(Date.now());
      setOrder(p.order === 'tier' ? 'tier' : null);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) {
        firstPageInFlight.current = false;
        setLoading(false);
      }
    }
  }, [api, key, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / filter change / refresh
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!nextAfter || firstPageInFlight.current) return;
    const current = begin();
    setLoadingMore(true);
    try {
      const p = await api.listCves({ ...(JSON.parse(key) as CveListQuery), limit: CVE_PAGE_SIZE, after: nextAfter });
      if (!current()) return;
      setItems((prev) => [...prev, ...p.items]);
      setNextAfter(p.nextAfter);
      setError(null);
    } catch (err) {
      if (!current()) return;
      // The Broker was upgraded while the list was open: its cursor belongs to the old order. Start again from the first page.
      if (isOlderOrderCursor(err)) await load();
      else setError(err);
    } finally {
      if (current()) setLoadingMore(false);
    }
  }, [api, key, nextAfter, begin, load]);

  return { items, computedAt, staleSeconds, receivedAt, order, loading, loadingMore, error, hasMore: nextAfter !== null, loadMore, reload: load };
}

/** The Broker's 400 for a `?after=` cursor from its previous (severity-first) list order. */
const OLDER_ORDER_CURSOR = 'after is a cursor from an older list order';
const isOlderOrderCursor = (err: unknown) => err instanceof VulnApiError && err.status === 400 && err.message.startsWith(OLDER_ORDER_CURSOR);

/** Rows one scope-only read covers for the header tiles (the Broker clamps `limit` to 500). */
export const CVE_TOTALS_LIMIT = 500;

/**
 * The CVE summary for the scope alone, no table filters, in one read of up
 * to CVE_TOTALS_LIMIT rows: what the header tiles count. `capped` when the
 * Broker had more rows than that, so every tile is a lower bound over the
 * first rows in the list's `order`: by tier (`tier`), or most severe first
 * (null, an older Broker).
 */
export function useCveTotals(namespace: string | undefined, refreshTick = 0, api: VulnApi = vulnApi) {
  const [items, setItems] = useState<CveSummary[]>([]);
  const [capped, setCapped] = useState(false);
  const [order, setOrder] = useState<'tier' | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  const scope = useRef(namespace);

  const load = useCallback(async () => {
    const current = begin();
    setLoading(true);
    // Another scope's counts are not this one's; a same-scope Refresh keeps them until the new read lands.
    if (scope.current !== namespace) {
      scope.current = namespace;
      setItems([]);
      setCapped(false);
      setError(null);
    }
    try {
      const p = await api.listCves({ ...(namespace ? { namespace } : {}), limit: CVE_TOTALS_LIMIT });
      if (!current()) return;
      setItems(p.items);
      setCapped(p.nextAfter !== null);
      setOrder(p.order === 'tier' ? 'tier' : null);
      setError(null);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) setLoading(false);
    }
  }, [api, namespace, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / scope change / refresh
    void load();
  }, [load, refreshTick]);

  return { items, capped, order, loading, error, reload: load };
}

/** Images per CVE whose findings the drawer reads (tier, factors, KEV/EPSS). */
export const CVE_IMAGE_READS = 10;
/** Findings per page of an image read in the drawer (the Broker's maximum). */
export const CVE_FINDING_PAGE_SIZE = 500;
/** Pages of one image's findings the drawer reads looking for the CVE, for a Broker that ignores `vuln_id`. */
export const CVE_FINDING_PAGES = 4;

/**
 * Every finding of CVE `id` in one image: one per package and version that
 * carries it. The read asks for that CVE alone (`vuln_id`), so a Broker that
 * supports it answers in one page. An older Broker ignores the parameter and
 * returns every finding, so rows of other CVEs are still skipped here and
 * the read pages until each package the exposure lists is found, the
 * findings (most severe first) are past the CVE's least severe package, or
 * the image has no more. `complete` is false when CVE_FINDING_PAGES ran out
 * first: what was found is part of the answer, not all of it. Stops (and
 * `signal` aborts the read in flight) once the drawer has moved on.
 */
async function cveFindingsIn(api: VulnApi, id: string, img: ExposedImage, current: () => boolean, signal: AbortSignal): Promise<{ matches: Finding[]; complete: boolean }> {
  const missing = new Set(img.packages.map((p) => `${p.name}@${p.installedVersion}`));
  const floor = Math.min(...img.packages.map((p) => VULN_SEVERITY_RANK[p.severity] ?? 0));
  const matches: Finding[] = [];
  let after: string | undefined;
  for (let page = 0; page < CVE_FINDING_PAGES; page++) {
    if (!current()) break;
    const v = await api.getImageVulns(img.digest, { vulnId: id, limit: CVE_FINDING_PAGE_SIZE, ...(after ? { after } : {}) }, signal);
    for (const f of v.items) {
      if (!sameVulnId(f.id, id)) continue;
      matches.push(f);
      missing.delete(`${f.package.name}@${f.installedVersion}`);
    }
    const last = v.items[v.items.length - 1];
    if (!v.nextAfter || missing.size === 0 || (last && (VULN_SEVERITY_RANK[last.severity] ?? 0) < floor)) return { matches, complete: true };
    after = v.nextAfter;
  }
  return { matches, complete: false };
}

/**
 * One CVE for the triage drawer: its exposure (images → workloads →
 * running, with observed network exposure), plus the CVE's finding in each
 * affected image (first CVE_IMAGE_READS): the Broker's tier and tier
 * factors, KEV, EPSS, title and link, which the exposure read does not
 * carry. Findings arrive per image as each read settles:
 *  - `findings`: digest → the finding (the most urgent over every package
 *    carrying the CVE, utils/vulnView mergeFindings), or null (read, CVE
 *    not in it);
 *  - `failed`: digests whose read failed;
 *  - `incomplete`: digests with more findings than the drawer reads, where
 *    some of the CVE's may not have been seen;
 *  - `pending`: reads still in flight.
 * `finding` is only for descriptive text (title, link); risk comes from
 * every row (utils/vulnView cveHeadline).
 */
export function useCveDetail(id: string | null, api: VulnApi = vulnApi) {
  const [exposure, setExposure] = useState<Exposure | null>(null);
  const [findings, setFindings] = useState<Map<string, Finding | null>>(new Map());
  const [failed, setFailed] = useState<Set<string>>(new Set());
  const [incomplete, setIncomplete] = useState<Set<string>>(new Set());
  const [pending, setPending] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useLatest();
  // The run in flight: a closed drawer or another CVE aborts its reads, so up to CVE_IMAGE_READS x CVE_FINDING_PAGES heavy reads are not left paging.
  const inFlight = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    inFlight.current?.abort();
    const current = begin();
    const abort = new AbortController();
    inFlight.current = abort;
    setLoading(Boolean(id));
    setExposure(null);
    setFindings(new Map());
    setFailed(new Set());
    setIncomplete(new Set());
    setPending(0);
    setError(null);
    if (!id) return;
    try {
      const e = await api.getExposure(id, undefined, abort.signal);
      if (!current()) return;
      const toRead = e.images.slice(0, CVE_IMAGE_READS);
      setExposure(e);
      setPending(toRead.length);
      setError(null);
      await withConcurrencyLimit(
        toRead.map((img) => async () => {
          if (!current()) return;
          try {
            const { matches, complete } = await cveFindingsIn(api, id, img, current, abort.signal);
            if (!current()) return;
            setFindings((prev) => new Map(prev).set(img.digest, mergeFindings(matches)));
            if (!complete) setIncomplete((prev) => new Set(prev).add(img.digest));
          } catch {
            // That image's tier and KEV / EPSS are unknown; the headline says the read failed.
            if (current()) setFailed((prev) => new Set(prev).add(img.digest));
          } finally {
            if (current()) setPending((n) => n - 1);
          }
        }),
        3,
      );
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
  // Unmounted (the drawer closed): stop its reads, and nothing of the run counts as current.
  useEffect(
    () => () => {
      inFlight.current?.abort();
      begin();
    },
    [begin],
  );

  // Descriptive text only (title, advisory link): the first image's finding.
  let finding: Finding | null = null;
  for (const img of exposure?.images ?? []) {
    const f = findings.get(img.digest);
    if (f) {
      finding = f;
      break;
    }
  }
  return { exposure, findings, failed, incomplete, pending, finding, loading, error, reload: load };
}

export const IMAGE_PAGE_SIZE = 25;
/** Per-digest reads in flight at once while enriching an Images page. */
export const IMAGE_ENRICH_CONCURRENCY = 6;

/**
 * What the Images table adds to each inventory row (two or three reads per
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
  /** SBOM reports (every source, with trust); [] = no SBOM; null with `sbomSkipped` = not read. */
  sbomReports: Report[] | null;
  sbomError: unknown;
  /** The SBOM read was skipped: no source reported on the digest, so nothing was matched from an SBOM. */
  sbomSkipped: boolean;
}

/**
 * `GET /images` one page (25 digests) at a time, each digest enriched with
 * its workloads and vulnerability reports, then its SBOM reports when a
 * source reported on it, at most IMAGE_ENRICH_CONCURRENCY digests in flight.
 * Enrichment is cached per digest for the session; a Refresh keeps the
 * cells on screen until their re-read lands.
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
  // A first page in flight owns the sequence: a page-more issued meanwhile would supersede it and page the wrong list.
  const firstPageInFlight = useRef(false);
  const loadedFor = useRef<string | null>(null);

  const enrich = useCallback(
    async (rows: ImageSummary[], current: () => boolean) => {
      const tasks = rows.map((r) => async () => {
        const [d, v] = await Promise.allSettled([api.getImage(r.digest), api.getImageVulns(r.digest, { limit: 1 })]);
        // No report means nothing was matched from an SBOM, so that read is skipped (most digests on a cluster without a scanner); a failed report read still looks.
        // The one exception: a registry SBOM (`sbomSources`), whose trust varies and so needs its report. Trivy Operator and node SBOMs are always `scanned`, so they need no read to show.
        const skipSbom = v.status === 'fulfilled' && v.value.reports.length === 0 && !r.sbomSources?.includes('registry');
        let sb: PromiseSettledResult<SbomPage> | null = null;
        if (!skipSbom) [sb] = await Promise.allSettled([api.getImageSbom(r.digest, { limit: 1 })]);
        const e: ImageEnrichment = {
          workloads: d.status === 'fulfilled' ? d.value.workloads : null,
          workloadsTruncated: d.status === 'fulfilled' ? d.value.truncated : false,
          workloadsError: d.status === 'rejected' ? d.reason ?? 'read failed' : null,
          vulnReports: v.status === 'fulfilled' ? v.value.reports : null,
          vulnError: v.status === 'rejected' ? v.reason ?? 'read failed' : null,
          sbomReports: sb?.status === 'fulfilled' ? sb.value.reports : null,
          sbomError: sb?.status === 'rejected' ? sb.reason ?? 'read failed' : null,
          sbomSkipped: skipSbom,
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
    firstPageInFlight.current = true;
    setLoading(true);
    // A new first page supersedes any page-more in flight, whose own reset is skipped.
    setLoadingMore(false);
    // Another namespace's rows, cursor and error are not this one's; a same-scope Refresh keeps the rows until the new page lands.
    const scope = namespace ?? '';
    if (loadedFor.current !== scope) {
      loadedFor.current = scope;
      setItems([]);
      setNextAfter(null);
      setError(null);
    }
    try {
      const p = await api.listImages({ limit: IMAGE_PAGE_SIZE, ...(namespace ? { namespace } : {}) });
      if (!current()) return;
      // Cells already read stay until their re-read lands: a Refresh is not 25 rows of "…".
      setItems(p.items);
      setNextAfter(p.nextAfter);
      setError(null);
      firstPageInFlight.current = false;
      setLoading(false);
      await enrich(p.items, () => gen === listGen.current);
    } catch (err) {
      if (current()) setError(err);
    } finally {
      if (current()) {
        firstPageInFlight.current = false;
        setLoading(false);
      }
    }
  }, [api, namespace, begin, enrich]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / scope change / refresh
    void load();
  }, [load, refreshTick]);

  const loadMore = useCallback(async () => {
    if (!nextAfter || firstPageInFlight.current) return;
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
  const loadedFor = useRef<string | null>(null);
  // A first page in flight owns the sequence: a page-more issued meanwhile would supersede it and page the wrong list.
  const firstPageInFlight = useRef(false);

  const load = useCallback(async () => {
    if (!digest) return;
    const current = begin();
    firstPageInFlight.current = true;
    setLoading(true);
    // A new first page supersedes any page-more in flight, whose own reset is skipped.
    setLoadingMore(false);
    // A new digest starts empty, so nothing of the previous image shows under it; a same-digest reload keeps its rows.
    if (loadedFor.current !== digest) {
      loadedFor.current = digest;
      setReports(null);
      setItems([]);
      setNextAfter(null);
    }
    setError(null);
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
      if (current()) {
        firstPageInFlight.current = false;
        setLoading(false);
      }
    }
  }, [api, digest, pageSize, begin]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on digest change
    void load();
  }, [load]);

  const loadMore = useCallback(async () => {
    if (!digest || !nextAfter || firstPageInFlight.current) return;
    const current = begin();
    setLoadingMore(true);
    try {
      const p = await api.getImageVulns(digest, { limit: pageSize, after: nextAfter });
      if (!current()) return;
      setItems((prev) => [...prev, ...p.items]);
      setNextAfter(p.nextAfter);
      setError(null);
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
              // A workload whose snapshots all failed has no dimensions: unknown, like a missing one.
              if (w.computedAt === null) continue;
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

/**
 * `GET /catalog/coverage` for the Images page banner. Null while loading
 * and whenever there is nothing to show: an older Broker (404), a busy one
 * (503), any other failure, or a Broker whose node catalog was never
 * enabled. It never gates the page and never shows an error.
 */
export function useCatalogCoverage(refreshTick = 0, api: VulnApi = vulnApi): CatalogCoverage | null {
  const [coverage, setCoverage] = useState<CatalogCoverage | null>(null);
  useEffect(() => {
    const abort = new AbortController();
    api.getCatalogCoverage(abort.signal).then(
      (c) => {
        if (!abort.signal.aborted) setCoverage(c);
      },
      () => {
        if (!abort.signal.aborted) setCoverage(null);
      },
    );
    return () => abort.abort();
  }, [api, refreshTick]);
  return coverage;
}
