import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { vulnApi, type VulnApi } from '../services/vulnApi';
import type { RunningImageSignature } from '../types/attestations';
import { signaturesByDigest, signaturesByWorkload, type DigestSignature, type WorkloadSignatures } from '../utils/signatures';
import { workloadKey } from '../utils/workloads';

/** `/attestations/running` page size (the Broker's maximum). */
export const RUNNING_PAGE_SIZE = 200;
/** Pages read before stopping (10,000 containers): beyond this the result says it is capped. */
export const RUNNING_MAX_PAGES = 50;

/** How far a running-feed read has got. */
export interface RunningProgress {
  pages: number;
  items: number;
}

export interface RunningSignatures {
  items: RunningImageSignature[];
  loading: boolean;
  error: unknown;
  /** More containers exist than were read. */
  truncated: boolean;
  /** Set while a read is in flight; null once it has settled. */
  progress: RunningProgress | null;
  /** `items` are the pages read so far of a first read, not the whole feed yet. */
  partial: boolean;
  reload: () => Promise<void>;
}

/**
 * Every running workload container's image verdict, for a namespace or the
 * cluster, paged to completion (or the cap). `onPage` sees the rows read so
 * far after each page; `last` says whether that page was the final one.
 * `cancelled` is checked around every page, so a caller that moved on
 * (scope change, unmount) stops the paging instead of reading a feed nobody
 * will see; the result is then incomplete and marked truncated.
 */
export async function readRunningSignatures(
  api: VulnApi,
  namespace?: string,
  opts: { onPage?: (items: RunningImageSignature[], progress: RunningProgress, last: boolean) => void; cancelled?: () => boolean } = {},
): Promise<{ items: RunningImageSignature[]; truncated: boolean }> {
  const items: RunningImageSignature[] = [];
  let after: string | undefined;
  for (let page = 0; page < RUNNING_MAX_PAGES; page++) {
    if (opts.cancelled?.()) break;
    const p = await api.listRunningSignatures({ limit: RUNNING_PAGE_SIZE, ...(namespace ? { namespace } : {}), ...(after ? { after } : {}) });
    if (opts.cancelled?.()) break;
    items.push(...p.items);
    opts.onPage?.(items, { pages: page + 1, items: items.length }, !p.nextAfter);
    if (!p.nextAfter) return { items, truncated: false };
    after = p.nextAfter;
  }
  return { items, truncated: true };
}

export function useRunningSignatures(namespace: string | undefined, refreshTick = 0, api: VulnApi = vulnApi, enabled = true): RunningSignatures {
  const [items, setItems] = useState<RunningImageSignature[]>([]);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<unknown>(null);
  const [truncated, setTruncated] = useState(false);
  const [progress, setProgress] = useState<RunningProgress | null>(null);
  const [partial, setPartial] = useState(false);
  const seq = useRef(0);
  const shown = useRef(0);
  const scope = useRef(namespace);

  const load = useCallback(async () => {
    if (!enabled) return;
    const id = ++seq.current;
    const live = () => id === seq.current;
    setLoading(true);
    setProgress({ pages: 0, items: 0 });
    // Another scope's rows are not a lower bound for this one.
    if (scope.current !== namespace) {
      scope.current = namespace;
      shown.current = 0;
      setItems([]);
      setTruncated(false);
    }
    // A first read shows rows as pages land; a refresh keeps the rows on screen until the new set is complete.
    const firstRead = shown.current === 0;
    let complete = false;
    try {
      const r = await readRunningSignatures(api, namespace, {
        cancelled: () => !live(),
        onPage: (soFar, p, last) => {
          if (!live()) return;
          setProgress(p);
          if (firstRead && !last) {
            shown.current = soFar.length;
            setItems([...soFar]);
            setPartial(true);
          }
        },
      });
      if (!live()) return;
      shown.current = r.items.length;
      setItems(r.items);
      setTruncated(r.truncated);
      setError(null);
      complete = true;
    } catch (err) {
      // Rows already on screen stay (marked stale by the caller); a first read shows the error.
      if (live()) setError(err);
    } finally {
      if (live()) {
        setLoading(false);
        setProgress(null);
        // Pages of a first read that failed midway stay on screen as a lower bound, not as the whole feed.
        setPartial(!complete && firstRead && shown.current > 0);
      }
    }
  }, [api, namespace, enabled]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on scope / refresh
    void load();
    // Leaving (scope change, refresh, unmount) abandons the read in flight: its paging stops.
    return () => {
      seq.current += 1;
    };
  }, [load, refreshTick]);

  return { items, loading, error, truncated, progress, partial, reload: load };
}

export interface WorkloadSignatureState {
  /** null until read, or when the workload runs nothing the Broker knows. */
  summary: WorkloadSignatures | null;
  rows: DigestSignature[];
  loading: boolean;
  error: unknown;
  truncated: boolean;
  reload: () => Promise<void>;
}

/** One workload's running images and their signature verdicts (its namespace's feed, filtered). */
export function useWorkloadSignatures(ns: string, kind: string, name: string, refreshTick = 0, api: VulnApi = vulnApi): WorkloadSignatureState {
  const running = useRunningSignatures(ns, refreshTick, api);
  const mine = useMemo(() => running.items.filter((i) => i.namespace === ns && i.workloadKind === kind && i.workloadName === name), [running.items, ns, kind, name]);
  const summary = useMemo(() => signaturesByWorkload(mine, workloadKey).get(workloadKey(ns, kind, name)) ?? null, [mine, ns, kind, name]);
  const rows = useMemo(() => signaturesByDigest(mine), [mine]);
  return { summary, rows, loading: running.loading, error: running.error, truncated: running.truncated, reload: running.reload };
}
