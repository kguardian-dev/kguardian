import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { vulnApi, type VulnApi } from '../services/vulnApi';
import type { RunningImageSignature } from '../types/attestations';
import { signaturesByDigest, signaturesByWorkload, type DigestSignature, type WorkloadSignatures } from '../utils/signatures';
import { workloadKey } from '../utils/workloads';

/** `/attestations/running` page size (the Broker's maximum). */
export const RUNNING_PAGE_SIZE = 200;
/** Pages read before stopping: beyond this the result says it is capped. */
export const RUNNING_MAX_PAGES = 5;

export interface RunningSignatures {
  items: RunningImageSignature[];
  loading: boolean;
  error: unknown;
  /** More containers exist than were read. */
  truncated: boolean;
  reload: () => Promise<void>;
}

/** Every running workload container's image verdict (paged to a cap), for a namespace or the cluster. */
export async function readRunningSignatures(api: VulnApi, namespace?: string): Promise<{ items: RunningImageSignature[]; truncated: boolean }> {
  const items: RunningImageSignature[] = [];
  let after: string | undefined;
  for (let page = 0; page < RUNNING_MAX_PAGES; page++) {
    const p = await api.listRunningSignatures({ limit: RUNNING_PAGE_SIZE, ...(namespace ? { namespace } : {}), ...(after ? { after } : {}) });
    items.push(...p.items);
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
  const seq = useRef(0);

  const load = useCallback(async () => {
    if (!enabled) return;
    const id = ++seq.current;
    setLoading(true);
    try {
      const r = await readRunningSignatures(api, namespace);
      if (id !== seq.current) return;
      setItems(r.items);
      setTruncated(r.truncated);
      setError(null);
    } catch (err) {
      // Rows already on screen stay (marked stale by the caller); a first read shows the error.
      if (id === seq.current) setError(err);
    } finally {
      if (id === seq.current) setLoading(false);
    }
  }, [api, namespace, enabled]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on scope / refresh
    void load();
  }, [load, refreshTick]);

  return { items, loading, error, truncated, reload: load };
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
