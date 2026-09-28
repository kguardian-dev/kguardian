import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { seccompApi, SeccompApiError, type SeccompApi } from '../services/seccompApi';
import type { WorkloadProfileDetail, WorkloadProfileSummary } from '../types/seccompWorkload';

function describe(err: unknown): string {
  if (err instanceof SeccompApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

/**
 * The per-workload profile list from `GET /seccomp/profiles` (read-only).
 * Polls while mounted so CR readiness (`ready/total`) and drift tick over as
 * the controller reconciles. `loading` is the first read only; a failed poll
 * keeps the previous rows and sets `error`.
 */
export function useSeccompProfiles(pollMs = 15_000) {
  const api = useMemo(() => seccompApi, []);
  const [profiles, setProfiles] = useState<WorkloadProfileSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const inflight = useRef(false);

  const refresh = useCallback(async () => {
    if (inflight.current) return;
    inflight.current = true;
    try {
      const rows = await api.listProfiles();
      setProfiles(rows);
      setError(null);
    } catch (err) {
      setError(describe(err));
    } finally {
      inflight.current = false;
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as usePodData
    void refresh();
    if (pollMs <= 0) return;
    const t = setInterval(() => void refresh(), pollMs);
    return () => clearInterval(t);
  }, [refresh, pollMs]);

  return { api, profiles, loading, error, refresh };
}

/** One workload's detail (summary + rendered effective profile). `errorStatus` is the HTTP status behind `error`, when there was one. */
export function useSeccompProfileDetail(api: SeccompApi, ns: string | null, kind: string | null, name: string | null) {
  const [detail, setDetail] = useState<WorkloadProfileDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);

  const reload = useCallback(async () => {
    if (!ns || !kind || !name) {
      setDetail(null);
      return;
    }
    setLoading(true);
    try {
      setDetail(await api.getProfile(ns, kind, name));
      setError(null);
      setErrorStatus(null);
    } catch (err) {
      setError(describe(err));
      setErrorStatus(err instanceof SeccompApiError ? err.status : null);
    } finally {
      setLoading(false);
    }
  }, [api, ns, kind, name]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as usePodData
    void reload();
  }, [reload]);

  return { detail, setDetail, loading, error, errorStatus, reload };
}

export interface WorkloadRef {
  namespace: string;
  kind: string;
  name: string;
}

/** Workloads the fallback reads at most, and how many reads are in flight at once. */
export const SECCOMP_FALLBACK_LIMIT = 50;
export const SECCOMP_FALLBACK_CONCURRENCY = 4;

const EMPTY: ReadonlyMap<string, WorkloadProfileSummary | null> = new Map();
const keyOf = (w: WorkloadRef) => `${w.namespace}/${w.kind}/${w.name}`;

/**
 * `GET /seccomp/profiles/{ns}/{kind}/{name}` for each of `workloads` while
 * the list read is unavailable: that route answers in well under a second
 * where the list can hit the statement timeout. Bounded to the first
 * SECCOMP_FALLBACK_LIMIT workloads given, through one queue with at most
 * SECCOMP_FALLBACK_CONCURRENCY reads in flight however often the list of
 * workloads changes; a workload no longer shown is dropped from the queue
 * before it is read, and nothing new is issued after unmount. Results are
 * kept by `ns/kind/name` and forgotten on `resetTick` (the header Refresh);
 * `null` means the Broker has no profile for that workload (404). A read
 * that fails otherwise leaves the workload unknown.
 */
export function useSeccompProfileFallback(
  api: SeccompApi,
  enabled: boolean,
  workloads: readonly WorkloadRef[],
  resetTick = 0,
): ReadonlyMap<string, WorkloadProfileSummary | null> {
  const [results, setResults] = useState<{ tick: number; map: Map<string, WorkloadProfileSummary | null> }>({ tick: resetTick, map: new Map() });
  const known = useRef(new Map<string, WorkloadProfileSummary | null>());
  const inFlight = useRef(new Set<string>());
  const queue = useRef<WorkloadRef[]>([]);
  const wantedKeys = useRef(new Set<string>());
  const tick = useRef(resetTick);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const pump = useCallback(() => {
    function run() {
      while (mounted.current && inFlight.current.size < SECCOMP_FALLBACK_CONCURRENCY && queue.current.length > 0) {
        const w = queue.current.shift()!;
        const k = keyOf(w);
        if (known.current.has(k) || inFlight.current.has(k) || !wantedKeys.current.has(k)) continue;
        inFlight.current.add(k);
        const forTick = tick.current;
        void api
          .getProfile(w.namespace, w.kind, w.name)
          .then(
            (d): WorkloadProfileSummary | null | undefined => d,
            (err: unknown) => (err instanceof SeccompApiError && err.status === 404 ? null : undefined),
          )
          .then((value) => {
            inFlight.current.delete(k);
            if (!mounted.current) return;
            if (tick.current !== forTick) {
              // Answered for a window the user has refreshed away: read it again for the new one.
              if (wantedKeys.current.has(k)) queue.current.push(w);
            } else if (value !== undefined) {
              known.current.set(k, value);
              setResults({ tick: forTick, map: new Map(known.current) });
            }
            run();
          });
      }
    }
    run();
  }, [api]);

  const wanted = useMemo(() => workloads.slice(0, SECCOMP_FALLBACK_LIMIT), [workloads]);
  const wantedKey = wanted.map(keyOf).join('\n');

  useEffect(() => {
    if (tick.current !== resetTick) {
      tick.current = resetTick;
      known.current = new Map();
    }
    // The queue is what is shown now and not yet read; the reads already in flight finish.
    wantedKeys.current = new Set(enabled ? wanted.map(keyOf) : []);
    queue.current = enabled ? wanted.filter((w) => !known.current.has(keyOf(w)) && !inFlight.current.has(keyOf(w))) : [];
    pump();
    // `wantedKey` stands for `wanted`: same workloads, same reads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, wantedKey, resetTick, pump]);

  return results.tick === resetTick ? results.map : EMPTY;
}

export { describe as describeSeccompError };
