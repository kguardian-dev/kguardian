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
 * the controller reconciles.
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

/** One workload's detail (summary + rendered effective profile). */
export function useSeccompProfileDetail(api: SeccompApi, ns: string | null, kind: string | null, name: string | null) {
  const [detail, setDetail] = useState<WorkloadProfileDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    if (!ns || !kind || !name) {
      setDetail(null);
      return;
    }
    setLoading(true);
    try {
      setDetail(await api.getProfile(ns, kind, name));
      setError(null);
    } catch (err) {
      setError(describe(err));
    } finally {
      setLoading(false);
    }
  }, [api, ns, kind, name]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as usePodData
    void reload();
  }, [reload]);

  return { detail, setDetail, loading, error, reload };
}

export { describe as describeSeccompError };
