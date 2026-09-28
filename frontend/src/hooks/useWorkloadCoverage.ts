import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import api from '../services/api';
import type { AuditVerdict, PodInfo } from '../types';
import { buildWorkloadRows, verdictsForNamespace, type WorkloadRow } from '../utils/workloads';
import { useSeccompProfileFallback, useSeccompProfiles } from './useSeccompProfiles';

/**
 * Rows per verdict kind the coverage column reads. The broker caps
 * /audit/verdicts at 500 rows and has no per-policy or per-workload counts,
 * so this is a recent window, not history. Allow and WouldDeny are fetched
 * separately so a burst of Allow rows cannot push the would-denies out.
 */
export const COVERAGE_VERDICT_LIMIT = 500;

export interface WorkloadCoverageOptions {
  /**
   * The rows the table shows (its scope and name filter). While the seccomp
   * profile list is failing, the first of these are read one workload at a
   * time from `GET /seccomp/profiles/{ns}/{kind}/{name}` instead.
   */
  visible?: (row: WorkloadRow) => boolean;
}

/**
 * Everything the Workloads coverage table and the placeholder workload page
 * read, from endpoints the broker already serves: the cluster-wide pod list
 * (passed in — usePodData already holds it), the seccomp profile list
 * (polled), and the most recent audit verdicts (fetched on mount/refresh).
 */
export function useWorkloadCoverage(allPods: readonly PodInfo[], refreshTick = 0, namespace?: string, opts: WorkloadCoverageOptions = {}) {
  const seccomp = useSeccompProfiles();
  const [verdicts, setVerdicts] = useState<AuditVerdict[]>([]);
  const [verdictsUnavailable, setVerdictsUnavailable] = useState(false);

  const loadVerdicts = useCallback(async () => {
    // A failed verdict read leaves the window empty and is flagged: the
    // column then reads "not reported" and the would-deny tile a dash, never
    // "no policy" or 0. Always the cluster-wide window: the Broker's
    // `namespace=` filters on the POLICY's namespace, so it drops every
    // verdict from a cluster-scoped policy. A narrowed view keeps the
    // verdicts whose subject pod is in its namespace.
    const base = { limit: COVERAGE_VERDICT_LIMIT };
    const results = await Promise.allSettled([
      api.getAuditVerdicts({ ...base, verdict: 'WouldDeny' }),
      api.getAuditVerdicts({ ...base, verdict: 'Allow' }),
    ]);
    const ok = results.filter((r): r is PromiseFulfilledResult<AuditVerdict[]> => r.status === 'fulfilled');
    setVerdicts(ok.flatMap((r) => r.value));
    setVerdictsUnavailable(ok.length < results.length);
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as usePodData
    void loadVerdicts();
  }, [loadVerdicts]);

  const { refresh: refreshProfiles } = seccomp;
  const refresh = useCallback(async () => {
    await Promise.all([refreshProfiles(), loadVerdicts()]);
  }, [refreshProfiles, loadVerdicts]);

  // Reload on the header Refresh (skip the mount; the effects above load).
  const seenTick = useRef(refreshTick);
  useEffect(() => {
    if (seenTick.current === refreshTick) return;
    seenTick.current = refreshTick;
    void refresh();
  }, [refreshTick, refresh]);

  const scoped = useMemo(() => (namespace ? verdictsForNamespace(verdicts, namespace) : verdicts), [verdicts, namespace]);

  // No list yet, or the list failed with nothing cached: seccomp cells and
  // tiles are unknown, not "no profile" and 0.
  const seccompUnavailable = seccomp.profiles.length === 0 && (seccomp.loading || seccomp.error != null);
  const baseRows = useMemo(
    () => buildWorkloadRows(allPods, seccomp.profiles, scoped, { seccompUnavailable }),
    [allPods, seccomp.profiles, scoped, seccompUnavailable],
  );

  const { visible } = opts;
  const fallbackFor = useMemo(() => {
    if (!seccompUnavailable || seccomp.loading) return [];
    const shown = visible ? baseRows.filter(visible) : baseRows;
    return shown.map((r) => ({ namespace: r.namespace, kind: r.kind, name: r.name }));
  }, [baseRows, visible, seccompUnavailable, seccomp.loading]);
  const fallback = useSeccompProfileFallback(seccomp.api, fallbackFor.length > 0, fallbackFor, refreshTick);
  // Only while the list is unavailable: once it has loaded it is authoritative, fallback reads or not.
  const rows = useMemo(
    () => (seccompUnavailable && fallback.size > 0 ? buildWorkloadRows(allPods, seccomp.profiles, scoped, { seccompUnavailable, seccompFallback: fallback }) : baseRows),
    [baseRows, fallback, allPods, seccomp.profiles, scoped, seccompUnavailable],
  );

  return {
    rows,
    seccompApi: seccomp.api,
    profiles: seccomp.profiles,
    loading: seccomp.loading,
    error: seccomp.error,
    seccompUnavailable,
    /** A verdict read failed: the would-deny tile is unknown, not 0. */
    verdictsUnavailable,
    verdictCount: scoped.length,
    refresh,
  };
}
