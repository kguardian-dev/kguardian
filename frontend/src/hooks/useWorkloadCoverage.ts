import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import api from '../services/api';
import type { AuditVerdict, PodInfo } from '../types';
import { buildWorkloadRows } from '../utils/workloads';
import { useSeccompProfiles } from './useSeccompProfiles';

/**
 * Rows per verdict kind the coverage column reads. The broker caps
 * /audit/verdicts at 500 rows and has no per-policy or per-workload counts,
 * so this is a recent window, not history. Allow and WouldDeny are fetched
 * separately so a burst of Allow rows cannot push the would-denies out.
 */
export const COVERAGE_VERDICT_LIMIT = 500;

/**
 * Everything the Workloads coverage table and the placeholder workload page
 * read, from endpoints the broker already serves: the cluster-wide pod list
 * (passed in — usePodData already holds it), the seccomp profile list
 * (polled), and the most recent audit verdicts (fetched on mount/refresh).
 */
export function useWorkloadCoverage(allPods: readonly PodInfo[], refreshTick = 0, namespace?: string) {
  const seccomp = useSeccompProfiles();
  const [verdicts, setVerdicts] = useState<AuditVerdict[]>([]);

  const loadVerdicts = useCallback(async () => {
    // getAuditVerdicts swallows errors into []: the column then reads
    // "not reported", which is the honest fallback. `namespace` filters on
    // the POLICY's namespace — for namespaced AuditNetworkPolicies that is
    // the subject workload's namespace, so a narrowed view's window is not
    // shared with noisy workloads elsewhere in the cluster.
    const base = { limit: COVERAGE_VERDICT_LIMIT, ...(namespace ? { namespace } : {}) };
    const [deny, allow] = await Promise.all([
      api.getAuditVerdicts({ ...base, verdict: 'WouldDeny' }),
      api.getAuditVerdicts({ ...base, verdict: 'Allow' }),
    ]);
    setVerdicts([...deny, ...allow]);
  }, [namespace]);

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

  const rows = useMemo(() => buildWorkloadRows(allPods, seccomp.profiles, verdicts), [allPods, seccomp.profiles, verdicts]);

  return {
    rows,
    seccompApi: seccomp.api,
    profiles: seccomp.profiles,
    loading: seccomp.loading,
    error: seccomp.error,
    verdictCount: verdicts.length,
    refresh,
  };
}
