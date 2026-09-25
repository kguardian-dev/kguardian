import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../services/api';
import type { AuditVerdict, PodInfo } from '../types';
import { buildWorkloadRows } from '../utils/workloads';
import { useSeccompProfiles } from './useSeccompProfiles';

/** How many recent audit verdicts the coverage column looks at. */
export const COVERAGE_VERDICT_LIMIT = 1000;

/**
 * Everything the Workloads coverage table and the placeholder workload page
 * read, from endpoints the broker already serves: the cluster-wide pod list
 * (passed in — usePodData already holds it), the seccomp profile list
 * (polled), and the most recent audit verdicts (fetched on mount/refresh).
 */
export function useWorkloadCoverage(allPods: readonly PodInfo[]) {
  const seccomp = useSeccompProfiles();
  const [verdicts, setVerdicts] = useState<AuditVerdict[]>([]);

  const loadVerdicts = useCallback(async () => {
    // getAuditVerdicts swallows errors into []: the column then reads
    // "not reported", which is the honest fallback.
    setVerdicts(await api.getAuditVerdicts({ limit: COVERAGE_VERDICT_LIMIT }));
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as usePodData
    void loadVerdicts();
  }, [loadVerdicts]);

  const { refresh: refreshProfiles } = seccomp;
  const refresh = useCallback(async () => {
    await Promise.all([refreshProfiles(), loadVerdicts()]);
  }, [refreshProfiles, loadVerdicts]);

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
