import { useEffect, useState } from 'react';
import api from '../services/api';
import { UNKNOWN_CLUSTER_ENVIRONMENT, type ClusterEnvironment } from '../types';

/**
 * The cluster's coarse environment (CNI et al.) from the broker.
 * Starts — and on any failure remains — all-'unknown', which every
 * consumer must treat as "behave exactly as before": the fetch must
 * never gate rendering. Memoized in the api service, so many mounts
 * cost one request.
 */
export function useClusterEnvironment(): ClusterEnvironment {
  const [env, setEnv] = useState<ClusterEnvironment>(UNKNOWN_CLUSTER_ENVIRONMENT);
  useEffect(() => {
    let cancelled = false;
    api.getClusterEnvironment().then((e) => {
      if (!cancelled) setEnv(e);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return env;
}
