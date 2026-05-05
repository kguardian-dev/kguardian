import { useState, useEffect, useCallback, useRef } from 'react';
import type { PodInfo, PodNodeData, ServiceInfo } from '../types';
import { apiClient } from '../services/api';

const POLL_INTERVAL_MS = 30_000;

async function withConcurrencyLimit<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  const executing = new Set<Promise<void>>();
  for (let i = 0; i < tasks.length; i++) {
    const index = i;
    const p = tasks[index]().then(r => { results[index] = r; });
    const tracked = p.then(() => { executing.delete(tracked); });
    executing.add(tracked);
    if (executing.size >= limit) {
      await Promise.race(executing);
    }
  }
  await Promise.all(executing);
  return results;
}

export const usePodData = (namespace: string) => {
  const [pods, setPods] = useState<PodNodeData[]>([]);
  const [allPodsLookup, setAllPodsLookup] = useState<PodInfo[]>([]);
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const fetchPodData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch all pods and services from broker
      const [allPods, allServices] = await Promise.all([
        apiClient.getAllPods(),
        apiClient.getAllServices(),
      ]);

      setServices(allServices);

      // Keep all pods (including dead) for cross-namespace IP resolution.
      // Dead pods resolve so their IPs are recognised as cluster-internal
      // and silently excluded from the graph rather than shown as "Internet".
      setAllPodsLookup(allPods);

      // Filter by namespace and only show active pods (is_dead = false)
      const filteredPods = allPods.filter(
        (pod) => pod.pod_namespace === namespace && !pod.is_dead
      );

      // Group pods by identity
      const podsByIdentity = new Map<string, typeof filteredPods>();
      filteredPods.forEach((pod) => {
        const identity = pod.pod_identity || pod.pod_name;
        const key = `${pod.pod_namespace}-${identity}`;
        if (!podsByIdentity.has(key)) {
          podsByIdentity.set(key, []);
        }
        podsByIdentity.get(key)!.push(pod);
      });

      // Fetch traffic and syscalls for each identity group with concurrency limit
      const identityEntries = Array.from(podsByIdentity.entries());
      const podDataTasks = identityEntries.map(([key, podsInGroup]) => () => {
        // Use first pod as the primary pod
        const primaryPod = podsInGroup[0];
        const identity = primaryPod.pod_identity || primaryPod.pod_name;

        // Fetch traffic and syscalls for all pods in the group with concurrency limit
        const trafficTasks = podsInGroup.map(pod => () => apiClient.getPodTrafficByName(pod.pod_name));
        const syscallTasks = podsInGroup.map(pod => () => apiClient.getPodSyscalls(pod.pod_name));

        return Promise.all([
          withConcurrencyLimit(trafficTasks, 10),
          withConcurrencyLimit(syscallTasks, 10),
        ]).then(([allTraffic, allSyscalls]) => {
          // Merge all traffic and syscalls
          const mergedTraffic = allTraffic.flat();
          const mergedSyscalls = allSyscalls.flat();

          return {
            id: key,
            label: identity,
            pod: primaryPod, // Primary pod for backward compatibility
            pods: podsInGroup, // All pods in this identity
            traffic: mergedTraffic,
            syscalls: mergedSyscalls.length > 0 ? mergedSyscalls : undefined,
            isExpanded: false,
          } as PodNodeData;
        });
      });

      const podData = await withConcurrencyLimit(podDataTasks, 10);
      setPods(podData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  }, [namespace]);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      if (cancelled) return;
      await fetchPodData();
      if (cancelled) return;
      timerRef.current = setTimeout(poll, POLL_INTERVAL_MS);
    };

    poll();

    return () => {
      cancelled = true;
      clearTimeout(timerRef.current);
    };
  }, [fetchPodData]);

  const togglePodExpansion = useCallback((podId: string) => {
    setPods((prevPods) =>
      prevPods.map((pod) =>
        pod.id === podId ? { ...pod, isExpanded: !pod.isExpanded } : pod
      )
    );
  }, []);

  const refreshData = useCallback(() => {
    clearTimeout(timerRef.current);
    fetchPodData();
  }, [fetchPodData]);

  return {
    pods,
    allPodsLookup,
    services,
    loading,
    error,
    togglePodExpansion,
    refreshData,
  };
};
