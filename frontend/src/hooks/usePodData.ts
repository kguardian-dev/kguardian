import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import type { PodInfo, PodNodeData, ServiceInfo } from '../types';
import { apiClient } from '../services/api';

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

  const fetchPodData = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);

    try {
      // Fetch all pods and services from broker
      const [allPods, allServices] = await Promise.all([
        apiClient.getAllPods(signal),
        apiClient.getAllServices(signal),
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
        // TODO: Replace with broker batch endpoint for better performance
        const trafficTasks = podsInGroup.map(pod => () => apiClient.getPodTrafficByName(pod.pod_name, signal));
        const syscallTasks = podsInGroup.map(pod => () => apiClient.getPodSyscalls(pod.pod_name, signal));

        return Promise.all([
          withConcurrencyLimit(trafficTasks, 50),
          withConcurrencyLimit(syscallTasks, 50),
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

      // TODO: Replace with broker batch endpoint for better performance
      const podData = await withConcurrencyLimit(podDataTasks, 50);
      setPods(podData);
    } catch (err) {
      if (axios.isCancel(err) || (err instanceof Error && err.name === 'CanceledError')) {
        return;
      }
      console.error('Error fetching pod data:', err);
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  }, [namespace]);

  useEffect(() => {
    const controller = new AbortController();
    fetchPodData(controller.signal);
    return () => controller.abort();
  }, [fetchPodData]);

  const togglePodExpansion = useCallback((podId: string) => {
    setPods((prevPods) =>
      prevPods.map((pod) =>
        pod.id === podId ? { ...pod, isExpanded: !pod.isExpanded } : pod
      )
    );
  }, []);

  const refreshData = useCallback(() => {
    fetchPodData();
  }, [fetchPodData]);

  return {
    pods,
    allPodsLookup,
    services,
    loading,
    isError: error !== null,
    error,
    togglePodExpansion,
    refreshData,
  };
};
