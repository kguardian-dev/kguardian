import { useState, useEffect, useCallback } from 'react';
import type { PodNodeData } from '../types';
import { apiClient } from '../services/api';

export const usePodData = (namespace: string) => {
  const [pods, setPods] = useState<PodNodeData[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPodData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch all pods from broker
      const allPods = await apiClient.getAllPods();

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

      // Fetch traffic and syscalls for each identity group
      const podDataPromises = Array.from(podsByIdentity.entries()).map(async ([key, podsInGroup]) => {
        // Use first pod as the primary pod
        const primaryPod = podsInGroup[0];
        const identity = primaryPod.pod_identity || primaryPod.pod_name;

        // Fetch traffic and syscalls for all pods in the group
        const allTrafficPromises = podsInGroup.map(pod => apiClient.getPodTrafficByName(pod.pod_name));
        const allSyscallsPromises = podsInGroup.map(pod => apiClient.getPodSyscalls(pod.pod_name));

        const allTraffic = await Promise.all(allTrafficPromises);
        const allSyscalls = await Promise.all(allSyscallsPromises);

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

      const podData = await Promise.all(podDataPromises);
      setPods(podData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  }, [namespace]);

  useEffect(() => {
    fetchPodData();
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
    loading,
    error,
    togglePodExpansion,
    refreshData,
  };
};
