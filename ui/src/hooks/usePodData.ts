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

      // Filter by namespace
      const filteredPods = allPods.filter(
        (pod) => pod.pod_namespace === namespace
      );

      // Fetch traffic and syscalls for each pod in the namespace
      const podDataPromises = filteredPods.map(async (pod) => {
        const traffic = await apiClient.getPodTrafficByName(pod.pod_name);
        const syscalls = await apiClient.getPodSyscalls(pod.pod_name);

        return {
          id: `${pod.pod_namespace}-${pod.pod_name}`,
          label: pod.pod_name,
          pod,
          traffic,
          syscalls,
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
