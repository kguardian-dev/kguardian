import { useState, useEffect, useCallback, useMemo } from 'react';
import type { PodInfo, PodNodeData, ServiceInfo } from '../types';
import { apiClient } from '../services/api';
import { useComputeData } from './useComputeData';
import { buildPodComputeData, containersForNode, nodeComputeState } from '../utils/compute';
import { withConcurrencyLimit } from '../utils/concurrency';
import type { ComputeFinding } from '../types/compute';

export const usePodData = (namespace: string) => {
  const [basePods, setPods] = useState<PodNodeData[]>([]);
  const [allPodsLookup, setAllPodsLookup] = useState<PodInfo[]>([]);
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

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
    // eslint-disable-next-line react-hooks/set-state-in-effect
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

  // Live compute gauges (design D8): the only polled data on the map. Merged
  // here — not fetched with traffic — so the 5 s poll never re-fetches
  // traffic or syscalls, and a pod without compute rows is left untouched.
  const compute = useComputeData(namespace);
  // Seed an expanded card's sparkline from stored history (design D8).
  //
  // Expanding a card is the only signal that its history is worth a read:
  // the sparklines are the sole consumer of seeded buckets and render only
  // when expanded, so nothing is fetched for a namespace nobody has opened a
  // card in. `seedPod` is idempotent, so running this for every open card on
  // every poll costs nothing once a pod is seeded or its read is in flight.
  //
  // One uid per card, the same one the chart below reads: a replica group's
  // other uids can never be displayed, so fetching them would be reads for
  // charts that do not exist.
  const seedPod = compute.seedPod;
  useEffect(() => {
    if (!compute.enabled) return; // no pod carries a `compute` field, so no chart can render
    for (const node of basePods) {
      if (!node.isExpanded) continue;
      const uid = containersForNode(node, compute.containersByPodUid, compute.containersByPodName)[0]?.pod_uid;
      if (uid) seedPod(uid);
    }
  }, [basePods, compute.enabled, compute.containersByPodUid, compute.containersByPodName, seedPod]);

  const pods = useMemo<PodNodeData[]>(() => {
    if (!compute.enabled) return basePods;
    const findingsByPodKey = new Map<string, ComputeFinding[]>();
    for (const f of compute.findings) {
      for (const key of [f.victim.pod_uid, `${f.victim.namespace}/${f.victim.pod_name}`]) {
        const list = findingsByPodKey.get(key);
        if (list) list.push(f);
        else findingsByPodKey.set(key, [f]);
      }
    }
    return basePods.map((pod) => {
      const containers = containersForNode(pod, compute.containersByPodUid, compute.containersByPodName);
      const members = pod.pods && pod.pods.length > 0 ? pod.pods : [pod.pod];
      // Findings for any replica of the identity (by uid, else by name).
      const seen = new Set<ComputeFinding>();
      const findings: ComputeFinding[] = [];
      for (const c of containers) {
        for (const f of findingsByPodKey.get(c.pod_uid) ?? []) {
          if (!seen.has(f)) { seen.add(f); findings.push(f); }
        }
      }
      for (const m of members) {
        for (const f of findingsByPodKey.get(`${m.pod_namespace ?? ''}/${m.pod_name}`) ?? []) {
          if (!seen.has(f)) { seen.add(f); findings.push(f); }
        }
      }
      // The pod's node state: from the container rows when we have them, else
      // from the pod record's node so an unsupported/off node still explains itself.
      const nodeName = containers[0]?.node ?? pod.pod.node_name;
      const nodeState = nodeComputeState(compute.nodesByName.get(nodeName));
      // One uid per identity drives the sparkline (replica sums are summed in
      // podLevelSample per uid; a multi-replica identity shows the first).
      const uid = containers[0]?.pod_uid;
      const samples = uid ? compute.history.get(uid)?.values() ?? [] : [];
      const data = buildPodComputeData({ containers, nodesByName: compute.nodesByName, findings, samples, nodeState });
      // Same shared constant as last tick ⇒ same pod object, so PodNode's
      // identity memo holds for pods without rows.
      return pod.compute === data ? pod : { ...pod, compute: data };
    });
    // `history` is a fresh Map per poll over the in-place ring buffers, so it
    // is the dependency that re-reads the sparklines.
  }, [basePods, compute.enabled, compute.containersByPodUid, compute.containersByPodName, compute.nodesByName, compute.findings, compute.history]);

  return {
    pods,
    compute,
    allPodsLookup,
    services,
    loading,
    error,
    togglePodExpansion,
    refreshData,
  };
};
