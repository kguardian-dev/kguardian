import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo, SyscallInfo } from '../types';
import axios from 'axios';
import { apiClient } from '../services/api';
import { useComputeData } from './useComputeData';
import { buildPodComputeData, containersForNode, nodeComputeState } from '../utils/compute';
import { withConcurrencyLimit } from '../utils/concurrency';
import type { ComputeFinding } from '../types/compute';

export interface UsePodDataOptions {
  /** False while no mounted view reads pod data (the Images view): nothing is
   *  fetched, and pods already loaded are kept for the next view that needs
   *  them. Default true. */
  enabled?: boolean;
  /** The compute poll's own gate, for views that read pods but draw no
   *  gauges. Defaults to `enabled`. */
  compute?: boolean;
}

/** Per-pod reads the broker did not answer in this namespace's last load. */
export interface FailedReads {
  traffic: number;
  syscalls: number;
}

const NO_FAILURES: FailedReads = { traffic: 0, syscalls: 0 };

/**
 * Per-pod reads in flight across the whole namespace. Twenty is what the
 * old nested limiters allowed for single-replica workloads (10 workloads, a
 * traffic and a syscall read each), so those load as fast as before; a
 * replica-heavy namespace no longer gets 10 × (10 + 10) = 200 at once.
 */
const POD_READ_CONCURRENCY = 20;

/** The Broker shed the read (read budget, or a cancelled statement). */
const isShed = (err: unknown): boolean => axios.isAxiosError(err) && err.response?.status === 503;

interface SettledRead<T> { rows: T[]; failed: boolean }

/**
 * @param selectedPodId The open card, or null. Selection is what opens a card
 *   (NetworkGraph derives `isExpanded` from it), so it is also the only signal
 *   that a pod's stored history is worth reading — see the seeding effect
 *   below. Passed in rather than read off `basePods`: the expanded flag on a
 *   pod object is no longer authoritative, and seeding off it would silently
 *   read nothing.
 */
export const usePodData = (namespace: string, selectedPodId: string | null = null, opts: UsePodDataOptions = {}) => {
  const enabled = opts.enabled ?? true;
  const computeEnabled = opts.compute ?? enabled;
  const [basePods, setPods] = useState<PodNodeData[]>([]);
  const [allPodsLookup, setAllPodsLookup] = useState<PodInfo[]>([]);
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [failedReads, setFailedReads] = useState<FailedReads>(NO_FAILURES);
  const [loading, setLoading] = useState<boolean>(enabled);
  const [error, setError] = useState<string | null>(null);
  // The namespace whose run has settled (loaded or failed), or null. Read
  // during render so the first render after enabling, or after a namespace
  // change, already reports loading: the effect that starts the run has not
  // run yet in that render, and without this React painted one frame of
  // "No workloads" between the namespace list arriving and the run starting.
  const [loadedFor, setLoadedFor] = useState<string | null>(null);

  // Run sequencing. Every fetch takes the next id; a run that is no longer
  // current writes nothing, and only the current run may clear `loading`.
  // Without this a namespace switch mid-load let the superseded run's
  // `finally` clear the flag while the real one still had its traffic reads
  // in flight, and the map showed "No workloads" for a namespace that had 20.
  const generation = useRef(0);
  /** The namespace the current run was issued for (loaded or loading). */
  const runFor = useRef<string | null>(null);

  const fetchPodData = useCallback(async () => {
    const gen = ++generation.current;
    const current = () => gen === generation.current;
    setLoading(true);
    setError(null);

    try {
      // Fetch all pods and services from broker
      const [allPods, allServices] = await Promise.all([
        apiClient.getAllPods(),
        apiClient.getAllServices(),
      ]);
      if (!current()) return;

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

      // A failed per-pod read is a marker, never an empty list (see api.ts).
      // Once the Broker sheds one with 503, the reads not yet sent are marked
      // failed without being sent: it is refusing reads, and every further
      // one would only add to what it is refusing.
      let shed = false;
      const settled = <T,>(read: () => Promise<T[]>) => async (): Promise<SettledRead<T>> => {
        if (shed) return { rows: [], failed: true };
        try {
          return { rows: await read(), failed: false };
        } catch (err) {
          if (isShed(err)) shed = true;
          return { rows: [], failed: true };
        }
      };

      // Traffic and syscalls for every pod of every identity group, under one
      // limit for the whole namespace.
      const identityEntries = Array.from(podsByIdentity.entries());
      const trafficTasks = identityEntries.flatMap(([, podsInGroup]) =>
        podsInGroup.map((pod) => settled(() => apiClient.getPodTrafficByName(pod.pod_name))));
      const syscallTasks = identityEntries.flatMap(([, podsInGroup]) =>
        podsInGroup.map((pod) => settled(() => apiClient.getPodSyscalls(pod.pod_name))));
      const reads = await withConcurrencyLimit<SettledRead<unknown>>([...trafficTasks, ...syscallTasks], POD_READ_CONCURRENCY);
      if (!current()) return;
      const allTraffic = reads.slice(0, trafficTasks.length) as SettledRead<NetworkTraffic>[];
      const allSyscalls = reads.slice(trafficTasks.length) as SettledRead<SyscallInfo>[];

      let offset = 0;
      const results = identityEntries.map(([key, podsInGroup]) => {
        // Use first pod as the primary pod
        const primaryPod = podsInGroup[0];
        const identity = primaryPod.pod_identity || primaryPod.pod_name;
        const groupTraffic = allTraffic.slice(offset, offset + podsInGroup.length);
        const groupSyscalls = allSyscalls.slice(offset, offset + podsInGroup.length);
        offset += podsInGroup.length;

        // Merge all traffic and syscalls
        const mergedTraffic = groupTraffic.flatMap((r) => r.rows);
        const mergedSyscalls = groupSyscalls.flatMap((r) => r.rows);
        const trafficFailed = groupTraffic.filter((r) => r.failed).length;
        const syscallsFailed = groupSyscalls.filter((r) => r.failed).length;

        const node = {
          id: key,
          label: identity,
          pod: primaryPod, // Primary pod for backward compatibility
          pods: podsInGroup, // All pods in this identity
          traffic: mergedTraffic,
          syscalls: mergedSyscalls.length > 0 ? mergedSyscalls : undefined,
          isExpanded: false,
          trafficError: trafficFailed > 0,
          syscallsError: syscallsFailed > 0,
        } as PodNodeData;
        return { node, trafficFailed, syscallsFailed };
      });
      setPods(results.map((r) => r.node));
      setFailedReads({
        traffic: results.reduce((n, r) => n + r.trafficFailed, 0),
        syscalls: results.reduce((n, r) => n + r.syscallsFailed, 0),
      });
    } catch (err) {
      if (!current()) return;
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      if (current()) {
        setLoadedFor(namespace);
        setLoading(false);
      }
    }
  }, [namespace]);

  useEffect(() => {
    if (!enabled) return; // no mounted view reads pod data: fetch nothing
    if (runFor.current === namespace) return; // already loaded, or loading, for this namespace
    runFor.current = namespace;
    // The previous namespace's cards must not stand in for this one while it loads.
    setPods([]);
    setFailedReads(NO_FAILURES);
    void fetchPodData();
  }, [enabled, namespace, fetchPodData]);

  // A refresh reloads in place: the current graph stays on screen while the
  // new run is in flight (only a namespace change blanks it).
  const refreshData = useCallback(() => {
    if (!enabled) return;
    runFor.current = namespace;
    void fetchPodData();
  }, [enabled, namespace, fetchPodData]);

  // Live compute gauges (design D8): the only polled data on the map. Merged
  // here — not fetched with traffic — so the 5 s poll never re-fetches
  // traffic or syscalls, and a pod without compute rows is left untouched.
  const compute = useComputeData(namespace, { enabled: computeEnabled });
  // Seed the open card's sparkline from stored history (design D8).
  //
  // Selecting a card is the only signal that its history is worth a read: the
  // sparklines are the sole consumer of seeded buckets and render only in the
  // expanded body, so nothing is fetched for a namespace nobody has opened a
  // card in. `seedPod` is idempotent, so re-running on every poll costs
  // nothing once a pod is seeded or its read is in flight.
  //
  // Keyed off `selectedPodId`, NOT off `isExpanded`. Expansion is derived
  // from selection in NetworkGraph and is never written back here, so the
  // flag on these pod objects is always false — seeding off it would fetch
  // nothing, and the only symptom would be an expanded card whose sparklines
  // stayed empty. At most one card is open, so this is one read, not one per
  // card as it was when cards expanded independently.
  //
  // One uid per card, the same one the chart below reads: a replica group's
  // other uids can never be displayed, so fetching them would be reads for
  // charts that do not exist.
  const seedPod = compute.seedPod;
  useEffect(() => {
    if (!compute.enabled) return; // no pod carries a `compute` field, so no chart can render
    if (!selectedPodId) return; // nothing open, so no sparkline to fill
    const node = basePods.find((p) => p.id === selectedPodId);
    if (!node) return; // an external or synthesised card: no local history to read
    const uid = containersForNode(node, compute.containersByPodUid, compute.containersByPodName)[0]?.pod_uid;
    if (uid) seedPod(uid);
  }, [basePods, selectedPodId, compute.enabled, compute.containersByPodUid, compute.containersByPodName, seedPod]);

  const pods = useMemo<PodNodeData[]>(() => {
    if (!compute.enabled) return basePods;
    // One time origin for the whole pass — the instant the last poll landed.
    // Every card drawn together then puts the same instant at the same x,
    // which a `Date.now()` per card would not, and render stays pure.
    const now = compute.polledAt;
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
      // The gauges of a multi-replica card read every replica's live rows
      // (buildPodComputeData), not this one uid's samples.
      const uid = containers[0]?.pod_uid;
      const samples = uid ? compute.history.get(uid)?.values() ?? [] : [];
      const data = buildPodComputeData({ containers, nodesByName: compute.nodesByName, findings, samples, nodeState, now });
      // Same shared constant as last tick ⇒ same pod object, so PodNode's
      // identity memo holds for pods without rows.
      return pod.compute === data ? pod : { ...pod, compute: data };
    });
    // `history` is a fresh Map per poll over the in-place ring buffers, so it
    // is the dependency that re-reads the sparklines.
  }, [basePods, compute.enabled, compute.containersByPodUid, compute.containersByPodName, compute.nodesByName, compute.findings, compute.history, compute.polledAt]);

  return {
    pods,
    compute,
    allPodsLookup,
    services,
    /** Per-pod reads that failed in the last load, so a consumer (the Policy
     *  Builder picker) can say "N reads failed" instead of "0 conns". */
    failedReads,
    /** True from the render that asks for a namespace until its run settles. */
    loading: loading || (enabled && loadedFor !== namespace),
    error,
    refreshData,
  };
};
