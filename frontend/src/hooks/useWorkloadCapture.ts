import { useEffect, useMemo, useState } from 'react';
import type { PodNodeData } from '../types';
import type { CaptureInfo } from '../types/seccompWorkload';
import { seccompApi } from '../services/seccompApi';
import { captureFromPods, resolveCapture } from '../utils/seccompCapture';

/**
 * Capture tier behind a pod-group's observed syscalls, for the per-pod
 * seccomp generator. Prefers the pod rows' own `capture_level` (present once
 * the controller reports tiers); when none of them carry it, asks the broker
 * for the workload summary; failing both, reports `unknown` — which the badge
 * treats as partial. Never assumes full.
 */
export function useWorkloadCapture(pod: PodNodeData | null, enabled: boolean): CaptureInfo {
  const fromPods = useMemo<CaptureInfo | null>(() => {
    if (!pod) return null;
    const rows = pod.pods?.length ? pod.pods : [pod.pod];
    return rows.some((p) => p.capture_level != null) ? captureFromPods(rows) : null;
  }, [pod]);

  const ns = pod?.pod.pod_namespace ?? null;
  const owner = pod?.pods?.find((p) => p.workload_kind && p.workload_name) ?? pod?.pod ?? null;
  const kind = owner?.workload_kind ?? null;
  const name = owner?.workload_name ?? null;

  const [fromBroker, setFromBroker] = useState<{ key: string; capture: CaptureInfo } | null>(null);
  const key = ns && kind && name ? `${ns}/${kind}/${name}` : null;

  useEffect(() => {
    if (!enabled || fromPods || !key || !ns || !kind || !name) return;
    let cancelled = false;
    seccompApi
      .getProfile(ns, kind, name)
      .then((d) => {
        if (!cancelled) setFromBroker({ key, capture: resolveCapture(d) });
      })
      .catch(() => {
        if (!cancelled) setFromBroker({ key, capture: { level: 'unknown', complete: false, pods: [] } });
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, fromPods, key, ns, kind, name]);

  if (fromPods) return fromPods;
  if (fromBroker && fromBroker.key === key) return fromBroker.capture;
  return { level: 'unknown', complete: false, pods: [] };
}
