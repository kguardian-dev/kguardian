import type { AuditVerdict, PodInfo } from '../types';
import type { CaptureInfo, CrDrift, WorkloadProfileSummary } from '../types/seccompWorkload';
import { captureFromPods, crStatus, resolveCapture, type CrStatus } from './seccompCapture';

/**
 * Network-policy coverage as far as the broker can tell today. kguardian does
 * not inventory NetworkPolicy objects yet, so the only positive signal is an
 * AuditNetworkPolicy verdict naming one of the workload's pods as its subject.
 * Absence is `unreported`, never "no policy".
 */
export type NetworkCoverage =
  | { state: 'audit'; policies: string[]; wouldDeny: number; verdicts: number }
  | { state: 'unreported' };

export interface WorkloadRow {
  /** `ns/kind/name` — the same key the seccomp profiles use. */
  key: string;
  namespace: string;
  kind: string;
  name: string;
  /** Live pods only. */
  pods: PodInfo[];
  profile: WorkloadProfileSummary | null;
  seccomp: CrStatus;
  /** Observed-vs-CR drift; null when no CR is deployed. */
  drift: CrDrift | null;
  capture: CaptureInfo;
  network: NetworkCoverage;
}

export const workloadKey = (ns: string, kind: string, name: string) => `${ns}/${kind}/${name}`;

/**
 * The workload a pod belongs to. Controller-owned pods use the top-level
 * owner the controller reports (the seccomp grouping key); a bare pod, or one
 * from a controller predating owner reporting, is its own workload of kind Pod.
 */
export function workloadOf(pod: PodInfo): { namespace: string; kind: string; name: string } | null {
  if (!pod.pod_namespace) return null;
  if (pod.workload_kind && pod.workload_name) {
    return { namespace: pod.pod_namespace, kind: pod.workload_kind, name: pod.workload_name };
  }
  return { namespace: pod.pod_namespace, kind: 'Pod', name: pod.pod_name };
}

/** The pod an audit verdict is about: the destination for ingress rules, the source for egress. */
function verdictSubject(v: AuditVerdict): { ns: string; pod: string } | null {
  const ingress = v.direction.toLowerCase() === 'ingress';
  const ns = ingress ? v.dst_namespace : v.src_namespace;
  const pod = ingress ? v.dst_pod : v.src_pod;
  return ns && pod ? { ns, pod } : null;
}

/**
 * One row per workload: the union of workloads with live pods and workloads
 * with a seccomp profile (a profile can outlive its pods, e.g. a scaled-to-zero
 * Deployment or a CronJob between runs). Workloads known only through dead pods
 * are dropped — they are history, not coverage.
 */
export function buildWorkloadRows(
  pods: readonly PodInfo[],
  profiles: readonly WorkloadProfileSummary[],
  verdicts: readonly AuditVerdict[] = [],
): WorkloadRow[] {
  const livePods = new Map<string, PodInfo[]>();
  const ident = new Map<string, { namespace: string; kind: string; name: string }>();
  // (ns, pod name) → workload key, for attributing verdicts. Dead pods count
  // too: a verdict recorded before a rollout is still about this workload.
  const podIndex = new Map<string, string>();

  for (const pod of pods) {
    const w = workloadOf(pod);
    if (!w) continue;
    const key = workloadKey(w.namespace, w.kind, w.name);
    podIndex.set(`${w.namespace}/${pod.pod_name}`, key);
    if (pod.is_dead) continue;
    ident.set(key, w);
    livePods.set(key, [...(livePods.get(key) ?? []), pod]);
  }

  const profileByKey = new Map<string, WorkloadProfileSummary>();
  for (const p of profiles) {
    const key = workloadKey(p.namespace, p.kind, p.name);
    profileByKey.set(key, p);
    if (!ident.has(key)) ident.set(key, { namespace: p.namespace, kind: p.kind, name: p.name });
  }

  const network = new Map<string, { policies: Set<string>; wouldDeny: number; verdicts: number }>();
  for (const v of verdicts) {
    const subject = verdictSubject(v);
    const key = subject && podIndex.get(`${subject.ns}/${subject.pod}`);
    if (!key) continue;
    const agg = network.get(key) ?? { policies: new Set<string>(), wouldDeny: 0, verdicts: 0 };
    agg.policies.add(v.policy_namespace ? `${v.policy_namespace}/${v.policy_name}` : v.policy_name);
    agg.verdicts += 1;
    if (v.verdict === 'WouldDeny') agg.wouldDeny += 1;
    network.set(key, agg);
  }

  const rows: WorkloadRow[] = [];
  for (const [key, w] of ident) {
    const profile = profileByKey.get(key) ?? null;
    const live = livePods.get(key) ?? [];
    const net = network.get(key);
    rows.push({
      key,
      ...w,
      pods: live,
      profile,
      seccomp: profile ? crStatus(profile) : 'none',
      drift: profile?.cr ? profile.cr.drift : null,
      capture: profile ? resolveCapture(profile, live) : captureFromPods(live),
      network: net
        ? { state: 'audit', policies: [...net.policies].sort(), wouldDeny: net.wouldDeny, verdicts: net.verdicts }
        : { state: 'unreported' },
    });
  }
  return rows.sort(
    (a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind),
  );
}
