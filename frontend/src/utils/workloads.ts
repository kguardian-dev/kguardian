import type { AuditVerdict, PodInfo } from '../types';
import type { SyscallsDimension } from '../types/profile';
import type { CaptureInfo, CrDrift, CrInfo, DistributionInfo, WorkloadProfileSummary } from '../types/seccompWorkload';
import { captureFromPods, crStatus, isBlockingAction, resolveCapture, type CrStatus } from './seccompCapture';

/**
 * Network-policy coverage as far as the broker can tell today. kguardian does
 * not inventory NetworkPolicy objects yet, so the only positive signal is an
 * AuditNetworkPolicy verdict naming one of the workload's pods as its subject.
 * Absence is `unreported`, never "no policy".
 */
export type NetworkCoverage =
  | { state: 'audit'; policies: string[]; wouldDeny: number; verdicts: number }
  | { state: 'unreported' };

/** A CR state, or `unknown` when the seccomp profile list could not be read. */
export type SeccompState = CrStatus | 'unknown';

export interface WorkloadRow {
  /** `ns/kind/name` — the same key the seccomp profiles use. */
  key: string;
  namespace: string;
  kind: string;
  name: string;
  /** Live pods only. */
  pods: PodInfo[];
  profile: WorkloadProfileSummary | null;
  /** `unknown` while the profile list is loading or failed and no per-workload read has answered. */
  seccomp: SeccompState;
  /** Observed-vs-CR drift; null when no CR is deployed (or unknown, see `seccomp`). */
  drift: CrDrift | null;
  /** null = unknown (see `seccomp`): pod tiers alone do not say whether the profile behind them is complete. */
  capture: CaptureInfo | null;
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

const isEgress = (v: AuditVerdict) => v.direction.toLowerCase() === 'egress';

/** The namespace an audit verdict is about: the destination's for ingress rules, the source's for egress. Not the policy's. */
export function verdictSubjectNamespace(v: AuditVerdict): string | null {
  return isEgress(v) ? v.src_namespace : v.dst_namespace;
}

/** The pod an audit verdict is about, when the Broker recorded one (a deleted peer may leave it null). */
export function verdictSubject(v: AuditVerdict): { ns: string; pod: string } | null {
  const ns = verdictSubjectNamespace(v);
  const pod = isEgress(v) ? v.src_pod : v.dst_pod;
  return ns && pod ? { ns, pod } : null;
}

/**
 * Verdicts whose subject is in `namespace`. The Broker's own `namespace=`
 * query filters on the policy's namespace instead, which drops every verdict
 * from a cluster-scoped AuditClusterNetworkPolicy.
 */
export function verdictsForNamespace(verdicts: readonly AuditVerdict[], namespace: string): AuditVerdict[] {
  return verdicts.filter((v) => verdictSubjectNamespace(v) === namespace);
}

export interface BuildRowsOptions {
  /** The profile list is loading or failed: a row without a profile reads unknown, not "no profile". */
  seccompUnavailable?: boolean;
  /** Per-workload reads made while the list was unavailable; null = the Broker has no profile for that workload. */
  seccompFallback?: ReadonlyMap<string, WorkloadProfileSummary | null>;
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
  opts: BuildRowsOptions = {},
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
    // Fallback reads only stand in while the list is unavailable; a loaded list is authoritative.
    const fallback = opts.seccompUnavailable ? opts.seccompFallback?.get(key) : undefined;
    const profile = profileByKey.get(key) ?? fallback ?? null;
    // No profile is an answer only when the list loaded, or the per-workload read said so.
    const known = profile !== null || !opts.seccompUnavailable || fallback === null;
    const live = livePods.get(key) ?? [];
    const net = network.get(key);
    rows.push({
      key,
      ...w,
      pods: live,
      profile,
      seccomp: profile ? crStatus(profile) : known ? 'none' : 'unknown',
      drift: profile?.cr ? profile.cr.drift : null,
      capture: profile ? resolveCapture(profile, live) : known ? captureFromPods(live) : null,
      network: net
        ? { state: 'audit', policies: [...net.policies].sort(), wouldDeny: net.wouldDeny, verdicts: net.verdicts }
        : { state: 'unreported' },
    });
  }
  return rows.sort(
    (a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind),
  );
}

/** Drift that matters: observed syscalls the CR does not allow. Syscalls the CR allows but never observed are not a drift. */
export function hasBlockingDrift(drift: CrDrift | null): boolean {
  return drift !== null && drift.missing.length > 0;
}

/**
 * The node readiness to show for a CR. The CR's own `status.distribution`
 * (the controller's count against the API server's node list) is the answer
 * when the Broker mirrored it; the Broker's node-status count only covers
 * nodes that reported recently and becomes the qualifier, shown when it differs.
 */
export function crDistribution(cr: Pick<CrInfo, 'distribution' | 'statusDistribution'>): { primary: DistributionInfo; reporting: DistributionInfo | null } {
  const status = cr.statusDistribution;
  if (!status) return { primary: cr.distribution, reporting: null };
  const state = status.state ?? (status.ready >= status.total ? 'Ready' : status.ready > 0 ? 'Partial' : 'Pending');
  const primary = { ...status, state };
  const differs = status.ready !== cr.distribution.ready || status.total !== cr.distribution.total;
  return { primary, reporting: differs ? cr.distribution : null };
}

/**
 * A Syscalls tab from `GET /seccomp/profiles/{ns}/{kind}/{name}` for when the
 * workload profile read fails: the same observed set, capture and CR (with
 * the CR's own status.distribution, which the profile lacks today), with
 * posture and denials unknown (that endpoint has neither).
 */
export function syscallsDimensionFromSeccomp(detail: WorkloadProfileSummary): SyscallsDimension {
  const capture = resolveCapture(detail);
  const cr = detail.cr ?? null;
  return {
    status: 'unknown',
    coverage: { level: 'partial', fraction: null, observedSince: null, note: 'From the seccomp profile endpoint: the workload profile could not be read, so posture and denials are unknown.' },
    reasons: [],
    observed: { syscallCount: detail.syscallCount, hash: detail.hash, architectures: detail.architectures, updatedAt: detail.updatedAt },
    capture: detail.capture
      ? { level: capture.level, complete: capture.complete, incompletePods: detail.capture.incomplete ?? capture.pods.filter((p) => p.level !== 'full').length }
      : null,
    cr: cr
      ? {
          name: cr.name,
          defaultAction: cr.defaultAction,
          mode: isBlockingAction(cr.defaultAction) ? 'enforce' : 'audit',
          syscallCount: cr.syscallCount,
          inSync: cr.drift.inSync,
          missing: cr.drift.missing,
          extra: cr.drift.extra,
          distribution: { ready: cr.distribution.ready, total: cr.distribution.total, state: cr.distribution.state },
          statusDistribution: cr.statusDistribution ?? null,
        }
      : null,
    denials: null,
  };
}
