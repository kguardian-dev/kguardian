import type { PolicyType } from '../hooks/policyEditor/usePolicyExport';
import { recommendedPolicyType } from './cniPolicySupport';
import type { ComputeFindingKind } from '../types/compute';

/** The kinds of finding the Risks view surfaces per workload. */
export type FindingKind =
  | 'denied-traffic'
  | 'sensitive-syscalls'
  | 'egress-fanout'
  | 'would-deny'
  | ComputeFindingKind;

/** The compute kinds (design D7): broker-computed, remediated by resources, not a policy. */
export const COMPUTE_FINDING_KINDS: readonly ComputeFindingKind[] = [
  'noisy-neighbor',
  'cpu-throttled',
  'cpu-contended',
  'memory-pressure',
  'memory-limit-thrash',
];

/** Every finding kind, for exhaustive tests. */
export const ALL_FINDING_KINDS: readonly FindingKind[] = [
  'denied-traffic',
  'sensitive-syscalls',
  'egress-fanout',
  'would-deny',
  ...COMPUTE_FINDING_KINDS,
];

export type FindingAction = 'policy' | 'resources';

/**
 * Which action a finding row offers. Network and syscall findings open the
 * Policy Builder; compute findings (D7) have no policy to build — the fix is
 * the workload's `resources:` — so the row links to the workload instead.
 * `policyTypeForFinding` is only ever called for `'policy'` kinds.
 */
export function findingAction(kind: FindingKind): FindingAction {
  return (COMPUTE_FINDING_KINDS as readonly string[]).includes(kind) ? 'resources' : 'policy';
}

/**
 * Which Policy Builder tab a finding's "Policy" action should open. A
 * sensitive-syscalls finding is a seccomp concern; every network finding
 * opens the network policy — CiliumNetworkPolicy when the cluster CNI is
 * Cilium (the #1421 preference), plain NetworkPolicy otherwise (including
 * 'unknown', which must behave exactly as before detection).
 */
export function policyTypeForFinding(kind: FindingKind, cni: string = 'unknown'): PolicyType {
  if (kind === 'sensitive-syscalls') return 'seccomp';
  // Delegated, not restated. This rule also decides the Policy Builder's
  // default tab, and two copies of "which kind can this cluster enforce"
  // drift the moment a CNI is added to one and not the other.
  return recommendedPolicyType(cni);
}
