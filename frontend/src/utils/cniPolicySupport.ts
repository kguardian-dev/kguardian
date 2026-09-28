import type { ClusterEnvironment } from '../types';

/**
 * Which policy kinds a cluster can actually enforce, and what to warn
 * the operator about when it cannot.
 *
 * Two facts drive every decision here, and they are independent:
 *
 *  1. WHICH policy kind the CNI understands. Only Cilium reads
 *     CiliumNetworkPolicy; applying one anywhere else either fails
 *     because the CRD is absent, or — worse — succeeds against a CRD
 *     some other operator installed and is then read by nobody.
 *
 *  2. WHETHER the CNI enforces policy at all. This is the one that
 *     used to be missed. AWS VPC CNI supports NetworkPolicy only when
 *     explicitly enabled and ships with it OFF; with it off it accepts
 *     the policy and silently ignores it, so `kubectl apply` succeeds,
 *     `kubectl get` shows the object, and nothing is enforced. Flannel
 *     never enforces. Cilium and Calico can be installed with policy
 *     disabled.
 *
 * The previous notice collapsed the two, telling operators that "a
 * standard Network Policy works on any CNI". That is false, and it is
 * false in the most damaging direction available to this product:
 * kguardian's value is that observed-absence means safe-to-deny, so an
 * operator who trusts an inert policy believes they have restricted a
 * workload that is in fact wide open.
 */

export type PolicyType = 'network' | 'cilium' | 'seccomp';

/** Ordered by how loudly the console should present it. */
export type AdvisorySeverity = 'error' | 'warning' | 'info';

export interface PolicyAdvisory {
  severity: AdvisorySeverity;
  /** Short lead-in, safe to render as a heading. */
  title: string;
  /** The specific consequence, in the operator's terms. */
  detail: string;
}

/** CNIs that read CiliumNetworkPolicy. */
const CILIUM_CNIS = new Set(['cilium']);

/**
 * The policy kind this cluster can enforce, used as the console's
 * default selection.
 *
 * Everything that is not Cilium gets standard NetworkPolicy, including
 * `unknown`: it is the portable kind, and it is what the cluster is
 * most likely to understand. Note this says nothing about whether the
 * policy will be ENFORCED — that is `enforcementAdvisory`'s job, and
 * conflating them is the bug this module exists to fix.
 */
export function recommendedPolicyType(cni: string): PolicyType {
  return CILIUM_CNIS.has(cni) ? 'cilium' : 'network';
}

/**
 * What to tell the operator about the policy kind they are looking at,
 * or null when there is nothing worth saying.
 *
 * Deliberately returns a value rather than rendering: the same decision
 * drives a banner, a tab badge and the assistant's wording, and three
 * copies of this reasoning would drift.
 */
export function enforcementAdvisory(
  policyType: PolicyType,
  env: Pick<ClusterEnvironment, 'cni' | 'policy_enforcement'>,
): PolicyAdvisory | null {
  const { cni, policy_enforcement: enforcement } = env;

  // Seccomp is a kubelet concern; the CNI has no bearing on it.
  if (policyType === 'seccomp') return null;

  if (policyType === 'cilium' && cni !== 'unknown' && !CILIUM_CNIS.has(cni)) {
    return {
      severity: 'warning',
      title: `Cluster CNI detected as ${cni}`,
      detail:
        'Only Cilium reads CiliumNetworkPolicy. Here the CRD is likely absent, so the apply fails — ' +
        'or it is present from another install and the policy is read by nobody. Export stays enabled ' +
        'in case this YAML is destined for a different cluster.',
    };
  }

  if (policyType === 'network') {
    if (enforcement === 'unenforced') {
      return {
        severity: 'error',
        title: 'This cluster will not enforce this policy',
        detail:
          `The ${cni === 'unknown' ? 'detected CNI' : cni} is not enforcing NetworkPolicy. ` +
          'Applying this will succeed and the object will show up in kubectl, but no traffic will be ' +
          'restricted. On AWS VPC CNI, enforcement is off by default and is enabled with ' +
          '--enable-network-policy on the node agent.',
      };
    }
    if (enforcement === 'mixed') {
      return {
        severity: 'error',
        title: 'Enforcement is inconsistent across nodes',
        detail:
          'Some nodes enforce NetworkPolicy and others do not, so this policy will restrict a pod on ' +
          'one node and not on another. Which you get depends on where the pod is scheduled.',
      };
    }
    if (enforcement === 'unknown') {
      return {
        severity: 'info',
        title: 'Enforcement could not be determined',
        detail:
          'kguardian could not establish whether this cluster enforces NetworkPolicy. Confirm before ' +
          'relying on this policy to restrict anything.',
      };
    }
  }

  return null;
}

/**
 * True when the console should treat the advisory as blocking enough to
 * keep in front of the operator rather than let them dismiss it.
 *
 * An inert policy is not a style note: the operator's whole reason for
 * being here is to restrict a workload, and dismissing the one message
 * saying it will not be restricted defeats the purpose. Lesser
 * advisories stay dismissible so the console does not nag.
 */
export function isDismissible(advisory: PolicyAdvisory): boolean {
  return advisory.severity !== 'error';
}

/** Why a generated policy has no rule at all. `no-rules`: traffic was
 *  observed but produced none (unparseable peers, or rules removed in the editor). */
export type DenyAllCause = 'no-traffic' | 'read-failed' | 'no-rules';

/** A direction a rule-less policy still covers (`policyTypes` / `enableDefaultDeny`). */
export type DeniedDirection = 'Ingress' | 'Egress';

/** "all ingress and egress", "all ingress" or "all egress". */
export function describeDenied(directions: readonly DeniedDirection[]): string {
  const words = directions.map((d) => d.toLowerCase());
  return `all ${words.join(' and ')}`;
}

/**
 * The advisory for a policy that has no rules while still covering a
 * direction, which denies that direction outright. Observed absence is safe
 * to deny; a read that never completed is not, and a rule list emptied by
 * dropped or removed peers is a third thing, so the causes get different
 * words. Never dismissible: applying it cuts the workload off.
 */
export function denyAllAdvisory(cause: DenyAllCause, directions: readonly DeniedDirection[]): PolicyAdvisory {
  const denied = describeDenied(directions);
  if (cause === 'read-failed') {
    return {
      severity: 'error',
      title: 'Traffic read failed, so this policy allows nothing',
      detail:
        "kguardian could not read this workload's traffic, so the empty rule set is not evidence that it " +
        `has none. Applying this denies ${denied} to the workload. Refresh and retry the read before saving.`,
    };
  }
  if (cause === 'no-rules') {
    return {
      severity: 'error',
      title: 'This policy has no rules and allows nothing',
      detail:
        'Traffic was observed but produced no rule (peers that did not parse, or rules removed in the ' +
        `editor), while the policy still covers ${denied.replace(/^all /, '')}: applying it denies ${denied}. ` +
        'Add the peers back or confirm the deny is intended.',
    };
  }
  return {
    severity: 'error',
    title: 'No traffic observed, so this policy allows nothing',
    detail:
      'No connections were recorded for this workload, so the policy has no rules and covers ' +
      `${denied.replace(/^all /, '')}: applying it denies ${denied}. Confirm the workload really is idle, ` +
      'or extend the observation window, before saving.',
  };
}

/**
 * The advisory for a policy built from a workload whose traffic read did
 * not complete for at least one member pod: rules exist, but peers may be
 * missing. A warning, dismissible, because the document is still usable.
 */
export function incompleteTrafficAdvisory(): PolicyAdvisory {
  return {
    severity: 'warning',
    title: 'Traffic for this workload is incomplete',
    detail:
      "A member pod's traffic read failed or timed out, so peers may be missing from these rules. " +
      'Refresh and retry the read before relying on them.',
  };
}
