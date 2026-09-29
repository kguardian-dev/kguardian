// Peer-attribution comment text and the pod→Service collapse shared by the
// standard (networkPolicyGenerator) and Cilium (ciliumPolicyGenerator)
// builders. Text must stay byte-identical to llm-bridge and the advisor:
// the fixture tests compare the emitted comment lines.

import type { NetworkTraffic } from '../types';
import type { TrafficIdentity } from './trafficIdentity';
import { parseBrokerTime, type UnattributedReason } from './peerResolution';

const UNATTRIBUTED_REASON_NOTE: Record<UnattributedReason, string> = {
  'service-lookup-failed': 'Service lookup failed',
  'pod-lookup-failed': 'pod lookup failed',
};

/**
 * The `# ...` line above an ipBlock / CIDR rule for an unattributed peer:
 * no pod may be selected for the flow (the start-time guard excluded every
 * pod that ever held the IP, or the stored peer is gone). `at` is the NEWEST
 * `time_stamp` among the rule's rows, printed verbatim; when none parses the
 * ` at …` part is omitted. `service` (frontend only; the advisor has no such
 * case) adds why a Service ClusterIP ended up here. `reason` (frontend only)
 * appends which lookup failed for an address no pod ever held.
 */
export function unattributedPeerComment(ip: string, at: string | undefined, service?: string, reason?: UnattributedReason): string {
  const base = at !== undefined && parseBrokerTime(at) !== null ? `unattributed peer ${ip} at ${at}` : `unattributed peer ${ip}`;
  // A failed lookup (frontend only; the advisor and llm-bridge have no such
  // case, so the goldens never see it) says so; the default line is unchanged.
  const lead = reason ? `${base} (${UNATTRIBUTED_REASON_NOTE[reason]})` : base;
  // A ClusterIP of a Service whose selector is unknown (its spec was never
  // stored): say what the address is and what to put in its place.
  if (service) return `${lead} — ClusterIP of Service ${service}, selector unknown: will not match after DNAT; replace with the Service's selector`;
  return lead;
}

/**
 * Identity key of a resolved peer — the SECONDARY rule order after the peer
 * IP, so that two rules for one IP (it changed hands) come out in the same
 * order from every generator. Derived from what is rendered: `cidr`,
 * `unattributed`, `host:<ns>/<workload-or-pod>` (`…/svc/<name>` for a
 * Service fronting host-network pods), `sel:<ns>:k=v,…` (keys sorted).
 */
export function identityKey(identity: TrafficIdentity): string {
  if (identity.unattributed) return 'unattributed';
  const labels = (ns: string | undefined, l: Record<string, string> | undefined) =>
    `sel:${ns ?? ''}:${Object.keys(l ?? {}).sort().map((k) => `${k}=${l![k]}`).join(',')}`;
  if (identity.svcName) return labels(identity.svcNamespace, identity.svcSelector);
  if (identity.podName) {
    if (identity.hostNetwork === true) return `host:${identity.podNamespace ?? ''}/${identity.workloadName || identity.podName}`;
    return labels(identity.podNamespace, identity.podLabels);
  }
  return 'cidr';
}

/**
 * Prefer the row whose `time_stamp` is newest (unparseable last) — the one
 * an unattributed rule's comment quotes.
 */
export function newerRow(a: string, b: string): boolean {
  const ta = parseBrokerTime(a);
  const tb = parseBrokerTime(b);
  if (ta === null) return false;
  if (tb === null) return true;
  return ta > tb;
}

/**
 * Redirect every pod identity that a Service identity in the same set
 * selects (same namespace, selector ⊆ labels) to that Service identity, so
 * traffic to a ClusterIP and to its backing pod IP collapse into one rule.
 * Mutates `rowIdentity` in place. An unattributed row has no pod identity
 * and is never redirected — a guarded-out pod must not come back through
 * the Service that fronts it.
 */
export function collapseToServiceIdentity(rowIdentity: Map<NetworkTraffic, TrafficIdentity>): void {
  const svcIdentities = Array.from(new Set(
    Array.from(rowIdentity.values()).filter((i) => i.svcName && i.svcSelector),
  ));
  if (svcIdentities.length === 0) return;
  for (const [row, identity] of rowIdentity) {
    if (!identity.podName || !identity.podNamespace || !identity.podLabels) continue;
    for (const svcIdentity of svcIdentities) {
      if (svcIdentity.svcNamespace !== identity.podNamespace) continue;
      const matches = Object.entries(svcIdentity.svcSelector!).every(([k, v]) => identity.podLabels![k] === v);
      if (matches) {
        rowIdentity.set(row, svcIdentity);
        break;
      }
    }
  }
}

/** How a generator rendered a Service that has no `spec.selector`. */
export type SelectorlessServiceRendering = 'ipBlock' | 'cidr' | 'kube-apiserver';

/**
 * The `# ...` line above a rule for a Service with no `spec.selector`
 * (`default/kubernetes`, operator-managed Endpoints): no backend label to
 * select, and a rule on the ClusterIP never matches after the Service DNAT.
 */
export function selectorlessServiceComment(
  namespace: string,
  name: string,
  ip: string,
  rendering: SelectorlessServiceRendering,
): string {
  const lead = `Service ${namespace}/${name} has no selector`;
  if (rendering === 'kube-apiserver') return `${lead} — kube-apiserver entity covers its endpoints`;
  return `${lead} — ${rendering} ${ip} is its ClusterIP and will not match after DNAT`;
}
