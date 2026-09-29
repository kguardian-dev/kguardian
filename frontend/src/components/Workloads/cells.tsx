import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { CrDrift } from '../../types/seccompWorkload';
import type { NetworkCoverage } from '../../utils/workloads';

/**
 * Network-policy coverage pill. Only an AuditNetworkPolicy verdict is a
 * positive signal today; everything else is "not reported", which must not
 * read as "no policy" — kguardian does not inventory NetworkPolicy objects yet.
 */
export function NetworkPill({ network }: { network: NetworkCoverage }) {
  if (network.state === 'audit') {
    const title =
      `Recent AuditNetworkPolicy verdicts name this workload (${network.verdicts} in the latest window): ${network.policies.join(', ')}.` +
      (network.wouldDeny > 0 ? ` ${network.wouldDeny} would be denied if enforcing.` : ' None would be denied.');
    // The count sits under the pill, so the column stays narrow.
    return (
      <span className="inline-flex flex-col items-start gap-0.5">
        <span title={title} className="shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium bg-state-audit/15 text-state-audit border-state-audit/30">
          Audit
        </span>
        {network.wouldDeny > 0 && (
          <span className="text-[11px] font-mono text-hubble-warning" title="Flows the audit policy would deny">
            {network.wouldDeny} would-deny
          </span>
        )}
      </span>
    );
  }
  return (
    <span
      title="kguardian does not inventory NetworkPolicy objects yet. This shows AuditNetworkPolicy coverage only, from the most recent audit verdicts (a recent window, not full history), so a covered but quiet workload can read as not reported."
      className="shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium bg-hubble-border/40 text-tertiary border-hubble-border"
    >
      Not reported
    </span>
  );
}

/**
 * Observed syscalls vs the deployed SeccompProfile CR. Only observed syscalls
 * the CR lacks are a drift (they would be blocked when enforcing); syscalls
 * the CR allows but were never observed just mean the CR is broader.
 *
 * `known`: whether the CR state is known (see WorkloadRow.seccomp); without it
 * no drift is "no CR".
 */
export function DriftCell({ drift, known }: { drift: CrDrift | null; known: boolean }) {
  if (!drift && !known) {
    return <span className="text-tertiary" title="Unknown until the seccomp profile list has been read" data-testid="drift-unknown">—</span>;
  }
  // The Drift filter's "No CR": there is nothing to drift from.
  if (!drift) {
    return <span className="text-tertiary" title="No seccomp CR is deployed, so there is nothing to drift from" data-testid="drift-no-cr">no CR</span>;
  }
  // The drift on the first line, the CR's unobserved extras under it, so the column stays narrow.
  const unobserved = drift.extra.length > 0 && (
    <span className="text-[11px] text-tertiary" title={`In the CR, never observed (not a drift): ${drift.extra.join(', ')}`} data-testid="drift-unobserved">
      {drift.extra.length} allowed but unobserved
    </span>
  );
  if (drift.missing.length === 0) {
    return (
      <span className="inline-flex flex-col items-start gap-0.5">
        <span className="inline-flex items-center gap-1 text-hubble-success" title="Every observed syscall is in the CR">
          <CheckCircle2 className="w-3.5 h-3.5" /> in sync
        </span>
        {unobserved}
      </span>
    );
  }
  return (
    <span className="inline-flex flex-col items-start gap-0.5">
      <span className="inline-flex items-center gap-1 text-hubble-warning" title={`Observed but not in the CR: ${drift.missing.join(', ')}`}>
        <AlertTriangle className="w-3.5 h-3.5" /> {drift.missing.length} missing
      </span>
      {unobserved}
    </span>
  );
}
