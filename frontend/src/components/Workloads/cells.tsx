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
    return (
      <span className="inline-flex items-center gap-1.5">
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

/** Observed syscalls vs the deployed SeccompProfile CR. */
export function DriftCell({ drift }: { drift: CrDrift | null }) {
  if (!drift) return <span className="text-tertiary">—</span>;
  if (drift.inSync) {
    return (
      <span className="inline-flex items-center gap-1 text-hubble-success" title="Every observed syscall is in the CR">
        <CheckCircle2 className="w-3.5 h-3.5" /> in sync
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-hubble-warning" title={`Observed but not in the CR: ${drift.missing.join(', ')}`}>
      <AlertTriangle className="w-3.5 h-3.5" /> {drift.missing.length} missing
      {drift.extra.length > 0 && <span className="text-tertiary">· {drift.extra.length} extra</span>}
    </span>
  );
}
