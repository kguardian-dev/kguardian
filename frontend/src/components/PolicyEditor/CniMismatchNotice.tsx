import React, { useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';

interface CniMismatchNoticeProps {
  /** The detected cluster CNI (never 'unknown' or 'cilium' here —
   *  callers only render this on a real mismatch). */
  cni: string;
}

/**
 * Dismissible notice shown on the Cilium Policy tab when the cluster's
 * detected CNI is something else: the CiliumNetworkPolicy CRD is
 * likely absent (apply fails), or — worse — present but unenforced
 * (policy applies and is silently inert). Export stays enabled: the
 * YAML may be destined for a different cluster.
 */
export const CniMismatchNotice: React.FC<CniMismatchNoticeProps> = ({ cni }) => {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;
  return (
    <div
      role="note"
      className="flex items-start gap-2 px-4 py-2.5 bg-hubble-warning/10 border-b border-hubble-warning/30 text-xs text-secondary"
    >
      <AlertTriangle className="w-4 h-4 text-hubble-warning shrink-0 mt-0.5" />
      <p className="flex-1">
        Cluster CNI detected as <span className="font-mono text-primary">{cni}</span> — the
        CiliumNetworkPolicy CRD is likely not installed here, and even if it is, only Cilium
        enforces it. A standard Network Policy works on any CNI.
      </p>
      <button
        onClick={() => setDismissed(true)}
        aria-label="Dismiss CNI notice"
        className="text-tertiary hover:text-primary transition-colors"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
};
