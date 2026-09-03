import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { CaptureInfo } from '../../types/seccompWorkload';
import { describePartialCapture, normalizeLevel } from '../../utils/seccompCapture';

/**
 * Compact capture-tier pill for list rows. Green "full" when every pod
 * records everything; amber "<tier> · partial" otherwise, with the full
 * explanation in the tooltip. The prominent banner version is
 * PartialCaptureWarning.
 */
export function CaptureBadge({ capture }: { capture: CaptureInfo }) {
  const warning = describePartialCapture(capture);
  const level = normalizeLevel(capture.level);
  if (!warning) {
    return (
      <span
        title="Full capture — every syscall recorded; the profile is complete."
        className="inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium bg-hubble-success/15 text-hubble-success border-hubble-success/30"
      >
        <CheckCircle2 className="w-3 h-3" />
        full
      </span>
    );
  }
  return (
    <span
      role="status"
      title={`${warning.title}. ${warning.consequence}`}
      className="inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium bg-hubble-warning/15 text-hubble-warning border-hubble-warning/30"
    >
      <AlertTriangle className="w-3 h-3" />
      <span className="font-mono">{level}</span>
      <span>· partial</span>
    </span>
  );
}
