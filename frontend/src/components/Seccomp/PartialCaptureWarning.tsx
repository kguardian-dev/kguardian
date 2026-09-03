import { AlertTriangle } from 'lucide-react';
import { CAPTURE_ANNOTATION, CAPTURE_HELM_VALUE, type CaptureInfo } from '../../types/seccompWorkload';
import { describePartialCapture } from '../../utils/seccompCapture';

interface PartialCaptureWarningProps {
  capture: CaptureInfo | null | undefined;
  /** Tighter padding for inside a modal/section. */
  compact?: boolean;
  className?: string;
}

/**
 * The headline requirement from the operator: it must be unmistakable when a
 * profile is built from a partial-capture tier. Names the tier and the pods,
 * states the consequence (blocked syscalls), and says exactly how to raise
 * the tier. Renders nothing when capture is complete.
 */
export function PartialCaptureWarning({ capture, compact = false, className = '' }: PartialCaptureWarningProps) {
  const warning = describePartialCapture(capture);
  if (!warning) return null;
  return (
    <div
      role="alert"
      data-testid="partial-capture-warning"
      className={`rounded-surface border border-hubble-warning/50 bg-hubble-warning/10 ${compact ? 'px-3 py-2.5' : 'px-4 py-3'} ${className}`}
    >
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="w-4 h-4 text-hubble-warning shrink-0 mt-0.5" />
        <div className="min-w-0 space-y-1.5">
          <p className="text-sm font-semibold text-hubble-warning">{warning.title}</p>
          <p className="text-xs text-secondary">{warning.consequence}</p>
          {warning.affectedPods.length > 0 && (
            <ul className="flex flex-wrap gap-1" aria-label="Pods below full capture">
              {warning.affectedPods.map((p) => (
                <li
                  key={p.name}
                  className="inline-flex items-center gap-1 rounded border border-hubble-warning/30 bg-hubble-card px-1.5 py-0.5 text-[11px] font-mono text-secondary"
                >
                  {p.name}
                  <span className="text-hubble-warning">{p.level}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="text-xs text-tertiary">
            Raise the tier for this workload with the pod-template annotation{' '}
            <code className="font-mono text-primary">{CAPTURE_ANNOTATION}: full</code>, or cluster-wide with Helm{' '}
            <code className="font-mono text-primary">{CAPTURE_HELM_VALUE}=full</code>, then let the profile re-accrue before
            publishing.
          </p>
        </div>
      </div>
    </div>
  );
}
