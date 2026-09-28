import type { CrInfo } from '../../types/seccompWorkload';
import { crDistribution } from '../../utils/workloads';

const READINESS_CLASS: Record<string, string> = {
  Ready: 'text-hubble-success',
  Partial: 'text-hubble-warning',
  Pending: 'text-tertiary',
};

/** Own keys only: the state string comes from the broker. */
function readinessClass(state: string): string {
  return Object.hasOwn(READINESS_CLASS, state) ? READINESS_CLASS[state] : 'text-secondary';
}

/**
 * A CR's node readiness: the CR's own `status.distribution` first, and the
 * Broker's node-status count (nodes that reported recently) as the
 * qualifier when it differs.
 */
export function CrNodes({ cr }: { cr: Pick<CrInfo, 'distribution' | 'statusDistribution'> }) {
  const { primary, reporting } = crDistribution(cr);
  const title = reporting
    ? `The CR's own status.distribution. The Broker's node-status count, ${reporting.ready}/${reporting.total}, only includes nodes that reported recently.`
    : cr.statusDistribution
      ? "The CR's own status.distribution; the Broker's node-status count agrees."
      : "The Broker's node-status count: nodes that reported this CR recently. The CR's own status.distribution is not available here.";
  return (
    <span className={`font-mono text-xs tabular-nums ${readinessClass(primary.state)}`} title={title} data-testid="cr-nodes">
      {primary.ready}/{primary.total}
      <span className="ml-1.5 text-tertiary">{primary.state}</span>
      {reporting && (
        <span className="ml-1.5 font-sans text-tertiary">
          · {reporting.ready}/{reporting.total} reporting
        </span>
      )}
    </span>
  );
}
