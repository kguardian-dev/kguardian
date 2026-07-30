import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  /** Compact variant for inside panels/tables. */
  compact?: boolean;
}

/**
 * One empty-state shell for "nothing here" moments (no workloads in a
 * namespace, no audit verdicts, cleared chat). Replaces the ad-hoc centered
 * text each surface improvised — a framed icon, a title, a calm explanation,
 * and an optional next action, so an empty screen reads as a designed state
 * rather than a failure.
 */
export function EmptyState({ icon: Icon, title, description, action, compact = false }: EmptyStateProps) {
  return (
    <div
      className={`flex flex-col items-center justify-center text-center ${
        compact ? 'py-10 px-6' : 'py-16 px-8'
      }`}
    >
      <div className="grid place-items-center w-12 h-12 rounded-surface bg-hubble-accent/10 border border-hubble-accent/20 text-hubble-accent">
        <Icon className="w-6 h-6" strokeWidth={1.75} />
      </div>
      <h3 className="mt-4 text-sm font-semibold text-primary">{title}</h3>
      {description && (
        <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-secondary">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
