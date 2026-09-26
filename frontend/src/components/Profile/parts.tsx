import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, CircleHelp, OctagonAlert, RotateCw, XCircle } from 'lucide-react';
import type { PostureStatus } from '../../types/profile';
import { STATUS_LABEL, STATUS_PILL_CLASS } from '../../utils/posture';
import { Button } from '../ui/Button';
import { Skeleton } from '../ui/Skeleton';

const STATUS_ICON: Record<PostureStatus, LucideIcon> = {
  ok: CheckCircle2,
  warn: AlertTriangle,
  risk: OctagonAlert,
  unknown: CircleHelp,
};

/**
 * A posture status pill. `unknown` is drawn as a dashed, neutral "No data"
 * with a question glyph — its own state, never a quiet version of OK.
 */
export function StatusPill({ status, children, title }: { status: PostureStatus; children?: ReactNode; title?: string }) {
  const Icon = STATUS_ICON[status];
  return (
    <span
      data-status={status}
      title={title}
      className={`inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${STATUS_PILL_CLASS[status]}`}
    >
      <Icon className="w-3 h-3 shrink-0" aria-hidden />
      {children ?? STATUS_LABEL[status]}
    </span>
  );
}

/** A tri-state check: true passes, false fails, null "can't tell". */
export function CheckMark({ ok }: { ok: boolean | null }) {
  if (ok === true) return <CheckCircle2 className="w-4 h-4 shrink-0 text-state-enforcing" aria-label="Pass" role="img" />;
  if (ok === false) return <XCircle className="w-4 h-4 shrink-0 text-severity-critical" aria-label="Fail" role="img" />;
  return <CircleHelp className="w-4 h-4 shrink-0 text-tertiary" aria-label="Can't tell" role="img" />;
}

/** Visible label for a tri-state null: kguardian cannot tell, which is not a pass. */
export function CantTell() {
  return (
    <span className="shrink-0 rounded-full border border-dashed border-hubble-border-strong px-1.5 py-px text-[11px] text-tertiary" data-testid="cant-tell">
      Can&apos;t tell
    </span>
  );
}

/** A card section: icon, title, hint, optional action. */
export function Panel({
  icon: Icon,
  title,
  hint,
  action,
  children,
  label,
}: {
  icon: LucideIcon;
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  /** Accessible name when the title alone is ambiguous. */
  label?: string;
}) {
  return (
    <section aria-label={label ?? title} className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden min-w-0">
      <header className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-hubble-border">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className="w-4 h-4 shrink-0 text-hubble-accent" aria-hidden />
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-primary">{title}</h3>
            {hint && <p className="text-[11px] text-tertiary">{hint}</p>}
          </div>
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

/** Loading placeholder for one section. */
export function SectionSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className={`h-6 ${i === rows - 1 ? 'w-2/3' : 'w-full'}`} />
      ))}
    </div>
  );
}

/** Error for one section, with a retry. Never a whole-page failure. */
export function SectionError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm text-severity-critical bg-severity-critical/10 border-t border-severity-critical/20">
      <span className="min-w-0">{message}</span>
      {onRetry && (
        <Button variant="secondary" size="sm" leftIcon={RotateCw} onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

/** One "why" line from a dimension's reasons[]. */
export function Reasons({ reasons }: { reasons: Array<{ code: string; message: string }> }) {
  if (reasons.length === 0) return null;
  return (
    <ul className="space-y-1 text-xs text-secondary">
      {reasons.map((r) => (
        <li key={r.code} data-code={r.code} className="flex gap-1.5">
          <span aria-hidden className="text-tertiary">·</span>
          {r.message}
        </li>
      ))}
    </ul>
  );
}

/** Small key/value row used in fact lists. */
export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5 text-xs">
      <dt className="text-tertiary shrink-0">{label}</dt>
      <dd className="text-primary text-right min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}
