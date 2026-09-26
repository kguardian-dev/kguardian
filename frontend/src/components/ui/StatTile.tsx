import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

export interface StatTileProps {
  label: string;
  value: ReactNode;
  icon: LucideIcon;
  /** Text-colour class for the icon and value (e.g. `text-severity-high`). */
  tone?: string;
  /** Muted trailing part of the value, e.g. `/31` for "9 of 31". */
  suffix?: ReactNode;
  /** Tooltip explaining exactly what is counted. */
  title?: string;
  /** Makes the tile a filter link into the view that lists what it counts. */
  onClick?: () => void;
}

// Each tile spans two rows of the strip's grid and adopts them as a subgrid
// (label row, value row). Tiles side by side therefore share row heights: when
// one label wraps to two lines, every value in that row still sits on the same
// baseline. Outside a StatStrip the tile is a plain two-row grid.
const SHELL =
  'grid grid-rows-subgrid row-span-2 content-start gap-y-1 min-w-0 rounded-surface border border-hubble-border bg-hubble-card px-4 py-3 text-left';

/**
 * One number with a label — the posture strip's unit. Extracted from the
 * identical inline copies that Findings and Seccomp Profiles each carried, so
 * every strip in the app reads the same and a tile can be a filter link.
 */
export function StatTile({ label, value, icon: Icon, tone = 'text-secondary', suffix, title, onClick }: StatTileProps) {
  const body = (
    <>
      <div className="flex items-start gap-2 text-tertiary text-[11px] leading-4 uppercase tracking-wide">
        <Icon className={`w-3.5 h-3.5 mt-px shrink-0 ${tone}`} aria-hidden />
        <span className="min-w-0 [overflow-wrap:anywhere]">{label}</span>
      </div>
      <div className={`self-end text-2xl leading-8 font-semibold font-mono tabular-nums ${tone}`}>
        {value}
        {suffix != null && <span className="text-base text-tertiary">{suffix}</span>}
      </div>
    </>
  );
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        title={title}
        className={`${SHELL} hover:border-hubble-border-strong hover:bg-hubble-hover/40 transition-colors`}
      >
        {body}
      </button>
    );
  }
  return (
    <div className={SHELL} title={title}>
      {body}
    </div>
  );
}

/** Responsive row of tiles; widens to five columns when there are five. */
export function StatStrip({ children, count, label }: { children: ReactNode; count: number; label?: string }) {
  return (
    <div
      role="group"
      aria-label={label}
      className={`grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-x-3 gap-y-3 ${count >= 5 ? 'lg:grid-cols-5' : ''}`}
    >
      {children}
    </div>
  );
}
