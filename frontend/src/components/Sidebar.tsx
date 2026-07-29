import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Shield } from 'lucide-react';

export interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  onClick: () => void;
  active?: boolean;
  hint?: string;
}

interface SidebarProps {
  items: NavItem[];
  footer?: ReactNode;
  version: string;
}

/**
 * Persistent left navigation rail — the product shell. Replaces the previous
 * "single screen, everything is a header-button modal" model with a stable
 * section rail (the Datadog/Grafana/Linear convention).
 */
export function Sidebar({ items, footer, version }: SidebarProps) {
  return (
    <aside className="w-56 shrink-0 flex flex-col bg-hubble-dark border-r border-hubble-border">
      {/* Brand */}
      <div className="h-14 flex items-center gap-2.5 px-4 border-b border-hubble-border">
        <div className="grid place-items-center w-8 h-8 rounded-control bg-hubble-accent/15 text-hubble-accent">
          <Shield size={18} />
        </div>
        <div className="leading-none">
          <div className="text-sm font-semibold text-primary tracking-tight">kguardian</div>
          <div className="mt-1 text-[10px] font-medium text-tertiary uppercase tracking-[0.14em]">Runtime Security</div>
        </div>
      </div>

      {/* Section nav */}
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
        <div className="px-2 pt-1.5 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">
          Workspace
        </div>
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={item.onClick}
              title={item.hint ?? item.label}
              aria-current={item.active ? 'page' : undefined}
              className={`w-full flex items-center gap-2.5 px-3 h-9 rounded-control text-sm transition-colors ${
                item.active
                  ? 'bg-hubble-accent/15 text-hubble-accent font-medium'
                  : 'text-secondary hover:bg-hubble-hover hover:text-primary'
              }`}
            >
              <Icon size={16} className="shrink-0" />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer: utilities + version */}
      <div className="p-2 border-t border-hubble-border flex items-center justify-between gap-2">
        <div className="flex items-center gap-1">{footer}</div>
        <span className="px-1.5 text-[10px] font-medium text-tertiary tabular-nums">v{version}</span>
      </div>
    </aside>
  );
}
