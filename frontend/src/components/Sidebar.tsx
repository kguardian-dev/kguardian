import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Shield, PanelLeftClose, PanelLeftOpen } from 'lucide-react';

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
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

/**
 * Persistent, collapsible left navigation rail — the product shell. Replaces
 * the previous "single screen, everything is a header-button modal" model with
 * a stable section rail (the Datadog/Grafana/Linear convention). Collapses to a
 * 56px icon rail; labels fall back to native tooltips via `title`.
 */
export function Sidebar({ items, footer, version, collapsed = false, onToggleCollapse }: SidebarProps) {
  return (
    <aside
      className={`${collapsed ? 'w-14' : 'w-56'} shrink-0 flex flex-col bg-hubble-dark border-r border-hubble-border transition-[width] duration-200 ease-out`}
    >
      {/* Brand + collapse toggle */}
      <div className={`h-14 flex items-center border-b border-hubble-border ${collapsed ? 'justify-center px-0' : 'gap-2.5 px-4'}`}>
        <div className="grid place-items-center w-8 h-8 rounded-control bg-hubble-accent/15 text-hubble-accent shrink-0">
          <Shield size={18} />
        </div>
        {!collapsed && (
          <div className="leading-none min-w-0 flex-1">
            <div className="text-sm font-semibold text-primary tracking-tight truncate">kguardian</div>
            <div className="mt-1 text-[10px] font-medium text-tertiary uppercase tracking-[0.14em]">Runtime Security</div>
          </div>
        )}
        {!collapsed && onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
            className="grid place-items-center w-7 h-7 rounded-control text-tertiary hover:text-primary hover:bg-hubble-hover transition-colors shrink-0"
          >
            <PanelLeftClose size={16} />
          </button>
        )}
      </div>

      {/* Section nav */}
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
        {!collapsed && (
          <div className="px-2 pt-1.5 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">
            Workspace
          </div>
        )}
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={item.onClick}
              title={item.hint ?? item.label}
              aria-current={item.active ? 'page' : undefined}
              className={`w-full flex items-center h-9 rounded-control text-sm transition-colors ${
                collapsed ? 'justify-center px-0' : 'gap-2.5 px-3'
              } ${
                item.active
                  ? 'bg-hubble-accent/15 text-hubble-accent font-medium'
                  : 'text-secondary hover:bg-hubble-hover hover:text-primary'
              }`}
            >
              <Icon size={16} className="shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Footer: utilities + version (+ expand control when collapsed) */}
      <div className={`p-2 border-t border-hubble-border flex items-center gap-1.5 ${collapsed ? 'flex-col' : 'justify-between'}`}>
        {collapsed && onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            title="Expand sidebar"
            aria-label="Expand sidebar"
            className="grid place-items-center w-9 h-9 rounded-control text-tertiary hover:text-primary hover:bg-hubble-hover transition-colors"
          >
            <PanelLeftOpen size={16} />
          </button>
        )}
        <div className="flex items-center gap-1">{footer}</div>
        {!collapsed && <span className="px-1.5 text-[10px] font-medium text-tertiary tabular-nums">v{version}</span>}
      </div>
    </aside>
  );
}
