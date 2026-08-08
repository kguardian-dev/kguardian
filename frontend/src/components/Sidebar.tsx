import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { BrandMark } from './BrandMark';

export interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  onClick: () => void;
  active?: boolean;
  hint?: string;
  /** Rail section this item belongs to (e.g. "Views", "Tools"). Items with the
   *  same group render under one header, in first-seen order. */
  group?: string;
}

interface SidebarProps {
  items: NavItem[];
  footer?: ReactNode;
  /** Rendered between the brand and the section nav (e.g. cluster switcher). */
  topSlot?: ReactNode;
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
/** Bucket nav items by their `group` (default "Workspace"), preserving the
 *  order each group's first item appears in. */
function groupItems(items: NavItem[]): Array<[string, NavItem[]]> {
  const order: string[] = [];
  const map = new Map<string, NavItem[]>();
  for (const item of items) {
    const group = item.group ?? 'Workspace';
    if (!map.has(group)) {
      map.set(group, []);
      order.push(group);
    }
    map.get(group)!.push(item);
  }
  return order.map((group) => [group, map.get(group)!]);
}

export function Sidebar({ items, footer, topSlot, version, collapsed = false, onToggleCollapse }: SidebarProps) {
  return (
    <aside
      className={`${collapsed ? 'w-14' : 'w-56'} shrink-0 flex flex-col bg-hubble-dark border-r border-hubble-border transition-[width] duration-200 ease-out`}
    >
      {/* Brand + collapse toggle */}
      <div className={`h-14 flex items-center border-b border-hubble-border ${collapsed ? 'justify-center px-0' : 'gap-2.5 px-4'}`}>
        <BrandMark size={28} className="shrink-0" />
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

      {/* Top slot (cluster switcher) */}
      {topSlot}

      {/* Section nav — grouped by NavItem.group, in first-seen order. */}
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
        {groupItems(items).map(([group, groupItemList], gi) => (
          <div key={group} className={gi > 0 ? 'pt-2' : undefined}>
            {!collapsed && (
              <div className="px-2 pt-1.5 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">
                {group}
              </div>
            )}
            {groupItemList.map((item) => {
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
          </div>
        ))}
      </nav>

      {/* Footer: account + version (+ expand control when collapsed) */}
      <div className="p-2 border-t border-hubble-border">
        {collapsed ? (
          <div className="flex flex-col items-center gap-1.5">
            {onToggleCollapse && (
              <button
                onClick={onToggleCollapse}
                title="Expand sidebar"
                aria-label="Expand sidebar"
                className="grid place-items-center w-9 h-9 rounded-control text-tertiary hover:text-primary hover:bg-hubble-hover transition-colors"
              >
                <PanelLeftOpen size={16} />
              </button>
            )}
            {footer}
          </div>
        ) : (
          <div className="space-y-1">
            {footer}
            <div className="px-1.5 text-[10px] font-medium text-tertiary tabular-nums">v{version}</div>
          </div>
        )}
      </div>
    </aside>
  );
}
