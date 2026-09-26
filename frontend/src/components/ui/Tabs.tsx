import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react';

export interface TabDef<T extends string> {
  id: T;
  label: ReactNode;
}

interface TabsProps<T extends string> {
  tabs: readonly TabDef<T>[];
  active: T;
  onChange: (id: T) => void;
  /** Accessible name for the tablist. */
  label: string;
  /** Prefix for tab/panel ids so two tablists on a page never collide. */
  idPrefix: string;
}

/**
 * WAI-ARIA tablist with a roving tabindex: Tab enters on the active tab,
 * Left/Right move and activate (automatic activation), Home/End jump to the
 * ends. The panel is rendered by the caller with `tabPanelProps`.
 */
export function Tabs<T extends string>({ tabs, active, onChange, label, idPrefix }: TabsProps<T>) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);

  // On a narrow screen the strip scrolls sideways; keep the active tab in
  // view (a deep link to the last tab would otherwise show none selected).
  const activeIndex = tabs.findIndex((t) => t.id === active);
  useEffect(() => {
    refs.current[activeIndex]?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
  }, [activeIndex]);

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(tabs[next].id);
    refs.current[next]?.focus();
  };

  return (
    <div
      role="tablist"
      aria-label={label}
      className="flex gap-1 overflow-x-auto border-b border-hubble-border [scrollbar-width:thin]"
    >
      {tabs.map((t, i) => {
        const on = t.id === active;
        return (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`${idPrefix}-tab-${t.id}`}
            aria-selected={on}
            aria-controls={`${idPrefix}-panel-${t.id}`}
            tabIndex={on ? 0 : -1}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={`shrink-0 whitespace-nowrap px-3 py-2 -mb-px text-sm border-b-2 transition-colors ${
              on ? 'border-hubble-accent text-primary font-medium' : 'border-transparent text-secondary hover:text-primary'
            }`}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}
