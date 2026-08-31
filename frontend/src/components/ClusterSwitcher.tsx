import { useState, useRef } from 'react';
import { Boxes, Check, ChevronsUpDown, Plus } from 'lucide-react';
import { useCluster } from '../contexts/ClusterContext';
import { useDismissable } from '../hooks/useDismissable';

/**
 * Active-cluster selector in the rail. With one cluster it reads as the current
 * context; once the multi-cluster backend registers more (ClusterContext), the
 * same control switches between them. No data rewrite — the provider swaps the
 * source and threads the active cluster into the API layer.
 */
export function ClusterSwitcher({ collapsed = false }: { collapsed?: boolean }) {
  const { clusters, activeCluster, setActiveClusterId } = useCluster();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useDismissable(open, () => setOpen(false), ref);

  return (
    <div ref={ref} className="relative px-2 pt-2">
      <button
        onClick={() => setOpen((o) => !o)}
        title={collapsed ? activeCluster.name : undefined}
        className={`w-full flex items-center h-9 rounded-control border border-hubble-border bg-hubble-card hover:bg-hubble-hover transition-colors ${
          collapsed ? 'justify-center px-0' : 'gap-2 px-2.5'
        }`}
      >
        <Boxes size={16} className="shrink-0 text-hubble-accent" />
        {!collapsed && (
          <>
            <span className="flex-1 min-w-0 text-left">
              <span className="block text-[10px] text-tertiary uppercase tracking-[0.1em] leading-none">Cluster</span>
              <span className="block text-xs font-medium text-primary truncate leading-tight mt-0.5">{activeCluster.name}</span>
            </span>
            <ChevronsUpDown size={14} className="shrink-0 text-tertiary" />
          </>
        )}
      </button>

      {open && (
        <div className="absolute left-2 right-2 top-full mt-1 z-30 rounded-control border border-hubble-border bg-hubble-card shadow-xl py-1">
          {clusters.map((c) => (
            <button
              key={c.id}
              onClick={() => { setActiveClusterId(c.id); setOpen(false); }}
              className="w-full flex items-center gap-2 px-2.5 h-8 text-xs text-secondary hover:bg-hubble-hover hover:text-primary transition-colors"
            >
              <Boxes size={14} className="shrink-0 text-tertiary" />
              <span className="flex-1 text-left truncate">{c.name}</span>
              {c.id === activeCluster.id && <Check size={14} className="shrink-0 text-hubble-accent" />}
            </button>
          ))}
          <div className="my-1 border-t border-hubble-border" />
          <button
            disabled
            title="Multi-cluster registration is coming"
            className="w-full flex items-center gap-2 px-2.5 h-8 text-xs text-tertiary opacity-60 cursor-not-allowed"
          >
            <Plus size={14} className="shrink-0" />
            <span>Add cluster…</span>
          </button>
        </div>
      )}
    </div>
  );
}
