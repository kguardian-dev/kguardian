import { Globe, Boxes, X } from 'lucide-react';

interface ScopeChipProps {
  namespace: string;
  allNamespaces: boolean;
  /** Present only on views that can show every namespace: clears the filter. */
  onShowAll?: () => void;
}

/**
 * Says what the current view is scoped to, so a count is never ambiguous:
 * "All namespaces", or "Namespace: payments" (with ✕ to widen, on views whose
 * data is cluster-wide). The namespace selector next to it narrows.
 */
export function ScopeChip({ namespace, allNamespaces, onShowAll }: ScopeChipProps) {
  const base = 'inline-flex items-center gap-1.5 h-6 pl-2 rounded-full border text-[11px] whitespace-nowrap';
  if (allNamespaces) {
    return (
      <span data-testid="scope-chip" className={`${base} pr-2.5 border-hubble-border text-secondary`}>
        <Globe className="w-3 h-3" aria-hidden />
        All namespaces
      </span>
    );
  }
  return (
    <span
      data-testid="scope-chip"
      className={`${base} ${onShowAll ? 'pr-1' : 'pr-2.5'} border-hubble-accent/40 bg-hubble-accent/10 text-primary`}
      title={onShowAll ? undefined : 'This view shows one namespace at a time'}
    >
      <Boxes className="w-3 h-3 text-hubble-accent" aria-hidden />
      <span className="text-tertiary">Namespace:</span>
      <span className="font-mono">{namespace}</span>
      {onShowAll && (
        <button
          type="button"
          onClick={onShowAll}
          aria-label="Show all namespaces"
          title="Show all namespaces"
          className="grid place-items-center w-4 h-4 rounded-full text-tertiary hover:text-primary hover:bg-hubble-hover"
        >
          <X className="w-3 h-3" />
        </button>
      )}
    </span>
  );
}
