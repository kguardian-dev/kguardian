import React from 'react';
import { Layers } from 'lucide-react';

interface NamespaceSelectorProps {
  selectedNamespace: string;
  onNamespaceChange: (namespace: string) => void;
  namespaces?: string[];
  /** Offer "All namespaces" (value '') first — for cluster-wide views, where
   *  the selector is a filter rather than the scope. */
  allOption?: boolean;
}

/** Sentinel value of the "All namespaces" option. */
const ALL = '';

const NamespaceSelector: React.FC<NamespaceSelectorProps> = ({
  selectedNamespace,
  onNamespaceChange,
  namespaces = ['default'],
  allOption = false,
}) => {
  return (
    <div className="flex items-center gap-2 bg-hubble-card px-2 lg:px-4 py-2 rounded-lg border border-hubble-border min-w-0">
      <Layers className="w-4 h-4 text-hubble-accent hidden sm:block shrink-0" />
      <label htmlFor="namespace" className="text-sm text-secondary font-medium sr-only lg:not-sr-only">
        Namespace:
      </label>
      <select
        id="namespace"
        value={selectedNamespace}
        onChange={(e) => onNamespaceChange(e.target.value)}
        className="bg-hubble-dark text-primary px-2 lg:px-3 py-1 rounded border border-hubble-border max-w-[10rem] sm:max-w-none
                   focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent
                   cursor-pointer"
      >
        {allOption && <option value={ALL}>All namespaces</option>}
        {namespaces.map((ns) => (
          <option key={ns} value={ns}>
            {ns}
          </option>
        ))}
      </select>
    </div>
  );
};

export default NamespaceSelector;
