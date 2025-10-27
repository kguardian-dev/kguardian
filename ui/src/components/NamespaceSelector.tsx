import React from 'react';
import { Layers } from 'lucide-react';

interface NamespaceSelectorProps {
  selectedNamespace: string;
  onNamespaceChange: (namespace: string) => void;
  namespaces?: string[];
}

const NamespaceSelector: React.FC<NamespaceSelectorProps> = ({
  selectedNamespace,
  onNamespaceChange,
  namespaces = ['default'],
}) => {
  return (
    <div className="flex items-center gap-2 bg-hubble-card px-4 py-2 rounded-lg border border-hubble-border">
      <Layers className="w-4 h-4 text-hubble-accent" />
      <label htmlFor="namespace" className="text-sm text-gray-300 font-medium">
        Namespace:
      </label>
      <select
        id="namespace"
        value={selectedNamespace}
        onChange={(e) => onNamespaceChange(e.target.value)}
        className="bg-hubble-dark text-gray-100 px-3 py-1 rounded border border-hubble-border
                   focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent
                   cursor-pointer"
      >
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
