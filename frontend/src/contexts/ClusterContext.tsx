import { createContext, useContext, useState, useMemo, useCallback, type ReactNode } from 'react';

export interface Cluster {
  id: string;
  name: string;
  /** Reserved: per-cluster API base once multi-cluster ingestion lands. */
  apiBase?: string;
}

// Extension point for multi-cluster support. Today the UI targets the single
// broker it's served alongside, exposed here as one "Primary" cluster. When the
// backend gains multi-cluster ingestion (a cluster_id on telemetry + per-cluster
// ingestion), this list will come from an API and `activeCluster.apiBase` will
// route the data layer (services/api.ts) per selected cluster — no UI rewrite,
// just swap this provider's source and thread `activeCluster` into the client.
// Exactly one entry, deliberately. A second entry was used during design
// preview to exercise the switcher, but it carried no distinct apiBase, so
// selecting it showed the primary cluster's data under another cluster's name.
// In a tool people use to decide what traffic is legitimate, telemetry
// mislabelled with the wrong cluster is worse than no multi-cluster support at
// all, so nothing goes in this list that is not a real, separately-sourced
// cluster.
//
// The name is generic for the same reason: the UI has no way to learn the
// cluster's real identity (no API exposes it), so anything specific here would
// be wrong for every operator but the one it was written for.
const LOCAL_CLUSTERS: Cluster[] = [{ id: 'primary', name: 'Primary' }];

const ACTIVE_KEY = 'kg-active-cluster';

interface ClusterContextValue {
  clusters: Cluster[];
  activeCluster: Cluster;
  setActiveClusterId: (id: string) => void;
  /** True once more than one cluster is registered (drives switcher UI). */
  isMultiCluster: boolean;
}

const ClusterContext = createContext<ClusterContextValue | undefined>(undefined);

export function ClusterProvider({ children }: { children: ReactNode }) {
  const clusters = LOCAL_CLUSTERS;
  const [activeId, setActiveId] = useState<string>(() => {
    const saved = localStorage.getItem(ACTIVE_KEY);
    return saved && clusters.some((c) => c.id === saved) ? saved : clusters[0].id;
  });

  const setActiveClusterId = useCallback((id: string) => {
    setActiveId(id);
    try { localStorage.setItem(ACTIVE_KEY, id); } catch { /* ignore */ }
  }, []);

  const value = useMemo<ClusterContextValue>(() => {
    const activeCluster = clusters.find((c) => c.id === activeId) ?? clusters[0];
    return { clusters, activeCluster, setActiveClusterId, isMultiCluster: clusters.length > 1 };
  }, [clusters, activeId, setActiveClusterId]);

  return <ClusterContext.Provider value={value}>{children}</ClusterContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useCluster(): ClusterContextValue {
  const ctx = useContext(ClusterContext);
  if (!ctx) throw new Error('useCluster must be used within a ClusterProvider');
  return ctx;
}
