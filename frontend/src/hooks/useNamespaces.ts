import { useState, useEffect } from 'react';
import { apiClient } from '../services/api';

/** The `ns` a deep link carries, read once so the first data run is for it. */
export function namespaceFromUrl(hash: string = typeof window !== 'undefined' ? window.location.hash : ''): string | null {
  const ns = new URLSearchParams(hash.split('?')[1] ?? '').get('ns');
  return ns ? ns : null;
}

/**
 * The namespaces with live pods. Seeded from the URL's `ns` (or empty), never
 * from a hardcoded `default`: the seed is what the first `usePodData` run
 * fetches for, and a `default` seed meant every page load first loaded a
 * namespace nobody asked for and then raced it against the real one.
 *
 * A read that fails keeps the seed and sets `error`: the list is then not
 * authoritative, so a deep link's namespace must not be judged unknown by it.
 */
export const useNamespaces = () => {
  const [namespaces, setNamespaces] = useState<string[]>(() => {
    const ns = namespaceFromUrl();
    return ns ? [ns] : [];
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchNamespaces = async () => {
      setLoading(true);
      try {
        const ns = await apiClient.getNamespaces();
        if (ns.length > 0) {
          setNamespaces(ns);
        }
        setError(null);
      } catch (err) {
        console.error('Error fetching namespaces:', err);
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    };

    fetchNamespaces();
  }, []);

  return { namespaces, loading, error };
};
