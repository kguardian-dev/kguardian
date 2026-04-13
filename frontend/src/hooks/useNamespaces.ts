import { useState, useEffect } from 'react';
import axios from 'axios';
import { apiClient } from '../services/api';

export const useNamespaces = () => {
  const [namespaces, setNamespaces] = useState<string[]>(['default']);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    const fetchNamespaces = async () => {
      setLoading(true);
      setError(null);
      try {
        const ns = await apiClient.getNamespaces(controller.signal);
        if (ns.length > 0) {
          setNamespaces(ns);
        }
      } catch (err) {
        if (axios.isCancel(err) || (err instanceof Error && err.name === 'CanceledError')) {
          return;
        }
        console.error('Error fetching namespaces:', err);
        setError(err instanceof Error ? err.message : 'Unknown error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchNamespaces();

    return () => controller.abort();
  }, []);

  return { namespaces, loading, isError: error !== null, error };
};
