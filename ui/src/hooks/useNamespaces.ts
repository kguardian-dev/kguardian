import { useState, useEffect } from 'react';
import { apiClient } from '../services/api';

export const useNamespaces = () => {
  const [namespaces, setNamespaces] = useState<string[]>(['default']);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchNamespaces = async () => {
      setLoading(true);
      try {
        const ns = await apiClient.getNamespaces();
        if (ns.length > 0) {
          setNamespaces(ns);
        }
      } catch (error) {
        console.error('Error fetching namespaces:', error);
        // Keep default namespace on error
      } finally {
        setLoading(false);
      }
    };

    fetchNamespaces();
  }, []);

  return { namespaces, loading };
};
