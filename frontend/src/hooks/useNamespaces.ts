import { useState, useEffect, useRef, useCallback } from 'react';
import { apiClient } from '../services/api';

const POLL_INTERVAL_MS = 30_000;
const RETRY_INTERVAL_MS = 5_000;

export const useNamespaces = () => {
  const [namespaces, setNamespaces] = useState<string[]>(['default']);
  const [loading, setLoading] = useState<boolean>(true);
  const [connected, setConnected] = useState<boolean>(false);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const fetchNamespaces = useCallback(async () => {
    try {
      const ns = await apiClient.getNamespaces();
      if (ns.length > 0) {
        setNamespaces(ns);
        setConnected(true);
        return true;
      }
    } catch (error) {
      console.error('Error fetching namespaces:', error);
    }
    setConnected(false);
    return false;
  }, []);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      if (cancelled) return;
      setLoading((prev) => prev); // keep existing loading state for polls
      const ok = await fetchNamespaces();
      if (cancelled) return;
      setLoading(false);
      // Poll faster when disconnected so we recover quickly
      const interval = ok ? POLL_INTERVAL_MS : RETRY_INTERVAL_MS;
      timerRef.current = setTimeout(poll, interval);
    };

    // Initial fetch
    setLoading(true);
    poll();

    // Re-fetch when the broker reconnects after an outage
    const onConnectionChange = (isConnected: boolean) => {
      if (isConnected && !cancelled) {
        // Clear pending timer and fetch immediately
        clearTimeout(timerRef.current);
        poll();
      }
    };
    apiClient.onConnectionChange(onConnectionChange);

    return () => {
      cancelled = true;
      clearTimeout(timerRef.current);
    };
  }, [fetchNamespaces]);

  return { namespaces, loading, connected };
};
