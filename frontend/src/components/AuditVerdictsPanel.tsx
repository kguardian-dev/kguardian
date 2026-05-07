import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { X, RefreshCw, AlertTriangle, Filter } from 'lucide-react';
import type { AuditVerdict } from '../types';
import api from '../services/api';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

/**
 * AuditVerdictsPanel — modal table of "would-deny" flows.
 *
 * Each row is one observation that an `AuditNetworkPolicy` (or the
 * cluster-scoped sibling) would have blocked if it were enforced.
 * Operators use this to triage false positives before promoting an
 * audit policy to a real `networking.k8s.io/v1.NetworkPolicy`.
 *
 * Backend is `GET /audit/verdicts` on the broker, which reads from
 * the `audit_verdicts` table populated by the broker -> evaluator
 * forwarder.
 */
const AuditVerdictsPanel: React.FC<Props> = ({ isOpen, onClose }) => {
  const [verdicts, setVerdicts] = useState<AuditVerdict[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policyFilter, setPolicyFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await api.getAuditVerdicts({ limit: 200 });
      setVerdicts(rows);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load audit verdicts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    void load();
  }, [isOpen, load]);

  // Group verdicts by policy for the side filter list. We don't
  // server-side filter by name because the broker's index is on
  // (policy_uid, observed_at) — the API supports it, but for the UI
  // it's snappier to filter the already-loaded set client-side.
  const byPolicy = useMemo(() => {
    const m = new Map<string, AuditVerdict[]>();
    for (const v of verdicts) {
      const key = v.policy_namespace ? `${v.policy_namespace}/${v.policy_name}` : v.policy_name;
      const list = m.get(key) || [];
      list.push(v);
      m.set(key, list);
    }
    return m;
  }, [verdicts]);

  const visible = useMemo(() => {
    if (!policyFilter) return verdicts;
    return verdicts.filter(v => {
      const key = v.policy_namespace ? `${v.policy_namespace}/${v.policy_name}` : v.policy_name;
      return key === policyFilter;
    });
  }, [verdicts, policyFilter]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="audit-verdicts-title"
      onClick={onClose}
    >
      <div
        className="bg-hubble-darker border border-hubble-border rounded-lg w-full max-w-6xl max-h-[90vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <header className="flex items-center justify-between px-6 py-4 border-b border-hubble-border">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-hubble-warning" />
            <div>
              <h2 id="audit-verdicts-title" className="text-xl font-semibold text-primary">
                Audit Verdicts — would-deny flows
              </h2>
              <p className="text-xs text-tertiary">
                Flows your AuditNetworkPolicies would have blocked. Nothing was actually dropped.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void load()}
              disabled={loading}
              className="flex items-center gap-2 px-3 py-1.5 bg-hubble-card border border-hubble-border rounded text-secondary hover:bg-hubble-dark hover:border-hubble-accent transition-all disabled:opacity-50"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
            <button
              onClick={onClose}
              className="p-2 text-tertiary hover:text-primary transition-colors"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </header>

        {/* Body */}
        <div className="flex-1 flex overflow-hidden">
          {/* Sidebar — policies */}
          <aside className="w-64 border-r border-hubble-border overflow-y-auto p-3 bg-hubble-dark">
            <div className="flex items-center gap-2 text-xs font-medium text-tertiary uppercase tracking-wide mb-2">
              <Filter className="w-3.5 h-3.5" /> Policies
            </div>
            <button
              onClick={() => setPolicyFilter('')}
              className={`w-full text-left px-2 py-1.5 rounded text-sm transition-colors ${
                policyFilter === ''
                  ? 'bg-hubble-accent/20 text-hubble-accent'
                  : 'text-secondary hover:bg-hubble-card'
              }`}
            >
              All ({verdicts.length})
            </button>
            {Array.from(byPolicy.entries())
              .sort(([, a], [, b]) => b.length - a.length)
              .map(([key, list]) => (
                <button
                  key={key}
                  onClick={() => setPolicyFilter(key)}
                  className={`w-full text-left px-2 py-1.5 rounded text-sm transition-colors mt-1 ${
                    policyFilter === key
                      ? 'bg-hubble-accent/20 text-hubble-accent'
                      : 'text-secondary hover:bg-hubble-card'
                  }`}
                  title={key}
                >
                  <span className="truncate block">
                    {key} <span className="text-tertiary">({list.length})</span>
                  </span>
                </button>
              ))}
          </aside>

          {/* Main — table */}
          <main className="flex-1 overflow-auto">
            {error && (
              <div className="m-4 p-3 bg-hubble-error/10 border border-hubble-error/40 text-hubble-error rounded">
                {error}
              </div>
            )}
            {!error && !loading && visible.length === 0 && (
              <div className="m-8 text-center text-tertiary">
                No audit verdicts in the rolling window.
                {policyFilter && (
                  <>
                    {' '}
                    <button
                      onClick={() => setPolicyFilter('')}
                      className="text-hubble-accent underline"
                    >
                      Clear filter
                    </button>
                    .
                  </>
                )}
              </div>
            )}
            {visible.length > 0 && (
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-hubble-dark z-10 border-b border-hubble-border">
                  <tr className="text-left text-xs font-medium text-tertiary uppercase tracking-wide">
                    <th className="px-4 py-2">When</th>
                    <th className="px-4 py-2">Policy</th>
                    <th className="px-4 py-2">Dir</th>
                    <th className="px-4 py-2">Source</th>
                    <th className="px-4 py-2">Destination</th>
                    <th className="px-4 py-2">Port</th>
                    <th className="px-4 py-2">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(v => {
                    const policyKey = v.policy_namespace
                      ? `${v.policy_namespace}/${v.policy_name}`
                      : v.policy_name;
                    return (
                      <tr key={v.id} className="border-b border-hubble-border/60 hover:bg-hubble-card/40">
                        <td className="px-4 py-2 text-tertiary whitespace-nowrap">
                          {formatTimestamp(v.observed_at)}
                        </td>
                        <td className="px-4 py-2 font-mono text-xs">
                          {policyKey}
                          {!v.policy_namespace && (
                            <span className="ml-1 text-xs text-hubble-accent">(cluster)</span>
                          )}
                        </td>
                        <td className="px-4 py-2 text-secondary">{v.direction}</td>
                        <td className="px-4 py-2 font-mono text-xs">{formatPodRef(v.src_namespace, v.src_pod)}</td>
                        <td className="px-4 py-2 font-mono text-xs">{formatPodRef(v.dst_namespace, v.dst_pod)}</td>
                        <td className="px-4 py-2 font-mono text-xs">
                          {v.dst_port}/{v.protocol}
                        </td>
                        <td className="px-4 py-2 text-tertiary text-xs">{v.reason ?? ''}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </main>
        </div>

        <footer className="px-6 py-2 border-t border-hubble-border text-xs text-tertiary">
          Showing the most recent {verdicts.length} verdict{verdicts.length === 1 ? '' : 's'}.
          Backed by <code className="font-mono">audit_verdicts</code>; rotated by the broker's retention loop.
        </footer>
      </div>
    </div>
  );
};

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function formatPodRef(ns: string | null, name: string | null): string {
  if (!ns && !name) return '—';
  if (!ns) return name || '—';
  if (!name) return `${ns}/?`;
  return `${ns}/${name}`;
}

export default AuditVerdictsPanel;
