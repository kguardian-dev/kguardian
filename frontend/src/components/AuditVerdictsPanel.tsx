import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { X, RefreshCw, AlertTriangle, CheckCircle2, Filter } from 'lucide-react';
import type { AuditVerdict, AuditVerdictKind } from '../types';
import api from '../services/api';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

type VerdictTab = 'WouldDeny' | 'Allow' | 'All';
type DirectionFilter = 'All' | 'Ingress' | 'Egress';

/**
 * AuditVerdictsPanel — modal table of evaluator verdicts.
 *
 * Each row is one observation of a flow checked against an
 * AuditNetworkPolicy or AuditClusterNetworkPolicy. Two verdicts are
 * surfaced:
 *
 *   - WouldDeny: the policy *would have blocked* this flow if enforced
 *   - Allow:     the policy explicitly *permits* this flow
 *
 * Both matter when previewing impact. Allow tells you the policy is
 * actually selecting the pods you intended (zero allows + zero denies
 * usually means a podSelector typo). WouldDeny tells you what to
 * triage before promoting.
 *
 * Backend: `GET /audit/verdicts` on the broker, reading the
 * `audit_verdicts` table populated by the broker → evaluator
 * forwarder.
 */
const AuditVerdictsPanel: React.FC<Props> = ({ isOpen, onClose }) => {
  const [verdicts, setVerdicts] = useState<AuditVerdict[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policyFilter, setPolicyFilter] = useState('');
  const [verdictTab, setVerdictTab] = useState<VerdictTab>('WouldDeny');
  // Direction is filtered server-side: the broker's /audit/verdicts
  // endpoint accepts a `direction` query param backed by
  // idx_audit_verdicts_verdict_time, so narrowing here avoids burning
  // the 400-row cap on rows we'd discard client-side.
  const [directionFilter, setDirectionFilter] = useState<DirectionFilter>('All');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch both verdicts in one shot; client-side filter by tab.
      // 400-row cap leaves headroom for the busiest pol/window combo
      // we expect operators to triage in one sitting.
      const rows = await api.getAuditVerdicts({
        limit: 400,
        ...(directionFilter !== 'All' ? { direction: directionFilter } : {}),
      });
      setVerdicts(rows);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load audit verdicts');
    } finally {
      setLoading(false);
    }
  }, [directionFilter]);

  useEffect(() => {
    if (!isOpen) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [isOpen, load]);

  // Group verdicts by policy for the side filter list. Each entry
  // shows the (deny, allow) split so operators can see at a glance
  // which policies are noisy on either side.
  const byPolicy = useMemo(() => {
    const m = new Map<string, { deny: number; allow: number; total: number }>();
    for (const v of verdicts) {
      const key = v.policy_namespace ? `${v.policy_namespace}/${v.policy_name}` : v.policy_name;
      const cur = m.get(key) || { deny: 0, allow: 0, total: 0 };
      cur.total++;
      if (v.verdict === 'WouldDeny') cur.deny++;
      else if (v.verdict === 'Allow') cur.allow++;
      m.set(key, cur);
    }
    return m;
  }, [verdicts]);

  const counts = useMemo(() => {
    let deny = 0;
    let allow = 0;
    for (const v of verdicts) {
      if (v.verdict === 'WouldDeny') deny++;
      else if (v.verdict === 'Allow') allow++;
    }
    return { deny, allow, total: verdicts.length };
  }, [verdicts]);

  const visible = useMemo(() => {
    return verdicts.filter(v => {
      if (verdictTab !== 'All' && v.verdict !== verdictTab) return false;
      if (policyFilter) {
        const key = v.policy_namespace ? `${v.policy_namespace}/${v.policy_name}` : v.policy_name;
        if (key !== policyFilter) return false;
      }
      return true;
    });
  }, [verdicts, verdictTab, policyFilter]);

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
                Audit Verdicts
              </h2>
              <p className="text-xs text-tertiary">
                Flows your AuditNetworkPolicies would block (or already permit). Nothing was actually dropped.
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

        {/* Verdict tabs + Direction filter */}
        <nav
          className="flex items-center justify-between border-b border-hubble-border bg-hubble-dark px-2"
          aria-label="Verdict filter"
        >
          <div className="flex">
            <VerdictTabButton
              active={verdictTab === 'WouldDeny'}
              onClick={() => setVerdictTab('WouldDeny')}
              icon={<AlertTriangle className="w-4 h-4" />}
              color="text-hubble-warning"
              label="Would-Deny"
              count={counts.deny}
            />
            <VerdictTabButton
              active={verdictTab === 'Allow'}
              onClick={() => setVerdictTab('Allow')}
              icon={<CheckCircle2 className="w-4 h-4" />}
              color="text-hubble-accent"
              label="Allow"
              count={counts.allow}
            />
            <VerdictTabButton
              active={verdictTab === 'All'}
              onClick={() => setVerdictTab('All')}
              icon={null}
              color="text-secondary"
              label="All"
              count={counts.total}
            />
          </div>
          <div
            className="flex items-center gap-2 pr-1"
            role="group"
            aria-label="Direction filter"
          >
            <span className="text-[11px] font-medium uppercase tracking-wide text-tertiary">
              Direction
            </span>
            <div className="flex overflow-hidden rounded border border-hubble-border">
              {(['All', 'Ingress', 'Egress'] as const).map(d => (
                <DirectionButton
                  key={d}
                  active={directionFilter === d}
                  onClick={() => setDirectionFilter(d)}
                  label={d}
                />
              ))}
            </div>
          </div>
        </nav>

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
              .sort(([, a], [, b]) => b.total - a.total)
              .map(([key, c]) => (
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
                  <span className="truncate block">{key}</span>
                  <span className="text-[11px] text-tertiary tabular-nums">
                    {c.deny > 0 && <span className="text-hubble-warning">{c.deny} deny</span>}
                    {c.deny > 0 && c.allow > 0 && <span> · </span>}
                    {c.allow > 0 && <span className="text-hubble-accent">{c.allow} allow</span>}
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
                No {verdictTab === 'All' ? '' : verdictTab.toLowerCase()} verdicts in the rolling window.
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
                    <th className="px-4 py-2">Verdict</th>
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
                        <td className="px-4 py-2">
                          <VerdictBadge verdict={v.verdict as AuditVerdictKind} />
                        </td>
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
          Showing {visible.length} of {verdicts.length} most recent verdict{verdicts.length === 1 ? '' : 's'} ·
          {' '}<span className="text-hubble-warning">{counts.deny} deny</span>
          {' '}·
          {' '}<span className="text-hubble-accent">{counts.allow} allow</span>.
          Backed by <code className="font-mono">audit_verdicts</code>; rotated by the broker's retention loop.
        </footer>
      </div>
    </div>
  );
};

interface VerdictTabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  color: string;
  label: string;
  count: number;
}

const VerdictTabButton: React.FC<VerdictTabButtonProps> = ({ active, onClick, icon, color, label, count }) => (
  <button
    onClick={onClick}
    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      active
        ? 'border-hubble-accent text-primary bg-hubble-card/40'
        : 'border-transparent text-secondary hover:text-primary'
    }`}
  >
    {icon && <span className={color}>{icon}</span>}
    {label}
    <span className={`text-xs tabular-nums ${active ? 'text-tertiary' : 'text-tertiary'}`}>({count})</span>
  </button>
);

interface DirectionButtonProps {
  active: boolean;
  onClick: () => void;
  label: string;
}

const DirectionButton: React.FC<DirectionButtonProps> = ({ active, onClick, label }) => (
  <button
    onClick={onClick}
    aria-pressed={active}
    className={`px-2.5 py-1 text-xs font-medium transition-colors border-r border-hubble-border last:border-r-0 ${
      active
        ? 'bg-hubble-accent/20 text-hubble-accent'
        : 'text-secondary hover:bg-hubble-card hover:text-primary'
    }`}
  >
    {label}
  </button>
);

const VerdictBadge: React.FC<{ verdict: AuditVerdictKind | string }> = ({ verdict }) => {
  if (verdict === 'WouldDeny') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-hubble-warning/20 text-hubble-warning">
        <AlertTriangle className="w-3 h-3" /> Deny
      </span>
    );
  }
  if (verdict === 'Allow') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-hubble-accent/20 text-hubble-accent">
        <CheckCircle2 className="w-3 h-3" /> Allow
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-hubble-card text-tertiary">
      {verdict}
    </span>
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
