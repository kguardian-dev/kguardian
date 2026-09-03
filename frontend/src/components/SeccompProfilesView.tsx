import { useMemo, useState } from 'react';
import { Lock, RefreshCw, Search, ShieldAlert, AlertTriangle, ChevronRight, Radar, GitCompareArrows, CheckCircle2 } from 'lucide-react';
import { useSeccompProfiles } from '../hooks/useSeccompProfiles';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';
import { crStatus, resolveCapture } from '../utils/seccompCapture';
import { Button } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import { CaptureBadge, StatePill } from './Seccomp';
import { SeccompProfileDrawer } from './Seccomp/SeccompProfileDrawer';

interface SeccompProfilesViewProps {
  namespace: string;
}

type Key = { ns: string; kind: string; name: string };

function keyOf(p: WorkloadProfileSummary): string {
  return `${p.namespace}/${p.kind}/${p.name}`;
}

const READINESS_CLASS: Record<string, string> = {
  Ready: 'text-hubble-success',
  Partial: 'text-hubble-warning',
  Pending: 'text-tertiary',
};

/**
 * Workload seccomp lifecycle: every profile the broker has aggregated, its
 * draft/published/enforcing state, how complete the capture behind it is,
 * and node readiness. Clicking a row opens the drawer with the actions and
 * the override editor. Namespace-scoped like the other views, with an
 * "all namespaces" escape hatch since profiles are cluster-wide.
 */
export function SeccompProfilesView({ namespace }: SeccompProfilesViewProps) {
  const { api, profiles, loading, error, refresh } = useSeccompProfiles();
  const [allNamespaces, setAllNamespaces] = useState(false);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Key | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return profiles
      .filter((p) => allNamespaces || p.namespace === namespace)
      .filter((p) => !q || keyOf(p).toLowerCase().includes(q))
      .sort((a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind));
  }, [profiles, allNamespaces, namespace, query]);

  const stats = useMemo(() => {
    const statuses = rows.map(crStatus);
    const partial = rows.filter((p) => !resolveCapture(p).complete).length;
    const drifted = rows.filter((p) => p.cr && !p.cr.drift.inSync).length;
    return [
      { label: 'Workloads', value: rows.length, icon: Lock, tone: 'text-hubble-accent' },
      { label: 'Enforcing CRs', value: statuses.filter((s) => s === 'enforcing').length, icon: ShieldAlert, tone: 'text-hubble-error' },
      { label: 'Drifted', value: drifted, icon: GitCompareArrows, tone: drifted > 0 ? 'text-hubble-warning' : 'text-secondary' },
      { label: 'Partial capture', value: partial, icon: AlertTriangle, tone: partial > 0 ? 'text-hubble-warning' : 'text-secondary' },
    ];
  }, [rows]);

  const selectedSummary = selected ? profiles.find((p) => keyOf(p) === `${selected.ns}/${selected.kind}/${selected.name}`) ?? null : null;

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl px-6 py-6 space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-primary">Seccomp Profiles</h2>
            <p className="text-xs text-tertiary mt-0.5">
              Observed syscalls per workload, and the status of the <span className="font-mono text-secondary">SeccompProfile</span> CR you
              deploy for it. kguardian never applies anything itself: export the CR, commit it, apply it. Only{' '}
              <span className="font-mono text-secondary">full</span> capture yields a complete allow-list.
            </p>
          </div>
          <Button variant="secondary" size="sm" leftIcon={RefreshCw} onClick={() => void refresh()} disabled={loading}>
            Refresh
          </Button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {stats.map((s) => {
            const Icon = s.icon;
            return (
              <div key={s.label} className="rounded-surface border border-hubble-border bg-hubble-card px-4 py-3">
                <div className="flex items-center gap-2 text-tertiary text-[11px] uppercase tracking-wide">
                  <Icon className={`w-3.5 h-3.5 ${s.tone}`} />
                  {s.label}
                </div>
                <div className={`mt-1 text-2xl font-semibold font-mono tabular-nums ${s.tone}`}>{s.value}</div>
              </div>
            );
          })}
        </div>

        {error && (
          <div role="alert" className="rounded-surface border border-hubble-error/40 bg-hubble-error/10 px-4 py-3 text-sm text-hubble-error">
            Could not load seccomp profiles: {error}
          </div>
        )}

        <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
          <header className="flex items-center justify-between gap-3 px-4 py-3 border-b border-hubble-border">
            <div className="flex items-center gap-2 h-8 px-3 rounded-control border border-hubble-border bg-hubble-darker focus-within:border-hubble-accent w-full max-w-xs">
              <Search className="w-3.5 h-3.5 text-tertiary shrink-0" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter workloads…"
                aria-label="Filter workloads"
                className="flex-1 bg-transparent text-xs text-primary placeholder:text-tertiary focus:outline-none"
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-secondary select-none">
              <input type="checkbox" checked={allNamespaces} onChange={(e) => setAllNamespaces(e.target.checked)} className="accent-hubble-accent" />
              All namespaces
            </label>
          </header>

          {loading && profiles.length === 0 ? (
            <div className="space-y-2 p-3">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-5/6" />
              <Skeleton className="h-8 w-2/3" />
            </div>
          ) : rows.length === 0 ? (
            <EmptyState
              icon={Radar}
              title={query ? 'No matching workloads' : allNamespaces ? 'No seccomp profiles yet' : `No seccomp profiles in ${namespace}`}
              description="A workload appears once the controller has reported syscalls for it and it has an owning controller (Deployment, StatefulSet, DaemonSet, CronJob)."
              compact
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-[11px] uppercase tracking-wide text-tertiary">
                  <tr className="border-b border-hubble-border">
                    <th className="text-left font-medium px-4 py-2">Workload</th>
                    <th className="text-left font-medium px-3 py-2">Capture</th>
                    <th className="text-left font-medium px-3 py-2">CR</th>
                    <th className="text-left font-medium px-3 py-2">Nodes</th>
                    <th className="text-left font-medium px-3 py-2">Drift</th>
                    <th className="text-right font-medium px-3 py-2">Syscalls</th>
                    <th className="px-2 py-2" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-hubble-border">
                  {rows.map((p) => {
                    const capture = resolveCapture(p);
                    return (
                      <tr
                        key={keyOf(p)}
                        onClick={() => setSelected({ ns: p.namespace, kind: p.kind, name: p.name })}
                        className="cursor-pointer hover:bg-hubble-hover/40 transition-colors"
                      >
                        <td className="px-4 py-2.5 min-w-0">
                          <div className="font-medium text-primary truncate">{p.name}</div>
                          <div className="text-[11px] text-tertiary font-mono truncate">
                            {p.kind}
                            {allNamespaces && ` · ${p.namespace}`}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <CaptureBadge capture={capture} />
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="inline-flex items-center gap-1.5">
                            <StatePill state={crStatus(p)} />
                            {p.cr && <span className="font-mono text-[11px] text-tertiary">{p.cr.name}</span>}
                          </span>
                        </td>
                        <td className={`px-3 py-2.5 font-mono text-xs tabular-nums ${p.cr ? READINESS_CLASS[p.cr.distribution.state] ?? 'text-secondary' : 'text-tertiary'}`}>
                          {p.cr ? (
                            <>
                              {p.cr.distribution.ready}/{p.cr.distribution.total}
                              <span className="ml-1.5 text-tertiary">{p.cr.distribution.state}</span>
                            </>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-xs">
                          {!p.cr ? (
                            <span className="text-tertiary">—</span>
                          ) : p.cr.drift.inSync ? (
                            <span className="inline-flex items-center gap-1 text-hubble-success" title="Every observed syscall is in the CR">
                              <CheckCircle2 className="w-3.5 h-3.5" /> in sync
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-hubble-warning" title={`Observed but not in the CR: ${p.cr.drift.missing.join(', ')}`}>
                              <AlertTriangle className="w-3.5 h-3.5" /> {p.cr.drift.missing.length} missing
                              {p.cr.drift.extra.length > 0 && <span className="text-tertiary">· {p.cr.drift.extra.length} extra</span>}
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums text-secondary">{p.syscallCount}</td>
                        <td className="px-2 py-2.5 text-tertiary">
                          <ChevronRight className="w-4 h-4" />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {selected && (
        <SeccompProfileDrawer
          api={api}
          workload={selected}
          summary={selectedSummary}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

export default SeccompProfilesView;
