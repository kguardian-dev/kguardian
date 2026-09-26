import { useMemo, useState } from 'react';
import { Lock, Search, AlertTriangle, ChevronRight, Radar, GitCompareArrows, Layers, ShieldAlert } from 'lucide-react';
import type { PodInfo } from '../types';
import { useWorkloadCoverage } from '../hooks/useWorkloadCoverage';
import { routeHref, workloadParams } from '../utils/routes';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import { StatStrip, StatTile, type StatTileProps } from './ui/StatTile';
import { CaptureBadge, StatePill } from './Seccomp';
import { DriftCell, NetworkPill } from './Workloads/cells';
import { PostureCell } from './Workloads/PostureCell';
import { useWorkloadPostures } from '../hooks/useWorkloadProfile';
import { errorMessage } from '../services/profileApi';
import type { PostureStatus } from '../types/profile';
import { Button } from './ui/Button';

export type WorkloadControl = 'seccomp';

interface WorkloadsViewProps {
  /** Cluster-wide pod list (usePodData's allPodsLookup). */
  allPods: readonly PodInfo[];
  /** Header namespace; applied only when `allNamespaces` is false. */
  namespace: string;
  allNamespaces: boolean;
  /** `seccomp` opens the table on the seccomp columns (the old Seccomp Profiles view). */
  control?: WorkloadControl;
  onControlChange: (control: WorkloadControl | undefined) => void;
  /** Opens `#/workload` with these params (utils/routes workloadParams). */
  onOpenWorkload: (params: Record<string, string>) => void;
  /** Increments on the header Refresh; reloads profiles and verdicts. */
  refreshTick?: number;
}

const READINESS_CLASS: Record<string, string> = {
  Ready: 'text-hubble-success',
  Partial: 'text-hubble-warning',
  Pending: 'text-tertiary',
};

/** Own keys only: the state string comes from the broker. */
function readinessClass(state: string): string {
  return Object.hasOwn(READINESS_CLASS, state) ? READINESS_CLASS[state] : 'text-secondary';
}

const CONTROLS: Array<{ id: WorkloadControl | undefined; label: string }> = [
  { id: undefined, label: 'All controls' },
  { id: 'seccomp', label: 'Seccomp' },
];

/**
 * Coverage table: one row per workload, with the state of every control
 * kguardian can report on today (network policy, seccomp + drift) and how
 * complete the capture behind it is. Absorbs the old Seccomp Profiles view as
 * its `control=seccomp` mode. Rows open the workload's page.
 *
 * Cluster-wide by default, because profiles and the pod list are; the header
 * scope chip narrows it to one namespace.
 */
export function WorkloadsView({ allPods, namespace, allNamespaces, control, onControlChange, onOpenWorkload, refreshTick }: WorkloadsViewProps) {
  const { rows: allRows, loading, error, profiles } = useWorkloadCoverage(allPods, refreshTick, allNamespaces ? undefined : namespace);
  const [query, setQuery] = useState('');
  const [postureFilter, setPostureFilter] = useState<PostureStatus | ''>('');
  const seccompMode = control === 'seccomp';
  // The posture column only exists on the all-controls table; the seccomp
  // columns never ask for it.
  const postures = useWorkloadPostures(allNamespaces ? undefined : namespace, postureFilter || undefined, refreshTick, undefined, undefined, !seccompMode);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allRows
      .filter((r) => allNamespaces || r.namespace === namespace)
      .filter((r) => !seccompMode || r.profile)
      // A posture filter is server-side: keep the rows the Broker returned.
      .filter((r) => seccompMode || !postureFilter || postures.byKey.has(r.key))
      .filter((r) => !q || r.key.toLowerCase().includes(q));
  }, [allRows, allNamespaces, namespace, seccompMode, query, postureFilter, postures.byKey]);

  const stats = useMemo<StatTileProps[]>(() => {
    const enforcing = rows.filter((r) => r.seccomp === 'enforcing').length;
    const partial = rows.filter((r) => !r.capture.complete).length;
    const drifted = rows.filter((r) => r.drift && !r.drift.inSync).length;
    const audited = rows.filter((r) => r.network.state === 'audit').length;
    const warn = (n: number) => (n > 0 ? 'text-hubble-warning' : 'text-secondary');
    if (seccompMode) {
      return [
        { label: 'Workloads', value: rows.length, icon: Lock, tone: 'text-hubble-accent' },
        { label: 'Enforcing CRs', value: enforcing, icon: Lock, tone: enforcing > 0 ? 'text-state-enforcing' : 'text-secondary' },
        { label: 'Drifted', value: drifted, icon: GitCompareArrows, tone: warn(drifted) },
        { label: 'Partial capture', value: partial, icon: AlertTriangle, tone: warn(partial) },
      ];
    }
    return [
      { label: 'Workloads', value: rows.length, icon: Layers, tone: 'text-hubble-accent' },
      {
        label: 'Seccomp enforcing', value: enforcing, suffix: `/${rows.length}`, icon: Lock,
        tone: rows.length > 0 && enforcing === rows.length ? 'text-state-enforcing' : 'text-secondary',
        title: 'Workloads whose SeccompProfile CR blocks unlisted syscalls',
        onClick: () => onControlChange('seccomp'),
      },
      {
        label: 'Network audit', value: audited, suffix: `/${rows.length}`, icon: ShieldAlert, tone: 'text-secondary',
        title: 'Workloads named by recent AuditNetworkPolicy verdicts',
      },
      { label: 'Drifted', value: drifted, icon: GitCompareArrows, tone: warn(drifted), title: 'Observed syscalls missing from the deployed CR' },
      { label: 'Partial capture', value: partial, icon: AlertTriangle, tone: warn(partial), title: 'Workloads with a pod below full syscall capture' },
    ];
  }, [rows, seccompMode, onControlChange]);

  const scopeLabel = allNamespaces ? 'all namespaces' : namespace;

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-6xl px-6 py-6 space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-primary">Workloads</h2>
            <p className="text-xs text-tertiary mt-0.5">
              {seccompMode ? (
                <>
                  Observed syscalls per workload, and the status of the <span className="font-mono text-secondary">SeccompProfile</span> CR you
                  deploy for it. kguardian never applies anything itself: export the CR, commit it, apply it. Only{' '}
                  <span className="font-mono text-secondary">full</span> capture yields a complete allow-list.
                </>
              ) : (
                <>Which controls cover each workload, and how complete the capture behind them is. kguardian reports and generates; it never applies.</>
              )}
            </p>
          </div>
        </div>

        <StatStrip count={stats.length} label="Coverage">
          {stats.map((s) => <StatTile key={s.label} {...s} />)}
        </StatStrip>

        {error && (
          <div role="alert" className="rounded-surface border border-hubble-error/40 bg-hubble-error/10 px-4 py-3 text-sm text-hubble-error">
            Could not load seccomp profiles: {error}
          </div>
        )}

        <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
          <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-hubble-border">
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
            <div className="flex flex-wrap items-center gap-2">
            {!seccompMode && (
              <label className="flex items-center gap-1.5 text-xs text-tertiary">
                Posture
                <select
                  value={postureFilter}
                  onChange={(e) => setPostureFilter(e.target.value as PostureStatus | '')}
                  className="h-8 rounded-control border border-hubble-border bg-hubble-darker px-2 text-xs text-primary"
                >
                  <option value="">Any</option>
                  <option value="risk">Risk</option>
                  <option value="warn">Warn</option>
                  <option value="ok">OK</option>
                  <option value="unknown">No data</option>
                </select>
              </label>
            )}
            <div role="group" aria-label="Control" className="inline-flex rounded-control border border-hubble-border overflow-hidden">
              {CONTROLS.map((c) => {
                const on = c.id === control;
                return (
                  <button
                    key={c.label}
                    type="button"
                    aria-pressed={on}
                    onClick={() => onControlChange(c.id)}
                    className={`px-3 h-8 text-xs transition-colors ${on ? 'bg-hubble-accent/20 text-primary' : 'text-secondary hover:bg-hubble-hover/60'}`}
                  >
                    {c.label}
                  </button>
                );
              })}
            </div>
            </div>
          </header>

          {loading && profiles.length === 0 && allRows.length === 0 ? (
            <div className="space-y-2 p-3">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-5/6" />
              <Skeleton className="h-8 w-2/3" />
            </div>
          ) : rows.length === 0 ? (
            <EmptyState
              icon={Radar}
              title={query || postureFilter ? 'No matching workloads' : seccompMode ? `No seccomp profiles in ${scopeLabel}` : `No workloads in ${scopeLabel}`}
              description={
                seccompMode
                  ? 'A workload appears once the controller has reported syscalls for it and it has an owning controller (Deployment, StatefulSet, DaemonSet, CronJob).'
                  : 'A workload appears once the controller has reported one of its pods.'
              }
              compact
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-[11px] uppercase tracking-wide text-tertiary">
                  {seccompMode ? (
                    <tr className="border-b border-hubble-border">
                      <th className="text-left font-medium px-4 py-2">Workload</th>
                      <th className="text-left font-medium px-3 py-2">Capture</th>
                      <th className="text-left font-medium px-3 py-2">CR</th>
                      <th className="text-left font-medium px-3 py-2">Nodes</th>
                      <th className="text-left font-medium px-3 py-2">Drift</th>
                      <th className="text-right font-medium px-3 py-2">Syscalls</th>
                      <th className="px-2 py-2" />
                    </tr>
                  ) : (
                    <tr className="border-b border-hubble-border">
                      <th className="text-left font-medium px-4 py-2">Workload</th>
                      <th className="text-left font-medium px-3 py-2" title="Worst status across the profile's dimensions with data, from the Broker's profile read model">Posture</th>
                      <th className="text-right font-medium px-3 py-2">Pods</th>
                      <th className="text-left font-medium px-3 py-2 whitespace-nowrap">Network policy</th>
                      <th className="text-left font-medium px-3 py-2">Seccomp</th>
                      <th className="text-left font-medium px-3 py-2">Drift</th>
                      <th className="text-left font-medium px-3 py-2">Capture</th>
                      <th className="px-2 py-2" />
                    </tr>
                  )}
                </thead>
                <tbody className="divide-y divide-hubble-border [&_td]:whitespace-nowrap">
                  {rows.map((r) => {
                    // One builder for both the click and the href, carrying
                    // this list's scope/control so Back returns here.
                    const target = workloadParams(r.namespace, r.kind, r.name, { scope: allNamespaces ? undefined : 'ns', control });
                    return (
                    <tr
                      key={r.key}
                      data-testid="workload-row"
                      onClick={() => onOpenWorkload(target)}
                      className="cursor-pointer hover:bg-hubble-hover/40 transition-colors"
                    >
                      <td className="px-4 py-2.5 min-w-0">
                        <a
                          href={routeHref('workload', target)}
                          onClick={(e) => e.stopPropagation()}
                          className="font-medium text-primary truncate hover:underline"
                        >
                          {r.name}
                        </a>
                        <div className="text-[11px] text-tertiary font-mono truncate">
                          {r.kind}
                          {allNamespaces && ` · ${r.namespace}`}
                        </div>
                      </td>
                      {seccompMode && r.profile ? (
                        <>
                          <td className="px-3 py-2.5"><CaptureBadge capture={r.capture} /></td>
                          <td className="px-3 py-2.5">
                            <span className="inline-flex items-center gap-1.5">
                              <StatePill state={r.seccomp} />
                              {r.profile.cr && <span className="font-mono text-[11px] text-tertiary">{r.profile.cr.name}</span>}
                            </span>
                          </td>
                          <td className={`px-3 py-2.5 font-mono text-xs tabular-nums ${r.profile.cr ? readinessClass(r.profile.cr.distribution.state) : 'text-tertiary'}`}>
                            {r.profile.cr ? (
                              <>
                                {r.profile.cr.distribution.ready}/{r.profile.cr.distribution.total}
                                <span className="ml-1.5 text-tertiary">{r.profile.cr.distribution.state}</span>
                              </>
                            ) : (
                              '—'
                            )}
                          </td>
                          <td className="px-3 py-2.5 text-xs"><DriftCell drift={r.drift} /></td>
                          <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums text-secondary">{r.profile.syscallCount}</td>
                        </>
                      ) : (
                        <>
                          <td className="px-3 py-2.5">
                            <PostureCell item={postures.byKey.get(r.key)} loading={postures.loading} unavailable={postures.error != null} morePages={postures.hasMore} />
                          </td>
                          <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums text-secondary">{r.pods.length}</td>
                          <td className="px-3 py-2.5"><NetworkPill network={r.network} /></td>
                          <td className="px-3 py-2.5">
                            {r.profile ? (
                              <StatePill state={r.seccomp} />
                            ) : (
                              <span className="text-xs text-tertiary" title="No syscalls aggregated for this workload yet (bare pods have no profile)">no profile</span>
                            )}
                          </td>
                          <td className="px-3 py-2.5 text-xs"><DriftCell drift={r.drift} /></td>
                          <td className="px-3 py-2.5"><CaptureBadge capture={r.capture} /></td>
                        </>
                      )}
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
          {!seccompMode && postures.error != null && rows.length > 0 && (
            <p className="px-4 py-2 text-[11px] text-tertiary border-t border-hubble-border">
              Posture unavailable: {errorMessage(postures.error)}
            </p>
          )}
          {!seccompMode && postures.hasMore && (
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 text-[11px] text-tertiary border-t border-hubble-border">
              <span>
                Posture loaded for {postures.byKey.size} workload{postures.byKey.size === 1 ? '' : 's'}
                {postureFilter ? ' matching the filter; more may match' : ''}.
              </span>
              <Button variant="secondary" size="sm" onClick={() => void postures.loadMore()} disabled={postures.loadingMore}>
                {postures.loadingMore ? 'Loading…' : 'Load more postures'}
              </Button>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default WorkloadsView;
