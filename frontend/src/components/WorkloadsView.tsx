import { useCallback, useEffect, useMemo, useState } from 'react';
import { Lock, Search, AlertTriangle, ChevronRight, CloudOff, Radar, GitCompareArrows, Layers, ShieldAlert } from 'lucide-react';
import type { PodInfo } from '../types';
import { useWorkloadCoverage } from '../hooks/useWorkloadCoverage';
import { routeHref, workloadParams } from '../utils/routes';
import { hasBlockingDrift, type WorkloadRow } from '../utils/workloads';
import { STATUS_LABEL } from '../utils/posture';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import { StatStrip, StatTile, type StatTileProps } from './ui/StatTile';
import { CaptureBadge, CrNodes, StatePill } from './Seccomp';
import { DriftCell, NetworkPill } from './Workloads/cells';
import { PostureCell } from './Workloads/PostureCell';
import {
  applyColumnFilters, columnFilterClauses, COLUMN_FILTER_OPTIONS, joinClauses, NO_COLUMN_FILTERS, shownColumnFilters,
  unknownRowsNote, type ColumnFilters,
} from './Workloads/filters';
import { POSTURE_AUTO_PAGES, useWorkloadPostures } from '../hooks/useWorkloadProfile';
import { errorMessage } from '../services/profileApi';
import type { PostureStatus } from '../types/profile';
import { Button } from './ui/Button';

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

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

const CONTROLS: Array<{ id: WorkloadControl | undefined; label: string }> = [
  { id: undefined, label: 'All controls' },
  { id: 'seccomp', label: 'Seccomp' },
];

const DRIFT_TITLE = 'Workloads with observed syscalls their deployed CR does not allow (blocked when enforcing). Syscalls the CR allows but never observed are not counted.';
const PARTIAL_TITLE = 'Workloads with a pod below full syscall capture';

/** Why the filtered table reads empty, naming every active filter rather than the pod-discovery copy. */
function emptyDescription(scopeLabel: string, query: string, postureFilter: PostureStatus | '', columns: string[], seccompMode: boolean): string {
  const posture = postureFilter ? (postureFilter === 'unknown' ? 'no posture data' : `posture ${STATUS_LABEL[postureFilter]}`) : '';
  const clauses = [posture, ...columns].filter(Boolean);
  if (clauses.length && query) return `No workload in ${scopeLabel} has ${joinClauses([...clauses, `a name or namespace containing “${query}”`])}.`;
  if (clauses.length) return `No workload in ${scopeLabel} has ${joinClauses(clauses)}${columns.length === 0 ? " in the Broker's profile list" : ''}.`;
  if (query) return `No workload name or namespace in ${scopeLabel} contains “${query}”.`;
  return seccompMode
    ? 'A workload appears once the controller has reported syscalls for it and it has an owning controller (Deployment, StatefulSet, DaemonSet, CronJob).'
    : 'A workload appears once the controller has reported one of its pods.';
}

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
  const [query, setQuery] = useState('');
  const [postureFilter, setPostureFilter] = useState<PostureStatus | ''>('');
  const [columnFilters, setColumnFilters] = useState<ColumnFilters>(NO_COLUMN_FILTERS);
  const seccompMode = control === 'seccomp';
  // The name filter also narrows the posture request (server-side search) and
  // the seccomp fallback reads, debounced so typing does not fire one request
  // per keystroke.
  const search = useDebounced(query.trim(), 300);
  const q = search.toLowerCase();
  const visible = useCallback(
    (r: WorkloadRow) => (allNamespaces || r.namespace === namespace) && (!q || r.key.toLowerCase().includes(q)),
    [allNamespaces, namespace, q],
  );
  const { rows: allRows, loading, error, profiles, seccompUnavailable, verdictsUnavailable, verdictsLoading } = useWorkloadCoverage(allPods, refreshTick, allNamespaces ? undefined : namespace, { visible });
  // The filter matches namespace/kind/name; the Broker's search matches the
  // name only. It narrows the posture request only while it finds the same
  // rows, so a namespace or kind match is not read as "no snapshot".
  const nameSearch = useMemo(
    () => (search && allRows.filter(visible).every((r) => r.name.toLowerCase().includes(q)) ? search : undefined),
    [search, q, allRows, visible],
  );
  // The posture column only exists on the all-controls table; the seccomp
  // columns never ask for it.
  const postures = useWorkloadPostures(allNamespaces ? undefined : namespace, postureFilter || undefined, nameSearch, refreshTick, undefined, undefined, !seccompMode);
  // Under a posture filter the rows are the Broker's answer; without one there is nothing to filter by.
  const postureFilterUnread = !seccompMode && !!postureFilter && postures.byKey.size === 0 && (postures.loading || postures.error != null);

  const filtered = useMemo(() => {
    const qi = query.trim().toLowerCase();
    const matched = allRows
      .filter((r) => allNamespaces || r.namespace === namespace)
      .filter((r) => !seccompMode || r.profile)
      // A posture filter is server-side: keep the rows the Broker returned.
      .filter((r) => seccompMode || !postureFilter || postures.byKey.has(r.key))
      .filter((r) => !qi || r.key.toLowerCase().includes(qi));
    return applyColumnFilters(matched, columnFilters, seccompMode, { verdictsUnknown: verdictsLoading || verdictsUnavailable });
  }, [allRows, allNamespaces, namespace, seccompMode, query, postureFilter, postures.byKey, columnFilters, verdictsLoading, verdictsUnavailable]);
  const { rows } = filtered;
  const unknownNote = unknownRowsNote(filtered);
  const columnClauses = columnFilterClauses(columnFilters, seccompMode);
  const filtering = query.trim() !== '' || (!seccompMode && postureFilter !== '') || columnClauses.length > 0;
  const clearFilters = () => {
    setQuery('');
    setPostureFilter('');
    setColumnFilters(NO_COLUMN_FILTERS);
  };

  // Page postures until every rendered row has one or the Broker has no
  // more, a bounded number of times; past that the user asks.
  const uncovered = useMemo(() => !seccompMode && rows.some((r) => !postures.byKey.has(r.key)), [rows, postures.byKey, seccompMode]);
  const { hasMore, loading: posturesLoading, loadingMore, pages, loadMore } = postures;
  useEffect(() => {
    if (!uncovered || !hasMore || posturesLoading || loadingMore || pages >= POSTURE_AUTO_PAGES) return;
    void loadMore();
  }, [uncovered, hasMore, posturesLoading, loadingMore, pages, loadMore]);

  const stats = useMemo<StatTileProps[]>(() => {
    const enforcing = rows.filter((r) => r.seccomp === 'enforcing').length;
    const partial = rows.filter((r) => r.capture && !r.capture.complete).length;
    const drifted = rows.filter((r) => hasBlockingDrift(r.drift)).length;
    const wouldDeny = rows.filter((r) => r.network.state === 'audit' && r.network.wouldDeny > 0).length;
    const warn = (n: number) => (n > 0 ? 'text-hubble-warning' : 'text-secondary');
    // A count from the seccomp profile list is not an answer while the list is loading or failed.
    const unknownTitle = loading ? 'Unknown until the seccomp profile list has loaded' : 'Unknown: the seccomp profile list could not be read';
    const seccompTile = (t: StatTileProps): StatTileProps => (seccompUnavailable ? { ...t, value: '—', suffix: undefined, tone: 'text-tertiary', title: unknownTitle } : t);
    if (seccompMode) {
      return [
        seccompTile({ label: 'Workloads', value: rows.length, icon: Lock, tone: 'text-hubble-accent' }),
        seccompTile({ label: 'Enforcing CRs', value: enforcing, icon: Lock, tone: enforcing > 0 ? 'text-state-enforcing' : 'text-secondary' }),
        seccompTile({ label: 'Drifted', value: drifted, icon: GitCompareArrows, tone: warn(drifted), title: DRIFT_TITLE }),
        seccompTile({ label: 'Partial capture', value: partial, icon: AlertTriangle, tone: warn(partial), title: PARTIAL_TITLE }),
      ];
    }
    return [
      { label: 'Workloads', value: rows.length, icon: Layers, tone: 'text-hubble-accent' },
      seccompTile({
        label: 'Seccomp enforcing', value: enforcing, suffix: `/${rows.length}`, icon: Lock,
        tone: rows.length > 0 && enforcing === rows.length ? 'text-state-enforcing' : 'text-secondary',
        title: 'Workloads whose SeccompProfile CR blocks unlisted syscalls',
        onClick: () => onControlChange('seccomp'),
      }),
      verdictsUnavailable || verdictsLoading
        ? {
            label: 'Would-deny (recent)', value: '—', icon: ShieldAlert, tone: 'text-tertiary',
            title: verdictsUnavailable ? 'Unknown: the audit verdicts could not be read' : 'Unknown until the audit verdicts have loaded',
          }
        : {
            label: 'Would-deny (recent)', value: wouldDeny, icon: ShieldAlert, tone: warn(wouldDeny),
            title: 'Workloads that are the subject of a WouldDeny verdict among the latest 500 audit verdicts of each kind. A recent window, not policy coverage: kguardian does not know which policies select a workload.',
          },
      seccompTile({ label: 'Drifted', value: drifted, icon: GitCompareArrows, tone: warn(drifted), title: DRIFT_TITLE }),
      seccompTile({ label: 'Partial capture', value: partial, icon: AlertTriangle, tone: warn(partial), title: PARTIAL_TITLE }),
    ];
  }, [rows, seccompMode, seccompUnavailable, verdictsUnavailable, verdictsLoading, loading, onControlChange]);

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

        {verdictsUnavailable && !seccompMode && (
          <p role="status" className="text-xs text-tertiary" data-testid="verdicts-unavailable">
            Audit verdicts could not be read: the Network policy column reads not reported and the would-deny tile is unknown until the header Refresh succeeds.
          </p>
        )}
        {error && (
          <div role="alert" className="rounded-surface border border-hubble-error/40 bg-hubble-error/10 px-4 py-3 text-sm text-hubble-error">
            Could not load seccomp profiles: {error}
            {seccompUnavailable && (
              <span className="block mt-1 text-xs opacity-90">
                Seccomp, drift and capture read unknown until the list answers; meanwhile the first rows shown are read one workload at a time.
              </span>
            )}
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
            {shownColumnFilters(seccompMode).map((k) => (
                <label key={k} className="flex items-center gap-1.5 text-xs text-tertiary">
                  {COLUMN_FILTER_OPTIONS[k].label}
                  <select
                    value={columnFilters[k]}
                    onChange={(e) => setColumnFilters((f) => ({ ...f, [k]: e.target.value }))}
                    className={`h-8 rounded-control border bg-hubble-darker px-2 text-xs text-primary ${columnFilters[k] ? 'border-hubble-accent' : 'border-hubble-border'}`}
                  >
                    <option value="">Any</option>
                    {COLUMN_FILTER_OPTIONS[k].options.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                </label>
              ))}
            {filtering && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>Clear filters</Button>
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
          {unknownNote && (
            <p role="status" className="px-4 py-2 text-[11px] text-tertiary border-b border-hubble-border" data-testid="filter-unknown">
              {unknownNote}
            </p>
          )}

          {(loading && profiles.length === 0 && (seccompMode || allRows.length === 0)) || (postureFilterUnread && postures.loading) ? (
            <div className="space-y-2 p-3" aria-busy="true" aria-label="Loading">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-5/6" />
              <Skeleton className="h-8 w-2/3" />
            </div>
          ) : postureFilterUnread ? (
            <EmptyState
              icon={CloudOff}
              title="Posture could not be read"
              description={`The Broker did not answer the posture list, so the ${STATUS_LABEL[postureFilter as PostureStatus]} filter has nothing to show: ${errorMessage(postures.error)}. Refresh from the header to try again, or set Posture to Any.`}
              compact
            />
          ) : rows.length === 0 ? (
            seccompMode && seccompUnavailable ? (
              <EmptyState
                icon={CloudOff}
                title="Seccomp profiles could not be read"
                description="The Broker did not answer the profile list; the error is above. Workloads with a profile appear here as their own seccomp reads answer. Refresh from the header to try the list again."
                compact
              />
            ) : (
              <EmptyState
                icon={Radar}
                title={filtering ? 'No matching workloads' : seccompMode ? `No seccomp profiles in ${scopeLabel}` : `No workloads in ${scopeLabel}`}
                description={emptyDescription(scopeLabel, query.trim(), seccompMode ? '' : postureFilter, columnClauses, seccompMode)}
                compact
              />
            )
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
                      <td className="px-4 py-2.5">
                        {/* Long names are cut, not allowed to push the table wider than a laptop screen. */}
                        <div className="max-w-[13rem] 2xl:max-w-[18rem]" title={`${r.namespace}/${r.kind}/${r.name}`}>
                          <a
                            href={routeHref('workload', target)}
                            onClick={(e) => e.stopPropagation()}
                            className="block font-medium text-primary truncate hover:underline"
                          >
                            {r.name}
                          </a>
                          <div className="text-[11px] text-tertiary font-mono truncate">
                            {r.kind}
                            {allNamespaces && ` · ${r.namespace}`}
                          </div>
                        </div>
                      </td>
                      {seccompMode && r.profile ? (
                        <>
                          <td className="px-3 py-2.5">{r.capture && <CaptureBadge capture={r.capture} />}</td>
                          <td className="px-3 py-2.5">
                            {/* The CR name under the pill, cut to the column. */}
                            <span className="inline-flex flex-col items-start gap-0.5">
                              <StatePill state={r.seccomp} />
                              {r.profile.cr && (
                                <span className="block font-mono text-[11px] text-tertiary truncate max-w-[11rem]" title={r.profile.cr.name}>
                                  {r.profile.cr.name}
                                </span>
                              )}
                            </span>
                          </td>
                          <td className="px-3 py-2.5">{r.profile.cr ? <CrNodes cr={r.profile.cr} /> : <span className="font-mono text-xs text-tertiary">—</span>}</td>
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
                            {r.profile || r.seccomp === 'unknown' ? (
                              <StatePill state={r.seccomp} />
                            ) : (
                              <span className="text-xs text-tertiary" title="No syscalls aggregated for this workload yet (bare pods have no profile)">no profile</span>
                            )}
                          </td>
                          <td className="px-3 py-2.5 text-xs"><DriftCell drift={r.drift} /></td>
                          <td className="px-3 py-2.5">
                            {r.capture ? (
                              <CaptureBadge capture={r.capture} />
                            ) : (
                              <span className="text-xs text-tertiary" title="Unknown: the seccomp profile list could not be read" data-testid="capture-unknown">—</span>
                            )}
                          </td>
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
              <Button variant="secondary" size="sm" onClick={() => void postures.loadMore()} disabled={postures.loadingMore || postures.loading}>
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
