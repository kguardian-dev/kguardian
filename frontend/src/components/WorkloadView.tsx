import { useMemo, useState } from 'react';
import { ArrowLeft, Lock, Share2, Network, SearchX } from 'lucide-react';
import type { PodInfo, PodNodeData, ServiceInfo } from '../types';
import { useWorkloadCoverage } from '../hooks/useWorkloadCoverage';
import { workloadKey, workloadOf } from '../utils/workloads';
import { Button } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import { CaptureBadge, PartialCaptureWarning, StatePill } from './Seccomp';
import { SeccompProfileDrawer } from './Seccomp/SeccompProfileDrawer';
import { DriftCell, NetworkPill } from './Workloads/cells';
import DataTable from './DataTable';

interface WorkloadViewProps {
  ns: string;
  kind: string;
  name: string;
  /** This namespace's map nodes (usePodData) — the traffic source. */
  pods: PodNodeData[];
  allPods: PodInfo[];
  services: ServiceInfo[];
  onBack: () => void;
  onOpenInMap: (podId: string) => void;
  /** Increments on the header Refresh; reloads profiles and verdicts. */
  refreshTick?: number;
  /** The cluster-wide pod list has not arrived yet. Until it has, a missing
   *  row means "not loaded", not "no such workload". */
  podsLoading?: boolean;
}

/**
 * Placeholder workload page (`#/workload?ns=&kind=&name=`): the facts
 * kguardian already records for one workload, gathered on one shareable URL —
 * control posture, the seccomp profile (with the existing drawer for export),
 * and observed traffic. The full workload security profile replaces this.
 */
export function WorkloadView({ ns, kind, name, pods, allPods, services, onBack, onOpenInMap, refreshTick, podsLoading = false }: WorkloadViewProps) {
  const { rows, loading: profilesLoading, seccompApi } = useWorkloadCoverage(allPods, refreshTick, ns);
  const loading = profilesLoading || podsLoading;
  const [drawerOpen, setDrawerOpen] = useState(false);
  const key = workloadKey(ns, kind, name);
  const row = rows.find((r) => r.key === key) ?? null;

  // The map node carrying this workload's traffic: the identity group whose
  // pods belong to this workload.
  const node = useMemo(
    () =>
      pods.find(
        (p) =>
          !p.isExternal &&
          (p.pods.length > 0 ? p.pods : [p.pod]).some((pod) => {
            const w = workloadOf(pod);
            return w !== null && workloadKey(w.namespace, w.kind, w.name) === key;
          }),
      ) ?? null,
    [pods, key],
  );

  if (!row) {
    return (
      <div className="h-full overflow-y-auto">
        <div className="mx-auto max-w-5xl px-6 py-6">
          <BackLink onBack={onBack} />
          {loading ? (
            <div className="space-y-2 mt-6">
              <Skeleton className="h-8 w-1/3" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : (
            <EmptyState
              icon={SearchX}
              title={`No workload ${ns}/${name}`}
              description={`kguardian has no live pods or seccomp profile for ${kind} ${ns}/${name}. It may have been deleted, or the link may be from another cluster.`}
            />
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl px-6 py-6 space-y-6">
        <div>
          <BackLink onBack={onBack} />
          <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-primary truncate">{name}</h2>
              <p className="text-xs text-tertiary font-mono mt-0.5">
                {kind} · {ns} · {row.pods.length} live pod{row.pods.length === 1 ? '' : 's'}
              </p>
            </div>
            {node && (
              <Button variant="secondary" size="sm" leftIcon={Share2} onClick={() => onOpenInMap(node.id)}>
                Open in map
              </Button>
            )}
          </div>
        </div>

        {/* Posture: one row per control, the lifecycle vocabulary the full profile page will extend. */}
        <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden" aria-label="Controls">
          <header className="px-4 py-3 border-b border-hubble-border">
            <h3 className="text-sm font-semibold text-primary">Controls</h3>
          </header>
          <div className="overflow-x-auto">
          <table className="w-full text-sm [&_td]:whitespace-nowrap">
            <thead className="text-[11px] uppercase tracking-wide text-tertiary">
              <tr className="border-b border-hubble-border">
                <th className="text-left font-medium px-4 py-2">Control</th>
                <th className="text-left font-medium px-3 py-2">State</th>
                <th className="text-left font-medium px-3 py-2">Drift</th>
                <th className="text-left font-medium px-3 py-2">Capture</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hubble-border">
              <tr>
                <td className="px-4 py-2.5 text-primary">Network policy</td>
                <td className="px-3 py-2.5"><NetworkPill network={row.network} /></td>
                <td className="px-3 py-2.5 text-tertiary">—</td>
                <td className="px-3 py-2.5 text-tertiary">—</td>
              </tr>
              <tr>
                <td className="px-4 py-2.5 text-primary">SeccompProfile</td>
                <td className="px-3 py-2.5">
                  {row.profile ? <StatePill state={row.seccomp} /> : <span className="text-xs text-tertiary">no profile</span>}
                </td>
                <td className="px-3 py-2.5 text-xs"><DriftCell drift={row.drift} /></td>
                <td className="px-3 py-2.5"><CaptureBadge capture={row.capture} /></td>
              </tr>
            </tbody>
          </table>
          </div>
        </section>

        <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden" aria-label="Seccomp">
          <header className="flex items-center justify-between gap-3 px-4 py-3 border-b border-hubble-border">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-hubble-accent" />
              <h3 className="text-sm font-semibold text-primary">Seccomp</h3>
            </div>
            {row.profile && (
              <Button variant="secondary" size="sm" onClick={() => setDrawerOpen(true)}>
                Open profile
              </Button>
            )}
          </header>
          {row.profile ? (
            <div className="px-4 py-3 space-y-3 text-sm">
              <PartialCaptureWarning capture={row.capture} />
              <p className="text-secondary">
                <span className="font-mono">{row.profile.syscallCount}</span> syscalls observed
                {row.profile.cr ? (
                  <>
                    {' '}· CR <span className="font-mono">{row.profile.cr.name}</span> on{' '}
                    <span className="font-mono">
                      {row.profile.cr.distribution.ready}/{row.profile.cr.distribution.total}
                    </span>{' '}
                    nodes
                  </>
                ) : (
                  ' · no SeccompProfile CR deployed'
                )}
              </p>
            </div>
          ) : (
            <EmptyState
              icon={Lock}
              title="No seccomp profile yet"
              description="A profile appears once the controller has reported syscalls for this workload and it has an owning controller (Deployment, StatefulSet, DaemonSet, CronJob)."
              compact
            />
          )}
        </section>

        <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden" aria-label="Traffic">
          <header className="flex items-center gap-2 px-4 py-3 border-b border-hubble-border">
            <Network className="w-4 h-4 text-hubble-accent" />
            <h3 className="text-sm font-semibold text-primary">Observed traffic and syscalls</h3>
          </header>
          {node ? (
            <DataTable selectedPod={node} allPodsLookup={allPods} services={services} />
          ) : (
            <EmptyState
              icon={Network}
              title="No live traffic"
              description="No live pod of this workload is in the loaded namespace, so there is no traffic to show."
              compact
            />
          )}
        </section>
      </div>

      {drawerOpen && row.profile && (
        <SeccompProfileDrawer
          api={seccompApi}
          workload={{ ns, kind, name }}
          summary={row.profile}
          onClose={() => setDrawerOpen(false)}
        />
      )}
    </div>
  );
}

function BackLink({ onBack }: { onBack: () => void }) {
  return (
    <button onClick={onBack} className="inline-flex items-center gap-1 text-xs text-secondary hover:text-primary transition-colors">
      <ArrowLeft className="w-3.5 h-3.5" /> Workloads
    </button>
  );
}

export default WorkloadView;
