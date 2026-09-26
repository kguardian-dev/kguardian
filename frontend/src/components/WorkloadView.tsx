import { useMemo, useState, type ReactNode } from 'react';
import { ArrowLeft, CloudOff, SearchX, Share2 } from 'lucide-react';
import type { PodNodeData } from '../types';
import { useWorkloadProfile } from '../hooks/useWorkloadProfile';
import { seccompApi } from '../services/seccompApi';
import { errorKind, errorMessage, type ProfileApi } from '../services/profileApi';
import { workloadKey, workloadOf } from '../utils/workloads';
import { formatAgo, formatTimestamp } from '../utils/posture';
import { Button } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { Tabs } from './ui/Tabs';
import { PROFILE_TABS, parseRevision, parseTab, tabPanelProps, type ProfileTab } from '../utils/profileView';
import { SeccompProfileDrawer } from './Seccomp/SeccompProfileDrawer';
import { PostureStrip } from './Profile/PostureStrip';
import { OverviewTab } from './Profile/OverviewTab';
import { NetworkTab } from './Profile/NetworkTab';
import { SyscallsTab } from './Profile/SyscallsTab';
import { ImagesTab } from './Profile/ImagesTab';
import { PodSecurityTab } from './Profile/PodSecurityTab';
import { VersionsTab } from './Profile/VersionsTab';
import { SectionError, SectionSkeleton } from './Profile/parts';

interface WorkloadViewProps {
  ns: string;
  kind: string;
  name: string;
  /** URL params this page owns: `tab`, and `from`/`to` on the Versions tab. */
  tab?: string;
  from?: string;
  to?: string;
  /** Replace this page's own URL params (no history entry). */
  onParamsChange: (patch: Record<string, string | undefined>) => void;
  /** This namespace's map nodes, for "Open in map". */
  pods: PodNodeData[];
  onBack: () => void;
  onOpenInMap: (podId: string) => void;
  /** Increments on the header Refresh. */
  refreshTick?: number;
  api?: ProfileApi;
}

/**
 * Workload Security Profile (`#/workload?ns=&kind=&name=&tab=`): the
 * Broker's profile read model for one workload — posture per dimension,
 * what needs attention, controls, readiness, exposure, and a tab per
 * dimension plus version history. Every section has its own loading, empty
 * and error state; a dimension with no data says "No data", never "OK".
 * kguardian reports and generates here; it applies nothing.
 */
export function WorkloadView({ ns, kind, name, tab: tabParam, from, to, onParamsChange, pods, onBack, onOpenInMap, refreshTick, api }: WorkloadViewProps) {
  const { profile, loading, error, reload } = useWorkloadProfile(ns, kind, name, refreshTick, 30_000, api);
  const tab = parseTab(tabParam);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const key = workloadKey(ns, kind, name);

  // The map node carrying this workload's traffic, for "Open in map".
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

  const openTab = (t: ProfileTab) => onParamsChange({ tab: t === 'overview' ? undefined : t, from: undefined, to: undefined });

  const kindOf = errorKind(error);
  let body: ReactNode;
  if (!profile && loading) {
    body = (
      <div className="rounded-surface border border-hubble-border bg-hubble-card">
        <SectionSkeleton rows={4} />
      </div>
    );
  } else if (!profile && kindOf === 'workload_not_found') {
    body = (
      <EmptyState
        icon={SearchX}
        title={`No workload ${ns}/${name}`}
        description={`The Broker has no inventory, syscalls, live pods or stored profile for ${kind} ${ns}/${name}. It may have been deleted, or the link may be from another cluster.`}
      />
    );
  } else if (!profile && kindOf === 'unsupported') {
    body = <EmptyState icon={CloudOff} title="Profiles not available" description={errorMessage(error)} />;
  } else if (!profile) {
    body = (
      <div className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
        <SectionError message={`Could not load this workload's profile: ${errorMessage(error)}`} onRetry={() => void reload()} />
      </div>
    );
  } else {
    const d = profile.dimensions;
    body = (
      <div className="space-y-4">
        <PostureStrip profile={profile} onOpenTab={openTab} />
        {error != null && (
          <div role="status" className="rounded-control border border-severity-medium/30 bg-severity-medium/10 px-3 py-2 text-xs text-severity-medium">
            Showing the profile from {formatAgo(profile.generatedAt)}; the latest refresh failed: {errorMessage(error)}
          </div>
        )}
        <Tabs tabs={PROFILE_TABS} active={tab} onChange={openTab} label="Profile sections" idPrefix="profile" />
        <div {...tabPanelProps('profile', tab)} className="focus-visible:outline-none">
          {tab === 'overview' && <OverviewTab profile={profile} onOpenTab={openTab} />}
          {tab === 'network' && <NetworkTab dim={d.network} />}
          {tab === 'syscalls' && <SyscallsTab dim={d.syscalls} onOpenSeccomp={d.syscalls.observed ? () => setDrawerOpen(true) : undefined} />}
          {tab === 'images' && <ImagesTab dim={d.images} />}
          {tab === 'podSecurity' && <PodSecurityTab dim={d.podSecurity} />}
          {tab === 'versions' && (
            <VersionsTab
              ns={ns}
              kind={kind}
              name={name}
              refreshTick={refreshTick}
              snapshotPending={profile.snapshotPending}
              from={parseRevision(from)}
              to={parseRevision(to)}
              onSelect={(f, t) => onParamsChange({ tab: 'versions', from: f === undefined ? undefined : String(f), to: t === undefined ? undefined : String(t) })}
              api={api}
            />
          )}
        </div>
      </div>
    );
  }

  const live = profile?.workload.pods.live;
  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-6 space-y-4">
        <div>
          <button onClick={onBack} className="inline-flex items-center gap-1 text-xs text-secondary hover:text-primary transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" aria-hidden /> Workloads
          </button>
          <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-primary [overflow-wrap:anywhere]">{name}</h2>
              <p className="text-xs text-tertiary font-mono mt-0.5 [overflow-wrap:anywhere]">
                {kind} · {ns}
                {live !== undefined && ` · ${live} live pod${live === 1 ? '' : 's'}`}
                {profile?.version && (
                  <span title={`Stored ${formatTimestamp(profile.version.createdAt)} · ${profile.version.contentHash}`}> · v{profile.version.revision}</span>
                )}
                {profile && !profile.version && <span title="The Broker stores the first version on its next snapshot"> · not versioned yet</span>}
                {profile?.version && profile.snapshotPending && (
                  <span title="The live profile differs from the newest stored version; the Broker stores it on its next snapshot"> · newer changes not yet versioned</span>
                )}
              </p>
            </div>
            {node && (
              <Button variant="secondary" size="sm" leftIcon={Share2} onClick={() => onOpenInMap(node.id)}>
                Open in map
              </Button>
            )}
          </div>
        </div>
        {body}
      </div>

      {/* The drawer loads this one workload's seccomp detail itself
          (GET /seccomp/profiles/{ns}/{kind}/{name}); no cluster-wide list. */}
      {drawerOpen && (
        <SeccompProfileDrawer api={seccompApi} workload={{ ns, kind, name }} summary={null} onClose={() => setDrawerOpen(false)} />
      )}
    </div>
  );
}

export default WorkloadView;
