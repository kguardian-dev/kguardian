import { Cpu } from 'lucide-react';
import { useSeccompProfileDetail } from '../../hooks/useSeccompProfiles';
import type { SeccompApi } from '../../services/seccompApi';
import { syscallsDimensionFromSeccomp } from '../../utils/workloads';
import { EmptyState } from '../ui/EmptyState';
import { Panel, SectionError, SectionSkeleton, StatusPill } from './parts';
import { SyscallsTab } from './SyscallsTab';

/**
 * The Syscalls tab when the workload profile read failed. The seccomp
 * endpoint answers on its own (capture, CR, drift, export), so the tab and
 * the drawer still work; posture and denials stay unknown.
 */
export function SyscallsFallbackTab({ ns, kind, name, api, onOpenSeccomp }: { ns: string; kind: string; name: string; api: SeccompApi; onOpenSeccomp: () => void }) {
  const { detail, loading, error, errorStatus, reload } = useSeccompProfileDetail(api, ns, kind, name);
  if (detail) return <SyscallsTab dim={syscallsDimensionFromSeccomp(detail)} onOpenSeccomp={onOpenSeccomp} />;
  const action = <StatusPill status="unknown" />;
  if (loading || error === null) {
    return (
      <Panel icon={Cpu} title="Syscalls" action={action}>
        <SectionSkeleton rows={3} />
      </Panel>
    );
  }
  if (errorStatus === 404) {
    return (
      <Panel icon={Cpu} title="Syscalls" action={action}>
        <EmptyState
          icon={Cpu}
          compact
          title="No syscalls reported yet"
          description="The Broker has no observed syscalls for this workload. A profile appears once the Controller has reported syscalls for it and it has an owning controller (Deployment, StatefulSet, DaemonSet, CronJob)."
        />
      </Panel>
    );
  }
  return (
    <Panel icon={Cpu} title="Syscalls" action={action}>
      <SectionError message={`Could not read the seccomp profile either: ${error}`} onRetry={() => void reload()} />
    </Panel>
  );
}
