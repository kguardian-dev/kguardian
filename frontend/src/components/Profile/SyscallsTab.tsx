import { Lock, Cpu } from 'lucide-react';
import type { SyscallsDimension } from '../../types/profile';
import { asStatus, formatAgo, formatTimestamp } from '../../utils/posture';
import { Button } from '../ui/Button';
import { EmptyState } from '../ui/EmptyState';
import { Fact, Panel, Reasons, ScoredStatus } from './parts';
import { ControlStatePill } from './OverviewTab';

export function SyscallsTab({ dim, onOpenSeccomp }: { dim: SyscallsDimension; onOpenSeccomp?: () => void }) {
  const status = asStatus(dim.status);
  const action = onOpenSeccomp && (
    <Button variant="secondary" size="sm" leftIcon={Lock} onClick={onOpenSeccomp} title="Review and export the SeccompProfile CR">
      Open seccomp profile
    </Button>
  );
  if (!dim.observed) {
    return (
      <Panel icon={Cpu} title="Syscalls" action={<ScoredStatus status={status} score={dim.score} />}>
        <EmptyState
          icon={Cpu}
          compact
          title="No syscalls reported yet"
          description="A profile appears once the Controller has reported syscalls for this workload and it has an owning controller (Deployment, StatefulSet, DaemonSet, CronJob)."
        />
      </Panel>
    );
  }
  const cr = dim.cr;
  return (
    <div className="space-y-4">
      <Panel icon={Cpu} title="Observed syscalls" hint={dim.coverage.note || undefined} action={<ScoredStatus status={status} score={dim.score} />}>
        <div className="px-4 py-3 space-y-3">
          <Reasons reasons={dim.reasons} />
          <dl className="divide-y divide-hubble-border">
            <Fact label="Syscalls"><span className="font-mono tabular-nums">{dim.observed.syscallCount}</span></Fact>
            <Fact label="Architectures"><span className="font-mono">{dim.observed.architectures.join(', ')}</span></Fact>
            <Fact label="Capture">
              {dim.capture ? (
                <span className={dim.capture.complete ? '' : 'text-severity-medium'}>
                  <span className="font-mono">{dim.capture.level}</span>
                  {dim.capture.complete ? ' · complete' : ` · ${dim.capture.incompletePods} pod${dim.capture.incompletePods === 1 ? '' : 's'} below full`}
                </span>
              ) : (
                <span className="text-tertiary">unknown</span>
              )}
            </Fact>
            <Fact label="Updated"><span title={formatTimestamp(dim.observed.updatedAt)}>{formatAgo(dim.observed.updatedAt)}</span></Fact>
            <Fact label="Denials">
              {dim.denials === null ? (
                <span className="text-tertiary" title="The Broker cannot tell 'nothing denied' from 'nothing capturing denials'">can&apos;t tell</span>
              ) : dim.denials.total === 0 ? (
                <span className="font-mono">0</span>
              ) : (
                <span className="text-severity-high font-mono">
                  {dim.denials.total} ({dim.denials.syscalls.join(', ')})
                </span>
              )}
            </Fact>
          </dl>
          {dim.capture && !dim.capture.complete && (
            <p className="text-xs text-severity-medium">Partial capture: an allow-list built from this set may block syscalls the app needs. Only full capture yields a complete profile.</p>
          )}
        </div>
      </Panel>

      <Panel icon={Lock} title="SeccompProfile CR" hint="kguardian never applies it: export, commit, apply" action={action}>
        {cr ? (
          <div className="px-4 py-3 space-y-3">
            <dl className="divide-y divide-hubble-border">
              <Fact label="Name"><span className="font-mono">{cr.name}</span></Fact>
              <Fact label="Mode"><ControlStatePill state={cr.mode === 'enforce' ? 'enforcing' : 'audit'} /></Fact>
              <Fact label="defaultAction"><span className="font-mono">{cr.defaultAction}</span></Fact>
              <Fact label="Syscalls in CR"><span className="font-mono tabular-nums">{cr.syscallCount}</span></Fact>
              <Fact label="Nodes">
                <span className="font-mono tabular-nums">{cr.distribution.ready}/{cr.distribution.total}</span> <span className="text-tertiary">{cr.distribution.state}</span>
              </Fact>
              <Fact label="Drift">
                {cr.inSync ? <span className="text-state-enforcing">in sync</span> : <span className="text-severity-medium">{cr.missing.length} missing · {cr.extra.length} extra</span>}
              </Fact>
            </dl>
            {!cr.inSync && (
              <div className="text-xs space-y-1">
                {cr.missing.length > 0 && (
                  <p>
                    <span className="text-tertiary">Observed, not in the CR (blocked when enforcing): </span>
                    <span className="font-mono text-severity-medium">{cr.missing.join(', ')}</span>
                  </p>
                )}
                {cr.extra.length > 0 && (
                  <p>
                    <span className="text-tertiary">In the CR, not observed: </span>
                    <span className="font-mono text-secondary">{cr.extra.join(', ')}</span>
                  </p>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="px-4 py-3 text-xs text-tertiary">No SeccompProfile CR references this workload. Export the observed profile and apply it in audit mode first.</p>
        )}
      </Panel>
    </div>
  );
}
