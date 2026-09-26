import { ArrowDownLeft, ArrowUpRight, Network, ShieldAlert } from 'lucide-react';
import type { NetworkDimension } from '../../types/profile';
import { peerLabel } from '../../utils/profileView';
import { asStatus, formatAgo, formatTimestamp } from '../../utils/posture';
import { EmptyState } from '../ui/EmptyState';
import { Fact, Panel, Reasons, ScoredStatus } from './parts';

export function NetworkTab({ dim }: { dim: NetworkDimension }) {
  const status = asStatus(dim.status);
  const audit = dim.policy.audit;
  return (
    <div className="space-y-4">
      <Panel icon={ShieldAlert} title="Policy" hint="AuditNetworkPolicy verdicts in the last 24h. Applied NetworkPolicies are not visible to the Broker yet." action={<ScoredStatus status={status} score={dim.score} />}>
        <div className="px-4 py-3 space-y-3">
          <Reasons reasons={dim.reasons} />
          {audit ? (
            <dl className="divide-y divide-hubble-border">
              <Fact label="Audit policies">
                <span className="font-mono">{audit.policies.map((p) => `${p.namespace}/${p.name}`).join(', ')}</span>
              </Fact>
              <Fact label={`Allow (${audit.windowHours}h)`}><span className="font-mono tabular-nums">{audit.allow}</span></Fact>
              <Fact label={`Would deny (${audit.windowHours}h)`}>
                <span className={`font-mono tabular-nums ${audit.wouldDeny > 0 ? 'text-severity-high' : ''}`}>{audit.wouldDeny}</span>
              </Fact>
              <Fact label="Last verdict"><span title={formatTimestamp(audit.lastVerdictAt)}>{formatAgo(audit.lastVerdictAt)}</span></Fact>
            </dl>
          ) : (
            <p className="text-xs text-tertiary">No audit policy covers this workload, so its network posture is unknown. Flows are still summarised below.</p>
          )}
        </div>
      </Panel>

      <Panel icon={Network} title="Observed peers" hint={dim.coverage.note || undefined}>
        {dim.peers.length === 0 ? (
          <EmptyState icon={Network} compact title="No flows observed" description="kguardian has not recorded traffic for this workload's pods. Absence of flows is not proof it is unreachable." />
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-hubble-border border-b border-hubble-border">
              {(['ingress', 'egress'] as const).map((dir) => {
                const s = dim.summary[dir];
                return (
                  <div key={dir} className="bg-hubble-card px-4 py-2.5 text-xs">
                    <div className="text-[11px] uppercase tracking-wide text-tertiary">{dir}</div>
                    <div className="mt-0.5 font-mono tabular-nums text-primary">
                      {s.peers} peer{s.peers === 1 ? '' : 's'}
                      {s.external > 0 && <span className="ml-2 text-severity-high">{s.external} external</span>}
                    </div>
                    <div className="mt-0.5 font-mono text-tertiary [overflow-wrap:anywhere]">{s.ports.join(' ') || '—'}</div>
                  </div>
                );
              })}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-[11px] uppercase tracking-wide text-tertiary">
                  <tr className="border-b border-hubble-border">
                    <th scope="col" className="text-left font-medium px-4 py-2">Direction</th>
                    <th scope="col" className="text-left font-medium px-3 py-2">Peer</th>
                    <th scope="col" className="text-left font-medium px-3 py-2">Port</th>
                    <th scope="col" className="text-right font-medium px-3 py-2">Flows</th>
                    <th scope="col" className="text-left font-medium px-3 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hubble-border">
                  {dim.peers.map((p, i) => {
                    const l = peerLabel(p.peer);
                    return (
                      <tr key={`${p.direction}-${p.protocol}-${p.port}-${l.primary}-${i}`}>
                        <td className="px-4 py-2 text-xs text-secondary whitespace-nowrap">
                          <span className="inline-flex items-center gap-1">
                            {p.direction === 'ingress' ? <ArrowDownLeft className="w-3.5 h-3.5" aria-hidden /> : <ArrowUpRight className="w-3.5 h-3.5" aria-hidden />}
                            {p.direction}
                          </span>
                        </td>
                        <td className="px-3 py-2 min-w-0">
                          <div className={`font-mono text-xs [overflow-wrap:anywhere] ${p.peer.kind === 'external' ? 'text-severity-high' : 'text-primary'}`}>{l.primary}</div>
                          <div className="text-[11px] text-tertiary">{l.secondary}</div>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">{p.protocol}/{p.port ?? '?'}</td>
                        <td className="px-3 py-2 text-right font-mono text-xs tabular-nums text-secondary">{p.flows}</td>
                        <td className="px-3 py-2 text-xs text-secondary whitespace-nowrap" title={formatTimestamp(p.lastSeen)}>{formatAgo(p.lastSeen)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {dim.truncated && <p className="px-4 py-2 text-[11px] text-tertiary border-t border-hubble-border">Showing the first {dim.peers.length} peers; more exist.</p>}
          </>
        )}
      </Panel>
    </div>
  );
}
