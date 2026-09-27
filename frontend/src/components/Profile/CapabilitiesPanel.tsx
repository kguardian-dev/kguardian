import { KeyRound } from 'lucide-react';
import type { CapabilityUse, ContainerCapabilities, ProfileCapabilities } from '../../types/profile';
import { capabilityEvidenceText, capabilitySummary, windowText } from '../../utils/capabilities';
import { formatAgo, formatTimestamp } from '../../utils/posture';
import { asUtc } from '../../utils/vulnView';
import { EmptyState } from '../ui/EmptyState';
import { Panel } from './parts';

const chip = 'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-mono';

function UseList({ label, hint, items, tone }: { label: string; hint: string; items: CapabilityUse[]; tone: string }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1">
      <div className="text-[11px] text-tertiary">
        <span className="font-medium text-secondary">{label}</span> · {hint}
      </div>
      <ul className="flex flex-wrap gap-1.5" aria-label={label}>
        {items.map((u) => (
          <li
            key={u.capability}
            className={`${chip} ${tone}`}
            title={`${u.count} check${u.count === 1 ? '' : 's'} · first ${formatTimestamp(asUtc(u.firstSeen))} · last ${formatTimestamp(asUtc(u.lastSeen))}`}
          >
            {u.capability}
            <span className="font-sans text-tertiary tabular-nums">×{u.count}</span>
            <span className="font-sans text-tertiary">· {formatAgo(asUtc(u.lastSeen))}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Recommendation({ c }: { c: ContainerCapabilities }) {
  // A recommendation stands only on sufficient evidence, whatever else the Broker sent.
  const r = c.evidence === 'sufficient' ? c.recommendation : null;
  if (!r) {
    return (
      <p className="text-xs text-secondary" data-testid="cap-no-recommendation">
        No observed-evidence recommendation: the Pod security patch keeps the restricted default (<span className="font-mono">drop: ["ALL"]</span>), not a set built from what this container used. What was observed is listed, but it is not evidence that nothing else is needed.
      </p>
    );
  }
  // Leaving a probed capability out is only safe with allowPrivilegeEscalation: false,
  // whether or not an older Broker says so in `requires`.
  const ape = r.requires?.allowPrivilegeEscalation === false || r.probedOmitted.length > 0;
  return (
    <div className="rounded-control border border-hubble-border bg-hubble-hover/20 px-3 py-2.5 space-y-2 text-xs" data-testid="cap-recommendation">
      <div className="font-medium text-primary">Recommended securityContext.capabilities (not applied)</div>
      <pre className="font-mono text-[11px] text-secondary whitespace-pre-wrap">
        {`capabilities:\n  drop: [${r.drop.map((d) => JSON.stringify(d)).join(', ')}]\n  add: ${r.add.length ? `[${r.add.map((a) => JSON.stringify(a)).join(', ')}]` : '[]'}${ape ? '\nallowPrivilegeEscalation: false' : ''}`}
      </pre>
      {ape && (
        <p className="text-severity-medium" data-testid="cap-requires-ape">
          Requires <span className="font-mono">allowPrivilegeEscalation: false</span>: the add list above is only enough with it, because it leaves out the capabilities below.
        </p>
      )}
      {r.probedOmitted.length > 0 && (
        <ul className="space-y-1" aria-label="Left out (probed only)">
          {r.probedOmitted.map((o) => (
            <li key={o.capability} className="text-secondary">
              <span className="font-mono text-primary">{o.capability}</span> left out: {o.reason}.
            </li>
          ))}
        </ul>
      )}
      {r.probedKept.length > 0 && (
        <p className="text-secondary">
          Kept only because the kernel probed for them: <span className="font-mono text-primary">{r.probedKept.join(', ')}</span>. Remove them only after someone confirms the workload does not need them.
        </p>
      )}
      {c.unusedAdded.length > 0 && (
        <p className="text-secondary" data-testid="cap-unused-added">
          Added today but never used or probed in the window: <span className="font-mono text-primary">{c.unusedAdded.join(', ')}</span>.
        </p>
      )}
    </div>
  );
}

function ContainerRow({ c, windowHours }: { c: ContainerCapabilities; windowHours: number }) {
  const sufficient = c.evidence === 'sufficient';
  return (
    <li className="px-4 py-3 space-y-2.5" data-testid="cap-container" data-evidence={c.evidence}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-sm text-primary">{c.container}</span>
          <span className="text-[11px] text-tertiary">{capabilitySummary(c)}</span>
        </div>
        <span
          className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${sufficient ? 'bg-hubble-border/30 text-secondary border-hubble-border-strong' : 'text-tertiary border-dashed border-hubble-border-strong'}`}
          title={sufficient ? `Every current digest was watched for the whole ${windowText(windowHours)} window` : capabilityEvidenceText(c.reason)}
        >
          {sufficient ? `Evidence: ${windowText(windowHours)} watched` : 'Evidence insufficient'}
        </span>
      </div>
      {!sufficient && <p className="text-[11px] text-tertiary">Why: {capabilityEvidenceText(c.reason)}.</p>}
      {sufficient && c.observedSince && <p className="text-[11px] text-tertiary">Watched since {formatTimestamp(asUtc(c.observedSince))}.</p>}
      <UseList label="Used" hint="checks that succeeded" items={c.used} tone="border-hubble-border-strong text-primary" />
      <UseList label="Probed" hint="the kernel asked whether the process is privileged; some gate real behaviour" items={c.probed} tone="border-dashed border-hubble-border-strong text-secondary" />
      <UseList label="Denied" hint="asked for without holding it" items={c.denied} tone="border-severity-medium/40 text-severity-medium" />
      {c.used.length + c.probed.length + c.denied.length === 0 && <p className="text-[11px] text-tertiary">No capability check observed.</p>}
      <Recommendation c={c} />
    </li>
  );
}

/**
 * The profile's `capabilities` block (contract 2.9): which capabilities
 * each container used, probed or was denied, whether that is enough
 * evidence, and the Broker's recommendation. Never sets posture; a
 * recommendation appears only with sufficient evidence.
 */
export function CapabilitiesPanel({ caps }: { caps: ProfileCapabilities | undefined }) {
  if (!caps) {
    return (
      <Panel icon={KeyRound} title="Capabilities">
        <p className="px-4 py-3 text-xs text-tertiary">This Broker does not report observed capability use (profile contract before P2-7).</p>
      </Panel>
    );
  }
  return (
    <Panel icon={KeyRound} title="Capabilities" hint={`Observed capability checks over ${windowText(caps.windowHours)}; not part of the posture`}>
      {caps.containers.length === 0 ? (
        <EmptyState icon={KeyRound} compact title="No current container" description="Capabilities are reported per current container; none is running now." />
      ) : (
        <ul className="divide-y divide-hubble-border">
          {caps.containers.map((c) => <ContainerRow key={c.container} c={c} windowHours={caps.windowHours} />)}
        </ul>
      )}
    </Panel>
  );
}
