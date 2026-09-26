import { useState } from 'react';
import { ChevronRight, ClipboardCheck, Package, Radar, ShieldCheck, SlidersHorizontal, Lock } from 'lucide-react';
import type { Control, DimensionName, Finding, WorkloadProfile } from '../../types/profile';
import { SEVERITY_BADGE_CLASS, TIER_BADGE_CLASS } from '../../utils/severity';
import { DIMENSION_LABEL, driftNotEvaluatedText, findingDimensionLabel, findingSeverity } from '../../utils/posture';
import { Button } from '../ui/Button';
import { EmptyState } from '../ui/EmptyState';
import { CantTell, CheckMark, Panel } from './parts';
import type { ProfileTab } from '../../utils/profileView';

const TAB_OF: Record<DimensionName, ProfileTab> = {
  network: 'network',
  syscalls: 'syscalls',
  podSecurity: 'podSecurity',
  images: 'images',
  compute: 'overview',
};

const FINDING_RANK: Record<Finding['severity'], number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** The Overview shows at most this many findings (the broker ranks them). */
export const ATTENTION_MAX = 5;

function FindingBadge({ f }: { f: Finding }) {
  if (f.tier) {
    return <span className={`shrink-0 rounded-md border px-1.5 py-px text-[11px] font-mono font-semibold ${TIER_BADGE_CLASS[f.tier]}`}>{f.tier}</span>;
  }
  return (
    <span className={`shrink-0 rounded-md border px-1.5 py-px text-[11px] font-medium ${SEVERITY_BADGE_CLASS[findingSeverity(f.severity)]}`}>
      {f.severity}
    </span>
  );
}

function NeedsAttention({ profile, onOpenTab }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void }) {
  // Top 5 by default; every finding stays reachable through "Show all".
  const [showAll, setShowAll] = useState(false);
  const total = profile.findings.length;
  // The contract does not order findings[]; sort worst first (stable).
  const list = showAll
    ? [...profile.findings].sort((a, b) => FINDING_RANK[b.severity] - FINDING_RANK[a.severity])
    : profile.attention.slice(0, ATTENTION_MAX);
  // Core dimensions with status unknown (contract v1.2).
  const unknown = profile.posture.unknownDimensions;
  // Drift checks the broker could not run (contract v1.7): no item for
  // them is not "no drift".
  const driftGaps = profile.drift?.notEvaluated ?? [];
  return (
    <Panel
      icon={Radar}
      title="Needs attention"
      hint={showAll ? `All ${total} findings, by severity` : `Top ${ATTENTION_MAX} by severity · ${total} finding${total === 1 ? '' : 's'} in total`}
      action={
        total > Math.min(ATTENTION_MAX, profile.attention.length) ? (
          <Button variant="ghost" size="sm" aria-expanded={showAll} onClick={() => setShowAll((v) => !v)}>
            {showAll ? `Show top ${ATTENTION_MAX}` : `Show all ${total}`}
          </Button>
        ) : undefined
      }
    >
      {list.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          compact
          title="No findings"
          description={
            unknown.length > 0
              ? `Nothing flagged in the dimensions with data. ${unknown.length} dimension${unknown.length === 1 ? ' has' : 's have'} no data yet (${unknown.map((d) => DIMENSION_LABEL[d] ?? d).join(', ')}), so this is not a clean bill of health.`
              : driftGaps.length > 0
                ? `Nothing flagged, but ${new Set(driftGaps.map((g) => g.type)).size} drift check${new Set(driftGaps.map((g) => g.type)).size === 1 ? ' was' : 's were'} not evaluated (listed below), so this is not a clean bill of health.`
                : 'Nothing flagged in any dimension.'
          }
        />
      ) : (
        <ul className="divide-y divide-hubble-border" aria-label={showAll ? 'All findings' : 'Top findings'}>
          {list.map((f) => {
            const tab = f.dimension === 'drift' ? 'overview' : (TAB_OF[f.dimension] ?? 'overview');
            return (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => onOpenTab(tab)}
                  disabled={tab === 'overview'}
                  className="w-full flex items-start justify-between gap-3 px-4 py-3 text-left hover:bg-hubble-hover/40 disabled:hover:bg-transparent transition-colors"
                >
                  <span className="min-w-0">
                    <span className="flex items-center gap-2">
                      <FindingBadge f={f} />
                      <span className="text-sm font-medium text-primary">{f.title}</span>
                    </span>
                    <span className="block mt-1 text-xs text-secondary">{f.detail}</span>
                    <span className="block mt-1 text-[11px] text-tertiary">
                      {findingDimensionLabel(f.dimension)}
                      {f.container && <> · container <span className="font-mono">{f.container}</span></>}
                    </span>
                  </span>
                  {tab !== 'overview' && <ChevronRight className="w-4 h-4 mt-0.5 shrink-0 text-tertiary" aria-hidden />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
      {driftGaps.length > 0 && (
        <ul className="px-4 py-2 border-t border-hubble-border text-[11px] text-tertiary" aria-label="Drift checks not evaluated">
          {driftGaps.map((n) => (
            <li key={`${n.type}/${n.container ?? ''}`}>
              Drift check <span className="font-mono">{n.type}</span> not evaluated
              {n.container ? <> for container <span className="font-mono">{n.container}</span></> : null}:{' '}
              {driftNotEvaluatedText(n.reason)}. No drift finding here does not mean no drift.
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

const CONTROL_LABEL: Record<Control['control'], string> = {
  networkPolicy: 'Network policy',
  seccompProfile: 'SeccompProfile',
  imageAdmission: 'Image admission',
};
const CONTROL_TAB: Record<Control['control'], ProfileTab> = {
  networkPolicy: 'network',
  seccompProfile: 'syscalls',
  imageAdmission: 'images',
};

/** Control lifecycle pill. `unknown` and `null` are not "none". */
export function ControlStatePill({ state }: { state: Control['state'] }) {
  const base = 'inline-flex items-center gap-1 shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap';
  switch (state) {
    case 'enforcing':
      return <span className={`${base} bg-state-enforcing/15 text-state-enforcing border-state-enforcing/30`}><Lock className="w-3 h-3" aria-hidden />Enforcing</span>;
    case 'audit':
      return <span className={`${base} bg-state-audit/15 text-state-audit border-state-audit/30`}>Audit</span>;
    case 'none':
      return <span className={`${base} bg-hubble-border/40 text-secondary border-hubble-border`}>None</span>;
    case 'unknown':
      return <span className={`${base} text-tertiary border-dashed border-hubble-border-strong`} title="kguardian cannot see this control's state">Unknown</span>;
    default:
      return <span className={`${base} text-tertiary border-dashed border-hubble-border-strong`} title="This check is not configured">Not configured</span>;
  }
}

function SyncCell({ inSync }: { inSync: boolean | null }) {
  if (inSync === true) return <span className="text-state-enforcing">in sync</span>;
  if (inSync === false) return <span className="text-severity-medium">drifted</span>;
  return <span className="text-tertiary">—</span>;
}

function Controls({ profile, onOpenTab }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void }) {
  return (
    <Panel icon={SlidersHorizontal} title="Controls" hint="kguardian generates these; you apply them">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-[11px] uppercase tracking-wide text-tertiary">
            <tr className="border-b border-hubble-border">
              <th scope="col" className="text-left font-medium px-4 py-2">Control</th>
              <th scope="col" className="text-left font-medium px-3 py-2">State</th>
              <th scope="col" className="text-left font-medium px-3 py-2">Drift</th>
              <th scope="col" className="text-left font-medium px-3 py-2">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-hubble-border">
            {profile.controls.map((c) => (
              <tr key={c.control}>
                <td className="px-4 py-2.5 whitespace-nowrap">
                  <button type="button" onClick={() => onOpenTab(CONTROL_TAB[c.control])} className="text-primary hover:underline">
                    {CONTROL_LABEL[c.control] ?? c.control}
                  </button>
                </td>
                <td className="px-3 py-2.5"><ControlStatePill state={c.state} /></td>
                <td className="px-3 py-2.5 text-xs whitespace-nowrap"><SyncCell inSync={c.inSync} /></td>
                <td className="px-3 py-2.5 text-xs text-secondary min-w-48">{c.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function ImageSummary({ profile, onOpenTab }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void }) {
  const img = profile.dimensions.images;
  const running = img.containers.flatMap((c) => c.running);
  const mixed = img.containers.filter((c) => c.mixedDigests).map((c) => c.name);
  const refs = [...new Set(running.map((r) => r.imageRef))];
  return (
    <Panel
      icon={Package}
      title="Image"
      hint={img.containers.length ? `${img.containers.length} container${img.containers.length === 1 ? '' : 's'} · ${running.length} running digest${running.length === 1 ? '' : 's'}` : undefined}
      action={
        <button type="button" onClick={() => onOpenTab('images')} className="inline-flex items-center gap-0.5 text-xs text-secondary hover:text-primary">
          Image &amp; packages <ChevronRight className="w-3.5 h-3.5" aria-hidden />
        </button>
      }
    >
      <div className="px-4 py-3 space-y-2 text-xs">
        {img.containers.length === 0 ? (
          <p className="text-tertiary">No image inventory for this workload yet.</p>
        ) : (
          <>
            <ul className="space-y-1">
              {refs.map((r) => (
                <li key={r} className="font-mono text-primary [overflow-wrap:anywhere]">{r}</li>
              ))}
              {refs.length === 0 && <li className="text-tertiary">No container is running now.</li>}
            </ul>
            {mixed.length > 0 && (
              <p className="text-severity-medium">Mixed digests in {mixed.join(', ')}: a rollout in progress, or nodes resolved the tag differently.</p>
            )}
          </>
        )}
        <p className="text-tertiary">
          {img.vulnerabilities === null ? 'Vulnerability data not configured.' : 'Vulnerability data available on the Image & packages tab.'}{' '}
          {img.supplyChain === null && 'Signature checks not configured.'}
        </p>
      </div>
    </Panel>
  );
}

function Readiness({ profile }: { profile: WorkloadProfile }) {
  return (
    <Panel icon={ClipboardCheck} title="Profile readiness" hint="Before you export and enforce">
      <ul className="px-4 py-2">
        {profile.readiness.map((r) => (
          <li key={r.id} data-ok={String(r.ok)} className="flex items-start gap-2 py-1.5 text-xs">
            <CheckMark ok={r.ok} />
            <span className={`min-w-0 ${r.ok === null ? 'text-tertiary' : 'text-primary'}`}>
              {r.ok === null && <><CantTell />{' '}</>}
              {r.message}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Exposure({ profile, onOpenTab }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void }) {
  const e = profile.exposure;
  const none = e.ingressPeers === null && e.egressPeers === null;
  const since = profile.dimensions.network.coverage.observedSince;
  return (
    <Panel
      icon={Radar}
      title="Exposure"
      hint="From observed flows; absence is not proof of unreachability"
      label="Exposure"
      action={
        <button type="button" onClick={() => onOpenTab('network')} className="inline-flex items-center gap-0.5 text-xs text-secondary hover:text-primary">
          Network <ChevronRight className="w-3.5 h-3.5" aria-hidden />
        </button>
      }
    >
      {none ? (
        <p className="px-4 py-3 text-xs text-tertiary">No flows observed for this workload, so exposure is unknown.</p>
      ) : (
        <div className="px-4 py-2 text-xs">
          <dl className="divide-y divide-hubble-border">
            <ExposureRow label="Ingress" peers={e.ingressPeers} external={e.ingressExternal} />
            <ExposureRow label="Egress" peers={e.egressPeers} external={e.egressExternal} />
          </dl>
          {since && <p className="pt-2 text-[11px] text-tertiary">Observed since {since.slice(0, 10)}</p>}
        </div>
      )}
    </Panel>
  );
}

function ExposureRow({ label, peers, external }: { label: string; peers: number | null; external: number | null }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5">
      <dt className="text-tertiary">{label}</dt>
      <dd className="font-mono tabular-nums text-primary">
        {peers === null ? '—' : `${peers} peer${peers === 1 ? '' : 's'}`}
        {external !== null && external > 0 && <span className="ml-2 text-severity-high">{external} external</span>}
      </dd>
    </div>
  );
}

export function OverviewTab({ profile, onOpenTab }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void }) {
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <div className="space-y-4 min-w-0">
        <NeedsAttention profile={profile} onOpenTab={onOpenTab} />
        <Controls profile={profile} onOpenTab={onOpenTab} />
        <ImageSummary profile={profile} onOpenTab={onOpenTab} />
      </div>
      <div className="space-y-4 min-w-0">
        <Exposure profile={profile} onOpenTab={onOpenTab} />
        <Readiness profile={profile} />
      </div>
    </div>
  );
}
