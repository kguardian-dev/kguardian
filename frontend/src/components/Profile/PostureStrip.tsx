import type { DimensionName, WorkloadProfile } from '../../types/profile';
import { asStatus, DIMENSION_LABEL, pssLevelText, STATUS_LABEL } from '../../utils/posture';
import { StatusPill } from './parts';

import type { ProfileTab } from '../../utils/profileView';

const ORDER: DimensionName[] = ['network', 'syscalls', 'podSecurity', 'images', 'compute'];

/** The tab a dimension pill opens; compute has none (informational only). */
const TAB_OF: Partial<Record<DimensionName, ProfileTab>> = {
  network: 'network',
  syscalls: 'syscalls',
  podSecurity: 'podSecurity',
  images: 'images',
};

function detailOf(p: WorkloadProfile, d: DimensionName): string | null {
  const dim = p.dimensions[d];
  if (asStatus(dim.status) === 'unknown') return null;
  if (d === 'podSecurity') return pssLevelText(p.dimensions.podSecurity.level, p.dimensions.podSecurity.levelConfidence);
  if (d === 'syscalls') {
    const cr = p.dimensions.syscalls.cr;
    return cr ? (cr.mode === 'enforce' ? 'Enforcing' : 'Audit') : 'No CR';
  }
  if (d === 'network') return p.dimensions.network.policy.audit ? 'Audit' : null;
  if (d === 'images') {
    const running = p.dimensions.images.containers.reduce((n, c) => n + c.running.length, 0);
    return `${running} running digest${running === 1 ? '' : 's'}`;
  }
  return null;
}

/**
 * One pill per dimension. A dimension with no data shows "No data" — it is
 * listed, not hidden, and never drawn as clean. The rollup beside it only
 * shows a score together with the coverage it was computed from.
 */
export function PostureStrip({ profile, onOpenTab }: { profile: WorkloadProfile; onOpenTab: (t: ProfileTab) => void }) {
  const p = profile.posture;
  const overall = asStatus(p.status);
  const coveragePct = Math.round(p.coverage * 100);
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-tertiary">Posture</span>
        <StatusPill
          status={overall}
          title={
            overall === 'unknown'
              ? 'No dimension has data yet'
              : `Worst status across the dimensions with data. Unknown dimensions are excluded, not counted as clean.`
          }
        >
          {STATUS_LABEL[overall]}
          {p.score !== null && <span className="font-mono tabular-nums">· {p.score}</span>}
          {p.grade && <span className="font-mono">· {p.grade}</span>}
        </StatusPill>
        <span
          className="font-mono tabular-nums text-tertiary"
          title="Share of the scoring weight whose dimension has data. The score covers only that share."
        >
          coverage {coveragePct}%
        </span>
        {p.unknownDimensions.length > 0 && (
          <span className="text-tertiary" title="Excluded from the score: no data yet, or data that is not scored (e.g. images without a vulnerability source). Never counted as 0 or 100.">
            · not scored: {p.unknownDimensions.map((d) => DIMENSION_LABEL[d] ?? d).join(', ').toLowerCase()}
          </span>
        )}
      </div>
      <ul aria-label="Posture by dimension" className="flex flex-wrap gap-2">
        {ORDER.map((d) => {
          const dim = profile.dimensions[d];
          const status = asStatus(dim.status);
          const detail = detailOf(profile, d);
          const tab = TAB_OF[d];
          const why = dim.reasons.map((r) => r.message).join('\n');
          const body = (
            <>
              <span className="text-secondary">{DIMENSION_LABEL[d]}</span>
              <StatusPill status={status}>
                {STATUS_LABEL[status]}
                {dim.score !== null && <span className="font-mono tabular-nums">· {dim.score}</span>}
              </StatusPill>
              {detail && <span className="text-tertiary">{detail}</span>}
            </>
          );
          const cls = 'inline-flex items-center gap-1.5 rounded-control border border-hubble-border bg-hubble-card px-2 py-1 text-xs';
          return (
            <li key={d} data-dimension={d}>
              {tab ? (
                <button type="button" onClick={() => onOpenTab(tab)} title={why || undefined} className={`${cls} hover:border-hubble-border-strong hover:bg-hubble-hover/40 transition-colors`}>
                  {body}
                </button>
              ) : (
                <span className={cls} title={why ? `${why}\nInformational: not scored.` : 'Informational: not scored.'}>
                  {body}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
