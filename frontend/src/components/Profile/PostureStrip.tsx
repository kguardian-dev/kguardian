import type { DimensionName, WorkloadProfile } from '../../types/profile';
import { asStatus, DIMENSION_LABEL, pssLevelText } from '../../utils/posture';
import type { ProfileTab } from '../../utils/profileView';
import { StatusPill } from './parts';

const ORDER: DimensionName[] = ['network', 'syscalls', 'podSecurity', 'images', 'compute'];

/** The tab a dimension pill opens; compute has none (informational only). */
const TAB_OF: Partial<Record<DimensionName, ProfileTab>> = {
  network: 'network',
  syscalls: 'syscalls',
  podSecurity: 'podSecurity',
  images: 'images',
};

/** A short fact next to a dimension's status; never a score. */
function detailOf(p: WorkloadProfile, d: DimensionName): string | null {
  const dims = p.dimensions;
  if (d === 'podSecurity') {
    // The level is useful even while the status is unknown (upper bound).
    return dims.podSecurity.level ? pssLevelText(dims.podSecurity.level, dims.podSecurity.levelConfidence) : null;
  }
  if (d === 'images') {
    // Inventory is known even while the status is unknown (no vulnerability data).
    const running = dims.images.containers.reduce((n, c) => n + c.running.length, 0);
    return dims.images.containers.length ? `${running} running digest${running === 1 ? '' : 's'}` : null;
  }
  if (asStatus(dims[d].status) === 'unknown') return null;
  if (d === 'syscalls') {
    const cr = dims.syscalls.cr;
    return cr ? (cr.mode === 'enforce' ? 'Enforcing' : 'Audit') : 'No CR';
  }
  if (d === 'network') return dims.network.policy.audit ? 'Audit' : null;
  return null;
}

/**
 * One pill per dimension plus the rollup: status, how much of the profile
 * that status covers, and the reasons behind it. No numeric score (contract
 * v1.2). A dimension with no data shows "No data": listed, not hidden, and
 * never drawn as clean.
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
          title={overall === 'unknown' ? 'No dimension has data yet' : 'Worst status across the dimensions with data. Dimensions with no data are excluded, not counted as clean.'}
        />
        <span className="font-mono tabular-nums text-tertiary" title="Share of the four core dimensions (network, syscalls, pod security, images) with a known status">
          coverage {coveragePct}%
        </span>
        {p.unknownDimensions.length > 0 && (
          <span className="text-tertiary">· no data for {p.unknownDimensions.map((d) => DIMENSION_LABEL[d] ?? d).join(', ').toLowerCase()}</span>
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
              <StatusPill status={status} />
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
                <span className={cls} title={why ? `${why}\nInformational: not part of the rollup.` : 'Informational: not part of the rollup.'}>
                  {body}
                </span>
              )}
            </li>
          );
        })}
      </ul>
      {p.reasons.length > 0 && (
        <ul aria-label="Why this posture" className="space-y-0.5 text-xs">
          {p.reasons.map((r) => (
            <li key={`${r.dimension}-${r.message}`} className="flex items-baseline gap-1.5">
              <StatusPill status={asStatus(r.status)}>{DIMENSION_LABEL[r.dimension] ?? r.dimension}</StatusPill>
              <span className="text-secondary">{r.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
