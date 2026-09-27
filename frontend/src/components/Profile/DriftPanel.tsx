import { GitCompare } from 'lucide-react';
import type { DriftItem, ProfileDrift } from '../../types/profile';
import { driftGapsOf, findingSeverity, formatAgo, formatTimestamp, shortDigest } from '../../utils/posture';
import { SEVERITY_BADGE_CLASS } from '../../utils/severity';
import { asUtc } from '../../utils/vulnView';
import { Panel } from './parts';

const DRIFT_LABEL: Record<string, string> = {
  tagMoved: 'Tag moved',
  imageChangedSinceExport: 'Image changed since export',
  securityContextRegression: 'securityContext regression',
  unshippedExecutable: 'Ran a file the image did not ship',
};

const ORIGIN_TEXT: Record<string, string> = {
  writableLayer: 'writable layer (written after start)',
  memfd: 'memfd (never on disk)',
  deleted: 'deleted while running',
};

function Detail({ item }: { item: DriftItem }) {
  const d = item.detail;
  if (!d) return null;
  switch (item.type) {
    case 'unshippedExecutable':
      return (
        <div className="space-y-1.5">
          <ul className="space-y-1" aria-label="Unshipped files">
            {(d.files ?? []).map((f) => (
              <li key={`${f.digest}-${f.path}`} className="text-[11px]">
                <span className="font-mono text-primary [overflow-wrap:anywhere]">{f.pathComplete ? f.path : `…${f.path}`}</span>
                <span className="text-tertiary">
                  {' '}· {f.kind === 'lib' ? 'loaded' : 'executed'} from {ORIGIN_TEXT[f.origin] ?? f.origin} · last {formatAgo(asUtc(f.lastSeen))}
                  {!f.pathComplete && ' · path cut short by the kernel (a suffix)'}
                </span>
              </li>
            ))}
          </ul>
          {d.truncated && (
            <p className="text-[11px] text-tertiary">
              {d.filesTotal != null && d.filesTotal > (d.files?.length ?? 0) ? `${d.filesTotal - (d.files?.length ?? 0)} more not listed (${d.filesTotal} in total).` : 'More files ran than are listed.'}
            </p>
          )}
        </div>
      );
    case 'tagMoved':
      return (
        <p className="text-[11px] text-secondary">
          <span className="font-mono">{d.imageRef}</span> resolved to {d.digests?.length ?? 0} digests ({(d.digests ?? []).map(shortDigest).join(', ')}){d.since && <>, since {formatTimestamp(asUtc(d.since))}</>}.
        </p>
      );
    case 'imageChangedSinceExport':
      return (
        <p className="text-[11px] text-secondary">
          {d.containerInExport === false ? 'New container since the export.' : `Exported ${(d.exportedDigests ?? []).map(shortDigest).join(', ') || 'no digest'}; now also ${(d.newDigests ?? []).map(shortDigest).join(', ')}.`}
        </p>
      );
    case 'securityContextRegression':
      return (
        <p className="text-[11px] text-secondary">
          {d.levelFrom && d.levelTo ? `${d.levelFrom} → ${d.levelTo}. ` : ''}Newly failing: <span className="font-mono">{(d.newlyFailing ?? []).join(', ')}</span>.
        </p>
      );
    default:
      return null;
  }
}

/**
 * The profile's drift block (contract 2.8): each item with its detail, the
 * checks that ran, and the ones that could not run and why. Drift never
 * sets posture; a check that did not run is "not evaluated", never "no drift".
 */
export function DriftPanel({ drift }: { drift: ProfileDrift | undefined }) {
  if (!drift) return null;
  const gaps = driftGapsOf(drift);
  const evaluated = drift.evaluated ?? [];
  return (
    <Panel icon={GitCompare} title="Drift" hint="From the accepted baseline and the runtime inventory; never sets posture">
      <div className="px-4 py-3 space-y-3 text-xs">
        {drift.items.length === 0 ? (
          <p className="text-secondary" data-testid="drift-none">
            {evaluated.length ? `No drift found by the checks that ran (${evaluated.map((t) => DRIFT_LABEL[t] ?? t).join(', ')}).` : 'No check ran.'}
            {gaps.length > 0 && ' Some checks did not run: not evaluated is not "no drift".'}
          </p>
        ) : (
          <ul className="space-y-3" aria-label="Drift items">
            {drift.items.map((it) => (
              <li key={it.findingId} data-testid="drift-item" data-type={it.type} className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-md border px-1.5 py-px text-[11px] font-medium ${SEVERITY_BADGE_CLASS[findingSeverity(it.severity)]}`}>{it.severity}</span>
                  <span className="font-medium text-primary">{DRIFT_LABEL[it.type] ?? it.type}</span>
                  {it.container && <span className="text-tertiary">container <span className="font-mono">{it.container}</span></span>}
                </div>
                <Detail item={it} />
              </li>
            ))}
          </ul>
        )}
        {gaps.length > 0 && (
          <p className="border-t border-hubble-border pt-2 text-[11px] text-tertiary" data-testid="drift-gaps-pointer">
            {gaps.length} check{gaps.length === 1 ? '' : 's'} not evaluated ({[...new Set(gaps.map((g) => DRIFT_LABEL[g.type] ?? g.type))].join(', ')}): why is listed under Needs attention.
          </p>
        )}
      </div>
    </Panel>
  );
}
