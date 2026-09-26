import type { ReactNode } from 'react';
import type { ProfileDiff } from '../../types/profile';
import { DIMENSION_LABEL, formatTimestamp } from '../../utils/posture';
import { diffLines, type LineKind } from '../../utils/profileView';

const MARK: Record<LineKind, { sign: string; sr: string; cls: string }> = {
  add: { sign: '+', sr: 'Added: ', cls: 'text-state-enforcing bg-state-enforcing/10' },
  remove: { sign: '−', sr: 'Removed: ', cls: 'text-severity-critical bg-severity-critical/10' },
  change: { sign: '~', sr: 'Changed: ', cls: 'text-state-audit bg-state-audit/10' },
};

const ORDER = ['podSecurity', 'images', 'syscalls', 'network'] as const;

/**
 * Per-dimension diff between two stored revisions: added (+), removed (−)
 * and changed (~) lines, each also spelled out for screen readers. Unchanged
 * dimensions collapse to one line so the change is what reads first.
 */
export function DiffViewer({ diff }: { diff: ProfileDiff }) {
  const lines = diffLines(diff);
  const header: ReactNode = diff.from ? (
    <>
      <span className="font-mono">v{diff.from.revision}</span> ({formatTimestamp(diff.from.createdAt)}) → <span className="font-mono">v{diff.to.revision}</span> ({formatTimestamp(diff.to.createdAt)})
    </>
  ) : diff.fromTrimmed ? (
    <>
      Earlier versions were trimmed by retention, so <span className="font-mono">v{diff.to.revision}</span> ({formatTimestamp(diff.to.createdAt)}) has nothing to compare with: everything shows as added
    </>
  ) : (
    <>
      First revision <span className="font-mono">v{diff.to.revision}</span> ({formatTimestamp(diff.to.createdAt)}): everything shows as added
    </>
  );
  return (
    <div className="space-y-3" data-testid="diff-viewer">
      <p className="text-xs text-secondary">{header}</p>
      {!diff.changed ? (
        <p className="text-xs text-tertiary">No policy-relevant change between these revisions.</p>
      ) : (
        ORDER.map((dim) => {
          const l = lines[dim];
          const changed = diff.dimensions[dim].changed;
          return (
            <section key={dim} aria-label={`${DIMENSION_LABEL[dim]} changes`} className="rounded-control border border-hubble-border overflow-hidden">
              <h4 className="flex items-center justify-between px-3 py-1.5 text-xs font-medium text-primary bg-hubble-hover/30 border-b border-hubble-border">
                {DIMENSION_LABEL[dim]}
                <span className="text-[11px] font-normal text-tertiary">{changed ? `${l.length} change${l.length === 1 ? '' : 's'}` : 'no change'}</span>
              </h4>
              {changed && l.length > 0 && (
                <ul className="font-mono text-xs">
                  {l.map((x, i) => (
                    <li key={i} data-kind={x.kind} className={`flex gap-2 px-3 py-0.5 ${MARK[x.kind].cls}`}>
                      <span aria-hidden className="w-3 shrink-0 select-none">{MARK[x.kind].sign}</span>
                      <span className="min-w-0 [overflow-wrap:anywhere]">
                        <span className="sr-only">{MARK[x.kind].sr}</span>
                        {x.text}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          );
        })
      )}
    </div>
  );
}
