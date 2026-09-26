import { GitCompareArrows, History } from 'lucide-react';
import { useProfileDiff, useProfileVersions } from '../../hooks/useWorkloadProfile';
import { errorKind, errorMessage, type ProfileApi } from '../../services/profileApi';
import { asStatus, DIMENSION_LABEL, formatAgo, formatTimestamp } from '../../utils/posture';
import { Button } from '../ui/Button';
import { EmptyState } from '../ui/EmptyState';
import { DiffViewer } from './DiffViewer';
import { Panel, ScoredStatus, SectionError, SectionSkeleton } from './parts';

interface VersionsTabProps {
  ns: string;
  kind: string;
  name: string;
  refreshTick?: number;
  /** Live profile differs from the newest stored version. */
  snapshotPending: boolean;
  /** Selected revisions (from the URL); undefined = the broker's default. */
  from?: number;
  to?: number;
  onSelect: (from: number | undefined, to: number | undefined) => void;
  api?: ProfileApi;
}

/**
 * Stored, immutable profile versions (newest first) and the diff between
 * two of them. The selection lives in the URL so a diff is shareable.
 */
export function VersionsTab({ ns, kind, name, refreshTick, snapshotPending, from, to, onSelect, api }: VersionsTabProps) {
  const versions = useProfileVersions(ns, kind, name, refreshTick, api);
  const items = versions.data?.items ?? [];
  const hasVersions = items.length > 0;
  const diff = useProfileDiff(ns, kind, name, from, to, hasVersions, api);
  const selectedTo = to ?? items[0]?.revision;
  const selectedFrom = from ?? (selectedTo !== undefined && selectedTo > 1 ? selectedTo - 1 : undefined);

  const listBody = versions.loading && !versions.data ? (
    <SectionSkeleton />
  ) : versions.error && !versions.data ? (
    <SectionError message={errorMessage(versions.error)} onRetry={() => void versions.reload()} />
  ) : !hasVersions ? (
    <EmptyState
      icon={History}
      compact
      title="No stored versions yet"
      description="The Broker stores a version when it first snapshots this workload (every few minutes), and a new one whenever the policy-relevant profile changes."
    />
  ) : (
    <>
      <ul className="divide-y divide-hubble-border">
        {items.map((v) => {
          const selected = v.revision === selectedTo;
          return (
            <li key={v.revision}>
              <button
                type="button"
                aria-pressed={selected}
                onClick={() => onSelect(undefined, v.revision)}
                className={`w-full flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-left transition-colors ${selected ? 'bg-hubble-accent/10' : 'hover:bg-hubble-hover/40'}`}
              >
                <span className="min-w-0">
                  <span className="font-mono text-sm text-primary">v{v.revision}</span>
                  <span className="ml-2 text-xs text-tertiary" title={formatTimestamp(v.createdAt)}>{formatAgo(v.createdAt)}</span>
                  <span className="block mt-0.5 text-[11px] text-tertiary">
                    {v.changedDimensions === null
                      ? 'changes unknown (the previous version was trimmed)'
                      : v.changedDimensions.length
                        ? `changed: ${v.changedDimensions.map((d) => DIMENSION_LABEL[d] ?? d).join(', ')}`
                        : 'no dimension changed'}
                  </span>
                </span>
                <ScoredStatus status={asStatus(v.posture.status)} score={v.posture.score} />
              </button>
            </li>
          );
        })}
      </ul>
      {versions.data?.nextBefore != null && (
        <div className="px-4 py-2 border-t border-hubble-border">
          <Button variant="ghost" size="sm" onClick={() => void versions.loadMore()} disabled={versions.loadingMore}>
            {versions.loadingMore ? 'Loading…' : 'Load older versions'}
          </Button>
        </div>
      )}
    </>
  );

  return (
    <div className="grid gap-4 lg:grid-cols-[18rem_minmax(0,1fr)]">
      <Panel icon={History} title="Versions" hint={snapshotPending ? 'The live profile has changed since the newest version; it is stored on the next snapshot.' : 'Newest first'}>
        {listBody}
      </Panel>
      <Panel
        icon={GitCompareArrows}
        title="Diff"
        hint="Policy-relevant changes only: timestamps, counts and scores are not versioned"
        action={
          hasVersions ? (
            <div className="flex items-center gap-2 text-xs">
              <label className="flex items-center gap-1 text-tertiary">
                From
                <select
                  value={selectedFrom ?? ''}
                  onChange={(e) => onSelect(e.target.value ? Number(e.target.value) : undefined, selectedTo)}
                  className="h-7 rounded-control border border-hubble-border bg-hubble-darker px-1.5 text-primary font-mono"
                >
                  {items.filter((v) => selectedTo === undefined || v.revision < selectedTo).map((v) => (
                    <option key={v.revision} value={v.revision}>v{v.revision}</option>
                  ))}
                  {selectedFrom === undefined && <option value="">none</option>}
                </select>
              </label>
              <label className="flex items-center gap-1 text-tertiary">
                To
                <select
                  value={selectedTo ?? ''}
                  onChange={(e) => onSelect(undefined, Number(e.target.value))}
                  className="h-7 rounded-control border border-hubble-border bg-hubble-darker px-1.5 text-primary font-mono"
                >
                  {items.map((v) => (
                    <option key={v.revision} value={v.revision}>v{v.revision}</option>
                  ))}
                </select>
              </label>
            </div>
          ) : undefined
        }
      >
        <div className="px-4 py-3">
          {!hasVersions ? (
            <p className="text-xs text-tertiary">Nothing to compare yet.</p>
          ) : diff.loading && !diff.diff ? (
            <SectionSkeleton />
          ) : diff.error && errorKind(diff.error) === 'revision_not_found' ? (
            // Not a failure: the Broker keeps the newest versions only.
            <div role="status" className="flex flex-wrap items-center justify-between gap-2 text-xs text-secondary" data-testid="diff-trimmed">
              <span>Earlier versions were trimmed by retention, so this comparison is no longer available.</span>
              {(from !== undefined || to !== undefined) && (
                <Button variant="secondary" size="sm" onClick={() => onSelect(undefined, undefined)}>
                  Compare the latest versions
                </Button>
              )}
            </div>
          ) : diff.error ? (
            <SectionError message={errorMessage(diff.error)} onRetry={() => void diff.reload()} />
          ) : diff.diff ? (
            <DiffViewer diff={diff.diff} />
          ) : null}
        </div>
      </Panel>
    </div>
  );
}
