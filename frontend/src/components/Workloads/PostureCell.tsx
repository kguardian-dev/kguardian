import type { WorkloadListItem } from '../../types/profile';
import { asStatus, DIMENSION_LABEL, formatAgo, formatTimestamp, STATUS_LABEL } from '../../utils/posture';
import { asUtc } from '../../utils/vulnView';
import { StatusPill } from '../Profile/parts';

/**
 * Workloads table posture: the `GET /workloads` rollup. Four honest
 * non-answers besides a status — still loading, the Broker could not serve
 * the column, a workload with no stored snapshot, and a workload whose
 * snapshot failed before it was ever computed — none of which may read as OK.
 */
export function PostureCell({
  item,
  loading,
  unavailable,
  morePages = false,
}: {
  item: WorkloadListItem | undefined;
  loading: boolean;
  unavailable: boolean;
  /** More `GET /workloads` pages exist that have not been fetched. */
  morePages?: boolean;
}) {
  if (!item) {
    if (loading) return <span className="text-xs text-tertiary">…</span>;
    if (unavailable) return <span className="text-xs text-tertiary" title="The Broker did not return profile postures">—</span>;
    if (morePages) {
      return (
        <span className="text-xs text-tertiary" title="Not in the posture pages loaded so far: use Load more postures below the table">
          not loaded
        </span>
      );
    }
    return (
      <span
        className="text-xs text-tertiary"
        title="The Broker has no stored profile snapshot for this workload. Snapshots are computed in the background; one that fails (for example on a statement timeout) is only retried on a later pass, so this can persist."
      >
        no snapshot
      </span>
    );
  }
  const failedAgo = item.failedAt ? formatAgo(asUtc(item.failedAt)) : null;
  const failure = item.lastError ? `${item.lastError}` : 'no error message recorded';
  if (item.computedAt === null) {
    // Never computed: the snapshotter's failed attempt is the only fact, and it can persist.
    return (
      <span
        className="text-xs text-severity-medium"
        title={`The Broker's profile snapshot for this workload failed${item.failedAt ? ` at ${formatTimestamp(asUtc(item.failedAt))}` : ''}: ${failure}. It is retried on a later pass.`}
        data-testid="posture-failed"
      >
        profile failed{failedAgo ? ` · ${failedAgo}` : ''}
      </span>
    );
  }
  const status = asStatus(item.posture.status);
  const unknown = item.posture.unknownDimensions.map((d) => DIMENSION_LABEL[d] ?? d);
  const coverage = Math.round(item.posture.coverage * 100);
  const title = [
    status === 'unknown' ? 'No dimension has data yet' : 'Worst status across the dimensions with data',
    `coverage ${coverage}% of the four core dimensions`,
    unknown.length ? `No data: ${unknown.join(', ')}` : '',
    item.lastError || item.failedAt ? `The latest snapshot attempt failed${failedAgo ? ` ${failedAgo}` : ''} (${failure}); this is the last good profile` : '',
  ]
    .filter(Boolean)
    .join('. ');
  return (
    <span className="inline-flex items-center gap-1.5">
      <StatusPill status={status} title={title}>
        {STATUS_LABEL[status]}
      </StatusPill>
      {/* Coverage whenever anything is known: a partial unknown is not a blank one. */}
      {item.posture.coverage > 0 && (
        <span className="font-mono text-[11px] tabular-nums text-tertiary" title={title}>
          {coverage}%
        </span>
      )}
      {(item.lastError || item.failedAt) && (
        <span className="text-[11px] text-severity-medium" title={title} data-testid="posture-stale">
          · snapshot failed{failedAgo ? ` ${failedAgo}` : ''}
        </span>
      )}
    </span>
  );
}
