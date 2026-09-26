import type { WorkloadListItem } from '../../types/profile';
import { asStatus, DIMENSION_LABEL, STATUS_LABEL } from '../../utils/posture';
import { StatusPill } from '../Profile/parts';

/**
 * Workloads table posture: the `GET /workloads` rollup. Three honest
 * non-answers besides a status — still loading, the Broker could not serve
 * the column, and a workload the snapshotter has not reached yet — none of
 * which may read as OK.
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
      <span className="text-xs text-tertiary" title="The Broker has not computed a profile for this workload yet (it snapshots every few minutes)">
        not computed yet
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
    </span>
  );
}
