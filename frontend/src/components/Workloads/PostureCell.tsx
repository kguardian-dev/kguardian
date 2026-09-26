import type { WorkloadListItem } from '../../types/profile';
import { asStatus, DIMENSION_LABEL, STATUS_LABEL } from '../../utils/posture';
import { StatusPill } from '../Profile/parts';

/**
 * Workloads table posture: the `GET /workloads` rollup. Three honest
 * non-answers besides a status — still loading, the Broker could not serve
 * the column, and a workload the snapshotter has not reached yet — none of
 * which may read as OK.
 */
export function PostureCell({ item, loading, unavailable }: { item: WorkloadListItem | undefined; loading: boolean; unavailable: boolean }) {
  if (!item) {
    if (loading) return <span className="text-xs text-tertiary">…</span>;
    if (unavailable) return <span className="text-xs text-tertiary" title="The Broker did not return profile postures">—</span>;
    return (
      <span className="text-xs text-tertiary" title="The Broker has not computed a profile for this workload yet (it snapshots every few minutes)">
        not computed yet
      </span>
    );
  }
  const status = asStatus(item.posture.status);
  const unknown = item.posture.unknownDimensions.map((d) => DIMENSION_LABEL[d] ?? d);
  const title = [
    item.posture.score !== null ? `Score ${item.posture.score} over ${Math.round(item.posture.coverage * 100)}% of the weight` : 'Not scored',
    unknown.length ? `Not scored: ${unknown.join(', ')}` : '',
  ]
    .filter(Boolean)
    .join('. ');
  return (
    <span className="inline-flex items-center gap-1.5">
      <StatusPill status={status} title={title}>
        {STATUS_LABEL[status]}
        {item.posture.score !== null && <span className="font-mono tabular-nums">· {item.posture.score}</span>}
      </StatusPill>
      {status !== 'unknown' && unknown.length > 0 && (
        <span className="text-[11px] text-tertiary" title={`Not scored (no data, or not scorable yet): ${unknown.join(', ')}`}>
          {unknown.length} not scored
        </span>
      )}
    </span>
  );
}
