import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from 'reactflow';

export interface TrafficEdgeData {
  /** The port / protocol summary, with the drop count appended. */
  label: string;
  /** At least one DROP row on this edge: the label is red and lifted above the cards. */
  isDrop: boolean;
}

/**
 * Cards sit at z 0 (1000 when selected). A default edge label lives inside
 * the edge's SVG under the cards, so a drop label that landed on a card was
 * clipped by it. Lifting only the label (not the line) puts the security
 * signal above unselected cards and still under the one card that is open.
 */
export const DROP_LABEL_Z_INDEX = 10;

/** A traffic flow edge whose label is drawn by the label renderer. */
export default function TrafficEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  style,
  markerEnd,
}: EdgeProps<TrafficEdgeData>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const isDrop = data?.isDrop ?? false;
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />
      {data?.label && (
        <EdgeLabelRenderer>
          <div
            className={`nodrag nopan absolute rounded bg-hubble-card px-1 text-[11px] font-mono leading-4 whitespace-nowrap ${
              isDrop ? 'font-semibold text-hubble-error' : 'text-secondary'
            }`}
            style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`, zIndex: isDrop ? DROP_LABEL_Z_INDEX : undefined }}
            data-testid="traffic-edge-label"
            data-drop={isDrop ? 'true' : undefined}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
