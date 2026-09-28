import { useEffect, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import {
  describeNodes,
  describeSilence,
  loadNodeStatus,
  silentNodes,
  type NodeStatusLoad,
  type NodeStatusResponse,
} from '../utils/nodeReporting';

export type { NodeStatusLoad };

const POLL_MS = 60_000;

interface Props {
  /** Bumped by the header's Refresh; reloads alongside the views. */
  refreshTick?: number;
  load?: () => Promise<NodeStatusLoad>;
  now?: () => number;
}

/**
 * "N nodes have not reported pods since …": the broker has marked (or is
 * about to mark) every pod on those nodes dead because their controller
 * stopped re-posting them, so they are missing from the namespace picker,
 * Workloads and the maps. Renders nothing when every node reports, on an
 * older broker, and on any failure; the fetch never gates the app.
 */
export function NodeReportingBanner({ refreshTick = 0, load = loadNodeStatus, now = Date.now }: Props) {
  const [status, setStatus] = useState<NodeStatusResponse | null>(null);
  const [unsupported, setUnsupported] = useState(false);

  useEffect(() => {
    if (unsupported) return;
    let cancelled = false;
    const run = async () => {
      const result = await load();
      if (cancelled) return;
      if (result.kind === 'ok') setStatus(result.status);
      else if (result.kind === 'unsupported') setUnsupported(true);
    };
    void run();
    const timer = setInterval(() => void run(), POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [load, refreshTick, unsupported]);

  if (!status) return null;
  const nowMs = now();
  const summary = silentNodes(status, nowMs);
  if (summary.nodes.length === 0) return null;
  return (
    <div
      role="status"
      data-testid="node-reporting-banner"
      title={describeNodes(summary)}
      className="flex flex-wrap items-center gap-x-2 gap-y-0.5 px-4 py-1.5 border-b border-hubble-border bg-severity-medium/10 text-xs text-severity-medium"
    >
      <TriangleAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span className="font-medium">{describeSilence(summary, nowMs)}.</span>
      <span className="text-tertiary">
        Their pods are missing from the namespace picker, Workloads and the maps until they report again.
      </span>
    </div>
  );
}
