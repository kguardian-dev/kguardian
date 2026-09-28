import axios from 'axios';
import api from '../services/api';
import { formatBrokerTime } from './brokerTime';
import { parseBrokerTime } from './peerResolution';

/** One row of `GET /node/status` (broker 1.20+). */
export interface NodeStatus {
  node: string;
  lastPodPostAt: string | null;
  alivePods: number;
  lastHeartbeatAt: string | null;
  stale: boolean;
}

export interface NodeStatusResponse {
  staleAfterSecs: number;
  nodes: NodeStatus[];
}

export type NodeStatusLoad =
  | { kind: 'ok'; status: NodeStatusResponse }
  /** A broker without `GET /node/status`: stop asking for the session. */
  | { kind: 'unsupported' }
  /** Anything else, a 503 from a busy broker included: keep the last answer, ask again next tick. */
  | { kind: 'error' };

export type NodeStatusGet = (url: string) => Promise<{ data: unknown }>;

// The api service keeps its axios client private; the base URL is all this
// needs, and `/api` is what it defaults to itself.
const defaultGet: NodeStatusGet = (url) => axios.get(url, { timeout: 10_000 });

function isNodeStatusResponse(data: unknown): data is NodeStatusResponse {
  if (!data || typeof data !== 'object') return false;
  const d = data as Partial<NodeStatusResponse>;
  return Array.isArray(d.nodes) && typeof d.staleAfterSecs === 'number';
}

/** Read `GET /node/status`; only a 404 means the broker does not have it. */
export async function loadNodeStatus(get: NodeStatusGet = defaultGet): Promise<NodeStatusLoad> {
  const base = typeof api?.baseURL === 'string' ? api.baseURL : '/api';
  try {
    const r = await get(`${base}/node/status`);
    return isNodeStatusResponse(r.data) ? { kind: 'ok', status: r.data } : { kind: 'error' };
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return { kind: 'unsupported' };
    return { kind: 'error' };
  }
}

export interface SilentNode {
  node: string;
  lastPodPostAt: string | null;
  /** `null` when the broker holds no pod row for the node at all. */
  lastPodPostAtMs: number | null;
}

export interface NodeReportingSummary {
  /** Node-name order. */
  nodes: SilentNode[];
  /** The newest known last post among them: none has reported since this. */
  sinceMs: number | null;
}

/**
 * The compute heartbeat arrives every sample interval, or every 300 s
 * when compute gauges are off, so a node is judged alive for two missed
 * heartbeats even when `PEER_STALE_ALIVE_SECS` is set below that;
 * otherwise a short window would make every healthy node look gone.
 */
export const HEARTBEAT_GRACE_MS = 2 * 300_000;

/**
 * Nodes whose controller is up but has stopped re-posting its pods: the
 * broker calls the pods stale, and the node's heartbeat is recent. A node
 * whose heartbeat is stale too has left the cluster and is not counted.
 * A node with a heartbeat but no pod row counts as well: a controller
 * posts its own pod within seconds of starting, and the broker prunes
 * dead rows after `DEAD_POD_RETENTION_DAYS`, so "no row" is either a node
 * stuck for longer than that or one that could never post, not a node
 * that just joined.
 */
export function silentNodes(status: NodeStatusResponse, nowMs: number): NodeReportingSummary {
  const windowMs = Math.max(Math.max(0, status.staleAfterSecs) * 1000, HEARTBEAT_GRACE_MS);
  const nodes: SilentNode[] = [];
  for (const n of status.nodes) {
    if (!n.stale) continue;
    const heartbeat = parseBrokerTime(n.lastHeartbeatAt);
    if (heartbeat === null || nowMs - heartbeat > windowMs) continue;
    nodes.push({ node: n.node, lastPodPostAt: n.lastPodPostAt, lastPodPostAtMs: parseBrokerTime(n.lastPodPostAt) });
  }
  nodes.sort((a, b) => a.node.localeCompare(b.node));
  const known = nodes.map((n) => n.lastPodPostAtMs).filter((ms): ms is number => ms !== null);
  const sinceMs = known.length === 0 ? null : Math.max(...known);
  return { nodes, sinceMs };
}

/** "45s", "12m", "5h", "3d": coarse, for a banner. */
export function ageLabel(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

/** Local wall-clock time of a broker timestamp, "07:37". */
export function clockLabel(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
}

/**
 * The banner sentence: "2 nodes have not reported pods since 07:37 (5h ago)",
 * or "... have not reported any pods" when no post is on record for any.
 */
export function describeSilence(summary: NodeReportingSummary, nowMs: number): string {
  const n = summary.nodes.length;
  const head = n === 1 ? '1 node has not reported' : `${n} nodes have not reported`;
  if (summary.sinceMs === null) return `${head} any pods`;
  return `${head} pods since ${clockLabel(summary.sinceMs)} (${ageLabel(nowMs - summary.sinceMs)} ago)`;
}

/** One line per node for the tooltip, full local date-time with zone. */
export function describeNodes(summary: NodeReportingSummary): string {
  return summary.nodes
    .map((n) =>
      n.lastPodPostAtMs === null
        ? `${n.node}: no pod post on record`
        : `${n.node}: last pod post ${formatBrokerTime(n.lastPodPostAt)}`,
    )
    .join('\n');
}
