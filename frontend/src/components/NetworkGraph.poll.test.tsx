// @vitest-environment jsdom
import { afterEach, beforeAll, expect, test, vi } from 'vitest';
import { cleanup, render, waitFor } from '@testing-library/react';
import NetworkGraph from './NetworkGraph';
import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo } from '../types';
import type { ComputeFinding, PodComputeData } from '../types/compute';
import { COMPUTE_STATE_PENDING } from '../utils/compute';

// The compute poll hands the map a new `pods` array every 5 s (each pod
// re-spread with its gauges), and a lens re-spreads them again with badges.
// Nothing traffic-derived reads either, yet peer resolution over every
// traffic row, the external peer nodes and the edges were rebuilt on every
// poll: about 150-250 ms of main-thread work each time on 300 pods with
// 1,000 flows each. They now rebuild only when the traffic inputs change.

const { resolvePeer } = vi.hoisted(() => ({ resolvePeer: { calls: 0 } }));
vi.mock('../utils/peerResolution', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../utils/peerResolution')>();
  return {
    ...actual,
    resolvePeerForView: (...args: Parameters<typeof actual.resolvePeerForView>) => {
      resolvePeer.calls += 1;
      return actual.resolvePeerForView(...args);
    },
  };
});

const { contention } = vi.hoisted(() => ({ contention: { calls: 0 } }));
vi.mock('../utils/contentionEdges', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../utils/contentionEdges')>();
  return {
    ...actual,
    buildContentionEdges: (...args: Parameters<typeof actual.buildContentionEdges>) => {
      contention.calls += 1;
      return actual.buildContentionEdges(...args);
    },
  };
});

vi.mock('elkjs/lib/elk.bundled.js', () => ({
  default: class {
    layout(graph: { children: { id: string }[] }) {
      return Promise.resolve({ children: graph.children.map((c, i) => ({ ...c, x: i * 400, y: 0 })) });
    }
  },
}));

beforeAll(() => {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});

afterEach(cleanup);

const pod = (name: string): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'payments', time_stamp: 't', node_name: 'worker-1', is_dead: false, pod_identity: name,
});
const egressTo = (ip: string): NetworkTraffic =>
  ({ uuid: ip, traffic_in_out_ip: ip, traffic_in_out_port: '443', ip_protocol: 'TCP', traffic_type: 'EGRESS', decision: 'ALLOW', time_stamp: '2026-09-28T00:00:00' }) as NetworkTraffic;
const node = (id: string, traffic: NetworkTraffic[]): PodNodeData =>
  ({ id, label: id, pod: pod(id), pods: [pod(id)], traffic, isExpanded: false }) as PodNodeData;

// App's listings are state: the same arrays across polls.
const lookup: PodInfo[] = [];
const services: ServiceInfo[] = [];
const graph = (pods: PodNodeData[], computeFindings?: ComputeFinding[]) => (
  <NetworkGraph
    pods={pods}
    computeFindings={computeFindings}
    allPodsLookup={lookup}
    services={services}
    showExternalNodes
    onToggleExternalNodes={() => {}}
    showDaemonSetNodes={false}
    onToggleDaemonSetNodes={() => {}}
    showTraffic
    onToggleTraffic={() => {}}
    layoutDirection="LR"
    onToggleLayoutDirection={() => {}}
    onPodSelect={() => {}}
    selectedPodId={null}
    focusedNodeId={null}
    onFocusChange={() => {}}
  />
);

const withGauges = (pods: PodNodeData[], cpuPct: number): PodNodeData[] =>
  pods.map((p) => ({ ...p, compute: { ...COMPUTE_STATE_PENDING, status: 'ok', cpuPct } as PodComputeData }));

test('a compute poll re-resolves no traffic rows; new traffic does', async () => {
  const pods = [node('api', [egressTo('140.82.112.3'), egressTo('10.0.0.9')]), node('worker', [egressTo('140.82.112.3')])];
  const { container, rerender } = render(graph(pods));
  await waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBeGreaterThan(0));
  const afterLoad = resolvePeer.calls;
  expect(afterLoad).toBeGreaterThan(0);

  // Three polls: new pod objects, same traffic.
  for (const pct of [10, 20, 30]) rerender(graph(withGauges(pods, pct)));
  await new Promise((r) => setTimeout(r, 0));
  expect(resolvePeer.calls).toBe(afterLoad);

  // A refresh brings new traffic arrays: those rows are resolved.
  rerender(graph(pods.map((p) => ({ ...p, traffic: [...(p.traffic ?? [])] }))));
  await waitFor(() => expect(resolvePeer.calls).toBeGreaterThan(afterLoad));
});

// The findings poll (15 s) hands over a new array every time, even when the
// Broker's answer is the same, and the contention edges, the drawn external
// nodes and every traffic edge were rebuilt from it.
test('a findings poll with the same answer rebuilds no contention or edges; a changed answer does', async () => {
  const finding = (share: number): ComputeFinding => ({
    kind: 'noisy-neighbor', severity: 'high',
    victim: { pod_uid: 'uid-api', namespace: 'payments', pod_name: 'api', container: 'app', container_uid: 'uid-api/app', node: 'worker-1' },
    culprit: { kind: 'pod', pod_uid: 'uid-etl', namespace: 'batch', pod_name: 'etl-1', container: 'etl', blame_share: share, usage_millis: 900 },
    evidence: { window_minutes: 5, cpu_psi_some10_max: 0, cpu_psi_full10_max: 0, runq_p99_us_max: null, throttled_ratio: 0, mem_psi_some10_max: 0, node_mem_some10_max: 0, refault_delta: 0, mem_events_high_delta: 0 },
    first_seen: 't', last_seen: 't', message: 'etl-1 starves api',
  } as ComputeFinding);
  const pods = [node('api', [egressTo('140.82.112.3')])];
  const { container, rerender } = render(graph(pods, [finding(0.6)]));
  await waitFor(() => expect(container.querySelectorAll('.react-flow__node').length).toBeGreaterThan(0));
  const afterLoad = contention.calls;

  for (let i = 0; i < 3; i++) rerender(graph(pods, [finding(0.6)])); // same content, new arrays
  await new Promise((r) => setTimeout(r, 0));
  expect(contention.calls).toBe(afterLoad);

  rerender(graph(pods, [finding(0.8)]));
  await waitFor(() => expect(contention.calls).toBeGreaterThan(afterLoad));
});
