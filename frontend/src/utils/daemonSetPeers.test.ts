import { describe, expect, test } from 'vitest';
import type { PodInfo, PodNodeData } from '../types';
import {
  EDGE_COLOR_DAEMONSET,
  EDGE_COLOR_DENIED,
  EDGE_COLOR_EXTERNAL,
  EDGE_COLOR_TRUSTED,
  edgeStrokeColor,
  isDaemonSetOrHostNetworkPod,
  isDaemonSetPeer,
  partitionDaemonSetPeers,
  shouldAutoShowDaemonSets,
} from './daemonSetPeers';

const pod = (name: string, extra: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: 'monitoring', time_stamp: 't', node_name: 'n', is_dead: false, ...extra,
});
const node = (id: string, pods: PodInfo[], isExternal = true): PodNodeData =>
  ({ id, label: id, pod: pods[0], pods, traffic: [], isExpanded: false, isExternal }) as PodNodeData;

const nodeExporter = pod('node-exporter-abc', { workload_kind: 'DaemonSet', host_network: true });
const ciliumAgent = pod('cilium-x', { workload_kind: 'DaemonSet', host_network: false });
const kubeletLike = pod('kube-proxy-y', { host_network: true }); // no workload_kind from an older row
const grafana = pod('grafana-0', { workload_kind: 'Deployment', host_network: false });
const legacy = pod('legacy-0'); // neither field (old broker)

describe('isDaemonSetOrHostNetworkPod', () => {
  test('DaemonSet-owned OR host-network qualifies; null/absent does not', () => {
    expect(isDaemonSetOrHostNetworkPod(nodeExporter)).toBe(true);
    expect(isDaemonSetOrHostNetworkPod(ciliumAgent)).toBe(true);
    expect(isDaemonSetOrHostNetworkPod(kubeletLike)).toBe(true);
    expect(isDaemonSetOrHostNetworkPod(grafana)).toBe(false);
    expect(isDaemonSetOrHostNetworkPod(legacy)).toBe(false);
    expect(isDaemonSetOrHostNetworkPod(pod('n', { host_network: null }))).toBe(false);
    expect(isDaemonSetOrHostNetworkPod(null)).toBe(false);
  });
});

describe('isDaemonSetPeer', () => {
  test('only EXTERNAL nodes are candidates — the namespace\'s own DaemonSets always render', () => {
    expect(isDaemonSetPeer(node('external-monitoring-node-exporter-out', [nodeExporter]))).toBe(true);
    expect(isDaemonSetPeer(node('monitoring-node-exporter', [nodeExporter], false))).toBe(false);
  });
  test('any member of the identity group qualifies the node', () => {
    expect(isDaemonSetPeer(node('x-in', [grafana, ciliumAgent]))).toBe(true);
    expect(isDaemonSetPeer(node('x-in', [grafana, legacy]))).toBe(false);
  });
  test('Internet / Service placeholder members (no workload facts) are never hidden', () => {
    expect(isDaemonSetPeer(node('external-internet-in', [pod('1.2.3.4', { pod_namespace: 'internet' })]))).toBe(false);
  });
  test('the Unattributed aggregate is never hidden, even if a member carries DaemonSet facts', () => {
    const unattributed = {
      ...node('external-unattributed-in', [pod('192.168.50.101', { pod_namespace: 'unattributed', workload_kind: 'DaemonSet', host_network: true })]),
      externalNamespace: 'unattributed',
    } as PodNodeData;
    expect(isDaemonSetPeer(unattributed)).toBe(false);
    expect(partitionDaemonSetPeers([unattributed], { show: false, focusedId: null, selectedId: null }).hidden).toEqual([]);
  });
});

describe('partitionDaemonSetPeers', () => {
  const ds = node('external-monitoring-node-exporter-out', [nodeExporter]);
  const cni = node('external-kube-system-cilium-in', [ciliumAgent]);
  const app = node('external-media-grafana-out', [grafana]);
  const all = [ds, cni, app];

  test('toggle on ⇒ nothing hidden, order preserved', () => {
    expect(partitionDaemonSetPeers(all, { show: true, focusedId: null, selectedId: null })).toEqual({ visible: all, hidden: [] });
  });
  test('toggle off ⇒ DaemonSet/host-network peers hidden, others kept', () => {
    const { visible, hidden } = partitionDaemonSetPeers(all, { show: false, focusedId: null, selectedId: null });
    expect(visible).toEqual([app]);
    expect(hidden).toEqual([ds, cni]);
  });
  test('focused peer is never hidden', () => {
    const { visible, hidden } = partitionDaemonSetPeers(all, { show: false, focusedId: ds.id, selectedId: null });
    expect(visible).toEqual([ds, app]);
    expect(hidden).toEqual([cni]);
  });
  test('selected peer is never hidden', () => {
    const { visible } = partitionDaemonSetPeers(all, { show: false, focusedId: null, selectedId: cni.id });
    expect(visible).toEqual([cni, app]);
  });
});

describe('edgeStrokeColor', () => {
  test('edges to/from a DaemonSet peer take the DaemonSets hue, distinct from External', () => {
    expect(edgeStrokeColor({ isDrop: false, isDaemonSet: true, isExternal: true })).toBe(EDGE_COLOR_DAEMONSET);
    expect(EDGE_COLOR_DAEMONSET).not.toBe(EDGE_COLOR_EXTERNAL);
    expect(EDGE_COLOR_DAEMONSET).not.toBe(EDGE_COLOR_TRUSTED);
  });
  test('denied always wins; otherwise external amber, in-cluster indigo', () => {
    expect(edgeStrokeColor({ isDrop: true, isDaemonSet: true, isExternal: true })).toBe(EDGE_COLOR_DENIED);
    expect(edgeStrokeColor({ isDrop: false, isDaemonSet: false, isExternal: true })).toBe(EDGE_COLOR_EXTERNAL);
    expect(edgeStrokeColor({ isDrop: false, isDaemonSet: false, isExternal: false })).toBe(EDGE_COLOR_TRUSTED);
  });
});

describe('shouldAutoShowDaemonSets', () => {
  const ds = node('external-monitoring-node-exporter-out', [nodeExporter]);
  const app = node('external-media-grafana-out', [grafana]);
  test('focus on a hidden-class peer while the toggle is off ⇒ turn it on', () => {
    expect(shouldAutoShowDaemonSets(ds.id, [ds, app], false)).toBe(true);
  });
  test('already on, no focus, or focus on a normal peer ⇒ leave it', () => {
    expect(shouldAutoShowDaemonSets(ds.id, [ds, app], true)).toBe(false);
    expect(shouldAutoShowDaemonSets(null, [ds, app], false)).toBe(false);
    expect(shouldAutoShowDaemonSets(app.id, [ds, app], false)).toBe(false);
    expect(shouldAutoShowDaemonSets('missing', [ds, app], false)).toBe(false);
  });
});
