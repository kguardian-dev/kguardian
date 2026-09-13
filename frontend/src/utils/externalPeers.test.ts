import { describe, expect, test } from 'vitest';
import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo } from '../types';
import { buildPeerIndex, resolvePeer, type PeerResolution } from './peerResolution';
import { buildExternalNodes, remoteNodeForRow } from './externalPeers';
import { isDaemonSetPeer } from './daemonSetPeers';

// The map's external-node builder, driven exactly like NetworkGraph drives
// it. Live finding on cluster-00 (2026-09-03): with External on, the
// game-servers map drew `external-svc-home-system-autobrr-in` into
// cmangos-database from a July row on 10.244.12.199, although the broker's
// guarded lookup 404s for it — the IP was being mapped to the Service
// because autobrr (started 2026-08-04) backs that Service and holds the IP
// NOW. A Service may only be reached through a peer resolvePeer accepted.

const pod = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default', time_stamp: '2026-09-03T05:00:00', node_name: 'worker-1', is_dead: false, ...p,
});
const cmangosDatabase = pod({
  pod_name: 'cmangos-database-0', pod_ip: '10.244.3.17', pod_namespace: 'game-servers',
  workload_name: 'cmangos-database', workload_selector_labels: { app: 'cmangos-database' }, started_at: '2026-05-01T00:00:00',
});
const autobrr = pod({
  pod_name: 'autobrr-7d9c4b8f6-q2x9k', pod_ip: '10.244.12.199', pod_namespace: 'home-system', node_name: 'worker-2',
  workload_kind: 'Deployment', workload_name: 'autobrr', workload_selector_labels: { app: 'autobrr' }, started_at: '2026-08-04T09:12:41',
});
const autobrrSvc: ServiceInfo = {
  svc_ip: '10.96.0.20', svc_name: 'autobrr', svc_namespace: 'home-system', service_spec: { spec: { selector: { app: 'autobrr' } } },
};

const row = (r: Partial<NetworkTraffic>): NetworkTraffic => ({
  uuid: Math.random().toString(36).slice(2), pod_name: 'cmangos-database-0', pod_namespace: 'game-servers', pod_ip: '10.244.3.17',
  pod_port: '3306', ip_protocol: 'TCP', traffic_type: 'INGRESS', traffic_in_out_ip: '10.244.12.199',
  traffic_in_out_port: '51234', decision: 'ALLOW', time_stamp: '2026-07-23T10:00:00', ...r,
});

/** Wire the inputs the way NetworkGraph does. */
function build(localPods: PodInfo[], allPods: PodInfo[], services: ServiceInfo[], traffic: NetworkTraffic[]) {
  const nodes: PodNodeData[] = localPods.map((p) => ({ id: `${p.pod_namespace}-${p.pod_name}`, label: p.pod_name, pod: p, pods: [p], traffic, isExpanded: false }));
  const index = buildPeerIndex(allPods, services);
  const rowPeers = new Map<NetworkTraffic, PeerResolution>();
  traffic.forEach((t) => { if (t.traffic_in_out_ip) rowPeers.set(t, resolvePeer(t, index)); });
  const localPodByName = new Map(nodes.map((n) => [n.pod.pod_name, n]));
  const selector = (svc: ServiceInfo) => ((svc.service_spec as { spec?: { selector?: Record<string, string> } })?.spec?.selector) ?? {};
  const matches = (labels: Record<string, string> | null | undefined, sel: Record<string, string>) =>
    Object.keys(sel).length > 0 && !!labels && Object.entries(sel).every(([k, v]) => labels[k] === v);
  const svcIpToLocalPod = new Map<string, PodNodeData>();
  const podNameToSvcIp = new Map<string, string>();
  services.forEach((svc) => {
    const local = nodes.find((n) => matches(n.pod.workload_selector_labels, selector(svc)));
    if (local) svcIpToLocalPod.set(svc.svc_ip, local);
    allPods.forEach((p) => { if (p.pod_namespace === svc.svc_namespace && matches(p.workload_selector_labels, selector(svc))) podNameToSvcIp.set(p.pod_name, svc.svc_ip); });
  });
  const external = buildExternalNodes({ pods: nodes, services, rowPeers, localPodByName, svcIpToLocalPod, podNameToSvcIp });
  const byKey = (dir: 'in' | 'out') => {
    const m = new Map<string, PodNodeData>();
    external.filter((n) => n.id.endsWith(`-${dir}`)).forEach((n) => n.peerKeys?.forEach((k) => m.set(k, n)));
    return m;
  };
  const remote = (t: NetworkTraffic) =>
    remoteNodeForRow(t, rowPeers, localPodByName, svcIpToLocalPod, byKey(t.traffic_type?.toLowerCase() === 'ingress' ? 'in' : 'out'));
  return { external, remote };
}

describe('buildExternalNodes — a Service is never derived from a raw IP', () => {
  test('the exact case: July row from 10.244.12.199, only candidate autobrr (started 2026-08-04) backing home-system/autobrr ⇒ Unattributed, no svc node', () => {
    const t = row({ time_stamp: '2026-07-23T10:00:00' });
    const { external, remote } = build([cmangosDatabase], [cmangosDatabase, autobrr], [autobrrSvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-unattributed-in']);
    expect(external[0].tooltip).toBe('former holder of this IP; no live pod matched at flow time');
    expect(external[0].pods.map((p) => p.pod_ip)).toEqual(['10.244.12.199']);
    expect(external.some((n) => n.id.startsWith('external-svc-'))).toBe(false);
    expect(external.some((n) => n.label === 'autobrr')).toBe(false);
    expect(remote(t)?.id).toBe('external-unattributed-in');
  });

  test('a NULL-started ghost that backs a Service does not pull the row into the svc node either', () => {
    const t = row({ time_stamp: '2026-09-01T10:00:00' });
    const ghost = { ...autobrr, started_at: null };
    const { external } = build([cmangosDatabase], [cmangosDatabase, ghost], [autobrrSvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-unattributed-in']);
  });

  test('a legitimately resolved backing pod still groups under its Service node (external-svc-*)', () => {
    const viaPod = row({ time_stamp: '2026-09-01T10:00:00' });
    const viaClusterIp = row({ time_stamp: '2026-09-01T10:00:01', traffic_type: 'EGRESS', traffic_in_out_ip: '10.96.0.20', traffic_in_out_port: '7474' });
    const { external, remote } = build([cmangosDatabase], [cmangosDatabase, autobrr], [autobrrSvc], [viaPod, viaClusterIp]);
    expect(external.map((n) => n.id).sort()).toEqual(['external-svc-home-system-autobrr-in', 'external-svc-home-system-autobrr-out']);
    const inNode = external.find((n) => n.id.endsWith('-in'))!;
    expect(inNode.label).toBe('autobrr');
    expect(inNode.pods.map((p) => p.pod_ip)).toEqual(['10.244.12.199']);
    expect(inNode.pods[0].workload_name).toBe('autobrr');
    expect(remote(viaPod)?.id).toBe('external-svc-home-system-autobrr-in');
    expect(remote(viaClusterIp)?.id).toBe('external-svc-home-system-autobrr-out');
  });

  test('a stored peer pointing at the pod that held the IP then renders as that workload, not as the current holder', () => {
    const backup = pod({
      pod_name: 'cmangos-backup-29271840-x7k2p', pod_ip: '10.244.12.199', pod_namespace: 'game-servers', is_dead: true,
      workload_kind: 'CronJob', workload_name: 'cmangos-backup', workload_selector_labels: { app: 'cmangos-backup' }, started_at: '2026-07-23T09:00:00',
    });
    const t = row({ time_stamp: '2026-07-23T10:00:00', peer_kind: 'pod', peer_namespace: 'game-servers', peer_name: backup.pod_name, peer_workload_kind: 'CronJob', peer_workload_name: 'cmangos-backup' });
    const { external } = build([cmangosDatabase], [cmangosDatabase, autobrr, backup], [autobrrSvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-game-servers-cmangos-backup-in']);
  });

  test('an IP nobody ever held is Internet; a local peer is an edge, not an external node', () => {
    const internet = row({ traffic_in_out_ip: '203.0.113.9', time_stamp: '2026-09-01T10:00:00' });
    const local = row({ traffic_in_out_ip: '10.244.3.17', time_stamp: '2026-09-01T10:00:00' });
    const { external, remote } = build([cmangosDatabase], [cmangosDatabase, autobrr], [autobrrSvc], [internet, local]);
    expect(external.map((n) => n.id)).toEqual(['external-internet-in']);
    expect(remote(internet)?.id).toBe('external-internet-in');
    expect(remote(local)?.id).toBe('game-servers-cmangos-database-0');
  });
});

// #1565: the synthetic member pods of a Service node used to be decorated
// from a last-write-wins IP → pod map over the whole /pod/info listing (dead
// rows included). pod_details keeps a row per pod ever seen, so a recycled
// address resolved to whichever former holder sorted last in (namespace,
// name) order — on EKS the node agents — and a Deployment-backed Service
// inherited workload_kind DaemonSet / host_network true from a dead
// ebs-csi-node or datadog-agent row, and the DaemonSets toggle hid it.
describe('buildExternalNodes — Service members carry the RESOLVED backing pod\'s workload facts (#1565)', () => {
  const RECYCLED_IP = '10.0.0.9';
  const flowAt = '2026-09-12T10:00:00';
  const live = pod({
    pod_name: 'web-7c9d-abcde', pod_ip: RECYCLED_IP, pod_namespace: 'shop', node_name: 'ip-10-0-0-1',
    is_dead: false, started_at: '2026-09-12T09:00:00', time_stamp: flowAt,
    workload_kind: 'Deployment', workload_name: 'web', workload_selector_labels: { app: 'web' }, host_network: false,
  });
  // Held the same address months ago. Namespace sorts after "shop", so in the
  // (pod_namespace, pod_name) order /pod/info returns it is the map's winner.
  const deadAgent = pod({
    pod_name: 'ebs-csi-node-zzzzz', pod_ip: RECYCLED_IP, pod_namespace: 'zz-system', node_name: 'ip-10-0-0-2',
    is_dead: true, started_at: '2026-06-01T00:00:00', time_stamp: '2026-07-01T00:00:00',
    workload_kind: 'DaemonSet', workload_name: 'ebs-csi-node', host_network: true,
  });
  const webSvc: ServiceInfo = {
    svc_ip: '10.96.0.30', svc_name: 'web', svc_namespace: 'shop', service_spec: { spec: { selector: { app: 'web' } } },
  };

  test('regression: a dead DaemonSet/host-network row that once held the backing pod\'s IP does not make the Service node a DaemonSet peer', () => {
    const t = row({ traffic_type: 'EGRESS', traffic_in_out_ip: RECYCLED_IP, traffic_in_out_port: '8080', time_stamp: flowAt });
    // Listed AFTER the live pod: that is the order in which the removed
    // last-write-wins IP → pod map picked the dead row, so this fixture fails
    // on the unpatched code and passes here.
    const listing = [cmangosDatabase, live, deadAgent];
    const index = buildPeerIndex(listing, [webSvc]);
    const resolved = resolvePeer(t, index);
    expect(resolved).toMatchObject({ kind: 'pod', pod: { pod_name: live.pod_name } });

    const { external } = build([cmangosDatabase], listing, [webSvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-svc-shop-web-out']);
    const node = external[0];
    expect(node.pods).toHaveLength(1);
    expect(node.pods[0].workload_kind).toBe('Deployment');
    expect(node.pods[0].workload_name).toBe('web');
    expect(node.pods[0].host_network).toBe(false);
    expect(node.pods[0].node_name).toBe(live.node_name);
    expect(isDaemonSetPeer(node)).toBe(false);
  });

  test('control: a Service whose resolved backing pod really is a DaemonSet (or host-network) is still flagged', () => {
    const nodeExporter = pod({
      pod_name: 'node-exporter-k7f2p', pod_ip: '10.0.0.40', pod_namespace: 'monitoring',
      started_at: '2026-09-01T00:00:00', time_stamp: flowAt,
      workload_kind: 'DaemonSet', workload_name: 'node-exporter', workload_selector_labels: { app: 'node-exporter' }, host_network: false,
    });
    const nodeExporterSvc: ServiceInfo = {
      svc_ip: '10.96.0.40', svc_name: 'node-exporter', svc_namespace: 'monitoring', service_spec: { spec: { selector: { app: 'node-exporter' } } },
    };
    const t = row({ traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.40', traffic_in_out_port: '9100', time_stamp: flowAt });
    const { external } = build([cmangosDatabase], [cmangosDatabase, nodeExporter], [nodeExporterSvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-svc-monitoring-node-exporter-out']);
    expect(external[0].pods[0].workload_kind).toBe('DaemonSet');
    expect(isDaemonSetPeer(external[0])).toBe(true);

    // host_network alone (a Deployment sharing the node's network) also qualifies.
    const hostNet = pod({
      pod_name: 'kube-proxy-shim-9x1', pod_ip: '10.0.0.41', pod_namespace: 'monitoring',
      started_at: '2026-09-01T00:00:00', time_stamp: flowAt,
      workload_kind: 'Deployment', workload_name: 'kube-proxy-shim', workload_selector_labels: { app: 'shim' }, host_network: true,
    });
    const hostNetSvc: ServiceInfo = {
      svc_ip: '10.96.0.41', svc_name: 'shim', svc_namespace: 'monitoring', service_spec: { spec: { selector: { app: 'shim' } } },
    };
    const t2 = row({ traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.41', traffic_in_out_port: '9100', time_stamp: flowAt });
    const r2 = build([cmangosDatabase], [cmangosDatabase, hostNet], [hostNetSvc], [t2]);
    expect(r2.external.map((n) => n.id)).toEqual(['external-svc-monitoring-shim-out']);
    expect(r2.external[0].pods[0].host_network).toBe(true);
    expect(isDaemonSetPeer(r2.external[0])).toBe(true);
  });
});
