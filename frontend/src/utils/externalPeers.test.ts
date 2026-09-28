import { describe, expect, test } from 'vitest';
import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo } from '../types';
import { PRIVATE_PEER_TOOLTIP, buildPeerIndex, resolvePeer, type PeerResolution } from './peerResolution';
import { buildExternalNodes, localWorkloadIndex, remoteNodeForRow } from './externalPeers';
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

/** Wire the inputs the way NetworkGraph does (one local node per pod, all rows on each). */
function build(localPods: PodInfo[], allPods: PodInfo[], services: ServiceInfo[], traffic: NetworkTraffic[]) {
  const nodes: PodNodeData[] = localPods.map((p) => ({ id: `${p.pod_namespace}-${p.pod_name}`, label: p.pod_name, pod: p, pods: [p], traffic, isExpanded: false }));
  return buildFromNodes(nodes, allPods, services, traffic);
}

/** Same wiring over prebuilt local nodes (identity cards with several replicas, rows on their own card). */
function buildFromNodes(nodes: PodNodeData[], allPods: PodInfo[], services: ServiceInfo[], traffic: NetworkTraffic[]) {
  const index = buildPeerIndex(allPods, services);
  const rowPeers = new Map<NetworkTraffic, PeerResolution>();
  traffic.forEach((t) => { if (t.traffic_in_out_ip) rowPeers.set(t, resolvePeer(t, index)); });
  const localPodByName = new Map<string, PodNodeData>();
  nodes.forEach((n) => { localPodByName.set(n.pod.pod_name, n); n.pods.forEach((p) => localPodByName.set(p.pod_name, n)); });
  const localPodByWorkload = localWorkloadIndex(nodes);
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
  const external = buildExternalNodes({ pods: nodes, services, rowPeers, localPodByName, localPodByWorkload, svcIpToLocalPod, podNameToSvcIp });
  const byKey = (dir: 'in' | 'out') => {
    const m = new Map<string, PodNodeData>();
    external.filter((n) => n.id.endsWith(`-${dir}`)).forEach((n) => n.peerKeys?.forEach((k) => m.set(k, n)));
    return m;
  };
  const remote = (t: NetworkTraffic) =>
    remoteNodeForRow(t, rowPeers, localPodByName, svcIpToLocalPod, byKey(t.traffic_type?.toLowerCase() === 'ingress' ? 'in' : 'out'), localPodByWorkload);
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

// F-17 (kguardian UI review, 2026-09-28): on the dev cluster 83 of argocd's
// 94 "Unattributed" IPs were argocd's own former replicas — 55 rows naming
// `argocd-redis-ha-server-{0,1,2}` whose current record has a different uid
// (a StatefulSet slot keeps its name across restarts) and 28 pruned replicas
// of its Deployments — because a stored peer whose record is gone or
// superseded became a placeholder and placeholders went to Unattributed. 18
// of the 69 "Internet" IPs were 10.62.0.0/16 addresses no record ever held.
// Service cards counted every backing record within the dead-pod window
// (DATA-05: 21 `argocd-redis-ha-haproxy` pods seen for 3 live endpoints).
describe('buildExternalNodes — a stored peer whose record is gone is grouped under its stored workload (F-17)', () => {
  const NS = 'argocd';
  const AT = '2026-09-26T13:06:51.121208';
  const argo = (name: string, ip: string, kind: string, workload: string, identity: string, uid: string, extra: Partial<PodInfo> = {}): PodInfo => pod({
    pod_name: name, pod_ip: ip, pod_namespace: NS, pod_identity: identity, workload_kind: kind, workload_name: workload,
    workload_selector_labels: { 'app.kubernetes.io/name': workload }, pod_obj: { metadata: { uid, labels: { 'app.kubernetes.io/name': workload } } },
    started_at: '2026-09-23T04:05:48', time_stamp: '2026-09-28T16:00:00', node_name: 'ip-10-62-100-1', host_network: false, ...extra,
  });
  // The map groups local cards by pod_identity (hooks/usePodData): the redis
  // StatefulSet's identity is `redis-ha`, not its workload name.
  const redis = ['0', '1', '2'].map((i) => argo(`argocd-redis-ha-server-${i}`, `10.62.101.${i}`, 'StatefulSet', 'argocd-redis-ha-server', 'redis-ha', `redis-uid-now-${i}`));
  const haproxy = ['k26m9', 'x9kxc', 'xcbjf'].map((h, i) => argo(`argocd-redis-ha-haproxy-b5fcfd449-${h}`, `10.62.102.${i}`, 'Deployment', 'argocd-redis-ha-haproxy', 'argocd-redis-ha-haproxy', `haproxy-uid-${h}`));
  const server = ['chqc7', 'd8bnz', 'v4qpb'].map((h, i) => argo(`argocd-server-5b4b857646-${h}`, `10.62.103.${i}`, 'Deployment', 'argocd-server', 'argocd-server', `server-uid-${h}`));
  const haproxySvc: ServiceInfo = {
    svc_ip: '172.20.10.5', svc_name: 'argocd-redis-ha-haproxy', svc_namespace: NS, service_spec: { spec: { selector: { 'app.kubernetes.io/name': 'argocd-redis-ha-haproxy' } } },
  };
  const card = (members: PodInfo[], traffic: NetworkTraffic[]): PodNodeData => {
    const names = new Set(members.map((p) => p.pod_name));
    const identity = members[0].pod_identity!;
    return { id: `${NS}-${identity}`, label: identity, pod: members[0], pods: members, traffic: traffic.filter((t) => t.pod_name && names.has(t.pod_name)), isExpanded: false };
  };
  const cards = (traffic: NetworkTraffic[]) => [card(redis, traffic), card(haproxy, traffic), card(server, traffic)];
  const listing = [...redis, ...haproxy, ...server];
  /** An INGRESS row on the first haproxy pod from a stored pod peer. */
  const from = (peer: Pick<NetworkTraffic, 'peer_kind' | 'peer_namespace' | 'peer_name' | 'peer_uid' | 'peer_workload_kind' | 'peer_workload_name'>, ip: string, r: Partial<NetworkTraffic> = {}): NetworkTraffic => row({
    pod_name: haproxy[0].pod_name, pod_namespace: NS, pod_ip: haproxy[0].pod_ip, pod_port: '6379', traffic_type: 'INGRESS',
    traffic_in_out_ip: ip, traffic_in_out_port: '0', time_stamp: AT, ...peer, ...r,
  });
  const former = (name: string, kind: string, workload: string, ns = NS, peer_kind = 'pod') =>
    ({ peer_kind, peer_namespace: ns, peer_name: name, peer_uid: `${name}-gone`, peer_workload_kind: kind, peer_workload_name: workload });

  test('uid mismatch: a restarted StatefulSet slot (same name, new uid) is an edge to its local card, not Unattributed', () => {
    // Rows stamped for argocd-redis-ha-server-1 under the uid it had before
    // its restart; the IP it held then is nobody's now.
    const t = from({ ...former('argocd-redis-ha-server-1', 'StatefulSet', 'argocd-redis-ha-server'), peer_uid: 'redis-uid-before-restart' }, '10.62.77.3');
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc], [t]);
    expect(external).toEqual([]);
    expect(remote(t)?.id).toBe(`${NS}-redis-ha`);
  });

  test('pruned replica of a local Deployment: routed to the local card through its stored workload', () => {
    // argocd-redis-ha-haproxy-7f9d9c8b5-old01 left pod_details 3 days after it
    // died; its rows stay for 14. Its name is in no listing.
    const t = from(former('argocd-redis-ha-haproxy-7f9d9c8b5-old01', 'Deployment', 'argocd-redis-ha-haproxy'), '10.62.55.9', { pod_name: server[0].pod_name, pod_ip: server[0].pod_ip, pod_port: '8080' });
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc], [t]);
    expect(external).toEqual([]);
    expect(remote(t)?.id).toBe(`${NS}-argocd-redis-ha-haproxy`);
  });

  test('a dead-but-listed replica of a local workload (uid matching) is an edge to its local card, not a same-namespace Service card', () => {
    // Still in pod_details (dead-pod window), gone from the live cards. On
    // main this drew external-svc-argocd-argocd-redis-ha-haproxy-in, a
    // Service card saying "ns: argocd" while viewing argocd.
    const deadHaproxy = argo('argocd-redis-ha-haproxy-b5fcfd449-r4tzd', '10.62.102.9', 'Deployment', 'argocd-redis-ha-haproxy', 'argocd-redis-ha-haproxy', 'haproxy-uid-r4tzd', { is_dead: true, time_stamp: '2026-09-27T00:00:00' });
    const t = from(
      { peer_kind: 'pod', peer_namespace: NS, peer_name: deadHaproxy.pod_name, peer_uid: 'haproxy-uid-r4tzd', peer_workload_kind: 'Deployment', peer_workload_name: 'argocd-redis-ha-haproxy' },
      deadHaproxy.pod_ip, { pod_name: server[0].pod_name, pod_ip: server[0].pod_ip, pod_port: '8080', time_stamp: '2026-09-26T10:00:00' },
    );
    const { external, remote } = buildFromNodes(cards([t]), [...listing, deadHaproxy], [haproxySvc], [t]);
    expect(external).toEqual([]);
    expect(remote(t)?.id).toBe(`${NS}-argocd-redis-ha-haproxy`);
  });

  test('the by-name Service merge never crosses namespaces: b/redis-0 does not join a/redis because a/redis-0 shares the name', () => {
    const mk = (ns: string, ip: string, uid: string) => pod({
      pod_name: 'redis-0', pod_ip: ip, pod_namespace: ns, pod_identity: 'redis', workload_kind: 'StatefulSet', workload_name: 'redis',
      workload_selector_labels: { app: 'redis' }, pod_obj: { metadata: { uid } }, started_at: '2026-09-20T00:00:00', time_stamp: '2026-09-28T16:00:00',
    });
    const svcFor = (ns: string, ip: string): ServiceInfo => ({ svc_ip: ip, svc_name: 'redis', svc_namespace: ns, service_spec: { spec: { selector: { app: 'redis' } } } });
    // a's Service last, so the name-keyed backing map points redis-0 at a's Service.
    const services = [haproxySvc, svcFor('b', '172.20.20.2'), svcFor('a', '172.20.20.1')];
    const t = from({ peer_kind: 'pod', peer_namespace: 'b', peer_name: 'redis-0', peer_uid: 'b-uid-before-restart', peer_workload_kind: 'StatefulSet', peer_workload_name: 'redis' }, '10.62.202.77');
    const { external, remote } = buildFromNodes(cards([t]), [...listing, mk('a', '10.62.201.1', 'a-uid'), mk('b', '10.62.202.1', 'b-uid-now')], services, [t]);
    expect(external.some((n) => n.id.startsWith('external-svc-a-'))).toBe(false);
    expect(external.map((n) => n.id)).toEqual(['external-b-redis-in']);
    expect(remote(t)?.id).toBe('external-b-redis-in');
  });

  test('a stored Service peer whose listing row has no ClusterIP still renders as a Service card on the observed address', () => {
    const headless: ServiceInfo = { svc_ip: '', svc_name: 'cassandra', svc_namespace: 'data', service_spec: { spec: { clusterIP: 'None', selector: { app: 'cassandra' } } } };
    const t = from({ peer_kind: 'service', peer_namespace: 'data', peer_name: 'cassandra', peer_uid: null, peer_workload_kind: null, peer_workload_name: null }, '172.20.30.9', { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '9042' });
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc, headless], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-svc-data-cassandra-out']);
    expect(external[0].pods.map((p) => p.pod_ip)).toEqual(['172.20.30.9']);
    expect(remote(t)?.id).toBe('external-svc-data-cassandra-out');
  });

  test('a stored peer with no local card of its own is a card under its stored workload, not Unattributed', () => {
    // The dex Deployment was removed from argocd; its former replica's rows remain.
    const t = from(former('argocd-dex-server-f54bfd56b-c5l46', 'Deployment', 'argocd-dex-server'), '10.62.66.1');
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc], [t]);
    expect(external.map((n) => n.id)).toEqual([`external-${NS}-argocd-dex-server-in`]);
    expect(external[0].label).toBe('argocd-dex-server');
    expect(external[0].pods).toHaveLength(1);
    expect(remote(t)?.id).toBe(`external-${NS}-argocd-dex-server-in`);
  });

  test('a same-named pod in ANOTHER namespace is not the local card', () => {
    const t = from(former('argocd-redis-ha-server-1', 'StatefulSet', 'argocd-redis-ha-server', 'argocd-staging'), '10.62.77.4');
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-argocd-staging-argocd-redis-ha-server-in']);
    expect(remote(t)?.id).toBe('external-argocd-staging-argocd-redis-ha-server-in');
  });

  test('cross-namespace pruned node agent: a card under its DaemonSet, hidden by the DaemonSets toggle like a live one', () => {
    const t = from(former('kguardian-controller-x7k2p', 'DaemonSet', 'kguardian-controller', 'kguardian', 'node'), '10.62.10.10', { pod_port: '8083' });
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-kguardian-kguardian-controller-in']);
    expect(external[0].label).toBe('kguardian-controller');
    expect(external[0].externalNamespace).toBe('kguardian');
    expect(external[0].pods[0].host_network).toBe(true);
    expect(isDaemonSetPeer(external[0])).toBe(true);
    expect(remote(t)?.id).toBe('external-kguardian-kguardian-controller-in');
    expect(external.some((n) => n.id.startsWith('external-unattributed'))).toBe(false);
  });

  test('cross-namespace pruned replica joins the card of its live sibling even when the identity name differs from the workload name', () => {
    // Local cards group by pod_identity (`argo-rollouts`); the row carries only
    // the workload (`platform-argo-rollouts`). Both must be one card.
    const live = pod({
      pod_name: 'platform-argo-rollouts-749d86dc66-g24j4', pod_ip: '10.62.120.1', pod_namespace: 'platform', pod_identity: 'argo-rollouts',
      workload_kind: 'Deployment', workload_name: 'platform-argo-rollouts', workload_selector_labels: { app: 'argo-rollouts' },
      pod_obj: { metadata: { uid: 'rollouts-live' } }, started_at: '2026-09-23T04:05:48', time_stamp: '2026-09-28T16:00:00',
    });
    const viaLive = from({ peer_kind: 'pod', peer_namespace: 'platform', peer_name: live.pod_name, peer_uid: 'rollouts-live', peer_workload_kind: 'Deployment', peer_workload_name: 'platform-argo-rollouts' }, live.pod_ip);
    const viaGone = from(former('platform-argo-rollouts-5d8f7c9b4-zzzzz', 'Deployment', 'platform-argo-rollouts', 'platform'), '10.62.120.77', { time_stamp: '2026-09-21T10:00:00' });
    // Placeholder rows first: grouping must not depend on row order.
    const traffic = [viaGone, viaLive];
    const { external, remote } = buildFromNodes(cards(traffic), [...listing, live], [haproxySvc], traffic);
    expect(external.map((n) => n.id)).toEqual(['external-platform-argo-rollouts-in']);
    expect(external[0].label).toBe('argo-rollouts');
    expect(external[0].traffic).toHaveLength(2);
    // The former replica is not a pod to count: only the live record is a member.
    expect(external[0].pods.map((p) => p.pod_name)).toEqual([live.pod_name]);
    expect(remote(viaGone)?.id).toBe('external-platform-argo-rollouts-in');
    expect(remote(viaLive)?.id).toBe('external-platform-argo-rollouts-in');
  });

  test('several former replicas of one cross-namespace workload are one card, one stand-in member, no pod count', () => {
    const a = from(former('coredns-7db6d8ff4d-aaaaa', 'Deployment', 'coredns', 'kube-system'), '10.62.200.1', { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '53' });
    const b = from(former('coredns-7db6d8ff4d-bbbbb', 'Deployment', 'coredns', 'kube-system'), '10.62.200.2', { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '53' });
    const { external } = buildFromNodes(cards([a, b]), listing, [haproxySvc], [a, b]);
    expect(external.map((n) => n.id)).toEqual(['external-kube-system-coredns-out']);
    expect(external[0].traffic).toHaveLength(2);
    expect(external[0].pods).toHaveLength(1);
    expect(external[0].peerKeys?.sort()).toEqual(['former:kube-system/coredns-7db6d8ff4d-aaaaa', 'former:kube-system/coredns-7db6d8ff4d-bbbbb']);
  });

  test('a stored dead peer whose record is still listed keeps rendering (a finished Job is a real peer)', () => {
    const job = pod({
      pod_name: 'argocd-backup-29271840-x7k2p', pod_ip: '10.62.130.5', pod_namespace: 'backups', is_dead: true,
      workload_kind: 'Job', workload_name: 'argocd-backup-29271840', workload_selector_labels: { 'batch.kubernetes.io/job-name': 'argocd-backup-29271840' },
      pod_obj: { metadata: { uid: 'job-uid' } }, started_at: '2026-09-26T13:00:00', time_stamp: '2026-09-26T13:10:00',
    });
    const t = from({ peer_kind: 'pod', peer_namespace: 'backups', peer_name: job.pod_name, peer_uid: 'job-uid', peer_workload_kind: 'Job', peer_workload_name: job.workload_name! }, job.pod_ip);
    const { external } = buildFromNodes(cards([t]), [...listing, job], [haproxySvc], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-backups-argocd-backup-29271840-in']);
    expect(external[0].pods).toEqual([job]);
  });

  test('Unattributed is kept for a row with NO stored identity that the guard excluded, and for a stored Service that is gone', () => {
    // 10.62.101.0 is redis-0's IP now; the flow predates redis-0's start.
    const guarded = from({ peer_kind: null, peer_namespace: null, peer_name: null, peer_uid: null, peer_workload_kind: null, peer_workload_name: null }, redis[0].pod_ip, { time_stamp: '2026-09-01T00:00:00' });
    const goneSvc = from({ peer_kind: 'service', peer_namespace: 'kube-system', peer_name: 'metrics-server', peer_uid: null, peer_workload_kind: null, peer_workload_name: null }, '172.20.99.99');
    const { external, remote } = buildFromNodes(cards([guarded, goneSvc]), listing, [haproxySvc], [guarded, goneSvc]);
    expect(external.map((n) => n.id)).toEqual(['external-unattributed-in']);
    expect(external[0].pods.map((p) => p.pod_ip).sort()).toEqual(['10.62.101.0', '172.20.99.99']);
    expect(remote(guarded)?.id).toBe('external-unattributed-in');
    expect(remote(goneSvc)?.id).toBe('external-unattributed-in');
  });

  test('a stored Service peer that still exists but has no selector (the kube API) is a Service card, not Unattributed', () => {
    const kubeApi: ServiceInfo = { svc_ip: '172.20.0.1', svc_name: 'kubernetes', svc_namespace: 'default', service_spec: { spec: { ports: [{ port: 443 }] } } };
    const t = from({ peer_kind: 'service', peer_namespace: 'default', peer_name: 'kubernetes', peer_uid: null, peer_workload_kind: null, peer_workload_name: null }, kubeApi.svc_ip, { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '443' });
    const { external, remote } = buildFromNodes(cards([t]), listing, [haproxySvc, kubeApi], [t]);
    expect(external.map((n) => n.id)).toEqual(['external-svc-default-kubernetes-out']);
    expect(external[0].label).toBe('kubernetes');
    expect(external[0].externalNamespace).toBe('default');
    expect(external[0].pods.map((p) => p.pod_ip)).toEqual([kubeApi.svc_ip]);
    expect(remote(t)?.id).toBe('external-svc-default-kubernetes-out');
  });

  describe('Service cards count live endpoints (DATA-05)', () => {
    const dns = (h: string, i: number, extra: Partial<PodInfo> = {}) => pod({
      pod_name: `coredns-7db6d8ff4d-${h}`, pod_ip: `10.62.200.${i}`, pod_namespace: 'kube-system', pod_identity: 'coredns',
      workload_kind: 'Deployment', workload_name: 'coredns', workload_selector_labels: { 'k8s-app': 'kube-dns' }, host_network: false,
      pod_obj: { metadata: { uid: `dns-${h}` } }, started_at: '2026-09-20T00:00:00', time_stamp: '2026-09-28T16:00:00', ...extra,
    });
    const alive = [dns('aaaaa', 1), dns('bbbbb', 2)];
    // Died 2 days ago: still in pod_details (3-day dead-pod window), no endpoint.
    const deadRetained = dns('ccccc', 3, { is_dead: true, time_stamp: '2026-09-26T20:00:00' });
    const kubeDns: ServiceInfo = { svc_ip: '172.20.0.10', svc_name: 'kube-dns', svc_namespace: 'kube-system', service_spec: { spec: { selector: { 'k8s-app': 'kube-dns' } } } };
    const to = (p: Pick<PodInfo, 'pod_name' | 'pod_ip'> & { uid: string }, at = AT) => from(
      { peer_kind: 'pod', peer_namespace: 'kube-system', peer_name: p.pod_name, peer_uid: p.uid, peer_workload_kind: 'Deployment', peer_workload_name: 'coredns' },
      p.pod_ip, { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '53', time_stamp: at },
    );

    test('2 live + 1 dead-but-listed + 1 pruned backing pod ⇒ one Service card, 2 members, all 4 rows on it', () => {
      const traffic = [
        to({ ...alive[0], uid: 'dns-aaaaa' }), to({ ...alive[1], uid: 'dns-bbbbb' }),
        to({ ...deadRetained, uid: 'dns-ccccc' }, '2026-09-26T10:00:00'),
        to({ pod_name: 'coredns-7db6d8ff4d-ddddd', pod_ip: '10.62.200.4', uid: 'dns-ddddd' }, '2026-09-22T10:00:00'), // pruned
      ];
      const { external, remote } = buildFromNodes(cards(traffic), [...listing, ...alive, deadRetained], [haproxySvc, kubeDns], traffic);
      expect(external.map((n) => n.id)).toEqual(['external-svc-kube-system-kube-dns-out']);
      const svc = external[0];
      expect(svc.label).toBe('kube-dns');
      expect(svc.pods.map((p) => p.pod_ip).sort()).toEqual(['10.62.200.1', '10.62.200.2']);
      expect(svc.pods.every((p) => p.workload_kind === 'Deployment' && p.host_network === false)).toBe(true);
      expect(svc.traffic).toHaveLength(4);
      traffic.forEach((t) => expect(remote(t)?.id).toBe('external-svc-kube-system-kube-dns-out'));
      expect(isDaemonSetPeer(svc)).toBe(false);
    });

    test('only dead backing pods known ⇒ the ClusterIP stands in, carrying their workload facts', () => {
      const exporter = pod({
        pod_name: 'node-exporter-k7f2p', pod_ip: '10.62.5.5', pod_namespace: 'monitoring', is_dead: true,
        workload_kind: 'DaemonSet', workload_name: 'node-exporter', workload_selector_labels: { app: 'node-exporter' }, host_network: true,
        pod_obj: { metadata: { uid: 'exp-uid' } }, started_at: '2026-09-20T00:00:00', time_stamp: '2026-09-27T00:00:00',
      });
      const exporterSvc: ServiceInfo = { svc_ip: '172.20.0.40', svc_name: 'node-exporter', svc_namespace: 'monitoring', service_spec: { spec: { selector: { app: 'node-exporter' } } } };
      const t = from({ peer_kind: 'node', peer_namespace: 'monitoring', peer_name: exporter.pod_name, peer_uid: 'exp-uid', peer_workload_kind: 'DaemonSet', peer_workload_name: 'node-exporter' }, exporter.pod_ip, { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '9100', time_stamp: '2026-09-26T10:00:00' });
      const { external } = buildFromNodes(cards([t]), [...listing, exporter], [haproxySvc, exporterSvc], [t]);
      expect(external.map((n) => n.id)).toEqual(['external-svc-monitoring-node-exporter-out']);
      expect(external[0].pods).toHaveLength(1);
      expect(external[0].pods[0].pod_ip).toBe(exporterSvc.svc_ip);
      expect(external[0].pods[0].workload_kind).toBe('DaemonSet');
      expect(isDaemonSetPeer(external[0])).toBe(true);
    });
  });

  describe('"Internet" is only for public addresses', () => {
    const noPeer = { peer_kind: null, peer_namespace: null, peer_name: null, peer_uid: null, peer_workload_kind: null, peer_workload_name: null };
    test('a private address no record holds is the Private network card, not Internet', () => {
      const vpc = from(noPeer, '10.62.139.244', { pod_name: server[0].pod_name, pod_ip: server[0].pod_ip, pod_port: '8080' });
      const cgnat = from(noPeer, '100.64.3.9', { pod_name: server[0].pod_name, pod_ip: server[0].pod_ip, pod_port: '8080' });
      const imds = from(noPeer, '169.254.169.254', { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '80' });
      const github = from(noPeer, '140.82.121.4', { traffic_type: 'EGRESS', pod_port: '0', traffic_in_out_port: '443' });
      const traffic = [vpc, cgnat, imds, github];
      const { external, remote } = buildFromNodes(cards(traffic), listing, [haproxySvc], traffic);
      expect(external.map((n) => n.id).sort()).toEqual(['external-internet-out', 'external-private-in', 'external-private-out']);
      const privIn = external.find((n) => n.id === 'external-private-in')!;
      expect(privIn.label).toBe('Private network');
      expect(privIn.externalNamespace).toBe('private');
      expect(privIn.tooltip).toBe(PRIVATE_PEER_TOOLTIP);
      // Like Internet, the aggregate lists every member IP on both directional cards.
      expect(privIn.pods.map((p) => p.pod_ip).sort()).toEqual(['10.62.139.244', '100.64.3.9', '169.254.169.254']);
      expect(privIn.traffic).toEqual([vpc, cgnat]);
      expect(isDaemonSetPeer(privIn)).toBe(false);
      const internet = external.find((n) => n.id === 'external-internet-out')!;
      expect(internet.pods.map((p) => p.pod_ip)).toEqual(['140.82.121.4']);
      expect(remote(vpc)?.id).toBe('external-private-in');
      expect(remote(cgnat)?.id).toBe('external-private-in');
      expect(remote(imds)?.id).toBe('external-private-out');
      expect(remote(github)?.id).toBe('external-internet-out');
    });
  });
});
