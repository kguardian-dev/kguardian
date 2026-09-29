// Service port -> backend targetPort, shared by the standard
// (networkPolicyGenerator) and Cilium (ciliumPolicyGenerator) builders.
// Mirrors advisor pkg/network/service_port.go; the comment text is pinned by
// the shared goldens (service_target_port).
//
// The controller records an egress flow from the socket, which under
// kube-proxy still holds the ClusterIP and the Service port: the DNAT to a
// backend pod happens later, in conntrack. NetworkPolicy and Cilium match the
// destination AFTER that translation, i.e. the backend pod's targetPort. A
// rule to the Service's selector that allowed the Service port would drop the
// traffic it was generated from whenever port != targetPort, so the observed
// port is mapped through spec.ports[] (port AND protocol) to its targetPort:
// a number as is, a name as the named port, omitted = the port. A named
// targetPort on a Service backed by host-network pods is resolved through the
// backends' containers[].ports[] (name AND protocol) to every distinct
// number: that rule's peer is an ipBlock / host entity, which has no
// endpoints to resolve a name against. No match, an unresolvable name, or no
// ports known keeps the observed port and the rule carries a comment.

import type { NetworkTraffic, PodInfo, ServiceInfo } from '../types';
import type { RowIdentityResolver, IdentitySources, TrafficIdentity } from './trafficIdentity';
import { apiClient } from '../services/api';
import { hostNetworkServiceBackends } from './hostNetwork';

/** One `service_spec.spec.ports[]` entry, as far as the mapping reads it. */
interface ServicePortSpec {
  port?: unknown;
  protocol?: unknown;
  targetPort?: unknown;
}

/** `spec.ports` of a stored Service manifest; empty when unknown. */
export function servicePortsOf(svc: ServiceInfo | null | undefined): ServicePortSpec[] {
  const spec = (svc?.service_spec as { spec?: { ports?: unknown } } | undefined)?.spec;
  return Array.isArray(spec?.ports) ? (spec.ports as ServicePortSpec[]) : [];
}

/** A Service-peer row's spec.ports, and its host-network backends (empty for ordinary pods). */
export interface RowServicePorts {
  ports: ServicePortSpec[];
  backends: readonly PodInfo[];
}

const protocolOrTCP = (p: unknown): unknown => (typeof p === 'string' && p !== '' ? p : 'TCP');

/** The containerPort numbers named `name` for `protocol` across `backends`, ascending, distinct. */
function backendPortNumbers(backends: readonly PodInfo[], name: string, protocol: string): string[] {
  const nums = new Set<number>();
  for (const b of backends) {
    const containers = (b.pod_obj?.spec as { containers?: { ports?: { name?: unknown; containerPort?: unknown; protocol?: unknown }[] }[] } | undefined)?.containers;
    for (const c of Array.isArray(containers) ? containers : []) {
      for (const cp of Array.isArray(c?.ports) ? c.ports : []) {
        const n = cp.containerPort;
        if (cp.name === name && protocolOrTCP(cp.protocol) === protocol && typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= 65535) nums.add(n);
      }
    }
  }
  return Array.from(nums).sort((a, b) => a - b).map(String);
}

/**
 * The port(s) a rule must allow for an egress flow observed on the Service
 * port `port`/`protocol` (decimal string, TCP/UDP/SCTP), and whether
 * spec.ports mapped it.
 */
export function mapServicePort(svc: RowServicePorts, port: string, protocol: string): { ports: string[]; mapped: boolean } {
  for (const sp of svc.ports) {
    if (sp.port !== Number(port) || protocolOrTCP(sp.protocol) !== protocol) continue;
    const t = sp.targetPort;
    if (typeof t === 'string' && t !== '') {
      if (svc.backends.length === 0) return { ports: [t], mapped: true };
      const nums = backendPortNumbers(svc.backends, t, protocol);
      return nums.length > 0 ? { ports: nums, mapped: true } : { ports: [port], mapped: false };
    }
    if (typeof t === 'number' && Number.isInteger(t) && t >= 1 && t <= 65535) return { ports: [String(t)], mapped: true };
    return { ports: [port], mapped: true };
  }
  return { ports: [port], mapped: false };
}

/** The `# ...` line above a rule for an observed Service port spec.ports could not map. */
export function unmappedServicePortComment(namespace: string, name: string, port: string, protocol: string): string {
  return `service ${namespace}/svc/${name}: port ${port}/${protocol} could not be mapped to a targetPort; allowing the Service port as observed`;
}

/** Port order of the reference (numeric ascending, then names, then protocol) over `PROTOCOL:port` keys. */
export function comparePortKeys(a: string, b: string): number {
  const [pa, na] = a.split(':');
  const [pb, nb] = b.split(':');
  const numA = /^[0-9]+$/.test(na);
  const numB = /^[0-9]+$/.test(nb);
  if (numA !== numB) return numA ? -1 : 1;
  if (numA && Number(na) !== Number(nb)) return Number(na) - Number(nb);
  if (!numA && na !== nb) return na < nb ? -1 : 1;
  return pa < pb ? -1 : pa > pb ? 1 : 0;
}

/**
 * The comment lines for a rule's unmapped Service ports (`PROTOCOL:port`
 * keys), in port order.
 */
export function unmappedServicePortComments(identity: TrafficIdentity, unmapped: ReadonlySet<string> | undefined): string[] {
  if (!unmapped || unmapped.size === 0 || !identity.svcName) return [];
  return Array.from(unmapped)
    .sort(comparePortKeys)
    .map((key) => {
      const [protocol, port] = key.split(':');
      return unmappedServicePortComment(identity.svcNamespace || 'default', identity.svcName!, port, protocol);
    });
}

/** A row whose OWN peer is a Service rendered by its selector (before the
 *  pod→Service collapse, which redirects rows already observed post-DNAT). */
export function isServiceSelectorPeer(identity: TrafficIdentity | undefined): boolean {
  return !!identity?.svcName && !!identity.svcSelector && !identity.svcNoSelector;
}

/**
 * The spec.ports (and host-network backends) of the Service each
 * Service-peer row was observed on, keyed by row. The record comes from the
 * resolver's listing, the supplied `services`, else `/svc/ip` (one read per
 * ClusterIP); it must still be the Service the row resolved to, and a failed
 * read is "unknown" (empty). Backends come from the resolver's pod listing,
 * else one `/pod/info` read.
 */
export async function servicePortsByRow(
  rows: readonly NetworkTraffic[],
  rowIdentity: ReadonlyMap<NetworkTraffic, TrafficIdentity>,
  resolver: RowIdentityResolver,
  sources: IdentitySources,
): Promise<Map<NetworkTraffic, RowServicePorts>> {
  let pods: Promise<readonly PodInfo[] | null> | undefined;
  const listPods = (): Promise<readonly PodInfo[] | null> => {
    if (resolver.pods) return Promise.resolve(resolver.pods);
    pods ??= apiClient.getAllPods().then((p) => (Array.isArray(p) ? p : null)).catch(() => null);
    return pods;
  };
  const byIp = new Map<string, Promise<ServiceInfo | null>>();
  const lookup = (ip: string): Promise<ServiceInfo | null> => {
    let p = byIp.get(ip);
    if (!p) {
      const listed = resolver.index?.servicesByIp.get(ip) ?? sources.services?.find((s) => s.svc_ip === ip);
      p = listed ? Promise.resolve(listed) : apiClient.getServiceByIP(ip).catch(() => null);
      byIp.set(ip, p);
    }
    return p;
  };
  const out = new Map<NetworkTraffic, RowServicePorts>();
  await Promise.all(rows.map(async (row) => {
    const identity = rowIdentity.get(row);
    const ip = row.traffic_in_out_ip;
    if (!ip || !isServiceSelectorPeer(identity) || row.traffic_type?.toLowerCase() !== 'egress') return;
    const svc = await lookup(ip);
    const same = svc && svc.svc_name === identity!.svcName && (svc.svc_namespace || undefined) === (identity!.svcNamespace || undefined);
    const ports = same ? servicePortsOf(svc) : [];
    // Backends matter only to resolve a named targetPort.
    const named = ports.some((p) => typeof p.targetPort === 'string' && p.targetPort !== '');
    const backends = named ? hostNetworkServiceBackends(await listPods(), identity!.svcNamespace, identity!.svcSelector) : [];
    out.set(row, { ports, backends });
  }));
  return out;
}
