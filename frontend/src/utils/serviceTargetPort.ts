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
// a number as is, a name as the named port, omitted = the port. No match, or
// no ports known, keeps the observed port and the rule carries a comment.

import type { NetworkTraffic, ServiceInfo } from '../types';
import type { RowIdentityResolver, IdentitySources, TrafficIdentity } from './trafficIdentity';
import { apiClient } from '../services/api';

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

/**
 * The port a rule must allow for an egress flow observed on the Service port
 * `port`/`protocol` (decimal string, TCP/UDP/SCTP), and whether spec.ports
 * mapped it.
 */
export function mapServicePort(ports: readonly ServicePortSpec[], port: string, protocol: string): { port: string; mapped: boolean } {
  for (const sp of ports) {
    const spProtocol = typeof sp.protocol === 'string' && sp.protocol !== '' ? sp.protocol : 'TCP';
    if (sp.port !== Number(port) || spProtocol !== protocol) continue;
    const t = sp.targetPort;
    if (typeof t === 'string' && t !== '') return { port: t, mapped: true };
    if (typeof t === 'number' && Number.isInteger(t) && t >= 1 && t <= 65535) return { port: String(t), mapped: true };
    return { port, mapped: true };
  }
  return { port, mapped: false };
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
 * The spec.ports of the Service each Service-peer row was observed on,
 * keyed by row. The record comes from the resolver's listing, the supplied
 * `services`, else `/svc/ip` (one read per ClusterIP); it must still be the
 * Service the row resolved to, and a failed read is "unknown" (empty).
 */
export async function servicePortsByRow(
  rows: readonly NetworkTraffic[],
  rowIdentity: ReadonlyMap<NetworkTraffic, TrafficIdentity>,
  resolver: RowIdentityResolver,
  sources: IdentitySources,
): Promise<Map<NetworkTraffic, ServicePortSpec[]>> {
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
  const out = new Map<NetworkTraffic, ServicePortSpec[]>();
  await Promise.all(rows.map(async (row) => {
    const identity = rowIdentity.get(row);
    const ip = row.traffic_in_out_ip;
    if (!ip || !isServiceSelectorPeer(identity) || row.traffic_type?.toLowerCase() !== 'egress') return;
    const svc = await lookup(ip);
    const same = svc && svc.svc_name === identity!.svcName && (svc.svc_namespace || undefined) === (identity!.svcNamespace || undefined);
    out.set(row, same ? servicePortsOf(svc) : []);
  }));
  return out;
}
