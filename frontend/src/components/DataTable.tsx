import React, { useState, useMemo, useCallback } from 'react';
import type { NetworkTraffic, PodInfo, PodNodeData, ServiceInfo } from '../types';
import { ArrowRight, Activity, ChevronDown, ChevronRight, Filter, MousePointerClick, Inbox, Cpu } from 'lucide-react';
import { EmptyState } from './ui/EmptyState';
import {
  COMPUTE_KIND_LABEL,
  denominatorLabel,
  formatBytes,
  formatMicros,
  formatMillicores,
  formatPercent,
  hasComputeGauges,
  throttledRatio,
} from '../utils/compute';
import type { ComputeBlame, ComputeContainer } from '../types/compute';
import { describeDrop, isDrop } from '../utils/dropCause';
import { displaySyscallList } from '../utils/syscalls';
import { UNATTRIBUTED_PEER_TOOLTIP, buildPeerIndex, isPlaceholderPod, resolvePeer } from '../utils/peerResolution';

interface DataTableProps {
  selectedPod: PodNodeData | null;
  allPodsLookup: PodInfo[];
  services: ServiceInfo[];
}

interface TrafficIdentity {
  podName?: string;
  podIdentity?: string;
  podNamespace?: string;
  svcName?: string;
  svcNamespace?: string;
  /** The start-time guard excluded every pod that ever held the IP. */
  unattributed?: boolean;
  isExternal: boolean;
}

const WELL_KNOWN_PORTS: Record<string, string> = {
  '53': 'DNS', '80': 'HTTP', '443': 'HTTPS',
  '6443': 'K8s API', '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt',
  '5432': 'PostgreSQL', '3306': 'MySQL', '6379': 'Redis',
  '9090': 'Prometheus',
};

const getPortLabel = (port: string, protocol: string): string => {
  return WELL_KNOWN_PORTS[port] || `${port}/${protocol}`;
};

const TRAFFIC_PROFILE_MAX = 8;

const DataTable: React.FC<DataTableProps> = ({ selectedPod, allPodsLookup, services }) => {
  const [expandedSyscalls, setExpandedSyscalls] = useState<Set<number>>(new Set());
  // Every section starts collapsed. The panel shares the screen with the map
  // and a selection now focuses the graph as well as opening the card, so the
  // useful default is the three section headers and nothing else: the reader
  // opens the one they came for. Expanded-by-default meant a selection pushed
  // the map off screen on the way to a table nobody had asked for yet.
  const [isTrafficExpanded, setIsTrafficExpanded] = useState(false);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(false);
  const [isComputeExpanded, setIsComputeExpanded] = useState(false);
  // External nodes get a fourth block. It collapses like the rest: an
  // always-open grid of up to eight port cards above three shut headers would
  // be the one thing the panel still opened with.
  const [isProfileExpanded, setIsProfileExpanded] = useState(false);

  // Helper function to render identity with pod name or service name
  const renderIdentity = (identity: TrafficIdentity, ip: string | null | undefined, port: string | null) => {
    if (identity.svcName) {
      // Service
      return (
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-1.5">
            <span className="px-1.5 py-0.5 bg-hubble-accent/20 text-hubble-accent rounded text-xs font-medium">
              Svc
            </span>
            <span className="text-primary font-semibold">{identity.svcName}</span>
          </div>
          {identity.svcNamespace && (
            <span className="text-tertiary text-xs pl-1">ns: {identity.svcNamespace}</span>
          )}
          <span className="font-mono text-xs text-secondary pl-1">
            {ip}{port ? `:${port}` : ''}
          </span>
        </div>
      );
    } else if (identity.podName) {
      // Pod - show identity if available, otherwise pod name
      const displayName = identity.podIdentity || identity.podName;
      return (
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-1.5">
            <span className="px-1.5 py-0.5 bg-hubble-success/20 text-hubble-success rounded text-xs font-medium">
              Pod
            </span>
            <span className="text-primary font-semibold">{displayName}</span>
          </div>
          {identity.podNamespace && (
            <span className="text-tertiary text-xs pl-1">ns: {identity.podNamespace}</span>
          )}
          {identity.podIdentity && identity.podIdentity !== identity.podName && (
            <span className="font-mono text-xs text-tertiary pl-1">{identity.podName}</span>
          )}
          <span className="font-mono text-xs text-secondary pl-1">
            {ip}{port ? `:${port}` : ''}
          </span>
        </div>
      );
    } else {
      // External, or a former IP holder no live pod matched at flow time
      return (
        <div className="flex flex-col gap-0.5">
          <span
            className="px-1.5 py-0.5 bg-hubble-border/30 text-secondary rounded text-xs font-medium w-fit"
            title={identity.unattributed ? UNATTRIBUTED_PEER_TOOLTIP : undefined}
          >
            {identity.unattributed ? 'Unattributed' : 'External'}
          </span>
          <span className="font-mono text-xs text-secondary pl-1">
            {ip}{port ? `:${port}` : ''}
          </span>
        </div>
      );
    }
  };

  // Traffic filters
  const [decisionFilter, setDecisionFilter] = useState<'all' | 'ALLOW' | 'DROP'>('all');
  const [trafficTypeFilter, setTrafficTypeFilter] = useState<'all' | 'ingress' | 'egress'>('all');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [portFilter, setPortFilter] = useState<string>('all');

  // Pagination for large traffic tables
  const [trafficPage, setTrafficPage] = useState(0);
  const TRAFFIC_PAGE_SIZE = 100; // Show 100 rows at a time

  // Create lookup maps from allPodsLookup (all namespaces) for cross-namespace resolution
  const podLookupMaps = useMemo(() => {
    const byIp = new Map<string, PodInfo>();
    const byName = new Map<string, PodInfo>();

    allPodsLookup.forEach((pod) => {
      if (pod.pod_ip) byIp.set(pod.pod_ip, pod);
      if (pod.pod_name) byName.set(pod.pod_name, pod);
    });

    return { byIp, byName };
  }, [allPodsLookup]);

  // Build service ClusterIP lookup
  const svcLookupByIp = useMemo(() => {
    const map = new Map<string, ServiceInfo>();
    services.forEach((svc) => {
      if (svc.svc_ip) map.set(svc.svc_ip, svc);
    });
    return map;
  }, [services]);

  // Synchronous identity resolution using in-memory lookups only
  // Uses allPodsLookup (all namespaces) so cross-namespace traffic is correctly identified
  const resolveTrafficIdentity = useCallback((ip: string | null): TrafficIdentity => {
    if (!ip) {
      return { isExternal: true };
    }

    // Try to find pod by IP in our lookup map (spans all namespaces)
    const podInfo = podLookupMaps.byIp.get(ip);
    if (podInfo) {
      return {
        podName: podInfo.pod_name,
        podIdentity: podInfo.pod_identity || undefined,
        podNamespace: podInfo.pod_namespace || undefined,
        isExternal: false,
      };
    }

    // Try to find a matching service ClusterIP
    const svcInfo = svcLookupByIp.get(ip);
    if (svcInfo) {
      return {
        svcName: svcInfo.svc_name || undefined,
        svcNamespace: svcInfo.svc_namespace || undefined,
        isExternal: false,
      };
    }

    // If not found in any namespace, it's truly external
    return { isExternal: true };
  }, [podLookupMaps, svcLookupByIp]);

  // Memoize resolved identities for the local side (pod_ip) — by IP
  const resolvedIdentities = useMemo(() => {
    if (!selectedPod?.traffic) return new Map<string, TrafficIdentity>();

    const identities = new Map<string, TrafficIdentity>();
    const uniqueIPs = new Set<string>();
    selectedPod.traffic.forEach(t => {
      if (t.pod_ip) uniqueIPs.add(t.pod_ip);
    });

    uniqueIPs.forEach((ip) => {
      identities.set(ip, resolveTrafficIdentity(ip));
    });

    return identities;
  }, [selectedPod, resolveTrafficIdentity]);

  // The remote side is attributed per ROW (utils/peerResolution): the row's
  // stored peer_* first, else by IP guarded by the flow time — one IP can be
  // different peers at different times.
  const peerIndex = useMemo(() => buildPeerIndex(allPodsLookup, services), [allPodsLookup, services]);
  const remoteIdentities = useMemo(() => {
    const identities = new Map<NetworkTraffic, TrafficIdentity>();
    selectedPod?.traffic?.forEach((t) => {
      const peer = resolvePeer(t, peerIndex);
      switch (peer.kind) {
        case 'pod':
        case 'node':
          if (isPlaceholderPod(peer.pod)) { identities.set(t, { isExternal: true, unattributed: true }); break; }
          identities.set(t, {
            podName: peer.pod.pod_name,
            podIdentity: peer.pod.pod_identity || peer.pod.workload_name || undefined,
            podNamespace: peer.pod.pod_namespace || undefined,
            isExternal: false,
          });
          break;
        case 'service':
          identities.set(t, peer.svc
            ? { svcName: peer.name || undefined, svcNamespace: peer.namespace || undefined, isExternal: false }
            : { isExternal: true, unattributed: true });
          break;
        case 'unattributed':
          identities.set(t, { isExternal: true, unattributed: true });
          break;
        default:
          // No pod ever held the IP and it is no ClusterIP. Never derived
          // from a pod or Service that holds the IP today.
          identities.set(t, { isExternal: true });
      }
    });
    return identities;
  }, [selectedPod, peerIndex]);

  // Compute available protocols and ports for filter dropdowns
  const availableProtocols = useMemo(() => {
    if (!selectedPod?.traffic) return [];
    const protos = new Set<string>();
    selectedPod.traffic.forEach(t => {
      if (t.ip_protocol) protos.add(t.ip_protocol.toUpperCase());
    });
    return [...protos].sort();
  }, [selectedPod]);

  const availablePorts = useMemo(() => {
    if (!selectedPod?.traffic) return [];
    const ports = new Map<string, string>();
    selectedPod.traffic.forEach(t => {
      const port = t.traffic_in_out_port;
      if (port && port !== '0') {
        const label = WELL_KNOWN_PORTS[port] || port;
        ports.set(port, label);
      }
    });
    return [...ports.entries()]
      .sort((a, b) => a[1].localeCompare(b[1]));
  }, [selectedPod]);

  // Sections close again with the new selection: a section left open from the
  // previous workload would show that one's data under this one's name, and
  // closing re-answers "which section did I want" per workload rather than
  // carrying one choice across all of them.
  //
  // This resets DURING RENDER rather than in an effect, and that is the whole
  // point of it. An effect runs after paint, so the new workload's rows get
  // painted once inside the previous workload's open section before snapping
  // shut — precisely the frame this reset exists to prevent. React re-renders
  // immediately when a component sets its own state while rendering, so the
  // browser never sees the stale combination. Testing-library flushes effects
  // inside `act()` before any assertion, which is why the effect version
  // looked correct under test and flashed in the browser.
  const [lastPodId, setLastPodId] = useState(selectedPod?.id);
  if (selectedPod?.id !== lastPodId) {
    setLastPodId(selectedPod?.id);
    setIsTrafficExpanded(false);
    setIsSyscallsExpanded(false);
    setIsComputeExpanded(false);
    setIsProfileExpanded(false);
    setExpandedSyscalls(new Set());
    setDecisionFilter('all');
    setTrafficTypeFilter('all');
    setProtocolFilter('all');
    setPortFilter('all');
    setTrafficPage(0);
  }
  // Memoize expensive calculations
  const hasTraffic = useMemo(
    () => selectedPod?.traffic && selectedPod.traffic.length > 0,
    [selectedPod?.traffic]
  );

  // Allow/drop tally for the workload. Counted over every flow it has, not
  // over the filtered page: this answers "how is this workload doing", and a
  // number that moved every time you changed a filter would answer nothing.
  // The header's "(filtered / total)" already says how much you are looking at.
  const verdicts = useMemo(() => {
    const rows = selectedPod?.traffic ?? [];
    let allowed = 0;
    let dropped = 0;
    for (const t of rows) {
      if (isDrop(t.decision)) dropped += 1;
      else if (t.decision) allowed += 1;
    }
    const decided = allowed + dropped;
    return { allowed, dropped, decided, successPct: decided > 0 ? Math.round((allowed / decided) * 100) : null };
  }, [selectedPod?.traffic]);

  const hasSyscalls = useMemo(
    () => selectedPod?.syscalls && selectedPod.syscalls.length > 0,
    [selectedPod]
  );

  // Compute section (design D8): per-container rows + the blame list, from
  // the live rows usePodData merged onto the node. Only for gauged pods.
  const compute = selectedPod?.compute;
  const hasCompute = hasComputeGauges(compute);
  // Read off `compute` rather than `hasCompute`: the header renders for a
  // workload with no compute at all, and must still say "0 containers".
  const containerCount = compute?.containers.length ?? 0;
  const blame = useMemo(() => {
    if (!compute) return { rows: [] as Array<ComputeBlame & { victim: string }>, totalWaitNs: 0 };
    // One list across the pod's containers, largest wait first. The share is
    // over EVERY blame entry, not the ten shown, so the visible rows never
    // sum to 100% when a long tail was cut off.
    const all: Array<ComputeBlame & { victim: string }> = [];
    for (const c of compute.containers) {
      for (const b of c.blame ?? []) all.push({ ...b, victim: c.container });
    }
    const totalWaitNs = all.reduce((sum, b) => sum + b.wait_ns, 0);
    return { rows: all.sort((a, b) => b.wait_ns - a.wait_ns).slice(0, 10), totalWaitNs };
  }, [compute]);
  const blameRows = blame.rows;
  const totalWaitNs = blame.totalWaitNs;

  // Memoize filtered traffic to avoid recalculation on every render
  const filteredTraffic = useMemo(() => {
    if (!selectedPod?.traffic) return [];

    return selectedPod.traffic
      .filter(traffic => {
        if (decisionFilter !== 'all' && traffic.decision !== decisionFilter) {
          return false;
        }
        if (trafficTypeFilter !== 'all' && traffic.traffic_type?.toLowerCase() !== trafficTypeFilter) {
          return false;
        }
        if (protocolFilter !== 'all' && traffic.ip_protocol?.toUpperCase() !== protocolFilter) {
          return false;
        }
        if (portFilter !== 'all' && traffic.traffic_in_out_port !== portFilter) {
          return false;
        }
        return true;
      })
      // Hoist denied flows: a DROP is the security-relevant row, so it leads;
      // within each decision group, newest first.
      .sort((a, b) => {
        const aDrop = a.decision === 'DROP' ? 0 : 1;
        const bDrop = b.decision === 'DROP' ? 0 : 1;
        if (aDrop !== bDrop) return aDrop - bDrop;
        return new Date(b.time_stamp).getTime() - new Date(a.time_stamp).getTime();
      });
  }, [selectedPod, decisionFilter, trafficTypeFilter, protocolFilter, portFilter]);

  // Aggregate traffic by port/protocol for external node summary
  const trafficAggregation = useMemo(() => {
    if (!selectedPod?.isExternal || !selectedPod?.traffic?.length) return null;

    const byPortProto = new Map<string, { count: number; drops: number; protocol: string; port: string }>();

    selectedPod.traffic.forEach((t) => {
      const port = t.traffic_in_out_port && t.traffic_in_out_port !== '0' ? t.traffic_in_out_port : 'ephemeral';
      const proto = t.ip_protocol || 'TCP';
      const key = `${port}/${proto}`;
      if (!byPortProto.has(key)) {
        byPortProto.set(key, { count: 0, drops: 0, protocol: proto, port });
      }
      const entry = byPortProto.get(key)!;
      entry.count++;
      if (t.decision === 'DROP') entry.drops++;
    });

    return Array.from(byPortProto.values())
      .sort((a, b) => b.count - a.count);
  }, [selectedPod]);

  // Paginated traffic for rendering (only render current page)
  const paginatedTraffic = useMemo(() => {
    const start = trafficPage * TRAFFIC_PAGE_SIZE;
    const end = start + TRAFFIC_PAGE_SIZE;
    return filteredTraffic.slice(start, end);
  }, [filteredTraffic, trafficPage, TRAFFIC_PAGE_SIZE]);

  const totalPages = Math.ceil(filteredTraffic.length / TRAFFIC_PAGE_SIZE);

  if (!selectedPod) {
    return (
      <div className="py-8 flex items-center justify-center">
        <EmptyState
          icon={MousePointerClick}
          title="No workload selected"
          description="Select a node in the map to inspect its traffic, decisions, and observed syscalls."
          compact
        />
      </div>
    );
  }

  return (
    <div className="p-4 space-y-4">
      {/* No identity header. It cost a fixed block of vertical space at the
          top of a surface whose whole job is the three sections below, and
          the panel is opened by selecting a card that is right there on the
          map and highlighted as selected.
          Note the card does NOT repeat all of it: `ns:` renders only for
          external peers (PodNode gates it on `externalNamespace`) and
          replicas show as a count, not a list. Losing the namespace of a
          local workload from this surface is a deliberate trade for the
          space, not a duplicate being removed. */}

      {/* Traffic Profile Summary (external nodes only) */}
      {selectedPod.isExternal && trafficAggregation && trafficAggregation.length > 0 && (
        <div>
          <button
            onClick={() => setIsProfileExpanded(!isProfileExpanded)}
            aria-expanded={isProfileExpanded}
            className="w-full text-md font-semibold text-primary mb-3 flex items-center gap-2 hover:text-hubble-accent transition-colors"
          >
            {isProfileExpanded ? (
              <ChevronDown className="w-4 h-4 text-hubble-accent" />
            ) : (
              <ChevronRight className="w-4 h-4 text-hubble-accent" />
            )}
            Traffic Profile ({trafficAggregation.length})
            <span className="text-xs text-tertiary font-normal">(grouped by port/protocol)</span>
          </button>

          {isProfileExpanded && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
            {trafficAggregation.slice(0, TRAFFIC_PROFILE_MAX).map((entry) => (
              <div
                key={`${entry.port}/${entry.protocol}`}
                className="bg-hubble-dark rounded-surface border border-hubble-border p-3"
              >
                <div className="text-primary font-bold text-sm">
                  {getPortLabel(entry.port, entry.protocol)}
                </div>
                <div className="text-secondary text-xs">
                  {entry.count} connection{entry.count !== 1 ? 's' : ''}
                </div>
                {entry.drops > 0 && (
                  <div className="text-hubble-error text-xs">
                    {entry.drops} drop{entry.drops !== 1 ? 's' : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
          )}
          {isProfileExpanded && trafficAggregation.length > TRAFFIC_PROFILE_MAX && (
            <p className="text-xs text-tertiary mt-2">
              +{trafficAggregation.length - TRAFFIC_PROFILE_MAX} more port groups
            </p>
          )}
        </div>
      )}

      {/* Network Traffic Section */}
      <div>
        <button
          onClick={() => setIsTrafficExpanded(!isTrafficExpanded)}
          aria-expanded={isTrafficExpanded}
          className="w-full text-md font-semibold text-primary mb-3 flex items-center gap-2 hover:text-hubble-accent transition-colors"
        >
          {isTrafficExpanded ? (
            <ChevronDown className="w-4 h-4 text-hubble-success" />
          ) : (
            <ChevronRight className="w-4 h-4 text-hubble-success" />
          )}
          <ArrowRight className="w-4 h-4 text-hubble-success" />
          Network Traffic ({filteredTraffic.length} / {selectedPod.traffic?.length || 0})
        </button>

        {isTrafficExpanded && hasTraffic && (
          <>
            {/* Filter Controls */}
            <div className="mb-3 flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-secondary" />
                <span className="text-sm text-secondary">Filters:</span>
              </div>

              {/* Decision Filter */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-tertiary">Decision:</span>
                <select
                  value={decisionFilter}
                  onChange={(e) => {
                    setDecisionFilter(e.target.value as 'all' | 'ALLOW' | 'DROP');
                    setTrafficPage(0); // Reset to first page when filter changes
                  }}
                  className="bg-hubble-dark border border-hubble-border rounded px-2 py-1 text-xs text-secondary focus:outline-none focus:border-hubble-accent"
                >
                  <option value="all">All</option>
                  <option value="ALLOW">Allow</option>
                  <option value="DROP">Drop</option>
                </select>
              </div>

              {/* Traffic Type Filter */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-tertiary">Type:</span>
                <select
                  value={trafficTypeFilter}
                  onChange={(e) => {
                    setTrafficTypeFilter(e.target.value as 'all' | 'ingress' | 'egress');
                    setTrafficPage(0);
                  }}
                  className="bg-hubble-dark border border-hubble-border rounded px-2 py-1 text-xs text-secondary focus:outline-none focus:border-hubble-accent"
                >
                  <option value="all">All</option>
                  <option value="ingress">Ingress</option>
                  <option value="egress">Egress</option>
                </select>
              </div>

              {/* Protocol Filter */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-tertiary">Protocol:</span>
                <select
                  value={protocolFilter}
                  onChange={(e) => {
                    setProtocolFilter(e.target.value);
                    setTrafficPage(0);
                  }}
                  className="bg-hubble-dark border border-hubble-border rounded px-2 py-1 text-xs text-secondary focus:outline-none focus:border-hubble-accent"
                >
                  <option value="all">All</option>
                  {availableProtocols.map(proto => (
                    <option key={proto} value={proto}>{proto}</option>
                  ))}
                </select>
              </div>

              {/* Port Filter */}
              {availablePorts.length > 1 && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-tertiary">Port:</span>
                  <select
                    value={portFilter}
                    onChange={(e) => {
                      setPortFilter(e.target.value);
                      setTrafficPage(0);
                    }}
                    className="bg-hubble-dark border border-hubble-border rounded px-2 py-1 text-xs text-secondary focus:outline-none focus:border-hubble-accent"
                  >
                    <option value="all">All</option>
                    {availablePorts.map(([port, label]) => (
                      <option key={port} value={port}>{label === port ? port : `${label} (${port})`}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* Clear Filters Button */}
              {(decisionFilter !== 'all' || trafficTypeFilter !== 'all' || protocolFilter !== 'all' || portFilter !== 'all') && (
                <button
                  onClick={() => {
                    setDecisionFilter('all');
                    setTrafficTypeFilter('all');
                    setProtocolFilter('all');
                    setPortFilter('all');
                    setTrafficPage(0);
                  }}
                  className="text-xs text-hubble-accent hover:text-hubble-accent/80 underline"
                >
                  Clear filters
                </button>
              )}
            </div>

            <div className="bg-hubble-card rounded-surface border border-hubble-border overflow-hidden">
            {/* Verdict tally for the workload, not for the filtered page. */}
            {verdicts.decided > 0 && (
              <div className="flex items-center justify-end gap-4 mb-2 text-xs">
                <span className="text-secondary">
                  Allowed: <span className="text-hubble-success font-medium tabular-nums">{verdicts.allowed}</span>
                </span>
                <span className="text-secondary">
                  Dropped: <span className={`font-medium tabular-nums ${verdicts.dropped > 0 ? 'text-hubble-error' : 'text-secondary'}`}>{verdicts.dropped}</span>
                </span>
                {verdicts.successPct !== null && (
                  <span
                    className="text-secondary"
                    title="Share of decided flows that completed. A drop means a handshake never completed, which is not by itself a policy denial."
                  >
                    Ratio: <span className={`font-medium tabular-nums ${verdicts.successPct === 100 ? 'text-hubble-success' : 'text-hubble-warning'}`}>{verdicts.successPct}% completed</span>
                  </span>
                )}
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 z-10 bg-hubble-dark border-b border-hubble-border">
                  <tr className="text-left text-xs font-medium text-tertiary uppercase tracking-wide">
                    <th className="px-4 py-2">Direction</th>
                    <th className="px-4 py-2">Source</th>
                    <th className="px-4 py-2">Destination</th>
                    <th className="px-4 py-2">Protocol</th>
                    <th className="px-4 py-2">Summary</th>
                    <th className="px-4 py-2">Decision</th>
                    <th className="px-4 py-2">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedTraffic.map((traffic, index) => {
                    const remoteIdentity = remoteIdentities.get(traffic) || { isExternal: true };
                    const isIngress = traffic.traffic_type?.toLowerCase() === 'ingress';

                    // For external nodes, traffic records come from local pods.
                    // pod_ip/pod_name = the local pod, traffic_in_out_ip = the external node's IP.
                    // Direction is from the local pod's perspective, so we use
                    // the record's pod_ip to identify the local pod.
                    let source: TrafficIdentity;
                    let sourceIP: string | null;
                    let sourcePort: string | null;
                    let destination: TrafficIdentity;
                    let destinationIP: string | null;
                    let destinationPort: string | null;

                    if (selectedPod.isExternal) {
                      // Resolve the local pod from the record's pod_ip
                      const localPodIdentity = resolvedIdentities.get(traffic.pod_ip || '') || {
                        podName: traffic.pod_name || undefined,
                        podNamespace: traffic.pod_namespace || undefined,
                        isExternal: false,
                      };
                      const externalIdentity: TrafficIdentity = {
                        podName: selectedPod.pod.pod_name,
                        podIdentity: selectedPod.pod.pod_identity || undefined,
                        podNamespace: selectedPod.pod.pod_namespace || undefined,
                        isExternal: true,
                      };

                      if (isIngress) {
                        // Local pod received from external: external → local
                        source = remoteIdentity.isExternal ? externalIdentity : remoteIdentity;
                        sourceIP = traffic.traffic_in_out_ip;
                        sourcePort = traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' ? traffic.traffic_in_out_port : null;
                        destination = localPodIdentity;
                        destinationIP = traffic.pod_ip;
                        destinationPort = traffic.pod_port && traffic.pod_port !== '0' ? traffic.pod_port : null;
                      } else {
                        // Local pod sent to external: local → external
                        source = localPodIdentity;
                        sourceIP = traffic.pod_ip;
                        sourcePort = traffic.pod_port && traffic.pod_port !== '0' ? traffic.pod_port : null;
                        destination = remoteIdentity.isExternal ? externalIdentity : remoteIdentity;
                        destinationIP = traffic.traffic_in_out_ip;
                        destinationPort = traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' ? traffic.traffic_in_out_port : null;
                      }
                    } else {
                      // Standard local pod: selectedPod is "self"
                      const selfIdentity: TrafficIdentity = {
                        podName: selectedPod.pod.pod_name,
                        podIdentity: selectedPod.pod.pod_identity || undefined,
                        podNamespace: selectedPod.pod.pod_namespace || undefined,
                        isExternal: false,
                      };

                      if (isIngress) {
                        source = remoteIdentity;
                        sourceIP = traffic.traffic_in_out_ip;
                        sourcePort = traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' ? traffic.traffic_in_out_port : null;
                        destination = selfIdentity;
                        destinationIP = traffic.pod_ip;
                        destinationPort = traffic.pod_port && traffic.pod_port !== '0' ? traffic.pod_port : null;
                      } else {
                        source = selfIdentity;
                        sourceIP = traffic.pod_ip;
                        sourcePort = traffic.pod_port && traffic.pod_port !== '0' ? traffic.pod_port : null;
                        destination = remoteIdentity;
                        destinationIP = traffic.traffic_in_out_ip;
                        destinationPort = traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' ? traffic.traffic_in_out_port : null;
                      }
                    }

                    return (
                      <tr
                        key={traffic.uuid || index}
                        className={`border-b border-hubble-border hover:bg-hubble-dark/50 transition-colors ${
                          traffic.decision === 'DROP' ? 'bg-hubble-error/[0.06]' : ''
                        }`}
                      >
                        {/* Direction */}
                        <td className="px-4 py-2">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            isIngress
                              ? 'bg-hubble-success/20 text-hubble-success'
                              : 'bg-hubble-warning/20 text-hubble-warning'
                          }`}>
                            {isIngress ? 'Ingress' : 'Egress'}
                          </span>
                        </td>

                        {/* Source */}
                        <td className="px-4 py-2">
                          {renderIdentity(source, sourceIP, sourcePort)}
                        </td>

                        {/* Destination */}
                        <td className="px-4 py-2">
                          {renderIdentity(destination, destinationIP, destinationPort)}
                        </td>

                        {/* Protocol */}
                        <td className="px-4 py-2">
                          <span className="px-2 py-1 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                            {traffic.ip_protocol || 'TCP'}
                          </span>
                        </td>

                        {/* Summary: protocol and the port that was CONNECTED
                            TO, which is the one that names the service. The
                            row's own Source/Destination cells carry both ends
                            in full; this is the at-a-glance version. No TCP
                            flags: the probe observes whether a handshake
                            completed, never the individual segments. */}
                        <td className="px-4 py-2 font-mono text-xs text-secondary whitespace-nowrap tabular-nums">
                          {traffic.ip_protocol || 'TCP'}
                          {destinationPort ? ` :${destinationPort}` : ''}
                        </td>

                        {/* Decision */}
                        <td className="px-4 py-2">
                          {traffic.decision && (
                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                              traffic.decision === 'ALLOW'
                                ? 'bg-hubble-success/20 text-hubble-success'
                                : traffic.decision === 'DROP'
                                ? 'bg-hubble-error/20 text-hubble-error'
                                : 'bg-hubble-border/30 text-secondary'
                            }`}
                            /* A DROP row means an outbound handshake never
                               completed; the probe cannot see why. The
                               title carries the classification so the
                               badge stops implying a policy denied it. */
                            title={
                              isDrop(traffic.decision)
                                ? describeDrop(traffic.drop_cause, traffic.syn_retries).detail
                                : undefined
                            }>
                              {isDrop(traffic.decision)
                                ? describeDrop(traffic.drop_cause, traffic.syn_retries).short
                                : traffic.decision}
                            </span>
                          )}
                          {!traffic.decision && (
                            <span className="text-tertiary text-xs">-</span>
                          )}
                        </td>

                        {/* Timestamp */}
                        <td className="px-4 py-2 text-tertiary text-xs font-mono tabular-nums whitespace-nowrap">
                          {new Date(traffic.time_stamp).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="px-4 py-3 bg-hubble-dark border-t border-hubble-border flex items-center justify-between">
                <div className="text-xs text-secondary">
                  Showing {trafficPage * TRAFFIC_PAGE_SIZE + 1} - {Math.min((trafficPage + 1) * TRAFFIC_PAGE_SIZE, filteredTraffic.length)} of {filteredTraffic.length} results
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setTrafficPage(Math.max(0, trafficPage - 1))}
                    disabled={trafficPage === 0}
                    className="px-3 py-1 bg-hubble-card border border-hubble-border rounded text-xs text-secondary hover:bg-hubble-darker disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  <span className="text-xs text-tertiary">
                    Page {trafficPage + 1} of {totalPages}
                  </span>
                  <button
                    onClick={() => setTrafficPage(Math.min(totalPages - 1, trafficPage + 1))}
                    disabled={trafficPage >= totalPages - 1}
                    className="px-3 py-1 bg-hubble-card border border-hubble-border rounded text-xs text-secondary hover:bg-hubble-darker disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
          </>
        )}

        {isTrafficExpanded && hasTraffic && filteredTraffic.length === 0 && (
          <div className="bg-hubble-card rounded-surface border border-hubble-border">
            <EmptyState
              icon={Filter}
              title="No traffic matches these filters"
              description="Adjust or clear the filters above to see recorded flows."
              compact
            />
          </div>
        )}

        {isTrafficExpanded && !hasTraffic && (
          <div className="bg-hubble-card rounded-surface border border-hubble-border">
            <EmptyState
              icon={Inbox}
              title="No network traffic recorded"
              description="The controller has not observed any flows for this workload yet."
              compact
            />
          </div>
        )}
      </div>

      {/* Compute Section. The header renders whether or not this workload has
          compute data, and the same goes for System Calls below. The panel is
          three fixed sections: a section that disappears when its data is
          missing changes the panel's shape between one selection and the next,
          so there is nothing stable to aim at and "this workload has none"
          becomes indistinguishable from "this section does not exist". The
          empty state says which. */}
      <div data-testid="compute-section">
        <button
          onClick={() => setIsComputeExpanded(!isComputeExpanded)}
          aria-expanded={isComputeExpanded}
          className="w-full text-md font-semibold text-primary mb-3 flex items-center gap-2 hover:text-hubble-accent transition-colors"
        >
          {isComputeExpanded ? (
            <ChevronDown className="w-4 h-4 text-hubble-accent" />
          ) : (
            <ChevronRight className="w-4 h-4 text-hubble-accent" />
          )}
          <Cpu className="w-4 h-4 text-hubble-accent" />
          Compute ({containerCount} container{containerCount !== 1 ? 's' : ''})
          {compute && compute.findings.length > 0 && (
            <span className="ml-1 rounded-full bg-hubble-error/15 text-hubble-error text-xs font-medium px-2 py-0.5 tabular-nums">
              {compute.findings.length} finding{compute.findings.length !== 1 ? 's' : ''}
            </span>
          )}
        </button>

        {isComputeExpanded && !(hasCompute && compute) && (
          <div className="bg-hubble-card rounded-surface border border-hubble-border">
            <EmptyState
              icon={Cpu}
              title="No compute data for this workload"
              description="Compute metrics arrive from the node agent. A workload with no gauges is either unscheduled or on a node that is not reporting."
              compact
            />
          </div>
        )}

        {isComputeExpanded && hasCompute && compute && (
          <div className="space-y-3">
            {compute.findings.length > 0 && (
              <ul className="space-y-1">
                {compute.findings.map((f) => (
                  <li
                    key={`${f.kind}:${f.victim.container_uid}`}
                    className={`rounded-surface border px-3 py-2 text-xs ${
                      f.severity === 'critical'
                        ? 'border-hubble-error/30 bg-hubble-error/10 text-hubble-error'
                        : 'border-hubble-warning/30 bg-hubble-warning/10 text-hubble-warning'
                    }`}
                  >
                    <span className="font-semibold">{COMPUTE_KIND_LABEL[f.kind] ?? f.kind}</span>
                    <span className="text-secondary"> · {f.message}</span>
                  </li>
                ))}
              </ul>
            )}

            <div className="bg-hubble-card rounded-surface border border-hubble-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 z-10 bg-hubble-dark border-b border-hubble-border">
                    <tr className="text-left text-xs font-medium text-tertiary uppercase tracking-wide">
                      <th className="px-4 py-2">Container</th>
                      <th className="px-4 py-2">CPU</th>
                      <th className="px-4 py-2">CPU req / lim</th>
                      <th className="px-4 py-2" title="Share of CFS periods spent throttled by the container's own limit (design D3)">Throttled</th>
                      <th className="px-4 py-2" title="cpu.pressure some / full avg10">CPU PSI</th>
                      <th className="px-4 py-2">Memory</th>
                      <th className="px-4 py-2">Mem req / lim</th>
                      <th className="px-4 py-2" title="memory.pressure some / full avg10">Mem PSI</th>
                      <th className="px-4 py-2" title="Run-queue latency p99 over the sample (scheduler probe)">p99 wait</th>
                    </tr>
                  </thead>
                  <tbody>
                    {compute.containers.map((c: ComputeContainer) => {
                      const ratio = throttledRatio(c);
                      return (
                        <tr key={c.container_uid} className="border-b border-hubble-border hover:bg-hubble-dark/50 transition-colors">
                          <td className="px-4 py-2 font-mono text-xs text-primary">
                            {c.container}
                            {selectedPod.pods.length > 1 && <div className="text-tertiary">{c.pod_name}</div>}
                          </td>
                          <td className="px-4 py-2 font-mono text-xs tabular-nums text-secondary">{formatMillicores(c.cpu_usage_millis)}</td>
                          <td className="px-4 py-2 font-mono text-xs tabular-nums text-tertiary">
                            {formatMillicores(c.cpu_request_millis)} / {formatMillicores(c.cpu_limit_millis)}
                          </td>
                          <td className={`px-4 py-2 font-mono text-xs tabular-nums ${ratio !== null && ratio >= 0.25 ? 'text-hubble-warning' : 'text-secondary'}`}>
                            {ratio === null ? '—' : formatPercent(ratio * 100)}
                          </td>
                          <td className={`px-4 py-2 font-mono text-xs tabular-nums ${c.cpu_psi_some10 >= 20 ? 'text-hubble-error' : 'text-secondary'}`}>
                            {formatPercent(c.cpu_psi_some10, 1)} / {formatPercent(c.cpu_psi_full10, 1)}
                          </td>
                          <td className="px-4 py-2 font-mono text-xs tabular-nums text-secondary">{formatBytes(c.mem_working_set)}</td>
                          <td className="px-4 py-2 font-mono text-xs tabular-nums text-tertiary">
                            {formatBytes(c.mem_request)} / {formatBytes(c.mem_limit)}
                          </td>
                          <td className={`px-4 py-2 font-mono text-xs tabular-nums ${c.mem_psi_some10 >= 10 ? 'text-hubble-error' : 'text-secondary'}`}>
                            {formatPercent(c.mem_psi_some10, 1)} / {formatPercent(c.mem_psi_full10, 1)}
                          </td>
                          <td className="px-4 py-2 font-mono text-xs tabular-nums text-secondary" title={c.runq_p99_us === null ? 'Scheduler probe not loaded on this node' : undefined}>
                            {formatMicros(c.runq_p99_us)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div className="px-4 py-2 bg-hubble-dark border-t border-hubble-border text-xs text-tertiary">
                Pod gauge: {formatMillicores(compute.cpuMillis)} of {formatMillicores(compute.cpuCapacityMillis)} CPU {denominatorLabel(compute.cpuDenominator)} ·{' '}
                {formatBytes(compute.memBytes)} of {formatBytes(compute.memCapacityBytes)} memory {denominatorLabel(compute.memDenominator)}
              </div>
            </div>

            {blameRows.length > 0 && (
              <div className="bg-hubble-card rounded-surface border border-hubble-border overflow-hidden" data-testid="compute-blame">
                <div className="px-4 py-2 bg-hubble-dark border-b border-hubble-border text-xs font-medium text-tertiary uppercase tracking-wide">
                  Blame — who was on the CPU while this pod waited
                </div>
                <table className="w-full text-sm">
                  <thead className="border-b border-hubble-border">
                    <tr className="text-left text-xs font-medium text-tertiary uppercase tracking-wide">
                      <th className="px-4 py-2">Culprit</th>
                      <th className="px-4 py-2">Kind</th>
                      <th className="px-4 py-2">Victim</th>
                      <th className="px-4 py-2">Share</th>
                      <th className="px-4 py-2">Wait</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blameRows.map((b) => (
                      <tr key={`${b.victim}:${b.cgroup_id}`} className="border-b border-hubble-border">
                        <td className="px-4 py-2 font-mono text-xs text-primary">{b.ref}</td>
                        <td className="px-4 py-2">
                          <span className={`px-2 py-0.5 rounded text-xs ${b.kind === 'pod' ? 'bg-hubble-error/15 text-hubble-error' : 'bg-hubble-border/30 text-secondary'}`}>{b.kind}</span>
                        </td>
                        <td className="px-4 py-2 font-mono text-xs text-secondary">{b.victim}</td>
                        <td className="px-4 py-2 font-mono text-xs tabular-nums text-secondary">
                          {totalWaitNs > 0 ? formatPercent((b.wait_ns / totalWaitNs) * 100) : '—'}
                        </td>
                        <td className="px-4 py-2 font-mono text-xs tabular-nums text-secondary">{formatMicros(b.wait_ns / 1000)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Syscalls Section */}
      <div>
        <button
          onClick={() => setIsSyscallsExpanded(!isSyscallsExpanded)}
          aria-expanded={isSyscallsExpanded}
          className="w-full text-md font-semibold text-primary mb-3 flex items-center gap-2 hover:text-hubble-accent transition-colors"
        >
          {isSyscallsExpanded ? (
            <ChevronDown className="w-4 h-4 text-hubble-warning" />
          ) : (
            <ChevronRight className="w-4 h-4 text-hubble-warning" />
          )}
          <Activity className="w-4 h-4 text-hubble-warning" />
          System Calls
        </button>

        {isSyscallsExpanded && !hasSyscalls && (
          <div className="bg-hubble-card rounded-surface border border-hubble-border">
            <EmptyState
              icon={Activity}
              title="No syscalls recorded"
              description="Syscall capture has not reported for this workload yet. Start a capture from the Workloads view (Seccomp) to collect them."
              compact
            />
          </div>
        )}

        {isSyscallsExpanded && hasSyscalls && (
          <div className="bg-hubble-card rounded-surface border border-hubble-border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-hubble-dark border-b border-hubble-border">
                <tr className="text-left text-xs font-medium text-tertiary uppercase tracking-wide">
                  <th className="px-4 py-2">Architecture</th>
                  <th className="px-4 py-2">Syscalls</th>
                  <th className="px-4 py-2">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {selectedPod.syscalls?.map((syscall, index) => {
                  // Sorted + de-duplicated: capture emits in observation
                  // order, which varies between pods and refreshes; the
                  // collapsed 10-chip preview must show a stable prefix.
                  const syscallList = displaySyscallList(syscall.syscalls);
                  const isExpanded = expandedSyscalls.has(index);
                  const displayedSyscalls = isExpanded ? syscallList : syscallList.slice(0, 10);

                  const toggleExpanded = () => {
                    setExpandedSyscalls(prev => {
                      const newSet = new Set(prev);
                      if (newSet.has(index)) {
                        newSet.delete(index);
                      } else {
                        newSet.add(index);
                      }
                      return newSet;
                    });
                  };

                  return (
                    <tr
                      key={index}
                      className="border-b border-hubble-border hover:bg-hubble-dark/50 transition-colors"
                    >
                      <td className="px-4 py-2 text-secondary">
                        <span className="px-2 py-1 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                          {syscall.arch}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-secondary">
                        <div className="flex flex-wrap gap-1">
                          {displayedSyscalls.map((sc, i) => (
                            <span key={i} className="px-2 py-1 bg-hubble-warning/20 text-hubble-warning rounded text-xs font-mono">
                              {sc.trim()}
                            </span>
                          ))}
                          {syscallList.length > 10 && (
                            <button
                              onClick={toggleExpanded}
                              className="px-2 py-1 bg-hubble-card border border-hubble-border text-secondary rounded text-xs hover:bg-hubble-dark
                                         transition-colors cursor-pointer"
                            >
                              {isExpanded
                                ? 'Show less'
                                : `+${syscallList.length - 10} more`
                              }
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-2 text-tertiary text-xs font-mono tabular-nums whitespace-nowrap">
                        {new Date(syscall.time_stamp).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
        )}
      </div>
    </div>
  );
};

export default DataTable;
