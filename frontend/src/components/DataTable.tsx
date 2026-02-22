import React, { useState, useEffect, useMemo, useCallback } from 'react';
import type { PodInfo, PodNodeData, ServiceInfo } from '../types';
import { ArrowRight, Activity, ChevronDown, ChevronRight, Filter } from 'lucide-react';

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
  const [isTrafficExpanded, setIsTrafficExpanded] = useState(true);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(true);

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
      // External
      return (
        <div className="flex flex-col gap-0.5">
          <span className="px-1.5 py-0.5 bg-hubble-border/30 text-secondary rounded text-xs font-medium w-fit">
            External
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

  // Memoize resolved identities map - recalculate only when traffic or pods change
  // Resolves both remote IPs (traffic_in_out_ip) and local pod IPs (pod_ip)
  const resolvedIdentities = useMemo(() => {
    if (!selectedPod?.traffic) return new Map<string, TrafficIdentity>();

    const identities = new Map<string, TrafficIdentity>();
    const uniqueIPs = new Set<string>();
    selectedPod.traffic.forEach(t => {
      if (t.traffic_in_out_ip) uniqueIPs.add(t.traffic_in_out_ip);
      if (t.pod_ip) uniqueIPs.add(t.pod_ip);
    });

    uniqueIPs.forEach((ip) => {
      identities.set(ip, resolveTrafficIdentity(ip));
    });

    return identities;
  }, [selectedPod, resolveTrafficIdentity]);

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

  // Reset expanded state, filters, and pagination when pod changes
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect */
    setExpandedSyscalls(new Set());
    setDecisionFilter('all');
    setTrafficTypeFilter('all');
    setProtocolFilter('all');
    setPortFilter('all');
    setTrafficPage(0);
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [selectedPod?.id]);
  // Memoize expensive calculations
  const hasTraffic = useMemo(
    () => selectedPod?.traffic && selectedPod.traffic.length > 0,
    [selectedPod?.traffic]
  );

  const hasSyscalls = useMemo(
    () => selectedPod?.syscalls && selectedPod.syscalls.length > 0,
    [selectedPod]
  );

  const identityName = useMemo(
    () => selectedPod?.label || selectedPod?.pod.pod_identity || selectedPod?.pod.pod_name || '',
    [selectedPod]
  );

  // Memoize filtered traffic to avoid recalculation on every render
  const filteredTraffic = useMemo(() => {
    if (!selectedPod?.traffic) return [];

    return selectedPod.traffic.filter(traffic => {
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
      <div className="h-full flex items-center justify-center text-tertiary">
        <p>Select a pod to view details</p>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      {/* Identity Information Header */}
      <div className="bg-hubble-card p-4 rounded-lg border border-hubble-border">
        <h3 className="text-lg font-semibold text-primary mb-2">
          {identityName}
        </h3>
        <div className="text-sm space-y-2">
          {selectedPod.externalNamespace !== 'internet' && (
            <div>
              <span className="text-tertiary">Namespace:</span>
              <span className="ml-2 text-secondary">{selectedPod.pod.pod_namespace || 'default'}</span>
            </div>
          )}
          {selectedPod.pods && selectedPod.pods.length > 0 && (
            <div>
              <span className="text-tertiary">{selectedPod.isExternal ? (selectedPod.externalNamespace === 'internet' ? 'IPs' : 'Pods') : 'Replicas'} ({selectedPod.pods.length}):</span>
              <div className="ml-2 mt-1 flex flex-wrap gap-2">
                {selectedPod.pods.map((pod) => (
                  <span key={pod.pod_name} className="px-2 py-1 bg-hubble-dark text-secondary font-mono text-xs rounded border border-hubble-border">
                    {pod.pod_name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Traffic Profile Summary (external nodes only) */}
      {selectedPod.isExternal && trafficAggregation && trafficAggregation.length > 0 && (
        <div>
          <h4 className="text-md font-semibold text-primary mb-1">Traffic Profile</h4>
          <p className="text-xs text-tertiary mb-3">(grouped by port/protocol)</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
            {trafficAggregation.slice(0, TRAFFIC_PROFILE_MAX).map((entry) => (
              <div
                key={`${entry.port}/${entry.protocol}`}
                className="bg-hubble-dark rounded-lg border border-hubble-border p-3"
              >
                <div className="text-primary font-bold text-sm">
                  {getPortLabel(entry.port, entry.protocol)}
                </div>
                <div className="text-secondary text-xs">
                  {entry.count} connection{entry.count !== 1 ? 's' : ''}
                </div>
                {entry.drops > 0 && (
                  <div className="text-red-400 text-xs">
                    {entry.drops} drop{entry.drops !== 1 ? 's' : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
          {trafficAggregation.length > TRAFFIC_PROFILE_MAX && (
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

            <div className="bg-hubble-card rounded-lg border border-hubble-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-hubble-dark border-b border-hubble-border">
                  <tr>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Direction</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Source</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Destination</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Protocol</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Decision</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedTraffic.map((traffic, index) => {
                    const remoteIdentity = resolvedIdentities.get(traffic.traffic_in_out_ip || '') || { isExternal: true };
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
                        className="border-b border-hubble-border hover:bg-hubble-dark/50 transition-colors"
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

                        {/* Decision */}
                        <td className="px-4 py-2">
                          {traffic.decision && (
                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                              traffic.decision === 'ALLOW'
                                ? 'bg-hubble-success/20 text-hubble-success'
                                : traffic.decision === 'DROP'
                                ? 'bg-hubble-error/20 text-hubble-error'
                                : 'bg-hubble-border/30 text-secondary'
                            }`}>
                              {traffic.decision}
                            </span>
                          )}
                          {!traffic.decision && (
                            <span className="text-tertiary text-xs">-</span>
                          )}
                        </td>

                        {/* Timestamp */}
                        <td className="px-4 py-2 text-tertiary text-xs">
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
          <div className="bg-hubble-card p-4 rounded-lg border border-hubble-border text-tertiary text-sm">
            No traffic matches the selected filters. Try adjusting or clearing the filters.
          </div>
        )}

        {isTrafficExpanded && !hasTraffic && (
          <div className="bg-hubble-card p-4 rounded-lg border border-hubble-border text-tertiary text-sm">
            No network traffic recorded
          </div>
        )}
      </div>

      {/* Syscalls Section */}
      {hasSyscalls && (
        <div>
          <button
            onClick={() => setIsSyscallsExpanded(!isSyscallsExpanded)}
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

          {isSyscallsExpanded && (
            <div className="bg-hubble-card rounded-lg border border-hubble-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-hubble-dark border-b border-hubble-border">
                  <tr>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Architecture</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Syscalls</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedPod.syscalls?.map((syscall, index) => {
                    const syscallList = syscall.syscalls.split(',').filter(s => s.trim());
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
                        <td className="px-4 py-2 text-tertiary text-xs">
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
      )}
    </div>
  );
};

export default DataTable;
