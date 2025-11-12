import React, { useState, useEffect, useMemo, useCallback } from 'react';
import type { PodNodeData } from '../types';
import { ArrowRight, Activity, ChevronDown, ChevronRight, Filter } from 'lucide-react';

interface DataTableProps {
  selectedPod: PodNodeData | null;
  allPods: PodNodeData[];
}

interface TrafficIdentity {
  podName?: string;
  podIdentity?: string;
  podNamespace?: string;
  svcName?: string;
  svcNamespace?: string;
  isExternal: boolean;
}

const DataTable: React.FC<DataTableProps> = ({ selectedPod, allPods }) => {
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
          <span className="px-1.5 py-0.5 bg-gray-500/20 text-gray-400 rounded text-xs font-medium w-fit">
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

  // Pagination for large traffic tables
  const [trafficPage, setTrafficPage] = useState(0);
  const TRAFFIC_PAGE_SIZE = 100; // Show 100 rows at a time

  // Create lookup maps from allPods (memoized to avoid recalculation)
  const podLookupMaps = useMemo(() => {
    const byIp = new Map<string, PodNodeData>();
    const byName = new Map<string, PodNodeData>();

    allPods.forEach((pod) => {
      // Map by IP for backward compatibility
      if (pod.pod.pod_ip) {
        byIp.set(pod.pod.pod_ip, pod);
      }
      // Map by name - more reliable for traffic lookups
      if (pod.pod.pod_name) {
        byName.set(pod.pod.pod_name, pod);
      }
      // Map all pods in the identity group
      pod.pods?.forEach((p) => {
        if (p.pod_ip) byIp.set(p.pod_ip, pod);
        if (p.pod_name) byName.set(p.pod_name, pod);
      });
    });

    return { byIp, byName };
  }, [allPods]);

  // Synchronous identity resolution using in-memory lookups only
  // No API calls, no state updates, no memory leaks
  const resolveTrafficIdentity = useCallback((ip: string | null): TrafficIdentity => {
    if (!ip) {
      return { isExternal: true };
    }

    // Try to find pod by IP in our lookup map
    const podData = podLookupMaps.byIp.get(ip);
    if (podData) {
      return {
        podName: podData.pod.pod_name,
        podIdentity: podData.pod.pod_identity || undefined,
        podNamespace: podData.pod.pod_namespace || undefined,
        isExternal: false,
      };
    }

    // If not found in our pods, it's external (service or internet)
    return { isExternal: true };
  }, [podLookupMaps]);

  // Memoize resolved identities map - recalculate only when traffic or pods change
  const resolvedIdentities = useMemo(() => {
    if (!selectedPod?.traffic) return new Map<string, TrafficIdentity>();

    const identities = new Map<string, TrafficIdentity>();
    const uniqueIPs = new Set(selectedPod.traffic.map(t => t.traffic_in_out_ip).filter(Boolean));

    uniqueIPs.forEach((ip) => {
      if (ip) {
        identities.set(ip, resolveTrafficIdentity(ip));
      }
    });

    return identities;
  }, [selectedPod?.traffic, resolveTrafficIdentity]);

  // Reset expanded state, filters, and pagination when pod changes
  useEffect(() => {
    setExpandedSyscalls(new Set());
    setDecisionFilter('all');
    setTrafficTypeFilter('all');
    setTrafficPage(0);
  }, [selectedPod?.id]);
  // Memoize expensive calculations
  const hasTraffic = useMemo(
    () => selectedPod?.traffic && selectedPod.traffic.length > 0,
    [selectedPod?.traffic]
  );

  const hasSyscalls = useMemo(
    () => selectedPod?.syscalls && selectedPod.syscalls.length > 0,
    [selectedPod?.syscalls]
  );

  const identityName = useMemo(
    () => selectedPod?.pod.pod_identity || selectedPod?.pod.pod_name || '',
    [selectedPod?.pod.pod_identity, selectedPod?.pod.pod_name]
  );

  // Memoize filtered traffic to avoid recalculation on every render
  const filteredTraffic = useMemo(() => {
    if (!selectedPod?.traffic) return [];

    return selectedPod.traffic.filter(traffic => {
      // Filter by decision
      if (decisionFilter !== 'all' && traffic.decision !== decisionFilter) {
        return false;
      }

      // Filter by traffic type
      if (trafficTypeFilter !== 'all' && traffic.traffic_type?.toLowerCase() !== trafficTypeFilter) {
        return false;
      }

      return true;
    });
  }, [selectedPod?.traffic, decisionFilter, trafficTypeFilter]);

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
          <div>
            <span className="text-tertiary">Namespace:</span>
            <span className="ml-2 text-secondary">{selectedPod.pod.pod_namespace || 'default'}</span>
          </div>
          {selectedPod.pods && selectedPod.pods.length > 0 && (
            <div>
              <span className="text-tertiary">Pods ({selectedPod.pods.length}):</span>
              <div className="ml-2 mt-1 flex flex-wrap gap-2">
                {selectedPod.pods.map((pod, index) => (
                  <span key={index} className="px-2 py-1 bg-hubble-dark text-secondary font-mono text-xs rounded border border-hubble-border">
                    {pod.pod_name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

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
                    setTrafficPage(0); // Reset to first page when filter changes
                  }}
                  className="bg-hubble-dark border border-hubble-border rounded px-2 py-1 text-xs text-secondary focus:outline-none focus:border-hubble-accent"
                >
                  <option value="all">All</option>
                  <option value="ingress">Ingress</option>
                  <option value="egress">Egress</option>
                </select>
              </div>

              {/* Clear Filters Button */}
              {(decisionFilter !== 'all' || trafficTypeFilter !== 'all') && (
                <button
                  onClick={() => {
                    setDecisionFilter('all');
                    setTrafficTypeFilter('all');
                    setTrafficPage(0); // Reset to first page
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

                    // Determine source and destination based on traffic direction
                    const source: TrafficIdentity = isIngress ? remoteIdentity : {
                      podName: selectedPod.pod.pod_name,
                      podIdentity: selectedPod.pod.pod_identity || undefined,
                      podNamespace: selectedPod.pod.pod_namespace || undefined,
                      isExternal: false
                    };
                    const sourceIP = isIngress ? traffic.traffic_in_out_ip : traffic.pod_ip;
                    const sourcePort = isIngress
                      ? (traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' ? traffic.traffic_in_out_port : null)
                      : (traffic.pod_port && traffic.pod_port !== '0' ? traffic.pod_port : null);

                    const destination: TrafficIdentity = isIngress ? {
                      podName: selectedPod.pod.pod_name,
                      podIdentity: selectedPod.pod.pod_identity || undefined,
                      podNamespace: selectedPod.pod.pod_namespace || undefined,
                      isExternal: false
                    } : remoteIdentity;
                    const destinationIP = isIngress ? traffic.pod_ip : traffic.traffic_in_out_ip;
                    const destinationPort = isIngress
                      ? (traffic.pod_port && traffic.pod_port !== '0' ? traffic.pod_port : null)
                      : (traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' ? traffic.traffic_in_out_port : null);

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
                                ? 'bg-red-500/20 text-red-400'
                                : 'bg-gray-500/20 text-gray-400'
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
