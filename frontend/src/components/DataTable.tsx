import React, { useState, useEffect } from 'react';
import type { PodNodeData, NetworkTraffic } from '../types';
import { ArrowRight, Activity, ChevronDown, ChevronRight, Filter } from 'lucide-react';
import { apiClient } from '../services/api';

interface DataTableProps {
  selectedPod: PodNodeData | null;
  allPods: PodNodeData[];
}

interface TrafficIdentity {
  podName?: string;
  podNamespace?: string;
  svcName?: string;
  svcNamespace?: string;
  isExternal: boolean;
}

const DataTable: React.FC<DataTableProps> = ({ selectedPod }) => {
  const [expandedSyscalls, setExpandedSyscalls] = useState<Set<number>>(new Set());
  const [isTrafficExpanded, setIsTrafficExpanded] = useState(true);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(true);

  // Traffic filters
  const [decisionFilter, setDecisionFilter] = useState<'all' | 'ALLOW' | 'DROP'>('all');
  const [trafficTypeFilter, setTrafficTypeFilter] = useState<'all' | 'ingress' | 'egress'>('all');

  // Cache for service and pod lookups by IP
  const [identityCache, setIdentityCache] = useState<Map<string, TrafficIdentity>>(new Map());

  // Helper to resolve traffic identity
  // Follows advisor priority: service first, then pod, then external
  const resolveTrafficIdentity = async (traffic: NetworkTraffic): Promise<TrafficIdentity> => {
    if (!traffic.traffic_in_out_ip) {
      return { isExternal: true };
    }

    const ip = traffic.traffic_in_out_ip;

    // Check cache first
    if (identityCache.has(ip)) {
      return identityCache.get(ip)!;
    }

    // Priority 1: Try to get service info from API
    try {
      const serviceInfo = await apiClient.getServiceByIP(ip);
      if (serviceInfo && serviceInfo.svc_name) {
        const identity: TrafficIdentity = {
          svcName: serviceInfo.svc_name,
          svcNamespace: serviceInfo.svc_namespace || undefined,
          isExternal: false,
        };

        // Cache the result
        setIdentityCache(prev => new Map(prev).set(ip, identity));
        return identity;
      }
    } catch (error) {
      // Service lookup failed, continue to pod lookup
    }

    // Priority 2: Try to get pod info from API (checks all namespaces)
    try {
      const podInfo = await apiClient.getPodDetailsByIP(ip);
      if (podInfo && podInfo.pod_name) {
        const identity: TrafficIdentity = {
          podName: podInfo.pod_name,
          podNamespace: podInfo.pod_namespace || undefined,
          isExternal: false,
        };

        // Cache the result
        setIdentityCache(prev => new Map(prev).set(ip, identity));
        return identity;
      }
    } catch (error) {
      // Pod lookup failed, continue to external
    }

    // Priority 3: External traffic
    const identity: TrafficIdentity = { isExternal: true };
    setIdentityCache(prev => new Map(prev).set(ip, identity));
    return identity;
  };

  // State for resolved identities
  const [resolvedIdentities, setResolvedIdentities] = useState<Map<string, TrafficIdentity>>(new Map());

  // Reset expanded state, identities, and filters when pod changes
  useEffect(() => {
    setExpandedSyscalls(new Set());
    setResolvedIdentities(new Map());
    setDecisionFilter('all');
    setTrafficTypeFilter('all');
  }, [selectedPod?.id]);

  // Resolve identities for all traffic when selected pod changes
  useEffect(() => {
    if (!selectedPod || !selectedPod.traffic) return;

    const resolveAllIdentities = async () => {
      const identities = new Map<string, TrafficIdentity>();

      for (const traffic of selectedPod.traffic) {
        if (traffic.traffic_in_out_ip && !identities.has(traffic.traffic_in_out_ip)) {
          const identity = await resolveTrafficIdentity(traffic);
          identities.set(traffic.traffic_in_out_ip, identity);
        }
      }

      setResolvedIdentities(identities);
    };

    resolveAllIdentities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedPod]);
  if (!selectedPod) {
    return (
      <div className="h-full flex items-center justify-center text-tertiary">
        <p>Select a pod to view details</p>
      </div>
    );
  }

  const hasTraffic = selectedPod.traffic && selectedPod.traffic.length > 0;
  const hasSyscalls = selectedPod.syscalls && selectedPod.syscalls.length > 0;

  // Filter traffic based on selected filters
  const filteredTraffic = selectedPod.traffic?.filter(traffic => {
    // Filter by decision
    if (decisionFilter !== 'all' && traffic.decision !== decisionFilter) {
      return false;
    }

    // Filter by traffic type
    if (trafficTypeFilter !== 'all' && traffic.traffic_type?.toLowerCase() !== trafficTypeFilter) {
      return false;
    }

    return true;
  }) || [];

  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      {/* Pod Information Header */}
      <div className="bg-hubble-card p-4 rounded-lg border border-hubble-border">
        <h3 className="text-lg font-semibold text-primary mb-2">
          {selectedPod.pod.pod_name}
        </h3>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span className="text-tertiary">Namespace:</span>
            <span className="ml-2 text-secondary">{selectedPod.pod.pod_namespace}</span>
          </div>
          <div>
            <span className="text-tertiary">IP:</span>
            <span className="ml-2 text-secondary font-mono">{selectedPod.pod.pod_ip}</span>
          </div>
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
                  onChange={(e) => setDecisionFilter(e.target.value as 'all' | 'ALLOW' | 'DROP')}
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
                  onChange={(e) => setTrafficTypeFilter(e.target.value as 'all' | 'ingress' | 'egress')}
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
                    <th className="px-4 py-2 text-left text-secondary font-medium">Type</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Pod</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Remote</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Protocol</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Decision</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTraffic.map((traffic, index) => (
                    <tr
                      key={traffic.uuid || index}
                      className="border-b border-hubble-border hover:bg-hubble-dark/50 transition-colors"
                    >
                      <td className="px-4 py-2">
                        <span className={`px-2 py-1 rounded text-xs ${
                          traffic.traffic_type === 'ingress'
                            ? 'bg-hubble-success/20 text-hubble-success'
                            : 'bg-hubble-warning/20 text-hubble-warning'
                        }`}>
                          {traffic.traffic_type || 'unknown'}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-secondary font-mono text-xs">
                        {traffic.pod_ip}
                        {/* For ingress, pod port is destination (meaningful). For egress, pod port is ephemeral source (hide if 0) */}
                        {traffic.traffic_type?.toLowerCase() === 'ingress' && traffic.pod_port && traffic.pod_port !== '0' && `:${traffic.pod_port}`}
                        {traffic.traffic_type?.toLowerCase() === 'egress' && traffic.pod_port && traffic.pod_port !== '0' && `:${traffic.pod_port}`}
                      </td>
                      <td className="px-4 py-2 text-secondary text-xs">
                        {(() => {
                          const identity = resolvedIdentities.get(traffic.traffic_in_out_ip || '') || { isExternal: true };

                          if (identity.podName) {
                            // In-cluster pod
                            return (
                              <div className="flex flex-col gap-1">
                                <div className="flex items-center gap-1">
                                  <span className="px-2 py-0.5 bg-hubble-success/20 text-hubble-success rounded text-xs">
                                    Pod
                                  </span>
                                  <span className="font-semibold text-primary">{identity.podName}</span>
                                </div>
                                {identity.podNamespace && (
                                  <span className="text-tertiary text-xs">ns: {identity.podNamespace}</span>
                                )}
                                <span className="font-mono text-xs text-tertiary">
                                  {traffic.traffic_in_out_ip}
                                  {/* For ingress, remote port is ephemeral source (hide if 0). For egress, remote port is destination (show if not 0) */}
                                  {traffic.traffic_type?.toLowerCase() === 'egress' && traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' && `:${traffic.traffic_in_out_port}`}
                                  {traffic.traffic_type?.toLowerCase() === 'ingress' && traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' && `:${traffic.traffic_in_out_port}`}
                                </span>
                              </div>
                            );
                          } else if (identity.svcName) {
                            // In-cluster service
                            return (
                              <div className="flex flex-col gap-1">
                                <div className="flex items-center gap-1">
                                  <span className="px-2 py-0.5 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                                    Svc
                                  </span>
                                  <span className="font-semibold text-primary">{identity.svcName}</span>
                                </div>
                                {identity.svcNamespace && (
                                  <span className="text-tertiary text-xs">ns: {identity.svcNamespace}</span>
                                )}
                                <span className="font-mono text-xs text-tertiary">
                                  {traffic.traffic_in_out_ip}
                                  {/* For ingress, remote port is ephemeral source (hide if 0). For egress, remote port is destination (show if not 0) */}
                                  {traffic.traffic_type?.toLowerCase() === 'egress' && traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' && `:${traffic.traffic_in_out_port}`}
                                  {traffic.traffic_type?.toLowerCase() === 'ingress' && traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' && `:${traffic.traffic_in_out_port}`}
                                </span>
                              </div>
                            );
                          } else {
                            // External traffic
                            return (
                              <div className="flex flex-col gap-1">
                                <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 rounded text-xs w-fit">
                                  External
                                </span>
                                <span className="font-mono text-xs">
                                  {traffic.traffic_in_out_ip}
                                  {/* For ingress, remote port is ephemeral source (hide if 0). For egress, remote port is destination (show if not 0) */}
                                  {traffic.traffic_type?.toLowerCase() === 'egress' && traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' && `:${traffic.traffic_in_out_port}`}
                                  {traffic.traffic_type?.toLowerCase() === 'ingress' && traffic.traffic_in_out_port && traffic.traffic_in_out_port !== '0' && `:${traffic.traffic_in_out_port}`}
                                </span>
                              </div>
                            );
                          }
                        })()}
                      </td>
                      <td className="px-4 py-2">
                        <span className="px-2 py-1 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                          {traffic.ip_protocol || 'TCP'}
                        </span>
                      </td>
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
                      <td className="px-4 py-2 text-tertiary text-xs">
                        {new Date(traffic.time_stamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
