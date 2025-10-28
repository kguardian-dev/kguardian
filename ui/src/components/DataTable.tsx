import React, { useState, useEffect } from 'react';
import type { PodNodeData } from '../types';
import { ArrowRight, Activity, ChevronDown, ChevronRight } from 'lucide-react';

interface DataTableProps {
  selectedPod: PodNodeData | null;
}

const DataTable: React.FC<DataTableProps> = ({ selectedPod }) => {
  const [expandedSyscalls, setExpandedSyscalls] = useState<Set<number>>(new Set());
  const [isTrafficExpanded, setIsTrafficExpanded] = useState(true);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(true);

  // Reset expanded state when pod changes
  useEffect(() => {
    setExpandedSyscalls(new Set());
  }, [selectedPod?.id]);
  if (!selectedPod) {
    return (
      <div className="h-full flex items-center justify-center text-tertiary">
        <p>Select a pod to view details</p>
      </div>
    );
  }

  const hasTraffic = selectedPod.traffic && selectedPod.traffic.length > 0;
  const hasSyscalls = selectedPod.syscalls && selectedPod.syscalls.length > 0;

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
          Network Traffic ({selectedPod.traffic?.length || 0})
        </button>

        {isTrafficExpanded && hasTraffic && (
          <div className="bg-hubble-card rounded-lg border border-hubble-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-hubble-dark border-b border-hubble-border">
                  <tr>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Type</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Pod</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Remote</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Protocol</th>
                    <th className="px-4 py-2 text-left text-secondary font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedPod.traffic.map((traffic, index) => (
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
                        {traffic.pod_port && `:${traffic.pod_port}`}
                      </td>
                      <td className="px-4 py-2 text-secondary font-mono text-xs">
                        {traffic.traffic_in_out_ip}
                        {traffic.traffic_in_out_port && `:${traffic.traffic_in_out_port}`}
                      </td>
                      <td className="px-4 py-2">
                        <span className="px-2 py-1 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                          {traffic.ip_protocol || 'TCP'}
                        </span>
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
