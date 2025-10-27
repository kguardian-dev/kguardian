import React from 'react';
import type { PodNodeData } from '../types';
import { ArrowRight, Activity } from 'lucide-react';

interface DataTableProps {
  selectedPod: PodNodeData | null;
}

const DataTable: React.FC<DataTableProps> = ({ selectedPod }) => {
  if (!selectedPod) {
    return (
      <div className="h-full flex items-center justify-center text-gray-400">
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
        <h3 className="text-lg font-semibold text-gray-100 mb-2">
          {selectedPod.pod.pod_name}
        </h3>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span className="text-gray-400">Namespace:</span>
            <span className="ml-2 text-gray-200">{selectedPod.pod.pod_namespace}</span>
          </div>
          <div>
            <span className="text-gray-400">IP:</span>
            <span className="ml-2 text-gray-200 font-mono">{selectedPod.pod.pod_ip}</span>
          </div>
        </div>
      </div>

      {/* Network Traffic Section */}
      <div>
        <h4 className="text-md font-semibold text-gray-100 mb-3 flex items-center gap-2">
          <ArrowRight className="w-4 h-4 text-hubble-success" />
          Network Traffic ({selectedPod.traffic?.length || 0})
        </h4>

        {hasTraffic ? (
          <div className="bg-hubble-card rounded-lg border border-hubble-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-hubble-dark border-b border-hubble-border">
                  <tr>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Type</th>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Pod</th>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Remote</th>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Protocol</th>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Timestamp</th>
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
                      <td className="px-4 py-2 text-gray-200 font-mono text-xs">
                        {traffic.pod_ip}
                        {traffic.pod_port && `:${traffic.pod_port}`}
                      </td>
                      <td className="px-4 py-2 text-gray-200 font-mono text-xs">
                        {traffic.traffic_in_out_ip}
                        {traffic.traffic_in_out_port && `:${traffic.traffic_in_out_port}`}
                      </td>
                      <td className="px-4 py-2">
                        <span className="px-2 py-1 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                          {traffic.ip_protocol || 'TCP'}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-gray-400 text-xs">
                        {new Date(traffic.time_stamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="bg-hubble-card p-4 rounded-lg border border-hubble-border text-gray-400 text-sm">
            No network traffic recorded
          </div>
        )}
      </div>

      {/* Syscalls Section */}
      {hasSyscalls && (
        <div>
          <h4 className="text-md font-semibold text-gray-100 mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-hubble-warning" />
            System Calls
          </h4>

          <div className="bg-hubble-card rounded-lg border border-hubble-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-hubble-dark border-b border-hubble-border">
                  <tr>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Architecture</th>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Syscalls</th>
                    <th className="px-4 py-2 text-left text-gray-300 font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedPod.syscalls?.map((syscall, index) => {
                    const syscallList = syscall.syscalls.split(',').filter(s => s.trim());
                    return (
                      <tr
                        key={index}
                        className="border-b border-hubble-border hover:bg-hubble-dark/50 transition-colors"
                      >
                        <td className="px-4 py-2 text-gray-200">
                          <span className="px-2 py-1 bg-hubble-accent/20 text-hubble-accent rounded text-xs">
                            {syscall.arch}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-gray-200">
                          <div className="flex flex-wrap gap-1">
                            {syscallList.slice(0, 10).map((sc, i) => (
                              <span key={i} className="px-2 py-1 bg-hubble-warning/20 text-hubble-warning rounded text-xs font-mono">
                                {sc.trim()}
                              </span>
                            ))}
                            {syscallList.length > 10 && (
                              <span className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">
                                +{syscallList.length - 10} more
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-2 text-gray-400 text-xs">
                          {new Date(syscall.time_stamp).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DataTable;
