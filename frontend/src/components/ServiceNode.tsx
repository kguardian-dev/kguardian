import React from 'react';
import { Handle, Position } from 'reactflow';
import { Globe } from 'lucide-react';
import type { ServiceInfo } from '../types';

interface ServiceNodeProps {
  data: ServiceInfo & {
    trafficCount: number;
  };
}

const ServiceNode: React.FC<ServiceNodeProps> = React.memo(({ data }) => {
  const displayName = data.svc_name || data.svc_ip;

  return (
    <div
      className="px-4 py-3 rounded-lg border-2 border-hubble-accent/60 bg-hubble-card
                 hover:border-hubble-accent transition-all min-w-[180px]"
    >
      <Handle type="target" position={Position.Left} />

      <div className="flex items-center gap-2">
        <Globe className="w-5 h-5 text-hubble-accent" />
        <div className="flex-1">
          <div className="font-semibold text-sm text-primary">
            {displayName}
          </div>
          {data.svc_namespace && (
            <div className="text-xs text-tertiary">
              ns: {data.svc_namespace}
            </div>
          )}
        </div>
        <span className="px-1.5 py-0.5 bg-hubble-accent/20 text-hubble-accent rounded text-xs font-medium">
          Svc
        </span>
      </div>

      <div className="mt-2 pt-2 border-t border-hubble-border">
        <div className="flex items-center justify-between text-xs">
          <span className="font-mono text-secondary">{data.svc_ip}</span>
          <span className="text-tertiary">{data.trafficCount} flows</span>
        </div>
      </div>

      <Handle type="source" position={Position.Right} />
    </div>
  );
}, (prevProps, nextProps) => {
  return (
    prevProps.data.svc_ip === nextProps.data.svc_ip &&
    prevProps.data.trafficCount === nextProps.data.trafficCount
  );
});

export default ServiceNode;
