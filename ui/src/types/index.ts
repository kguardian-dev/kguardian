// Matches broker's PodDetail type
export interface PodInfo {
  pod_name: string;
  pod_ip: string;
  pod_namespace: string | null;
  pod_obj?: any;
  time_stamp: string;
}

// Matches broker's PodTraffic type
export interface NetworkTraffic {
  uuid: string;
  pod_name: string | null;
  pod_namespace: string | null;
  pod_ip: string | null;
  pod_port: string | null;
  ip_protocol: string | null;
  traffic_type: string | null;
  traffic_in_out_ip: string | null;
  traffic_in_out_port: string | null;
  time_stamp: string;
}

// Matches broker's PodSyscalls type
export interface SyscallInfo {
  pod_name: string;
  pod_namespace: string;
  syscalls: string; // Comma-separated string
  arch: string;
  time_stamp: string;
}

export interface PodNodeData {
  id: string;
  label: string;
  pod: PodInfo;
  traffic: NetworkTraffic[];
  syscalls?: SyscallInfo[];
  isExpanded: boolean;
}

export interface ServiceInfo {
  service_name: string;
  service_namespace: string;
  service_ip: string;
  cluster_ip?: string;
  ports?: Array<{
    port: number;
    protocol: string;
    targetPort: number;
  }>;
}
