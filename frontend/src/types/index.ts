// Matches broker's PodDetail type
export interface PodInfo {
  pod_name: string;
  pod_ip: string;
  pod_namespace: string | null;
  pod_obj?: any;
  time_stamp: string;
  node_name: string;
  is_dead: boolean;
  pod_identity?: string | null;
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
  decision: string | null; // ALLOW or DROP
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

// Matches broker's SvcDetail type
export interface ServiceInfo {
  svc_ip: string;
  svc_name: string | null;
  svc_namespace: string | null;
  service_spec?: any; // Full Kubernetes Service object
}
