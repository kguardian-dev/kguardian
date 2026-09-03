// Partial Kubernetes object metadata used for label extraction
export interface KubeObjectMetadata {
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  name?: string;
  namespace?: string;
  [key: string]: unknown;
}

// Partial Kubernetes object shape (pod spec, service spec, etc.)
export interface KubeObject {
  metadata?: KubeObjectMetadata;
  [key: string]: unknown;
}

// Matches broker's PodDetail type
export interface PodInfo {
  pod_name: string;
  pod_ip: string;
  pod_namespace: string | null;
  pod_obj?: KubeObject;
  time_stamp: string;
  node_name: string;
  is_dead: boolean;
  pod_identity?: string | null;
  workload_selector_labels?: Record<string, string> | null;
  /** Top-level owning controller (Deployment, StatefulSet, ...) — the key the
   *  broker groups syscalls on for per-workload seccomp profiles. Absent for a
   *  bare pod or from an older controller. */
  workload_kind?: string | null;
  workload_name?: string | null;
  /** Syscall capture tier the controller ran for this pod: one of
   *  `full | high | medium | low | custom`. Absent/null from a controller
   *  predating tiers — never assume that means complete. */
  capture_level?: string | null;
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
  pod: PodInfo; // Primary pod (for backward compatibility and single-pod identities)
  pods: PodInfo[]; // All pods in this identity group
  traffic: NetworkTraffic[];
  syscalls?: SyscallInfo[];
  isExpanded: boolean;
  isExternal?: boolean; // True if this pod is outside the selected namespace
  externalNamespace?: string; // The namespace this external pod belongs to
}

// Matches broker's SvcDetail type
export interface ServiceInfo {
  svc_ip: string;
  svc_name: string | null;
  svc_namespace: string | null;
  service_spec?: KubeObject; // Full Kubernetes Service object
}

// Matches broker's AuditVerdict type — one row per (flow, policy,
// direction) the evaluator decided on. The broker forwarder persists
// `Allow` and `WouldDeny`; `NotApplicable` is dropped before insert.
export type AuditVerdictKind = 'Allow' | 'WouldDeny';

export interface AuditVerdict {
  id: number;
  policy_uid: string;
  policy_namespace: string; // empty string for cluster-scoped policies
  policy_name: string;
  direction: 'Ingress' | 'Egress' | string;
  src_namespace: string | null;
  src_pod: string | null;
  dst_namespace: string | null;
  dst_pod: string | null;
  dst_port: number;
  protocol: string;
  reason: string | null;
  observed_at: string; // ISO 8601
  verdict: AuditVerdictKind | string;
}

/**
 * Coarse cluster-environment aggregates from the broker (GET
 * /cluster/environment, backed by controller-reported node facts).
 * 'unknown' anywhere means "no signal — behave exactly as before".
 */
export interface ClusterEnvironment {
  cni: string;
  ip_family: string;
  provider: string;
  distro: string;
  node_os: string;
  nodes: number;
}

export const UNKNOWN_CLUSTER_ENVIRONMENT: ClusterEnvironment = {
  cni: 'unknown',
  ip_family: 'unknown',
  provider: 'unknown',
  distro: 'unknown',
  node_os: 'unknown',
  nodes: 0,
};
