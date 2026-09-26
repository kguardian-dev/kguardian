import type { PodComputeData } from './compute';

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
  /** `pod.spec.hostNetwork`. A host-network pod shares the node's IP, so a
   *  podSelector can never match its traffic — the generators render such a
   *  peer as an ipBlock / Cilium entities instead. Absent/null from a broker or
   *  controller predating the column ⇒ treated as unknown (legacy rendering). */
  host_network?: boolean | null;
  /** Every IP the pod holds (dual-stack); `pod_ip` is the first. Absent from
   *  an older broker. */
  pod_ips?: string[] | null;
  /** `pod.status.startTime` as broker-naive UTC (`2026-08-04T09:12:41`).
   *  Drives the start-time guard (utils/peerResolution): a flow older than
   *  this can never have been to/from this pod. null/absent = unknown (row
   *  written by a broker predating the column, or no startTime) ⇒ the pod is
   *  NOT excluded by the guard, it merely ranks last. */
  started_at?: string | null;
}

/**
 * What the broker resolved `traffic_in_out_ip` to AT INGEST (`peer_kind`).
 * `pod` = a pod-network pod held the IP at `time_stamp`; `node` = a
 * host-network pod (the IP is a node IP); `service` = a ClusterIP. null =
 * unresolved (legacy row, external IP, or the peer's spec never arrived) ⇒
 * consumers fall back to a by-IP lookup guarded by the flow time.
 */
export type PeerKind = 'pod' | 'node' | 'service';

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
  /** Why a DROP row was recorded: 'no-policy' | 'policy-governs' |
   *  'unknown'. Null on an ALLOW row, on a row written before
   *  classification existed, or when the evaluator could not classify
   *  it — all of which read as "cause unknown". The drop probe observes
   *  only that a TCP handshake never completed; it cannot see why, so
   *  never present a bare DROP as a policy denial. Use
   *  `describeDrop` from utils/dropCause. */
  drop_cause?: string | null;
  /** SYN retransmissions before the flow was reported. The evidence
   *  behind a drop: 4 retries is a slow peer, 40 is blackholed. */
  syn_retries?: number | null;
  /** Peer identity stamped by the broker when the row was ingested (or by
   *  its late-resolve pass). Pod IPs are recycled constantly, so this — not
   *  a by-IP lookup at read time — is the authoritative peer. All null on a
   *  row the broker could not resolve or one written before the column
   *  existed; absent entirely from an older broker. */
  peer_kind?: PeerKind | string | null;
  peer_namespace?: string | null;
  peer_name?: string | null;
  peer_uid?: string | null;
  peer_workload_kind?: string | null;
  peer_workload_name?: string | null;
  peer_resolved_at?: string | null;
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
  /** Peer keys (utils/peerResolution `peerKey`) this external node stands for.
   *  Edges resolve through these, not through member IPs, because one IP can
   *  belong to different peers at different times. */
  peerKeys?: string[];
  /** Hover text for the node title when the label alone is misleading — set
   *  on the "Unattributed" node (guarded-out former IP holders). */
  tooltip?: string;
  /** Live compute gauges + findings (hooks/useComputeData, utils/compute).
   *  Absent when the pod's node reports no compute rows — the card then
   *  renders exactly as it did before the feature. */
  compute?: PodComputeData;
  /** Map lens badge (hooks/useMapLens): absent when the lens is Traffic —
   *  the card then renders exactly as it did before lenses. */
  lensBadge?: LensBadge;
}

/** Map lens (URL `lens=`): what the cards carry besides their name. */
export type MapLens = 'traffic' | 'vulns' | 'supply' | 'coverage';

/**
 * One card's badge under a non-traffic lens. `unknown` is its own tone and
 * is never drawn like a good state: missing data is not clean.
 */
export interface LensBadge {
  lens: Exclude<MapLens, 'traffic'>;
  tone: 'p0' | 'p1' | 'risk' | 'warn' | 'good' | 'neutral' | 'unknown';
  /** Short text on the card. */
  text: string;
  /** Full sentence: tooltip and accessible name. */
  label: string;
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
  /**
   * Whether a NetworkPolicy would actually be enforced in this cluster:
   * 'enforced' | 'unenforced' | 'mixed' | 'unknown'.
   *
   * Separate from `cni` because the two are orthogonal. AWS VPC CNI
   * supports NetworkPolicy only when explicitly enabled and ships with
   * it off; with it off the CNI accepts a policy and silently ignores
   * it. So knowing the CNI never answered whether a generated policy
   * will do anything, which is the only question the operator actually
   * has.
   */
  policy_enforcement: string;
  nodes: number;
}

export const UNKNOWN_CLUSTER_ENVIRONMENT: ClusterEnvironment = {
  cni: 'unknown',
  ip_family: 'unknown',
  provider: 'unknown',
  distro: 'unknown',
  node_os: 'unknown',
  policy_enforcement: 'unknown',
  nodes: 0,
};
