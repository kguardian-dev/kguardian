import type { SeccompProfile } from './seccompProfile';

/**
 * Syscall capture tiers, spelled exactly as the controller, chart, and broker
 * spell them. Only `full` records every syscall; the others filter in BPF and
 * so can never feed a complete seccomp profile. `unknown` is the broker's
 * answer when it has no tier for a workload (older controller) — treated as
 * incomplete, never assumed full.
 */
export type CaptureLevel = 'full' | 'high' | 'medium' | 'low' | 'custom' | 'unknown';

export const CAPTURE_LEVELS: readonly CaptureLevel[] = ['full', 'high', 'medium', 'low', 'custom', 'unknown'];

/** Pod-template annotation that raises a workload's capture tier. */
export const CAPTURE_ANNOTATION = 'kguardian.dev/syscall-capture';
/** Helm value that sets the cluster-wide default tier. */
export const CAPTURE_HELM_VALUE = 'syscalls.captureLevel';

export interface CapturePod {
  name: string;
  level: CaptureLevel | string;
}

/** `capture` block on a profile summary. `level` is the LOWEST tier across the
 *  workload's live pods; `complete` is true only when every pod is `full`. */
export interface CaptureInfo {
  level: CaptureLevel | string;
  complete: boolean;
  pods: CapturePod[];
  /** Pods beyond the ones listed (broker caps the list). */
  more?: number;
  /** Count of pods below `full`. */
  incomplete?: number;
}

export interface DistributionInfo {
  /** Nodes with the CR's file at the CR's current hash. */
  ready: number;
  /** Live nodes. */
  total: number;
  state: 'Ready' | 'Partial' | 'Pending' | string;
  /** Nodes reporting the path at any hash (broker-computed only). */
  present?: number;
}

/** Observed set vs the deployed CR's spec. */
export interface CrDrift {
  /** Observed syscalls not in the CR (the CR would block these). */
  missing: string[];
  /** CR syscalls never observed. */
  extra: string[];
  inSync: boolean;
}

/**
 * The user-owned `SeccompProfile` CR (kguardian.dev/v1alpha1) that references
 * this workload, as mirrored to the broker by the controller. `null` when none
 * is deployed. The UI never writes it — the user commits and applies the
 * manifest the export produces.
 */
export interface CrInfo {
  name: string;
  defaultAction: string;
  /** status.hash — FNV-1a-64 of the rendered node file. */
  hash: string;
  syscallCount: number;
  architectures?: string[];
  localhostProfile?: string;
  /** Broker-computed from node-status (path + hash match). */
  distribution: DistributionInfo;
  /** Mirrored verbatim from the CR's own status, when the controller set it. */
  statusDistribution?: DistributionInfo | null;
  drift: CrDrift;
  updatedAt?: string;
}

export interface RecommendedSnippet {
  seccompProfile: { type: 'Localhost'; localhostProfile: string };
}

/** One row of `GET /seccomp/profiles`. */
export interface WorkloadProfileSummary {
  namespace: string;
  kind: string;
  name: string;
  /** Fingerprint of the observed set rendered with SCMP_ACT_LOG. */
  hash: string;
  syscallCount: number;
  architectures: string[];
  updatedAt: string;
  capture?: CaptureInfo;
  /** = capture.complete */
  captureComplete?: boolean;
  /** `<kind lowercased>-<workload name>` — the CR name the export uses. */
  suggestedName?: string;
  cr?: CrInfo | null;
  /** Set when several CRs reference the workload; `cr` is the newest. */
  crCount?: number;
  recommendedSnippet?: RecommendedSnippet;
}

/** `GET /seccomp/profiles/{ns}/{kind}/{name}` — summary + rendered observed profile. */
export interface WorkloadProfileDetail extends WorkloadProfileSummary {
  profile: SeccompProfile;
}

/** Query params for `GET …/export`. */
export interface ExportParams {
  /** Overrides `metadata.name` (default: suggestedName). */
  name?: string;
  /** Overrides `spec.defaultAction` (default: SCMP_ACT_LOG). */
  defaultAction?: string;
  format?: 'yaml' | 'json';
}

/** Body for `POST …/export` — the staged edits applied server-side:
 *  `(observed ∪ add) \ remove`. */
export interface ExportBody extends ExportParams {
  add?: string[];
  remove?: string[];
}

/** Default actions the CRD accepts for `spec.defaultAction`. */
export const CR_DEFAULT_ACTIONS = ['SCMP_ACT_LOG', 'SCMP_ACT_ERRNO', 'SCMP_ACT_KILL', 'SCMP_ACT_KILL_PROCESS'] as const;
export type CrDefaultAction = (typeof CR_DEFAULT_ACTIONS)[number];

/** Workload kinds `spec.workloadRef.kind` accepts. */
export const CR_WORKLOAD_KINDS = ['Deployment', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job', 'ReplicaSet', 'ReplicationController'] as const;
