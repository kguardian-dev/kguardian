/**
 * Workload Security Profile — the broker's read model (contract v1,
 * `GET /workloads`, `…/profile`, `…/profile/versions`, `…/profile/diff`).
 *
 * Contract conventions the UI must keep:
 *  - every field is present;
 *  - `null` = unknown / not configured / no data yet. Never render it as 0,
 *    "none", "ok" or false;
 *  - `[]` = known to be empty.
 */

export type PostureStatus = 'ok' | 'warn' | 'risk' | 'unknown';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingTier = 'P0' | 'P1' | 'P2';
export type DimensionName = 'network' | 'syscalls' | 'podSecurity' | 'images' | 'compute';
/** A finding's dimension: a core one, or `drift` (contract section 2.8), which never sets posture. */
export type FindingDimension = DimensionName | 'drift';
export type PssLevel = 'privileged' | 'baseline' | 'restricted';
export type LevelConfidence = 'confirmed' | 'upper_bound';

/**
 * Rollup (contract v1.2: no numeric score). Status is the worst known
 * dimension status, derived from findings; `coverage` is the share of the
 * weighted dimensions that have a known status.
 */
export interface Posture {
  status: PostureStatus;
  coverage: number;
  /** Dimensions whose status is unknown (excluded, never counted as clean). */
  unknownDimensions: DimensionName[];
}

/** Why the rollup is what it is: one line per contributing dimension. */
export interface PostureReason {
  dimension: DimensionName;
  status: PostureStatus;
  message: string;
}

export interface DimensionBrief {
  status: PostureStatus;
}

interface WorkloadListItemBase {
  clusterId: string;
  namespace: string;
  kind: string;
  name: string;
  /** The snapshotter's most recent failed attempt (Broker 1.20+); beside a computed profile, the profile fields are the last good one. */
  lastError?: string | null;
  failedAt?: string | null;
}

/** A `GET /workloads` item with a stored profile snapshot. */
export interface ComputedWorkloadListItem extends WorkloadListItemBase {
  revision: number;
  contentHash: string;
  computedAt: string;
  lastChangedAt: string;
  posture: Posture;
  dimensions: {
    network: DimensionBrief;
    syscalls: DimensionBrief;
    podSecurity: DimensionBrief & { level: PssLevel | null; levelConfidence: LevelConfidence | null };
    images: DimensionBrief & { runningDigests: number | null; mixedDigests: boolean | null };
    compute: DimensionBrief;
  };
  findingCounts: Record<FindingSeverity, number>;
}

/**
 * A `GET /workloads` item whose every snapshot attempt failed (Broker 1.20+):
 * no profile fields on the wire, only the failure. `computedAt === null` is
 * the discriminant, so a reader must check it before touching the posture.
 */
export interface FailedWorkloadListItem extends WorkloadListItemBase {
  revision: null;
  contentHash: null;
  computedAt: null;
  lastChangedAt: null;
  posture?: undefined;
  dimensions?: undefined;
  findingCounts?: undefined;
}

export type WorkloadListItem = ComputedWorkloadListItem | FailedWorkloadListItem;

export interface WorkloadListPage {
  items: WorkloadListItem[];
  nextAfter: string | null;
}

export interface Finding {
  id: string;
  dimension: FindingDimension;
  severity: FindingSeverity;
  tier: FindingTier | null;
  title: string;
  detail: string;
  container: string | null;
}

export interface Reason {
  code: string;
  message: string;
}

export interface Coverage {
  level: 'full' | 'partial' | 'none';
  fraction: number | null;
  observedSince: string | null;
  note: string;
}

/** §2.1 — the envelope every dimension carries (v1.2: no score). */
export interface DimensionEnvelope {
  status: PostureStatus;
  coverage: Coverage;
  reasons: Reason[];
}

export interface ContainerSecurityContext {
  privileged: boolean | null;
  allowPrivilegeEscalation: boolean | null;
  runAsNonRoot: boolean | null;
  runAsUser: number | null;
  runAsGroup: number | null;
  readOnlyRootFilesystem: boolean | null;
  capabilitiesAdd: string[] | null;
  capabilitiesDrop: string[] | null;
  seccompProfileType: string | null;
}

export interface FailingCheck {
  check: string;
  level: 'baseline' | 'restricted';
  field: string;
  value: unknown;
  message: string;
}

export interface PodSecurityContainer {
  name: string;
  kind: string;
  source: 'running' | 'last_known';
  digest: string;
  securityContext: ContainerSecurityContext;
  level: PssLevel | null;
  failing: FailingCheck[];
}

export interface PodSecurityDimension extends DimensionEnvelope {
  pssVersion: string;
  level: PssLevel | null;
  levelConfidence: LevelConfidence | null;
  unevaluatedChecks: string[];
  pod: {
    /** Whether any pod-level fields have been reported. */
    known: boolean;
    /** Pod-level failing checks (contract v1.1); the workload level accounts for them. */
    failing: FailingCheck[];
    serviceAccountName: string | null;
    automountServiceAccountToken: boolean | null;
    hostNetwork: boolean | null;
    hostPID: boolean | null;
    hostIPC: boolean | null;
    hostUsers: boolean | null;
    securityContext: {
      runAsNonRoot: boolean | null;
      runAsUser: number | null;
      runAsGroup: number | null;
      fsGroup: number | null;
      seccompProfileType: string | null;
    };
  } | null;
  containers: PodSecurityContainer[];
  /** Containers with inventory rows but no recent report; not evaluated. */
  staleContainers: Array<{ name: string; kind: string; digest: string; lastSeen: string }>;
  recommendation: {
    recommendation: true;
    targetLevel: PssLevel;
    format: string;
    yaml: string;
    caveats: string[];
  } | null;
}

export interface NetworkPeer {
  direction: 'ingress' | 'egress';
  protocol: string;
  port: number | null;
  peer: {
    kind: 'pod' | 'service' | 'node' | 'external' | 'unresolved';
    namespace: string | null;
    workloadKind: string | null;
    workloadName: string | null;
    name: string | null;
    ip: string | null;
  };
  flows: number;
  firstSeen: string;
  lastSeen: string;
}

export interface NetworkDimension extends DimensionEnvelope {
  summary: {
    ingress: { peers: number; external: number; ports: string[] };
    egress: { peers: number; external: number; ports: string[] };
  };
  peers: NetworkPeer[];
  truncated: boolean;
  policy: {
    audit: {
      policies: Array<{ namespace: string; name: string }>;
      allow: number;
      wouldDeny: number;
      lastVerdictAt: string;
      windowHours: number;
    } | null;
    enforced: null;
  };
}

export interface SyscallsDimension extends DimensionEnvelope {
  observed: { syscallCount: number; hash: string; architectures: string[]; updatedAt: string } | null;
  capture: { level: string; complete: boolean; incompletePods: number } | null;
  cr: {
    name: string;
    defaultAction: string;
    mode: 'enforce' | 'audit';
    syscallCount: number;
    inSync: boolean;
    missing: string[];
    extra: string[];
    /** The Broker's node-status count: nodes that reported this CR recently. */
    distribution: { ready: number; total: number; state: string };
    /** The CR's own status.distribution (every node the controller counts), when the Broker mirrors it. */
    statusDistribution?: { ready: number; total: number; state: string } | null;
  } | null;
  denials: { total: number; syscalls: string[]; lastSeen: string | null } | null;
}

export interface ImageDigestRow {
  digest: string;
  imageRef: string;
  state: 'running' | 'waiting' | 'terminated' | null;
  stateReason: string | null;
  ranAsInit: boolean;
  lastPodName: string | null;
  firstSeen: string;
  lastSeen: string;
}

export interface ImageContainer {
  name: string;
  kind: string;
  mixedDigests: boolean;
  /** No digest of this container has been reported recently. */
  stale: boolean;
  running: ImageDigestRow[];
  previous: ImageDigestRow[];
}

/** A verified signer as the profile lists it (only signers with an identity). */
export interface ProfileSigner {
  signerKind: 'keyless' | 'key' | string;
  issuer?: string | null;
  san?: string | null;
  keyName?: string | null;
  keyFingerprint?: string | null;
}

/** `dimensions.images.supplyChain` (contract v1.8, section 2.6). */
export interface SupplyChainDimension {
  /** not_configured: signature discovery is off in the deployment (neither unknown nor not checked). */
  status?: 'configured' | 'not_configured' | string;
  /** Worst over the current digests: invalid, unsigned, key_signed, unknown, verified; or not_configured. */
  verdict: string;
  /** Of the worst digest: not_checked (never checked), no_signer_identity, a discovery reason, ... */
  reason: string | null;
  container: string | null;
  digest: string | null;
  checkedAt: string | null;
  signers: ProfileSigner[];
  signersOmitted?: number;
  counts: { verified: number; keySigned: number; unsigned: number; invalid: number; unknown: number; notChecked: number };
  digests?: Array<{ container: string; digest: string; verdict: string | null; reason: string | null; signers: ProfileSigner[]; signersOmitted?: number; checkedAt: string | null }>;
  truncated?: boolean;
  /**
   * The evaluator's ImageTrustPolicy results for this workload (contract v1.9).
   * Absent from an older Broker; `null` where not read. `available: false` or
   * `evaluatedAt: null` is unknown, never "nothing would be denied".
   */
  imageTrust?: ImageTrust | null;
}

export interface ImageTrustResult {
  /** "namespace/name" or "cluster/name". */
  policy: string;
  namespace: string;
  /** "<kind>/<name>". */
  workload: string;
  container: string;
  digest: string;
  image: string;
  /** Trusted | WouldDeny | Unknown (a verdict the UI does not know reads as Unknown). */
  verdict: string;
  reason?: string | null;
}

/** `supplyChain.imageTrust` (v1.9). Report-only: never sets posture, status or readiness. */
export interface ImageTrust {
  available: boolean;
  reason?: string | null;
  evaluatedAt: string | null;
  total: number;
  wouldDeny: number;
  unknown: number;
  trusted: number;
  policies: string[];
  /** WouldDeny first, at most 20; the counts cover all. */
  results: ImageTrustResult[];
  truncated: boolean;
}

export interface ImagesDimension extends DimensionEnvelope {
  runningWindowSeconds: number;
  containers: ImageContainer[];
  truncated: boolean;
  /** Always null in v1 = no vulnerability source configured. */
  vulnerabilities: unknown | null;
  /**
   * Signature results of the current digests (contract v1.8). `null` means no
   * current digest on a v1.8 Broker; an older Broker always sends `null`.
   */
  supplyChain: SupplyChainDimension | null;
}

export interface ComputeDimension extends DimensionEnvelope {
  containers: Array<{
    pod: string;
    container: string;
    cpuRequestMillis: number | null;
    cpuLimitMillis: number | null;
    memRequestBytes: number | null;
    memLimitBytes: number | null;
    cpuUsageMillis: number | null;
    memWorkingSetBytes: number | null;
    oomKills: number | null;
    throttledRatio: number | null;
    updatedAt: string;
  }>;
  truncated: boolean;
}

export interface Control {
  control: 'networkPolicy' | 'seccompProfile' | 'imageAdmission';
  /** networkPolicy audit|unknown; seccompProfile enforcing|audit|none; imageAdmission null (v1). */
  state: 'audit' | 'unknown' | 'enforcing' | 'none' | null;
  detail: string;
  inSync: boolean | null;
}

export interface ReadinessItem {
  id: string;
  ok: boolean | null;
  message: string;
}

export interface VersionRef {
  revision: number;
  contentHash: string;
  createdAt: string;
}

export interface WorkloadProfile {
  workload: {
    clusterId: string;
    namespace: string;
    kind: string;
    name: string;
    transient: boolean;
    pods: { live: number; names: string[]; truncated: boolean };
  };
  generatedAt: string;
  contentHash: string;
  version: VersionRef | null;
  snapshotPending: boolean;
  posture: Posture & { reasons: PostureReason[] };
  attention: Finding[];
  findings: Finding[];
  controls: Control[];
  readiness: ReadinessItem[];
  exposure: {
    ingressPeers: number | null;
    ingressExternal: number | null;
    egressPeers: number | null;
    egressExternal: number | null;
  };
  dimensions: {
    network: NetworkDimension;
    syscalls: SyscallsDimension;
    podSecurity: PodSecurityDimension;
    images: ImagesDimension;
    compute: ComputeDimension;
  };
  /** Absent from a broker without drift (contract v1.4+; notEvaluated v1.7). */
  drift?: ProfileDrift;
  /** Observed capability use and its evidence (P2-7); absent from an older broker. */
  capabilities?: ProfileCapabilities;
}

/** A drift check that could not run for a container (null = the workload), and why. */
export interface DriftNotEvaluated {
  type: string;
  container: string | null;
  reason: string;
}

/** One file an `unshippedExecutable` item lists (contract v1.7). */
export interface UnshippedFile {
  path: string;
  kind: 'exec' | 'lib' | string;
  /** writableLayer | memfd | deleted (the runtime inventory's unshipped origins). */
  origin: string;
  digest: string;
  /** false: the kernel path walk was cut and `path` is a suffix. */
  pathComplete: boolean;
  firstSeen: string;
  lastSeen: string;
}

/** A drift item's detail, by type (contract section 2.8). Unknown types keep whatever the Broker sent. */
export interface DriftDetail {
  // tagMoved
  imageRef?: string;
  digests?: string[];
  since?: string;
  // imageChangedSinceExport
  containerInExport?: boolean;
  exportedDigests?: string[];
  newDigests?: string[];
  // securityContextRegression
  newlyFailing?: string[];
  levelFrom?: string | null;
  levelTo?: string | null;
  // unshippedExecutable
  origins?: string[];
  files?: UnshippedFile[];
  filesTotal?: number;
  truncated?: boolean;
}

export interface DriftItem {
  type: string;
  findingId: string;
  severity: FindingSeverity;
  container: string | null;
  detail?: DriftDetail;
}

export interface ProfileDrift {
  /** Checks that ran for the whole workload. One not listed was not evaluated. Absent = none. */
  evaluated?: string[];
  notEvaluated?: DriftNotEvaluated[];
  items: DriftItem[];
}

/** One capability's checks (contract section 2.9). */
export interface CapabilityUse {
  capability: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export interface CapabilityRecommendation {
  drop: string[];
  /** Every used and every probed capability, except the probed-only ones in `probedOmitted`. */
  add: string[];
  /** The part of `add` there only because of probes: remove only after a person confirms. */
  probedKept: string[];
  probedOmitted: { capability: string; reason: string }[];
  /** Settings `add` depends on (allowPrivilegeEscalation: false when anything was omitted). */
  requires?: { allowPrivilegeEscalation?: boolean } | null;
}

export interface ContainerCapabilities {
  container: string;
  digests: string[];
  used: CapabilityUse[];
  denied: CapabilityUse[];
  probed: CapabilityUse[];
  /** sufficient: every current digest watched for the whole window. */
  evidence: 'sufficient' | 'insufficient' | string;
  reason: string | null;
  observedSince: string | null;
  /** null without sufficient evidence. */
  recommendation: CapabilityRecommendation | null;
  /** Capabilities added today that were never used or probed (only with sufficient evidence). */
  unusedAdded: string[];
}

/** Contract v1.6+ (P2-7): not a dimension, never sets posture. */
export interface ProfileCapabilities {
  windowHours: number;
  containers: ContainerCapabilities[];
}

export interface VersionListItem extends VersionRef {
  dimensionHashes: Record<string, string>;
  /** null = unknown: the predecessor was trimmed by retention (contract v1.1). */
  changedDimensions: DimensionName[] | null;
  posture: Pick<Posture, 'status' | 'coverage'>;
}

export interface VersionList {
  namespace: string;
  kind: string;
  name: string;
  items: VersionListItem[];
  nextBefore: number | null;
}

export interface Change<T = unknown> {
  from: T;
  to: T;
}

export interface NetworkRule {
  direction: string;
  protocol: string;
  port: number | null;
  peer: string;
}

export interface CrRef {
  name: string;
  defaultAction: string;
  hash: string;
}

export interface ProfileDiff {
  namespace: string;
  kind: string;
  name: string;
  from: VersionRef | null;
  /** `from` was omitted and the predecessor of `to` was trimmed by
   *  retention, so everything in `to` shows as added. */
  fromTrimmed?: boolean;
  to: VersionRef;
  changed: boolean;
  dimensions: {
    podSecurity: {
      changed: boolean;
      level: Change<PssLevel | null> | null;
      pod: Array<{ field: string } & Change>;
      containersAdded: string[];
      containersRemoved: string[];
      containers: Array<{ name: string; fields: Array<{ field: string } & Change> }>;
    };
    images: {
      changed: boolean;
      containersAdded: string[];
      containersRemoved: string[];
      containers: Array<{ name: string; added: string[]; removed: string[] }>;
    };
    syscalls: {
      changed: boolean;
      added: string[];
      removed: string[];
      captureLevel: Change<string | null> | null;
      cr: Change<CrRef | null> | null;
    };
    network: {
      changed: boolean;
      added: NetworkRule[];
      removed: NetworkRule[];
    };
  };
}
