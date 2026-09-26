/**
 * Supply-chain read API (broker, PR #1671): vulnerabilities, SBOMs and the
 * image inventory they join to. Shapes follow the captured responses in
 * fixtures/vuln-captures.
 *
 * Conventions the UI keeps:
 *  - `null` is unknown, never "no" / "safe" / zero (kev, epss, exposed,
 *    inUse, sbomTrust, dbUpdatedAt ...);
 *  - an empty `reports` list means no vulnerability data for the image:
 *    unknown, not clean;
 *  - `title` / `primaryUrl` are third-party text: rendered as text or a
 *    plain link, never fetched or executed.
 */

export type VulnSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';
export type VulnSource = 'trivy-operator' | 'grype' | 'registry';
/** How a report was matched to what runs, strongest first. */
export type JoinKind = 'image_id' | 'platform_manifest' | 'workload_tag' | 'report_digest';
/** Weakest first. Only `verified` may be shown as signed. */
export type SbomTrust = 'attached-unbound' | 'unverified' | 'scanned' | 'verified';
/** `executed` | `loaded` | `unknown` | `installed_not_observed` (#1678); `unknown` before it. */
export type InUseState = 'executed' | 'loaded' | 'unknown' | 'installed_not_observed' | string;

/**
 * Fields added by the in-use tiers release (#1678). All optional: an older
 * Broker omits them, and the UI then shows the tier as unknown.
 */
export interface InUseDetail {
  state: InUseState;
  /** Why the state is unknown (language_package, no_runtime_data, capture_gap, host_network, no_package_files). */
  reason: string | null;
  observedSince: string | null;
  windowHours: number;
  containers: number;
  /** `file` | `static_binary` | `interpreted`. */
  coverage: string;
}

// ── GET /vulnerabilities ────────────────────────────────────────────────
export interface CveSummary {
  id: string;
  severity: VulnSeverity;
  maxScore: number | null;
  fixable: boolean;
  kev: boolean | null;
  maxEpss: number | null;
  packages: string[];
  sources: string[];
  images: number;
  workloads: number;
  runningWorkloads: number;
  namespaces: number;
  weakestJoin: JoinKind;
  inUse: boolean | null;
  inUseState: InUseState;
  /** #1678: the most urgent tier over every affected workload container in scope. */
  tier?: string;
  executedWorkloads?: number;
  loadedWorkloads?: number;
  unknownWorkloads?: number;
  notObservedWorkloads?: number;
  exposedWorkloads?: number;
}

export interface CvePage {
  items: CveSummary[];
  nextAfter: string | null;
  /** When the summary was last rebuilt; null until the first rebuild. */
  computedAt: string | null;
  staleSeconds: number | null;
}

// ── GET /vulnerabilities/{id}/exposure ───────────────────────────────────
export interface ExposedPackage {
  name: string;
  installedVersion: string;
  fixedVersions: string[];
  severity: VulnSeverity;
  sources: string[];
}

export interface ExposedImage {
  digest: string;
  repository: string | null;
  tags: string[];
  sources: string[];
  reportDigests: string[];
  join: JoinKind;
  severity: VulnSeverity;
  packages: ExposedPackage[];
}

export type ExposedVia = 'other_namespace' | 'unattributed' | 'public_ip' | 'node';

export interface NetworkExposure {
  windowHours: number;
  podsObserved: number;
  flowsObserved: number;
  ingressFlowsObserved: number;
  ingressFromOtherNamespaces: number;
  ingressFromUnattributedPeers: number;
  ingressFromPublicIps: number;
  ingressFromNodes: number;
  /** true: outside ingress seen; false: ingress seen, none from outside; null: no ingress observed (unknown). */
  exposed: boolean | null;
  exposedVia: ExposedVia[];
}

export interface ExposedWorkload {
  clusterId: string;
  namespace: string;
  kind: string;
  name: string;
  container: string;
  imageDigest: string;
  join: JoinKind;
  running: boolean;
  lastSeen: string;
  network: NetworkExposure | null;
  inUse: boolean | null;
  inUseState: InUseState;
}

export interface NamespaceExposure {
  namespace: string;
  workloads: number;
  runningWorkloads: number;
  exposedWorkloads: number;
  unknownExposureWorkloads: number;
}

export interface Exposure {
  id: string;
  severity: VulnSeverity;
  fixable: boolean;
  truncated: boolean;
  images: ExposedImage[];
  workloads: ExposedWorkload[];
  namespaces: NamespaceExposure[];
  inUse: boolean | null;
  inUseState: InUseState;
}

// ── GET /images/{digest}/vulnerabilities and /sbom ───────────────────────
export interface Report {
  source: VulnSource | string;
  reportDigest: string;
  join: JoinKind;
  digestKind: string;
  scannedAt: string;
  dbUpdatedAt: string | null;
  scannerName: string | null;
  scannerVersion: string | null;
  osFamily: string | null;
  osName: string | null;
  osEosl: boolean;
  imageRef: string | null;
  itemCount: number;
  sbomFormat: string | null;
  receivedAt: string;
  sbomSources: string[];
  /** null = not stated by the source. */
  sbomTrust: SbomTrust | null;
  attestation: {
    mechanism: string | null;
    artifact_digest: string | null;
    media_type: string | null;
    predicate_type: string | null;
    verified: boolean | null;
  } | null;
}

export interface Finding {
  id: string;
  package: { name: string; type: string | null; purl: string | null };
  installedVersion: string;
  /** Every distinct fixed version the sources give, ordered by source. */
  fixedVersions: string[];
  fixable: boolean;
  severity: VulnSeverity;
  score: number | null;
  cvss: unknown;
  title: string | null;
  primaryUrl: string | null;
  target: string | null;
  class: string | null;
  publishedAt: string | null;
  lastModifiedAt: string | null;
  filePaths: string[];
  kev: boolean | null;
  kevDateAdded: string | null;
  epss: number | null;
  epssPercentile: number | null;
  sources: string[];
  reportDigests: string[];
  inUse: boolean | null;
  inUseState: InUseState;
  /** #1678. Worst over every workload container running the image. */
  tier?: string;
  /** #1678: what produced `tier`, e.g. ["in_use:loaded", "kev", "severity:high", "exposed"]. */
  tierFactors?: string[];
  inUseDetail?: InUseDetail;
}

export interface ImageVulnsPage {
  digest: string;
  /** Empty = no vulnerability data for this image (unknown, not clean). */
  reports: Report[];
  items: Finding[];
  nextAfter: string | null;
}

export interface SbomComponent {
  id: number;
  name: string;
  version: string | null;
  purl: string | null;
  type: string | null;
  class: string | null;
  licenses: string[];
  srcName: string | null;
  srcVersion: string | null;
  layerDigest: string | null;
  filePaths: string[];
}

export interface SbomPage {
  digest: string;
  /** Every source's SBOM with its trust. */
  reports: Report[];
  /** The one the items come from; null = no SBOM. */
  report: Report | null;
  items: SbomComponent[];
  /** Component id cursor (numeric, unlike the other reads' string cursors). */
  nextAfter: number | null;
}

// ── GET /images and /images/{digest} (image inventory, #1655) ────────────
export interface ImageSummary {
  digest: string;
  repository: string | null;
  tags: string[];
  digestKind: string;
  firstSeen: string;
  lastSeen: string;
  runningContainers: number;
}

export interface ImagePage {
  items: ImageSummary[];
  nextAfter: string | null;
}

export interface ImageUser {
  clusterId: string;
  namespace: string;
  workloadKind: string;
  workloadName: string;
  containerName: string;
  containerKind: string;
  imageRef: string;
  firstSeen: string;
  lastSeen: string;
  state: string | null;
  stateReason: string | null;
  ranAsInit: boolean;
  running: boolean;
}

export interface ImageDetail extends Omit<ImageSummary, 'runningContainers'> {
  workloads: ImageUser[];
  truncated: boolean;
}
