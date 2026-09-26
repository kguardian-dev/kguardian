/**
 * Profile API fixtures, built from the examples in the broker contract (v1).
 * Used by the unit tests and by the local fake broker for screenshots.
 * Neutral sample data only (payments / observability / flux-system).
 *
 * Only `import type` here: the fake broker loads this file with Node's type
 * stripping, so it must stay free of runtime imports.
 */
import type {
  ImagesDimension,
  NetworkDimension,
  PodSecurityDimension,
  PostureStatus,
  ProfileDiff,
  SyscallsDimension,
  ComputeDimension,
  VersionList,
  WorkloadListItem,
  WorkloadProfile,
} from '../types/profile';

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

export const podSecurityExample: PodSecurityDimension = {
  status: 'ok',
  score: 80,
  scored: true,
  coverage: {
    level: 'partial', fraction: 0.5, observedSince: '2026-09-19T08:12:00Z',
    note: '9 of 18 PSS checks evaluated; volumes, ports, probes, AppArmor, SELinux, procMount, sysctls and hostProcess are not ingested',
  },
  reasons: [{ code: 'pss_upper_bound', message: 'Evaluated checks pass restricted; unevaluated checks may lower the level' }],
  pssVersion: 'kubernetes/website@2c1aa11c (Kubernetes v1.37 docs)',
  level: 'restricted',
  levelConfidence: 'upper_bound',
  unevaluatedChecks: ['hostProcess', 'hostPathVolumes', 'hostPorts', 'hostProbesLifecycle', 'appArmor', 'seLinux', 'procMount', 'sysctls', 'volumeTypes'],
  pod: {
    failing: [],
    serviceAccountName: 'checkout',
    automountServiceAccountToken: null,
    hostNetwork: false,
    hostPID: null,
    hostIPC: null,
    hostUsers: null,
    securityContext: { runAsNonRoot: true, runAsUser: null, runAsGroup: null, fsGroup: 2000, seccompProfileType: 'RuntimeDefault' },
  },
  containers: [
    {
      name: 'app', kind: 'regular', source: 'running', digest: 'sha256:9f2c0d1e7a4b3c5d6e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6',
      securityContext: {
        privileged: null, allowPrivilegeEscalation: false, runAsNonRoot: null, runAsUser: 10001,
        runAsGroup: null, readOnlyRootFilesystem: null, capabilitiesAdd: null, capabilitiesDrop: ['ALL'], seccompProfileType: null,
      },
      level: 'restricted',
      failing: [],
    },
    {
      name: 'migrate', kind: 'init', source: 'last_known', digest: 'sha256:41ab77c0d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f809',
      securityContext: {
        privileged: null, allowPrivilegeEscalation: null, runAsNonRoot: null, runAsUser: null,
        runAsGroup: null, readOnlyRootFilesystem: null, capabilitiesAdd: null, capabilitiesDrop: null, seccompProfileType: null,
      },
      level: 'baseline',
      failing: [
        { check: 'privilegeEscalation', level: 'restricted', field: 'spec.initContainers[migrate].securityContext.allowPrivilegeEscalation', value: null, message: 'allowPrivilegeEscalation must be set to false' },
        { check: 'capabilitiesRestricted', level: 'restricted', field: 'spec.initContainers[migrate].securityContext.capabilities.drop', value: null, message: 'capabilities.drop must include ALL' },
      ],
    },
  ],
  recommendation: {
    recommendation: true,
    targetLevel: 'restricted',
    format: 'strategic-merge-patch',
    yaml:
      '# kguardian recommendation, not applied. Review before use.\n# Target: Pod Security Standards restricted (kubernetes.io/docs/concepts/security/pod-security-standards)\nspec:\n  template:\n    spec:\n      initContainers:\n      - name: migrate\n        securityContext:\n          allowPrivilegeEscalation: false\n          capabilities:\n            drop: ["ALL"]\n',
    caveats: [
      'Checks kguardian cannot see (hostPath and other volume types, hostPort, AppArmor, SELinux, procMount, sysctls) may still fail restricted.',
      "runAsNonRoot: true fails at container start if the image's USER is root; set runAsUser to a UID the image supports.",
    ],
  },
};

export const networkExample: NetworkDimension = {
  status: 'unknown',
  score: null,
  scored: false,
  coverage: { level: 'partial', fraction: null, observedSince: '2026-09-20T06:02:11Z', note: 'Flows from 2 live pods; 214 flow rows summarised' },
  reasons: [{ code: 'policy_state_unknown', message: 'No audit policy covers this workload; applied NetworkPolicies are not visible to the broker' }],
  summary: {
    ingress: { peers: 3, external: 0, ports: ['TCP/8080'] },
    egress: { peers: 4, external: 1, ports: ['TCP/443', 'TCP/5432', 'UDP/53'] },
  },
  peers: [
    {
      direction: 'ingress', protocol: 'TCP', port: 8080,
      peer: { kind: 'pod', namespace: 'ingress-nginx', workloadKind: 'Deployment', workloadName: 'ingress-nginx-controller', name: 'ingress-nginx-controller-5c8d7f9b4-q2w8r', ip: '10.42.1.17' },
      flows: 12, firstSeen: '2026-09-20T06:02:11Z', lastSeen: '2026-09-26T09:58:40Z',
    },
    {
      direction: 'ingress', protocol: 'TCP', port: 8080,
      peer: { kind: 'pod', namespace: 'observability', workloadKind: 'StatefulSet', workloadName: 'prometheus', name: 'prometheus-0', ip: '10.42.2.11' },
      flows: 40, firstSeen: '2026-09-20T06:05:00Z', lastSeen: '2026-09-26T10:00:10Z',
    },
    {
      direction: 'egress', protocol: 'TCP', port: 5432,
      peer: { kind: 'pod', namespace: 'payments', workloadKind: 'StatefulSet', workloadName: 'postgres', name: 'postgres-0', ip: '10.42.1.13' },
      flows: 88, firstSeen: '2026-09-20T06:02:30Z', lastSeen: '2026-09-26T10:04:40Z',
    },
    {
      direction: 'egress', protocol: 'UDP', port: 53,
      peer: { kind: 'service', namespace: 'kube-system', workloadKind: null, workloadName: null, name: 'kube-dns', ip: '10.43.0.10' },
      flows: 51, firstSeen: '2026-09-20T06:02:11Z', lastSeen: '2026-09-26T10:05:00Z',
    },
    {
      direction: 'egress', protocol: 'TCP', port: 443,
      peer: { kind: 'external', namespace: null, workloadKind: null, workloadName: null, name: null, ip: '203.0.113.10' },
      flows: 3, firstSeen: '2026-09-21T11:00:00Z', lastSeen: '2026-09-26T08:00:00Z',
    },
  ],
  truncated: false,
  policy: { audit: null, enforced: null },
};

export const syscallsExample: SyscallsDimension = {
  status: 'warn',
  score: 60,
  scored: true,
  coverage: { level: 'full', fraction: null, observedSince: null, note: 'capture level full on 2 pods' },
  reasons: [{ code: 'no_cr', message: 'No SeccompProfile CR references this workload' }],
  observed: { syscallCount: 61, hash: 'a1b2c3d4e5f60718', architectures: ['SCMP_ARCH_X86_64'], updatedAt: '2026-09-26T09:40:00Z' },
  capture: { level: 'full', complete: true, incompletePods: 0 },
  cr: null,
  denials: { total: 0, syscalls: [], lastSeen: null },
};

export const imagesExample: ImagesDimension = {
  status: 'ok',
  score: null,
  scored: false,
  coverage: { level: 'full', fraction: null, observedSince: '2026-09-19T08:12:00Z', note: 'running window 900 s' },
  reasons: [{ code: 'vulnerabilities_not_configured', message: 'No vulnerability source is configured; images are inventoried but not scored' }],
  runningWindowSeconds: 900,
  containers: [
    {
      name: 'app', kind: 'regular', mixedDigests: false,
      running: [
        {
          digest: 'sha256:9f2c0d1e7a4b3c5d6e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6', imageRef: 'ghcr.io/example/checkout:4.0.9', state: 'running', stateReason: null,
          ranAsInit: false, lastPodName: 'checkout-7d9f8b6c5-2xkqp', firstSeen: '2026-09-19T08:12:00Z', lastSeen: '2026-09-26T10:05:00Z',
        },
      ],
      previous: [
        {
          digest: 'sha256:0c3d5e7f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9', imageRef: 'ghcr.io/example/checkout:4.0.8', state: 'terminated', stateReason: 'Completed',
          ranAsInit: false, lastPodName: null, firstSeen: '2026-09-10T07:00:00Z', lastSeen: '2026-09-19T08:20:00Z',
        },
      ],
    },
    {
      name: 'migrate', kind: 'init', mixedDigests: false,
      running: [],
      previous: [
        {
          digest: 'sha256:41ab77c0d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f809', imageRef: 'ghcr.io/example/checkout-migrate:4.0.9', state: 'terminated', stateReason: 'Completed',
          ranAsInit: true, lastPodName: 'checkout-7d9f8b6c5-2xkqp', firstSeen: '2026-09-19T08:11:00Z', lastSeen: '2026-09-19T08:11:40Z',
        },
      ],
    },
  ],
  truncated: false,
  vulnerabilities: null,
  supplyChain: null,
};

export const computeExample: ComputeDimension = {
  status: 'warn',
  score: null,
  scored: false,
  coverage: { level: 'full', fraction: null, observedSince: '2026-09-26T10:04:00Z', note: '2 containers reporting' },
  reasons: [{ code: 'missing_limits', message: '1 container has no memory limit' }],
  containers: [
    {
      pod: 'checkout-7d9f8b6c5-2xkqp', container: 'app', cpuRequestMillis: 100, cpuLimitMillis: null,
      memRequestBytes: 134217728, memLimitBytes: null, cpuUsageMillis: 12.5, memWorkingSetBytes: 98566144,
      oomKills: 0, throttledRatio: 0.0, updatedAt: '2026-09-26T10:04:00Z',
    },
  ],
  truncated: false,
};

/** §2 example assembled: payments/Deployment/checkout, posture warn. */
export const checkoutProfile: WorkloadProfile = {
  workload: {
    clusterId: 'primary', namespace: 'payments', kind: 'Deployment', name: 'checkout', transient: false,
    pods: { live: 2, names: ['checkout-7d9f8b6c5-2xkqp', 'checkout-7d9f8b6c5-9hmtz'], truncated: false },
  },
  generatedAt: '2026-09-26T10:07:31Z',
  contentHash: 'fnv1a64:6f1c2a9e0b7d4c31',
  version: { revision: 3, contentHash: 'fnv1a64:6f1c2a9e0b7d4c31', createdAt: '2026-09-25T18:40:12Z' },
  snapshotPending: false,
  posture: {
    status: 'warn', score: 71, coverage: 0.47, grade: null,
    weights: { network: 20, syscalls: 15, podSecurity: 20, images: 30 },
    unknownDimensions: ['network', 'images'],
    deductions: [
      { dimension: 'syscalls', findingId: 'syscalls.no_enforcing_profile', points: 40 },
      { dimension: 'podSecurity', findingId: 'podSecurity.readOnlyRootFilesystem/app', points: 5 },
    ],
  },
  attention: [
    {
      id: 'syscalls.no_enforcing_profile', dimension: 'syscalls', severity: 'medium', tier: 'P2',
      title: 'No SeccompProfile CR enforces the observed syscall set',
      detail: 'Pods run with RuntimeDefault only. Export the observed profile (61 syscalls) and apply it in audit mode first.',
      container: null,
    },
    {
      id: 'podSecurity.allowPrivilegeEscalation/migrate', dimension: 'podSecurity', severity: 'medium', tier: 'P2',
      title: 'Init container migrate may escalate privileges',
      detail: 'allowPrivilegeEscalation is not set to false.',
      container: 'migrate',
    },
    {
      id: 'podSecurity.readOnlyRootFilesystem/app', dimension: 'podSecurity', severity: 'low', tier: null,
      title: 'Container app has a writable root filesystem',
      detail: 'Set readOnlyRootFilesystem: true and mount an emptyDir for paths the app writes.',
      container: 'app',
    },
  ],
  findings: [],
  controls: [
    { control: 'networkPolicy', state: 'unknown', detail: 'No audit policy covers this workload; applied NetworkPolicies are not visible to the broker', inSync: null },
    { control: 'seccompProfile', state: 'none', detail: 'No SeccompProfile CR references this workload', inSync: null },
    { control: 'imageAdmission', state: null, detail: 'Signature/admission checks are not configured', inSync: null },
  ],
  readiness: [
    { id: 'trafficObserved24h', ok: true, message: 'Traffic observed for 6d 4h' },
    { id: 'syscallCaptureComplete', ok: true, message: 'Every pod captured at level full (startup included)' },
    { id: 'noWouldDeny24h', ok: null, message: 'No audit policy covers this workload' },
    { id: 'imageSigned', ok: null, message: 'Signature verification is not configured' },
    { id: 'podSecurityRestricted', ok: true, message: 'Evaluated checks pass restricted; 9 checks could not be evaluated' },
  ],
  exposure: { ingressPeers: 3, ingressExternal: 0, egressPeers: 4, egressExternal: 1 },
  dimensions: {
    network: networkExample,
    syscalls: syscallsExample,
    podSecurity: podSecurityExample,
    images: imagesExample,
    compute: computeExample,
  },
};
checkoutProfile.findings = clone(checkoutProfile.attention);

/**
 * payments/Deployment/ledger — posture risk: a privileged container, an
 * audit policy with would-denies, a seccomp CR in audit with drift, and an
 * image rollout in progress (mixed digests) with a crash-looping sidecar.
 */
export const ledgerProfile: WorkloadProfile = (() => {
  const p = clone(checkoutProfile);
  p.workload = { ...p.workload, name: 'ledger', pods: { live: 3, names: ['ledger-6c9d7f5b8-a1b2c', 'ledger-6c9d7f5b8-d3e4f', 'ledger-84f7c9d6b-g5h6j'], truncated: false } };
  p.contentHash = 'fnv1a64:1d9e44a07c3b2f18';
  p.version = { revision: 7, contentHash: 'fnv1a64:1d9e44a07c3b2f18', createdAt: '2026-09-26T09:12:00Z' };
  p.snapshotPending = true;
  p.posture = {
    ...p.posture, status: 'risk', score: 38, coverage: 0.65, grade: null, unknownDimensions: ['images'],
    deductions: [
      { dimension: 'podSecurity', findingId: 'podSecurity.privileged/app', points: 40 },
      { dimension: 'podSecurity', findingId: 'podSecurity.capabilitiesAdded/app', points: 30 },
      { dimension: 'network', findingId: 'network.wouldDeny', points: 30 },
      { dimension: 'syscalls', findingId: 'syscalls.drift', points: 20 },
      { dimension: 'syscalls', findingId: 'syscalls.no_enforcing_profile', points: 20 },
    ],
  };
  p.attention = [
    { id: 'podSecurity.privileged/app', dimension: 'podSecurity', severity: 'high', tier: 'P1', title: 'Container app runs privileged', detail: 'securityContext.privileged is true: the container has every capability and access to host devices.', container: 'app' },
    { id: 'podSecurity.capabilitiesAdded/app', dimension: 'podSecurity', severity: 'high', tier: 'P1', title: 'Container app adds SYS_ADMIN', detail: 'SYS_ADMIN is outside the PSS baseline capability set.', container: 'app' },
    { id: 'network.wouldDeny', dimension: 'network', severity: 'high', tier: 'P1', title: 'Audit policy payments/ledger-egress would deny 14 flows', detail: '14 of 212 flows in the last 24h would be denied if the policy enforced.', container: null },
    { id: 'syscalls.drift', dimension: 'syscalls', severity: 'medium', tier: 'P2', title: 'SeccompProfile CR is missing 2 observed syscalls', detail: 'ptrace and keyctl were observed but are not in deployment-ledger. Enforcing now would block them.', container: null },
    { id: 'images.crashLoop/metrics', dimension: 'images', severity: 'medium', tier: 'P2', title: 'Container metrics is in CrashLoopBackOff', detail: 'The newest digest has not started successfully.', container: 'metrics' },
  ];
  p.findings = [...clone(p.attention), { id: 'images.mixedDigests/app', dimension: 'images', severity: 'low', tier: null, title: 'Container app runs two digests', detail: 'A rollout is in progress or nodes resolved the tag differently.', container: 'app' }];
  p.controls = [
    { control: 'networkPolicy', state: 'audit', detail: 'AuditNetworkPolicy payments/ledger-egress: 198 allow, 14 would-deny (24h)', inSync: null },
    { control: 'seccompProfile', state: 'audit', detail: 'deployment-ledger (SCMP_ACT_LOG) on 2/3 nodes', inSync: false },
    { control: 'imageAdmission', state: null, detail: 'Signature/admission checks are not configured', inSync: null },
  ];
  p.readiness = [
    { id: 'trafficObserved24h', ok: true, message: 'Traffic observed for 9d 2h' },
    { id: 'syscallCaptureComplete', ok: false, message: '1 of 3 pods below full capture (high)' },
    { id: 'noWouldDeny24h', ok: false, message: '14 would-deny verdicts in the last 24h' },
    { id: 'imageSigned', ok: null, message: 'Signature verification is not configured' },
    { id: 'podSecurityRestricted', ok: false, message: 'Container app fails baseline: privileged, capabilities' },
  ];
  p.exposure = { ingressPeers: 2, ingressExternal: 1, egressPeers: 3, egressExternal: 0 };
  p.dimensions.network = {
    ...clone(networkExample), status: 'warn', score: 70, scored: true,
    reasons: [{ code: 'would_deny', message: '14 flows would be denied by payments/ledger-egress' }],
    summary: { ingress: { peers: 2, external: 1, ports: ['TCP/9000'] }, egress: { peers: 3, external: 0, ports: ['TCP/5432', 'UDP/53'] } },
    peers: [
      { direction: 'ingress', protocol: 'TCP', port: 9000, peer: { kind: 'pod', namespace: 'payments', workloadKind: 'Deployment', workloadName: 'checkout', name: 'checkout-7d9f8b6c5-2xkqp', ip: '10.42.1.10' }, flows: 120, firstSeen: '2026-09-17T06:00:00Z', lastSeen: '2026-09-26T10:04:00Z' },
      { direction: 'ingress', protocol: 'TCP', port: 9000, peer: { kind: 'external', namespace: null, workloadKind: null, workloadName: null, name: null, ip: '198.51.100.24' }, flows: 2, firstSeen: '2026-09-25T22:10:00Z', lastSeen: '2026-09-25T22:11:00Z' },
      { direction: 'egress', protocol: 'TCP', port: 5432, peer: { kind: 'pod', namespace: 'payments', workloadKind: 'StatefulSet', workloadName: 'postgres', name: 'postgres-0', ip: '10.42.1.13' }, flows: 76, firstSeen: '2026-09-17T06:00:00Z', lastSeen: '2026-09-26T10:04:00Z' },
      { direction: 'egress', protocol: 'UDP', port: 53, peer: { kind: 'service', namespace: 'kube-system', workloadKind: null, workloadName: null, name: 'kube-dns', ip: '10.43.0.10' }, flows: 30, firstSeen: '2026-09-17T06:00:00Z', lastSeen: '2026-09-26T10:04:00Z' },
      { direction: 'egress', protocol: 'TCP', port: 8443, peer: { kind: 'unresolved', namespace: null, workloadKind: null, workloadName: null, name: null, ip: '10.42.3.99' }, flows: 14, firstSeen: '2026-09-25T02:00:00Z', lastSeen: '2026-09-26T09:00:00Z' },
    ],
    policy: { audit: { policies: [{ namespace: 'payments', name: 'ledger-egress' }], allow: 198, wouldDeny: 14, lastVerdictAt: '2026-09-26T10:01:00Z', windowHours: 24 }, enforced: null },
  };
  p.dimensions.syscalls = {
    ...clone(syscallsExample), status: 'warn', score: 60,
    coverage: { level: 'partial', fraction: null, observedSince: null, note: 'capture level high on 1 of 3 pods' },
    reasons: [{ code: 'capture_incomplete', message: '1 pod below full capture' }, { code: 'cr_drift', message: 'CR is missing 2 observed syscalls' }],
    observed: { syscallCount: 46, hash: '5e6f7a8b9c0d1e2f', architectures: ['SCMP_ARCH_X86_64'], updatedAt: '2026-09-26T09:55:00Z' },
    capture: { level: 'high', complete: false, incompletePods: 1 },
    cr: { name: 'deployment-ledger', defaultAction: 'SCMP_ACT_LOG', mode: 'audit', syscallCount: 44, inSync: false, missing: ['keyctl', 'ptrace'], extra: ['chmod'], distribution: { ready: 2, total: 3, state: 'Partial' } },
    denials: null,
  };
  p.dimensions.podSecurity = {
    ...clone(podSecurityExample), status: 'risk', score: 0,
    reasons: [{ code: 'pss_privileged', message: 'Container app fails baseline checks' }],
    level: 'privileged', levelConfidence: 'confirmed',
    pod: {
      ...clone(podSecurityExample.pod!),
      serviceAccountName: 'ledger',
      hostPID: true,
      failing: [{ check: 'hostNamespaces', level: 'baseline', field: 'spec.hostPID', value: true, message: 'hostPID must be unset or false' }],
    },
    containers: [
      {
        name: 'app', kind: 'regular', source: 'running', digest: 'sha256:b7e1c2d3a4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9',
        securityContext: { privileged: true, allowPrivilegeEscalation: null, runAsNonRoot: null, runAsUser: 0, runAsGroup: null, readOnlyRootFilesystem: null, capabilitiesAdd: ['SYS_ADMIN'], capabilitiesDrop: null, seccompProfileType: null },
        level: 'privileged',
        failing: [
          { check: 'privileged', level: 'baseline', field: 'spec.containers[app].securityContext.privileged', value: true, message: 'privileged must be unset or false' },
          { check: 'capabilitiesBaseline', level: 'baseline', field: 'spec.containers[app].securityContext.capabilities.add', value: ['SYS_ADMIN'], message: 'SYS_ADMIN is not in the baseline capability set' },
          { check: 'runAsUser', level: 'restricted', field: 'spec.containers[app].securityContext.runAsUser', value: 0, message: 'runAsUser must not be 0' },
        ],
      },
      {
        name: 'metrics', kind: 'regular', source: 'running', digest: 'sha256:c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3',
        securityContext: { privileged: null, allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: 65534, runAsGroup: null, readOnlyRootFilesystem: true, capabilitiesAdd: null, capabilitiesDrop: ['ALL'], seccompProfileType: null },
        level: 'restricted',
        failing: [],
      },
    ],
    recommendation: {
      recommendation: true, targetLevel: 'restricted', format: 'strategic-merge-patch',
      yaml: '# kguardian recommendation, not applied. Review before use.\n# Target: Pod Security Standards restricted (kubernetes.io/docs/concepts/security/pod-security-standards)\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        securityContext:\n          privileged: false\n          allowPrivilegeEscalation: false\n          runAsNonRoot: true\n          runAsUser: 10001\n          capabilities:\n            add: null\n            drop: ["ALL"]\n',
      caveats: [
        'Checks kguardian cannot see (hostPath and other volume types, hostPort, AppArmor, SELinux, procMount, sysctls) may still fail restricted.',
        'Removing privileged and SYS_ADMIN changes what the app can do: test before rolling out.',
      ],
    },
  };
  p.dimensions.images = {
    ...clone(imagesExample), status: 'warn',
    reasons: [{ code: 'vulnerabilities_not_configured', message: 'No vulnerability source is configured; images are inventoried but not scored' }, { code: 'crash_loop', message: 'Container metrics is in CrashLoopBackOff' }],
    containers: [
      {
        name: 'app', kind: 'regular', mixedDigests: true,
        running: [
          { digest: 'sha256:b7e1c2d3a4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9', imageRef: 'registry.example.com/payments/ledger:2.14.0', state: 'running', stateReason: null, ranAsInit: false, lastPodName: 'ledger-84f7c9d6b-g5h6j', firstSeen: '2026-09-26T09:10:00Z', lastSeen: '2026-09-26T10:05:00Z' },
          { digest: 'sha256:a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f0', imageRef: 'registry.example.com/payments/ledger:2.13.2', state: 'running', stateReason: null, ranAsInit: false, lastPodName: 'ledger-6c9d7f5b8-a1b2c', firstSeen: '2026-09-17T06:00:00Z', lastSeen: '2026-09-26T10:05:00Z' },
        ],
        previous: [],
      },
      {
        name: 'metrics', kind: 'regular', mixedDigests: false,
        running: [
          { digest: 'sha256:c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3', imageRef: 'registry.example.com/payments/ledger-metrics:0.9.1', state: 'waiting', stateReason: 'CrashLoopBackOff', ranAsInit: false, lastPodName: 'ledger-84f7c9d6b-g5h6j', firstSeen: '2026-09-26T09:10:00Z', lastSeen: '2026-09-26T10:05:00Z' },
        ],
        previous: [
          { digest: 'sha256:d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5', imageRef: 'registry.example.com/payments/ledger-metrics:0.9.2', state: 'waiting', stateReason: 'ImagePullBackOff', ranAsInit: false, lastPodName: 'ledger-84f7c9d6b-g5h6j', firstSeen: '2026-09-26T09:40:00Z', lastSeen: '2026-09-26T09:45:00Z' },
        ],
      },
    ],
  };
  return p;
})();

/** observability/Deployment/grafana — posture ok across every scored dimension. */
export const grafanaProfile: WorkloadProfile = (() => {
  const p = clone(checkoutProfile);
  p.workload = { ...p.workload, namespace: 'observability', name: 'grafana', pods: { live: 1, names: ['grafana-6b8c9d7f5-q1w2e'], truncated: false } };
  p.version = { revision: 2, contentHash: 'fnv1a64:77aa01bc9d3e5f20', createdAt: '2026-09-24T12:00:00Z' };
  p.contentHash = 'fnv1a64:77aa01bc9d3e5f20';
  p.posture = { ...p.posture, status: 'ok', score: 93, coverage: 0.65, grade: null, unknownDimensions: ['images'], deductions: [{ dimension: 'podSecurity', findingId: 'podSecurity.automountToken', points: 5 }] };
  p.attention = [{ id: 'podSecurity.automountToken', dimension: 'podSecurity', severity: 'low', tier: null, title: 'Service account token is mounted', detail: 'automountServiceAccountToken is not set on the pod; the token is assumed mounted.', container: null }];
  p.findings = clone(p.attention);
  p.controls = [
    { control: 'networkPolicy', state: 'audit', detail: 'AuditNetworkPolicy observability/grafana: 540 allow, 0 would-deny (24h)', inSync: null },
    { control: 'seccompProfile', state: 'enforcing', detail: 'deployment-grafana (SCMP_ACT_ERRNO) on 3/3 nodes', inSync: true },
    { control: 'imageAdmission', state: null, detail: 'Signature/admission checks are not configured', inSync: null },
  ];
  p.readiness = p.readiness.map((r) => (r.id === 'noWouldDeny24h' ? { ...r, ok: true, message: '0 would-deny verdicts in the last 24h' } : r));
  p.dimensions.network = { ...clone(networkExample), status: 'ok', score: 100, scored: true, reasons: [{ code: 'audit_clean', message: 'Audit policy observability/grafana: no would-deny in 24h' }], policy: { audit: { policies: [{ namespace: 'observability', name: 'grafana' }], allow: 540, wouldDeny: 0, lastVerdictAt: '2026-09-26T10:02:00Z', windowHours: 24 }, enforced: null } };
  p.dimensions.syscalls = { ...clone(syscallsExample), status: 'ok', score: 100, reasons: [{ code: 'enforcing', message: 'Enforcing CR in sync' }], cr: { name: 'deployment-grafana', defaultAction: 'SCMP_ACT_ERRNO', mode: 'enforce', syscallCount: 52, inSync: true, missing: [], extra: [], distribution: { ready: 3, total: 3, state: 'Ready' } } };
  p.dimensions.podSecurity = { ...clone(podSecurityExample), score: 95, containers: [clone(podSecurityExample.containers[0])], recommendation: null };
  p.dimensions.podSecurity.containers[0].name = 'grafana';
  p.dimensions.compute = { ...clone(computeExample), status: 'ok', reasons: [] };
  return p;
})();

/**
 * flux-system/Deployment/source-controller — just discovered: nothing is
 * known yet. Every dimension unknown; this must never read as clean.
 */
export const unknownProfile: WorkloadProfile = (() => {
  const p = clone(checkoutProfile);
  p.workload = { ...p.workload, namespace: 'flux-system', name: 'source-controller', pods: { live: 1, names: ['source-controller-8f7d6c5b4-z9y8x'], truncated: false } };
  p.version = null;
  p.snapshotPending = true;
  p.posture = { ...p.posture, status: 'unknown', score: null, coverage: 0, grade: null, unknownDimensions: ['network', 'syscalls', 'podSecurity', 'images'], deductions: [] };
  p.attention = [];
  p.findings = [];
  p.controls = [
    { control: 'networkPolicy', state: 'unknown', detail: 'No audit policy covers this workload; applied NetworkPolicies are not visible to the broker', inSync: null },
    { control: 'seccompProfile', state: 'none', detail: 'No SeccompProfile CR references this workload', inSync: null },
    { control: 'imageAdmission', state: null, detail: 'Signature/admission checks are not configured', inSync: null },
  ];
  p.readiness = [
    { id: 'trafficObserved24h', ok: false, message: 'Traffic observed for 12m' },
    { id: 'syscallCaptureComplete', ok: null, message: 'No syscalls reported yet' },
    { id: 'noWouldDeny24h', ok: null, message: 'No audit policy covers this workload' },
    { id: 'imageSigned', ok: null, message: 'Signature verification is not configured' },
    { id: 'podSecurityRestricted', ok: null, message: 'No container securityContext reported yet' },
  ];
  p.exposure = { ingressPeers: null, ingressExternal: null, egressPeers: null, egressExternal: null };
  const unknown = (code: string, message: string) => ({
    status: 'unknown' as PostureStatus, score: null, scored: false,
    coverage: { level: 'none' as const, fraction: null, observedSince: null, note: '' },
    reasons: [{ code, message }],
  });
  p.dimensions.network = { ...clone(networkExample), ...unknown('no_flows', 'No flows observed for this workload yet'), summary: { ingress: { peers: 0, external: 0, ports: [] }, egress: { peers: 0, external: 0, ports: [] } }, peers: [] };
  p.dimensions.syscalls = { ...clone(syscallsExample), ...unknown('no_aggregate', 'No syscalls reported for this workload yet'), observed: null, capture: null, cr: null, denials: null };
  p.dimensions.podSecurity = { ...clone(podSecurityExample), ...unknown('no_security_context', 'No container securityContext has been reported'), level: null, levelConfidence: null, pod: null, containers: [], recommendation: null };
  p.dimensions.images = { ...clone(imagesExample), ...unknown('no_inventory', 'No image inventory for this workload yet'), containers: [] };
  p.dimensions.compute = { ...clone(computeExample), ...unknown('no_compute_data', 'Compute collection is off or no live pods report'), containers: [] };
  return p;
})();

export const PROFILES: WorkloadProfile[] = [checkoutProfile, ledgerProfile, grafanaProfile, unknownProfile];

/** GET /workloads item derived from a profile (§1 shape). */
export function listItemOf(p: WorkloadProfile): WorkloadListItem {
  const d = p.dimensions;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of p.findings) counts[f.severity] += 1;
  const running = d.images.containers.reduce((n, c) => n + c.running.length, 0);
  return {
    clusterId: 'primary', namespace: p.workload.namespace, kind: p.workload.kind, name: p.workload.name,
    revision: p.version?.revision ?? 1, contentHash: p.contentHash, computedAt: '2026-09-26T10:05:00Z',
    lastChangedAt: p.version?.createdAt ?? '2026-09-26T10:05:00Z',
    posture: { status: p.posture.status, score: p.posture.score, coverage: p.posture.coverage, grade: p.posture.grade, unknownDimensions: p.posture.unknownDimensions },
    dimensions: {
      network: { status: d.network.status, score: d.network.score },
      syscalls: { status: d.syscalls.status, score: d.syscalls.score },
      podSecurity: { status: d.podSecurity.status, score: d.podSecurity.score, level: d.podSecurity.level, levelConfidence: d.podSecurity.levelConfidence },
      images: { status: d.images.status, score: d.images.score, runningDigests: d.images.status === 'unknown' ? null : running, mixedDigests: d.images.status === 'unknown' ? null : d.images.containers.some((c) => c.mixedDigests) },
      compute: { status: d.compute.status, score: d.compute.score },
    },
    findingCounts: counts,
  };
}

export const workloadsPage = { items: PROFILES.map(listItemOf).sort((a, b) => `${a.namespace}/${a.kind}/${a.name}`.localeCompare(`${b.namespace}/${b.kind}/${b.name}`)), nextAfter: null };

/** §3.1 example, extended to three revisions of payments/checkout. */
export const checkoutVersions: VersionList = {
  namespace: 'payments', kind: 'Deployment', name: 'checkout',
  items: [
    { revision: 3, contentHash: 'fnv1a64:6f1c2a9e0b7d4c31', createdAt: '2026-09-25T18:40:12Z', dimensionHashes: { network: 'fnv1a64:11', syscalls: 'fnv1a64:22', podSecurity: 'fnv1a64:33', images: 'fnv1a64:44' }, changedDimensions: ['podSecurity', 'images'], posture: { status: 'warn', score: 71, coverage: 0.47, grade: null } },
    { revision: 2, contentHash: 'fnv1a64:2b8e0f7a19c4d653', createdAt: '2026-09-22T09:00:00Z', dimensionHashes: { network: 'fnv1a64:11', syscalls: 'fnv1a64:21', podSecurity: 'fnv1a64:32', images: 'fnv1a64:43' }, changedDimensions: ['network', 'syscalls'], posture: { status: 'warn', score: 64, coverage: 0.47, grade: null } },
    { revision: 1, contentHash: 'fnv1a64:9a7c5e3b1d2f4068', createdAt: '2026-09-20T06:10:00Z', dimensionHashes: { network: 'fnv1a64:10', syscalls: 'fnv1a64:20', podSecurity: 'fnv1a64:30', images: 'fnv1a64:40' }, changedDimensions: ['network', 'syscalls', 'podSecurity', 'images'], posture: { status: 'unknown', score: null, coverage: 0, grade: null } },
  ],
  nextBefore: null,
};

/** §3.3 example (checkout, 2 → 3), plus network and syscall changes for 1 → 2. */
export const checkoutDiff: ProfileDiff = {
  namespace: 'payments', kind: 'Deployment', name: 'checkout',
  from: { revision: 2, contentHash: 'fnv1a64:2b8e0f7a19c4d653', createdAt: '2026-09-22T09:00:00Z' },
  to: { revision: 3, contentHash: 'fnv1a64:6f1c2a9e0b7d4c31', createdAt: '2026-09-25T18:40:12Z' },
  changed: true,
  dimensions: {
    podSecurity: {
      changed: true,
      level: { from: 'baseline', to: 'restricted' },
      pod: [{ field: 'securityContext.seccompProfileType', from: null, to: 'RuntimeDefault' }],
      containersAdded: [], containersRemoved: [],
      containers: [{ name: 'app', fields: [{ field: 'allowPrivilegeEscalation', from: null, to: false }] }],
    },
    images: {
      changed: true,
      containersAdded: [], containersRemoved: [],
      containers: [{ name: 'app', added: ['sha256:9f2c0d1e7a4b3c5d6e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6'], removed: ['sha256:0c3d5e7f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9'] }],
    },
    syscalls: { changed: false, added: [], removed: [], captureLevel: null, cr: null },
    network: { changed: false, added: [], removed: [], audited: null },
  },
};

export const checkoutDiff1to2: ProfileDiff = {
  namespace: 'payments', kind: 'Deployment', name: 'checkout',
  from: { revision: 1, contentHash: 'fnv1a64:9a7c5e3b1d2f4068', createdAt: '2026-09-20T06:10:00Z' },
  to: { revision: 2, contentHash: 'fnv1a64:2b8e0f7a19c4d653', createdAt: '2026-09-22T09:00:00Z' },
  changed: true,
  dimensions: {
    podSecurity: { changed: false, level: null, pod: [], containersAdded: [], containersRemoved: [], containers: [] },
    images: { changed: false, containersAdded: [], containersRemoved: [], containers: [] },
    syscalls: { changed: true, added: ['epoll_pwait2', 'openat2'], removed: ['select'], captureLevel: { from: 'high', to: 'full' }, cr: null },
    network: {
      changed: true,
      added: [{ direction: 'egress', protocol: 'TCP', port: 443, peer: 'external:203.0.113.10' }],
      removed: [{ direction: 'egress', protocol: 'TCP', port: 6379, peer: 'pod:payments/StatefulSet/redis' }],
      audited: null,
    },
  },
};
