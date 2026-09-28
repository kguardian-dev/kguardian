// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { AuditVerdict, PodInfo } from '../types';
import type { WorkloadProfileSummary } from '../types/seccompWorkload';

afterEach(cleanup);

const profiles: WorkloadProfileSummary[] = [
  {
    namespace: 'payments', kind: 'Deployment', name: 'api', hash: 'h', syscallCount: 61, architectures: ['x86_64'], updatedAt: 't',
    capture: { level: 'full', complete: true, pods: [{ name: 'api-1', level: 'full' }] },
    cr: {
      name: 'deployment-api', defaultAction: 'SCMP_ACT_ERRNO', hash: 'x', syscallCount: 61,
      distribution: { ready: 3, total: 3, state: 'Ready' }, drift: { missing: [], extra: [], inSync: true },
    },
  },
];

const verdicts: AuditVerdict[] = [
  {
    id: 1, policy_uid: 'u', policy_namespace: 'observability', policy_name: 'grafana-ingress', direction: 'Ingress',
    src_namespace: 'payments', src_pod: 'api-1', dst_namespace: 'observability', dst_pod: 'grafana-1',
    dst_port: 3000, protocol: 'TCP', reason: null, observed_at: 't', verdict: 'WouldDeny',
  },
];

// The seccomp profile list as the hook reports it; tests flip it to the
// loading and failed states.
const refreshProfiles = vi.fn(async () => {});
const seccompState: { profiles: WorkloadProfileSummary[]; loading: boolean; error: string | null } = { profiles, loading: false, error: null };
const fallbackArgs: unknown[][] = [];
const fallbackState: { map: Map<string, WorkloadProfileSummary | null> } = { map: new Map() };
vi.mock('../hooks/useSeccompProfiles', () => ({
  useSeccompProfiles: () => ({ api: {}, profiles: seccompState.profiles, loading: seccompState.loading, error: seccompState.error, refresh: refreshProfiles }),
  useSeccompProfileFallback: (...args: unknown[]) => {
    fallbackArgs.push(args);
    return fallbackState.map;
  },
}));
const getAuditVerdicts = vi.fn(async (opts: { verdict?: string; namespace?: string } = {}) =>
  verdicts.filter((v) => !opts.verdict || v.verdict === opts.verdict),
);
vi.mock('../services/api', () => ({ default: { getAuditVerdicts: (o: never) => getAuditVerdicts(o) } }));

// GET /workloads posture summaries: the captured list pages (real Broker
// responses), keyed like the rows. Posture tests render pods for exactly
// those captured workloads.
import { listNamespacePayments, listPage1, listPage2 } from '../fixtures/profile';
import type { WorkloadListItem } from '../types/profile';
const capturedItems: WorkloadListItem[] = [...listPage1.body.items, ...listPage2.body.items, ...listNamespacePayments.body.items];
const keyOf = (i: WorkloadListItem) => `${i.namespace}/${i.kind}/${i.name}`;
const loadMore = vi.fn(async () => {});
const AUTO_PAGES = 5;
const postureState: { byKey: Map<string, WorkloadListItem>; loading: boolean; loadingMore: boolean; error: unknown; hasMore: boolean; pages: number; loadMore: () => Promise<void> } = {
  byKey: new Map(capturedItems.map((i) => [keyOf(i), i])),
  loading: false,
  loadingMore: false,
  error: null,
  hasMore: false,
  pages: 1,
  loadMore,
};
const postureArgs: unknown[][] = [];
vi.mock('../hooks/useWorkloadProfile', () => ({
  POSTURE_AUTO_PAGES: 5,
  useWorkloadPostures: (...args: unknown[]) => {
    postureArgs.push(args);
    return postureState;
  },
}));

import { WorkloadsView } from './WorkloadsView';
import { StatePill } from './Seccomp';

const pod = (name: string, ns: string, kind: string, workload: string, over: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: ns, time_stamp: 't', node_name: 'worker-1', is_dead: false,
  workload_kind: kind, workload_name: workload, capture_level: 'high', ...over,
});

const pods = [
  pod('api-1', 'payments', 'Deployment', 'api', { capture_level: 'full' }),
  pod('grafana-1', 'observability', 'Deployment', 'grafana'),
  pod('source-controller-0', 'flux-system', 'Deployment', 'source-controller'),
];

const renderView = (over: Partial<Parameters<typeof WorkloadsView>[0]> = {}) => {
  const onOpenWorkload = vi.fn();
  const onControlChange = vi.fn();
  render(
    <WorkloadsView
      allPods={pods}
      namespace="payments"
      allNamespaces
      onOpenWorkload={onOpenWorkload}
      onControlChange={onControlChange}
      {...over}
    />,
  );
  return { onOpenWorkload, onControlChange };
};

const rows = () => screen.getAllByTestId('workload-row');
const tile = (label: string) => within(screen.getByRole('group', { name: 'Coverage' })).getByText(label).closest('[class*="rounded-surface"]') as HTMLElement;
/** Run `fn` with the seccomp list in the given state, restoring afterwards. */
async function withSeccomp(state: Partial<typeof seccompState>, fn: () => void | Promise<void>) {
  const saved = { ...seccompState };
  Object.assign(seccompState, state);
  try {
    await fn();
  } finally {
    Object.assign(seccompState, saved);
    fallbackState.map = new Map();
  }
}

test('one row per workload across all namespaces, with network, seccomp and capture state', async () => {
  renderView();
  await waitFor(() => expect(within(rows()[1]).queryByText('Audit')).not.toBeNull());
  expect(rows().map((r) => r.querySelector('a')!.textContent)).toEqual(['source-controller', 'grafana', 'api']);

  const [flux, grafana, api] = rows();
  // Cluster-wide: the namespace is shown under the name.
  expect(within(flux).getByText(/flux-system/)).not.toBeNull();
  // Network: only an audit verdict is a positive signal; otherwise "not reported".
  expect(within(flux).getByText('Not reported')).not.toBeNull();
  expect(within(grafana).getByText('1 would-deny')).not.toBeNull();
  // Seccomp: enforcing is the posture green with a lock, never critical red.
  const enforcing = within(api).getByText('Enforcing');
  expect(enforcing.className).toContain('text-state-enforcing');
  expect(enforcing.className).not.toContain('hubble-error');
  expect(within(grafana).getByText('no profile')).not.toBeNull();
  // Capture: derived from pods when there is no profile, never assumed full.
  expect(within(grafana).getByText('· partial')).not.toBeNull();
  expect(within(api).getByText('full')).not.toBeNull();
});

test('narrowed to the header namespace when not showing all namespaces', () => {
  renderView({ allNamespaces: false, namespace: 'observability' });
  expect(rows()).toHaveLength(1);
  expect(within(rows()[0]).getByText('grafana')).not.toBeNull();
});

test('control=seccomp keeps only profiled workloads and shows the seccomp columns', () => {
  renderView({ control: 'seccomp' });
  expect(rows()).toHaveLength(1);
  expect(screen.getByRole('columnheader', { name: 'Syscalls' })).not.toBeNull();
  expect(within(rows()[0]).getByText('deployment-api')).not.toBeNull();
  expect(within(rows()[0]).getByText('61')).not.toBeNull();
});

test('clicking a row opens that workload; the control tabs switch mode', () => {
  const { onOpenWorkload, onControlChange } = renderView();
  fireEvent.click(rows()[2]);
  expect(onOpenWorkload).toHaveBeenCalledWith({ ns: 'payments', kind: 'Deployment', name: 'api' });
  // The name is also a real link, so it can be opened in a new tab or copied.
  expect(rows()[2].querySelector('a')!.getAttribute('href')).toBe('#/workload?ns=payments&kind=Deployment&name=api');

  // Toggle buttons, not a tablist: there are no tab panels.
  const seccomp = screen.getByRole('button', { name: 'Seccomp' });
  expect(seccomp.getAttribute('aria-pressed')).toBe('false');
  expect(screen.getByRole('button', { name: 'All controls' }).getAttribute('aria-pressed')).toBe('true');
  fireEvent.click(seccomp);
  expect(onControlChange).toHaveBeenCalledWith('seccomp');
});

test('a narrowed seccomp list passes its scope and control to the workload link', () => {
  const { onOpenWorkload } = renderView({ allNamespaces: false, namespace: 'payments', control: 'seccomp' });
  const [api] = rows();
  expect(api.querySelector('a')!.getAttribute('href')).toBe('#/workload?ns=payments&kind=Deployment&name=api&scope=ns&control=seccomp');
  fireEvent.click(api);
  expect(onOpenWorkload).toHaveBeenCalledWith({ ns: 'payments', kind: 'Deployment', name: 'api', scope: 'ns', control: 'seccomp' });
});

test('the seccomp posture tile links into the seccomp columns', () => {
  const { onControlChange } = renderView();
  fireEvent.click(screen.getByRole('button', { name: /Seccomp enforcing/ }));
  expect(onControlChange).toHaveBeenCalledWith('seccomp');
});

test('the header refresh tick reloads profiles; there is no in-page Refresh button', () => {
  refreshProfiles.mockClear();
  const onOpenWorkload = vi.fn();
  const props = { allPods: pods, namespace: 'payments', allNamespaces: true, onOpenWorkload, onControlChange: vi.fn() };
  const { rerender } = render(<WorkloadsView {...props} refreshTick={0} />);
  expect(screen.queryByRole('button', { name: /Refresh/ })).toBeNull();
  expect(refreshProfiles).not.toHaveBeenCalled();
  rerender(<WorkloadsView {...props} refreshTick={1} />);
  expect(refreshProfiles).toHaveBeenCalledTimes(1);
});

test('Audit pills use the audit state token, not the brand accent', async () => {
  renderView();
  const [, grafana] = rows();
  // Network column (audit verdict)…
  const network = await waitFor(() => within(grafana).getByText('Audit'));
  // …and the seccomp lifecycle pill share the token.
  render(<StatePill state="audit" />);
  const seccomp = screen.getAllByText('Audit').find((el) => !grafana.contains(el))!;
  for (const pill of [network, seccomp]) {
    expect(pill.className).toContain('text-state-audit');
    expect(pill.className).not.toContain('hubble-accent');
  }
});

test('verdicts are fetched per kind (so Allow noise cannot push out would-denies) and never with the Broker namespace filter', async () => {
  getAuditVerdicts.mockClear();
  renderView({ allNamespaces: false, namespace: 'observability' });
  await waitFor(() => expect(getAuditVerdicts).toHaveBeenCalledTimes(2));
  // `namespace=` filters on the policy's namespace, which drops cluster-scoped policies' verdicts.
  expect(getAuditVerdicts).toHaveBeenCalledWith({ limit: 500, verdict: 'WouldDeny' });
  expect(getAuditVerdicts).toHaveBeenCalledWith({ limit: 500, verdict: 'Allow' });
  cleanup();
  getAuditVerdicts.mockClear();
  renderView();
  await waitFor(() => expect(getAuditVerdicts).toHaveBeenCalledTimes(2));
  expect(getAuditVerdicts).toHaveBeenCalledWith({ limit: 500, verdict: 'WouldDeny' });
});

test('a narrowed view keeps a cluster-scoped policy\'s verdicts about its own pods and drops the rest', async () => {
  const clusterScoped: AuditVerdict[] = [
    // AuditClusterNetworkPolicy: policy_namespace is empty; the subject is the ingress destination.
    { ...verdicts[0], id: 10, policy_namespace: '', policy_name: 'cluster-baseline-audit', dst_namespace: 'observability', dst_pod: 'grafana-1' },
    { ...verdicts[0], id: 11, policy_namespace: '', policy_name: 'cluster-baseline-audit', dst_namespace: 'flux-system', dst_pod: 'source-controller-0' },
  ];
  getAuditVerdicts.mockImplementationOnce(async () => clusterScoped).mockImplementationOnce(async () => []);
  renderView({ allNamespaces: false, namespace: 'observability' });
  const [grafana] = rows();
  await waitFor(() => expect(within(grafana).queryByText('Audit')).not.toBeNull());
  expect(within(grafana).getByText('1 would-deny')).not.toBeNull();
  expect(tile('Would-deny (recent)').textContent).toContain('1');
});

// Pods for the captured workloads (and one the snapshotter has not reached).
const capturedPods = [
  pod('source-controller-1', 'flux-system', 'Deployment', 'source-controller'),
  pod('node-exporter-a', 'observability', 'DaemonSet', 'node-exporter'),
  pod('otel-collector-1', 'observability', 'Deployment', 'otel-collector'),
  pod('checkout-1', 'payments', 'Deployment', 'checkout'),
  pod('ledger-1', 'payments', 'Deployment', 'ledger'),
  pod('reports-1', 'payments', 'Deployment', 'reports'),
];
const rowNamed = (name: string) => rows().find((r) => r.querySelector('a')!.textContent === name)!;
const pill = (row: HTMLElement) => row.querySelector('td:nth-child(2) [data-status]') as HTMLElement;

test('posture column: the captured status per workload, with coverage and no score; unknown reads "No data"', () => {
  renderView({ allPods: capturedPods });
  // v1.3: known dimensions all ok but images unknown reads unknown, not ok.
  expect(pill(rowNamed('source-controller')).dataset.status).toBe('unknown');
  expect(pill(rowNamed('node-exporter')).dataset.status).toBe('risk');
  expect(pill(rowNamed('checkout')).dataset.status).toBe('warn');
  const otel = pill(rowNamed('otel-collector'));
  expect(otel.dataset.status).toBe('unknown');
  expect(otel.textContent).toBe('No data');
  expect(otel.className).not.toContain('state-enforcing');
  // Coverage beside a known status, never a number inside the pill.
  expect(within(rowNamed('node-exporter')).getByText('50%')).not.toBeNull();
  // Partial unknown shows how much is known; fully unknown shows no percentage.
  expect(within(rowNamed('source-controller')).getByText('50%')).not.toBeNull();
  expect(within(rowNamed('otel-collector')).queryByText(/%$/)).toBeNull();
  for (const r of rows()) {
    const p = pill(r);
    if (p) expect(p.textContent).not.toMatch(/\d/);
  }
});

test('posture column: a workload with no stored snapshot says so, without promising one soon', () => {
  renderView({ allPods: capturedPods });
  const cell = within(rowNamed('reports')).getByText('no snapshot');
  expect(cell.getAttribute('title')).not.toMatch(/every few minutes/);
  expect(cell.getAttribute('title')).toMatch(/can persist/);
  expect(screen.queryByText('not computed yet')).toBeNull();
});

test('posture column: a Broker that cannot serve postures leaves the table working and says why', () => {
  const saved = postureState.byKey;
  postureState.byKey = new Map();
  postureState.error = new Error('This Broker does not serve workload profiles.');
  try {
    renderView({ allPods: capturedPods });
    // Every pod's workload, plus payments/api from the seccomp profile list.
    expect(rows()).toHaveLength(capturedPods.length + 1);
    expect(screen.getByText(/Posture unavailable: This Broker does not serve workload profiles/)).not.toBeNull();
    expect(screen.queryByText('no snapshot')).toBeNull();
  } finally {
    postureState.byKey = saved;
    postureState.error = null;
  }
});

test('posture column: pages are fetched on their own while rendered rows are uncovered, up to the cap', () => {
  const saved = postureState.byKey;
  postureState.byKey = new Map(listPage1.body.items.map((i) => [keyOf(i), i]));
  postureState.hasMore = true;
  postureState.pages = 1;
  loadMore.mockClear();
  try {
    renderView({ allPods: capturedPods });
    // Uncovered rows and more pages: the table asks without a click.
    expect(loadMore).toHaveBeenCalledTimes(1);
    expect(within(rowNamed('checkout')).getByText('not loaded')).not.toBeNull();
    cleanup();
    // Every rendered row covered (api comes from the profile list, reports has no captured posture): nothing more is fetched even though the Broker has more.
    loadMore.mockClear();
    postureState.byKey = new Map([
      ...capturedItems.map((i) => [keyOf(i), i] as const),
      ['payments/Deployment/api', capturedItems[0]],
      ['payments/Deployment/reports', capturedItems[0]],
    ]);
    renderView({ allPods: capturedPods });
    expect(loadMore).not.toHaveBeenCalled();
    cleanup();
    // At the cap: the user asks.
    loadMore.mockClear();
    postureState.byKey = new Map(listPage1.body.items.map((i) => [keyOf(i), i]));
    postureState.pages = AUTO_PAGES;
    renderView({ allPods: capturedPods });
    expect(loadMore).not.toHaveBeenCalled();
    expect(within(rowNamed('checkout')).getByText('not loaded')).not.toBeNull();
    expect(screen.queryByText('no snapshot')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Load more postures' }));
    expect(loadMore).toHaveBeenCalledTimes(1);
  } finally {
    postureState.byKey = saved;
    postureState.hasMore = false;
    postureState.pages = 1;
  }
});

test('postures are requested with the narrowed namespace, posture filter and debounced name search; seccomp mode requests none', async () => {
  postureArgs.length = 0;
  renderView({ allNamespaces: false, namespace: 'payments' });
  expect(postureArgs.at(-1)!.slice(0, 3)).toEqual(['payments', undefined, undefined]);
  fireEvent.change(screen.getByLabelText('Posture'), { target: { value: 'risk' } });
  expect(postureArgs.at(-1)!.slice(0, 3)).toEqual(['payments', 'risk', undefined]);
  fireEvent.change(screen.getByLabelText('Filter workloads'), { target: { value: ' ledg ' } });
  await waitFor(() => expect(postureArgs.at(-1)!.slice(0, 3)).toEqual(['payments', 'risk', 'ledg']));
  cleanup();
  postureArgs.length = 0;
  renderView({ control: 'seccomp' });
  // enabled = false (7th argument) in seccomp mode.
  expect(postureArgs.at(-1)![6]).toBe(false);
});

test('a posture filter keeps only the rows the Broker returned for it', () => {
  const saved = postureState.byKey;
  // What the captured ?status=risk page returned.
  postureState.byKey = new Map(capturedItems.filter((i) => i.posture.status === 'risk').map((i) => [keyOf(i), i]));
  try {
    renderView({ allPods: capturedPods });
    fireEvent.change(screen.getByLabelText('Posture'), { target: { value: 'risk' } });
    expect(rows().map((r) => r.querySelector('a')!.textContent)).toEqual(['node-exporter']);
  } finally {
    postureState.byKey = saved;
  }
});

test('an empty posture filter explains the filter, not pod discovery', () => {
  const saved = postureState.byKey;
  postureState.byKey = new Map();
  try {
    renderView({ allPods: capturedPods });
    fireEvent.change(screen.getByLabelText('Posture'), { target: { value: 'risk' } });
    expect(screen.getByText('No matching workloads')).not.toBeNull();
    expect(screen.getByText(/No workload in all namespaces has posture Risk/)).not.toBeNull();
    expect(screen.queryByText(/once the controller has reported/)).toBeNull();
    fireEvent.change(screen.getByLabelText('Posture'), { target: { value: 'unknown' } });
    expect(screen.getByText(/has no posture data/)).not.toBeNull();
    fireEvent.change(screen.getByLabelText('Posture'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Filter workloads'), { target: { value: 'zzz' } });
    expect(screen.getByText(/No workload name or namespace in all namespaces contains “zzz”/)).not.toBeNull();
  } finally {
    postureState.byKey = saved;
  }
});

test('while the profile list loads, seccomp cells and tiles are unknown, never "no profile", "full" or 0', async () => {
  await withSeccomp({ profiles: [], loading: true, error: null }, () => {
    renderView();
    expect(screen.queryByText('no profile')).toBeNull();
    expect(screen.queryByText('full')).toBeNull();
    for (const r of rows()) {
      expect(within(r).getByText('Unknown').getAttribute('title')).toMatch(/could not be read|unknown/i);
      expect(within(r).getByTestId('capture-unknown')).not.toBeNull();
    }
    for (const label of ['Seccomp enforcing', 'Drifted', 'Partial capture']) {
      expect(tile(label).textContent).toContain('—');
      expect(tile(label).textContent).not.toMatch(/\d/);
    }
    // Workloads and would-deny do not come from the list, so they still count.
    expect(tile('Workloads').textContent).toContain('3');
    expect(screen.queryByRole('alert')).toBeNull();
    // No fallback reads while the list is merely loading.
    expect(fallbackArgs.at(-1)![1]).toBe(false);
  });
});

test('a failed profile list keeps the cells and tiles unknown under the error, and reads the shown rows one at a time', async () => {
  fallbackArgs.length = 0;
  await withSeccomp({ profiles: [], loading: false, error: 'canceling statement due to statement timeout' }, () => {
    renderView();
    expect(screen.getByRole('alert').textContent).toMatch(/statement timeout/);
    expect(screen.getByRole('alert').textContent).toMatch(/read unknown/);
    expect(screen.queryByText('no profile')).toBeNull();
    expect(screen.getAllByText('Unknown')).toHaveLength(3);
    for (const label of ['Seccomp enforcing', 'Drifted', 'Partial capture']) expect(tile(label).textContent).toContain('—');
    // The fallback is asked for exactly the rows on screen, in table order.
    const [, enabled, wanted] = fallbackArgs.at(-1)! as [unknown, boolean, Array<{ namespace: string; name: string }>];
    expect(enabled).toBe(true);
    expect(wanted.map((w) => w.name)).toEqual(['source-controller', 'grafana', 'api']);
  });
});

test('per-workload fallback reads answer the rows they cover; the tiles stay unknown', async () => {
  fallbackState.map = new Map<string, WorkloadProfileSummary | null>([
    ['payments/Deployment/api', profiles[0]],
    // The Broker answered 404: this workload has no profile, which is now known.
    ['observability/Deployment/grafana', null],
  ]);
  await withSeccomp({ profiles: [], loading: false, error: 'timeout' }, () => {
    renderView();
    const [flux, grafana, api] = rows();
    expect(within(api).getByText('Enforcing')).not.toBeNull();
    expect(within(api).getByText('full')).not.toBeNull();
    expect(within(grafana).getByText('no profile')).not.toBeNull();
    expect(within(grafana).getByText('· partial')).not.toBeNull();
    expect(within(flux).getByText('Unknown')).not.toBeNull();
    expect(tile('Seccomp enforcing').textContent).toContain('—');
  });
});

test('seccomp mode: the skeleton while the list loads, and no "No seccomp profiles" claim after it failed', async () => {
  await withSeccomp({ profiles: [], loading: true, error: null }, () => {
    renderView({ control: 'seccomp' });
    expect(screen.getByLabelText('Loading')).not.toBeNull();
    expect(screen.queryByText(/No seccomp profiles/)).toBeNull();
  });
  cleanup();
  await withSeccomp({ profiles: [], loading: false, error: 'timeout' }, () => {
    renderView({ control: 'seccomp' });
    expect(screen.queryByText(/No seccomp profiles/)).toBeNull();
    expect(screen.getByText('Seccomp profiles could not be read')).not.toBeNull();
    for (const label of ['Workloads', 'Enforcing CRs', 'Drifted', 'Partial capture']) expect(tile(label).textContent).toContain('—');
  });
  cleanup();
  // A successful empty list is the one case for the empty state.
  await withSeccomp({ profiles: [], loading: false, error: null }, () => {
    renderView({ control: 'seccomp' });
    expect(screen.getByText('No seccomp profiles in all namespaces')).not.toBeNull();
  });
});

test('drift: syscalls the CR allows but never observed are not a drift and do not count as Drifted', async () => {
  const unobservedOnly: WorkloadProfileSummary = {
    ...profiles[0],
    cr: { ...profiles[0].cr!, drift: { missing: [], extra: ['clock_settime', 'mount'], inSync: false } },
  };
  const missing: WorkloadProfileSummary = {
    ...profiles[0], namespace: 'observability', name: 'grafana',
    cr: { ...profiles[0].cr!, name: 'deployment-grafana', drift: { missing: ['ptrace'], extra: ['mount'], inSync: false } },
  };
  await withSeccomp({ profiles: [unobservedOnly, missing] }, () => {
    renderView();
    const api = rowNamed('api');
    expect(within(api).getByText('in sync')).not.toBeNull();
    expect(within(api).getByTestId('drift-unobserved').textContent).toBe('· 2 allowed but unobserved');
    expect(within(api).queryByText(/extra/)).toBeNull();
    const grafana = rowNamed('grafana');
    expect(within(grafana).getByText('1 missing')).not.toBeNull();
    expect(tile('Drifted').textContent).toContain('1');
    expect(tile('Drifted').textContent).not.toContain('2');
  });
});

test('the would-deny tile counts subject workloads in the recent window and says so, not "audit coverage"', async () => {
  renderView();
  await waitFor(() => expect(tile('Would-deny (recent)').textContent).toContain('1'));
  expect(screen.queryByText('Network audit')).toBeNull();
  expect(tile('Would-deny (recent)').getAttribute('title')).toMatch(/latest 500 audit verdicts/);
  expect(tile('Would-deny (recent)').getAttribute('title')).toMatch(/not policy coverage/);
  expect(tile('Would-deny (recent)').textContent).not.toMatch(/\/3/);
});

test('seccomp mode: node readiness is the CR\'s own status.distribution, with the Broker\'s recent-report count as the qualifier', async () => {
  const cr = { ...profiles[0].cr!, distribution: { ready: 55, total: 55, state: 'Ready', present: 55 }, statusDistribution: { ready: 60, total: 60, state: 'Ready' } };
  await withSeccomp({ profiles: [{ ...profiles[0], cr }] }, () => {
    renderView({ control: 'seccomp' });
    const nodes = within(rows()[0]).getByTestId('cr-nodes');
    expect(nodes.textContent).toBe('60/60Ready· 55/55 reporting');
    expect(nodes.getAttribute('title')).toMatch(/status\.distribution/);
  });
  cleanup();
  // Without a mirrored CR status the Broker's count is all there is, unqualified.
  renderView({ control: 'seccomp' });
  expect(within(rows()[0]).getByTestId('cr-nodes').textContent).toBe('3/3Ready');
});

test('a failed verdict read makes the would-deny tile unknown and says so; the column stays "Not reported"', async () => {
  getAuditVerdicts
    .mockImplementationOnce(async () => {
      throw new Error('canceling statement due to statement timeout');
    })
    .mockImplementationOnce(async () => {
      throw new Error('canceling statement due to statement timeout');
    });
  renderView();
  await waitFor(() => expect(screen.getByTestId('verdicts-unavailable')).not.toBeNull());
  expect(tile('Would-deny (recent)').textContent).toContain('—');
  expect(tile('Would-deny (recent)').textContent).not.toMatch(/\d/);
  expect(tile('Would-deny (recent)').getAttribute('title')).toMatch(/could not be read/);
  for (const r of rows()) expect(within(r).getByText('Not reported')).not.toBeNull();
  expect(screen.queryByText('Audit')).toBeNull();
});

test('posture column: a snapshot that failed before it was ever computed reads "profile failed", and a stale one says so', () => {
  const saved = postureState.byKey;
  const failedOnly: WorkloadListItem = {
    clusterId: 'c', namespace: 'payments', kind: 'Deployment', name: 'reports', revision: null, contentHash: null, computedAt: null, lastChangedAt: null,
    lastError: 'canceling statement due to statement timeout', failedAt: '2026-09-28T12:00:00Z',
  };
  const checkout = capturedItems.find((i) => i.name === 'checkout')!;
  const stale: WorkloadListItem = { ...checkout, lastError: 'canceling statement due to statement timeout', failedAt: '2026-09-28T12:00:00' };
  postureState.byKey = new Map([...capturedItems.map((i) => [keyOf(i), i] as const), [keyOf(failedOnly), failedOnly], [keyOf(stale), stale]]);
  try {
    renderView({ allPods: capturedPods });
    const failed = within(rowNamed('reports')).getByTestId('posture-failed');
    expect(failed.textContent).toMatch(/^profile failed · .+ago$/);
    expect(failed.getAttribute('title')).toMatch(/statement timeout/);
    expect(failed.getAttribute('title')).toMatch(/retried on a later pass/);
    expect(within(rowNamed('reports')).queryByText('no snapshot')).toBeNull();
    // A computed profile with a later failed attempt keeps its status and says the snapshot is stale.
    const row = rowNamed('checkout');
    expect(pill(row).dataset.status).toBe('warn');
    expect(within(row).getByTestId('posture-stale').textContent).toMatch(/snapshot failed .+ago/);
    expect(within(row).getByTestId('posture-stale').getAttribute('title')).toMatch(/last good profile/);
  } finally {
    postureState.byKey = saved;
  }
});
