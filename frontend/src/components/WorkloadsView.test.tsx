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

const refreshProfiles = vi.fn(async () => {});
vi.mock('../hooks/useSeccompProfiles', () => ({
  useSeccompProfiles: () => ({ api: {}, profiles, loading: false, error: null, refresh: refreshProfiles }),
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
const postureState: { byKey: Map<string, WorkloadListItem>; loading: boolean; loadingMore: boolean; error: unknown; hasMore: boolean; loadMore: () => Promise<void> } = {
  byKey: new Map(capturedItems.map((i) => [keyOf(i), i])),
  loading: false,
  loadingMore: false,
  error: null,
  hasMore: false,
  loadMore,
};
const postureArgs: unknown[][] = [];
vi.mock('../hooks/useWorkloadProfile', () => ({
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

test('verdicts are fetched per kind (so Allow noise cannot push out would-denies), namespace-filtered when narrowed', async () => {
  getAuditVerdicts.mockClear();
  renderView({ allNamespaces: false, namespace: 'observability' });
  await waitFor(() => expect(getAuditVerdicts).toHaveBeenCalledTimes(2));
  expect(getAuditVerdicts).toHaveBeenCalledWith({ limit: 500, namespace: 'observability', verdict: 'WouldDeny' });
  expect(getAuditVerdicts).toHaveBeenCalledWith({ limit: 500, namespace: 'observability', verdict: 'Allow' });
  cleanup();
  getAuditVerdicts.mockClear();
  renderView();
  await waitFor(() => expect(getAuditVerdicts).toHaveBeenCalledTimes(2));
  expect(getAuditVerdicts).toHaveBeenCalledWith({ limit: 500, verdict: 'WouldDeny' });
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

test('posture column: a workload the snapshotter has not reached yet is "not computed yet"', () => {
  renderView({ allPods: capturedPods });
  expect(within(rowNamed('reports')).getByText('not computed yet')).not.toBeNull();
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
    expect(screen.queryByText('not computed yet')).toBeNull();
  } finally {
    postureState.byKey = saved;
    postureState.error = null;
  }
});

test('posture column: pages not yet fetched say "not loaded" and offer Load more', () => {
  const saved = postureState.byKey;
  // Only the first captured page (limit=2) has arrived.
  postureState.byKey = new Map(listPage1.body.items.map((i) => [keyOf(i), i]));
  postureState.hasMore = true;
  loadMore.mockClear();
  try {
    renderView({ allPods: capturedPods });
    expect(within(rowNamed('checkout')).getByText('not loaded')).not.toBeNull();
    expect(screen.queryByText('not computed yet')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Load more postures' }));
    expect(loadMore).toHaveBeenCalledTimes(1);
  } finally {
    postureState.byKey = saved;
    postureState.hasMore = false;
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
