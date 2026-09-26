// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// The seccomp drawer is the existing component; here it only needs to show
// which workload it was opened for (it loads that one workload's detail).
vi.mock('./Seccomp/SeccompProfileDrawer', () => ({
  SeccompProfileDrawer: (p: { workload: { ns: string; kind: string; name: string }; summary: unknown }) => (
    <div data-testid="seccomp-drawer" data-summary={String(p.summary)}>{`${p.workload.ns}/${p.workload.kind}/${p.workload.name}`}</div>
  ),
}));

import { WorkloadView } from './WorkloadView';
import { ProfileApi } from '../services/profileApi';
import {
  checkoutDiff,
  checkoutDiff1to2,
  checkoutProfile,
  checkoutVersions,
  grafanaProfile,
  ledgerProfile,
  unknownProfile,
} from '../fixtures/profile';
import type { WorkloadProfile } from '../types/profile';
// A real response captured from the broker implementation (PR 1669, local
// run). Guards against drift between the hand-built fixtures and what ships.
import realSample from '../fixtures/profile-sample.json';

type Reply = { status: number; body: unknown };

/** A ProfileApi over a fake fetch: `route(url)` answers each request. */
function fakeApi(route: (url: URL) => Reply) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://x');
    calls.push(url.pathname + url.search);
    const r = route(url);
    return new Response(typeof r.body === 'string' ? r.body : JSON.stringify(r.body), { status: r.status });
  }) as unknown as typeof fetch;
  return { api: new ProfileApi({ fetchImpl }), calls };
}

function serving(profile: WorkloadProfile) {
  return fakeApi((url) => {
    if (url.pathname.endsWith('/profile')) return { status: 200, body: profile };
    if (url.pathname.endsWith('/profile/versions')) return { status: 200, body: checkoutVersions };
    if (url.pathname.endsWith('/profile/diff')) {
      return { status: 200, body: url.searchParams.get('to') === '2' ? checkoutDiff1to2 : checkoutDiff };
    }
    return { status: 404, body: 'not found' };
  });
}

function renderPage(api: ProfileApi, over: Partial<Parameters<typeof WorkloadView>[0]> = {}) {
  const onParamsChange = vi.fn();
  const onBack = vi.fn();
  const w = { ns: 'payments', kind: 'Deployment', name: 'checkout' };
  const utils = render(
    <WorkloadView {...w} pods={[]} onBack={onBack} onOpenInMap={() => {}} onParamsChange={onParamsChange} api={api} {...over} />,
  );
  return { ...utils, onParamsChange, onBack };
}

const dimensionPill = (d: string) =>
  screen.getByRole('list', { name: 'Posture by dimension' }).querySelector(`[data-dimension="${d}"] [data-status]`) as HTMLElement;

test('the profile request is exactly the contract path, encoded', async () => {
  const { api, calls } = serving(checkoutProfile);
  renderPage(api, { name: 'check out' });
  await waitFor(() => expect(calls).toContain('/api/workloads/payments/Deployment/check%20out/profile'));
});

test.each([
  ['warn', checkoutProfile],
  ['risk', ledgerProfile],
  ['ok', grafanaProfile],
  ['unknown', unknownProfile],
] as const)('posture %s renders as that status', async (status, profile) => {
  const { api } = serving(profile);
  renderPage(api);
  const overall = await screen.findByTitle(/Worst status|No dimension has data/);
  expect(overall.dataset.status).toBe(status);
});

test('ok, warn, risk and unknown dimensions are all distinct; unknown says "No data", never OK', async () => {
  const { api } = serving(checkoutProfile);
  renderPage(api);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(dimensionPill('network').dataset.status).toBe('unknown');
  expect(dimensionPill('network').textContent).toBe('No data');
  expect(dimensionPill('syscalls').dataset.status).toBe('warn');
  expect(dimensionPill('syscalls').textContent).toContain('60');
  expect(dimensionPill('podSecurity').dataset.status).toBe('ok');
  const classes = new Set(['network', 'syscalls', 'podSecurity'].map((d) => dimensionPill(d).className));
  expect(classes.size).toBe(3);
  // The rollup names the dimensions its score leaves out (v1.1: unknown OR
  // known-but-unscored — images has an inventory, so it is not "No data").
  expect(screen.getByText(/not scored: network, images/)).not.toBeNull();
  expect(dimensionPill('images').dataset.status).toBe('ok');
});

test('a workload with no data at all: every pill is No data and "no findings" is not a clean bill', async () => {
  const { api } = serving(unknownProfile);
  renderPage(api, { ns: 'flux-system', name: 'source-controller' });
  await screen.findByRole('list', { name: 'Posture by dimension' });
  for (const d of ['network', 'syscalls', 'podSecurity', 'images', 'compute']) {
    expect(dimensionPill(d).dataset.status).toBe('unknown');
  }
  expect(screen.queryByText('OK')).toBeNull();
  expect(screen.getByText(/not a clean bill of health/)).not.toBeNull();
  expect(screen.getByText(/No flows observed for this workload, so exposure is unknown/)).not.toBeNull();
});

test('Overview: needs attention is capped at 5, controls and readiness keep null distinct', async () => {
  const many = structuredClone(ledgerProfile);
  many.attention = [...many.attention, ...many.attention.map((f) => ({ ...f, id: `${f.id}-2` }))];
  const { api } = serving(many);
  renderPage(api, { name: 'ledger' });
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  expect(within(attention).getAllByRole('listitem')).toHaveLength(5);
  const controls = screen.getByRole('region', { name: 'Controls' });
  expect(within(controls).getByText('Not configured')).not.toBeNull();
  expect(within(controls).getByText('drifted')).not.toBeNull();
  const readiness = screen.getByRole('region', { name: 'Profile readiness' });
  expect(within(readiness).getAllByRole('img', { name: 'Fail' }).length).toBe(3);
  expect(within(readiness).getAllByRole('img', { name: "Can't tell" }).length).toBe(1);
});

test('clicking a dimension pill or a tab asks for that tab in the URL', async () => {
  const { api } = serving(checkoutProfile);
  const { onParamsChange } = renderPage(api);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  fireEvent.click(screen.getByRole('list', { name: 'Posture by dimension' }).querySelector('[data-dimension="podSecurity"] button')!);
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'podSecurity', from: undefined, to: undefined });
  fireEvent.click(screen.getByRole('tab', { name: 'Versions' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'versions', from: undefined, to: undefined });
  fireEvent.click(screen.getByRole('tab', { name: 'Overview' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: undefined, from: undefined, to: undefined });
});

test('an unknown tab param falls back to Overview', async () => {
  const { api } = serving(checkoutProfile);
  renderPage(api, { tab: 'constructor' });
  expect((await screen.findByRole('tab', { name: 'Overview' })).getAttribute('aria-selected')).toBe('true');
});

test('the Back link goes back to the list', async () => {
  const { api } = serving(checkoutProfile);
  const { onBack } = renderPage(api);
  fireEvent.click(screen.getByRole('button', { name: 'Workloads' }));
  expect(onBack).toHaveBeenCalledTimes(1);
});

test('Pod security: level with its confidence, failing checks per container, and a copyable patch that is only a recommendation', async () => {
  const writeText = vi.fn(async () => {});
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
  const { api } = serving(checkoutProfile);
  renderPage(api, { tab: 'podSecurity' });
  expect((await screen.findByTestId('pss-level')).textContent).toBe('Restricted (at most)');
  const [app, migrate] = screen.getAllByTestId('pss-container');
  expect(within(app).getByText('Passes every evaluated check.')).not.toBeNull();
  expect(within(migrate).getByText('allowPrivilegeEscalation must be set to false')).not.toBeNull();
  expect(within(migrate).getByText(/securityContext.capabilities.drop = unset/)).not.toBeNull();
  expect(screen.getByText(/kguardian never applies it/)).not.toBeNull();
  expect(screen.getByTestId('pss-patch').textContent).toBe(checkoutProfile.dimensions.podSecurity.recommendation!.yaml);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Copy securityContext patch' }));
  });
  expect(writeText).toHaveBeenCalledWith(checkoutProfile.dimensions.podSecurity.recommendation!.yaml);
  expect(screen.getByText('Copied')).not.toBeNull();
});

test('Pod security: a confirmed privileged level is stated flat', async () => {
  const { api } = serving(ledgerProfile);
  renderPage(api, { name: 'ledger', tab: 'podSecurity' });
  expect((await screen.findByTestId('pss-level')).textContent).toBe('Privileged');
});

test('Image & packages: digest states, mixed digests, and vulnerabilities null = not configured', async () => {
  const { api } = serving(ledgerProfile);
  renderPage(api, { name: 'ledger', tab: 'images' });
  await screen.findByText('Vulnerability data not configured');
  expect(screen.getByText('Mixed digests')).not.toBeNull();
  const states = screen.getAllByTestId('digest-state').map((e) => e.textContent);
  expect(states).toContain('Running');
  expect(states).toContain('Waiting: CrashLoopBackOff');
  expect(states).toContain('Waiting: ImagePullBackOff');
  cleanup();
  const { api: api2 } = serving(checkoutProfile);
  renderPage(api2, { tab: 'images' });
  await screen.findByText('Vulnerability data not configured');
  expect(screen.getAllByTestId('digest-state').map((e) => e.textContent)).toContain('Ran as init (completed)');
});

test('Versions: lists stored revisions and shows the diff; picking a revision updates the URL selection', async () => {
  const { api, calls } = serving(checkoutProfile);
  const { onParamsChange } = renderPage(api, { tab: 'versions' });
  const diff = await screen.findByTestId('diff-viewer');
  expect(within(diff).getByText(/PSS level: baseline → restricted/)).not.toBeNull();
  expect(calls).toContain('/api/workloads/payments/Deployment/checkout/profile/diff');
  fireEvent.click(screen.getByRole('button', { name: /v2/ }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'versions', from: undefined, to: '2' });
});

test('Versions: a to= selection from the URL is requested from the broker', async () => {
  const { api, calls } = serving(checkoutProfile);
  renderPage(api, { tab: 'versions', to: '2' });
  const diff = await screen.findByTestId('diff-viewer');
  await waitFor(() => expect(within(diff).getByText(/openat2/)).not.toBeNull());
  expect(calls).toContain('/api/workloads/payments/Deployment/checkout/profile/diff?to=2');
});

test('404 workload_not_found says there is no such workload', async () => {
  const { api } = fakeApi(() => ({ status: 404, body: { error: 'workload_not_found', message: 'no such workload' } }));
  renderPage(api, { name: 'api' });
  expect(await screen.findByText('No workload payments/api')).not.toBeNull();
});

test('a 404 with no contract code is an older Broker, not a missing workload', async () => {
  const { api } = fakeApi(() => ({ status: 404, body: 'Not Found' }));
  renderPage(api);
  expect(await screen.findByText('Profiles not available')).not.toBeNull();
  expect(screen.queryByText(/No workload/)).toBeNull();
});

test('503 (read budget) shows a section error with Retry, and Retry recovers', async () => {
  let busy = true;
  const { api } = fakeApi((url) =>
    busy ? { status: 503, body: 'busy' } : url.pathname.endsWith('/profile') ? { status: 200, body: checkoutProfile } : { status: 404, body: '' },
  );
  renderPage(api);
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/read budget/);
  busy = false;
  fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
  expect(await screen.findByRole('list', { name: 'Posture by dimension' })).not.toBeNull();
});

test('while loading, no "no workload" claim is made', () => {
  const fetchImpl = vi.fn(() => new Promise<Response>(() => {})) as unknown as typeof fetch;
  renderPage(new ProfileApi({ fetchImpl }));
  expect(screen.queryByText(/No workload/)).toBeNull();
  expect(screen.getByLabelText('Loading')).not.toBeNull();
});

test('no findings with a known-but-unscored dimension names only the dimensions that truly have no data', async () => {
  const p = structuredClone(checkoutProfile);
  p.attention = [];
  p.findings = [];
  const { api } = serving(p);
  renderPage(api);
  // unknownDimensions is [network, images], but images has an inventory.
  expect(await screen.findByText(/1 dimension has no data yet \(Network\)/)).not.toBeNull();
});

test('Pod security: pod-level failing checks (contract v1.1) are listed', async () => {
  const { api } = serving(ledgerProfile);
  renderPage(api, { name: 'ledger', tab: 'podSecurity' });
  const pod = await screen.findByTestId('pss-pod-failing');
  expect(within(pod).getByText('hostPID must be unset or false')).not.toBeNull();
  expect(within(pod).getByText('spec.hostPID = true')).not.toBeNull();
});

test('header: an unversioned workload says so; a versioned one with newer changes says that instead', async () => {
  const { api } = serving(unknownProfile);
  renderPage(api, { ns: 'flux-system', name: 'source-controller' });
  expect(await screen.findByText(/not versioned yet/)).not.toBeNull();
  expect(screen.queryByText(/newer changes not yet versioned/)).toBeNull();
  cleanup();
  const { api: api2 } = serving(ledgerProfile);
  renderPage(api2, { name: 'ledger' });
  expect(await screen.findByText(/newer changes not yet versioned/)).not.toBeNull();
});

test('Versions: changedDimensions null (predecessor trimmed) is shown as unknown, not as "no change"', async () => {
  const versions = structuredClone(checkoutVersions);
  versions.items[2].changedDimensions = null;
  versions.items[2].revision = 9;
  const { api } = fakeApi((url) =>
    url.pathname.endsWith('/profile/versions')
      ? { status: 200, body: versions }
      : url.pathname.endsWith('/profile/diff')
        ? { status: 200, body: checkoutDiff }
        : { status: 200, body: checkoutProfile },
  );
  renderPage(api, { tab: 'versions' });
  expect(await screen.findByText('changes unknown (the previous version was trimmed)')).not.toBeNull();
});

test.each(['overview', 'network', 'syscalls', 'images', 'podSecurity'])('the real broker sample renders the %s tab', async (tab) => {
  const errors = vi.spyOn(console, 'error');
  const { api } = serving(realSample as unknown as WorkloadProfile);
  renderPage(api, { tab });
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(screen.getByRole('tab', { selected: true }).id).toBe(`profile-tab-${tab}`);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(errors).not.toHaveBeenCalled();
  errors.mockRestore();
});

test('Overview: findings beyond the top 5 are reachable with Show all, sorted worst first', async () => {
  const p = structuredClone(ledgerProfile);
  expect(p.findings.length).toBe(6);
  const { api } = serving(p);
  renderPage(api, { name: 'ledger' });
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  expect(within(attention).getAllByRole('listitem')).toHaveLength(5);
  const toggle = within(attention).getByRole('button', { name: 'Show all 6' });
  expect(toggle.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(toggle);
  const all = within(attention).getByRole('list', { name: 'All findings' });
  const items = within(all).getAllByRole('listitem');
  expect(items).toHaveLength(6);
  expect(items[5].textContent).toContain('Container app runs two digests');
  fireEvent.click(within(attention).getByRole('button', { name: 'Show top 5' }));
  expect(within(attention).getAllByRole('listitem')).toHaveLength(5);
});

test('Syscalls: the seccomp drawer opens for this workload without fetching the cluster-wide list', async () => {
  const { api } = serving(ledgerProfile);
  const fetchSpy = vi.fn(() => Promise.reject(new Error('unexpected')));
  vi.stubGlobal('fetch', fetchSpy);
  renderPage(api, { name: 'ledger', tab: 'syscalls' });
  fireEvent.click(await screen.findByRole('button', { name: 'Open seccomp profile' }));
  expect(screen.getByTestId('seccomp-drawer').textContent).toBe('payments/Deployment/ledger');
  expect(fetchSpy.mock.calls.map((c) => String((c as unknown[])[0]))).not.toContain('/api/seccomp/profiles');
});

test('Syscalls: no seccomp button when nothing has been observed', async () => {
  const { api } = serving(unknownProfile);
  renderPage(api, { ns: 'flux-system', name: 'source-controller', tab: 'syscalls' });
  await screen.findByText('No syscalls reported yet');
  expect(screen.queryByRole('button', { name: 'Open seccomp profile' })).toBeNull();
});

test('Versions: a diff against a trimmed revision says so and offers the latest comparison', async () => {
  const { api } = fakeApi((url) => {
    if (url.pathname.endsWith('/profile/versions')) return { status: 200, body: checkoutVersions };
    if (url.pathname.endsWith('/profile/diff')) return { status: 404, body: { error: 'revision_not_found', message: 'revision 1 not found' } };
    return { status: 200, body: checkoutProfile };
  });
  const { onParamsChange } = renderPage(api, { tab: 'versions', from: '1', to: '3' });
  const notice = await screen.findByTestId('diff-trimmed');
  expect(notice.textContent).toContain('Earlier versions were trimmed by retention');
  expect(screen.queryByRole('alert')).toBeNull();
  fireEvent.click(within(notice).getByRole('button', { name: 'Compare the latest versions' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'versions', from: undefined, to: undefined });
});
