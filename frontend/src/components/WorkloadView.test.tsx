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
import { answer, replayApi } from '../fixtures/replay';
import {
  PROFILE_CAPTURES,
  checkoutProfile,
  checkoutVersions,
  err404RevisionNotFound,
  ledgerProfile,
  partialProfile,
  refundsProfile,
  riskProfile,
  unknownProfile,
} from '../fixtures/profile';
import type { WorkloadProfile } from '../types/profile';

// Every page here is driven by responses captured from a v1.2 Broker
// (fixtures/captures). Workload identities below are the captured ones.
const CHECKOUT = { ns: 'payments', kind: 'Deployment', name: 'checkout' };
const LEDGER = { ns: 'payments', kind: 'Deployment', name: 'ledger' };
const NODE_EXPORTER = { ns: 'observability', kind: 'DaemonSet', name: 'node-exporter' };
const SOURCE_CONTROLLER = { ns: 'flux-system', kind: 'Deployment', name: 'source-controller' };
const REFUNDS = { ns: 'payments', kind: 'Deployment', name: 'refunds' };
const OTEL = { ns: 'observability', kind: 'Deployment', name: 'otel-collector' };

function renderPage(api: ProfileApi, w: { ns: string; kind: string; name: string } = CHECKOUT, over: Partial<Parameters<typeof WorkloadView>[0]> = {}) {
  const onParamsChange = vi.fn();
  const onBack = vi.fn();
  const utils = render(<WorkloadView {...w} pods={[]} onBack={onBack} onOpenInMap={() => {}} onParamsChange={onParamsChange} api={api} {...over} />);
  return { ...utils, onParamsChange, onBack };
}

const strip = () => screen.getByRole('list', { name: 'Posture by dimension' });
const dimensionPill = (d: string) => strip().querySelector(`[data-dimension="${d}"] [data-status]`) as HTMLElement;
const overallPill = () => screen.getByTitle(/Worst status|No dimension has data/);

test('the profile request is exactly the contract path, encoded', async () => {
  const { api, calls } = replayApi();
  renderPage(api, { ...CHECKOUT, name: 'check out' });
  await waitFor(() => expect(calls).toContain('GET /workloads/payments/Deployment/check%20out/profile'));
});

test.each([
  ['warn', CHECKOUT],
  ['risk', NODE_EXPORTER],
  ['unknown', OTEL],
  ['unknown', SOURCE_CONTROLLER],
] as const)('posture %s (captured) renders as that status', async (status, w) => {
  const { api } = replayApi();
  renderPage(api, w);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(overallPill().dataset.status).toBe(status);
});

test('posture ok renders as OK (no v1.3 capture can be ok: derived from the partial capture with every core dimension ok)', async () => {
  const ok: WorkloadProfile = structuredClone(partialProfile);
  ok.posture = { ...ok.posture, status: 'ok', coverage: 1, unknownDimensions: [], reasons: [] };
  ok.dimensions.podSecurity.status = 'ok';
  ok.dimensions.images.status = 'ok';
  const { api } = replayApi([answer('GET /workloads/flux-system/Deployment/source-controller/profile', ok)]);
  renderPage(api, SOURCE_CONTROLLER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(overallPill().dataset.status).toBe('ok');
  expect(overallPill().textContent).toBe('OK');
  expect(overallPill().className).toContain('state-enforcing');
});

test('v1.3: all known dimensions ok but some unknown is posture unknown, not OK', async () => {
  const { api } = replayApi();
  renderPage(api, SOURCE_CONTROLLER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(overallPill().dataset.status).toBe('unknown');
  expect(overallPill().textContent).toBe('No data');
  expect(dimensionPill('network').dataset.status).toBe('ok');
  expect(dimensionPill('syscalls').dataset.status).toBe('ok');
  expect(screen.getByText('coverage 50%')).not.toBeNull();
});

test('no numeric score anywhere: status, coverage and reasons only', async () => {
  const { api } = replayApi();
  renderPage(api, NODE_EXPORTER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(screen.getByText('coverage 50%')).not.toBeNull();
  // Every pill reads a status word, never "· <number>".
  for (const pill of document.querySelectorAll('[data-status]')) expect(pill.textContent).not.toMatch(/·\s*\d/);
  const why = screen.getByRole('list', { name: 'Why this posture' });
  expect(within(why).getByText('Privileged under PSS: pod spec fail(s) a baseline check')).not.toBeNull();
  expect(within(why).getByText('No syscalls have been captured for this workload')).not.toBeNull();
});

test('ok, warn, risk and unknown dimensions are all distinct; unknown says "No data", never OK', async () => {
  const { api } = replayApi();
  renderPage(api, NODE_EXPORTER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(dimensionPill('network').dataset.status).toBe('warn');
  expect(dimensionPill('syscalls').dataset.status).toBe('unknown');
  expect(dimensionPill('syscalls').textContent).toBe('No data');
  expect(dimensionPill('podSecurity').dataset.status).toBe('risk');
  // v1.3: images is unknown without vulnerability data, but its inventory still shows.
  expect(dimensionPill('images').dataset.status).toBe('unknown');
  expect(strip().querySelector('[data-dimension="images"]')!.textContent).toContain('1 running digest');
  expect(screen.getByText(/no data for syscalls, images/)).not.toBeNull();
  cleanup();
  const { api: api2 } = replayApi();
  renderPage(api2, SOURCE_CONTROLLER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(dimensionPill('network').dataset.status).toBe('ok');
  // ok, warn, risk and unknown pills all look different.
  const byStatus = new Map<string, string>();
  for (const el of document.querySelectorAll('[data-status]')) byStatus.set((el as HTMLElement).dataset.status!, el.className);
  cleanup();
  const { api: api3 } = replayApi();
  renderPage(api3, NODE_EXPORTER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  for (const el of document.querySelectorAll('[data-status]')) byStatus.set((el as HTMLElement).dataset.status!, el.className);
  expect([...byStatus.keys()].sort()).toEqual(['ok', 'risk', 'unknown', 'warn']);
  expect(new Set(byStatus.values()).size).toBe(4);
});

test('pod security restricted is an upper bound: the pill is No data, the level still shows "(at most)"', async () => {
  const { api } = replayApi();
  renderPage(api, SOURCE_CONTROLLER);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  expect(dimensionPill('podSecurity').dataset.status).toBe('unknown');
  expect(strip().querySelector('[data-dimension="podSecurity"]')!.textContent).toContain('Restricted (at most)');
});

test('a freshly seen workload: every pill is No data and "no findings" is not a clean bill', async () => {
  const { api } = replayApi();
  renderPage(api, OTEL);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  for (const d of ['network', 'syscalls', 'podSecurity', 'images', 'compute']) expect(dimensionPill(d).dataset.status).toBe('unknown');
  expect(screen.queryByText('OK')).toBeNull();
  expect(screen.getByText(/not a clean bill of health/)).not.toBeNull();
  expect(screen.getByText(/No flows observed for this workload, so exposure is unknown/)).not.toBeNull();
});

test('Overview: attention capped at 5, Show all reaches every finding worst first', async () => {
  expect(riskProfile.findings).toHaveLength(6);
  const { api } = replayApi();
  renderPage(api, NODE_EXPORTER);
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  expect(within(attention).getAllByRole('listitem')).toHaveLength(5);
  const toggle = within(attention).getByRole('button', { name: 'Show all 6' });
  expect(toggle.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(toggle);
  const items = within(within(attention).getByRole('list', { name: 'All findings' })).getAllByRole('listitem');
  expect(items).toHaveLength(6);
  expect(items[5].textContent).toContain('Container node-exporter has no seccomp profile set');
  fireEvent.click(within(attention).getByRole('button', { name: 'Show top 5' }));
  expect(within(attention).getAllByRole('listitem')).toHaveLength(5);
});

test('Overview: findings outside attention (untiered lows) are reachable too', async () => {
  expect(checkoutProfile.attention).toHaveLength(1);
  const { api } = replayApi();
  renderPage(api, CHECKOUT);
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  fireEvent.click(within(attention).getByRole('button', { name: `Show all ${checkoutProfile.findings.length}` }));
  expect(within(attention).getAllByRole('listitem')).toHaveLength(checkoutProfile.findings.length);
});

test('Overview: controls keep unknown / not configured / none distinct; readiness null is "Can\'t tell"', async () => {
  const { api } = replayApi();
  renderPage(api, CHECKOUT);
  const controls = await screen.findByRole('region', { name: 'Controls' });
  expect(within(controls).getByText('Unknown')).not.toBeNull();
  expect(within(controls).getByText('None')).not.toBeNull();
  expect(within(controls).getByText('Not configured')).not.toBeNull();
  const readiness = screen.getByRole('region', { name: 'Profile readiness' });
  const nulls = checkoutProfile.readiness.filter((r) => r.ok === null).length;
  expect(nulls).toBeGreaterThan(0);
  expect(within(readiness).getAllByTestId('cant-tell')).toHaveLength(nulls);
  expect(within(readiness).getAllByRole('img', { name: "Can't tell" })).toHaveLength(nulls);
  // v1.2: podSecurityRestricted is null for an upper-bound restricted level.
  const pss = within(readiness).getByText(/restricted is not confirmed/).closest('li')!;
  expect(pss.dataset.ok).toBe('null');
});

test('clicking a dimension pill or a tab asks for that tab in the URL', async () => {
  const { api } = replayApi();
  const { onParamsChange } = renderPage(api);
  await screen.findByRole('list', { name: 'Posture by dimension' });
  fireEvent.click(strip().querySelector('[data-dimension="podSecurity"] button')!);
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'podSecurity', from: undefined, to: undefined });
  fireEvent.click(screen.getByRole('tab', { name: 'Versions' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'versions', from: undefined, to: undefined });
  fireEvent.click(screen.getByRole('tab', { name: 'Overview' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: undefined, from: undefined, to: undefined });
});

test('an unknown tab param falls back to Overview', async () => {
  const { api } = replayApi();
  renderPage(api, CHECKOUT, { tab: 'constructor' });
  expect((await screen.findByRole('tab', { name: 'Overview' })).getAttribute('aria-selected')).toBe('true');
});

test('the Back link calls onBack', async () => {
  const { api } = replayApi();
  const { onBack } = renderPage(api);
  fireEvent.click(screen.getByRole('button', { name: 'Workloads' }));
  expect(onBack).toHaveBeenCalledTimes(1);
});

test('Pod security: confirmed privileged, pod-level and container failing checks, and a copyable recommendation', async () => {
  const writeText = vi.fn(async () => {});
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
  const { api } = replayApi();
  renderPage(api, NODE_EXPORTER, { tab: 'podSecurity' });
  expect((await screen.findByTestId('pss-level')).textContent).toBe('Privileged');
  const pod = screen.getByTestId('pss-pod-failing');
  expect(within(pod).getByText('hostPID must be unset or false')).not.toBeNull();
  expect(within(pod).getByText('spec.hostNetwork = true')).not.toBeNull();
  const [c] = screen.getAllByTestId('pss-container');
  expect(within(c).getByText('capabilities.drop must include ALL')).not.toBeNull();
  expect(screen.getByText(/kguardian never applies it/)).not.toBeNull();
  const yaml = riskProfile.dimensions.podSecurity.recommendation!.yaml;
  expect(screen.getByTestId('pss-patch').textContent).toBe(yaml);
  // The node-agent caveat from the Broker is shown with the patch.
  expect(screen.getByText(/This looks like a node agent/)).not.toBeNull();
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Copy securityContext patch' }));
  });
  expect(writeText).toHaveBeenCalledWith(yaml);
  expect(screen.getByText('Copied')).not.toBeNull();
});

test('Pod security: a baseline init container gives a patch for that init container (refunds capture)', async () => {
  const { api } = replayApi();
  renderPage(api, REFUNDS, { tab: 'podSecurity' });
  expect((await screen.findByTestId('pss-level')).textContent).toBe('Baseline (at most)');
  const yaml = refundsProfile.dimensions.podSecurity.recommendation!.yaml;
  expect(yaml).toContain('initContainers');
  expect(screen.getByTestId('pss-patch').textContent).toBe(yaml);
});

test('Pod security: an upper-bound restricted level reads "(at most)", with no patch', async () => {
  const { api } = replayApi();
  renderPage(api, CHECKOUT, { tab: 'podSecurity' });
  expect((await screen.findByTestId('pss-level')).textContent).toBe('Restricted (at most)');
  expect(checkoutProfile.dimensions.podSecurity.recommendation).toBeNull();
  expect(screen.queryByRole('button', { name: 'Copy securityContext patch' })).toBeNull();
});

test('Pod security: stale containers are listed as not evaluated', async () => {
  const { api } = replayApi();
  renderPage(api, LEDGER, { tab: 'podSecurity' });
  const stale = await screen.findByTestId('pss-stale');
  expect(stale.textContent).toContain('legacy-proxy');
});

test('Pod security: a workload with no securityContext reported yet', async () => {
  const { api } = replayApi();
  renderPage(api, OTEL, { tab: 'podSecurity' });
  expect(await screen.findByText('No securityContext reported yet')).not.toBeNull();
});

test('Image & packages: mixed digests, CrashLoopBackOff, a stale container, and vulnerabilities null = not configured', async () => {
  const { api } = replayApi();
  renderPage(api, LEDGER, { tab: 'images' });
  await screen.findByText('Vulnerability data not configured');
  expect(screen.getByText('Mixed digests')).not.toBeNull();
  expect(screen.getByText('Stale')).not.toBeNull();
  const states = screen.getAllByTestId('digest-state').map((e) => e.textContent);
  expect(states).toContain('Running');
  expect(states).toContain('Waiting: CrashLoopBackOff');
  cleanup();
  const { api: api2 } = replayApi();
  renderPage(api2, CHECKOUT, { tab: 'images' });
  await screen.findByText('Vulnerability data not configured');
  fireEvent.click(screen.getByText(/earlier or not-started digest/));
  expect(screen.getAllByTestId('digest-state').map((e) => e.textContent)).toContain('Ran as init (completed)');
});

test('Versions: lists the stored revisions (revision 1 trimmed) and the default diff', async () => {
  const { api, calls } = replayApi();
  const { onParamsChange } = renderPage(api, CHECKOUT, { tab: 'versions' });
  const diff = await screen.findByTestId('diff-viewer');
  expect(within(diff).getByText(/PSS level: baseline → restricted/)).not.toBeNull();
  expect(calls).toContain('GET /workloads/payments/Deployment/checkout/profile/diff');
  // No from/to in the URL: the pickers show the pair the Broker chose (v3 → v4).
  expect((screen.getByLabelText('From') as HTMLSelectElement).value).toBe('3');
  expect((screen.getByLabelText('To') as HTMLSelectElement).value).toBe('4');
  // The oldest retained revision's changes are unknown (its predecessor was trimmed).
  expect(screen.getByText('changes unknown (the previous version was trimmed)')).not.toBeNull();
  const v2 = checkoutVersions.items.find((v) => v.revision === 2)!;
  expect(v2.changedDimensions).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /^v2/ }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'versions', from: undefined, to: '2' });
});

test('Versions: an explicit from/to pair is requested and rendered', async () => {
  const { api, calls } = replayApi();
  renderPage(api, CHECKOUT, { tab: 'versions', from: '2', to: '4' });
  const diff = await screen.findByTestId('diff-viewer');
  await waitFor(() => expect(within(diff).getByText(/external:198\.51\.100\.20/)).not.toBeNull());
  expect(calls).toContain('GET /workloads/payments/Deployment/checkout/profile/diff?from=2&to=4');
});

test('Versions: a diff whose predecessor was trimmed (fromTrimmed) says so', async () => {
  const { api } = replayApi();
  renderPage(api, CHECKOUT, { tab: 'versions', to: '2' });
  const diff = await screen.findByTestId('diff-viewer');
  await waitFor(() => expect(within(diff).getByText(/Earlier versions were trimmed by retention/)).not.toBeNull());
  // The From picker says so rather than showing a revision that was not compared.
  const fromPicker = screen.getByLabelText('From') as HTMLSelectElement;
  expect(fromPicker.selectedOptions[0].textContent).toBe('trimmed');
});

test('Versions: a 404 revision_not_found says versions were trimmed and offers the latest comparison', async () => {
  // The captured 404 is for from=1&to=3; the page asks exactly that.
  expect(err404RevisionNotFound.request).toBe('GET /workloads/payments/Deployment/checkout/profile/diff?from=1&to=3');
  const { api } = replayApi();
  const { onParamsChange } = renderPage(api, CHECKOUT, { tab: 'versions', from: '1', to: '3' });
  const notice = await screen.findByTestId('diff-trimmed');
  expect(notice.textContent).toContain('Earlier versions were trimmed by retention');
  // The pickers show the pair that was asked for, not a guess.
  expect((screen.getByLabelText('From') as HTMLSelectElement).selectedOptions[0].textContent).toBe('v1 (not retained)');
  expect((screen.getByLabelText('To') as HTMLSelectElement).value).toBe('3');
  expect(screen.queryByRole('alert')).toBeNull();
  fireEvent.click(within(notice).getByRole('button', { name: 'Compare the latest versions' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'versions', from: undefined, to: undefined });
});

test('404 workload_not_found (captured) says there is no such workload', async () => {
  const { api } = replayApi();
  renderPage(api, { ns: 'payments', kind: 'Deployment', name: 'does-not-exist' });
  expect(await screen.findByText('No workload payments/does-not-exist')).not.toBeNull();
});

test('a 404 with no contract code is an older Broker, not a missing workload', async () => {
  const { api } = replayApi();
  renderPage(api, { ns: 'payments', kind: 'Deployment', name: 'never-captured' });
  expect(await screen.findByText('Profiles not available')).not.toBeNull();
  expect(screen.queryByText(/No workload/)).toBeNull();
});

test('503 (read budget) shows a section error with Retry, and Retry recovers', async () => {
  let busy = true;
  const fetchImpl = (async () =>
    busy ? new Response('busy', { status: 503 }) : new Response(JSON.stringify(checkoutProfile), { status: 200 })) as unknown as typeof fetch;
  renderPage(new ProfileApi({ fetchImpl }));
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

test('header: newer changes not yet versioned vs not versioned yet', async () => {
  const pending: WorkloadProfile = { ...checkoutProfile, snapshotPending: true };
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', pending)]);
  renderPage(api);
  expect(await screen.findByText(/newer changes not yet versioned/)).not.toBeNull();
  cleanup();
  const unversioned: WorkloadProfile = { ...checkoutProfile, version: null, snapshotPending: true };
  const { api: api2 } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', unversioned)]);
  renderPage(api2);
  expect(await screen.findByText(/not versioned yet/)).not.toBeNull();
  expect(screen.queryByText(/newer changes not yet versioned/)).toBeNull();
});

test('Syscalls: the seccomp drawer opens for this workload, and nothing loads the cluster-wide list', async () => {
  const fetchSpy = vi.fn(() => Promise.reject(new Error('unexpected')));
  vi.stubGlobal('fetch', fetchSpy);
  const { api } = replayApi();
  renderPage(api, LEDGER, { tab: 'syscalls' });
  fireEvent.click(await screen.findByRole('button', { name: 'Open seccomp profile' }));
  expect(screen.getByTestId('seccomp-drawer').textContent).toBe('payments/Deployment/ledger');
  expect(fetchSpy.mock.calls.map((c) => String((c as unknown[])[0]))).not.toContain('/api/seccomp/profiles');
});

test('Syscalls: no seccomp button when nothing has been observed', async () => {
  const { api } = replayApi();
  renderPage(api, NODE_EXPORTER, { tab: 'syscalls' });
  await screen.findByText('No syscalls reported yet');
  expect(screen.queryByRole('button', { name: 'Open seccomp profile' })).toBeNull();
});

test.each(PROFILE_CAPTURES.flatMap((c) => ['overview', 'network', 'syscalls', 'images', 'podSecurity', 'versions'].map((tab) => [c.request, tab] as const)))(
  'captured %s renders the %s tab without errors',
  async (request, tab) => {
    const errors = vi.spyOn(console, 'error');
    const [, ns, kind, name] = request.match(/^GET \/workloads\/([^/]+)\/([^/]+)\/([^/]+)\/profile$/)!;
    const { api } = replayApi();
    renderPage(api, { ns, kind, name }, { tab });
    await screen.findByRole('list', { name: 'Posture by dimension' });
    expect(screen.getByRole('tab', { selected: true }).id).toBe(`profile-tab-${tab}`);
    if (tab !== 'versions') expect(screen.queryByRole('alert')).toBeNull();
    expect(errors).not.toHaveBeenCalled();
    errors.mockRestore();
  },
);

// Keep the fixture set honest: one capture per posture status.
test('the captures cover warn, risk and unknown (v1.3 has no posture ok)', () => {
  expect([checkoutProfile, riskProfile, unknownProfile, partialProfile, refundsProfile, ledgerProfile].map((p) => p.posture.status)).toEqual([
    'warn', 'risk', 'unknown', 'unknown', 'warn', 'warn',
  ]);
});
