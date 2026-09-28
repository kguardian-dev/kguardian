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
import { replayVulnApi } from '../fixtures/vulns';
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
  const utils = render(<WorkloadView {...w} pods={[]} onBack={onBack} onOpenInMap={() => {}} onParamsChange={onParamsChange} api={api} vulnApi={replayVulnApi().api} {...over} />);
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

test('Pod security: a workload with no securityContext reported yet still shows its Capabilities panel', async () => {
  const { api } = replayApi();
  renderPage(api, OTEL, { tab: 'podSecurity' });
  expect(await screen.findByText('No securityContext reported yet')).not.toBeNull();
  expect(screen.getByRole('region', { name: 'Capabilities' })).not.toBeNull();
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
    busy ? new Response('broker read memory budget exhausted: this request needs 51200 KiB of a 262144 KiB budget and waited 5000 ms without getting it', { status: 503, headers: { 'Retry-After': '1' } }) : new Response(JSON.stringify(checkoutProfile), { status: 200 })) as unknown as typeof fetch;
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

test('Overview: a drift finding is labelled Drift, and a drift check not evaluated says so (never "no drift")', async () => {
  // The checkout capture with a v1.7 drift block added: one unshipped-file
  // finding, and the check not evaluated for the sidecar.
  const drifted: WorkloadProfile = {
    ...checkoutProfile,
    attention: [
      {
        id: 'drift.unshippedExecutable/app',
        dimension: 'drift',
        severity: 'high',
        tier: null,
        title: 'Container app ran files its image did not ship (memfd)',
        detail: '1 file(s) executed or loaded from a memfd',
        container: 'app',
      },
      ...checkoutProfile.attention,
    ],
    drift: {
      evaluated: ['tagMoved'],
      notEvaluated: [{ type: 'unshippedExecutable', container: 'side', reason: 'no_runtime_data' }],
      items: [{ type: 'unshippedExecutable', findingId: 'drift.unshippedExecutable/app', severity: 'high', container: 'app' }],
    },
  };
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', drifted)]);
  renderPage(api, CHECKOUT);
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  const first = within(attention).getAllByRole('listitem')[0];
  expect(first.textContent).toContain('ran files its image did not ship');
  expect(first.textContent).toContain('Drift');
  const note = within(attention).getByRole('list', { name: 'Drift checks not evaluated' });
  expect(note.textContent).toContain('unshippedExecutable not evaluated for container side');
  expect(note.textContent).toContain('no runtime capture heartbeat for this container');
  expect(note.textContent).toContain('does not mean no drift');
});

test('Overview: no findings but drift checks not evaluated is not "Nothing flagged in any dimension"', async () => {
  const quiet: WorkloadProfile = {
    ...checkoutProfile,
    posture: { ...checkoutProfile.posture, unknownDimensions: [] },
    attention: [],
    findings: [],
    drift: {
      evaluated: ['tagMoved'],
      notEvaluated: [
        { type: 'imageChangedSinceExport', container: null, reason: 'no_export' },
        { type: 'unshippedExecutable', container: null, reason: 'no_running_containers' },
      ],
      items: [],
    },
  };
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', quiet)]);
  renderPage(api, CHECKOUT);
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  expect(attention.textContent).not.toContain('Nothing flagged in any dimension');
  expect(attention.textContent).toContain('2 drift checks were not evaluated');
  expect(attention.textContent).toContain('not a clean bill of health');
  const note = within(attention).getByRole('list', { name: 'Drift checks not evaluated' });
  expect(note.textContent).toContain('never been exported');
  expect(note.textContent).toContain('no container is running');
});

test('Overview: an older broker (evaluated, no notEvaluated) still shows the drift checks it skipped', async () => {
  const older = {
    ...checkoutProfile,
    posture: { ...checkoutProfile.posture, unknownDimensions: [] },
    attention: [],
    findings: [],
    drift: { evaluated: ['tagMoved'], items: [] },
  } as unknown as WorkloadProfile;
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', older)]);
  renderPage(api, CHECKOUT);
  const attention = await screen.findByRole('region', { name: 'Needs attention' });
  expect(attention.textContent).not.toContain('Nothing flagged in any dimension');
  expect(attention.textContent).toContain('2 drift checks were not evaluated');
  const note = within(attention).getByRole('list', { name: 'Drift checks not evaluated' });
  expect(note.textContent).toContain('imageChangedSinceExport not evaluated');
  expect(note.textContent).toContain('securityContextRegression not evaluated');
  expect(note.textContent).toContain('does not say why');
});

// The seccomp endpoint's answer for checkout, as the page's Syscalls tab
// reads it when the profile itself cannot be read.
const seccompDetail = {
  namespace: 'payments', kind: 'Deployment', name: 'checkout', hash: 'd209ca3de4379e1d', syscallCount: 104, architectures: ['SCMP_ARCH_AARCH64'], updatedAt: '2026-09-14T00:33:32Z',
  capture: { level: 'full', complete: true, pods: [{ name: 'checkout-1', level: 'full' }] },
  cr: {
    name: 'media-transform-api', defaultAction: 'SCMP_ACT_LOG', hash: '03f8d0a8c2756eda', syscallCount: 140,
    distribution: { ready: 55, total: 55, state: 'Ready', present: 55 }, statusDistribution: { ready: 60, total: 60, state: 'Ready' },
    drift: { missing: [], extra: ['mount', 'ptrace'], inSync: false },
  },
  profile: { defaultAction: 'SCMP_ACT_LOG', syscalls: [] },
};
const failingApi = () => new ProfileApi({ fetchImpl: (async () => new Response('canceling statement due to statement timeout', { status: 500 })) as unknown as typeof fetch });
const stubSeccomp = (status: number, body: unknown = seccompDetail) =>
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes('/seccomp/profiles/payments/Deployment/checkout') ? new Response(JSON.stringify(body), { status }) : new Response('', { status: 404 }),
    ),
  );

test('a failed profile read keeps the tab strip: Syscalls loads from the seccomp endpoint and opens the drawer', async () => {
  stubSeccomp(200);
  renderPage(failingApi(), CHECKOUT, { tab: 'syscalls' });
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/Could not load this workload's profile: canceling statement due to statement timeout/);
  expect(within(alert).getByRole('button', { name: 'Retry' })).not.toBeNull();
  expect(screen.getByRole('tab', { selected: true }).id).toBe('profile-tab-syscalls');
  // Observed set, capture and the CR come from GET /seccomp/profiles/{ns}/{kind}/{name}.
  expect(await screen.findByText('104')).not.toBeNull();
  expect(screen.getByText('media-transform-api')).not.toBeNull();
  expect(screen.getByText('Audit')).not.toBeNull();
  // Node readiness is the CR's own status, with the Broker's recent-report count as the qualifier.
  expect(screen.getByTestId('cr-nodes').textContent).toBe('60/60Ready· 55/55 reporting');
  expect(screen.getByTestId('drift-unobserved').textContent).toContain('2 allowed but unobserved');
  // Nothing the endpoint does not know is claimed.
  expect(screen.getByText("can't tell")).not.toBeNull();
  expect(screen.getByText(/posture and denials are unknown/)).not.toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Open seccomp profile' }));
  expect(screen.getByTestId('seccomp-drawer').textContent).toBe('payments/Deployment/checkout');
});

test('a failed profile read: the other tabs say they need the profile, and Versions still lists', async () => {
  stubSeccomp(200);
  const { onParamsChange } = renderPage(failingApi(), CHECKOUT);
  await screen.findByRole('alert');
  expect(screen.getByText('Not available without the profile')).not.toBeNull();
  expect(screen.getByText(/The Overview tab is built from the workload profile/)).not.toBeNull();
  fireEvent.click(screen.getByRole('tab', { name: 'Network' }));
  expect(onParamsChange).toHaveBeenLastCalledWith({ tab: 'network', from: undefined, to: undefined });
  cleanup();
  renderPage(failingApi(), CHECKOUT, { tab: 'podSecurity' });
  await screen.findByRole('alert');
  expect(screen.getByText(/The Pod security tab is built from the workload profile/)).not.toBeNull();
});

test('a failed profile read for a workload with no observed syscalls says so on the Syscalls tab, not an error', async () => {
  stubSeccomp(404, { error: 'no profile for workload' });
  renderPage(failingApi(), CHECKOUT, { tab: 'syscalls' });
  expect(await screen.findByText('No syscalls reported yet')).not.toBeNull();
  expect(screen.queryByRole('button', { name: 'Open seccomp profile' })).toBeNull();
});

test('a failed profile read and a failed seccomp read: the Syscalls tab shows its own error with Retry', async () => {
  stubSeccomp(500, { error: 'canceling statement due to statement timeout' });
  renderPage(failingApi(), CHECKOUT, { tab: 'syscalls' });
  const own = await screen.findByText(/Could not read the seccomp profile either: canceling statement due to statement timeout/);
  expect(own.closest('[role="alert"]')).not.toBeNull();
  expect(within(own.closest('[role="alert"]') as HTMLElement).getByRole('button', { name: 'Retry' })).not.toBeNull();
  // The profile's own error is still there, above the tabs.
  expect(screen.getAllByRole('alert')).toHaveLength(2);
});

test('the skeleton says how long it has been reading, and after a few seconds why that can be slow', () => {
  vi.useFakeTimers();
  try {
    const hang = (() => new Promise<Response>(() => {})) as unknown as typeof fetch;
    renderPage(new ProfileApi({ fetchImpl: hang }));
    expect(screen.getByLabelText('Loading')).not.toBeNull();
    expect(screen.getByTestId('profile-elapsed').textContent).toBe('Reading the profile… 0s');
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.getByTestId('profile-elapsed').textContent).toBe('Reading the profile… 3s');
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.getByTestId('profile-elapsed').textContent).toMatch(/6s.*up to 30 s/);
  } finally {
    vi.useRealTimers();
  }
});

test('Syscalls: a CR broader than the observed set is in sync with "allowed but unobserved", never "extra"', async () => {
  const p: WorkloadProfile = structuredClone(ledgerProfile);
  p.dimensions.syscalls.cr = {
    name: 'deployment-ledger', defaultAction: 'SCMP_ACT_LOG', mode: 'audit', syscallCount: 140, inSync: false, missing: [], extra: ['mount', 'ptrace'],
    distribution: { ready: 3, total: 3, state: 'Ready' },
  };
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/ledger/profile', p)]);
  renderPage(api, LEDGER, { tab: 'syscalls' });
  expect(await screen.findByText('in sync')).not.toBeNull();
  // The profile carries only the Broker's node-status count today, and the fact says so.
  const nodes = screen.getByTestId('cr-nodes');
  expect(nodes.textContent).toBe('3/3Ready');
  expect(nodes.getAttribute('title')).toMatch(/Broker's node-status count/);
  expect(nodes.getAttribute('title')).toMatch(/status\.distribution is not available/);
  expect(screen.getByTestId('drift-unobserved').textContent).toContain('2 allowed but unobserved');
  expect(screen.getByText(/Allowed but unobserved \(in the CR, never seen; not a drift\)/)).not.toBeNull();
  expect(screen.queryByText(/\bextra\b/)).toBeNull();
  cleanup();
  p.dimensions.syscalls.cr!.missing = ['clock_settime'];
  const { api: api2 } = replayApi([answer('GET /workloads/payments/Deployment/ledger/profile', p)]);
  renderPage(api2, LEDGER, { tab: 'syscalls' });
  expect(await screen.findByText('1 observed, not in the CR')).not.toBeNull();
  expect(screen.queryByText('in sync')).toBeNull();
});

test('Network: a bounded profile read that did not reach the flows says "not read", not "No flows observed"', async () => {
  const note = 'The flow read did not finish within the bounded window, so network data was not read for this profile.';
  const p: WorkloadProfile = structuredClone(checkoutProfile);
  p.dimensions.network = {
    ...p.dimensions.network,
    status: 'unknown',
    peers: [],
    truncated: false,
    reasons: [{ code: 'network_unread', message: note }],
    coverage: { level: 'none', fraction: null, observedSince: null, note },
  };
  p.posture = { ...p.posture, unknownDimensions: ['network'] };
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', p)]);
  renderPage(api, CHECKOUT, { tab: 'network' });
  expect(await screen.findByText('Network not read')).not.toBeNull();
  expect(screen.getAllByText(note).length).toBeGreaterThan(0);
  expect(screen.queryByText('No flows observed')).toBeNull();
});

test('Overview: exposure for an unread network says the flows were not read, not that there were none', async () => {
  const note = 'The flow read did not finish within the bounded window, so network data was not read for this profile.';
  const p: WorkloadProfile = structuredClone(checkoutProfile);
  p.dimensions.network = { ...p.dimensions.network, status: 'unknown', peers: [], reasons: [{ code: 'network_unread', message: note }], coverage: { level: 'none', fraction: null, observedSince: null, note } };
  p.exposure = { ingressPeers: null, ingressExternal: null, egressPeers: null, egressExternal: null };
  const { api } = replayApi([answer('GET /workloads/payments/Deployment/checkout/profile', p)]);
  renderPage(api, CHECKOUT);
  const exposure = await screen.findByRole('region', { name: 'Exposure' });
  expect(exposure.textContent).toContain(note);
  expect(exposure.textContent).toContain('Exposure is unknown.');
  expect(exposure.textContent).not.toContain('No flows observed');
});
