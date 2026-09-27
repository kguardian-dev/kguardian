// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { WorkloadView } from '../WorkloadView';
import { replayApi } from '../../fixtures/replay';
import { replayVulnApi, vulnCapture } from '../../fixtures/vulns';
import type { WorkloadProfile } from '../../types/profile';

afterEach(cleanup);

// Profiles captured from a Broker whose seed includes the controller's runtime
// posts (../../fixtures/vuln-captures/capture.py): capability evidence and
// runtime drift are the Broker's own.
const profile = (wl: string) => vulnCapture<WorkloadProfile>(`profile-${wl}`);
const WL: Record<string, { ns: string; kind: string; name: string }> = {
  checkout: { ns: 'payments', kind: 'Deployment', name: 'checkout' },
  ledger: { ns: 'payments', kind: 'Deployment', name: 'ledger' },
  grafana: { ns: 'observability', kind: 'Deployment', name: 'grafana' },
  prometheus: { ns: 'observability', kind: 'StatefulSet', name: 'prometheus' },
};
function page(wl: string, tab: string, body?: WorkloadProfile) {
  const c = profile(wl);
  const { api } = replayApi([body ? { ...c, body } : c]);
  return render(<WorkloadView {...WL[wl]} tab={tab} pods={[]} onBack={() => {}} onOpenInMap={() => {}} onParamsChange={() => {}} api={api} vulnApi={replayVulnApi().api} />);
}
const container = async (name: string) => (await screen.findAllByTestId('cap-container')).find((c) => within(c).queryByText(name, { selector: '.font-mono' }))!;

test('the profiles are real Broker captures', () => {
  for (const wl of Object.keys(WL)) expect(profile(wl).provenance).toMatch(/^captured from broker [0-9a-f]{7,}/);
});

test('capabilities, sufficient evidence: used, probed and denied, and the recommendation with its allowPrivilegeEscalation requirement', async () => {
  page('checkout', 'podSecurity');
  const app = await container('app');
  expect(app.getAttribute('data-evidence')).toBe('sufficient');
  expect(within(app).getByText('Evidence: 7 d watched')).toBeTruthy();
  const names = (label: string) => [...within(app).getByRole('list', { name: label }).querySelectorAll('li')].map((li) => li.firstChild!.textContent);
  expect(names('Used')).toEqual(['CHOWN', 'NET_BIND_SERVICE']);
  expect(names('Probed')).toEqual(['SYS_ADMIN']);
  expect(names('Denied')).toEqual(['NET_RAW']);
  const rec = within(app).getByTestId('cap-recommendation');
  expect(rec.querySelector('pre')!.textContent).toBe('capabilities:\n  drop: ["ALL"]\n  add: ["CHOWN", "NET_BIND_SERVICE"]\nallowPrivilegeEscalation: false');
  expect(within(rec).getByTestId('cap-requires-ape').textContent).toMatch(/Requires allowPrivilegeEscalation: false/);
  const omitted = within(rec).getByRole('list', { name: 'Left out (probed only)' });
  expect(omitted.textContent).toMatch(/^SYS_ADMIN left out: probed only \(memory reserve \/ seccomp without no_new_privs\); allowPrivilegeEscalation=false removes the need\.$/);
});

test('capabilities, insufficient evidence: the reason in words and no recommendation', async () => {
  page('ledger', 'podSecurity');
  const c = await container('ledger');
  expect(c.getAttribute('data-evidence')).toBe('insufficient');
  expect(within(c).getByText(/^Why: the runtime inventory runs in exec mode/)).toBeTruthy();
  expect(within(c).queryByTestId('cap-recommendation')).toBeNull();
  expect(within(c).getByTestId('cap-no-recommendation').textContent).toMatch(/not evidence that nothing else is needed/);
});

test('capabilities seen, but not since the container started: listed, still no recommendation', async () => {
  page('grafana', 'podSecurity');
  const c = await container('grafana');
  expect(within(c).getByText(/^Why: the container was already running when the probe attached/)).toBeTruthy();
  expect(within(c).getByRole('list', { name: 'Used' }).textContent).toMatch(/^SETUID/);
  expect(within(c).queryByTestId('cap-recommendation')).toBeNull();
});

test('a Broker without the capabilities block says so', async () => {
  const older: WorkloadProfile = { ...profile('checkout').body };
  delete older.capabilities;
  page('checkout', 'podSecurity', older);
  expect(await screen.findByText(/does not report observed capability use/)).toBeTruthy();
});

test('drift: an unshipped executable with its file, origin and the checks that did not run', async () => {
  page('grafana', 'overview');
  const item = await screen.findByTestId('drift-item');
  expect(item.getAttribute('data-type')).toBe('unshippedExecutable');
  expect(within(item).getByText('high')).toBeTruthy();
  expect(within(item).getByText('Ran a file the image did not ship')).toBeTruthy();
  expect(within(item).getByText('/var/lib/grafana/plugins/example-panel/gpx_example-panel_linux_amd64')).toBeTruthy();
  expect(within(item).getByText(/executed from writable layer \(written after start\)/)).toBeTruthy();
  expect(screen.getByTestId('drift-gaps-pointer').textContent).toBe('2 checks not evaluated (Image changed since export, securityContext regression): why is listed under Needs attention.');
  const gaps = screen.getByRole('list', { name: 'Drift checks not evaluated' });
  expect(gaps.textContent).toMatch(/imageChangedSinceExport not evaluated: the workload has never been exported/);
});

test('drift: no item is "no drift found by the checks that ran", and the capture gap is not evaluated, not clean', async () => {
  page('prometheus', 'overview');
  expect((await screen.findByTestId('drift-none')).textContent).toBe('No drift found by the checks that ran (Tag moved). Some checks did not run: not evaluated is not "no drift".');
  const gaps = screen.getByRole('list', { name: 'Drift checks not evaluated' });
  expect(gaps.textContent).toMatch(/unshippedExecutable not evaluated for container prometheus: the capture has a gap in the window \(or began inside it\)/);
});

// Variants of the captured checkout profile, one field changed each.
function withContainer(patch: (c: NonNullable<WorkloadProfile['capabilities']>['containers'][number]) => void): WorkloadProfile {
  const body: WorkloadProfile = JSON.parse(JSON.stringify(profile('checkout').body));
  patch(body.capabilities!.containers[0]);
  return body;
}

test('a recommendation the Broker sent with insufficient evidence is not shown; the patch keeps the restricted default', async () => {
  page('checkout', 'podSecurity', withContainer((c) => {
    c.evidence = 'insufficient';
    c.reason = 'coverage_unavailable';
  }));
  const app = await container('app');
  expect(within(app).queryByTestId('cap-recommendation')).toBeNull();
  expect(within(app).getByTestId('cap-no-recommendation').textContent).toMatch(/keeps the restricted default \(drop: \["ALL"\]\)/);
  expect(within(app).getByText(/^Why: runtime coverage cannot be read \(the coverage function is missing from the database\)\.$/)).toBeTruthy();
});

test('an older Broker without `requires`: omitting a probed capability still shows the allowPrivilegeEscalation requirement', async () => {
  page('checkout', 'podSecurity', withContainer((c) => {
    delete c.recommendation!.requires;
  }));
  const rec = within(await container('app')).getByTestId('cap-recommendation');
  expect(within(rec).getByTestId('cap-requires-ape')).toBeTruthy();
  expect(rec.querySelector('pre')!.textContent).toMatch(/allowPrivilegeEscalation: false$/);
});

test('drift: a truncated item without filesTotal never shows a negative count', async () => {
  const body: WorkloadProfile = JSON.parse(JSON.stringify(profile('grafana').body));
  const d = body.drift!.items[0].detail!;
  d.truncated = true;
  delete d.filesTotal;
  page('grafana', 'overview', body);
  const item = await screen.findByTestId('drift-item');
  expect(within(item).getByText('More files ran than are listed.')).toBeTruthy();
  expect(item.textContent).not.toMatch(/-\d+ more/);
});
