// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { WorkloadView } from '../WorkloadView';
import { replayApi } from '../../fixtures/replay';
import { replayVulnApi, vulnCapture } from '../../fixtures/vulns';
import type { ImageTrust, WorkloadProfile } from '../../types/profile';

afterEach(cleanup);

// Profiles from a contract v1.9 Broker (fixtures/attestation-captures): image
// trust from ./evaluator-standin, the evaluator's own imagetrust Runner over the
// real Broker with an in-memory fake Kubernetes API (answered), with the evaluator down
// (unavailable), and from a v1.8 Broker with no imageTrust at all (absent).
const WL: Record<string, { ns: string; kind: string; name: string }> = {
  checkout: { ns: 'payments', kind: 'Deployment', name: 'checkout' },
  ledger: { ns: 'payments', kind: 'Deployment', name: 'ledger' },
  reports: { ns: 'payments', kind: 'CronJob', name: 'reports' },
  grafana: { ns: 'observability', kind: 'Deployment', name: 'grafana' },
  prometheus: { ns: 'observability', kind: 'StatefulSet', name: 'prometheus' },
  'node-exporter': { ns: 'observability', kind: 'DaemonSet', name: 'node-exporter' },
  'source-controller': { ns: 'flux-system', kind: 'Deployment', name: 'source-controller' },
  'ingress-nginx-controller': { ns: 'ingress-nginx', kind: 'Deployment', name: 'ingress-nginx-controller' },
};
const answered = (wl: string) => vulnCapture<WorkloadProfile>(`signature-profile-${wl}`);
const down = (wl: string) => vulnCapture<WorkloadProfile>(`signature-profile-evaluator-down-${wl}`);

function page(wl: string, body: WorkloadProfile) {
  const { api } = replayApi([{ ...answered(wl), body }]);
  return render(<WorkloadView {...WL[wl]} tab="images" pods={[]} onBack={() => {}} onOpenInMap={() => {}} onParamsChange={() => {}} api={api} vulnApi={replayVulnApi().api} />);
}
const block = () => screen.findByRole('region', { name: 'Image trust policies' });
/** A captured profile with imageTrust replaced (test-local states no captured Broker run produced). */
const withTrust = (wl: string, t: ImageTrust | null) => {
  const b: WorkloadProfile = JSON.parse(JSON.stringify(answered(wl).body));
  b.dimensions.images.supplyChain!.imageTrust = t;
  return b;
};
// Never claimed without a finished evaluation.
const ALL_CLEAR = /nothing would be denied|allowed|all clear|no policy would deny/i;

test('the answered captures are real v1.9 Broker responses, evaluated by the evaluator\'s own imagetrust code (fake Kubernetes API)', () => {
  for (const wl of Object.keys(WL)) {
    expect(answered(wl).provenance).toMatch(/^captured from broker [0-9a-f]{7,} .*\.\/evaluator-standin \(the evaluator's own imagetrust Runner and Handler over the real Broker/);
    expect(down(wl).provenance).toMatch(/EVALUATOR_URL pointed at a closed port/);
  }
});

test.each(Object.keys(WL))('%s: the Broker\'s counts and each result, WouldDeny first, in its tone', async (wl) => {
  const t = answered(wl).body.dimensions.images.supplyChain!.imageTrust!;
  page(wl, answered(wl).body);
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe('answer');
  expect(within(b).getByTestId('trust-summary').textContent).toBe(
    `Image trust policies: ${t.wouldDeny} would deny, ${t.unknown} unknown, ${t.trusted} trusted (${t.total} result${t.total === 1 ? '' : 's'} over ${t.policies.length} polic${t.policies.length === 1 ? 'y' : 'ies'}).`,
  );
  const rows = within(b).getAllByRole('listitem');
  expect(rows.map((r) => r.getAttribute('data-trust-verdict'))).toEqual(t.results.map((r) => r.verdict));
  for (const r of rows) {
    const tone = r.querySelector('[data-trust-tone]')!.className;
    const v = r.getAttribute('data-trust-verdict');
    if (v === 'WouldDeny') expect(tone).toMatch(/severity-critical/);
    if (v === 'Unknown') expect(tone).toMatch(/border-dashed/);
    // Trusted is the policy's trust, never a good (green) tone.
    expect(tone).not.toMatch(/state-enforcing|green|success/);
  }
});

test('the ledger: one policy trusts it, another would deny it, with the reason in words', async () => {
  page('ledger', answered('ledger').body);
  const b = await block();
  const deny = within(b).getAllByRole('listitem').find((r) => r.getAttribute('data-trust-verdict') === 'WouldDeny')!;
  expect(deny.textContent).toMatch(/cluster\/example-org-releases/);
  expect(deny.textContent).toMatch(/signed, but not by a signer the policy trusts/);
});

test.each(Object.keys(WL))('%s, evaluator down: unknown with the Broker\'s reason, no results, never an all-clear', async (wl) => {
  const t = down(wl).body.dimensions.images.supplyChain!.imageTrust!;
  expect(t.available).toBe(false);
  page(wl, down(wl).body);
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe('unavailable');
  expect(within(b).getByTestId('trust-summary').textContent).toBe(`Image trust policies: unknown, ${t.reason}.`);
  expect(within(b).queryByRole('list', { name: 'Image trust results' })).toBeNull();
  expect(b.textContent).not.toMatch(ALL_CLEAR);
  expect(b.textContent).not.toMatch(/0 would deny/);
});

test('a v1.8 Broker (no imageTrust at all, captured): not reported, unknown', async () => {
  const v18 = vulnCapture<WorkloadProfile>('profile-checkout');
  expect('imageTrust' in v18.body.dimensions.images.supplyChain!).toBe(false);
  const { api } = replayApi([v18]);
  render(<WorkloadView {...WL.checkout} tab="images" pods={[]} onBack={() => {}} onOpenInMap={() => {}} onParamsChange={() => {}} api={api} vulnApi={replayVulnApi().api} />);
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe('absent');
  expect(within(b).getByTestId('trust-summary').textContent).toBe('Image trust policies: not reported by this Broker (unknown).');
  expect(b.textContent).not.toMatch(ALL_CLEAR);
});

// Test-local: states the contract defines that no captured Broker run produced here.
test.each([
  ['not read (null)', null, 'not_read', 'Image trust policies: not read for this workload (unknown).'],
  ['no finished pass (evaluatedAt null)', { available: true, evaluatedAt: null, total: 0, wouldDeny: 0, unknown: 0, trusted: 0, policies: [], results: [], truncated: false }, 'pending', 'Image trust policies: the evaluator has not finished a pass yet (unknown).'],
  ['unavailable with a blank reason', { available: false, reason: '  ', evaluatedAt: null, total: 0, wouldDeny: 0, unknown: 0, trusted: 0, policies: [], results: [], truncated: false }, 'unavailable', 'Image trust policies: unknown, no reason given.'],
] as const)('%s is unknown, never an all-clear', async (_, t, state, text) => {
  page('checkout', withTrust('checkout', t as ImageTrust | null));
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe(state);
  expect(within(b).getByTestId('trust-summary').textContent).toBe(text);
  expect(b.textContent).not.toMatch(ALL_CLEAR);
});

test('test-local: an answer with no policy selecting the workload says none was evaluated, not allowed', async () => {
  page('checkout', withTrust('checkout', { available: true, evaluatedAt: '2026-09-27T00:00:00Z', total: 0, wouldDeny: 0, unknown: 0, trusted: 0, policies: [], results: [], truncated: false }));
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe('none_apply');
  expect(within(b).getByTestId('trust-summary').textContent).toMatch(/none was evaluated \(not the same as allowed\)/);
});

test('the posture chip tooltip carries the image trust line from the profile', async () => {
  page('prometheus', answered('prometheus').body);
  const strip = await screen.findByRole('list', { name: 'Posture by dimension' });
  const chip = within(strip.querySelector('[data-dimension="supplyChain"]') as HTMLElement).getByRole('button');
  expect(chip.getAttribute('title')).toMatch(/\nImage trust policies: 1 would deny, 0 unknown, 0 trusted \(1 result over 1 policy\)\.$/);
});

// Test-local: count shapes no captured Broker run produced, built on the captured ledger answer.
const ledgerTrust = () => JSON.parse(JSON.stringify(answered('ledger').body.dimensions.images.supplyChain!.imageTrust!)) as ImageTrust;

test('a total the counts do not account for: the gap is unknown, never silently dropped (page and chip)', async () => {
  const t = { ...ledgerTrust(), total: 7 }; // counts: 1 would deny + 0 unknown + 1 trusted
  page('ledger', withTrust('ledger', t));
  const b = await block();
  expect(within(b).getByTestId('trust-summary').textContent).toBe('Image trust policies: 1 would deny, 5 unknown (5 not accounted for), 1 trusted (7 results over 2 policies).');
  const strip = await screen.findByRole('list', { name: 'Posture by dimension' });
  const chip = within(strip.querySelector('[data-dimension="supplyChain"]') as HTMLElement).getByRole('button');
  expect(chip.getAttribute('title')).toMatch(/5 unknown \(5 not accounted for\)/);
});

test('counts that add up to more than the total are unknown as a whole, not an answer', async () => {
  page('ledger', withTrust('ledger', { ...ledgerTrust(), total: 1 }));
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe('unavailable');
  expect(within(b).getByTestId('trust-summary').textContent).toBe("Image trust policies: unknown, the Broker's counts do not add up (2 counted, total 1).");
  expect(b.textContent).not.toMatch(ALL_CLEAR);
});

test('truncated: the counts come from the Broker summary, not from the results listed', async () => {
  // The Broker lists at most 20; here only the Trusted row is listed while the summary counts both.
  const t = ledgerTrust();
  const listed = { ...t, truncated: true, results: t.results.filter((r) => r.verdict === 'Trusted') };
  page('ledger', withTrust('ledger', listed));
  const b = await block();
  expect(within(b).getByTestId('trust-summary').textContent).toBe('Image trust policies: 1 would deny, 0 unknown, 1 trusted (2 results over 2 policies).');
  expect(within(b).getAllByRole('listitem').map((r) => r.getAttribute('data-trust-verdict'))).toEqual(['Trusted']);
  expect(within(b).getByText('More results than listed; the counts above cover all of them.')).toBeTruthy();
});

test.each([
  ['total missing', { total: undefined }],
  ['every count missing', { total: undefined, wouldDeny: undefined, unknown: undefined, trusted: undefined }],
  ['a negative count', { wouldDeny: -1 }],
  ['a string count', { trusted: 'x' }],
  ['a non-integer total', { total: 2.5 }],
  ['a NaN count', { unknown: Number.NaN }],
] as const)('counts that are not whole non-negative numbers (%s) are unknown as a whole, never rendered', async (_, patch) => {
  page('ledger', withTrust('ledger', { ...ledgerTrust(), ...(patch as unknown as Partial<ImageTrust>) }));
  const b = await block();
  expect(b.getAttribute('data-trust-state')).toBe('unavailable');
  expect(within(b).getByTestId('trust-summary').textContent).toBe("Image trust policies: unknown, the Broker's counts are not valid.");
  expect(b.textContent).not.toMatch(/undefined|NaN|-1 would|x trusted|0\.5/);
  expect(within(b).queryByRole('list', { name: 'Image trust results' })).toBeNull();
});
