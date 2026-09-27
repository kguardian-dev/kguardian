// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { WorkloadView } from '../WorkloadView';
import { replayApi } from '../../fixtures/replay';
import { vulnCapture } from '../../fixtures/vulns';
import { VulnApi } from '../../services/vulnApi';
import type { WorkloadProfile } from '../../types/profile';

afterEach(cleanup);

// Profiles from a contract v1.8 Broker (images.supplyChain), captured by
// ../../fixtures/attestation-captures/capture.py, discovery on and off.
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
const capture = (wl: string, notConfigured = false) => vulnCapture<WorkloadProfile>(`signature-profile${notConfigured ? '-not-configured' : ''}-${wl}`);
// The running feed fails: a chip that still shows the verdict read the profile.
const noFeed = new VulnApi({ fetchImpl: (async () => new Response('boom', { status: 500 })) as typeof fetch });

function page(wl: string, notConfigured = false) {
  const c = capture(wl, notConfigured);
  const { api } = replayApi([c]);
  return render(<WorkloadView {...WL[wl]} pods={[]} onBack={() => {}} onOpenInMap={() => {}} onParamsChange={() => {}} api={api} vulnApi={noFeed} />);
}
async function strip() {
  const list = await screen.findByRole('list', { name: 'Posture by dimension' });
  const chip = within(list.querySelector('[data-dimension="supplyChain"]') as HTMLElement).getByRole('button');
  const images = list.querySelector('[data-dimension="images"] [data-status]')!.getAttribute('data-status');
  return { chip, images };
}
const EXPECT: Record<string, string> = {
  verified: 'Signature verified',
  key_signed: 'Signed, key not held',
  unsigned: 'Unsigned',
  invalid: 'Invalid signature',
  unknown: 'Unknown',
};

test('captures are from a v1.8 Broker', () => {
  for (const wl of Object.keys(WL)) {
    expect(capture(wl).provenance).toMatch(/^captured from broker [0-9a-f]{7,}/);
    expect(capture(wl).body.dimensions.images.supplyChain).not.toBeNull();
  }
});

test.each(Object.keys(WL))('%s: the chip shows the profile verdict and agrees with the images rollup', async (wl) => {
  page(wl);
  const sc = capture(wl).body.dimensions.images.supplyChain!;
  const { chip, images } = await strip();
  expect(chip.getAttribute('data-source')).toBe('profile');
  await waitFor(() => expect(chip.querySelector('[data-signature]')).not.toBeNull());
  const shown = chip.querySelector('[data-signature]')!;
  const expected = sc.verdict === 'unknown' && sc.reason === 'not_checked' ? 'Not checked' : EXPECT[sc.verdict];
  expect(shown.textContent).toBe(expected);
  // The rule the rollup follows (contract 2.2): invalid makes images risk.
  expect(sc.counts.invalid > 0).toBe(images === 'risk');
  expect(shown.getAttribute('data-signature') === 'invalid').toBe(images === 'risk');
  const title = chip.getAttribute('title')!;
  if (sc.verdict === 'invalid') expect(title).toMatch(/Affects the posture: an invalid signature makes Images risk\./);
  else if (sc.verdict === 'verified') expect(title).toMatch(/signatures alone never make it OK\./);
  else expect(title).toMatch(/keeps Images from OK once vulnerability data exists, but is not a risk on its own\./);
  expect(title).not.toMatch(/not part of the rollup/);
});

test('verified names its signer, from the profile, with no running-feed read', async () => {
  page('checkout');
  const { chip } = await strip();
  expect(within(chip).getByText('example-org/checkout release.yaml')).toBeTruthy();
  expect(chip.getAttribute('aria-label')).toMatch(/signed by https:\/\/github\.com\/example-org\/checkout\/\.github\/workflows\/release\.yaml@refs\/tags\/v4\.2\.0 via https:\/\/token\.actions\.githubusercontent\.com$/);
});

test.each(Object.keys(WL))('%s with discovery off: "Not configured", its own state, not unknown or not checked', async (wl) => {
  page(wl, true);
  expect(capture(wl, true).body.dimensions.images.supplyChain!.status).toBe('not_configured');
  const { chip } = await strip();
  expect(chip.querySelector('[data-signature]')!.getAttribute('data-signature')).toBe('not_configured');
  expect(chip.textContent).toBe('Supply chainNot configured');
  expect(chip.getAttribute('title')).toMatch(/Signatures do not affect the posture\.$/);
  expect(chip.getAttribute('aria-label')).toBe('Supply chain: not configured');
});

test('the Not configured badge is neutral and dashed, never a good (green) tone', async () => {
  page('checkout', true);
  const { chip } = await strip();
  const badge = chip.querySelector('[data-signature="not_configured"]')!;
  expect(badge.className).toMatch(/border-dashed/);
  expect(badge.className).toMatch(/text-tertiary/);
  expect(badge.className).not.toMatch(/state-enforcing|severity-|success|green/);
});
