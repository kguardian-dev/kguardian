// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { WorkloadView } from '../WorkloadView';
import { replayApi } from '../../fixtures/replay';
import { replayVulnApi, vulnCapture } from '../../fixtures/vulns';
import type { RunningSignaturePage } from '../../types/attestations';
import { VulnApi } from '../../services/vulnApi';

afterEach(cleanup);

// Profiles come from the workload-profile captures, signature results from
// ../../fixtures/attestation-captures: both real Broker responses for the
// same namespaces and workload names.
function page(w: { ns: string; kind: string; name: string }, vulnApi: VulnApi = replayVulnApi().api, tab?: string) {
  const { api } = replayApi();
  return render(<WorkloadView {...w} tab={tab} pods={[]} onBack={() => {}} onOpenInMap={() => {}} onParamsChange={() => {}} api={api} vulnApi={vulnApi} />);
}
const chip = async () => {
  const strip = await screen.findByRole('list', { name: 'Posture by dimension' });
  const li = strip.querySelector('[data-dimension="supplyChain"]') as HTMLElement;
  await waitFor(() => expect(li.textContent).not.toMatch(/…/));
  return li;
};

test('posture chip, older Broker (profile supplyChain null while digests run): from the running feed, labelled informational', async () => {
  page({ ns: 'payments', kind: 'Deployment', name: 'checkout' });
  const c = await chip();
  expect(within(c).getByText('Signature verified')).toBeTruthy();
  expect(within(c).getByText('example-org/checkout release.yaml')).toBeTruthy();
  const btn = within(c).getByRole('button');
  expect(btn.getAttribute('title')).toMatch(/valid, not vetted/);
  expect(btn.getAttribute('title')).toMatch(/Informational: this Broker's posture does not use signatures\./);
  expect(btn.getAttribute('data-source')).toBe('feed');
  expect(c.querySelector('[data-signature="verified"]')!.className).not.toMatch(/state-enforcing/);
});

test('posture chip: unknown with its reason; a key signature shows the key', async () => {
  page({ ns: 'observability', kind: 'DaemonSet', name: 'node-exporter' });
  const c = await chip();
  expect(within(c).getByText('Unknown')).toBeTruthy();
  cleanup();
  page({ ns: 'payments', kind: 'Deployment', name: 'ledger' });
  const l = await chip();
  expect(within(l).getByText('key payments-release')).toBeTruthy();
});

test('posture chip: a workload with no running image in the feed is "No data", never signed', async () => {
  page({ ns: 'payments', kind: 'Deployment', name: 'refunds' });
  const c = await chip();
  expect(within(c).getByText('No data')).toBeTruthy();
  expect(c.querySelector('[data-signature]')).toBeNull();
});

test('posture chip: the signature read failed is "read failed", unknown', async () => {
  const failing = new VulnApi({ fetchImpl: (async () => new Response('boom', { status: 500 })) as typeof fetch });
  page({ ns: 'payments', kind: 'Deployment', name: 'checkout' }, failing);
  const c = await chip();
  expect(within(c).getByText('read failed')).toBeTruthy();
});

test('Image & packages: each running digest with its signer, and the workload admission export', async () => {
  const vulnApi = replayVulnApi();
  page({ ns: 'payments', kind: 'Deployment', name: 'checkout' }, vulnApi.api, 'images');
  const row = await screen.findByTestId('signature-row');
  expect(row.getAttribute('data-state')).toBe('verified');
  expect(within(row).getByText(/^https:\/\/github\.com\/example-org\/checkout\/.* via https:\/\/token\.actions\.githubusercontent\.com$/)).toBeTruthy();
  expect(screen.getByText(/Verified means the signature is valid, not that the signer is trusted/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Export admission policy' }));
  const header = await screen.findByRole('region', { name: 'Policy header: review before applying' });
  expect(within(header).getByText(/^REVIEW EVERY IDENTITY BEFORE APPLYING/)).toBeTruthy();
  expect(vulnApi.calls).toContain('GET /workloads/payments/Deployment/checkout/export?artifacts=admission&mode=audit&format=zip-manifest');
});

test('posture chip: "verified" with no signer is unknown, never "Signature verified" or "0 signers"', async () => {
  const feed = vulnCapture<RunningSignaturePage>('attestations-running-namespace-payments');
  const items = feed.body.items.map((i) => (i.workloadName === 'checkout' ? { ...i, signers: [] } : i));
  page({ ns: 'payments', kind: 'Deployment', name: 'checkout' }, replayVulnApi([{ ...feed, body: { ...feed.body, items } }]).api);
  const c = await chip();
  expect(within(c).getByText('Unknown')).toBeTruthy();
  expect(c.textContent).not.toMatch(/Signature verified|0 signers/);
});

test('posture chip: its accessible name carries the signer', async () => {
  page({ ns: 'payments', kind: 'Deployment', name: 'checkout' });
  const c = await chip();
  expect(within(c).getByRole('button').getAttribute('aria-label')).toBe(
    'Supply chain: Signature verified, signed by https://github.com/example-org/checkout/.github/workflows/release.yaml@refs/tags/v4.2.0 via https://token.actions.githubusercontent.com',
  );
});
