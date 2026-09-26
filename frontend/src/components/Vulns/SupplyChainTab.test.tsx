// @vitest-environment jsdom
import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ImagesView } from '../ImagesView';
import { AdmissionPolicyModal } from './AdmissionPolicyModal';
import { replayVulnApi, vulnCapture } from '../../fixtures/vulns';
import { VulnApi } from '../../services/vulnApi';
import type { RunningSignaturePage } from '../../types/attestations';

afterEach(cleanup);

const noop = () => {};
const supplyTab = (api = replayVulnApi().api, over: Partial<Parameters<typeof ImagesView>[0]> = {}) =>
  render(<ImagesView namespace="payments" allNamespaces tab="supply" onParamsChange={noop} onOpenWorkload={noop} onShowOnMap={noop} onAskAI={noop} api={api} {...over} />);
/** The row whose image reference starts with `repo` (plain string match, no regex). */
const rowOf = async (repo: string) => (await screen.findAllByTestId('signature-row')).find((r) => r.querySelector('.font-mono')!.textContent!.startsWith(`${repo}:`))!;

describe('Images → Supply chain (captured from a real Broker)', () => {
  test('one row per running digest, each with its verdict; the unchecked digest is "Not checked", not unsigned', async () => {
    supplyTab();
    const rows = await screen.findAllByTestId('signature-row');
    expect(rows).toHaveLength(8);
    const state = Object.fromEntries(rows.map((r) => [r.querySelector('.font-mono')!.textContent!.split(':')[0], r.getAttribute('data-state')]));
    expect(state).toMatchObject({
      'ghcr.io/example/checkout': 'verified',
      'ghcr.io/example/reports': 'unsigned',
      'docker.io/grafana/grafana': 'key_signed',
      'quay.io/prometheus/prometheus': 'invalid',
      'registry.k8s.io/ingress-nginx/controller': 'unchecked',
    });
    const ingress = await rowOf('registry.k8s.io/ingress-nginx/controller');
    expect(within(ingress).getByText('Not checked')).toBeTruthy();
    expect(within(ingress).queryByText('Unsigned')).toBeNull();
  });

  test('a verified row names its signer in full and never says trusted', async () => {
    supplyTab();
    const checkout = await rowOf('ghcr.io/example/checkout');
    expect(within(checkout).getByText('Signature verified')).toBeTruthy();
    expect(within(checkout).getByText(/^https:\/\/github\.com\/example-org\/checkout\/\.github\/workflows\/release\.yaml@refs\/tags\/v4\.2\.0 via https:\/\/token\.actions\.githubusercontent\.com$/)).toBeTruthy();
    expect(within(checkout).getByText(/SLSA provenance/)).toBeTruthy();
    const ledger = await rowOf('ghcr.io/example/ledger');
    expect(within(ledger).getByText(/^key payments-release \(sha256:d4d97426189e…\)$/)).toBeTruthy();
    // "trusted" appears only as "not ... trusted" in the reminder.
    for (const el of screen.getAllByText(/trusted/i)) expect(el.textContent).toMatch(/not (that the signer is )?trusted|trust root/i);
    expect(screen.getByText(/Verified means the signature is valid, not that the signer is trusted/)).toBeTruthy();
  });

  test('unknown shows its reason in words, including a code this Broker does not know', async () => {
    supplyTab();
    const sc = await rowOf('ghcr.io/fluxcd/source-controller');
    expect(within(sc).getByText('Unknown')).toBeTruthy();
    expect(within(sc).getByText(/a reason this Broker does not know/)).toBeTruthy();
    const ne = await rowOf('quay.io/prometheus/node-exporter');
    expect(within(ne).getByText(/rate-limited/)).toBeTruthy();
  });

  test('the tiles count unknown and not checked apart from good; the filter narrows the rows', async () => {
    supplyTab();
    await screen.findAllByTestId('signature-row');
    const tiles = screen.getByRole('group', { name: 'Signature posture' });
    const value = (label: string) => within(tiles).getByText(label).closest('div,button')!.parentElement!.textContent!;
    expect(value('Invalid or unsigned')).toContain('2');
    expect(value('Unknown or not checked')).toContain('4'); // node-exporter, source-controller, ingress (unchecked), grafana (key not held)
    expect(value('Verified signature')).toContain('2');
    fireEvent.change(screen.getByLabelText('Signature'), { target: { value: 'unchecked' } });
    const rows = screen.getAllByTestId('signature-row');
    expect(rows.map((r) => r.getAttribute('data-state'))).toEqual(['unchecked']);
  });

  test('checked ages read the naive UTC timestamp as UTC, whatever the browser zone', async () => {
    const tz = process.env.TZ;
    process.env.TZ = 'Australia/Sydney';
    try {
      const feed = vulnCapture<RunningSignaturePage>('attestations-running-namespace-payments');
      const threeHoursAgo = new Date(Date.now() - 3 * 3600_000).toISOString().slice(0, 19); // naive, like the Broker's
      const items = feed.body.items.map((i) => ({ ...i, checkedAt: i.checkedAt ? threeHoursAgo : null }));
      supplyTab(replayVulnApi([{ ...feed, request: 'GET /attestations/running', body: { ...feed.body, items } }]).api);
      const rows = await screen.findAllByTestId('signature-row');
      for (const r of rows) expect(within(r).getByText(/^checked /).textContent).toBe('checked 3h ago');
    } finally {
      process.env.TZ = tz;
    }
  });

  test('a state without a reason code still says what it means', async () => {
    supplyTab();
    const grafana = await rowOf('docker.io/grafana/grafana');
    expect(within(grafana).getByText(/^Signed with a public key kguardian was not given/)).toBeTruthy();
    const reports = await rowOf('ghcr.io/example/reports');
    expect(within(reports).getByText('No signature, and every lookup answered.')).toBeTruthy();
  });

  test('a "verified" row with no signer is unknown in the row and the tiles, never counted as verified', async () => {
    const feed = vulnCapture<RunningSignaturePage>('attestations-running');
    const items = feed.body.items.map((i) => (i.workloadName === 'checkout' ? { ...i, signers: [] } : i));
    supplyTab(replayVulnApi([{ ...feed, body: { ...feed.body, items } }]).api);
    const checkout = await rowOf('ghcr.io/example/checkout');
    expect(checkout.getAttribute('data-state')).toBe('unknown');
    expect(within(checkout).getByText(/Reported verified, but no verified signer identity came with it: unknown, not signed\./)).toBeTruthy();
    const tiles = screen.getByRole('group', { name: 'Signature posture' });
    const value = (label: string) => within(tiles).getByText(label).closest('div,button')!.parentElement!.textContent!;
    expect(value('Verified signature')).toContain('1');
    expect(value('Unknown or not checked')).toContain('5');
  });

  test('ImageTrustPolicy results are not shown, and the page says where to read them', async () => {
    supplyTab();
    await screen.findAllByTestId('signature-row');
    expect(screen.getByText(/the Broker does not serve them, so they are not shown here/)).toBeTruthy();
  });

  test('no result for any image: says discovery is off or has not run, not "unsigned"', async () => {
    const unchecked = vulnCapture<RunningSignaturePage>('attestations-running-namespace-ingress-nginx');
    supplyTab(replayVulnApi([{ ...unchecked, request: 'GET /attestations/running' }]).api);
    await screen.findAllByTestId('signature-row');
    expect(screen.getByRole('status').textContent).toMatch(/signature discovery is off .* Not checked is not unsigned/);
  });

  test('a Broker without the signature routes: says so, never an empty clean list', async () => {
    const old = new VulnApi({ fetchImpl: (async () => new Response('', { status: 404 })) as typeof fetch });
    supplyTab(old);
    expect(await screen.findByText('Signature results not available')).toBeTruthy();
    expect(screen.queryAllByTestId('signature-row')).toHaveLength(0);
  });

  test('a 401 from the Broker is a token message', async () => {
    supplyTab(new VulnApi({ fetchImpl: (async () => new Response('', { status: 401 })) as typeof fetch }));
    expect(await screen.findByText('Broker token required')).toBeTruthy();
  });
});

describe('Export admission policy', () => {
  test('cluster: audit by default, kguardian format, with the review-every-identity header shown above the YAML', async () => {
    const { api, calls } = replayVulnApi();
    supplyTab(api);
    await screen.findAllByTestId('signature-row');
    fireEvent.click(screen.getByRole('button', { name: 'Export admission policy' }));
    const header = await screen.findByRole('region', { name: 'Policy header: review before applying' });
    expect(within(header).getByText(/^REVIEW EVERY IDENTITY BEFORE APPLYING/)).toBeTruthy();
    expect(within(header).getAllByText(/^identity: /)).toHaveLength(2);
    expect(within(header).getByText(/^not covered: ghcr\.io\/example\/reports/)).toBeTruthy();
    expect(screen.getByLabelText('Policy YAML').textContent).toMatch(/^apiVersion: kguardian\.dev\/v1alpha1\nkind: ClusterImageTrustPolicy/);
    expect(calls).toContain('GET /attestations/policy?format=kguardian&mode=audit');
    expect(screen.getByText(/audit mode/)).toBeTruthy();
  });

  test('switching engine reads that format, still audit', async () => {
    const { api, calls } = replayVulnApi();
    render(<AdmissionPolicyModal api={api} scope={{ kind: 'cluster' }} onClose={noop} />);
    await screen.findByLabelText('Policy YAML');
    fireEvent.click(screen.getByLabelText(/Kyverno ImageValidatingPolicy/));
    await waitFor(() => expect(screen.getByLabelText('Policy YAML').textContent).toMatch(/kind: ImageValidatingPolicy/));
    expect(screen.getByLabelText('Policy YAML').textContent).toMatch(/- Audit/);
    expect(calls).toContain('GET /attestations/policy?format=kyverno&mode=audit');
    expect(calls.every((c) => !c.includes('enforce'))).toBe(true);
  });

  test("workload: the export bundle's admission artifact, header visible", async () => {
    const { api, calls } = replayVulnApi();
    render(<AdmissionPolicyModal api={api} scope={{ kind: 'workload', namespace: 'payments', workloadKind: 'Deployment', name: 'checkout' }} onClose={noop} />);
    const header = await screen.findByRole('region', { name: 'Policy header: review before applying' });
    expect(within(header).getByText('kguardian image admission policy for payments/Deployment/checkout')).toBeTruthy();
    expect(within(header).getByText(/^REVIEW EVERY IDENTITY/)).toBeTruthy();
    expect(screen.getByLabelText('Policy YAML').textContent).toMatch(/kind: ImageTrustPolicy\n/);
    expect(calls).toEqual(['GET /workloads/payments/Deployment/checkout/export?artifacts=admission&mode=audit&format=zip-manifest']);
  });

  test("workload with nothing verified: the Broker's reason, and no YAML to download", async () => {
    const { api } = replayVulnApi();
    render(<AdmissionPolicyModal api={api} scope={{ kind: 'workload', namespace: 'payments', workloadKind: 'CronJob', name: 'reports' }} onClose={noop} />);
    expect(await screen.findByText(/No policy was generated: no image of this workload has every running digest signed by a verified signer \(ghcr\.io\/example\/reports: a running digest is unsigned\)/)).toBeTruthy();
    expect(screen.queryByLabelText('Policy YAML')).toBeNull();
    expect((screen.getByRole('button', { name: 'Download YAML' }) as HTMLButtonElement).disabled).toBe(true);
  });

  test('copy puts the whole document on the clipboard, header included', async () => {
    const { api } = replayVulnApi();
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(<AdmissionPolicyModal api={api} scope={{ kind: 'cluster' }} onClose={noop} />);
    await screen.findByLabelText('Policy YAML');
    fireEvent.click(screen.getByRole('button', { name: 'Copy YAML' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const copied = (writeText.mock.calls[0] as unknown as [string])[0];
    expect(copied).toBe(vulnCapture<string>('policy-kguardian-audit').body);
    expect(copied).toMatch(/^# kguardian image admission policy/);
    expect(copied).toContain('# REVIEW EVERY IDENTITY BEFORE APPLYING');
  });

  test('download saves the whole document, header included', async () => {
    const { api } = replayVulnApi();
    const created: Blob[] = [];
    const url = vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
      created.push(b as Blob);
      return 'blob:x';
    });
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    render(<AdmissionPolicyModal api={api} scope={{ kind: 'cluster' }} onClose={noop} />);
    await screen.findByLabelText('Policy YAML');
    fireEvent.click(screen.getByRole('button', { name: 'Download YAML' }));
    expect(await created[0].text()).toBe(vulnCapture<string>('policy-kguardian-audit').body);
    url.mockRestore();
    revoke.mockRestore();
  });
});
