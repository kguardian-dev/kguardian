// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { ImagesView } from './ImagesView';
import { replayVulnApi, cvePage, imageDetail } from '../fixtures/vulns';
import { answer, replayApi } from '../fixtures/replay';
import { listNamespacePayments } from '../fixtures/profile';
import { VulnApi } from '../services/vulnApi';

afterEach(cleanup);

const noop = () => {};
const view = (over: Partial<Parameters<typeof ImagesView>[0]> = {}) => (
  <ImagesView
    namespace="payments"
    allNamespaces
    onParamsChange={noop}
    onOpenWorkload={noop}
    onShowOnMap={noop}
    onAskAI={noop}
    api={replayVulnApi().api}
    {...over}
  />
);
const failing = (status: number) => new VulnApi({ fetchImpl: (async () => new Response('', { status })) as typeof fetch });

describe('ImagesView: Vulnerabilities tab', () => {
  test("tiers are the Broker's: one row per CVE, the KEV row P0, with its chips", async () => {
    render(view({ api: replayVulnApi([], { tiers: true }).api }));
    const rows = await screen.findAllByTestId('cve-row');
    expect(rows).toHaveLength(cvePage.items.length);
    const tierOf = (id: string) => rows.find((r) => within(r).queryByText(id))!.querySelector('[data-tier]')!.getAttribute('data-tier');
    expect(tierOf('CVE-2099-0001')).toBe('P0');
    expect(tierOf('CVE-2099-0005')).toBe('P2'); // high, no fix, not exposed: the Broker's rule, not ours
    expect(tierOf('CVE-2099-0004')).toBe('Background');
    const kev = rows.find((r) => within(r).queryByText('CVE-2099-0001'))!;
    // Chips render twice (stacked under the id on phones, own column from sm up).
    const chips = [...kev.querySelectorAll('td:nth-child(3) [data-factor]')].map((c) => c.getAttribute('data-factor'));
    expect(chips).toEqual(['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix']);
    expect(screen.getByLabelText('Tier', { exact: false })).toBeTruthy();
  });

  test('a Broker without tiers: every row "Tier ?", tier tiles unknown, no tier filter; never a computed tier', async () => {
    render(view());
    const rows = await screen.findAllByTestId('cve-row');
    for (const r of rows) expect(r.querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('unknown');
    expect(screen.getAllByText('unknown').length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByLabelText('Tier', { exact: false })).toBeNull();
  });

  test('401 is an auth-required state, not an empty list', async () => {
    render(view({ api: failing(401) }));
    expect(await screen.findByText('Broker token required')).toBeTruthy();
    expect(screen.queryByText(/No CVEs reported/)).toBeNull();
  });

  test('a Broker without the endpoints says so', async () => {
    render(view({ api: failing(404) }));
    expect(await screen.findByText('Vulnerability data not available')).toBeTruthy();
  });

  test('before the first summary rebuild: "not computed yet", never "no vulnerabilities"', async () => {
    const { api } = replayVulnApi([answer('GET /vulnerabilities?limit=50', { items: [], nextAfter: null, computedAt: null, staleSeconds: null })]);
    render(view({ api }));
    expect(await screen.findByText('Not computed yet')).toBeTruthy();
  });
});

describe('ImagesView: Images tab', () => {
  test('one failed read blanks only its own column (a 503 on the SBOM read is not "No SBOM")', async () => {
    const grafana = imageDetail('grafana').digest;
    const { api } = replayVulnApi([answer(`GET /images/${grafana}/sbom?limit=1`, 'busy', 503)]);
    render(view({ tab: 'images', api }));
    const rows = await screen.findAllByTestId('image-row');
    const row = rows.find((r) => within(r).queryByText('docker.io/grafana/grafana:11.2.0'))!;
    await waitFor(() => expect(within(row).getAllByText('Unknown').length).toBeGreaterThan(0));
    expect(within(row).queryByText('No SBOM')).toBeNull();
    // The other columns still read.
    expect(within(row).getAllByText('observability/grafana').length).toBeGreaterThan(0);
    expect(within(row).getAllByText(/2 findings/).length).toBeGreaterThan(0);
  });

  test('an image no source reported on reads "No data", not clean', async () => {
    render(view({ tab: 'images' }));
    const rows = await screen.findAllByTestId('image-row');
    const ne = rows.find((r) => within(r).queryByText('quay.io/prometheus/node-exporter:v1.8.2'))!;
    await waitFor(() => expect(within(ne).getAllByText('No data').length).toBeGreaterThan(0));
  });
});

describe('CVE drawer', () => {
  test("each workload row: its image's Broker tier, its own exposure and in-use, privilege from its profile", async () => {
    const { api: profileApi } = replayApi([answer('GET /workloads?namespace=payments&limit=500', listNamespacePayments.body)]);
    render(view({ cve: 'CVE-2099-0001', profileApi, api: replayVulnApi([], { tiers: true }).api }));
    await waitFor(() => expect(screen.getAllByTestId('cve-workload').length).toBeGreaterThan(0));
    const row = (name: string) => screen.getAllByTestId('cve-workload').find((r) => within(r).queryByText(name))!;
    await waitFor(() => expect(row('payments/checkout').querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('P0'));
    expect(row('payments/ledger').querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('P1');
    // KEV is per CVE across sources (#1678 @ 0c25f288): the Trivy-only reports row
    // is KEV too, and with exposure unknown (counted as exposed) it is P0.
    expect(row('payments/reports').querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('P0');
    const checkout = row('payments/checkout');
    await waitFor(() => expect(within(checkout).getAllByText('Not privileged').length).toBeGreaterThan(0));
    const chips = [...checkout.querySelectorAll('td:last-child [data-factor]')].map((c) => c.getAttribute('data-factor'));
    expect(chips).toEqual(['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix', 'privileged']);
    expect(within(checkout).getAllByText('Exposed: public IP, unattributed peer, other namespace').length).toBeGreaterThan(0);
  });

  test('on a Broker without tiers the drawer shows "Tier ?", not a computed tier', async () => {
    render(view({ cve: 'CVE-2099-0001' }));
    await waitFor(() => expect(screen.getAllByTestId('cve-workload').length).toBeGreaterThan(0));
    for (const r of screen.getAllByTestId('cve-workload')) expect(r.querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('unknown');
  });

  test('a CVE that affects nothing in the inventory says so', async () => {
    render(view({ cve: 'CVE-2099-9999' }));
    expect(await screen.findByText(/affects nothing in the inventory/)).toBeTruthy();
  });
});

test('a failed read never shows zero counts', async () => {
  render(view({ api: new VulnApi({ fetchImpl: (async () => new Response('', { status: 401 })) as typeof fetch }) }));
  await screen.findByText('Broker token required');
  expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(4);
  expect(screen.queryByText('Summary not computed yet')).toBeNull();
});

describe('Background and null tiers', () => {
  test('a Background row carries a visible caveat, not only a tooltip', async () => {
    render(view({ api: replayVulnApi([], { tiers: true }).api }));
    await screen.findAllByTestId('cve-row');
    expect(screen.getByTestId('background-caveat').textContent).toMatch(/Not proof it is unreachable/);
  });

  test('tier: null (not computed yet) is "Tier ?", never a guessed tier', async () => {
    const withNull = { ...cvePage, items: cvePage.items.map((c, i) => ({ ...c, tier: i === 0 ? null : 'P2' })) };
    const { api } = replayVulnApi([answer('GET /vulnerabilities?limit=50', withNull)]);
    render(view({ api }));
    const rows = await screen.findAllByTestId('cve-row');
    const first = rows.find((r) => within(r).queryByText('CVE-2099-0001'))!;
    expect(first.querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('unknown');
    expect(first.querySelector('[data-tier]')!.getAttribute('title')).toMatch(/not computed/);
  });
});
