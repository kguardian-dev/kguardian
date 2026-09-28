// @vitest-environment jsdom
import { afterEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ImagesView } from './ImagesView';
import { replayVulnApi, cvePage, gatedVulnApi, imageDetail, imageVulns, vulnCapture } from '../fixtures/vulns';
import { answer, replayApi } from '../fixtures/replay';
import { listNamespacePayments } from '../fixtures/profile';
import { VulnApi } from '../services/vulnApi';
import type { CvePage } from '../types/vulns';

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
    render(view({ api: replayVulnApi().api }));
    const rows = await screen.findAllByTestId('cve-row');
    expect(rows).toHaveLength(cvePage.items.length);
    const tierOf = (id: string) => rows.find((r) => within(r).queryByText(id))!.querySelector('[data-tier]')!.getAttribute('data-tier');
    expect(tierOf('CVE-2099-0001')).toBe('P0');
    expect(tierOf('CVE-2099-0005')).toBe('P2'); // high, no fix, not exposed: the Broker's rule, not ours
    expect(tierOf('CVE-2099-0004')).toBe('Background'); // busybox: installed, covered and never run
    const kev = rows.find((r) => within(r).queryByText('CVE-2099-0001'))!;
    // Chips render twice (stacked under the id on phones, own column from sm up).
    const chips = [...kev.querySelectorAll('td:nth-child(3) [data-factor]')].map((c) => c.getAttribute('data-factor'));
    expect(chips).toEqual(['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix']);
    expect(screen.getByLabelText('Tier', { exact: false })).toBeTruthy();
  });

  test('a Broker without tiers: every row "Tier ?", tier tiles unknown, no tier filter; never a computed tier', async () => {
    render(view({ api: replayVulnApi([], { broker: '1671' }).api }));
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
    render(view({ cve: 'CVE-2099-0001', profileApi, api: replayVulnApi().api }));
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
    render(view({ cve: 'CVE-2099-0001', api: replayVulnApi([], { broker: '1671' }).api }));
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

describe('ImagesView: header tiles count the scope (DATA-10, IMG-07)', () => {
  const tile = (label: string) => within(screen.getByRole('group', { name: 'Vulnerability posture' })).getByText(label).closest('div,button')!.parentElement!.textContent!;

  test('the tiles count every CVE in scope while the table shows its first page', async () => {
    const page1 = vulnCapture<CvePage>('vulnerabilities-page1-limit2').body;
    const { api, calls } = replayVulnApi([answer('GET /vulnerabilities?limit=50', page1)]);
    render(view({ api }));
    expect(await screen.findAllByTestId('cve-row')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Load more CVEs' })).toBeTruthy();
    await waitFor(() => expect(tile('CVEs on running workloads')).toBe('CVEs on running workloads7'));
    expect(tile('P0 act now')).toBe('P0 act now1');
    expect(tile('P1 schedule')).toBe('P1 schedule3');
    expect(tile('In CISA KEV')).toBe('In CISA KEV14 unknown');
    expect(calls).toContain('GET /vulnerabilities?limit=500');
    expect(screen.queryByTestId('tiles-caption')).toBeNull();
  });

  test('the filters narrow the table only; the tiles keep the scope counts and say so', async () => {
    render(view({ api: replayVulnApi().api }));
    expect(await screen.findAllByTestId('cve-row')).toHaveLength(cvePage.items.length);
    fireEvent.change(screen.getByLabelText('Severity', { exact: false }), { target: { value: 'c' } });
    await waitFor(() => expect(screen.getAllByTestId('cve-row')).toHaveLength(1));
    expect(tile('P1 schedule')).toBe('P1 schedule3');
    expect(tile('CVEs on running workloads')).toBe('CVEs on running workloads7');
    expect(screen.getByTestId('tiles-caption').textContent).toBe('The tiles count every CVE in all namespaces; the filters below narrow the table only.');
  });

  test('more CVEs than one read returns: the tiles say "+" and that they cover the first 500', async () => {
    const { api } = replayVulnApi([answer('GET /vulnerabilities?limit=500', { ...cvePage, nextAfter: 'more' })]);
    render(view({ api }));
    await screen.findAllByTestId('cve-row');
    await waitFor(() => expect(tile('CVEs on running workloads')).toBe('CVEs on running workloads7+'));
    expect(tile('P0 act now')).toBe('P0 act now1+');
    expect(screen.getByTestId('tiles-caption').textContent).toMatch(/\(the first 500\)/);
  });

  test('a scope change clears the tiles and the table until the new scope has been read', async () => {
    const empty = { items: [], nextAfter: null, computedAt: cvePage.computedAt, staleSeconds: 1 };
    const g = gatedVulnApi((l) => l.startsWith('GET /vulnerabilities?namespace=empty'), [
      answer('GET /vulnerabilities?namespace=empty&limit=50', empty),
      answer('GET /vulnerabilities?namespace=empty&limit=500', empty),
    ]);
    const { rerender } = render(view({ api: g.api }));
    await screen.findAllByTestId('cve-row');
    await waitFor(() => expect(tile('CVEs on running workloads')).toBe('CVEs on running workloads7'));
    rerender(view({ api: g.api, allNamespaces: false, namespace: 'empty' }));
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(g.held.length).toBe(2);
    // The header says "empty": its tiles and rows must not still be the cluster's.
    expect(tile('CVEs on running workloads')).toBe('CVEs on running workloads…');
    expect(tile('P1 schedule')).toBe('P1 schedule…');
    expect(screen.queryAllByTestId('cve-row')).toHaveLength(0);
    await act(() => g.release(/limit=500/));
    await act(() => g.release(/limit=50$/));
    await waitFor(() => expect(tile('CVEs on running workloads')).toBe('CVEs on running workloads0'));
    expect(await screen.findByText(/No CVEs reported for empty/)).toBeTruthy();
  });

  test('IMG-17: the Tier filter stays when the scope has no CVEs; only a Broker that sends no tiers hides it', async () => {
    const empty = { items: [], nextAfter: null, computedAt: cvePage.computedAt, staleSeconds: 1 };
    const { api } = replayVulnApi([answer('GET /vulnerabilities?namespace=empty&limit=50', empty), answer('GET /vulnerabilities?namespace=empty&limit=500', empty)]);
    render(view({ api, allNamespaces: false, namespace: 'empty' }));
    await screen.findByText(/No CVEs reported for empty/);
    expect(screen.getByLabelText('Tier', { exact: false })).toBeTruthy();
  });
});

describe('Summary freshness (IMG-15)', () => {
  afterEach(() => vi.useRealTimers());

  test('the age keeps counting while the page sits open', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
    const { api } = replayVulnApi([answer('GET /vulnerabilities?limit=50', { ...cvePage, staleSeconds: 100 })]);
    render(view({ api }));
    expect((await screen.findByText(/^Summary rebuilt/)).textContent).toBe('Summary rebuilt 2m ago');
    act(() => {
      vi.advanceTimersByTime(65_000);
    });
    expect(screen.getByText(/^Summary rebuilt/).textContent).toBe('Summary rebuilt 3m ago');
    expect(screen.getByText(/^Summary rebuilt/).getAttribute('title')).toMatch(/^Rebuilt 2026-09-27 01:29 UTC\./);
  });
});

describe('ImagesView: Images tab reads (IMG-09, IMG-11)', () => {
  test('a digest no source reported on skips the SBOM read and says "Not read", not "No SBOM"', async () => {
    const ne = imageDetail('node-exporter').digest;
    const grafana = imageDetail('grafana').digest;
    const { api, calls } = replayVulnApi();
    render(view({ tab: 'images', api }));
    const rows = await screen.findAllByTestId('image-row');
    const row = rows.find((r) => within(r).queryByText('quay.io/prometheus/node-exporter:v1.8.2'))!;
    await waitFor(() => expect(within(row).getAllByText('Not read').length).toBeGreaterThan(0));
    expect(within(row).queryByText('No SBOM')).toBeNull();
    // A digest with a report still has its SBOM read.
    await waitFor(() => expect(calls.some((c) => c.startsWith(`GET /images/${grafana}/sbom`))).toBe(true));
    expect(calls.some((c) => c.startsWith(`GET /images/${ne}/sbom`))).toBe(false);
  });

  test('a Refresh keeps the cells on screen until their re-read lands', async () => {
    const { api } = replayVulnApi();
    const { rerender } = render(view({ tab: 'images', api, refreshTick: 0 }));
    const rows = await screen.findAllByTestId('image-row');
    await waitFor(() => expect(screen.queryAllByText('…')).toHaveLength(0));
    rerender(view({ tab: 'images', api, refreshTick: 1 }));
    expect(screen.queryAllByText('…')).toHaveLength(0);
    expect(screen.getAllByTestId('image-row')).toHaveLength(rows.length);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(screen.queryAllByText('…')).toHaveLength(0);
  });

  test('IMG-11: when /sbom lists nothing but the report names the SBOM it matched from, the cell shows that SBOM', async () => {
    const ledger = imageDetail('ledger').digest;
    const page = imageVulns('ledger');
    const grype = { ...page.reports[0], source: 'grype', sbomSources: ['registry'], sbomTrust: 'unverified' as const };
    const { api } = replayVulnApi([answer(`GET /images/${ledger}/vulnerabilities?limit=1`, { ...page, reports: [grype] })]);
    render(view({ tab: 'images', api }));
    const rows = await screen.findAllByTestId('image-row');
    const row = rows.find((r) => within(r).queryByText('ghcr.io/example/ledger:2.3.1'))!;
    await waitFor(() => expect(within(row).getAllByTestId('sbom-matched').length).toBeGreaterThan(0));
    expect(within(row).getAllByText(/used by Grype/).length).toBeGreaterThan(0);
    expect(within(row).queryByText('No SBOM')).toBeNull();
  });
});

describe('Background and null tiers', () => {
  test('a Background row carries a visible caveat, not only a tooltip', async () => {
    // Captured: busybox is Background on a real Broker.
    expect(cvePage.items.find((c) => c.id === 'CVE-2099-0004')!.tier).toBe('Background');
    render(view({ api: replayVulnApi().api }));
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
