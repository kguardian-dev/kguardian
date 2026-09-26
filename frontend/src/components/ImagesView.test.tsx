// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { ImagesView } from './ImagesView';
import { replayVulnApi, cvePage } from '../fixtures/vulns';
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
  test('one row per captured CVE; the KEV row is P0 with its reason chips', async () => {
    render(view());
    const rows = await screen.findAllByTestId('cve-row');
    expect(rows).toHaveLength(cvePage.items.length);
    const kev = rows.find((r) => within(r).queryByText('CVE-2099-0001'))!;
    expect(kev.querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('P0');
    // Chips render twice (stacked under the id on phones, own column from sm up).
    const chips = [...kev.querySelectorAll('td:nth-child(3) [data-factor]')].map((c) => c.getAttribute('data-factor'));
    expect(chips).toEqual(['inuse', 'kev', 'epss', 'cvss', 'fix']);
    expect(within(kev).getAllByText('Loaded: unknown').length).toBeGreaterThan(0);
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
  test('an image no source reported on reads "No data", not clean', async () => {
    render(view({ tab: 'images' }));
    const rows = await screen.findAllByTestId('image-row');
    const ne = rows.find((r) => within(r).queryByText('quay.io/prometheus/node-exporter:v1.8.2'))!;
    await waitFor(() => expect(within(ne).getByText('No data')).toBeTruthy());
  });
});

describe('CVE drawer', () => {
  test('each workload is tiered with its own exposure and shows every chip, privilege from its profile', async () => {
    const { api: profileApi } = replayApi([answer('GET /workloads?namespace=payments&limit=500', listNamespacePayments.body)]);
    render(view({ cve: 'CVE-2099-0001', profileApi }));
    await waitFor(() => expect(screen.getAllByTestId('cve-workload').length).toBeGreaterThan(0));
    const rows = screen.getAllByTestId('cve-workload');
    const checkout = rows.find((r) => within(r).queryByText('payments/checkout'))!;
    const ledger = rows.find((r) => within(r).queryByText('payments/ledger'))!;
    expect(checkout.querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('P0');
    expect(ledger.querySelector('[data-tier]')!.getAttribute('data-tier')).toBe('P1');
    await waitFor(() => expect(within(checkout).getAllByText('Not privileged').length).toBeGreaterThan(0));
    const chips = [...checkout.querySelectorAll('td:last-child [data-factor]')].map((c) => c.getAttribute('data-factor'));
    expect(chips).toEqual(['inuse', 'exposure', 'kev', 'epss', 'cvss', 'fix', 'privileged']);
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
