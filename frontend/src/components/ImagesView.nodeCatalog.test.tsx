// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ImagesView } from './ImagesView';
import { imageDetail, imageSbom, imagesPage, replayVulnApi } from '../fixtures/vulns';
import { answer } from '../fixtures/replay';
import type { CatalogCoverage, ImagePage, NodeCatalogState, SbomPage } from '../types/vulns';

afterEach(cleanup);

const noop = () => {};
const view = (over: Partial<Parameters<typeof ImagesView>[0]> = {}) => (
  <ImagesView namespace="payments" allNamespaces onParamsChange={noop} onOpenWorkload={noop} onShowOnMap={noop} onAskAI={noop} api={replayVulnApi().api} {...over} />
);

const coverage: CatalogCoverage = {
  grantsEnabled: true, tokenConfigured: true, runningImages: 8, trivy: 5, node: 2, trusted: 6, coverageRatio: 0.75,
  byState: { pending: 1, done: 3, failed: 1 }, byCompleteness: { full: 1, partial: 1 }, byReason: { lsm_denied: 1, oom: 1 }, platforms: { 'linux/arm64': 2 },
};
const nc = (over: Partial<NodeCatalogState>): NodeCatalogState => ({ state: 'done', reason: null, platform: 'linux/arm64', completeness: 'full', catalogedAt: '2026-09-30T10:00:00Z', ...over });
const grafana = imageDetail('grafana').digest;
const ne = imageDetail('node-exporter').digest;
const prom = imageDetail('prometheus').digest;

// The captured inventory plus the node catalog's fields on three digests.
const withCatalog: ImagePage = {
  ...imagesPage,
  items: imagesPage.items.map((i) => {
    if (i.digest === grafana) return { ...i, sbomSources: ['node', 'registry'], nodeCatalog: nc({ completeness: 'partial' }) };
    if (i.digest === ne) return { ...i, nodeCatalog: nc({ reason: 'no_packages_found', completeness: null, platform: null }) };
    if (i.digest === prom) return { ...i, nodeCatalog: nc({ state: 'claimed', completeness: null, catalogedAt: null }) };
    return i;
  }),
};
const grafanaSbom = imageSbom('grafana');
const nodeSbom: SbomPage = {
  ...grafanaSbom,
  reports: [{ ...grafanaSbom.reports[0], source: 'node', sbomTrust: 'scanned', attestation: null, scannerName: 'kguardian-cataloger' }, ...grafanaSbom.reports],
};
const extra = [answer('GET /images?limit=25', withCatalog), answer('GET /catalog/coverage', coverage), answer(`GET /images/${grafana}/sbom?limit=1`, nodeSbom)];
const rowOf = async (repo: string) => (await screen.findAllByTestId('image-row')).find((r) => within(r).queryByText(repo))!;
const sbomCell = (row: HTMLElement) => row.querySelector('td:nth-child(4)') as HTMLElement;

/** Opens an image from the table, and re-renders with the digest in the URL as the app would. */
async function openImage(repo: string) {
  let digest: string | undefined;
  const api = replayVulnApi(extra).api;
  const onParamsChange = (patch: Record<string, string | undefined>) => {
    if ('digest' in patch) digest = patch.digest;
  };
  const { rerender } = render(view({ tab: 'images', api, onParamsChange }));
  fireEvent.click(await rowOf(repo));
  rerender(view({ tab: 'images', api, onParamsChange, digest }));
  return screen.findByRole('dialog');
}

describe('ImagesView: node catalog (additive; an older Broker sends none of it)', () => {
  test('the coverage banner: trusted SBOMs by source, the queue, failures by reason', async () => {
    render(view({ api: replayVulnApi(extra).api }));
    const banner = await screen.findByTestId('coverage-banner');
    expect(within(banner).getByTestId('coverage-headline').textContent).toBe('6 of 8 running images have a trusted SBOM: 5 Trivy, 2 node');
    expect(within(banner).getByTestId('coverage-queue').textContent).toBe('· 1 pending, 1 failed');
    expect(within(banner).getByTestId('coverage-reasons').textContent).toBe('Not cataloged, by reason: LSM denied 1, out of memory 1');
  });

  test.each([404, 503])('the banner is hidden, quietly, on a %i', async (status) => {
    const { api, calls } = replayVulnApi([answer('GET /catalog/coverage', status === 503 ? 'busy' : '', status)]);
    render(view({ api }));
    await screen.findAllByTestId('cve-row');
    await waitFor(() => expect(calls).toContain('GET /catalog/coverage'));
    expect(screen.queryByTestId('coverage-banner')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  test('image rows: provenance chips with the node platform and completeness; not assessable; cataloging', async () => {
    render(view({ tab: 'images', api: replayVulnApi(extra).api }));
    const cell = sbomCell(await rowOf('docker.io/grafana/grafana:11.2.0'));
    expect([...cell.querySelectorAll('[data-testid="provenance-chip"]')].map((c) => c.textContent)).toEqual(['Cataloged on node (linux/arm64)', 'Registry SBOM']);
    expect(within(cell).getByTestId('provenance-completeness').textContent).toBe('partial');
    // The node SBOM is always scanned; the registry one's trust follows once its read lands.
    expect(within(cell).getByText('Scanned in cluster')).toBeTruthy();
    await waitFor(() => expect(within(cell).getByText('Attached, unbound')).toBeTruthy());

    const n = await rowOf('quay.io/prometheus/node-exporter:v1.8.2');
    const na = await within(sbomCell(n)).findByTestId('not-assessable');
    expect(na.getAttribute('data-reason')).toBe('no_packages_found');
    expect(within(na).getByText('Not assessable')).toBeTruthy();
    expect(within(na).getByText('no packages found')).toBeTruthy();
    expect(within(n).queryByText('Not read')).toBeNull();

    const p = await rowOf('quay.io/prometheus/prometheus:v2.54.1');
    expect(within(sbomCell(p)).getByTestId('catalog-pending').textContent).toBe('Node catalog: cataloging');
  });

  test('a failed vulnerability read (503) is unknown, not "no report": no "Not assessable"', async () => {
    const page: ImagePage = { ...imagesPage, items: imagesPage.items.map((i) => (i.digest === ne ? { ...i, nodeCatalog: nc({ state: 'failed', reason: 'oom', completeness: null }) } : i)) };
    const { api, calls } = replayVulnApi([answer('GET /images?limit=25', page), answer(`GET /images/${ne}/vulnerabilities?limit=1`, 'busy', 503)]);
    render(view({ tab: 'images', api }));
    const n = await rowOf('quay.io/prometheus/node-exporter:v1.8.2');
    await waitFor(() => expect(calls.some((c) => c.startsWith(`GET /images/${ne}/sbom`))).toBe(true));
    await waitFor(() => expect(within(n).getAllByText('Unknown').length).toBeGreaterThan(0));
    expect(within(n).queryByTestId('not-assessable')).toBeNull();
  });

  test('a pending row whose last node could not catalog it is pending, naming that node\'s reason', async () => {
    const page: ImagePage = { ...imagesPage, items: imagesPage.items.map((i) => (i.digest === ne ? { ...i, nodeCatalog: nc({ state: 'pending', reason: 'lsm_denied', completeness: null }) } : i)) };
    render(view({ tab: 'images', api: replayVulnApi([answer('GET /images?limit=25', page)]).api }));
    const n = await rowOf('quay.io/prometheus/node-exporter:v1.8.2');
    expect((await within(sbomCell(n)).findByTestId('catalog-pending')).textContent).toBe('Node catalog: pending · last node: LSM denied');
    await waitFor(() => expect(within(sbomCell(n)).getByText('Not read')).toBeTruthy());
    expect(within(n).queryByTestId('not-assessable')).toBeNull();
  });

  test('a scanner report without an SBOM is an assessment: no "Not assessable" beside it', async () => {
    // reports: Trivy Operator reported on it; the node catalog failed (oom).
    const reports = imageDetail('reports').digest;
    const page: ImagePage = { ...imagesPage, items: imagesPage.items.map((i) => (i.digest === reports ? { ...i, nodeCatalog: nc({ state: 'failed', reason: 'oom', completeness: null }) } : i)) };
    render(view({ tab: 'images', api: replayVulnApi([answer('GET /images?limit=25', page)]).api }));
    const r = await rowOf('ghcr.io/example/reports:1.0.3');
    await waitFor(() => expect(within(r).getAllByText(/1 finding/).length).toBeGreaterThan(0));
    expect(within(r).queryByTestId('not-assessable')).toBeNull();
  });

  test('the extra SBOM read is only for a registry SBOM: node and Trivy SBOMs show as scanned without it', async () => {
    const page = (sources: string[]): ImagePage => ({ ...imagesPage, items: imagesPage.items.map((i) => (i.digest === ne ? { ...i, sbomSources: sources, nodeCatalog: nc({}) } : i)) });
    const nodeOnly = replayVulnApi([answer('GET /images?limit=25', page(['node', 'trivy-operator']))]);
    render(view({ tab: 'images', api: nodeOnly.api }));
    const n = await rowOf('quay.io/prometheus/node-exporter:v1.8.2');
    expect([...sbomCell(n).querySelectorAll('[data-testid="provenance-chip"]')].map((c) => c.textContent)).toEqual(['Trivy Operator', 'Cataloged on node (linux/arm64)']);
    expect(within(sbomCell(n)).getAllByText('Scanned in cluster')).toHaveLength(2);
    await waitFor(() => expect(nodeOnly.calls.filter((c) => c.startsWith('GET /images/sha256')).length).toBeGreaterThan(8));
    await new Promise((r) => setTimeout(r, 50));
    expect(nodeOnly.calls.some((c) => c.startsWith(`GET /images/${ne}/sbom`))).toBe(false);
    cleanup();

    const withRegistry = replayVulnApi([answer('GET /images?limit=25', page(['node', 'registry']))]);
    render(view({ tab: 'images', api: withRegistry.api }));
    await rowOf('quay.io/prometheus/node-exporter:v1.8.2');
    await waitFor(() => expect(withRegistry.calls.some((c) => c.startsWith(`GET /images/${ne}/sbom`))).toBe(true));
  });

  test('a new Broker with the catalog disabled makes exactly the reads an older one does, and renders the same', async () => {
    // What a node catalog Broker sends with the catalog off: sbomSources, no nodeCatalog.
    const sourcesOf: Record<string, string[]> = { [imageDetail('checkout').digest]: ['trivy-operator'], [grafana]: ['registry'], [imageDetail('source-controller').digest]: ['registry'] };
    const disabled: ImagePage = { ...imagesPage, items: imagesPage.items.map((i) => (sourcesOf[i.digest] ? { ...i, sbomSources: sourcesOf[i.digest] } : i)) };
    const run = async (api: ReturnType<typeof replayVulnApi>) => {
      render(view({ tab: 'images', api: api.api }));
      const rows = await screen.findAllByTestId('image-row');
      await waitFor(() => expect(rows.every((r) => !sbomCell(r).textContent!.includes('…'))).toBe(true));
      await new Promise((r) => setTimeout(r, 50));
      const cells = rows.map((r) => sbomCell(r).textContent);
      const reads = api.calls.filter((c) => c !== 'GET /catalog/coverage').sort();
      cleanup();
      return { cells, reads };
    };
    const older = await run(replayVulnApi());
    const newer = await run(replayVulnApi([answer('GET /images?limit=25', disabled)]));
    expect(newer.reads).toEqual(older.reads);
    expect(newer.cells).toEqual(older.cells);
    expect(document.querySelector('[data-testid="provenance-chip"]')).toBeNull();
  });

  test('the image drawer names the node SBOM with its platform and completeness', async () => {
    const dialog = await openImage('docker.io/grafana/grafana:11.2.0');
    const reports = await within(dialog).findAllByTestId('sbom-report');
    const node = reports.find((r) => r.querySelector('[data-source="node"]'))!;
    expect(node.querySelector('[data-source="node"]')!.textContent).toBe('Cataloged on node (linux/arm64)');
    expect(within(node).getByTestId('provenance-completeness').textContent).toBe('partial');
    expect(within(node).getByText('Scanned in cluster').getAttribute('title')).toMatch(/node cataloger/);
  });

  test('the image drawer says "Not assessable" with the reason, never "0 CVEs"', async () => {
    const dialog = await openImage('quay.io/prometheus/node-exporter:v1.8.2');
    const na = await within(dialog).findByTestId('not-assessable');
    expect(na.textContent).toMatch(/^Not assessable: no packages found/);
    expect(within(dialog).queryByText('No SBOM from any source.')).toBeNull();
  });

  test('the image drawer for a failed catalog with no report: not assessable, with the back-off', async () => {
    const page: ImagePage = { ...imagesPage, items: imagesPage.items.map((i) => (i.digest === ne ? { ...i, nodeCatalog: nc({ state: 'failed', reason: 'timeout', completeness: null }) } : i)) };
    let digest: string | undefined;
    const api = replayVulnApi([answer('GET /images?limit=25', page)]).api;
    const onParamsChange = (patch: Record<string, string | undefined>) => {
      if ('digest' in patch) digest = patch.digest;
    };
    const { rerender } = render(view({ tab: 'images', api, onParamsChange }));
    fireEvent.click(await rowOf('quay.io/prometheus/node-exporter:v1.8.2'));
    rerender(view({ tab: 'images', api, onParamsChange, digest }));
    const na = await within(await screen.findByRole('dialog')).findByTestId('not-assessable');
    expect(na.textContent).toMatch(/^Not assessable: timed out/);
    expect(na.textContent).toMatch(/Retried after a back-off\./);
  });

  test('the image drawer opened by deep link (no inventory row): the node SBOM without platform, and no state it cannot know', async () => {
    render(view({ tab: 'images', api: replayVulnApi(extra).api, digest: grafana }));
    const dialog = await screen.findByRole('dialog');
    const reports = await within(dialog).findAllByTestId('sbom-report');
    const node = reports.find((r) => r.querySelector('[data-source="node"]'))!;
    expect(node.querySelector('[data-source="node"]')!.textContent).toBe('Cataloged on node');
    expect(within(dialog).queryByTestId('provenance-completeness')).toBeNull();
    cleanup();
    render(view({ tab: 'images', api: replayVulnApi(extra).api, digest: ne }));
    const d2 = await screen.findByRole('dialog');
    await within(d2).findByText('No SBOM from any source.');
    expect(within(d2).queryByTestId('not-assessable')).toBeNull();
  });

  test('an older Broker: no chips, no banner, the SBOM column as before', async () => {
    render(view({ tab: 'images', api: replayVulnApi().api }));
    const g = await rowOf('docker.io/grafana/grafana:11.2.0');
    await waitFor(() => expect(within(g).getAllByText('Registry SBOM').length).toBeGreaterThan(0));
    expect(screen.queryByTestId('provenance-chip')).toBeNull();
    expect(screen.queryByTestId('not-assessable')).toBeNull();
    expect(screen.queryByTestId('catalog-pending')).toBeNull();
    expect(screen.queryByTestId('coverage-banner')).toBeNull();
  });
});
