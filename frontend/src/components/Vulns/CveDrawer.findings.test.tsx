// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { CveDrawer } from './CveDrawer';
import { VulnApi } from '../../services/vulnApi';
import { ProfileApi } from '../../services/profileApi';
import { vulnCapture } from '../../fixtures/vulns';
import { CVE_FINDING_PAGES } from '../../hooks/useVulns';
import type { Exposure, Finding, ImageVulnsPage } from '../../types/vulns';

// The image read returns one finding per (CVE, package, version), and has no
// CVE filter: the drawer must look at every one of the CVE's findings in the
// image, however many packages carry it and however deep in the pages they are.

afterEach(cleanup);

const noProfiles = new ProfileApi({ fetchImpl: (async () => new Response('', { status: 404 })) as typeof fetch });
const exposure = vulnCapture<Exposure>('exposure-CVE-2099-0001').body;
const ledgerPage = vulnCapture<ImageVulnsPage>('image-ledger-vulnerabilities').body;
const cveFinding = ledgerPage.items.find((x) => x.id === exposure.id)!;
const ledgerOnly: Exposure = {
  ...exposure,
  workloads: exposure.workloads.filter((w) => w.name === 'ledger'),
  images: exposure.images.filter((i) => i.repository?.endsWith('ledger')),
};
const filler = (n: number): Finding[] => Array.from({ length: n }, (_, i) => ({ ...cveFinding, id: `CVE-2098-${1000 + i}`, severity: 'CRITICAL', tier: 'P1' }));

/** Answers the image read one page at a time: `pages[i]` for the request whose `after` is `c<i>`. */
function paged(e: Exposure, pages: Finding[][]) {
  const reads: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const u = new URL(String(input), 'http://x');
    if (u.pathname.endsWith('/exposure')) return new Response(JSON.stringify(e), { status: 200 });
    reads.push(u.search);
    const i = Number((u.searchParams.get('after') ?? 'c0').slice(1));
    return new Response(JSON.stringify({ ...ledgerPage, items: pages[i], nextAfter: i + 1 < pages.length ? `c${i + 1}` : null }), { status: 200 });
  }) as typeof fetch;
  return { api: new VulnApi({ fetchImpl }), reads };
}

async function settle() {
  for (let i = 0; i < 40 && screen.queryAllByTestId('cve-workload').length === 0; i++) await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
  await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
}

const renderDrawer = (api: VulnApi, e: Exposure) =>
  render(<CveDrawer id={e.id} onClose={() => {}} onOpenWorkload={() => {}} onShowOnMap={() => {}} onAskAI={() => {}} api={api} profileApi={noProfiles} />);
const headlineTier = () => screen.getByRole('dialog').querySelector('[data-tier]:not([data-testid=cve-workload] [data-tier])')?.getAttribute('data-tier');
const rowTier = () => screen.getAllByTestId('cve-workload')[0].querySelector('[data-tier]')!.getAttribute('data-tier');
const headlineLabels = () =>
  [...screen.getByRole('dialog').querySelectorAll('[data-factor]')].filter((c) => !c.closest('[data-testid=cve-workload]')).map((c) => c.textContent);

describe('CVE drawer: the CVE in several packages of one image', () => {
  test('the worst tier over every package, not the first one listed', async () => {
    const twoPkgs: Exposure = {
      ...ledgerOnly,
      images: ledgerOnly.images.map((i) => ({ ...i, packages: [{ ...i.packages[0], name: 'libfoo-doc' }, ...i.packages] })),
    };
    const items = [
      // Listed first (same severity, lower row id), and nothing ran: Background.
      { ...cveFinding, package: { ...cveFinding.package, name: 'libfoo-doc' }, kev: false, tier: 'Background', tierFactors: ['in_use:installed_not_observed', 'severity:critical', 'internal'] },
      { ...cveFinding, tier: 'P0', tierFactors: ['in_use:executed', 'kev', 'severity:critical', 'exposed'] },
      ...ledgerPage.items.filter((x) => x.id !== exposure.id),
    ];
    const { api } = paged(twoPkgs, [items]);
    renderDrawer(api, twoPkgs);
    await settle();
    expect({ head: headlineTier(), row: rowTier() }).toEqual({ head: 'P0', row: 'P0' });
    // The P0 package's factors explain the tier (in-use and exposure are each workload's own).
    expect(headlineLabels()).toContain('KEV');
  });
});

describe('CVE drawer: an image with more findings than one read', () => {
  test('the CVE past the first page is still found', async () => {
    const { api, reads } = paged(ledgerOnly, [filler(500), [{ ...cveFinding, tier: 'P0', tierFactors: ['in_use:executed', 'kev', 'severity:critical', 'exposed'] }]]);
    renderDrawer(api, ledgerOnly);
    await settle();
    expect(rowTier()).toBe('P0');
    expect(reads).toHaveLength(2);
  });

  test('every package found on the first page: no second read', async () => {
    const { api, reads } = paged(ledgerOnly, [[cveFinding, ...filler(499)], filler(500)]);
    renderDrawer(api, ledgerOnly);
    await settle();
    expect(rowTier()).toBe(cveFinding.tier);
    expect(reads).toHaveLength(1);
  });

  test('paging stops past the CVE\'s severity: the rest of the image cannot carry it', async () => {
    const low = filler(500).map((f) => ({ ...f, severity: 'LOW' as const }));
    const { api, reads } = paged(ledgerOnly, [low, filler(500)]);
    renderDrawer(api, ledgerOnly);
    await settle();
    expect(reads).toHaveLength(1);
    // Read in full and not there: unknown, as before, and not "read incomplete".
    expect(rowTier()).toBe('unknown');
    expect(headlineLabels()).not.toContain('read incomplete');
  });

  test('not found within the read budget: the row is unknown and the headline says the read was incomplete', async () => {
    const { api, reads } = paged(ledgerOnly, Array.from({ length: CVE_FINDING_PAGES + 1 }, () => filler(500)));
    renderDrawer(api, ledgerOnly);
    await settle();
    expect(reads).toHaveLength(CVE_FINDING_PAGES);
    expect(rowTier()).toBe('unknown');
    const labels = headlineLabels();
    expect(labels).toContain('read incomplete');
    expect(labels).toContain('1 unknown');
  });
});
