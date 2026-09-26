// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { CveDrawer } from './CveDrawer';
import { VulnApi } from '../../services/vulnApi';
import { ProfileApi } from '../../services/profileApi';
import { vulnCapture } from '../../fixtures/vulns';
import type { CveSummary, CvePage, Exposure, ImageVulnsPage } from '../../types/vulns';

// The headline is the worst case over EVERY workload row, and says nothing
// until every image read has settled. Image reads here resolve only when the
// test says so, in the order it chooses, so the result cannot depend on timing.

afterEach(cleanup);

type Deferred = { resolve: (r: Response) => void; reject: (e: unknown) => void };

function controlled(exposure: Exposure) {
  const waiting = new Map<string, Deferred>();
  const fetchImpl = ((input: RequestInfo | URL) => {
    const path = new URL(String(input), 'http://x').pathname.replace(/^\/api/, '');
    if (path.endsWith('/exposure')) return Promise.resolve(new Response(JSON.stringify(exposure), { status: 200 }));
    const digest = decodeURIComponent(path.split('/')[2]);
    return new Promise<Response>((resolve, reject) => waiting.set(digest, { resolve, reject }));
  }) as typeof fetch;
  const api = new VulnApi({ fetchImpl });
  const answer = async (digest: string, page: ImageVulnsPage | 'fail') => {
    for (let i = 0; i < 50 && !waiting.has(digest); i++) await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
    const d = waiting.get(digest);
    if (!d) throw new Error(`no read in flight for ${digest}`);
    await act(async () => {
      if (page === 'fail') d.resolve(new Response('busy', { status: 503 }));
      else d.resolve(new Response(JSON.stringify(page), { status: 200 }));
    });
  };
  return { api, answer };
}

const noProfiles = new ProfileApi({ fetchImpl: (async () => new Response('', { status: 404 })) as typeof fetch });
const exposure = vulnCapture<Exposure>('exposure-CVE-2099-0001').body;
const page = (name: string) => vulnCapture<ImageVulnsPage>(`image-${name}-vulnerabilities`).body;
const digestOf = (repo: string) => exposure.images.find((i) => i.repository?.endsWith(repo))!.digest;

const renderDrawer = (api: VulnApi, e: Exposure = exposure, summary?: CveSummary) =>
  render(<CveDrawer id={e.id} summary={summary} onClose={() => {}} onOpenWorkload={() => {}} onShowOnMap={() => {}} onAskAI={() => {}} api={api} profileApi={noProfiles} />);
const rowTier = (name: string) =>
  screen.getAllByTestId('cve-workload').find((r) => r.textContent?.includes(name))!.querySelector('[data-tier]')!.getAttribute('data-tier');

const headlineTier = () => screen.getByRole('dialog').querySelector('[data-tier]:not([data-testid=cve-workload] [data-tier])')?.getAttribute('data-tier');
const headlineLabels = () =>
  [...screen.getByRole('dialog').querySelectorAll('[data-factor]')].filter((c) => !c.closest('[data-testid=cve-workload]')).map((c) => c.textContent);

describe('CVE drawer headline', () => {
  test('the least severe image answers first: pending until all settle, then the worst case over every row', async () => {
    const { api, answer } = controlled(exposure);
    renderDrawer(api);
    // ledger: P1, no outside ingress. Alone it would understate the CVE.
    await answer(digestOf('ledger'), page('ledger'));
    expect(screen.getByTestId('headline-pending')).toBeTruthy();
    expect(headlineTier()).toBeUndefined();
    // Rows whose read is still in flight say "…" too, not "unknown".
    expect(rowTier('payments/ledger')).toBe('P1');
    expect(rowTier('payments/checkout')).toBe('pending');
    expect(rowTier('payments/reports')).toBe('pending');
    await answer(digestOf('reports'), page('reports'));
    expect(screen.getByTestId('headline-pending')).toBeTruthy();
    await answer(digestOf('checkout'), page('checkout'));
    expect(screen.queryByTestId('headline-pending')).toBeNull();
    expect(headlineTier()).toBe('P0');
    const labels = headlineLabels();
    expect(labels).toContain('KEV');
    expect(labels.some((l) => l?.startsWith('Exposed'))).toBe(true);
    // In use is unknown on every captured row (no runtime inventory on main yet).
    expect(labels).toContain('Loaded: unknown');
    expect(labels).not.toContain('No outside ingress seen (7d)');
  });

  test('a P2 row and a row with no tier: P2 plus "1 unknown", never P2 alone', async () => {
    const two: Exposure = {
      ...exposure,
      workloads: exposure.workloads.filter((w) => w.name !== 'reports'),
      images: exposure.images.filter((i) => !i.repository?.endsWith('reports')),
    };
    const { api, answer } = controlled(two);
    renderDrawer(api, two);
    const asP2 = { ...page('ledger'), items: page('ledger').items.map((f) => (f.id === exposure.id ? { ...f, tier: 'P2', tierFactors: ['in_use:loaded', 'severity:critical', 'internal'] } : f)) };
    const noTier = { ...page('checkout'), items: page('checkout').items.map((f) => (f.id === exposure.id ? { ...f, tier: null, tierFactors: [] } : f)) };
    await answer(digestOf('ledger'), asP2);
    await answer(digestOf('checkout'), noTier);
    expect(headlineTier()).toBe('P2');
    expect(headlineLabels()).toContain('1 unknown');
    // With an unknown row the known P2 is a floor, not the answer.
    const floor = screen.getByRole('dialog').querySelector('[data-at-least]')!;
    // Seen: "≥P2"; read out: "at least P2; 1 unknown" (the glyph is aria-hidden).
    const seen = [...floor.childNodes].filter((n) => !(n instanceof HTMLElement && n.classList.contains('sr-only'))).map((n) => n.textContent).join('');
    expect(seen).toBe('≥P2');
    expect(floor.querySelector('[aria-hidden="true"]')!.textContent).toBe('≥');
    expect(floor.textContent!.replace('≥', '')).toBe('at least P2; 1 unknown');
    expect(floor.getAttribute('title')).toBe('at least P2; 1 row unknown');
  });

  test('a failed read: "read failed" in the headline, and its row is unknown', async () => {
    const { api, answer } = controlled(exposure);
    renderDrawer(api);
    await answer(digestOf('ledger'), page('ledger'));
    await answer(digestOf('reports'), page('reports'));
    await answer(digestOf('checkout'), 'fail');
    const labels = headlineLabels();
    expect(labels).toContain('read failed');
    expect(labels).toContain('1 unknown');
  });
});

test("the Broker's CVE-level tier is folded in: a P0 summary beats a P1 row, with the unknowns and the failed read still shown", async () => {
  const two: Exposure = {
    ...exposure,
    workloads: exposure.workloads,
    images: exposure.images,
  };
  const summary = { ...vulnCapture<CvePage>('vulnerabilities').body.items.find((c) => c.id === exposure.id)!, tier: 'P0' };
  const { api, answer } = controlled(two);
  renderDrawer(api, two, summary);
  const noTier = { ...page('checkout'), items: page('checkout').items.map((f) => (f.id === exposure.id ? { ...f, tier: null, tierFactors: [] } : f)) };
  await answer(digestOf('ledger'), page('ledger')); // P1
  await answer(digestOf('checkout'), noTier); // no tier
  await answer(digestOf('reports'), 'fail'); // read failed
  expect(headlineTier()).toBe('P0');
  const labels = headlineLabels();
  expect(labels).toContain('2 unknown');
  expect(labels).toContain('read failed');
});
