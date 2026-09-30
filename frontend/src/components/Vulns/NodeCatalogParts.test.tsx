// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { CatalogPendingChip, CoverageBanner, NotAssessableState, ProvenanceChips } from './NodeCatalogParts';
import type { CatalogCoverage, NodeCatalogState, Report } from '../../types/vulns';
import { catalogPending, notAssessable } from '../../utils/nodeCatalog';

afterEach(cleanup);

const nc = (over: Partial<NodeCatalogState> = {}): NodeCatalogState => ({ state: 'done', reason: null, platform: 'linux/arm64', completeness: 'full', catalogedAt: '2026-09-30T10:00:00Z', ...over });
const report = (source: string, sbomTrust: Report['sbomTrust']) => ({ source, sbomTrust }) as Report;

describe('ProvenanceChips', () => {
  test('one chip per source, by trust rank; the node one names its platform', () => {
    render(<ProvenanceChips sources={['registry', 'node', 'trivy-operator']} nodeCatalog={nc()} />);
    const chips = screen.getAllByTestId('provenance-chip');
    expect(chips.map((c) => [c.getAttribute('data-source'), c.textContent])).toEqual([
      ['trivy-operator', 'Trivy Operator'],
      ['node', 'Cataloged on node (linux/arm64)'],
      ['registry', 'Registry SBOM'],
    ]);
    expect(screen.queryByTestId('provenance-completeness')).toBeNull();
  });

  test('partial and OS-only completeness are shown next to the node chip', () => {
    const { rerender } = render(<ProvenanceChips sources={['node']} nodeCatalog={nc({ completeness: 'partial' })} />);
    expect(screen.getByTestId('provenance-completeness').textContent).toBe('partial');
    rerender(<ProvenanceChips sources={['node']} nodeCatalog={nc({ completeness: 'os_only' })} />);
    expect(screen.getByTestId('provenance-completeness').textContent).toBe('OS packages only');
  });

  test('Trivy Operator and node are always scanned; a registry SBOM shows trust only from its read report', () => {
    const { container, rerender } = render(<ProvenanceChips sources={['node', 'registry']} nodeCatalog={nc()} />);
    expect(screen.getByText('Scanned in cluster').getAttribute('title')).toMatch(/node cataloger/);
    expect(container.textContent).not.toMatch(/Attached|Unverified|Trust not stated/);
    rerender(<ProvenanceChips sources={['node', 'registry']} nodeCatalog={nc()} reports={[report('registry', 'attached-unbound')]} />);
    expect(screen.getByText('Attached, unbound')).toBeTruthy();
  });

  test('a node SBOM without nodeCatalog (opened by URL) still says where it came from', () => {
    render(<ProvenanceChips sources={['node']} />);
    expect(screen.getByTestId('provenance-chip').textContent).toBe('Cataloged on node');
  });
});

describe('CatalogPendingChip', () => {
  test('a pending row with a per-node reason is pending, naming the last node, never not assessable', () => {
    render(<CatalogPendingChip {...catalogPending({ nodeCatalog: nc({ state: 'pending', reason: 'lsm_denied', completeness: null }) })!} />);
    const chip = screen.getByTestId('catalog-pending');
    expect(chip.textContent).toBe('Node catalog: pending · last node: LSM denied');
    expect(chip.getAttribute('title')).toMatch(/other nodes may still catalog it/);
  });
});

describe('NotAssessableState', () => {
  test('compact: the chip with the short reason, the sentence in its title and as screen-reader text', () => {
    render(<NotAssessableState na={notAssessable({ nodeCatalog: nc({ state: 'failed', reason: 'oom' }) })!} compact />);
    const el = screen.getByTestId('not-assessable');
    expect(el.getAttribute('data-reason')).toBe('oom');
    expect(within(el).getByText('Not assessable').getAttribute('title')).toMatch(/ran out of memory.*Retried after a back-off\.$/);
    expect(within(el).getByText('out of memory')).toBeTruthy();
    expect(el.querySelector('.sr-only')!.textContent).toMatch(/ran out of memory/);
    expect(el.textContent).not.toMatch(/0 CVE|No vulnerabilities|clean/i);
  });

  test('block: the sentence and when it is retried', () => {
    render(<NotAssessableState na={notAssessable({ nodeCatalog: nc({ state: 'done', reason: 'no_packages_found' }) })!} />);
    const el = screen.getByTestId('not-assessable');
    expect(el.textContent).toMatch(/^Not assessable: no packages found/);
    expect(el.textContent).toMatch(/not the same as no CVEs/);
    expect(el.textContent).not.toMatch(/Retried/);
  });
});

const coverage = (over: Partial<CatalogCoverage> = {}): CatalogCoverage => ({
  grantsEnabled: true,
  tokenConfigured: true,
  runningImages: 20,
  trivy: 8,
  node: 6,
  trusted: 12,
  coverageRatio: 0.6,
  byState: { pending: 2, claimed: 1, done: 9, failed: 2 },
  byCompleteness: { full: 9 },
  byReason: { lsm_denied: 3, timeout: 1 },
  platforms: { 'linux/arm64': 2 },
  ...over,
});

describe('CoverageBanner', () => {
  test('the headline, labelled cluster-wide, the queue and the reasons; a plain region, not a live one', () => {
    render(<CoverageBanner coverage={coverage()} />);
    const banner = screen.getByTestId('coverage-banner');
    expect(screen.getByTestId('coverage-scope').textContent).toBe('Cluster-wide:');
    expect(banner.getAttribute('role')).toBeNull();
    expect(banner.getAttribute('aria-live')).toBeNull();
    expect(screen.getByRole('region', { name: 'Node catalog coverage' })).toBe(banner);
    expect(screen.getByTestId('coverage-headline').textContent).toBe('12 of 20 running images have a trusted SBOM: 8 Trivy, 6 node');
    expect(screen.getByTestId('coverage-queue').textContent).toBe('· 3 pending, 2 failed');
    expect(screen.getByTestId('coverage-reasons').textContent).toBe('Not cataloged, by reason: LSM denied 3, timed out 1');
    expect(screen.queryByTestId('coverage-warning')).toBeNull();
  });

  test('the kill switch is said', () => {
    render(<CoverageBanner coverage={coverage({ grantsEnabled: false })} />);
    expect(screen.getAllByTestId('coverage-warning').map((w) => w.textContent)).toEqual([
      'New node catalog grants are off (the kill switch, nodeCatalog.grants=false).',
    ]);
  });

  test('a 200 with no catalog token stays hidden, even with rows left from when it was enabled', () => {
    const { container } = render(<CoverageBanner coverage={coverage({ tokenConfigured: false })} />);
    expect(container.innerHTML).toBe('');
  });

  test('nothing without data, and nothing for a catalog that was never enabled', () => {
    const { container, rerender } = render(<CoverageBanner coverage={null} />);
    expect(container.innerHTML).toBe('');
    rerender(<CoverageBanner coverage={coverage({ tokenConfigured: false, byState: {}, byReason: {}, platforms: {}, node: 0, trusted: 8 })} />);
    expect(container.innerHTML).toBe('');
  });
});
