// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { CoverageBanner, NotAssessableState, ProvenanceChips } from './NodeCatalogParts';
import type { CatalogCoverage, NodeCatalogState, Report } from '../../types/vulns';
import { notAssessable } from '../../utils/nodeCatalog';

afterEach(cleanup);

const nc = (over: Partial<NodeCatalogState> = {}): NodeCatalogState => ({ state: 'done', reason: null, platform: 'linux/arm64', completeness: 'full', catalogedAt: '2026-09-30T10:00:00Z', ...over });
const report = (source: string, sbomTrust: Report['sbomTrust']) => ({ source, sbomTrust }) as Report;

describe('ProvenanceChips', () => {
  test('one chip per source; the node one names its platform', () => {
    render(<ProvenanceChips sources={['node', 'trivy-operator']} nodeCatalog={nc()} />);
    const chips = screen.getAllByTestId('provenance-chip');
    expect(chips.map((c) => [c.getAttribute('data-source'), c.textContent])).toEqual([
      ['node', 'Cataloged on node (linux/arm64)'],
      ['trivy-operator', 'Trivy Operator'],
    ]);
    expect(screen.queryByTestId('provenance-completeness')).toBeNull();
  });

  test('partial and OS-only completeness are shown next to the node chip', () => {
    const { rerender } = render(<ProvenanceChips sources={['node']} nodeCatalog={nc({ completeness: 'partial' })} />);
    expect(screen.getByTestId('provenance-completeness').textContent).toBe('partial');
    rerender(<ProvenanceChips sources={['node']} nodeCatalog={nc({ completeness: 'os_only' })} />);
    expect(screen.getByTestId('provenance-completeness').textContent).toBe('OS packages only');
  });

  test('trust shows only from a read report, never inferred; the node scan is named as such', () => {
    const { container, rerender } = render(<ProvenanceChips sources={['node', 'registry']} nodeCatalog={nc()} />);
    expect(container.textContent).not.toMatch(/Scanned in cluster|Unverified/);
    rerender(<ProvenanceChips sources={['node', 'registry']} nodeCatalog={nc()} reports={[report('node', 'scanned'), report('registry', 'attached-unbound')]} />);
    const scanned = screen.getByText('Scanned in cluster');
    expect(scanned.getAttribute('title')).toMatch(/node cataloger/);
    expect(screen.getByText('Attached, unbound')).toBeTruthy();
  });

  test('a node SBOM without nodeCatalog (opened by URL) still says where it came from', () => {
    render(<ProvenanceChips sources={['node']} />);
    expect(screen.getByTestId('provenance-chip').textContent).toBe('Cataloged on node');
  });
});

describe('NotAssessableState', () => {
  test('compact: the chip with the short reason, the sentence in its title', () => {
    render(<NotAssessableState na={notAssessable({ nodeCatalog: nc({ state: 'pending', reason: 'lsm_denied' }) })!} compact />);
    const el = screen.getByTestId('not-assessable');
    expect(el.getAttribute('data-reason')).toBe('lsm_denied');
    expect(within(el).getByText('Not assessable').getAttribute('title')).toMatch(/SELinux or AppArmor denied.*Other nodes may still catalog it/);
    expect(within(el).getByText('LSM denied')).toBeTruthy();
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
  test('the headline, the queue and the reasons', () => {
    render(<CoverageBanner coverage={coverage()} />);
    expect(screen.getByTestId('coverage-headline').textContent).toBe('12 of 20 running images have a trusted SBOM: 8 Trivy, 6 node');
    expect(screen.getByTestId('coverage-queue').textContent).toBe('· 3 pending, 2 failed');
    expect(screen.getByTestId('coverage-reasons').textContent).toBe('Not cataloged, by reason: LSM denied 3, timed out 1');
    expect(screen.queryByTestId('coverage-warning')).toBeNull();
  });

  test('the kill switch and a missing token are said', () => {
    render(<CoverageBanner coverage={coverage({ grantsEnabled: false, tokenConfigured: false })} />);
    expect(screen.getAllByTestId('coverage-warning').map((w) => w.textContent)).toEqual([
      'New node catalog grants are off (the kill switch, nodeCatalog.grants=false).',
      'The Broker has no catalog token, so node SBOMs cannot be stored.',
    ]);
  });

  test('nothing without data, and nothing for a catalog that was never enabled', () => {
    const { container, rerender } = render(<CoverageBanner coverage={null} />);
    expect(container.innerHTML).toBe('');
    rerender(<CoverageBanner coverage={coverage({ tokenConfigured: false, byState: {}, byReason: {}, platforms: {}, node: 0, trusted: 8 })} />);
    expect(container.innerHTML).toBe('');
  });
});
