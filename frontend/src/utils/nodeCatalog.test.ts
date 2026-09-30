import { describe, expect, test } from 'vitest';
import type { CatalogCoverage, NodeCatalogState } from '../types/vulns';
import { CATALOG_REASON, catalogInUse, catalogPending, completenessNote, coverageSummary, nodeSourceLabel, notAssessable, provenanceLabel, reasonCopy, reasonShort } from './nodeCatalog';

const nc = (over: Partial<NodeCatalogState> = {}): NodeCatalogState => ({ state: 'done', reason: null, platform: 'linux/arm64', completeness: 'full', catalogedAt: '2026-09-30T10:00:00Z', ...over });

/** Every reason broker/src/node_catalog.rs accepts or records (claim failures, skips, done reasons). */
const BROKER_REASONS = [
  'timeout', 'oom', 'error',
  'pid_gone', 'drift', 'exited_before_catalog',
  'sandboxed', 'lazy_snapshotter', 'unsupported_rootfs', 'kernel_unsupported', 'lsm_denied', 'caps_unavailable', 'deferred_pressure', 'worker_unavailable', 'no_cataloger',
  'retry_cap',
  'no_packages_found', 'superseded',
];

describe('reason copy', () => {
  test('every Broker claim reason has a short label and a sentence', () => {
    for (const r of BROKER_REASONS) {
      expect(Object.hasOwn(CATALOG_REASON, r), r).toBe(true);
      expect(reasonShort(r)).not.toBe(r);
      expect(reasonCopy(r)).toMatch(/\.$/);
    }
    expect(Object.keys(CATALOG_REASON).sort()).toEqual([...BROKER_REASONS].sort());
  });

  test('an unrecognised reason is shown as sent, never dropped; prototype keys are not reasons', () => {
    expect(reasonShort('new_reason')).toBe('new_reason');
    expect(reasonCopy('new_reason')).toBe('The node catalog reported new_reason.');
    expect(reasonShort('constructor')).toBe('constructor');
  });

  test('no_packages_found never reads as clean', () => {
    expect(reasonCopy('no_packages_found')).toMatch(/cannot be assessed/);
    expect(reasonCopy('no_packages_found')).toMatch(/not the same as no CVEs/);
  });
});

describe('provenance labels', () => {
  test('the node source names the platform it was cataloged for', () => {
    expect(nodeSourceLabel(nc())).toBe('Cataloged on node (linux/arm64)');
    expect(nodeSourceLabel(nc({ platform: null }))).toBe('Cataloged on node');
    expect(nodeSourceLabel(undefined)).toBe('Cataloged on node');
    expect(provenanceLabel('node', nc({ platform: 'linux/amd64' }))).toBe('Cataloged on node (linux/amd64)');
    expect(provenanceLabel('trivy-operator')).toBe('Trivy Operator');
    expect(provenanceLabel('registry')).toBe('Registry SBOM');
  });

  test('completeness is shown only when partial or OS-only', () => {
    expect(completenessNote(nc())).toBeNull();
    expect(completenessNote(nc({ completeness: null }))).toBeNull();
    expect(completenessNote(nc({ completeness: 'partial' }))?.label).toBe('partial');
    expect(completenessNote(nc({ completeness: 'os_only' }))?.label).toBe('OS packages only');
  });
});

describe('not assessable', () => {
  test('no packages found on a done claim, with no SBOM from any source: terminal', () => {
    const na = notAssessable({ nodeCatalog: nc({ reason: 'no_packages_found', completeness: null }) });
    expect(na).toMatchObject({ reason: 'no_packages_found', terminal: true, retry: null });
  });

  test('a failed scan backs off; a per-node skip leaves other nodes to try', () => {
    expect(notAssessable({ nodeCatalog: nc({ state: 'failed', reason: 'oom' }) })).toMatchObject({ reason: 'oom', terminal: false, retry: 'Retried after a back-off.' });
    expect(notAssessable({ nodeCatalog: nc({ state: 'failed', reason: null }) })?.reason).toBe('error');
    for (const r of ['lsm_denied', 'sandboxed', 'kernel_unsupported', 'lazy_snapshotter', 'unsupported_rootfs', 'caps_unavailable', 'worker_unavailable', 'no_cataloger', 'deferred_pressure', 'retry_cap']) {
      expect(notAssessable({ nodeCatalog: nc({ state: 'pending', reason: r }) })?.retry, r).toMatch(/Other nodes may still catalog it/);
    }
  });

  test('never when any source holds an SBOM, while still being cataloged, or without node catalog data', () => {
    expect(notAssessable({ sbomSources: ['trivy-operator'], nodeCatalog: nc({ state: 'failed', reason: 'timeout' }) })).toBeNull();
    expect(notAssessable({ sbomSources: ['registry'], nodeCatalog: nc({ reason: 'no_packages_found' }) })).toBeNull();
    expect(notAssessable({ nodeCatalog: nc({ state: 'pending', reason: null }) })).toBeNull();
    expect(notAssessable({ nodeCatalog: nc({ state: 'pending', reason: 'pid_gone' }) })).toBeNull();
    expect(notAssessable({ nodeCatalog: nc({ state: 'claimed', reason: null }) })).toBeNull();
    expect(notAssessable({ sbomSources: ['node'], nodeCatalog: nc() })).toBeNull();
    // An older Broker: neither field.
    expect(notAssessable({})).toBeNull();
  });
});

describe('catalog pending', () => {
  test('pending and claimed rows without a node SBOM, with the last retry reason', () => {
    expect(catalogPending({ nodeCatalog: nc({ state: 'claimed' }) })?.label).toBe('Node catalog: cataloging');
    expect(catalogPending({ nodeCatalog: nc({ state: 'pending', reason: null }) })?.label).toBe('Node catalog: pending');
    expect(catalogPending({ nodeCatalog: nc({ state: 'pending', reason: 'drift' }) })?.title).toMatch(/changed its packages/);
  });

  test('nothing once the node SBOM exists, when not assessable, or without data', () => {
    expect(catalogPending({ sbomSources: ['node'], nodeCatalog: nc({ state: 'pending' }) })).toBeNull();
    expect(catalogPending({ nodeCatalog: nc({ state: 'pending', reason: 'lsm_denied' }) })).toBeNull();
    expect(catalogPending({ nodeCatalog: nc() })).toBeNull();
    expect(catalogPending({})).toBeNull();
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
  byCompleteness: { full: 7, partial: 1, os_only: 1 },
  byReason: { timeout: 1, lsm_denied: 3, oom: 1 },
  platforms: { 'linux/amd64': 3, 'linux/arm64': 2 },
  ...over,
});

describe('coverage summary', () => {
  test('"N of M running images have a trusted SBOM: T Trivy, K node; P pending, F failed by reason"', () => {
    const s = coverageSummary(coverage());
    expect(s.headline).toBe('12 of 20 running images have a trusted SBOM: 8 Trivy, 6 node');
    expect(s.queue).toBe('3 pending, 2 failed');
    expect(s.reasons.map((r) => `${r.label} ${r.count}`)).toEqual(['LSM denied 3', 'out of memory 1', 'timed out 1']);
    expect(s.warnings).toEqual([]);
  });

  test('singular, empty queue, and the operator warnings', () => {
    const s = coverageSummary(coverage({ runningImages: 1, trusted: 1, trivy: 1, node: 0, byState: { done: 1 }, byReason: {}, grantsEnabled: false, tokenConfigured: false }));
    expect(s.headline).toBe('1 of 1 running image has a trusted SBOM: 1 Trivy, 0 node');
    expect(s.queue).toBeNull();
    expect(s.reasons).toEqual([]);
    expect(s.warnings).toHaveLength(2);
    expect(s.warnings[0]).toMatch(/nodeCatalog\.grants=false/);
    expect(s.warnings[1]).toMatch(/no catalog token/);
  });

  test('a catalog never enabled (no token, no claims, no node offered) is not in use', () => {
    expect(catalogInUse(coverage())).toBe(true);
    expect(catalogInUse(coverage({ tokenConfigured: false, byState: {}, platforms: {} }))).toBe(false);
    expect(catalogInUse(coverage({ tokenConfigured: false, byState: { pending: 1 }, platforms: {} }))).toBe(true);
    expect(catalogInUse(coverage({ tokenConfigured: false, byState: {}, platforms: { 'linux/amd64': 1 } }))).toBe(true);
  });
});
