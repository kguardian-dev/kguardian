import { describe, expect, test } from 'vitest';
import { imageDetail, imageSbom, imageVulns, tierFixture } from '../fixtures/vulns';
import { listNamespacePayments } from '../fixtures/profile';
import type { PodInfo, PodNodeData } from '../types';
import type { ImageVulnsPage } from '../types/vulns';
import { badgesByNode, coverageBadge, imagesByWorkload, supplyBadge, vulnBadge, type ImageFacts } from './useMapLens';

// Inputs are Broker responses: #1671 captures (fixtures/vuln-captures) and,
// for tiers, the #1678 contract-derived fixtures (fixtures/vuln-contract-1678).
// Only the map nodes are written here.

const IMAGES = ['checkout', 'grafana', 'ledger', 'node-exporter', 'prometheus', 'reports', 'source-controller'];

/** What the lens reads per image: `tier=P0,P1` findings on a Broker with tiers. */
function facts(tiered: boolean): ImageFacts[] {
  return IMAGES.map((n) => {
    const v = tiered ? tierFixture<ImageVulnsPage>(`image-${n}-vulnerabilities-p0p1`).body : imageVulns(n);
    const hasTier = v.items.length === 0 ? null : v.items.every((f) => f.tier !== undefined);
    return {
      digest: imageDetail(n).digest,
      workloads: imageDetail(n).workloads,
      vulnReports: v.reports,
      sbomReports: imageSbom(n).reports,
      hot: hasTier ? v.items : [],
      tiered: hasTier,
      hotTruncated: false,
    };
  });
}

describe('Vulnerabilities lens: the Broker ranks, the lens only counts', () => {
  const imgs = imagesByWorkload(facts(true));

  test("checkout's KEV finding is the Broker's P0; ledger's is P1", () => {
    const checkout = vulnBadge(imgs.get('payments/Deployment/checkout'));
    expect(checkout.tone).toBe('p0');
    // The count covers P0 and P1 together, so the text says so.
    expect(checkout.text).toBe('P0/P1 · 3');
    expect(checkout.label).toContain('CVE-2099-0001');
    expect(vulnBadge(imgs.get('payments/Deployment/ledger')).tone).toBe('p1');
  });

  test('a workload that is not running gets no badge from its images', () => {
    expect(imgs.has('payments/CronJob/reports')).toBe(false);
  });

  test('no vulnerability report is unknown, never clean', () => {
    const b = vulnBadge(imgs.get('observability/DaemonSet/node-exporter'));
    expect(b.tone).toBe('unknown');
    expect(b.text).toBe('no data');
  });

  test('scanned, nothing the Broker ranks P0/P1: neutral "no P0/P1", lower tiers may exist', () => {
    const b = vulnBadge(imgs.get('flux-system/Deployment/source-controller'));
    expect(b).toMatchObject({ tone: 'neutral', text: 'no P0/P1' });
    expect(b.label).toMatch(/Lower tiers may exist/);
  });

  test('an older Broker (findings without tier) is "tier ?", never a UI-computed tier', () => {
    const old = imagesByWorkload(facts(false));
    // checkout has critical + KEV findings, but no Broker tier: not P0.
    expect(vulnBadge(old.get('payments/Deployment/checkout'))).toMatchObject({ tone: 'unknown', text: 'tier ?' });
  });

  test('no badge is ever drawn in the good tone or claims safety', () => {
    for (const tiered of [true, false]) {
      for (const v of imagesByWorkload(facts(tiered)).values()) {
        const b = vulnBadge(v);
        expect(b.tone).not.toBe('good');
        expect(`${b.text} ${b.label}`.toLowerCase().replace('not clean', '')).not.toMatch(/safe|clean|secure/);
      }
    }
  });
});

describe('a failed read is unknown, never "none"', () => {
  const failed = (field: 'vulnFailed' | 'sbomFailed') =>
    imagesByWorkload(facts(true).map((f) => (f.digest === imageDetail('source-controller').digest ? { ...f, [field]: true, vulnReports: null, sbomReports: null, hot: [] } : f)));

  test('vulnerability read failed: "read failed", not "no data" or "no P0/P1"', () => {
    const b = vulnBadge(failed('vulnFailed').get('flux-system/Deployment/source-controller'));
    expect(b).toMatchObject({ tone: 'unknown', text: 'read failed' });
  });

  test('SBOM read failed (a 503): "read failed", not "no SBOM"', () => {
    const b = supplyBadge(failed('sbomFailed').get('flux-system/Deployment/source-controller'));
    expect(b).toMatchObject({ tone: 'unknown', text: 'read failed' });
  });

  test('a card with no badge of its own is "read failed" / "not read" when reads failed or were capped', () => {
    const pod = { pod_name: 'x-1', pod_namespace: 'payments', workload_kind: 'Deployment', workload_name: 'x' } as PodInfo;
    const nodes = [{ id: 'n', label: 'n', pod, pods: [pod], isExternal: false } as PodNodeData];
    expect(badgesByNode('vulns', new Map(), nodes, { readFailures: 2, truncated: false }).get('n')!.text).toBe('read failed');
    expect(badgesByNode('supply', new Map(), nodes, { readFailures: 0, truncated: true }).get('n')!.text).toBe('not read');
    expect(badgesByNode('vulns', new Map(), nodes).get('n')!.text).toBe('no data');
  });
});

describe('Supply chain lens', () => {
  const imgs = imagesByWorkload(facts(true));
  test('verified SBOM is the only good state; attached-unbound is neutral; none is unknown', () => {
    expect(supplyBadge(imgs.get('flux-system/Deployment/source-controller')).tone).toBe('good');
    expect(supplyBadge(imgs.get('observability/Deployment/grafana')).tone).toBe('neutral');
    expect(supplyBadge(undefined).tone).toBe('unknown');
  });

  test('every badge says signatures are not checked', () => {
    for (const v of imgs.values()) expect(supplyBadge(v).label).toMatch(/Signatures: not checked/);
  });
});

describe('Coverage lens', () => {
  test('from the workload profile list; no profile is unknown', () => {
    const checkout = listNamespacePayments.body.items.find((w) => w.name === 'checkout')!;
    expect(coverageBadge(checkout).text).toBe(`${Math.round(checkout.posture.coverage * 100)}% seen`);
    expect(coverageBadge(undefined).tone).toBe('unknown');
  });
});

describe('badgesByNode', () => {
  const pod = (ns: string, kind: string, name: string): PodInfo => ({ pod_name: `${name}-abc`, pod_namespace: ns, workload_kind: kind, workload_name: name } as PodInfo);
  const node = (id: string, p: PodInfo, isExternal = false): PodNodeData => ({ id, label: id, pod: p, pods: [p], isExternal } as PodNodeData);

  test('matches by workload; an in-cluster card with no data gets the lens unknown badge; externals get none', () => {
    const imgs = imagesByWorkload(facts(true));
    const byWorkload = new Map([['payments/Deployment/checkout', vulnBadge(imgs.get('payments/Deployment/checkout'))]]);
    const out = badgesByNode('vulns', byWorkload, [
      node('a', pod('payments', 'Deployment', 'checkout')),
      node('b', pod('payments', 'Deployment', 'unknown-app')),
      node('c', pod('payments', 'Deployment', 'x'), true),
    ]);
    expect(out.get('a')?.tone).toBe('p0');
    expect(out.get('b')?.tone).toBe('unknown');
    expect(out.has('c')).toBe(false);
  });
});
