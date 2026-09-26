import { describe, expect, test } from 'vitest';
import { cvePage, exposureOf, imageDetail, imageSbom, imageVulns } from '../fixtures/vulns';
import { listNamespacePayments } from '../fixtures/profile';
import type { PodInfo, PodNodeData } from '../types';
import {
  badgesByNode,
  coverageBadge,
  hotCvesByWorkload,
  imagesByWorkload,
  lensCandidate,
  supplyBadge,
  vulnBadge,
  type ImageFacts,
} from './useMapLens';

// Every input here is a raw Broker capture (fixtures/vuln-captures,
// fixtures/captures); nothing is hand-written except the map nodes.

const IMAGES = ['checkout', 'grafana', 'ledger', 'node-exporter', 'prometheus', 'reports', 'source-controller'];
const facts: ImageFacts[] = IMAGES.map((n) => ({
  digest: imageDetail(n).digest,
  workloads: imageDetail(n).workloads,
  vulnReports: imageVulns(n).reports,
  sbomReports: imageSbom(n).reports,
}));
const exposures = cvePage.items.filter(lensCandidate).map((summary) => ({ summary, exposure: exposureOf(summary.id) }));
const hot = hotCvesByWorkload(exposures);
const imgs = imagesByWorkload(facts);

describe('Vulnerabilities lens', () => {
  test('the KEV CVE with public ingress makes checkout P0; ledger (no outside ingress) stays P1', () => {
    expect(hot.get('payments/Deployment/checkout')?.tier).toBe('P0');
    expect(hot.get('payments/Deployment/checkout')?.ids).toContain('CVE-2099-0001');
    expect(hot.get('payments/Deployment/ledger')?.tier).toBe('P1');
  });

  test('a workload that is not running gets no tier from its images', () => {
    expect(hot.has('payments/CronJob/reports')).toBe(false);
  });

  test('no vulnerability report is unknown, never clean', () => {
    const b = vulnBadge(hot.get('observability/DaemonSet/node-exporter'), imgs.get('observability/DaemonSet/node-exporter'), true);
    expect(b.tone).toBe('unknown');
    expect(b.text).toBe('no data');
  });

  test('scanned with zero findings reads "no P0/P1", neutral, and says lower tiers may exist', () => {
    const b = vulnBadge(hot.get('flux-system/Deployment/source-controller'), imgs.get('flux-system/Deployment/source-controller'), true);
    expect(b.tone).toBe('neutral');
    expect(b.text).toBe('no P0/P1');
    const capped = vulnBadge(undefined, imgs.get('flux-system/Deployment/source-controller'), false);
    expect(capped.label).toMatch(/not assessed/);
  });

  test('no vulnerabilities-lens badge is ever drawn in the good tone or claims safety', () => {
    for (const k of new Set([...hot.keys(), ...imgs.keys()])) {
      const b = vulnBadge(hot.get(k), imgs.get(k), true);
      expect(b.tone).not.toBe('good');
      expect(`${b.text} ${b.label}`.toLowerCase().replace('not clean', '')).not.toMatch(/safe|clean|secure/);
    }
  });
});

describe('Supply chain lens', () => {
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
    const b = coverageBadge(checkout);
    expect(b.text).toBe(`${Math.round(checkout.posture.coverage * 100)}% seen`);
    expect(coverageBadge(undefined).tone).toBe('unknown');
  });
});

describe('badgesByNode', () => {
  const pod = (ns: string, kind: string, name: string): PodInfo => ({ pod_name: `${name}-abc`, pod_namespace: ns, workload_kind: kind, workload_name: name } as PodInfo);
  const node = (id: string, p: PodInfo, isExternal = false): PodNodeData => ({ id, label: id, pod: p, pods: [p], isExternal } as PodNodeData);

  test('matches by workload; an in-cluster card with no data gets the lens unknown badge; externals get none', () => {
    const byWorkload = new Map([['payments/Deployment/checkout', vulnBadge(hot.get('payments/Deployment/checkout'), imgs.get('payments/Deployment/checkout'), true)]]);
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
