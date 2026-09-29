// @vitest-environment jsdom
import { describe, expect, test } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { imageDetail, imageSbom, imageVulns, replayVulnApi, vulnCapture } from '../fixtures/vulns';
import type { RunningSignaturePage } from '../types/attestations';
import { signaturesByWorkload } from '../utils/signatures';
import { workloadKey } from '../utils/workloads';
import { listNamespacePayments } from '../fixtures/profile';
import type { MapLens, PodInfo, PodNodeData } from '../types';
import type { ImageVulnsPage } from '../types/vulns';
import { badgesByNode, coverageBadge, imagesByWorkload, sbomBadge, supplyBadge, useMapLens, vulnBadge, type ImageFacts } from './useMapLens';
import { VulnApiError } from '../services/vulnApi';
import type { ProfileApi } from '../services/profileApi';
import type { WorkloadListItem } from '../types/profile';

// Inputs are Broker responses: captures from a Broker at main
// (fixtures/vuln-captures) and, for an older Broker, from #1671
// (fixtures/vuln-captures-1671). Only the map nodes are written here.

const IMAGES = ['checkout', 'grafana', 'ledger', 'node-exporter', 'prometheus', 'reports', 'source-controller'];

/** What the lens reads per image: `tier=P0,P1` findings on a Broker with tiers. */
function facts(tiered: boolean): ImageFacts[] {
  return IMAGES.map((n) => {
    // Current Broker: its real `tier=P0,P1` read. Older Broker (#1671): findings without tiers.
    const v = tiered ? vulnCapture<ImageVulnsPage>(`image-${n}-vulnerabilities-p0p1`).body : imageVulns(n, '1671');
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

  test('SBOM read failed (a 503): the SBOM part says "read failed", not "no SBOM"', () => {
    const b = sbomBadge(failed('sbomFailed').get('flux-system/Deployment/source-controller'));
    expect(b).toMatchObject({ tone: 'unknown', text: 'read failed' });
    expect(supplyBadge(failed('sbomFailed').get('flux-system/Deployment/source-controller')).label).toMatch(/SBOM: Unknown: the SBOM read failed/);
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
  test('SBOM part: verified SBOM is its only good state; attached-unbound is neutral; none is unknown', () => {
    expect(sbomBadge(imgs.get('flux-system/Deployment/source-controller')).tone).toBe('good');
    expect(sbomBadge(imgs.get('observability/Deployment/grafana')).tone).toBe('neutral');
    expect(sbomBadge(undefined).tone).toBe('unknown');
  });

  test('no signature row: "not checked", unknown, never the SBOM state in its place (not even a verified SBOM)', () => {
    for (const v of imgs.values()) expect(supplyBadge(v)).toMatchObject({ tone: 'unknown', text: 'not checked' });
    expect(supplyBadge(imgs.get('flux-system/Deployment/source-controller')).label).toMatch(/not checked, not unsigned.*SBOM: Every running image has an SBOM from a verified attestation/);
    expect(supplyBadge(undefined)).toMatchObject({ tone: 'unknown', text: 'not checked' });
  });

  test('the signature read failed: "read failed" on every card; a Broker without the route: "not checked"', () => {
    for (const v of imgs.values()) expect(supplyBadge(v, undefined, 'failed')).toMatchObject({ tone: 'unknown', text: 'read failed' });
    expect(supplyBadge(imgs.get('flux-system/Deployment/source-controller'), undefined, 'failed').label).toMatch(/^Signatures: the read failed, unknown\..*SBOM: /);
    expect(supplyBadge(imgs.get('flux-system/Deployment/source-controller'), undefined, 'unsupported')).toMatchObject({ tone: 'unknown', text: 'not checked' });
    expect(supplyBadge(imgs.get('flux-system/Deployment/source-controller'), undefined, 'unsupported').label).toMatch(/does not serve signature results/);
  });

  test('with signature results the badge is the worst verdict; verified is neutral and names its signer', () => {
    const sigs = signaturesByWorkload(vulnCapture<RunningSignaturePage>('attestations-running').body.items, workloadKey);
    const badge = (k: string) => supplyBadge(imgs.get(k), sigs.get(k));
    expect(badge('payments/Deployment/checkout')).toMatchObject({ tone: 'neutral', text: 'signed' });
    expect(badge('payments/Deployment/checkout').label).toMatch(/not vetted.*SBOM: /);
    expect(badge('payments/Deployment/ledger')).toMatchObject({ tone: 'neutral', text: 'signed' });
    // The signer is in the label (tooltip and accessible name), in full.
    expect(badge('payments/Deployment/ledger').label).toMatch(/Signed by key payments-release \(sha256:d4d97426189e…\)/);
    expect(badge('payments/Deployment/checkout').label).toMatch(/Signed by https:\/\/github\.com\/example-org\/checkout\/.*release\.yaml@refs\/tags\/v4\.2\.0 via https:\/\/token\.actions\.githubusercontent\.com/);
    expect(badge('payments/CronJob/reports')).toMatchObject({ tone: 'warn', text: 'unsigned' });
    expect(badge('observability/StatefulSet/prometheus')).toMatchObject({ tone: 'risk', text: 'sig invalid' });
    expect(badge('observability/Deployment/grafana')).toMatchObject({ tone: 'unknown', text: 'key-signed' });
    expect(badge('observability/DaemonSet/node-exporter')).toMatchObject({ tone: 'unknown', text: 'sig unknown' });
    expect(badge('ingress-nginx/Deployment/ingress-nginx-controller')).toMatchObject({ tone: 'unknown', text: 'not checked' });
    for (const k of sigs.keys()) expect(badge(k).tone).not.toBe('good');
  });
});

describe('Supply chain lens, read through the replayed Broker', () => {
  test('payments: signature badges per workload from one running-feed read', async () => {
    const { api, calls } = replayVulnApi();
    const { result } = renderHook(() => useMapLens('payments', 'supply', 0, { vulnApi: api }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    const b = result.current.byWorkload;
    expect(b.get('payments/Deployment/checkout')).toMatchObject({ tone: 'neutral', text: 'signed' });
    expect(b.get('payments/CronJob/reports')).toMatchObject({ tone: 'warn', text: 'unsigned' });
    expect(calls.filter((c) => c.startsWith('GET /attestations/running'))).toEqual(['GET /attestations/running?limit=200&namespace=payments']);
    expect(result.current.readFailures).toBe(0);
  });

  test('the signature read fails: every card says "read failed" (unknown), and the failure is counted', async () => {
    const { api } = replayVulnApi();
    const orig = api.listRunningSignatures.bind(api);
    api.listRunningSignatures = async () => {
      throw new Error('boom');
    };
    const { result } = renderHook(() => useMapLens('payments', 'supply', 0, { vulnApi: api }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.byWorkload.size).toBeGreaterThan(0);
    for (const badge of result.current.byWorkload.values()) {
      expect(badge).toMatchObject({ tone: 'unknown', text: 'read failed' });
      expect(badge.label).toMatch(/Signatures: the read failed, unknown/);
    }
    expect(result.current.readFailures).toBe(1);
    api.listRunningSignatures = orig;
  });

  test('a Broker without the signature route (404): "not checked" with why, not a read failure', async () => {
    const { api } = replayVulnApi();
    api.listRunningSignatures = async () => {
      throw new VulnApiError(404, 'unsupported', 'no route');
    };
    const { result } = renderHook(() => useMapLens('payments', 'supply', 0, { vulnApi: api }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    for (const badge of result.current.byWorkload.values()) expect(badge).toMatchObject({ tone: 'unknown', text: 'not checked' });
    expect(result.current.readFailures).toBe(0);
  });
});

describe('Coverage lens', () => {
  const checkout = listNamespacePayments.body.items.find((w) => w.name === 'checkout')!;
  // Broker 1.20+: a workload whose every snapshot attempt failed is listed without posture or dimensions.
  const failed: WorkloadListItem = {
    clusterId: checkout.clusterId, namespace: 'payments', kind: 'Deployment', name: 'reports',
    revision: null, contentHash: null, computedAt: null, lastChangedAt: null,
    lastError: 'canceling statement due to statement timeout', failedAt: '2026-09-29T02:11:03.123456Z',
  };

  test('from the workload profile list; no profile is unknown', () => {
    expect(coverageBadge(checkout).text).toBe(`${Math.round(checkout.posture!.coverage * 100)}% seen`);
    expect(coverageBadge(undefined).tone).toBe('unknown');
  });

  test('a workload whose snapshots all failed is "profile failed" with the error, never a coverage number', () => {
    const b = coverageBadge(failed);
    expect(b).toMatchObject({ tone: 'unknown', text: 'profile failed' });
    expect(b.label).toMatch(/snapshot for this workload failed: canceling statement due to statement timeout/);
    expect(b.label).not.toMatch(/%/);
  });

  test('one failed workload in the page does not put the lens into its error state; the others keep their badges', async () => {
    const profileApi = { listWorkloads: async () => ({ items: [checkout, failed], nextAfter: null }) } as unknown as ProfileApi;
    const vulnApi = replayVulnApi().api;
    const { result } = renderHook(() => useMapLens('payments', 'coverage', 0, { vulnApi, profileApi }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBeNull();
    expect(result.current.byWorkload.get('payments/Deployment/checkout')?.text).toBe(`${Math.round(checkout.posture!.coverage * 100)}% seen`);
    expect(result.current.byWorkload.get('payments/Deployment/reports')).toMatchObject({ tone: 'unknown', text: 'profile failed' });
  });
});

// App shows "Reading…" only while the badge map is empty. Carrying the
// previous lens's (or namespace's) badges into a new read drew vulnerability
// chips as Coverage badges, or every card's definitive fallback, until the
// slow read landed.
describe('switching lens or namespace never shows the previous badges as current', () => {
  const never = { listWorkloads: () => new Promise(() => {}) } as unknown as ProfileApi;
  const checkout = listNamespacePayments.body.items.find((w) => w.name === 'checkout')!;

  test('vulns -> coverage: no vulnerability badges while coverage loads', async () => {
    const { api } = replayVulnApi();
    const { result, rerender } = renderHook(({ lens }: { lens: MapLens }) => useMapLens('payments', lens, 0, { vulnApi: api, profileApi: never }), { initialProps: { lens: 'vulns' as MapLens } });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.byWorkload.size).toBeGreaterThan(0);
    rerender({ lens: 'coverage' });
    await waitFor(() => expect(result.current.loading).toBe(true));
    expect(result.current.byWorkload.size).toBe(0);
  });

  test('a namespace switch drops the previous namespace\'s badges', async () => {
    let calls = 0;
    const profileApi = {
      listWorkloads: () => (++calls === 1 ? Promise.resolve({ items: [checkout], nextAfter: null }) : new Promise(() => {})),
    } as unknown as ProfileApi;
    const vulnApi = replayVulnApi().api;
    const { result, rerender } = renderHook(({ ns }: { ns: string }) => useMapLens(ns, 'coverage', 0, { vulnApi, profileApi }), { initialProps: { ns: 'payments' } });
    await waitFor(() => expect(result.current.byWorkload.size).toBe(1));
    rerender({ ns: 'other' });
    await waitFor(() => expect(result.current.loading).toBe(true));
    expect(result.current.byWorkload.size).toBe(0);
  });

  test('a refresh of the same lens and namespace keeps its badges while it reloads', async () => {
    let calls = 0;
    const profileApi = {
      listWorkloads: () => (++calls === 1 ? Promise.resolve({ items: [checkout], nextAfter: null }) : new Promise(() => {})),
    } as unknown as ProfileApi;
    const vulnApi = replayVulnApi().api;
    const { result, rerender } = renderHook(({ tick }: { tick: number }) => useMapLens('payments', 'coverage', tick, { vulnApi, profileApi }), { initialProps: { tick: 0 } });
    await waitFor(() => expect(result.current.byWorkload.size).toBe(1));
    rerender({ tick: 1 });
    await waitFor(() => expect(result.current.loading).toBe(true));
    expect(result.current.byWorkload.size).toBe(1);
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
