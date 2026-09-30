import { expect, test } from 'vitest';
import { brokerFactors, brokerTier, exposureFactor, factChips, inUseFactor, mergeFactors, privilegedFactor, tierRank } from './tiers';
import { vulnCapture, VULN_CAPTURES } from '../fixtures/vulns';
import type { ImageVulnsPage } from '../types/vulns';
import { findingFactors } from './vulnView';
import * as tiers from './tiers';

test('the UI has no tier computation of its own', () => {
  expect(Object.keys(tiers)).not.toContain('computeTier');
  expect(Object.keys(tiers)).not.toContain('EPSS_P0_THRESHOLD');
});

test('brokerTier: only the four tiers; anything else (an older Broker sends none) is unknown', () => {
  expect(brokerTier('P0')).toBe('P0');
  expect(brokerTier('Background')).toBe('Background');
  expect(brokerTier(undefined)).toBeNull();
  expect(brokerTier('P9')).toBeNull();
});

test("tierRank is the Broker's tier order: P0, unknown, P1, P2, Background", () => {
  const tiers = ['Background', 'P1', null, 'P2', 'P0'] as const;
  expect([...tiers].sort((a, b) => tierRank(b) - tierRank(a))).toEqual(['P0', null, 'P1', 'P2', 'Background']);
  // Unknown never reads as better than a known P1, and nothing outranks P0.
  expect(tierRank(null)).toBeGreaterThan(tierRank('P1'));
  expect(tierRank('P0')).toBeGreaterThan(tierRank(null));
});

test("every #1678 factor maps to a chip; an unrecognised one is shown as sent", () => {
  const f = brokerFactors(['in_use:loaded', 'kev', 'epss>=0.1', 'severity:critical', 'exposed', 'no_fix', 'something_new']);
  expect(f.map((x) => [x.key, x.label])).toEqual([
    ['inuse', 'Loaded'],
    ['kev', 'KEV'],
    ['epss', 'EPSS ≥ 10%'],
    ['severity', 'critical'],
    ['exposure', 'Exposed'],
    ['fix', 'No fix yet'],
    ['something_new', 'something_new'],
  ]);
  expect(brokerFactors(['internal'])[0].label).toBe('No outside ingress seen');
  expect(brokerFactors(['exposure:unknown'])[0].tone).toBe('unknown');
});

test('in-use states: unknown and not-observed never read as safe', () => {
  expect(inUseFactor('executed').tone).toBe('risk');
  expect(inUseFactor('unknown', { state: 'unknown', reason: 'language_package', observedSince: null, windowHours: 24, containers: 1, coverage: 'interpreted' }).title).toMatch(/interpreted-language/);
  expect(inUseFactor(undefined).label).toBe('Loaded: unknown');
  const bg = inUseFactor('installed_not_observed');
  expect(bg.tone).toBe('neutral');
  expect(bg.title).toMatch(/Not proof/);
});

test('facts carry no threshold judgement: EPSS is only a risk when the Broker says so', () => {
  expect(factChips({ epss: 0.34 })[0].tone).toBe('neutral');
  const merged = mergeFactors(brokerFactors(['epss>=0.1']), factChips({ epss: 0.34 }));
  expect(merged).toHaveLength(1);
  expect(merged[0]).toMatchObject({ key: 'epss', label: 'EPSS 34%', tone: 'risk' });
});

test('EPSS labels never round across a line that matters: not to 100%, not to 0%, and thresholds keep their decimals', () => {
  const epss = (v: number) => factChips({ epss: v })[0].label;
  expect(epss(0.34)).toBe('EPSS 34%');
  expect(epss(0.0123)).toBe('EPSS 1%');
  expect(epss(0.0042)).toBe('EPSS 0.4%');
  // Near the top: never "100%" for what is not certain.
  expect(epss(0.995)).toBe('EPSS 99.5%');
  expect(epss(0.99999)).toBe('EPSS 99.9%');
  expect(epss(1)).toBe('EPSS 100%');
  // Near the bottom: small, not zero.
  expect(epss(0.0004)).toBe('EPSS <0.1%');
  expect(epss(0)).toBe('EPSS 0%');
  const threshold = (raw: string) => brokerFactors([raw])[0].label;
  expect(threshold('epss>=0.1')).toBe('EPSS ≥ 10%');
  expect(threshold('epss>=0.005')).toBe('EPSS ≥ 0.5%');
  expect(threshold('epss>=0.07')).toBe('EPSS ≥ 7%');
  expect(threshold('epss>=0.0001')).toBe('EPSS ≥ 0.01%');
});

test('several fixed versions are all shown, none picked', () => {
  expect(factChips({ fixable: true, fixedVersions: ['4.20.0', '4.19.2'] })[0].label).toBe('Fix: 4.20.0 / 4.19.2');
  expect(factChips({ fixable: false })[0].label).toBe('No fix yet');
});

test('privileged is context from the profile: unknown without one, absent when not assessed', () => {
  expect(privilegedFactor(undefined)).toBeNull();
  expect(privilegedFactor(null)!.label).toBe('Privileged: unknown');
  expect(privilegedFactor({ level: 'privileged', confidence: 'upper_bound' })!.label).toBe('Privileged (at most)');
  expect(privilegedFactor({ level: 'restricted', confidence: 'confirmed' })!.label).toBe('Not privileged');
});

test('the fixtures are real captures and say which Broker they came from', () => {
  expect(VULN_CAPTURES.length).toBeGreaterThan(0);
  for (const c of VULN_CAPTURES) expect(c.provenance).toMatch(/^captured from broker [0-9a-f]{7,}/);
});

test("a finding's chips are the Broker's factors with the facts' labels", () => {
  const checkout = vulnCapture<ImageVulnsPage>('image-checkout-vulnerabilities').body;
  const kev = checkout.items.find((f) => f.id === 'CVE-2099-0001')!;
  expect(kev.tier).toBe('P0');
  // The Broker saw /usr/bin/openssl executed in the checkout container (seeded runtime inventory).
  expect(findingFactors(kev).map((f) => f.label).sort()).toEqual(['CVSS 9.8', 'EPSS 34%', 'Executed', 'Exposed', 'Fix: 3.3.2-r0', 'KEV']);
});

test('in-use states are the Broker\'s: executed, loaded, not observed, and unknown with its reason', () => {
  const items = vulnCapture<ImageVulnsPage>('image-checkout-vulnerabilities').body.items;
  const inuse = (id: string) => findingFactors(items.find((f) => f.id === id)!).find((f) => f.key === 'inuse')!;
  expect(inuse('CVE-2099-0001').label).toBe('Executed'); // openssl
  expect(inuse('CVE-2099-0003').label).toBe('Loaded'); // zlib: libz mapped
  expect(inuse('CVE-2099-0004').label).toBe('Not observed loaded'); // busybox: covered, never run
  // express is an npm package: the kernel cannot see a language package load.
  expect(inuse('CVE-2099-0002').label).toBe('Loaded: unknown');
  expect(inuse('CVE-2099-0002').title).toMatch(/language/i);
});

test('the node catalog and capture-mode unknown reasons each have their own copy; an unrecognised one is shown as sent', () => {
  const why = (reason: string) => inUseFactor('unknown', { state: 'unknown', reason, observedSince: null, windowHours: 24, containers: 1, coverage: 'file' });
  const expected: Record<string, RegExp> = {
    probes_missing: /capture probes are not running/,
    libraries_not_tracked: /exec-only mode/,
    sbom_incomplete: /node SBOM is partial/,
    platform_mismatch: /another platform/,
    interpreted_content: /scripts or data files/,
  };
  for (const [reason, copy] of Object.entries(expected)) {
    const f = why(reason);
    expect(f.label).toBe('Loaded: unknown');
    expect(f.tone).toBe('unknown');
    expect(f.title, reason).toMatch(copy);
    // Unknown stays ranked as if loaded, whatever the reason.
    expect(f.title).toMatch(/Ranked as if loaded\.$/);
  }
  expect(why('some_future_reason').title).toBe('Unknown: some_future_reason. Ranked as if loaded.');
});

test('KEV / EPSS: null is "not reported" (unknown), false and absent are not', () => {
  expect(factChips({ kev: null })[0]).toMatchObject({ key: 'kev', tone: 'unknown', label: 'KEV: not reported' });
  expect(factChips({ kev: false })).toEqual([]);
  expect(factChips({ epss: null })[0]).toMatchObject({ key: 'epss', tone: 'unknown', label: 'EPSS: not reported' });
  expect(factChips({})).toEqual([]);
});

test('captured: a finding no source reported on shows KEV and EPSS as "not reported", a KEV "no" shows nothing', () => {
  const items = vulnCapture<ImageVulnsPage>('image-checkout-vulnerabilities').body.items;
  const zlib = items.find((f) => f.id === 'CVE-2099-0003')!;
  expect([zlib.kev, zlib.epss]).toEqual([null, null]);
  const labels = findingFactors(zlib).map((f) => f.label);
  expect(labels).toContain('KEV: not reported');
  expect(labels).toContain('EPSS: not reported');
  const express = items.find((f) => f.id === 'CVE-2099-0002')!;
  expect(express.kev).toBe(false);
  expect(findingFactors(express).some((f) => f.key === 'kev')).toBe(false);
});

test('IMG-06: ingress from nodes alone is a neutral chip that names kubelet probes, not the red exposed chip, under either Broker shape', () => {
  const node = exposureFactor(true, ['node'])!;
  expect(node.tone).toBe('neutral');
  expect(node.label).toBe('Node ingress only');
  expect(node.title).toMatch(/kubelet liveness and readiness probes/);
  expect(node.title).toMatch(/NodePort/);
  expect(node.title).toMatch(/still counts it as exposed/);
  // Broker #1780 and later: exposed: false with node still listed. Same chip, no "still counts" caveat.
  const later = exposureFactor(false, ['node'])!;
  expect(later).toMatchObject({ tone: 'neutral', label: 'Node ingress only' });
  expect(later.title).not.toMatch(/still counts/);
  // Anything beyond the node is exposure; so is "exposed" with no source named, since the Broker said so.
  expect(exposureFactor(true, ['node', 'other_namespace'])!.tone).toBe('risk');
  expect(exposureFactor(true, ['public_ip'])!.label).toBe('Exposed: public IP');
  expect(exposureFactor(true, [])!.tone).toBe('risk');
  expect(exposureFactor(false)!.tone).toBe('neutral');
  expect(exposureFactor(null)!.tone).toBe('unknown');
});

test('a Background finding reads "Not observed loaded" (captured: busybox, covered and never run)', () => {
  const busybox = vulnCapture<ImageVulnsPage>('image-checkout-vulnerabilities').body.items.find((f) => f.id === 'CVE-2099-0004')!;
  expect(busybox).toMatchObject({ tier: 'Background', inUseState: 'installed_not_observed', inUse: false });
  expect(findingFactors(busybox).find((f) => f.key === 'inuse')!.label).toBe('Not observed loaded');
});
