import { expect, test } from 'vitest';
import { brokerFactors, brokerTier, factChips, inUseFactor, mergeFactors, privilegedFactor, tierRank } from './tiers';
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
  // Unknown is never ranked below a known tier.
  expect(tierRank(null)).toBeGreaterThan(tierRank('P0'));
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
  // No runtime inventory on main yet: in use is unknown, for a stated reason.
  expect(findingFactors(kev).map((f) => f.label).sort()).toEqual(['CVSS 9.8', 'EPSS 34%', 'Exposed', 'Fix: 3.3.2-r0', 'KEV', 'Loaded: unknown']);
  expect(findingFactors(kev).find((f) => f.key === 'inuse')!.title).toMatch(/no runtime capture/);
});

test('a Background finding reads "Not observed loaded" (not in any capture until the runtime inventory lands)', () => {
  const busybox = vulnCapture<ImageVulnsPage>('image-checkout-vulnerabilities').body.items.find((f) => f.id === 'CVE-2099-0004')!;
  // Test-local: the captured finding as a Broker with runtime data would send it.
  const bg = { ...busybox, tier: 'Background', tierFactors: ['in_use:installed_not_observed', 'severity:low', 'exposed'], inUseState: 'installed_not_observed', inUse: false };
  expect(findingFactors(bg).find((f) => f.key === 'inuse')!.label).toBe('Not observed loaded');
});
