import { expect, test } from 'vitest';
import { computeTier, worstTier, type TierInput } from './tiers';

const base: TierInput = { severity: 'LOW', kev: null, epss: null, fixable: true, inUse: null };

test('P0: KEV and exposed, in use unknown (degrades upward)', () => {
  const r = computeTier({ ...base, severity: 'CRITICAL', kev: true, exposed: true, exposedVia: ['public_ip'] });
  expect(r.tier).toBe('P0');
  expect(r.factors.map((f) => f.label)).toContain('Loaded: unknown');
  expect(r.factors.map((f) => f.label)).toContain('Exposed: public IP');
});

test('P0 also when exposure is unknown or not assessed: only a definite false lowers it', () => {
  expect(computeTier({ ...base, kev: true, exposed: null }).tier).toBe('P0');
  expect(computeTier({ ...base, kev: true }).tier).toBe('P0');
  expect(computeTier({ ...base, epss: 0.34 }).tier).toBe('P0');
  expect(computeTier({ ...base, kev: true, exposed: false }).tier).toBe('P1');
});

test('EPSS below the threshold is not a P0 factor', () => {
  expect(computeTier({ ...base, severity: 'MEDIUM', epss: 0.09 }).tier).toBe('P2');
});

test('P1: critical or high', () => {
  expect(computeTier({ ...base, severity: 'CRITICAL' }).tier).toBe('P1');
  expect(computeTier({ ...base, severity: 'HIGH' }).tier).toBe('P1');
  // High with no fix is still P1 unless no outside ingress was seen.
  expect(computeTier({ ...base, severity: 'HIGH', fixable: false }).tier).toBe('P1');
  expect(computeTier({ ...base, severity: 'HIGH', fixable: false, exposed: null }).tier).toBe('P1');
});

test('P2: medium/low, unknown severity, or high with no fix and no outside ingress seen', () => {
  expect(computeTier({ ...base, severity: 'MEDIUM' }).tier).toBe('P2');
  expect(computeTier({ ...base, severity: 'LOW' }).tier).toBe('P2');
  expect(computeTier({ ...base, severity: 'UNKNOWN' }).tier).toBe('P2');
  expect(computeTier({ ...base, severity: 'HIGH', fixable: false, exposed: false }).tier).toBe('P2');
});

test('Background only from a definite inUse=false; unknown never reaches it', () => {
  expect(computeTier({ ...base, severity: 'CRITICAL', inUse: false }).tier).toBe('Background');
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'] as const) {
    expect(computeTier({ ...base, severity, inUse: null }).tier).not.toBe('Background');
  }
});

test('nothing is ever called safe', () => {
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'] as const) {
    for (const exposed of [true, false, null, undefined]) {
      const r = computeTier({ ...base, severity, exposed });
      // The verdict text (tier reason and chip labels) never claims safety.
      const verdict = `${r.reason} ${r.factors.map((f) => f.label).join(' ')}`.toLowerCase();
      expect(verdict).not.toMatch(/safe|not exploitable|unreachable|clean/);
    }
  }
});

test('fix chips: several fixed versions are all shown, none picked', () => {
  const r = computeTier({ ...base, severity: 'HIGH', fixedVersions: ['4.20.0', '4.19.2'] });
  expect(r.factors.find((f) => f.key === 'fix')!.label).toBe('Fix: 4.20.0 / 4.19.2');
  expect(computeTier({ ...base, fixable: false }).factors.find((f) => f.key === 'fix')!.label).toBe('No fix yet');
});

test('exposure chips distinguish true / false / unknown', () => {
  const lbl = (exposed: boolean | null) => computeTier({ ...base, exposed, exposedVia: ['node'] }).factors.find((f) => f.key === 'exposure')!.label;
  expect(lbl(true)).toBe('Exposed: node');
  expect(lbl(false)).toBe('No outside ingress seen (7d)');
  expect(lbl(null)).toBe('Exposure unknown');
  expect(computeTier(base).factors.find((f) => f.key === 'exposure')).toBeUndefined();
});

test('worstTier', () => {
  expect(worstTier(['P2', 'P0', 'P1'])).toBe('P0');
  expect(worstTier([])).toBeNull();
});

test('privileged chip: PSS level, unknown when no profile, absent when not assessed', () => {
  const chip = (privileged: TierInput['privileged']) => computeTier({ ...base, privileged }).factors.find((f) => f.key === 'privileged');
  expect(chip(undefined)).toBeUndefined();
  expect(chip(null)!.label).toBe('Privileged: unknown');
  expect(chip({ level: null, confidence: null })!.tone).toBe('unknown');
  expect(chip({ level: 'privileged', confidence: 'confirmed' })!.label).toBe('Privileged');
  expect(chip({ level: 'privileged', confidence: 'upper_bound' })!.label).toBe('Privileged (at most)');
  expect(chip({ level: 'restricted', confidence: 'confirmed' })!.label).toBe('Not privileged');
  // A chip only: it does not move the tier.
  expect(computeTier({ ...base, severity: 'MEDIUM', privileged: { level: 'privileged', confidence: 'confirmed' } }).tier).toBe('P2');
});

test('chip order in a workload row: Loaded, Exposed, KEV, EPSS, CVSS, Fix, Privileged are all present', () => {
  const r = computeTier({ ...base, severity: 'CRITICAL', kev: true, epss: 0.2, score: 9.8, exposed: true, exposedVia: ['public_ip'], privileged: null });
  expect(r.factors.map((f) => f.key).sort()).toEqual(['cvss', 'epss', 'exposure', 'fix', 'inuse', 'kev', 'privileged']);
});
