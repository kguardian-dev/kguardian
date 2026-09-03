import { describe, expect, test } from 'vitest';
import { policyTypeForFinding } from './findingPolicyType';

describe('policyTypeForFinding', () => {
  test('sensitive syscalls → seccomp regardless of CNI', () => {
    expect(policyTypeForFinding('sensitive-syscalls')).toBe('seccomp');
    expect(policyTypeForFinding('sensitive-syscalls', 'cilium')).toBe('seccomp');
  });
  test('network findings → NetworkPolicy by default (unknown / non-cilium CNI)', () => {
    expect(policyTypeForFinding('denied-traffic')).toBe('network');
    expect(policyTypeForFinding('egress-fanout', 'unknown')).toBe('network');
    expect(policyTypeForFinding('would-deny', 'calico')).toBe('network');
  });
  test('network findings → Cilium tab when the cluster CNI is cilium', () => {
    expect(policyTypeForFinding('denied-traffic', 'cilium')).toBe('cilium');
    expect(policyTypeForFinding('egress-fanout', 'cilium')).toBe('cilium');
    expect(policyTypeForFinding('would-deny', 'cilium')).toBe('cilium');
  });
});
