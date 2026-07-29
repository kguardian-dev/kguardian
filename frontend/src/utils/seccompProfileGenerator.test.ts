import { describe, it, expect } from 'vitest';
import { buildSeccompProfile, validateSeccompProfile } from './seccompProfileGenerator';

// Parity with the advisor's k8s.ValidateProfile and the llm-bridge assistant's
// validateSeccompProfile: an unrecognized CPU arch must be rejected rather than
// yielding a silently-unusable profile. buildSeccompProfile stays pure (the G2
// fixtures assert its output); validation is a separate, explicit step.
describe('validateSeccompProfile', () => {
  it('accepts a well-formed profile', () => {
    const p = buildSeccompProfile(['read', 'write'], 'x86_64');
    expect(() => validateSeccompProfile(p)).not.toThrow();
    expect(p.architectures).toEqual(['SCMP_ARCH_X86_64']);
  });

  it('rejects an unrecognized architecture (empty architectures)', () => {
    const p = buildSeccompProfile(['read'], 'ppc64le');
    expect(p.architectures).toEqual([]); // build stays pure
    expect(() => validateSeccompProfile(p)).toThrow(/unrecognized architecture/);
  });

  it('rejects a missing default action', () => {
    expect(() =>
      validateSeccompProfile({ defaultAction: '', architectures: ['SCMP_ARCH_X86_64'], syscalls: [{ names: ['read'], action: 'SCMP_ACT_ALLOW' }] }),
    ).toThrow(/default action is required/);
  });

  it('rejects no syscall rules', () => {
    expect(() =>
      validateSeccompProfile({ defaultAction: 'SCMP_ACT_ERRNO', architectures: ['SCMP_ARCH_X86_64'], syscalls: [] }),
    ).toThrow(/at least one syscall rule/);
  });
});
