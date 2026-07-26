import type { PodNodeData } from '../types';
import type { SeccompProfile } from '../types/seccompProfile';
import { parseSyscallString } from './syscalls';
import { quoteYamlValue } from './networkPolicyGenerator';

// Map the controller-recorded CPU architecture (Rust std::env::consts::ARCH —
// "x86_64" / "aarch64") to seccomp arch tokens. This is the single source of
// truth for the frontend, kept byte-for-byte in step with the advisor
// reference (advisor/pkg/k8s SeccompArchitectures) and the G2 golden fixtures
// under test/fixtures/generators/seccomp. Previously the frontend hardcoded
// the x86 arch set for every pod, so an aarch64 pod got an unusable x86
// profile.
const SECCOMP_ARCHITECTURES: Record<string, string[]> = {
  x86_64: ['SCMP_ARCH_X86_64'],
  aarch64: ['SCMP_ARCH_ARM64'],
};

/**
 * Build a seccomp profile from an observed syscall set and CPU architecture.
 * Pure function and the parity seam shared with the advisor generator (G2):
 * allow-lists exactly the given syscalls, denies the rest, and always emits
 * the allow rule so the shape is stable even for a pod with no observed
 * syscalls.
 */
export function buildSeccompProfile(syscalls: string[], arch: string): SeccompProfile {
  return {
    defaultAction: 'SCMP_ACT_ERRNO', // deny any syscall not explicitly allowed
    architectures: SECCOMP_ARCHITECTURES[arch] ?? [],
    syscalls: [
      {
        names: [...syscalls].sort(),
        action: 'SCMP_ACT_ALLOW',
      },
    ],
  };
}

export function generateSeccompProfile(pod: PodNodeData): SeccompProfile {
  // Collect all unique valid syscalls from the pod's observed behavior.
  const uniqueSyscalls = new Set<string>();
  let arch = '';

  pod.syscalls?.forEach((syscallRecord) => {
    if (!arch && syscallRecord.arch) arch = syscallRecord.arch;
    if (syscallRecord.syscalls) {
      const { valid } = parseSyscallString(syscallRecord.syscalls);
      valid.forEach(syscall => uniqueSyscalls.add(syscall));
    }
  });

  return buildSeccompProfile(Array.from(uniqueSyscalls), arch);
}

export function profileToJSON(profile: SeccompProfile): string {
  return JSON.stringify(profile, null, 2);
}

export function profileToYAML(profile: SeccompProfile, resourceName: string, namespace: string): string {
  const yaml: string[] = [];

  // Create a Kubernetes SeccompProfile CRD format
  yaml.push('apiVersion: security-profiles-operator.x-k8s.io/v1beta1');
  yaml.push('kind: SeccompProfile');
  yaml.push('metadata:');
  yaml.push(`  name: ${quoteYamlValue(`${resourceName}-seccomp`)}`);
  yaml.push(`  namespace: ${quoteYamlValue(namespace)}`);
  yaml.push('spec:');
  yaml.push(`  defaultAction: ${profile.defaultAction}`);

  if (profile.architectures && profile.architectures.length > 0) {
    yaml.push('  architectures:');
    profile.architectures.forEach(arch => {
      yaml.push(`  - ${arch}`);
    });
  }

  if (profile.syscalls && profile.syscalls.length > 0) {
    yaml.push('  syscalls:');
    profile.syscalls.forEach((syscall) => {
      yaml.push('  - names:');
      syscall.names.forEach(name => {
        yaml.push(`    - ${name}`);
      });
      yaml.push(`    action: ${syscall.action}`);
    });
  }

  return yaml.join('\n');
}
