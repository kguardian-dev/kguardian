import type { PodNodeData } from '../types';
import type { SeccompProfile, SeccompSyscall } from '../types/seccompProfile';
import { parseSyscallString } from './syscalls';

export function generateSeccompProfile(pod: PodNodeData): SeccompProfile {
  console.log('Generating seccomp profile for pod:', pod.pod.pod_name);
  console.log('Syscall records:', pod.syscalls?.length || 0);

  // Collect all unique syscalls from the pod's observed behavior
  const uniqueSyscalls = new Set<string>();
  const invalidSyscalls: string[] = [];

  pod.syscalls?.forEach((syscallRecord, idx) => {
    console.log(`Syscall record ${idx}:`, syscallRecord);

    if (syscallRecord.syscalls) {
      // Split comma-separated syscalls and validate
      const { valid, invalid } = parseSyscallString(syscallRecord.syscalls);

      // Add valid syscalls to set
      valid.forEach(syscall => uniqueSyscalls.add(syscall));

      // Track invalid syscalls for logging
      if (invalid.length > 0) {
        invalidSyscalls.push(...invalid);
        console.warn(`  Invalid syscalls in record ${idx}:`, invalid);
      }

      console.log(`  Added ${valid.length} valid syscalls from record ${idx}`);
    }
  });

  if (invalidSyscalls.length > 0) {
    console.warn(`Total invalid syscalls filtered out: ${invalidSyscalls.length}`, invalidSyscalls);
  }

  console.log(`Total unique valid syscalls: ${uniqueSyscalls.size}`);

  // Create syscall rules - group all observed syscalls into one allow rule
  const syscallRules: SeccompSyscall[] = [];

  if (uniqueSyscalls.size > 0) {
    syscallRules.push({
      names: Array.from(uniqueSyscalls).sort(),
      action: 'SCMP_ACT_ALLOW',
    });
  }

  // Create the seccomp profile
  const profile: SeccompProfile = {
    defaultAction: 'SCMP_ACT_ERRNO', // Default to deny all syscalls not explicitly allowed
    architectures: [
      'SCMP_ARCH_X86_64',
      'SCMP_ARCH_X86',
      'SCMP_ARCH_X32',
    ],
    syscalls: syscallRules,
  };

  return profile;
}

export function profileToJSON(profile: SeccompProfile): string {
  return JSON.stringify(profile, null, 2);
}

export function profileToYAML(profile: SeccompProfile, resourceName: string, namespace: string): string {
  const yaml: string[] = [];

  // Create a Kubernetes SeccompProfile CRD format
  yaml.push('apiVersion: security.kubernetes.io/v1alpha1');
  yaml.push('kind: SeccompProfile');
  yaml.push('metadata:');
  yaml.push(`  name: ${resourceName}-seccomp`);
  yaml.push(`  namespace: ${namespace}`);
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
