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

/**
 * Actions that let a syscall through. Everything else in `SeccompAction`
 * blocks it: ERRNO returns an errno, the KILL_* family terminates, TRAP
 * raises SIGSYS, and TRACE without a listening tracer fails the call.
 * SCMP_ACT_NOTIFY is handled by the same fall-through and also blocks
 * with no supervisor attached; naming it here so a reader checking
 * completeness does not have to already know it exists.
 *
 * Unrecognised actions therefore fail SAFE: a future seccomp action
 * makes this reject a profile it does not understand rather than pass
 * it, which is the right default for a validator.
 *
 * Named to match `PERMISSIVE_ACTIONS` in llm-bridge and `permissiveAction`
 * in the advisor: this check exists in three places and the point of
 * fixing it in three places was to stop them drifting.
 */
const PERMISSIVE_ACTIONS: ReadonlySet<string> = new Set([
  'SCMP_ACT_ALLOW',
  'SCMP_ACT_LOG',
]);

/**
 * Reject a profile that would be unusable if applied — parity port of the
 * advisor's k8s.ValidateProfile and the llm-bridge assistant's
 * validateSeccompProfile. An unrecognized `arch` yields `architectures: []`;
 * without this the editor would present a silently-broken profile. Throws a
 * clear message the caller can surface (the editor catches it and warns rather
 * than crashing, since the user can pick an architecture manually).
 */
export function validateSeccompProfile(profile: SeccompProfile): void {
  if (!profile.defaultAction) {
    throw new Error('seccomp profile is invalid: default action is required');
  }
  if (!profile.architectures || profile.architectures.length === 0) {
    throw new Error(
      `seccomp profile is invalid: unrecognized architecture — no seccomp arch mapping (supported: ${Object.keys(SECCOMP_ARCHITECTURES).join(', ')}). Select an architecture below.`,
    );
  }
  if (!profile.syscalls || profile.syscalls.length === 0) {
    throw new Error('seccomp profile is invalid: at least one syscall rule is required');
  }
  // The check above counts RULES, and `buildSeccompProfile` always emits
  // exactly one, so it never fires for the profile that matters: a rule
  // whose `names` list is empty. With a denying `defaultAction` that
  // permits nothing at all, which stops the container before its
  // entrypoint runs rather than restricting it.
  //
  // Only meaningful when the default denies. A permissive default
  // (ALLOW / LOG) with an empty rule is merely a no-op, not a trap.
  if (!PERMISSIVE_ACTIONS.has(profile.defaultAction)) {
    const permits = profile.syscalls.some(
      (rule) =>
        PERMISSIVE_ACTIONS.has(rule.action) && (rule.names?.length ?? 0) > 0,
    );
    if (!permits) {
      throw new Error(
        `seccomp profile is invalid: defaultAction is ${profile.defaultAction} and no rule allows any syscall, so every syscall would be denied and the container could not start. Add at least one syscall to an SCMP_ACT_ALLOW rule.`,
      );
    }
  }
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

/**
 * Render the profile as a Security Profiles Operator `SeccompProfile` CR
 * (security-profiles-operator.x-k8s.io/v1beta1). This is NOT the raw seccomp
 * JSON the kubelet loads from disk (see profileToJSON) — it needs the SPO
 * installed to reconcile into a node file. kguardian's own distribution path
 * (publish from the Workloads view, Seccomp columns) needs no operator.
 */
export function profileToYAML(profile: SeccompProfile, resourceName: string, namespace: string): string {
  const yaml: string[] = [];

  // Security Profiles Operator SeccompProfile CR
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
