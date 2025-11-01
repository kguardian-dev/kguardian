export interface SeccompProfile {
  defaultAction: SeccompAction;
  architectures?: string[];
  syscalls?: SeccompSyscall[];
}

export interface SeccompSyscall {
  names: string[];
  action: SeccompAction;
}

export type SeccompAction =
  | 'SCMP_ACT_ALLOW'
  | 'SCMP_ACT_ERRNO'
  | 'SCMP_ACT_KILL'
  | 'SCMP_ACT_KILL_PROCESS'
  | 'SCMP_ACT_KILL_THREAD'
  | 'SCMP_ACT_LOG'
  | 'SCMP_ACT_TRACE'
  | 'SCMP_ACT_TRAP';

export const SECCOMP_ACTIONS: SeccompAction[] = [
  'SCMP_ACT_ALLOW',
  'SCMP_ACT_ERRNO',
  'SCMP_ACT_KILL',
  'SCMP_ACT_KILL_PROCESS',
  'SCMP_ACT_KILL_THREAD',
  'SCMP_ACT_LOG',
  'SCMP_ACT_TRACE',
  'SCMP_ACT_TRAP',
];

// Action descriptions from https://kubernetes.io/docs/reference/node/seccomp/
export const SECCOMP_ACTION_DESCRIPTIONS: Record<SeccompAction, string> = {
  'SCMP_ACT_ALLOW': 'Allow the syscall to be executed',
  'SCMP_ACT_ERRNO': 'Return an error code (reject syscall)',
  'SCMP_ACT_KILL': 'Kill only the thread',
  'SCMP_ACT_KILL_PROCESS': 'Kill the entire process',
  'SCMP_ACT_KILL_THREAD': 'Kill only the thread',
  'SCMP_ACT_LOG': 'Allow the syscall and log it to syslog or auditd',
  'SCMP_ACT_TRACE': 'Notify a tracing process with the specified value',
  'SCMP_ACT_TRAP': 'Throw a SIGSYS signal',
};

export const ARCHITECTURES = [
  'SCMP_ARCH_X86_64',
  'SCMP_ARCH_X86',
  'SCMP_ARCH_X32',
  'SCMP_ARCH_ARM',
  'SCMP_ARCH_AARCH64',
  'SCMP_ARCH_MIPS',
  'SCMP_ARCH_MIPS64',
  'SCMP_ARCH_MIPS64N32',
  'SCMP_ARCH_MIPSEL',
  'SCMP_ARCH_MIPSEL64',
  'SCMP_ARCH_MIPSEL64N32',
  'SCMP_ARCH_PPC',
  'SCMP_ARCH_PPC64',
  'SCMP_ARCH_PPC64LE',
  'SCMP_ARCH_S390',
  'SCMP_ARCH_S390X',
];
