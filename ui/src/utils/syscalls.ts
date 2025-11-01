// Comprehensive list of Linux syscalls
// Based on Linux kernel syscall tables for x86_64, ARM, and other architectures
export const VALID_SYSCALLS = new Set<string>([
  // Process management
  'fork', 'vfork', 'clone', 'clone3', 'execve', 'execveat', 'exit', 'exit_group',
  'wait4', 'waitid', 'getpid', 'gettid', 'getppid', 'getpgid', 'setpgid',
  'getpgrp', 'setsid', 'getsid', 'getuid', 'setuid', 'getgid', 'setgid',
  'geteuid', 'getegid', 'setreuid', 'setregid', 'getresuid', 'getresgid',
  'setresuid', 'setresgid', 'getgroups', 'setgroups', 'capget', 'capset',
  'prctl', 'arch_prctl', 'setns', 'unshare', 'pidfd_open', 'pidfd_send_signal',
  'pidfd_getfd',

  // Memory management
  'brk', 'mmap', 'mmap2', 'munmap', 'mremap', 'mprotect', 'madvise', 'mlock',
  'mlock2', 'munlock', 'mlockall', 'munlockall', 'mincore', 'msync', 'remap_file_pages',
  'memfd_create', 'memfd_secret', 'mempolicy', 'mbind', 'get_mempolicy', 'set_mempolicy',
  'migrate_pages', 'move_pages', 'pkey_alloc', 'pkey_free', 'pkey_mprotect',

  // File operations
  'read', 'write', 'open', 'openat', 'openat2', 'close', 'close_range', 'creat',
  'link', 'linkat', 'unlink', 'unlinkat', 'symlink', 'symlinkat', 'readlink',
  'readlinkat', 'chmod', 'fchmod', 'fchmodat', 'chown', 'fchown', 'lchown',
  'fchownat', 'umask', 'access', 'faccessat', 'faccessat2', 'stat', 'fstat',
  'lstat', 'fstatat', 'statx', 'readv', 'writev', 'pread', 'pread64', 'pwrite',
  'pwrite64', 'preadv', 'preadv2', 'pwritev', 'pwritev2', 'lseek', 'dup', 'dup2',
  'dup3', 'fcntl', 'ioctl', 'flock', 'fsync', 'fdatasync', 'sync', 'sync_file_range',
  'syncfs', 'truncate', 'ftruncate', 'fallocate', 'fadvise64', 'sendfile', 'sendfile64',
  'splice', 'tee', 'vmsplice', 'copy_file_range', 'name_to_handle_at', 'open_by_handle_at',

  // Directory operations
  'getcwd', 'chdir', 'fchdir', 'chroot', 'mkdir', 'mkdirat', 'rmdir', 'rename',
  'renameat', 'renameat2', 'getdents', 'getdents64', 'lookup_dcookie',

  // Filesystem operations
  'mount', 'umount', 'umount2', 'pivot_root', 'statfs', 'fstatfs', 'ustat',
  'quotactl', 'fsopen', 'fsconfig', 'fsmount', 'fspick', 'move_mount', 'open_tree',

  // I/O multiplexing
  'select', 'pselect6', 'poll', 'ppoll', 'epoll_create', 'epoll_create1',
  'epoll_ctl', 'epoll_wait', 'epoll_pwait', 'epoll_pwait2',

  // Socket operations
  'socket', 'socketpair', 'bind', 'listen', 'accept', 'accept4', 'connect',
  'getsockname', 'getpeername', 'send', 'sendto', 'sendmsg', 'sendmmsg',
  'recv', 'recvfrom', 'recvmsg', 'recvmmsg', 'shutdown', 'setsockopt',
  'getsockopt', 'socketcall',

  // Signal handling
  'kill', 'tkill', 'tgkill', 'signal', 'sigaction', 'rt_sigaction', 'sigprocmask',
  'rt_sigprocmask', 'sigpending', 'rt_sigpending', 'sigsuspend', 'rt_sigsuspend',
  'sigaltstack', 'rt_sigtimedwait', 'rt_sigqueueinfo', 'rt_tgsigqueueinfo',
  'rt_sigreturn', 'restart_syscall', 'pause', 'signalfd', 'signalfd4',

  // Time operations
  'time', 'gettimeofday', 'settimeofday', 'clock_gettime', 'clock_settime',
  'clock_getres', 'clock_nanosleep', 'clock_adjtime', 'adjtimex', 'times',
  'nanosleep', 'alarm', 'setitimer', 'getitimer', 'timer_create', 'timer_settime',
  'timer_gettime', 'timer_getoverrun', 'timer_delete', 'timerfd_create',
  'timerfd_settime', 'timerfd_gettime',

  // Scheduling
  'sched_setparam', 'sched_getparam', 'sched_setscheduler', 'sched_getscheduler',
  'sched_get_priority_max', 'sched_get_priority_min', 'sched_rr_get_interval',
  'sched_yield', 'sched_setaffinity', 'sched_getaffinity', 'sched_setattr',
  'sched_getattr',

  // System information
  'uname', 'sysinfo', 'syslog', 'klogctl', 'personality', 'getrlimit', 'setrlimit',
  'prlimit64', 'getrusage', 'sysfs', 'sethostname', 'setdomainname', 'gethostname',
  'getdomainname',

  // User/Group IDs
  'setfsuid', 'setfsgid',

  // Extended attributes
  'setxattr', 'lsetxattr', 'fsetxattr', 'getxattr', 'lgetxattr', 'fgetxattr',
  'listxattr', 'llistxattr', 'flistxattr', 'removexattr', 'lremovexattr',
  'fremovexattr',

  // Advanced I/O
  'io_setup', 'io_destroy', 'io_submit', 'io_cancel', 'io_getevents',
  'io_pgetevents', 'io_uring_setup', 'io_uring_enter', 'io_uring_register',

  // Futex
  'futex', 'futex_waitv', 'set_robust_list', 'get_robust_list',

  // IPC - Message queues
  'mq_open', 'mq_unlink', 'mq_timedsend', 'mq_timedreceive', 'mq_notify',
  'mq_getsetattr',

  // IPC - Semaphores
  'semget', 'semop', 'semctl', 'semtimedop',

  // IPC - Shared memory
  'shmget', 'shmat', 'shmdt', 'shmctl',

  // IPC - Message passing
  'msgget', 'msgsnd', 'msgrcv', 'msgctl',

  // IPC - General
  'ipc',

  // Pipes
  'pipe', 'pipe2',

  // Event notification
  'inotify_init', 'inotify_init1', 'inotify_add_watch', 'inotify_rm_watch',
  'fanotify_init', 'fanotify_mark',

  // Key management
  'add_key', 'request_key', 'keyctl',

  // Modules
  'init_module', 'finit_module', 'delete_module',

  // BPF
  'bpf',

  // Performance monitoring
  'perf_event_open',

  // Landlock
  'landlock_create_ruleset', 'landlock_add_rule', 'landlock_restrict_self',

  // NUMA
  'set_mempolicy_home_node',

  // Process VM
  'process_vm_readv', 'process_vm_writev',

  // Random
  'getrandom',

  // Reboot
  'reboot',

  // Resource limits
  'getpriority', 'setpriority', 'ioprio_set', 'ioprio_get',

  // Ptrace
  'ptrace',

  // Acct
  'acct',

  // Security
  'seccomp',

  // Tracing
  'utrace',

  // Misc
  'vhangup', 'uselib', 'kcmp', 'swapon', 'swapoff', 'readahead',

  // Architecture specific - x86
  'modify_ldt', 'ioperm', 'iopl', 'vm86', 'vm86old',

  // ARM specific
  'breakpoint', 'cacheflush', 'set_tls', 'usr26', 'usr32',

  // Obsolete but may still appear
  'oldolduname', 'olduname', 'oldstat', 'oldlstat', 'oldfstat',
  '_sysctl', 'create_module', 'query_module', 'get_kernel_syms',
  'afs_syscall', 'nfsservctl', 'getpmsg', 'putpmsg', 'vserver',
  'ioperm', 'iopl', 'idle', 'sysctl', 'bdflush',

  // New syscalls (Linux 5.x+)
  'process_madvise', 'process_mrelease', 'mount_setattr', 'quotactl_fd',
  'memfd_secret', 'landlock_create_ruleset', 'landlock_add_rule',
  'landlock_restrict_self', 'futex_waitv',
]);

/**
 * Validates if a given string is a valid Linux syscall name
 */
export function isValidSyscall(name: string): boolean {
  return VALID_SYSCALLS.has(name.trim().toLowerCase());
}

/**
 * Filters syscall names to only include valid ones
 */
export function filterValidSyscalls(names: string[]): string[] {
  return names.filter(name => isValidSyscall(name));
}

/**
 * Gets syscall suggestions based on a partial input
 */
export function getSyscallSuggestions(partial: string, limit: number = 10): string[] {
  if (!partial) return [];

  const lowerPartial = partial.toLowerCase();
  const suggestions: string[] = [];

  for (const syscall of VALID_SYSCALLS) {
    if (syscall.startsWith(lowerPartial)) {
      suggestions.push(syscall);
      if (suggestions.length >= limit) break;
    }
  }

  // If we don't have enough exact prefix matches, look for contains
  if (suggestions.length < limit) {
    for (const syscall of VALID_SYSCALLS) {
      if (syscall.includes(lowerPartial) && !suggestions.includes(syscall)) {
        suggestions.push(syscall);
        if (suggestions.length >= limit) break;
      }
    }
  }

  return suggestions.sort();
}

/**
 * Validates and sanitizes syscall names from comma-separated string
 */
export function parseSyscallString(syscallStr: string): {
  valid: string[];
  invalid: string[];
} {
  const names = syscallStr.split(',').map(s => s.trim()).filter(s => s.length > 0);
  const valid: string[] = [];
  const invalid: string[] = [];

  names.forEach(name => {
    if (isValidSyscall(name)) {
      valid.push(name.toLowerCase());
    } else {
      invalid.push(name);
    }
  });

  return { valid, invalid };
}
