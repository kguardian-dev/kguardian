// Package sandbox confines the scan child before it parses anything:
// descriptors, no_new_privs, scheduling and resource limits, capability
// checks, and a seccomp filter.
package sandbox

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Syscalls that fail with EPERM in the scan child. None is needed to parse
// files; each is a way out of the sandbox or into the kernel's attack
// surface. The architecture files add their own (e.g. x86 iopl).
var deniedCommon = []uint32{
	// Handle-based opens bypass path confinement entirely.
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
	// Other processes' memory.
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_PIDFD_GETFD, unix.SYS_KCMP, unix.SYS_PROCESS_MADVISE,
	// Mounts and namespaces.
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_UNSHARE, unix.SYS_SETNS,
	unix.SYS_CHROOT, unix.SYS_PIVOT_ROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
	// Kernel attack surface.
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_FANOTIFY_INIT,
	// io_uring performs I/O the filter never sees.
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	// Running anything: the child never executes after it starts.
	unix.SYS_EXECVE, unix.SYS_EXECVEAT,
	// New processes and sessions: a forked grandchild would outlive the
	// scan's SIGKILL (clone is restricted to threads below).
	unix.SYS_SETSID,
	// Sockets of any family: the child's only channel is fd 4, already
	// connected. Even AF_UNIX would reach host abstract sockets from the
	// Controller's hostNetwork pod (the CVE-2020-15257 class).
	unix.SYS_SOCKET, unix.SYS_SOCKETPAIR,
	// Host administration.
	unix.SYS_ACCT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_REBOOT,
	unix.SYS_QUOTACTL, unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME,
	unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
}

// cloneNamespaceFlags: clone(2) with any of these would create a namespace.
const cloneNamespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWUSER | unix.CLONE_NEWPID |
	unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP |
	unix.CLONE_NEWTIME

const (
	offNr   = 0
	offArch = 4
	offArg0 = 16 // args[0], low 32 bits (both supported arches are little-endian)

	retAllow = unix.SECCOMP_RET_ALLOW
	retKill  = unix.SECCOMP_RET_KILL_PROCESS
)

func retErrno(e unix.Errno) uint32 {
	return unix.SECCOMP_RET_ERRNO | (uint32(e) & unix.SECCOMP_RET_DATA)
}

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k, Jt: jt, Jf: jf}
}

const (
	ldAbsW = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	jeqK   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	jgeK   = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	jsetK  = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	retK   = unix.BPF_RET | unix.BPF_K
)

// Filter builds the scan child's seccomp program: kill on a foreign
// architecture; EPERM for x32 syscalls and the denied syscalls (including
// every socket and fork); clone only for threads (CLONE_THREAD set, no
// namespace flags); clone3 ENOSYS (its flags live in memory the filter
// cannot read, and ENOSYS makes callers fall back to clone; the Go runtime
// creates threads with clone, and only exec uses clone3); everything else
// allowed.
func Filter() []unix.SockFilter {
	p := []unix.SockFilter{
		stmt(ldAbsW, offArch),
		jump(jeqK, auditArch, 1, 0),
		stmt(retK, retKill),
		stmt(ldAbsW, offNr),
	}
	if x32Bit != 0 {
		// x32 ABI syscall numbers alias the 64-bit ones with this bit set.
		p = append(p, jump(jgeK, x32Bit, 0, 1), stmt(retK, retErrno(unix.EPERM)))
	}
	for _, nr := range append(append([]uint32{}, deniedCommon...), deniedArch...) {
		p = append(p, jump(jeqK, nr, 0, 1), stmt(retK, retErrno(unix.EPERM)))
	}
	p = append(p, jump(jeqK, unix.SYS_CLONE3, 0, 1), stmt(retK, retErrno(unix.ENOSYS)))
	// clone: allowed only for a thread without namespace flags.
	p = append(p,
		jump(jeqK, unix.SYS_CLONE, 0, 5),
		stmt(ldAbsW, offArg0+cloneFlagsArg*8),
		jump(jsetK, cloneNamespaceFlags, 2, 0),
		jump(jsetK, unix.CLONE_THREAD, 0, 1),
		stmt(retK, retAllow),
		stmt(retK, retErrno(unix.EPERM)),
	)
	p = append(p, stmt(retK, retAllow))
	return p
}

// InstallSeccomp sets no_new_privs and installs Filter on every thread of
// the process (SECCOMP_FILTER_FLAG_TSYNC; the Go runtime is already
// multi-threaded).
func InstallSeccomp() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	return InstallFilter(Filter())
}

// InstallFilter installs a seccomp program on every thread (no_new_privs
// must already be set).
func InstallFilter(f []unix.SockFilter) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	if r != 0 {
		return fmt.Errorf("seccomp: thread %d could not be synchronised", r)
	}
	return nil
}

// FaultFilter returns errno for the given syscalls and allows the rest
// (tests use it to simulate an old kernel or an LSM refusal).
func FaultFilter(faults map[uint32]unix.Errno) []unix.SockFilter {
	p := []unix.SockFilter{stmt(ldAbsW, offNr)}
	for nr, e := range faults {
		p = append(p, jump(jeqK, nr, 0, 1), stmt(retK, retErrno(e)))
	}
	return append(p, stmt(retK, retAllow))
}

// SelfCheckSeccomp confirms the filter is live: unshare(0) is a no-op the
// kernel allows, so only the filter can make it fail with EPERM.
func SelfCheckSeccomp() error {
	_, _, errno := unix.Syscall(unix.SYS_UNSHARE, 0, 0, 0)
	if errno != unix.EPERM {
		return errors.New("seccomp filter is not active")
	}
	return nil
}
