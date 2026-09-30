package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	x32Bit    = 0x40000000
	// cloneFlagsArg: clone(flags, stack, parent_tid, child_tid, tls).
	cloneFlagsArg = 0
)

// fork and vfork exist only on amd64 (arm64 forks through clone).
var deniedArch = []uint32{unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MODIFY_LDT, unix.SYS_FORK, unix.SYS_VFORK}

// selfCheckFork: fork(2) must fail with EPERM. If the filter were missing
// and a child were created, it exits at once and is reaped.
func selfCheckFork() error {
	r, _, errno := unix.RawSyscall(unix.SYS_FORK, 0, 0, 0)
	if errno == 0 && r == 0 {
		_, _, _ = unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}
	if errno != unix.EPERM {
		if errno == 0 {
			var ws unix.WaitStatus
			_, _ = unix.Wait4(int(r), &ws, 0, nil)
		}
		return fmt.Errorf("seccomp filter is not active: fork returned %v", errno)
	}
	return nil
}
