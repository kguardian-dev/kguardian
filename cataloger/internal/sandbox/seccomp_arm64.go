package sandbox

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_AARCH64
	x32Bit    = 0
	// cloneFlagsArg: clone(flags, stack, parent_tid, tls, child_tid).
	cloneFlagsArg = 0
)

var deniedArch = []uint32{}

// selfCheckFork: arm64 has no fork syscall (a process-creating clone is
// refused by the filter and covered by its tests).
func selfCheckFork() error { return nil }
