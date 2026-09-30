package sandbox

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	x32Bit    = 0x40000000
	// cloneFlagsArg: clone(flags, stack, parent_tid, child_tid, tls).
	cloneFlagsArg = 0
)

var deniedArch = []uint32{unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MODIFY_LDT}
