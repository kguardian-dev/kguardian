package sandbox

import "golang.org/x/sys/unix"

// fork and vfork exist as syscalls only on amd64.
var forkSyscalls = map[string]uintptr{"fork": unix.SYS_FORK, "vfork": unix.SYS_VFORK}
