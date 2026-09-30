package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// CloexecInherited sets FD_CLOEXEC on every descriptor >= 3 this process
// has. The worker parent calls it first thing: whatever it inherited from
// its own parent without close-on-exec (a runtime's pipe, a CI runner's
// log pipe) would otherwise be passed to every child it starts, including
// the helpers that skip the scan child's descriptor cleanup. Descriptors
// the Go runtime and os/exec open are already close-on-exec, so marking
// them again changes nothing; os/exec passes a child's intended
// descriptors (ExtraFiles) regardless.
func CloexecInherited() error {
	fds, err := OpenFDs()
	if err != nil {
		return fmt.Errorf("list descriptors: %w", err)
	}
	for _, fd := range fds {
		if fd < 3 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			continue // closed meanwhile (the listing's own fd)
		}
		if flags&unix.FD_CLOEXEC != 0 {
			continue
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
			return fmt.Errorf("set FD_CLOEXEC on fd %d: %w", fd, err)
		}
	}
	return nil
}
