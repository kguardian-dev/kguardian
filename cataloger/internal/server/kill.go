package server

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// killAs SIGKILLs the process behind pidfd. The worker parent is uid 0
// without CAP_KILL, and the kernel lets a process signal another only if
// its real or effective uid matches the target's real or saved uid, so a
// scan child running as ScanUID is out of reach of a plain kill. Instead
// of adding CAP_KILL, the signal is sent from a locked OS thread whose
// effective uid is switched to the child's for the one syscall
// (CAP_SETUID allows it; real and saved uid stay 0, so switching back
// needs no capability and restores the effective set). The thread is not
// unlocked afterwards: the runtime retires it with the goroutine, so no
// other goroutine ever runs with the borrowed uid.
//
// The pidfd pins the process, so a recycled pid is never signalled.
func killAs(pidfd int, uid int) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately no UnlockOSThread: see above.
		if uid >= 0 {
			if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), uintptr(uid), ^uintptr(0)); e != 0 {
				errc <- fmt.Errorf("seteuid %d: %w", uid, e)
				return
			}
		}
		err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		if uid >= 0 {
			if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), 0, ^uintptr(0)); e != 0 && err == nil {
				err = fmt.Errorf("restore euid: %w", e)
			}
		}
		if err == unix.ESRCH {
			err = nil // already gone
		}
		errc <- err
	}()
	return <-errc
}
