package server

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

// killAs SIGKILLs the process behind pidfd and every process in the
// process group pgid (the child is started as its own group leader).
//
// The worker parent is uid 0 without CAP_KILL, and the kernel lets a
// process signal another only if its real or effective uid matches the
// target's real or saved uid, so a scan child running as ScanUID is out of
// reach of a plain kill. Instead of adding CAP_KILL, the signals are sent
// from a locked OS thread whose effective uid is switched to the child's
// for those syscalls (CAP_SETUID allows it; real and saved uid stay 0, so
// switching back needs no capability and restores the effective set). The
// thread is not unlocked afterwards: the runtime retires it with the
// goroutine, so no other goroutine ever runs with the borrowed uid.
//
// uid < 0 means the child runs as the parent's own uid (no switch).
//
// The pidfd pins the child, so a recycled pid is never signalled. The
// group is signalled too, for anything the child managed to start (the
// seccomp filter denies fork, so this is defence in depth); it cannot be
// recycled while the pinned child is still its member.
func killAs(pidfd, pgid, uid int) error {
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
		var err error
		if pidfd >= 0 {
			if e := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); e != nil && !errors.Is(e, unix.ESRCH) {
				err = e
			}
		}
		if pgid > 1 {
			if e := unix.Kill(-pgid, unix.SIGKILL); e != nil && !errors.Is(e, unix.ESRCH) && err == nil {
				err = e
			}
		}
		if uid >= 0 {
			if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), 0, ^uintptr(0)); e != 0 && err == nil {
				err = fmt.Errorf("restore euid: %w", e)
			}
		}
		errc <- err
	}()
	return <-errc
}

// childKiller kills one child. The pidfd is opened right after Start, or
// lazily by the first kill if that comes first (os/exec may run Cancel
// before Start has returned to us); either way before Wait, so the pid
// cannot have been reaped and reused yet.
type childKiller struct {
	mu    sync.Mutex
	pid   func() int // the child's pid once started, else 0
	pidfd int
	uid   int
}

func newChildKiller(uid int, pid func() int) *childKiller {
	return &childKiller{pid: pid, pidfd: -1, uid: uid}
}

// started pins the child with a pidfd.
func (k *childKiller) started() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.openLocked()
}

func (k *childKiller) openLocked() {
	if k.pidfd >= 0 {
		return
	}
	if pid := k.pid(); pid > 0 {
		if fd, err := unix.PidfdOpen(pid, 0); err == nil {
			k.pidfd = fd
		}
	}
}

// kill SIGKILLs the child and its process group. It never falls back to
// a plain kill(2) of the child, which would fail with EPERM for a child of
// another uid and leave it running.
func (k *childKiller) kill() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.openLocked()
	pid := k.pid()
	if pid <= 0 {
		return nil
	}
	return killAs(k.pidfd, pid, k.uid)
}

// close releases the pidfd (after Wait).
func (k *childKiller) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pidfd >= 0 {
		_ = unix.Close(k.pidfd)
		k.pidfd = -1
	}
}
