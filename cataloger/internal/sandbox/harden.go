package sandbox

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Limits for the scan child.
type Limits struct {
	// KeepFDs: descriptors 0..KeepFDs-1 stay open; every other is closed.
	KeepFDs int
	// MemoryLimit is the Go soft memory limit in bytes (0: leave it).
	MemoryLimit int64
	// MaxFileSize caps any file the child writes (its temp files).
	MaxFileSize int64
	// OnFileTooLarge runs when a write hits MaxFileSize (nil: ignore).
	OnFileTooLarge func()
}

const (
	ioprioClassIdle  = 3
	ioprioClassShift = 13
	ioprioWhoProcess = 1
)

// Harden applies the process-wide limits the child needs before it reads
// anything: closes every descriptor it was not meant to have, lowest CPU
// and idle I/O priority, one P, a soft memory limit, RLIMIT_NOFILE 4096,
// no core dumps, and a cap on written file size (EFBIG, not SIGXFSZ).
// It must run first in the child, before anything opens a file.
func Harden(l Limits) error {
	if err := closeInherited(l.KeepFDs); err != nil {
		return fmt.Errorf("close fds: %w", err)
	}
	// Both are per thread on Linux: apply to every runtime thread (threads
	// started later inherit them).
	if err := allThreads(unix.SYS_SETPRIORITY, unix.PRIO_PROCESS, 0, 19); err != nil {
		return fmt.Errorf("nice: %w", err)
	}
	if err := allThreads(unix.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprioClassIdle<<ioprioClassShift); err != nil {
		return fmt.Errorf("ioprio_set: %w", err)
	}
	runtime.GOMAXPROCS(1)
	if l.MemoryLimit > 0 {
		debug.SetMemoryLimit(l.MemoryLimit)
	}
	for _, rl := range []struct {
		res int
		v   uint64
	}{
		{unix.RLIMIT_NOFILE, 4096},
		{unix.RLIMIT_CORE, 0},
	} {
		if err := unix.Setrlimit(rl.res, &unix.Rlimit{Cur: rl.v, Max: rl.v}); err != nil {
			return fmt.Errorf("setrlimit %d: %w", rl.res, err)
		}
	}
	if l.MaxFileSize > 0 {
		// A write past the limit raises SIGXFSZ and fails with EFBIG.
		// Catching the signal (rather than ignoring it) keeps the process
		// alive and tells the caller the temp budget was hit, even when
		// the writer swallows the error.
		if l.OnFileTooLarge != nil {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGXFSZ)
			go func() {
				for range ch {
					l.OnFileTooLarge()
				}
			}()
		} else {
			signal.Ignore(syscall.SIGXFSZ)
		}
		v := uint64(l.MaxFileSize)
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: v, Max: v}); err != nil {
			return fmt.Errorf("setrlimit fsize: %w", err)
		}
	}
	return nil
}

// runtimeFD: descriptors the Go runtime itself creates lazily (the netpoll
// epoll instance and its wake-up eventfd; the first timer or pollable file
// creates them, possibly during package initialisation). Closing them
// kills the process with "netpoll failed".
//
// Since Go 1.25 the runtime also keeps the cgroup CPU limit files open to
// follow the container's CPU quota (container-aware GOMAXPROCS).
func runtimeFD(target string) bool {
	if target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]" {
		return true
	}
	if strings.HasPrefix(target, "/sys/fs/cgroup/") {
		switch path.Base(target) {
		case "cpu.max", "cpu.cfs_quota_us", "cpu.cfs_period_us":
			return true
		}
	}
	return false
}

// RuntimeFD reports whether a /proc/self/fd target is one the Go runtime
// opens for itself (tests).
func RuntimeFD(target string) bool { return runtimeFD(target) }

// closeInherited closes every descriptor >= keep except the runtime's own.
// Everything the parent passes is O_CLOEXEC except fds 0..keep-1, so this
// is defence in depth against a leaked descriptor; a blind close_range
// would also close the runtime's epoll fd. Contiguous runs are closed with
// close_range(2).
func closeInherited(keep int) error {
	fds, err := OpenFDs()
	if err != nil {
		return err
	}
	for _, fd := range fds {
		if fd < keep {
			continue
		}
		target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if err == nil && runtimeFD(target) {
			continue
		}
		if err := unix.CloseRange(uint(fd), uint(fd), 0); err != nil && err != unix.EBADF {
			return err
		}
	}
	return nil
}

// allThreads runs a per-thread syscall on every thread (cgo-free builds);
// with cgo it falls back to the calling thread.
func allThreads(trap, a1, a2, a3 uintptr) error {
	_, _, errno := syscall.AllThreadsSyscall(trap, a1, a2, a3)
	if errno == syscall.ENOTSUP {
		_, _, errno = unix.Syscall(trap, a1, a2, a3)
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// OpenFDs lists this process's open descriptors (tests).
func OpenFDs() ([]int, error) {
	fd, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	buf := make([]byte, 8192)
	var names []string
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			break
		}
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
	}
	var out []int
	for _, n := range names {
		var v int
		if _, err := fmt.Sscanf(n, "%d", &v); err == nil && v != fd {
			out = append(out, v)
		}
	}
	return out, nil
}
