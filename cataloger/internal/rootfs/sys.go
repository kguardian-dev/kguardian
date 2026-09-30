// Package rootfs is a Syft file resolver over a container root that was
// handed over as a directory file descriptor. Every lookup is resolved by
// the kernel relative to that fd with openat2(2) RESOLVE_IN_ROOT, so no
// symlink, ".." or absolute path can leave the root; RESOLVE_NO_XDEV and
// STATX_MNT_ID keep it off every other mount (volumes, the service-account
// token, /etc/hosts, anything mounted mid-scan); RESOLVE_NO_MAGICLINKS
// stops /proc-style links. Nothing is ever opened by a host path.
package rootfs

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ErrKernelUnsupported means the kernel lacks openat2 (5.6) or
// STATX_MNT_ID (5.8). There is no weaker fallback.
var ErrKernelUnsupported = errors.New("kernel lacks openat2 or STATX_MNT_ID")

// ErrLSMDenied means the root itself could not be read although it is a
// directory we were handed: an LSM (SELinux, AppArmor) refused it.
var ErrLSMDenied = errors.New("access to the container root denied")

// ErrTooManyFiles means the tree has more entries than the file budget.
var ErrTooManyFiles = errors.New("file budget exceeded")

// resolveFlags confine every lookup to the root, on the root's mount, and
// refuse magic links.
const resolveFlags = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS

// statxMask is what the indexer needs from each entry.
const statxMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID |
	unix.STATX_SIZE | unix.STATX_MTIME | unix.STATX_CTIME | unix.STATX_INO | unix.STATX_NLINK |
	unix.STATX_MNT_ID

// openat2 retries EINTR and EAGAIN (the kernel returns EAGAIN for
// RESOLVE_IN_ROOT lookups that raced a rename; retrying is the documented
// response).
func openat2(dirfd int, name string, flags uint64, resolve uint64) (int, error) {
	how := unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Resolve: resolve}
	for range 8 {
		fd, err := unix.Openat2(dirfd, name, &how)
		if err == nil {
			return fd, nil
		}
		if err != unix.EINTR && err != unix.EAGAIN {
			return -1, err
		}
	}
	return -1, unix.EAGAIN
}

// statx is a single-name, no-follow statx relative to dirfd.
func statx(dirfd int, name string) (unix.Statx_t, error) {
	var st unix.Statx_t
	flags := unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT
	if name == "" {
		flags |= unix.AT_EMPTY_PATH
	}
	for {
		err := unix.Statx(dirfd, name, flags, statxMask, &st)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return st, err
		}
		if st.Mask&unix.STATX_MNT_ID == 0 {
			return st, ErrKernelUnsupported
		}
		return st, nil
	}
}

// CheckKernel verifies openat2 and STATX_MNT_ID against dirfd.
func CheckKernel(dirfd int) error {
	fd, err := openat2(dirfd, ".", unix.O_PATH|unix.O_DIRECTORY, resolveFlags)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.E2BIG) {
			return ErrKernelUnsupported
		}
		return fmt.Errorf("openat2: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if _, err := statx(fd, ""); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, ErrKernelUnsupported) {
			return ErrKernelUnsupported
		}
		return fmt.Errorf("statx: %w", err)
	}
	return nil
}

// isAccessErr reports an LSM or DAC refusal.
func isAccessErr(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

// readDirNames returns the names in the directory open at fd (not "."
// or ".."), at most max of them (max <= 0: no limit), reading getdents
// in fixed chunks so a huge directory never has to fit in memory at once.
// truncated reports that more names were left unread.
func readDirNames(fd int, max int) (names []string, truncated bool, err error) {
	buf := make([]byte, 32*1024)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return names, false, err
		}
		if n <= 0 {
			return names, false, nil
		}
		want := -1
		if max > 0 {
			want = max - len(names)
		}
		var consumed int
		consumed, _, names = unix.ParseDirent(buf[:n], want, names)
		if max > 0 && len(names) >= max {
			// Anything left in this chunk, or in the next one, is unread.
			if hasName(buf[consumed:n]) {
				return names, true, nil
			}
			n2, err := unix.ReadDirent(fd, buf)
			return names, err == nil && n2 > 0 && hasName(buf[:n2]), nil
		}
	}
}

// hasName reports whether a getdents chunk holds any name besides "."
// and "..".
func hasName(b []byte) bool {
	_, count, _ := unix.ParseDirent(b, 1, nil)
	return count > 0
}

// readlinkat reads a symlink's target relative to dirfd.
func readlinkat(dirfd int, name string) (string, error) {
	for size := 256; size <= 64*1024; size *= 4 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", unix.ENAMETOOLONG
}
