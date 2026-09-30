package rootfs

import (
	"io/fs"
	"syscall"
	"time"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"golang.org/x/sys/unix"
)

// fileMode converts a raw st_mode to fs.FileMode the way os.Lstat does,
// so catalogers see the same mode (execute bits, type) as with Syft's own
// directory resolver.
func fileMode(m uint16) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFBLK:
		mode |= fs.ModeDevice
	case unix.S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFSOCK:
		mode |= fs.ModeSocket
	}
	if m&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

func tsTime(ts unix.StatxTimestamp) time.Time {
	return time.Unix(ts.Sec, int64(ts.Nsec))
}

// tsNanos is a statx timestamp as unix nanoseconds.
func tsNanos(ts unix.StatxTimestamp) int64 {
	return ts.Sec*1e9 + int64(ts.Nsec)
}

// fileInfo builds the fs.FileInfo Syft's directory resolver would get
// from os.Lstat, including a *syscall.Stat_t for Sys() (Syft reads the
// owner from it).
func fileInfo(name string, st *unix.Statx_t) fs.FileInfo {
	sys := &syscall.Stat_t{
		Ino:  st.Ino,
		Mode: uint32(st.Mode),
		Uid:  st.Uid,
		Gid:  st.Gid,
		Size: int64(st.Size),
	}
	sys.Mtim.Sec, sys.Mtim.Nsec = st.Mtime.Sec, int64(st.Mtime.Nsec)
	sys.Ctim.Sec, sys.Ctim.Nsec = st.Ctime.Sec, int64(st.Ctime.Nsec)
	return stereofile.ManualInfo{
		NameValue:    name,
		SizeValue:    int64(st.Size),
		ModeValue:    fileMode(st.Mode),
		ModTimeValue: tsTime(st.Mtime),
		SysValue:     sys,
	}
}
