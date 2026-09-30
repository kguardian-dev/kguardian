package rootfs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Options bound and shape one scan of a root.
type Options struct {
	// Submounts are mount points inside the root (absolute paths) that are
	// never entered or read, in addition to the kernel's mount checks.
	Submounts []string
	// CtimeCutoffNanos: a non-directory whose ctime is later (unix nanos)
	// is runtime drift. It is left out of the index and recorded in
	// Stats.CtimeDropped / Root.Dropped. 0 disables the check.
	CtimeCutoffNanos int64
	// MaxFiles bounds indexed entries (0: unbounded).
	MaxFiles int
	// MaxDepth bounds directory depth below the root (0: unbounded).
	MaxDepth int
	// StopAtBudget ends indexing quietly at MaxFiles (Stats.FileBudget)
	// instead of failing with ErrTooManyFiles.
	StopAtBudget bool
	// SystemFirst indexes the OS directories before the rest, so a budget
	// stop keeps the package databases and system binaries.
	SystemFirst bool
	// SniffExecutablesOnly reads the MIME type only of files that look
	// executable (execute bit or *.so*), not of every regular file.
	SniffExecutablesOnly bool
}

// Stats counts what the indexer saw. Safe for concurrent use.
type Stats struct {
	Files        atomic.Int64 // indexed non-directories
	Dirs         atomic.Int64
	EACCES       atomic.Int64 // entries refused by DAC or an LSM
	MountSkipped atomic.Int64 // entries on another mount, or a listed submount
	DepthLimited atomic.Int64 // directories not entered: too deep
	CtimeDropped atomic.Int64 // runtime-changed files left out
	Swapped      atomic.Int64 // entries that changed type between stat and open
	Special      atomic.Int64 // devices, FIFOs, sockets (never read)
	FileBudget   atomic.Bool  // StopAtBudget hit MaxFiles
}

// Root is a container root handed over as a directory fd.
type Root struct {
	fd    int // O_PATH directory
	mntID uint64
	opts  Options
	subs  map[string]struct{}

	Stats Stats

	mu      sync.Mutex
	dropped map[string]droppedFile // paths left out for ctime drift
}

// droppedFile is what the indexer saw of a runtime-changed entry before
// leaving it out: enough to decide whether it could have been package
// evidence (see Resolver.ClassifyDropped).
type droppedFile struct {
	mode uint32 // st_mode, type and permission bits
	size int64
	mime string // sniffed like an indexed file ("" when not sniffed)
	// unsniffed: the file should have been sniffed but could not be read.
	unsniffed bool
	atRead    bool // dropped when a cataloger went to read it
}

// Open wraps dirfd (which Root now owns and closes). It verifies the kernel
// features the resolver depends on and that dirfd is a directory.
func Open(dirfd int, opts Options) (*Root, error) {
	if err := CheckKernel(dirfd); err != nil {
		if isAccessErr(err) {
			return nil, ErrLSMDenied
		}
		return nil, err
	}
	st, err := statx(dirfd, "")
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("root fd is not a directory")
	}
	r := &Root{fd: dirfd, mntID: st.Mnt_id, opts: opts, subs: map[string]struct{}{}, dropped: map[string]droppedFile{}}
	for _, s := range opts.Submounts {
		if c := path.Clean("/" + s); c != "/" {
			r.subs[c] = struct{}{}
		}
	}
	return r, nil
}

// OpenPath opens a host directory as a root (tests and the scan-dir
// debugging command). Production roots arrive as fds.
func OpenPath(dir string, opts Options) (*Root, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	r, err := Open(fd, opts)
	if err != nil {
		_ = unix.Close(fd)
	}
	return r, err
}

// Close releases the root fd.
func (r *Root) Close() error {
	if r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

// excluded reports whether p (absolute, clean) is a listed submount or
// below one.
func (r *Root) excluded(p string) bool {
	if len(r.subs) == 0 {
		return false
	}
	for q := p; q != "/" && q != "."; q = path.Dir(q) {
		if _, ok := r.subs[q]; ok {
			return true
		}
	}
	return false
}

func (r *Root) late(st *unix.Statx_t) bool {
	return r.opts.CtimeCutoffNanos > 0 && st.Mode&unix.S_IFMT != unix.S_IFDIR &&
		tsNanos(st.Ctime) > r.opts.CtimeCutoffNanos
}

func (r *Root) drop(p string, d droppedFile) {
	r.mu.Lock()
	if old, ok := r.dropped[p]; !ok {
		r.dropped[p] = d
		r.Stats.CtimeDropped.Add(1)
	} else if d.atRead && !old.atRead {
		old.atRead = true
		r.dropped[p] = old
	}
	r.mu.Unlock()
}

// Dropped reports whether p was left out as runtime drift.
func (r *Root) Dropped(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.dropped[path.Clean("/"+p)]
	return ok
}

// rel turns an absolute in-root path into the relative name openat2 wants.
func rel(p string) string {
	p = strings.TrimLeft(path.Clean("/"+p), "/")
	if p == "" {
		return "."
	}
	return p
}

// OpenFile opens the regular file at p (in-root path) for reading. The
// kernel resolves p against the root (symlinks stay inside it, mounts and
// magic links are refused); O_NONBLOCK keeps a FIFO from blocking the
// open; the result must be a regular file on the root's mount, and must
// not have changed after the ctime cutoff.
func (r *Root) OpenFile(p string) (*os.File, error) {
	clean := path.Clean("/" + p)
	if r.excluded(clean) {
		return nil, &os.PathError{Op: "open", Path: clean, Err: unix.EXDEV}
	}
	fd, err := openat2(r.fd, rel(clean), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_NOCTTY, resolveFlags)
	if err != nil {
		if isAccessErr(err) {
			r.Stats.EACCES.Add(1)
		}
		return nil, &os.PathError{Op: "open", Path: clean, Err: err}
	}
	st, err := statx(fd, "")
	if err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "stat", Path: clean, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: clean, Err: errors.New("not a regular file")}
	}
	if st.Mnt_id != r.mntID {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: clean, Err: unix.EXDEV}
	}
	if r.late(&st) {
		_ = unix.Close(fd)
		r.drop(clean, droppedFile{mode: uint32(st.Mode), size: int64(st.Size), atRead: true})
		return nil, &os.PathError{Op: "open", Path: clean, Err: errors.New("changed after container start")}
	}
	// A regular file: blocking reads are fine now, and a blocking fd keeps
	// os.File off the netpoller.
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), clean), nil
}

// StatPath returns the no-follow metadata of p, resolved in-root.
func (r *Root) StatPath(p string) (unix.Statx_t, error) {
	clean := path.Clean("/" + p)
	fd, err := openat2(r.fd, rel(clean), unix.O_PATH|unix.O_NOFOLLOW, resolveFlags)
	if err != nil {
		return unix.Statx_t{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	return statx(fd, "")
}
