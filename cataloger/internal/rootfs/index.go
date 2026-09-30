package rootfs

import (
	"errors"
	"io"
	"path"
	"sort"
	"strings"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"golang.org/x/sys/unix"
)

// systemDirs are indexed first under Options.SystemFirst.
var systemDirs = []string{"etc", "lib", "lib64", "lib32", "usr", "bin", "sbin", "var", "opt"}

var errStop = errors.New("stop walking")

// maxNamesPerDir caps the names read from one directory. Past it the rest
// of the directory is skipped and the scan is partial (Stats.FileBudget).
var maxNamesPerDir = 256 << 10

// beforeOpenDir, when set (tests only), runs between the stat of a
// subdirectory and its open: the window a racing rename or symlink swap
// would use.
var beforeOpenDir func(p string)

type indexer struct {
	r     *Root
	tree  filetree.ReadWriter
	index filetree.Index
	count int
}

// Index walks the whole root (depth-first, names sorted like
// filepath.Walk) and returns the file tree and index Syft's search
// context runs on. It indexes what Syft's own directory resolver indexes
// (directories, regular files, symlinks with their in-root targets; not
// devices, FIFOs or sockets), with MIME types sniffed from the first
// bytes of each regular file.
func (r *Root) Index() (filetree.ReadWriter, filetree.Index, error) {
	ix := &indexer{r: r, tree: filetree.New(), index: filetree.NewIndex()}
	st, err := statx(r.fd, "")
	if err != nil {
		return nil, nil, err
	}
	ref, err := ix.tree.AddDir("/")
	if err != nil {
		return nil, nil, err
	}
	ix.index.Add(*ref, ix.metadata("/", &st, stereofile.TypeDirectory, "", ""))
	r.Stats.Dirs.Add(1)

	fd, err := openat2(r.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY, resolveFlags)
	if err != nil {
		if isAccessErr(err) {
			return nil, nil, ErrLSMDenied
		}
		return nil, nil, err
	}
	err = ix.walkDir(fd, "/", 0)
	if errors.Is(err, errStop) {
		err = nil
	}
	if err != nil {
		return nil, nil, err
	}
	return ix.tree, ix.index, nil
}

func (ix *indexer) metadata(p string, st *unix.Statx_t, t stereofile.Type, link, mime string) stereofile.Metadata {
	return stereofile.Metadata{
		FileInfo:        fileInfo(path.Base(p), st),
		Path:            p,
		LinkDestination: link,
		UserID:          int(st.Uid),
		GroupID:         int(st.Gid),
		Type:            t,
		MIMEType:        mime,
	}
}

// budget counts one directory entry (of any kind, indexed or not)
// against MaxFiles.
func (ix *indexer) budget() error {
	ix.count++
	if max := ix.r.opts.MaxFiles; max > 0 && ix.count > max {
		if ix.r.opts.StopAtBudget {
			ix.r.Stats.FileBudget.Store(true)
			return errStop
		}
		return ErrTooManyFiles
	}
	return nil
}

func (ix *indexer) orderNames(names []string, top bool) {
	sort.Strings(names)
	if !top || !ix.r.opts.SystemFirst {
		return
	}
	rank := map[string]int{}
	for i, n := range systemDirs {
		rank[n] = i + 1
	}
	sort.SliceStable(names, func(i, j int) bool {
		ri, rj := rank[names[i]], rank[names[j]]
		if ri == 0 {
			ri = len(systemDirs) + 1
		}
		if rj == 0 {
			rj = len(systemDirs) + 1
		}
		return ri < rj
	})
}

// walkDir indexes the directory open at fd (which it closes).
func (ix *indexer) walkDir(fd int, dirPath string, depth int) error {
	r := ix.r
	// Read one name more than the file budget allows, so an overrun is
	// seen by budget() below, and never more than maxNamesPerDir.
	limit := maxNamesPerDir
	if m := r.opts.MaxFiles; m > 0 {
		limit = min(limit, max(m-ix.count+1, 1))
	}
	names, truncated, err := readDirNames(fd, limit)
	if truncated && len(names) >= maxNamesPerDir {
		r.Stats.FileBudget.Store(true)
	}
	if err != nil {
		_ = unix.Close(fd)
		if isAccessErr(err) {
			if depth == 0 {
				// The root itself: an LSM refused it (DAC is covered by
				// CAP_DAC_READ_SEARCH, or counted under model (ii) below).
				return ErrLSMDenied
			}
			r.Stats.EACCES.Add(1)
		}
		return nil
	}
	ix.orderNames(names, depth == 0)

	type sub struct {
		name string
		st   unix.Statx_t
	}
	var subs []sub
	for _, name := range names {
		// Every entry costs budget, whatever it turns out to be: a tree of
		// FIFOs or excluded names must not be free to walk.
		if err := ix.budget(); err != nil {
			_ = unix.Close(fd)
			return err
		}
		p := path.Join(dirPath, name)
		if r.excluded(p) {
			r.Stats.MountSkipped.Add(1)
			continue
		}
		st, err := statx(fd, name)
		if err != nil {
			if isAccessErr(err) {
				r.Stats.EACCES.Add(1)
			}
			continue
		}
		if st.Mnt_id != r.mntID {
			r.Stats.MountSkipped.Add(1)
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			ref, err := ix.tree.AddDir(stereofile.Path(p))
			if err != nil {
				continue
			}
			ix.index.Add(*ref, ix.metadata(p, &st, stereofile.TypeDirectory, "", ""))
			r.Stats.Dirs.Add(1)
			if max := r.opts.MaxDepth; max > 0 && depth+1 > max {
				r.Stats.DepthLimited.Add(1)
				continue
			}
			subs = append(subs, sub{name, st})
		case unix.S_IFREG:
			// Sniffed exactly as an indexed file would be, so a dropped
			// file can be tested against the catalogers' MIME queries.
			sniff := !r.opts.SniffExecutablesOnly || looksExecutable(name, uint32(st.Mode))
			if r.late(&st) {
				d := droppedFile{mode: uint32(st.Mode), size: int64(st.Size)}
				if sniff {
					d.mime, d.unsniffed = sniffQuiet(fd, name, &st)
				}
				r.drop(p, d)
				continue
			}
			mime := ""
			if sniff {
				mime = ix.sniff(fd, name, &st)
			}
			ref, err := ix.tree.AddFile(stereofile.Path(p))
			if err != nil {
				continue
			}
			ix.index.Add(*ref, ix.metadata(p, &st, stereofile.TypeRegular, "", mime))
			r.Stats.Files.Add(1)
		case unix.S_IFLNK:
			if r.late(&st) {
				r.drop(p, droppedFile{mode: uint32(st.Mode)})
				continue
			}
			target, err := readlinkat(fd, name)
			if err != nil {
				if isAccessErr(err) {
					r.Stats.EACCES.Add(1)
				}
				continue
			}
			link := linkTarget(dirPath, target)
			ref, err := ix.tree.AddSymLink(stereofile.Path(p), stereofile.Path(link))
			if err != nil {
				continue
			}
			ix.index.Add(*ref, ix.metadata(p, &st, stereofile.TypeSymLink, link, ""))
			r.Stats.Files.Add(1)
		default:
			// Devices, FIFOs, sockets: never indexed, never opened
			// (Syft's directory resolver skips them too).
			r.Stats.Special.Add(1)
		}
	}

	// Component-wise: each subdirectory is opened by one name relative to
	// its parent's fd, which stays open while the subtree is walked (one
	// fd per level). Running out of fds (RLIMIT_NOFILE 4096 against a
	// 4096-deep tree) stops the descent there, like the depth cap.
	for _, s := range subs {
		p := path.Join(dirPath, s.name)
		if beforeOpenDir != nil {
			beforeOpenDir(p)
		}
		cfd, err := openat2(fd, s.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, resolveFlags)
		if err != nil {
			switch {
			case isAccessErr(err):
				r.Stats.EACCES.Add(1)
			case errors.Is(err, unix.EXDEV):
				r.Stats.MountSkipped.Add(1)
			case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
				r.Stats.Swapped.Add(1)
			case errors.Is(err, unix.EMFILE), errors.Is(err, unix.ENFILE):
				r.Stats.DepthLimited.Add(1)
			}
			continue
		}
		// The directory opened must be the one that was stat'ed: a swap
		// in between (rename, bind mount) is skipped, not followed.
		if cst, err := statx(cfd, ""); err != nil || cst.Ino != s.st.Ino || cst.Mnt_id != r.mntID {
			_ = unix.Close(cfd)
			r.Stats.Swapped.Add(1)
			continue
		}
		if err := ix.walkDir(cfd, p, depth+1); err != nil {
			_ = unix.Close(fd)
			return err
		}
	}
	_ = unix.Close(fd)
	return nil
}

// sniff reads the MIME type of the regular file name in dirfd, opened
// in-root, non-blocking, and checked to be the regular file stat'ed.
func (ix *indexer) sniff(dirfd int, name string, st *unix.Statx_t) string {
	fd, err := openat2(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_NOCTTY, resolveFlags)
	if err != nil {
		if isAccessErr(err) {
			ix.r.Stats.EACCES.Add(1)
		}
		return ""
	}
	defer func() { _ = unix.Close(fd) }()
	fst, err := statx(fd, "")
	if err != nil || fst.Mode&unix.S_IFMT != unix.S_IFREG || fst.Ino != st.Ino {
		ix.r.Stats.Swapped.Add(1)
		return ""
	}
	return stereofile.MIMEType(fdReader(fd))
}

// sniffQuiet is sniff for a file being left out as drift: the same MIME
// detection, but nothing is counted (the entry is not part of the scan).
// unsniffed reports that it could not be read.
func sniffQuiet(dirfd int, name string, st *unix.Statx_t) (mime string, unsniffed bool) {
	fd, err := openat2(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_NOCTTY, resolveFlags)
	if err != nil {
		return "", true
	}
	defer func() { _ = unix.Close(fd) }()
	fst, err := statx(fd, "")
	if err != nil || fst.Mode&unix.S_IFMT != unix.S_IFREG || fst.Ino != st.Ino {
		return "", true
	}
	return stereofile.MIMEType(fdReader(fd)), false
}

// fdReader reads an fd without taking ownership of it.
type fdReader int

func (f fdReader) Read(b []byte) (int, error) {
	for {
		n, err := unix.Read(int(f), b)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

// linkTarget is where a symlink at dir/<name> points, as an in-root path:
// absolute targets are relative to the root, relative ones to dir, and
// ".." never climbs above "/". This is the same mapping Syft's directory
// resolver applies with a base path equal to the scan root.
func linkTarget(dir, target string) string {
	if path.IsAbs(target) {
		return path.Clean(target)
	}
	return path.Clean(path.Join("/", dir, target))
}

// looksExecutable: any execute bit, or a *.so / *.so.* base name.
func looksExecutable(name string, mode uint32) bool {
	return mode&0o111 != 0 || IsSharedObjectName(name)
}

// IsSharedObjectName matches *.so and *.so.* base names.
func IsSharedObjectName(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}
