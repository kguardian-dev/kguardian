package rootfs

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const secret = "TOPSECRET-outside-the-root"

// corpus builds root/ next to outside/secret and fills root with every
// way we know of to point outside it, plus special files. It returns the
// root, the outside directory, and the host path of the secret.
func corpus(t *testing.T) (root, outside, secretPath string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	outside = filepath.Join(base, "outside")
	secretPath = filepath.Join(outside, "secret")
	must(t, os.MkdirAll(outside, 0o755))
	must(t, os.WriteFile(secretPath, []byte(secret), 0o644))
	for _, d := range []string{"etc", "lib/apk/db", "usr/bin", "var/lib", "dev", "deep"} {
		must(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\nVERSION_ID=3.20.0\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "usr/bin/tool"), []byte("#!/bin/sh\n"), 0o755))
	links := map[string]string{
		"etc/abs":         "/../../outside/secret",
		"etc/rel":         "../../outside/secret",
		"etc/dotdot":      strings.Repeat("../", 40) + "outside/secret",
		"etc/hostabs":     secretPath,                       // the secret's real host path
		"etc/hostdir":     outside,                          // a directory outside
		"etc/proc1":       "/proc/1/root" + secretPath,      // magic-link route
		"etc/procself":    "/proc/self/root" + secretPath,   // magic-link route
		"etc/procfd":      "/proc/self/fd/3",                // fd magic link
		"etc/shadowlink":  "/proc/1/root/etc/shadow",        // the classic target
		"loop1":           "loop2",                          // loop
		"loop2":           "loop1",                          //
		"self":            "self",                           // self loop
		"usr/bin/escape":  "../../../outside/secret",        // escaping binary
		"var/lib/outside": "../../../outside",               // escaping directory
		"usr/lib":         "../etc",                         // merged-usr style dir link
		"lib/apk/db/lock": "/dev/null",                      // device via link
		"etc/dirchain":    "../var/lib/outside/../outside",  // climbs through a link
		"etc/dev":         "../dev",                         //
		"etc/empty":       "",                               // empty target (invalid on Linux; skipped)
		"etc/long":        strings.Repeat("a/", 2000) + "x", // long target
		"etc/tmplink":     filepath.Join(os.TempDir(), "x"), // absolute host tmp
		"etc/rootlink":    "/",                              // the root itself
		"etc/parent":      "..",                             //
		"etc/dotslash":    "./../../../../outside/secret",   //
		"etc/slashes":     "//..//..//outside//secret",      //
		"etc/nul":         "outside\x01secret",              // odd bytes
		"usr/bin/busybox": "../../usr/bin/tool",             // in-root, valid
		"etc/good":        "/usr/bin/tool",                  // in-root absolute, valid
	}
	for name, target := range links {
		if target == "" {
			continue
		}
		must(t, os.Symlink(target, filepath.Join(root, name)))
	}
	// A FIFO where the apk database is expected: opening it blocking would
	// hang the scan forever.
	must(t, unix.Mkfifo(filepath.Join(root, "lib/apk/db/installed"), 0o644))
	// A Unix socket.
	l, err := net.Listen("unix", filepath.Join(root, "var/lib/sock"))
	must(t, err)
	t.Cleanup(func() { _ = l.Close() })
	// Device files (root only).
	if os.Geteuid() == 0 {
		_ = unix.Mknod(filepath.Join(root, "dev/null"), unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3)))
		_ = unix.Mknod(filepath.Join(root, "dev/zero"), unix.S_IFCHR|0o666, int(unix.Mkdev(1, 5)))
		_ = unix.Mknod(filepath.Join(root, "dev/sda"), unix.S_IFBLK|0o600, int(unix.Mkdev(8, 0)))
	}
	return root, outside, secretPath
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// watchOutside reports every open or read of anything in dir.
func watchOutside(t *testing.T, dir string) func() []string {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	must(t, err)
	_, err = unix.InotifyAddWatch(fd, dir, unix.IN_OPEN|unix.IN_ACCESS)
	must(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	return func() []string {
		var evs []string
		buf := make([]byte, 64*1024)
		for {
			n, err := unix.Read(fd, buf)
			if n <= 0 || err != nil {
				return evs
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				name := strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:off+unix.SizeofInotifyEvent+int(ev.Len)]), "\x00")
				evs = append(evs, name)
				off += unix.SizeofInotifyEvent + int(ev.Len)
			}
		}
	}
}

// The watcher itself must see a real read, or every "nothing outside was
// read" assertion below is vacuous.
func TestWatcherSeesOutsideReads(t *testing.T) {
	_, outside, secretPath := corpus(t)
	events := watchOutside(t, outside)
	_ = events()
	if _, err := os.ReadFile(secretPath); err != nil {
		t.Fatal(err)
	}
	if evs := events(); len(evs) == 0 {
		t.Fatal("inotify did not report a direct read of the secret")
	}
}

func readAll(t *testing.T, res *Resolver) map[string]string {
	t.Helper()
	got := map[string]string{}
	for loc := range res.AllLocations(context.Background()) {
		rc, err := res.FileContentsByLocation(loc)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		_ = rc.Close()
		got[loc.RealPath] = string(b)
	}
	return got
}

func TestNothingOutsideTheRootIsRead(t *testing.T) {
	root, outside, _ := corpus(t)
	events := watchOutside(t, outside)
	_ = events() // drain the setup's own writes

	r, err := OpenPath(root, Options{})
	must(t, err)
	defer r.Close()
	done := make(chan struct{})
	var res *Resolver
	go func() {
		defer close(done)
		res, err = NewResolver(r)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("indexing hung (FIFO?)")
	}
	must(t, err)

	// Read every indexed file.
	for p, content := range readAll(t, res) {
		if strings.Contains(content, secret) {
			t.Errorf("read the secret through %s", p)
		}
	}
	// Ask for every link by path and glob, as catalogers do.
	var asked []string
	for loc := range res.AllLocations(context.Background()) {
		asked = append(asked, loc.RealPath)
	}
	asked = append(asked, "/etc/abs", "/etc/rel", "/etc/dotdot", "/etc/hostabs", "/etc/hostdir/secret",
		"/etc/proc1", "/etc/procself", "/etc/procfd", "/etc/shadowlink", "/var/lib/outside/secret",
		"/etc/dirchain/secret", "../../outside/secret", "/../outside/secret", outside+"/secret",
		"/proc/1/root/etc/shadow", "/proc/self/root"+outside+"/secret", "loop1", "/self/x")
	locs, _ := res.FilesByPath(asked...)
	globs, _ := res.FilesByGlob("**/secret", "**/*", "/etc/*", "**/shadow", "../**")
	for _, loc := range append(locs, globs...) {
		if !strings.HasPrefix(loc.RealPath, "/") || strings.Contains(loc.RealPath, "..") {
			t.Errorf("location outside the root: %+v", loc)
		}
		rc, err := res.FileContentsByLocation(loc)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if strings.Contains(string(b), secret) {
			t.Errorf("read the secret via %s -> %s", loc.AccessPath, loc.RealPath)
		}
	}
	// Direct opens by path go through the kernel's in-root resolution.
	for _, p := range asked {
		f, err := r.OpenFile(p)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(f)
		_ = f.Close()
		if strings.Contains(string(b), secret) {
			t.Errorf("OpenFile(%q) read the secret", p)
		}
	}
	if evs := events(); len(evs) > 0 {
		t.Errorf("files outside the root were opened or read: %v", evs)
	}

	// In-root links still work.
	if l, _ := res.FilesByPath("/etc/good"); len(l) != 1 || l[0].RealPath != "/usr/bin/tool" || l[0].AccessPath != "/etc/good" {
		t.Errorf("in-root absolute link: %+v", l)
	}
	if l, _ := res.FilesByPath("/usr/lib/os-release"); len(l) != 1 || l[0].RealPath != "/etc/os-release" {
		t.Errorf("in-root directory link: %+v", l)
	}
	// Special files are never indexed, so never opened.
	for _, p := range []string{"/lib/apk/db/installed", "/var/lib/sock", "/dev/null", "/dev/zero", "/dev/sda"} {
		if res.HasPath(p) {
			t.Errorf("special file %s was indexed", p)
		}
	}
	if r.Stats.Special.Load() < 2 {
		t.Errorf("special files counted: %d", r.Stats.Special.Load())
	}
}

func TestFIFOOpenDoesNotHang(t *testing.T) {
	root, _, _ := corpus(t)
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer r.Close()
	done := make(chan error, 1)
	go func() {
		f, err := r.OpenFile("/lib/apk/db/installed")
		if f != nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO open: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
	if _, err := r.OpenFile("/dev/zero"); err == nil {
		t.Error("opened a device")
	}
}

func TestDirectorySwappedForSymlinkMidScan(t *testing.T) {
	root, outside, _ := corpus(t)
	events := watchOutside(t, outside)
	_ = events()
	// The walker stat()s var/lib as a directory; before it opens it,
	// replace it with a symlink to the outside directory.
	swapped := false
	beforeOpenDir = func(p string) {
		if p == "/var/lib" && !swapped {
			swapped = true
			must(t, os.Rename(filepath.Join(root, "var/lib"), filepath.Join(root, "var/lib.orig")))
			must(t, os.Symlink(outside, filepath.Join(root, "var/lib")))
		}
	}
	t.Cleanup(func() { beforeOpenDir = nil })
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer r.Close()
	res, err := NewResolver(r)
	must(t, err)
	if !swapped {
		t.Fatal("hook did not run")
	}
	if r.Stats.Swapped.Load() == 0 {
		t.Error("swap not detected")
	}
	if res.HasPath("/var/lib/secret") {
		t.Error("followed the swapped directory out of the root")
	}
	for p, c := range readAll(t, res) {
		if strings.Contains(c, secret) {
			t.Errorf("read the secret via %s", p)
		}
	}
	if evs := events(); len(evs) > 0 {
		t.Errorf("outside opened: %v", evs)
	}
}

func TestFileSwappedForSymlinkAfterIndexing(t *testing.T) {
	root, outside, secretPath := corpus(t)
	events := watchOutside(t, outside)
	_ = events()
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer r.Close()
	res, err := NewResolver(r)
	must(t, err)
	locs, _ := res.FilesByPath("/etc/os-release")
	if len(locs) != 1 {
		t.Fatalf("os-release: %v", locs)
	}
	// Swap the file for a link to the secret, and a parent directory for
	// a link to the outside directory.
	must(t, os.Remove(filepath.Join(root, "etc/os-release")))
	must(t, os.Symlink(secretPath, filepath.Join(root, "etc/os-release")))
	if rc, err := res.FileContentsByLocation(locs[0]); err == nil {
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		t.Errorf("opened a swapped-in symlink: %q", b)
	}
	tool, _ := res.FilesByPath("/usr/bin/tool")
	must(t, os.Rename(filepath.Join(root, "usr/bin"), filepath.Join(root, "usr/bin.orig")))
	must(t, os.Symlink(outside, filepath.Join(root, "usr/bin")))
	if len(tool) == 1 {
		if rc, err := res.FileContentsByLocation(tool[0]); err == nil {
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			if strings.Contains(string(b), secret) {
				t.Error("read the secret through a swapped parent")
			}
		}
	}
	if evs := events(); len(evs) > 0 {
		t.Errorf("outside opened: %v", evs)
	}
}

func TestDeepTree(t *testing.T) {
	root := t.TempDir()
	// 4200 levels: past the depth cap, and past PATH_MAX as one path, so
	// only component-wise opens can walk it at all.
	d, err := os.Open(root)
	must(t, err)
	dirfd := int(d.Fd())
	for i := 0; i < 4200; i++ {
		must(t, unix.Mkdirat(dirfd, "d", 0o755))
		nfd, err := unix.Openat(dirfd, "d", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		must(t, err)
		if i == 3000 {
			must(t, os.WriteFile("/proc/self/fd/"+strconv.Itoa(nfd)+"/marker", []byte("x"), 0o644))
		}
		if dirfd != int(d.Fd()) {
			_ = unix.Close(dirfd)
		}
		dirfd = nfd
	}
	_ = unix.Close(dirfd)
	_ = d.Close()

	var old unix.Rlimit
	must(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &old))
	lim := unix.Rlimit{Cur: 4096, Max: old.Max}
	must(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &lim))
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &old) })

	r, err := OpenPath(root, Options{MaxDepth: 4096})
	must(t, err)
	defer r.Close()
	res, err := NewResolver(r)
	must(t, err)
	if r.Stats.DepthLimited.Load() == 0 {
		t.Error("depth cap not reported")
	}
	if got := r.Stats.Dirs.Load(); got < 3002 {
		t.Errorf("walked only %d directories", got)
	}
	marker := "/" + strings.Repeat("d/", 3001) + "marker"
	if !res.HasPath(marker) {
		t.Error("file at depth 3001 not indexed")
	}
}

func TestUnreadableEntriesAreCounted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything (the caps model test covers the scan uid)")
	}
	root, _, _ := corpus(t)
	must(t, os.MkdirAll(filepath.Join(root, "private/inner"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("x"), 0o000))
	must(t, os.Chmod(filepath.Join(root, "private"), 0o000))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "private"), 0o755) })
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer r.Close()
	_, err = NewResolver(r)
	must(t, err)
	if r.Stats.EACCES.Load() < 2 {
		t.Errorf("EACCES = %d, want >= 2", r.Stats.EACCES.Load())
	}
}

func TestUnreadableRootIsLSMDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can list a 0000 directory")
	}
	root := t.TempDir()
	must(t, os.Chmod(root, 0o100)) // traversable, not listable
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer r.Close()
	if _, err := NewResolver(r); !errors.Is(err, ErrLSMDenied) {
		t.Fatalf("got %v, want ErrLSMDenied", err)
	}
}

func TestSubmountsAreNeverEntered(t *testing.T) {
	root, _, _ := corpus(t)
	must(t, os.MkdirAll(filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount/token"), []byte("tok"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "etc/hosts"), []byte("h"), 0o644))
	r, err := OpenPath(root, Options{Submounts: []string{"/var/run/secrets/kubernetes.io/serviceaccount", "/etc/hosts"}})
	must(t, err)
	defer r.Close()
	res, err := NewResolver(r)
	must(t, err)
	for _, p := range []string{"/var/run/secrets/kubernetes.io/serviceaccount/token", "/etc/hosts"} {
		if res.HasPath(p) {
			t.Errorf("%s indexed", p)
		}
		if f, err := r.OpenFile(p); err == nil {
			_ = f.Close()
			t.Errorf("%s opened", p)
		}
	}
}

func TestCtimeAfterStartIsDropped(t *testing.T) {
	root, _, _ := corpus(t)
	cut := time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	must(t, os.WriteFile(filepath.Join(root, "usr/bin/dropped"), []byte("\x7fELF"), 0o755))
	r, err := OpenPath(root, Options{CtimeCutoffNanos: cut})
	must(t, err)
	defer r.Close()
	res, err := NewResolver(r)
	must(t, err)
	if res.HasPath("/usr/bin/dropped") {
		t.Error("runtime-created file indexed")
	}
	if !r.Dropped("/usr/bin/dropped") || r.Stats.CtimeDropped.Load() == 0 {
		t.Error("drop not recorded")
	}
	if !res.HasPath("/etc/os-release") {
		t.Error("an older file was dropped")
	}
	// A file indexed before its ctime moved is refused at read time.
	locs, _ := res.FilesByPath("/usr/bin/tool")
	r.opts.CtimeCutoffNanos = time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	must(t, os.Chmod(filepath.Join(root, "usr/bin/tool"), 0o700))
	if _, err := res.FileContentsByLocation(locs[0]); err == nil {
		t.Error("read a file whose ctime moved past the cutoff")
	}
}

func TestFileBudget(t *testing.T) {
	root, _, _ := corpus(t)
	r, err := OpenPath(root, Options{MaxFiles: 5})
	must(t, err)
	defer r.Close()
	if _, err := NewResolver(r); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("got %v", err)
	}
	// Enough for the top level and /etc, not for everything.
	must(t, os.MkdirAll(filepath.Join(root, "aaa-app/node_modules"), 0o755))
	for i := range 50 {
		must(t, os.WriteFile(filepath.Join(root, "aaa-app/node_modules", strconv.Itoa(i)), nil, 0o644))
	}
	r2, err := OpenPath(root, Options{MaxFiles: 45, StopAtBudget: true, SystemFirst: true})
	must(t, err)
	defer r2.Close()
	res, err := NewResolver(r2)
	must(t, err)
	if !r2.Stats.FileBudget.Load() {
		t.Error("budget stop not recorded")
	}
	if !res.HasPath("/etc/os-release") {
		t.Error("system-first order did not index /etc first")
	}
	if res.HasPath("/aaa-app/node_modules/49") {
		t.Error("indexed past the budget")
	}
}

func TestLinkTarget(t *testing.T) {
	for _, c := range []struct{ dir, target, want string }{
		{"/bin", "busybox", "/bin/busybox"},
		{"/bin", "/bin/busybox", "/bin/busybox"},
		{"/usr/bin", "../../../../etc/passwd", "/etc/passwd"},
		{"/", "../x", "/x"},
		{"/a", "/../../x", "/x"},
		{"/a", "./b/../c", "/a/c"},
	} {
		if got := linkTarget(c.dir, c.target); got != c.want {
			t.Errorf("linkTarget(%q, %q) = %q, want %q", c.dir, c.target, got, c.want)
		}
	}
}

func TestSharedObjectName(t *testing.T) {
	for p, want := range map[string]bool{
		"/lib/libc.so.6": true, "/lib/libz.so": true, "/usr/lib/libssl.so.3": true,
		"/usr/lib/x.sock": false, "/usr/lib/solaris": false, "/a.so.d/file": false, "/lib/foo.sop": false,
	} {
		if got := IsSharedObjectName(p); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

func TestKernelSupported(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	must(t, err)
	defer unix.Close(fd)
	if err := CheckKernel(fd); err != nil {
		t.Fatalf("this kernel should support openat2 and STATX_MNT_ID: %v", err)
	}
}
