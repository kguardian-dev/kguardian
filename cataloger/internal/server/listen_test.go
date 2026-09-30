package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/child"
	"github.com/kguardian-dev/kguardian/cataloger/internal/sandbox"
)

func TestListenSecuresSocketAndDirectory(t *testing.T) {
	base := worldDir(t)
	dir := filepath.Join(base, "catalog")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // an emptyDir as kubelet makes it
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "worker.sock")
	// A stale socket from a previous run is replaced.
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil || st.Mode&0o7777 != 0o700 || int(st.Uid) != os.Geteuid() {
		t.Errorf("directory mode %o uid %d, want 0700 uid %d", st.Mode&0o7777, st.Uid, os.Geteuid())
	}
	if err := unix.Lstat(sock, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&0o7777 != 0o600 || int(st.Uid) != os.Geteuid() {
		t.Errorf("socket mode %o uid %d, want a 0600 socket owned by %d", st.Mode, st.Uid, os.Geteuid())
	}
	old := syscall.Umask(0o022)
	syscall.Umask(old)
	if old == 0o177 {
		t.Error("umask left at 0177")
	}
}

func TestListenRefusesHostilePaths(t *testing.T) {
	base := worldDir(t)
	// A regular file where the socket goes.
	dir := filepath.Join(base, "a")
	write(t, filepath.Join(dir, "worker.sock"), []byte("x"), 0o600)
	if _, err := Listen(filepath.Join(dir, "worker.sock")); err == nil {
		t.Error("replaced a regular file")
	}
	// A symlinked socket directory.
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(base, "link", "worker.sock")); err == nil {
		t.Error("listened in a symlinked directory")
	}
	// A directory owned by another uid (setting it up needs root).
	if os.Geteuid() == 0 {
		other := filepath.Join(base, "other")
		if err := os.Mkdir(other, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(other, 4242, 4242); err == nil {
			if _, err := Listen(filepath.Join(other, "worker.sock")); err == nil {
				t.Error("listened in a directory owned by another uid")
			}
		}
	}
}

// The listening socket (and every other parent descriptor) must never
// reach a child: children get stdio, the root fd and their socketpair.
func TestChildrenInheritOnlyTheirDescriptors(t *testing.T) {
	// A descriptor the worker itself inherited without close-on-exec (as
	// from a CI runner or a container runtime) must not reach a child.
	var leak [2]int
	if err := unix.Pipe2(leak[:], 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(leak[0]); _ = unix.Close(leak[1]) })
	e := newServer(t, nil)
	// Hold a connection open too, so an accepted socket would show.
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	root, err := os.Open(alpineRoot(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	r := e.srv.run(context.Background(), "probe-caps", e.srv.Model(), root, nil, 1<<20)
	var p child.ProbeResult
	if r.payload == nil || json.Unmarshal(r.payload, &p) != nil {
		t.Fatalf("probe: %s", r.stderr)
	}
	for fd, target := range p.FDs {
		if fd > child.FDConn && !sandbox.RuntimeFD(target) {
			t.Errorf("child inherited fd %d -> %s", fd, target)
		}
	}
	if !strings.HasPrefix(p.FDs[child.FDConn], "socket:") || !strings.Contains(p.FDs[child.FDRoot], "kgc-test-") {
		t.Errorf("expected the root fd at 3 and the socketpair at 4: %v", p.FDs)
	}
}
