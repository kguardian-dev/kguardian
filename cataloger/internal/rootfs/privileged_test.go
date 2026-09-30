//go:build privileged

package rootfs

// Resolver tests that need real mounts and device nodes (CAP_SYS_ADMIN,
// CAP_MKNOD): hack/privileged-tests.sh runs them in a --privileged
// container.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func needRootMounts(t *testing.T) {
	t.Helper()
	if os.Getenv("KG_PRIVILEGED_ROOTFS") == "" {
		t.Skip("KG_PRIVILEGED_ROOTFS not set (run hack/privileged-tests.sh)")
	}
}

func mount(t *testing.T, src, dst, fstype string, flags uintptr) {
	t.Helper()
	must(t, os.MkdirAll(dst, 0o755))
	if err := unix.Mount(src, dst, fstype, flags, ""); err != nil {
		t.Fatalf("mount %s on %s: %v", src, dst, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dst, unix.MNT_DETACH) })
}

func noSecret(t *testing.T, r *Root, res *Resolver, paths ...string) {
	t.Helper()
	for p, c := range readAll(t, res) {
		if strings.Contains(c, secret) {
			t.Errorf("read the secret through %s", p)
		}
	}
	for _, p := range paths {
		if locs, _ := res.FilesByPath(p); len(locs) > 0 {
			t.Errorf("%s resolved to %+v", p, locs)
		}
		if f, err := r.OpenFile(p); err == nil {
			b, _ := io.ReadAll(f)
			_ = f.Close()
			if strings.Contains(string(b), secret) {
				t.Errorf("OpenFile(%s) read the secret", p)
			}
		}
	}
}

// A volume (tmpfs) and a bind mount inside the root are never entered,
// whether reached by walking or through a symlink: RESOLVE_NO_XDEV and
// STATX_MNT_ID, with no submount list to help.
func TestMountsAreNeverCrossed(t *testing.T) {
	needRootMounts(t)
	root, outside, _ := corpus(t)
	mount(t, "tmpfs", filepath.Join(root, "mnt/vol"), "tmpfs", 0)
	must(t, os.WriteFile(filepath.Join(root, "mnt/vol/secret"), []byte(secret), 0o644))
	mount(t, outside, filepath.Join(root, "data"), "", unix.MS_BIND)
	must(t, os.Symlink("/mnt/vol/secret", filepath.Join(root, "etc/tovol")))
	must(t, os.Symlink("/data/secret", filepath.Join(root, "etc/tobind")))

	r, err := OpenPath(root, Options{})
	must(t, err)
	defer func() { _ = r.Close() }()
	res, err := NewResolver(r)
	must(t, err)
	if r.Stats.MountSkipped.Load() < 2 {
		t.Errorf("mount points skipped: %d", r.Stats.MountSkipped.Load())
	}
	for _, p := range []string{"/mnt/vol", "/mnt/vol/secret", "/data", "/data/secret"} {
		if res.HasPath(p) {
			t.Errorf("%s indexed", p)
		}
	}
	noSecret(t, r, res, "/etc/tovol", "/etc/tobind", "/mnt/vol/secret", "/data/secret")
	if _, err := r.OpenFile("/mnt/vol/secret"); err == nil || !strings.Contains(err.Error(), "cross-device") {
		t.Errorf("open across a mount: %v, want EXDEV", err)
	}
}

// A mount that appears mid-scan, between the stat of a directory and its
// open, is refused by the open itself.
func TestMountAppearingMidScan(t *testing.T) {
	needRootMounts(t)
	root, outside, _ := corpus(t)
	mounted := false
	beforeOpenDir = func(p string) {
		if p == "/var/lib" && !mounted {
			mounted = true
			mount(t, outside, filepath.Join(root, "var/lib"), "", unix.MS_BIND)
		}
	}
	t.Cleanup(func() { beforeOpenDir = nil })
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer func() { _ = r.Close() }()
	res, err := NewResolver(r)
	must(t, err)
	if !mounted || r.Stats.MountSkipped.Load()+r.Stats.Swapped.Load() == 0 {
		t.Errorf("mid-scan mount not refused (mounted %v)", mounted)
	}
	noSecret(t, r, res, "/var/lib/secret")
}

// /proc mounted inside the root, and links into its magic links: the
// mount is never entered, and RESOLVE_NO_MAGICLINKS backs it up.
func TestMagicLinksLeadNowhere(t *testing.T) {
	needRootMounts(t)
	root, outside, secretPath := corpus(t)
	mount(t, "proc", filepath.Join(root, "proc"), "proc", 0)
	for name, target := range map[string]string{
		"etc/m-root": "/proc/self/root" + secretPath,
		"etc/m-cwd":  "/proc/self/cwd",
		"etc/m-fd":   "/proc/self/fd/0",
		"etc/m-1":    "/proc/1/root" + secretPath,
	} {
		must(t, os.Symlink(target, filepath.Join(root, name)))
	}
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer func() { _ = r.Close() }()
	res, err := NewResolver(r)
	must(t, err)
	if res.HasPath("/proc/self") || res.HasPath("/proc/1/root") {
		t.Error("/proc was entered")
	}
	noSecret(t, r, res, "/etc/m-root", "/etc/m-cwd", "/etc/m-fd", "/etc/m-1", "/proc/self/root"+secretPath)
	_ = outside
}

// Device nodes (the corpus creates them as root) are never indexed and
// never opened, even named directly.
func TestDeviceNodesAreNeverOpened(t *testing.T) {
	needRootMounts(t)
	root, _, _ := corpus(t)
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(root, "dev/zero"), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		t.Fatalf("no device node in the corpus: %v", err)
	}
	r, err := OpenPath(root, Options{})
	must(t, err)
	defer func() { _ = r.Close() }()
	res, err := NewResolver(r)
	must(t, err)
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/sda", "/lib/apk/db/lock"} {
		if l, _ := res.FilesByPath(p); len(l) > 0 {
			t.Errorf("%s resolved: %+v", p, l)
		}
		if f, err := r.OpenFile(p); err == nil {
			_ = f.Close()
			t.Errorf("%s opened", p)
		}
	}
	if r.Stats.Special.Load() < 4 {
		t.Errorf("special files counted: %d", r.Stats.Special.Load())
	}
}
