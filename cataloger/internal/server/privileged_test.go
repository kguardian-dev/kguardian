//go:build privileged

package server

// Capability-model tests. They need a container set up like the worker's
// (hack/privileged-tests.sh runs both):
//
//	model (i):  uid 0, --cap-drop ALL --cap-add DAC_READ_SEARCH,SETUID,SETGID,
//	            no-new-privileges, Docker's default seccomp profile
//	model (ii): the same without DAC_READ_SEARCH
//
// KG_EXPECT_MODEL says which one the container is.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/kguardian-dev/kguardian/cataloger/internal/child"
	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
	"github.com/kguardian-dev/kguardian/cataloger/internal/sandbox"
)

func expectModel(t *testing.T) string {
	m := os.Getenv("KG_EXPECT_MODEL")
	if m == "" {
		t.Skip("KG_EXPECT_MODEL not set (run hack/privileged-tests.sh)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the capability-model tests run as uid 0")
	}
	return m
}

func TestCapsModelProbe(t *testing.T) {
	want := expectModel(t)
	e := newServer(t, nil)
	m := e.srv.Model()
	if m.Name != want {
		t.Fatalf("model %s (%s), want %s", m.Name, m.Why, want)
	}
	if !m.SetUID {
		t.Error("uid 0 parent must start children as the scan uid")
	}
	// What a scan child actually holds.
	r := e.srv.run(context.Background(), "probe-caps", m, nil, nil, 4096)
	var p child.ProbeResult
	if r.payload == nil || json.Unmarshal(r.payload, &p) != nil {
		t.Fatalf("probe: %s", r.stderr)
	}
	wantCaps := uint64(0)
	if want == "i" {
		wantCaps = sandbox.ChildModelI
	}
	if p.UID != ScanUID || p.GID != ScanUID || p.Caps.Effective != wantCaps || p.Caps.Permitted != wantCaps {
		t.Errorf("child uid %d gid %d eff %s prm %s, want uid/gid %d and %s", p.UID, p.GID,
			sandbox.Names(p.Caps.Effective), sandbox.Names(p.Caps.Permitted), ScanUID, sandbox.Names(wantCaps))
	}
	if want == "i" && p.Caps.Ambient != sandbox.ChildModelI {
		t.Errorf("ambient %s", sandbox.Names(p.Caps.Ambient))
	}
}

// A root-owned 0600 file in a 0700 directory: readable by the scan uid
// only through CAP_DAC_READ_SEARCH.
func TestCapsModelReadsRootOnlyFiles(t *testing.T) {
	want := expectModel(t)
	root := alpineRoot(t, 3)
	write(t, filepath.Join(root, "opt/private/app/README"), []byte("x"), 0o600)
	must(t, os.Chmod(filepath.Join(root, "opt/private"), 0o700))
	// The package database itself root-only: model (i) must still read it.
	if want == "i" {
		must(t, os.Chmod(filepath.Join(root, "lib/apk/db/installed"), 0o600))
		must(t, os.Chmod(filepath.Join(root, "lib/apk/db"), 0o700))
	}
	e := newServer(t, nil)
	resp, err := e.controller(t, req("caps"), rootFD(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusOK || len(resp.Components) != 4 {
		t.Fatalf("%s/%s: %s %+v", resp.Status, resp.Reason, resp.Message, resp.Components)
	}
	switch want {
	case "i":
		if resp.Completeness != protocol.CompletenessFull || resp.Stats.EACCES != 0 {
			t.Errorf("model (i): completeness %s partial %v eacces %d", resp.Completeness, resp.PartialReasons, resp.Stats.EACCES)
		}
	case "ii":
		if resp.Completeness != protocol.CompletenessPartial || resp.Stats.EACCES == 0 ||
			!contains(resp.PartialReasons, protocol.PartialNoDACReadSearch) || !contains(resp.PartialReasons, protocol.PartialEACCES) {
			t.Errorf("model (ii): completeness %s partial %v eacces %d", resp.Completeness, resp.PartialReasons, resp.Stats.EACCES)
		}
	}
}

// With CAP_DAC_READ_SEARCH the child could read any path it can name on
// the host, so this checks it names none: links out of the root lead
// nowhere, and nothing outside is opened while the child scans.
func TestCapsModelHostFilesUnreachable(t *testing.T) {
	expectModel(t)
	base := worldDir(t)
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(outside, "secret"), []byte("TOPSECRET"), 0o600)
	must(t, os.Chmod(outside, 0o700))
	root := filepath.Join(base, "root")
	must(t, os.MkdirAll(root, 0o755))
	for _, f := range []string{"etc/os-release", "lib/apk/db/installed"} {
		b, err := os.ReadFile(filepath.Join(alpineRoot(t, 1), f))
		must(t, err)
		write(t, filepath.Join(root, f), b, 0o644)
	}
	for name, target := range map[string]string{
		"etc/abs":    filepath.Join(outside, "secret"),
		"etc/rel":    "../../outside/secret",
		"etc/proc":   "/proc/1/root" + filepath.Join(outside, "secret"),
		"etc/shadow": "/proc/1/root/etc/shadow",
		"out":        "../outside",
	} {
		must(t, os.Symlink(target, filepath.Join(root, name)))
	}
	ifd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	must(t, err)
	defer unix.Close(ifd)
	_, err = unix.InotifyAddWatch(ifd, outside, unix.IN_OPEN|unix.IN_ACCESS)
	must(t, err)

	e := newServer(t, nil)
	resp, err := e.controller(t, req("host"), rootFD(t, root))
	if err != nil || resp.Status != protocol.StatusOK {
		t.Fatalf("%+v %v", resp, err)
	}
	buf := make([]byte, 4096)
	if n, _ := unix.Read(ifd, buf); n > 0 {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[0]))
		t.Errorf("the scan child opened something outside the root (mask %#x)", ev.Mask)
	}
	for _, c := range resp.Components {
		for _, p := range c.FilePaths {
			if strings.Contains(p, "outside") || strings.Contains(p, "secret") {
				t.Errorf("a path outside the root was reported: %s", p)
			}
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
